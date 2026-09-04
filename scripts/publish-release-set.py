#!/usr/bin/env python3
"""Publish a verified Dev Tools release set through exact Git and gh frontends."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

from release_signing import (
    load_root_document,
    load_signed_product_manifest,
    read_public_key,
    verify_product_manifest,
    verify_root_document,
)
from release_targets import require_accepted_release_target

ROOT = Path(__file__).resolve().parents[1]
PRODUCT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
TARGET_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
METADATA_LIMIT = 1024 * 1024
ARTIFACT_LIMIT = 512 * 1024 * 1024
MAX_PRODUCTS = 16
COMMAND_TIMEOUT = 120


@dataclass(frozen=True)
class Asset:
    path: Path
    length: int
    sha256: str


@dataclass(frozen=True)
class ExactCommand:
    launcher: Path
    executable: Path


@dataclass(frozen=True)
class ProductRelease:
    product: str
    version: str
    tag: str
    title: str
    source_bound: bool
    assets: tuple[Asset, ...]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-root", required=True, type=Path)
    parser.add_argument(
        "--trusted-root-public-key",
        type=Path,
        default=ROOT / "crates/update-all/trust/root-public-key.txt",
    )
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--git-command", required=True, type=Path)
    parser.add_argument("--gh-command", required=True, type=Path)
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--format", choices=("human", "json"), default="human")
    return parser.parse_args()


def checked_file(path: Path, *, label: str, limit: int) -> tuple[int, str]:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise SystemExit(f"{label} is not readable: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise SystemExit(f"{label} must be a single-link regular file: {path}")
        if metadata.st_size > limit:
            raise SystemExit(f"{label} exceeds its size limit: {path}")
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        return metadata.st_size, digest.hexdigest()
    finally:
        os.close(descriptor)


def require_root_owned_path(path: Path, *, label: str) -> None:
    for component in reversed(path.parents):
        try:
            metadata = component.lstat()
        except OSError as exc:
            raise SystemExit(f"{label} path is unavailable: {component}") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            raise SystemExit(
                f"{label} path must traverse root-owned non-writable directories"
            )


def exact_command(path: Path, expected_name: str) -> ExactCommand:
    if not path.is_absolute() or path.name != expected_name:
        raise SystemExit(
            f"{expected_name} command must be an absolute same-name launcher"
        )
    try:
        metadata = path.lstat()
        target = path.resolve(strict=True)
        target_metadata = target.stat()
    except OSError as exc:
        raise SystemExit(f"{expected_name} command is unavailable: {path}") from exc
    if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
        raise SystemExit(f"{expected_name} command has an unsupported file type")
    if metadata.st_uid != 0:
        raise SystemExit(f"{expected_name} command launcher is not root-owned")
    require_root_owned_path(path, label=f"{expected_name} command launcher")
    require_root_owned_path(target, label=f"{expected_name} command target")
    if not stat.S_ISREG(target_metadata.st_mode) or not os.access(target, os.X_OK):
        raise SystemExit(f"{expected_name} command target is not executable")
    if target_metadata.st_uid != 0 or target_metadata.st_mode & 0o022:
        raise SystemExit(f"{expected_name} command target is group- or other-writable")
    return ExactCommand(launcher=path, executable=target)


def artifact_name_from_url(url: str, repository: str, tag: str) -> str:
    parsed = urlparse(url)
    parts = [unquote(value) for value in parsed.path.split("/") if value]
    owner, repo = repository.split("/", 1)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parts[:4] != [owner, repo, "releases", "download"]
        or len(parts) != 6
        or parts[4] != tag
        or not parts[5]
        or Path(parts[5]).name != parts[5]
    ):
        raise SystemExit(
            "product manifest artifact URL does not match the publication target"
        )
    return parts[5]


def load_release(
    directory: Path, trusted_root: Path, repository: str, source_commit: str
) -> ProductRelease:
    if directory.is_symlink() or not directory.is_dir():
        raise SystemExit(
            f"release product path must be a non-symlink directory: {directory}"
        )
    product = directory.name
    if not PRODUCT_RE.fullmatch(product):
        raise SystemExit(f"release product directory has an invalid name: {directory}")
    root_path = directory / "dev-tools-root.json"
    manifest_path = directory / f"{product}-stable.json"
    checked_file(root_path, label="root document", limit=METADATA_LIMIT)
    checked_file(manifest_path, label="product manifest", limit=METADATA_LIMIT)
    root_document = load_root_document(root_path)
    verify_root_document(root_document, read_public_key(trusted_root))
    envelope = load_signed_product_manifest(manifest_path)
    signed = verify_product_manifest(envelope, root_document)

    schema = signed.get("schema")
    expected_fields = {
        "schema",
        "product",
        "generation",
        "version",
        "engine_protocol",
        "artifacts",
    }
    if schema == "dev-auth-product-v2":
        expected_fields.add("source_commit")
    elif schema != "dev-tools-product-v1":
        raise SystemExit("product manifest schema is unsupported")
    if set(signed) != expected_fields:
        raise SystemExit("product manifest has unsupported fields")
    if signed.get("product") != product:
        raise SystemExit("product manifest does not match its release directory")
    version = signed.get("version")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise SystemExit("product manifest version is not stable semantic version")
    generation = signed.get("generation")
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 1
    ):
        raise SystemExit("product manifest generation must be positive")
    if signed.get("engine_protocol") != 1:
        raise SystemExit("product manifest engine protocol is unsupported")
    if schema == "dev-auth-product-v2" and signed.get("source_commit") != source_commit:
        raise SystemExit(
            "dev-auth manifest source commit does not match publication source"
        )
    artifacts = signed.get("artifacts")
    if not isinstance(artifacts, dict) or len(artifacts) != 1:
        raise SystemExit("product manifest must contain exactly one target artifact")
    target, record = next(iter(artifacts.items()))
    if not isinstance(target, str) or not TARGET_RE.fullmatch(target):
        raise SystemExit("product manifest target is invalid")
    require_accepted_release_target(product, target)
    if not isinstance(record, dict) or set(record) != {"url", "length", "sha256"}:
        raise SystemExit("product manifest artifact record is invalid")
    tag = f"{product}/v{version}"
    url = record.get("url")
    length = record.get("length")
    digest = record.get("sha256")
    if not isinstance(url, str):
        raise SystemExit("product manifest artifact URL is invalid")
    if (
        isinstance(length, bool)
        or not isinstance(length, int)
        or length < 0
        or length > ARTIFACT_LIMIT
    ):
        raise SystemExit("product manifest artifact length is invalid")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise SystemExit("product manifest artifact digest is invalid")
    artifact_path = directory / artifact_name_from_url(url, repository, tag)
    actual_length, actual_digest = checked_file(
        artifact_path,
        label="release artifact",
        limit=ARTIFACT_LIMIT,
    )
    if (actual_length, actual_digest) != (length, digest):
        raise SystemExit("release artifact does not match its signed manifest")
    expected_files = {root_path.name, manifest_path.name, artifact_path.name}
    actual_files = {entry.name for entry in directory.iterdir()}
    if actual_files != expected_files:
        raise SystemExit("release product directory contains unexpected files")
    assets = []
    for path in (artifact_path, manifest_path, root_path):
        asset_length, asset_digest = checked_file(
            path,
            label="release asset",
            limit=ARTIFACT_LIMIT,
        )
        assets.append(Asset(path=path, length=asset_length, sha256=asset_digest))
    return ProductRelease(
        product=product,
        version=version,
        tag=tag,
        title=f"{product} v{version}",
        source_bound=schema == "dev-auth-product-v2",
        assets=tuple(assets),
    )


def run(
    command: ExactCommand, *arguments: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(command.launcher), *arguments],
        executable=str(command.executable),
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=COMMAND_TIMEOUT,
        check=False,
    )
    if check and result.returncode != 0:
        raise SystemExit(
            f"{command.launcher.name} command failed: {result.stderr.strip()}"
        )
    return result


def ensure_source(git: ExactCommand, source_commit: str) -> None:
    if not COMMIT_RE.fullmatch(source_commit):
        raise SystemExit("source commit must be 40 lowercase hexadecimal characters")
    status = run(git, "status", "--porcelain", "--untracked-files=normal").stdout
    if status:
        raise SystemExit("release publication requires a clean checkout")
    run(git, "cat-file", "-e", f"{source_commit}^{{commit}}")


def remote_tag_rows(git: ExactCommand, remote: str, tag: str) -> dict[str, str]:
    remote_rows = run(
        git,
        "ls-remote",
        "--tags",
        remote,
        f"refs/tags/{tag}",
        f"refs/tags/{tag}^{{}}",
    ).stdout.splitlines()
    rows = [row.split("\t", 1) for row in remote_rows]
    if any(len(row) != 2 or not COMMIT_RE.fullmatch(row[0]) for row in rows):
        raise SystemExit(f"remote returned invalid tag metadata: {tag}")
    return {reference: commit for commit, reference in rows}


def verify_local_tag(
    git: ExactCommand, release: ProductRelease, source_commit: str
) -> None:
    peeled = run(git, "rev-list", "-n", "1", release.tag).stdout.strip()
    if peeled != source_commit:
        raise SystemExit(
            f"local release tag points at a different source: {release.tag}"
        )
    configured_key = run(git, "config", "--get", "user.signingKey").stdout.splitlines()
    if len(configured_key) != 1 or not configured_key[0].startswith("key::"):
        raise SystemExit("Git signing identity is not one inline SSH public key")
    fields = configured_key[0].removeprefix("key::").split()
    if (
        len(fields) < 2
        or not re.fullmatch(r"[A-Za-z0-9@._+-]{1,128}", fields[0])
        or not re.fullmatch(r"[A-Za-z0-9+/]+={0,3}", fields[1])
    ):
        raise SystemExit("Git signing identity is not one inline SSH public key")
    try:
        key_bytes = base64.b64decode(fields[1], validate=True)
    except ValueError as exc:
        raise SystemExit(
            "Git signing identity is not one inline SSH public key"
        ) from exc
    if not 32 <= len(key_bytes) <= 16 * 1024:
        raise SystemExit("Git signing identity is not one inline SSH public key")
    with tempfile.TemporaryDirectory(prefix="dev-tools-allowed-signers-") as directory:
        allowed_signers = Path(directory) / "allowed-signers"
        allowed_signers.write_text(
            f'* namespaces="git" {fields[0]} {fields[1]}\n', encoding="ascii"
        )
        allowed_signers.chmod(0o600)
        run(
            git,
            "-c",
            f"gpg.ssh.allowedSignersFile={allowed_signers}",
            "verify-tag",
            release.tag,
        )


def ensure_signed_tag(
    git: ExactCommand,
    remote: str,
    release: ProductRelease,
    source_commit: str,
) -> bool:
    remote_refs = remote_tag_rows(git, remote, release.tag)
    remote_ref = f"refs/tags/{release.tag}"
    remote_peeled = f"{remote_ref}^{{}}"
    if remote_refs:
        if (
            remote_refs.get(remote_peeled) != source_commit
            or remote_ref not in remote_refs
        ):
            raise SystemExit(
                f"remote release tag is not the expected signed source: {release.tag}"
            )
        local = run(git, "tag", "--list", release.tag).stdout.splitlines()
        if not local:
            run(git, "fetch", "--no-tags", remote, f"{remote_ref}:{remote_ref}")
        elif local != [release.tag]:
            raise SystemExit(f"local release tag is ambiguous: {release.tag}")
        verify_local_tag(git, release, source_commit)
        return False

    local = run(git, "tag", "--list", release.tag).stdout.splitlines()
    if not local:
        run(git, "tag", "-s", release.tag, source_commit, "-m", release.title)
    elif local != [release.tag]:
        raise SystemExit(f"local release tag is ambiguous: {release.tag}")
    verify_local_tag(git, release, source_commit)
    run(git, "push", remote, f"{remote_ref}:{remote_ref}")
    published_refs = remote_tag_rows(git, remote, release.tag)
    if (
        published_refs.get(remote_peeled) != source_commit
        or remote_ref not in published_refs
    ):
        raise SystemExit(f"remote release tag did not verify after push: {release.tag}")
    return True


def release_view(
    gh: ExactCommand, repository: str, tag: str
) -> dict[str, object] | None:
    result = run(
        gh,
        "release",
        "view",
        tag,
        "--repo",
        repository,
        "--json",
        "tagName,isDraft,isPrerelease,assets",
        check=False,
    )
    if result.returncode != 0:
        if result.returncode == 1 and result.stderr.strip() == "release not found":
            return None
        raise SystemExit(
            f"gh could not determine release state: {result.stderr.strip()}"
        )
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit("gh returned invalid release metadata") from exc
    if not isinstance(value, dict):
        raise SystemExit("gh returned invalid release metadata")
    return value


def verify_published_assets(
    gh: ExactCommand, repository: str, release: ProductRelease
) -> None:
    view = release_view(gh, repository, release.tag)
    if view is None:
        raise SystemExit(f"published release is absent after creation: {release.tag}")
    if (
        view.get("tagName") != release.tag
        or view.get("isDraft") is not False
        or view.get("isPrerelease") is not False
    ):
        raise SystemExit(f"published release metadata is unexpected: {release.tag}")
    assets = view.get("assets")
    if not isinstance(assets, list):
        raise SystemExit("published release asset metadata is invalid")
    observed = {
        row.get("name"): row.get("size")
        for row in assets
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    }
    expected = {asset.path.name: asset.length for asset in release.assets}
    if observed != expected:
        raise SystemExit(
            f"published release assets do not match the signed set: {release.tag}"
        )
    with tempfile.TemporaryDirectory(prefix="dev-tools-release-download-") as directory:
        destination = Path(directory)
        for asset in release.assets:
            run(
                gh,
                "release",
                "download",
                release.tag,
                "--repo",
                repository,
                "--dir",
                str(destination),
                "--pattern",
                asset.path.name,
            )
            downloaded = destination / asset.path.name
            length, digest = checked_file(
                downloaded, label="downloaded release asset", limit=ARTIFACT_LIMIT
            )
            if (length, digest) != (asset.length, asset.sha256):
                raise SystemExit(
                    f"downloaded release asset does not match: {asset.path.name}"
                )


def publish_one(
    git: ExactCommand,
    gh: ExactCommand,
    remote: str,
    repository: str,
    release: ProductRelease,
    source_commit: str,
) -> bool:
    changed = ensure_signed_tag(git, remote, release, source_commit)
    existing = release_view(gh, repository, release.tag)
    if existing is None:
        for asset in release.assets:
            if checked_file(
                asset.path,
                label="release asset",
                limit=ARTIFACT_LIMIT,
            ) != (asset.length, asset.sha256):
                raise SystemExit(
                    f"release asset changed before publication: {asset.path.name}"
                )
        if release.source_bound:
            notes = (
                f"Authenticated {release.title} release from source `{source_commit}`."
            )
        else:
            notes = (
                f"Authenticated {release.title} release. Its signed v1 manifest does "
                "not bind artifact provenance to the source tag."
            )
        run(
            gh,
            "release",
            "create",
            release.tag,
            "--repo",
            repository,
            "--verify-tag",
            "--title",
            release.title,
            "--notes",
            notes,
            *(str(asset.path) for asset in release.assets),
        )
        changed = True
    verify_published_assets(gh, repository, release)
    return changed


def main() -> int:
    args = parse_args()
    if not REPOSITORY_RE.fullmatch(args.repository):
        raise SystemExit("repository must be OWNER/NAME")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", args.remote):
        raise SystemExit("remote name is invalid")
    source_commit = args.source_commit.lower()
    if not COMMIT_RE.fullmatch(source_commit):
        raise SystemExit("source commit must be 40 hexadecimal characters")
    git = exact_command(args.git_command, "git")
    gh = exact_command(args.gh_command, "gh")
    if args.release_root.is_symlink():
        raise SystemExit("release root must be a non-symlink directory")
    release_root = args.release_root.resolve(strict=True)
    if not release_root.is_dir():
        raise SystemExit("release root must be a non-symlink directory")
    checked_file(
        args.trusted_root_public_key,
        label="trusted root public key",
        limit=METADATA_LIMIT,
    )
    directories = sorted(entry for entry in release_root.iterdir() if entry.is_dir())
    if not directories or len(directories) > MAX_PRODUCTS:
        raise SystemExit("release root must contain between one and sixteen products")
    if any(not entry.is_dir() for entry in release_root.iterdir()):
        raise SystemExit("release root contains an unexpected non-directory entry")
    releases = [
        load_release(
            directory, args.trusted_root_public_key, args.repository, source_commit
        )
        for directory in directories
    ]
    tags = [release.tag for release in releases]
    if len(tags) != len(set(tags)):
        raise SystemExit("release set contains duplicate tags")
    ensure_source(git, source_commit)
    changed = False
    reports = []
    for release in releases:
        release_changed = publish_one(
            git,
            gh,
            args.remote,
            args.repository,
            release,
            source_commit,
        )
        changed = changed or release_changed
        reports.append(
            {
                "product": release.product,
                "version": release.version,
                "tag": release.tag,
                "source_bound": release.source_bound,
            }
        )
    report = {
        "schema": "dev-tools-release-publication-v1",
        "tag_source_commit": source_commit,
        "repository": args.repository,
        "changed": changed,
        "verified": True,
        "releases": reports,
    }
    if args.format == "json":
        print(json.dumps(report, sort_keys=True))
    else:
        print(f"changed={str(changed).lower()}")
        print("verified=true")
        for release in reports:
            print(f"release={release['tag']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
