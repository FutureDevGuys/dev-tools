#!/usr/bin/env python3
"""Build and sign every Dev Tools product from one exact clean revision."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SIGNER = ROOT / "scripts" / "build-signed-release.py"
PRODUCTS = ("update-all", "dev-auth", "dev-cache", "sync-configs", "skills-sync")


def run(*args: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return result.stdout.strip()


def resolve_public_git(explicit: Path | None) -> Path:
    if explicit is not None:
        if not explicit.is_absolute():
            raise SystemExit("public Git command must be an absolute executable path")
        candidates = (explicit,)
    else:
        system = platform.system().lower()
        candidates = {
            "linux": (Path("/usr/bin/git"), Path("/bin/git")),
            "darwin": (Path("/usr/bin/git"), Path("/opt/homebrew/bin/git")),
            "windows": (
                Path("C:/Program Files/Git/cmd/git.exe"),
                Path("C:/Program Files/Git/bin/git.exe"),
            ),
        }.get(system, ())
    for candidate in candidates:
        try:
            canonical = candidate.resolve(strict=True)
            metadata = canonical.stat()
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode) and os.access(canonical, os.X_OK):
            return canonical
    raise SystemExit(
        "public Git command was not found at a fixed platform location; "
        "pass --public-git-command with an absolute native Git executable"
    )


def exact_source(public_git: Path) -> tuple[str, str]:
    git = str(public_git)
    status = run(git, "status", "--porcelain", "--untracked-files=normal")
    if status:
        raise SystemExit("release construction requires a clean checkout")
    commit = run(git, "rev-parse", "HEAD")
    timestamp = run(git, "show", "-s", "--format=%ct", "HEAD")
    if len(commit) != 40 or not timestamp.isdigit():
        raise SystemExit("could not resolve exact source revision metadata")
    return commit, timestamp


def product_versions() -> dict[str, str]:
    metadata = json.loads(
        run("cargo", "metadata", "--no-deps", "--format-version", "1")
    )
    versions = {
        package["name"]: package["version"]
        for package in metadata["packages"]
        if package["name"] in PRODUCTS
    }
    if set(versions) != set(PRODUCTS):
        raise SystemExit(f"release version metadata is incomplete: {sorted(versions)}")
    return versions


def target_id() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    os_name = {"linux": "linux", "darwin": "macos", "windows": "windows"}.get(system)
    arch = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "aarch64": "aarch64",
        "arm64": "aarch64",
    }.get(machine)
    if os_name is None or arch is None:
        raise SystemExit(f"unsupported release builder platform: {system}-{machine}")
    return f"{os_name}-{arch}"


def manifest_generations(
    values: list[str], products: tuple[str, ...]
) -> dict[str, int]:
    if len(values) == 1 and "=" not in values[0]:
        try:
            generation = int(values[0])
        except ValueError as exc:
            raise SystemExit("manifest generation must be a positive integer") from exc
        if generation < 1:
            raise SystemExit("manifest generation must be a positive integer")
        return {product: generation for product in products}

    generations: dict[str, int] = {}
    for value in values:
        product, separator, raw_generation = value.partition("=")
        if not separator or product not in products or product in generations:
            raise SystemExit(
                "manifest generations must name each selected product exactly once"
            )
        try:
            generation = int(raw_generation)
        except ValueError as exc:
            raise SystemExit("manifest generation must be a positive integer") from exc
        if generation < 1:
            raise SystemExit("manifest generation must be a positive integer")
        generations[product] = generation
    if set(generations) != set(products):
        raise SystemExit(
            "manifest generations must name each selected product exactly once"
        )
    return generations


def release_environment(commit: str, timestamp: str, output: Path) -> dict[str, str]:
    """Return a deterministic build environment without host-local path metadata."""
    remaps = (
        (ROOT.resolve(), Path("/dev-tools/source")),
        (output.resolve(), Path("/dev-tools/output")),
        (Path.home().resolve(), Path("/dev-tools/home")),
    )
    encoded_rustflags = "\x1f".join(
        f"--remap-path-prefix={source}={destination}" for source, destination in remaps
    )
    environment = dict(os.environ)
    environment.pop("RUSTFLAGS", None)
    environment.pop("CARGO_ENCODED_RUSTFLAGS", None)
    environment.update(
        {
            "CARGO_ENCODED_RUSTFLAGS": encoded_rustflags,
            "DEV_TOOLS_GIT_COMMIT": commit,
            "DEV_AUTH_SOURCE_COMMIT": commit,
            "DEV_TOOLS_GIT_DIRTY": "0",
            "SOURCE_DATE_EPOCH": timestamp,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return environment


def release_artifacts(cargo_target: Path, target: str) -> dict[str, Path]:
    """Resolve every product to its native Cargo release artifact."""
    suffix = ".exe" if target.startswith("windows-") else ""
    return {
        product: cargo_target / "release" / f"{product}{suffix}" for product in PRODUCTS
    }


def cargo_build_command(products: tuple[str, ...]) -> list[str]:
    """Build only the selected native product executables."""
    command = ["cargo", "build", "--release", "--locked"]
    for product in products:
        command.extend(["--bin", product])
    return command


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root-document",
        type=Path,
        default=ROOT / "release-trust/dev-tools-root.json",
    )
    signer = parser.add_mutually_exclusive_group(required=True)
    signer.add_argument("--release-private-key", type=Path)
    signer.add_argument("--release-signer", type=Path)
    parser.add_argument("--release-signer-profile")
    parser.add_argument("--release-key-id")
    parser.add_argument(
        "--public-git-command",
        type=Path,
        help=(
            "absolute native Git executable used only for public source identity; "
            "fixed platform locations are tried when omitted"
        ),
    )
    parser.add_argument(
        "--trusted-root-public-key",
        type=Path,
        default=ROOT / "crates/update-all/trust/root-public-key.txt",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--manifest-generation",
        required=True,
        action="append",
        help=(
            "positive generation for all selected products, or repeat "
            "PRODUCT=GENERATION for independent generations"
        ),
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--product",
        dest="products",
        action="append",
        choices=PRODUCTS,
        help="product to build and sign; repeat to select multiple (default: all)",
    )
    return parser.parse_args()


def release_signer_arguments(args: argparse.Namespace) -> list[str]:
    if args.release_private_key is not None:
        if args.release_signer_profile is not None or args.release_key_id is not None:
            raise SystemExit(
                "external signer profile and key identifier require --release-signer"
            )
        return ["--release-private-key", str(args.release_private_key)]
    if (
        args.release_signer is None
        or args.release_signer_profile is None
        or args.release_key_id is None
    ):
        raise SystemExit(
            "--release-signer requires --release-signer-profile and --release-key-id"
        )
    return [
        "--release-signer",
        str(args.release_signer),
        "--release-signer-profile",
        args.release_signer_profile,
        "--release-key-id",
        args.release_key_id,
    ]


def main() -> int:
    args = parse_args()
    signer_arguments = release_signer_arguments(args)
    commit, timestamp = exact_source(resolve_public_git(args.public_git_command))
    versions = product_versions()
    products = tuple(dict.fromkeys(args.products or PRODUCTS))
    generations = manifest_generations(args.manifest_generation, products)
    target = target_id()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"release output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    trusted_root = args.trusted_root_public_key.read_text(encoding="ascii").strip()
    if len(trusted_root) != 64:
        raise SystemExit("trusted root public key must be 32-byte hexadecimal")
    try:
        bytes.fromhex(trusted_root)
    except ValueError as exc:
        raise SystemExit("trusted root public key must be 32-byte hexadecimal") from exc
    build_root = output / "build"
    cargo_target = build_root / "cargo-target"
    env = release_environment(commit, timestamp, output)
    env.update(
        {
            "CARGO_TARGET_DIR": str(cargo_target),
            "DEV_TOOLS_TRUST_ROOT_PUBLIC_KEY": trusted_root,
        }
    )
    if products:
        subprocess.run(cargo_build_command(products), cwd=ROOT, env=env, check=True)
    artifacts = release_artifacts(cargo_target, target)
    summaries: list[dict[str, object]] = []
    for product in products:
        destination = output / "releases" / product
        command = [
            sys.executable,
            str(SIGNER),
            "--product",
            product,
            "--version",
            versions[product],
            "--target",
            target,
            "--artifact",
            str(artifacts[product]),
            "--root-document",
            str(args.root_document),
            "--trusted-root-public-key",
            str(args.trusted_root_public_key),
            "--manifest-generation",
            str(generations[product]),
            "--output",
            str(destination),
        ]
        command.extend(signer_arguments)
        if product == "dev-auth":
            command.extend(["--source-commit", commit])
        summaries.append(json.loads(run(*command, env=env)))
    shutil.rmtree(build_root, ignore_errors=True)
    print(
        json.dumps(
            {
                "commit": commit,
                "source_date_epoch": int(timestamp),
                "target": target,
                "versions": {product: versions[product] for product in products},
                "products": summaries,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
