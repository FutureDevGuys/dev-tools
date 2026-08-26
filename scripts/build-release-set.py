#!/usr/bin/env python3
"""Build and sign every Dev Tools product from one exact clean revision."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SIGNER = ROOT / "scripts" / "build-signed-release.py"
PRODUCTS = ("update-all", "dev-cache", "sync-configs", "skills-sync")


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


def exact_source() -> tuple[str, str]:
    status = run("git", "status", "--porcelain", "--untracked-files=normal")
    if status:
        raise SystemExit("release construction requires a clean checkout")
    commit = run("git", "rev-parse", "HEAD")
    timestamp = run("git", "show", "-s", "--format=%ct", "HEAD")
    if len(commit) != 40 or not timestamp.isdigit():
        raise SystemExit("could not resolve exact source revision metadata")
    return commit, timestamp


def product_version() -> str:
    metadata = json.loads(run("cargo", "metadata", "--no-deps", "--format-version", "1"))
    versions = {
        package["name"]: package["version"]
        for package in metadata["packages"]
        if package["name"] in PRODUCTS
    }
    sync_metadata = tomllib.loads(
        (ROOT / "sync-configs/pyproject.toml").read_text(encoding="utf-8")
    )
    versions["sync-configs"] = str(sync_metadata["project"]["version"])
    if set(versions) != set(PRODUCTS):
        raise SystemExit(f"release version metadata is incomplete: {sorted(versions)}")
    unique = set(versions.values())
    if len(unique) != 1:
        raise SystemExit(f"product versions must match for a release set: {versions}")
    return unique.pop()


def target_id() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    os_name = {"linux": "linux", "windows": "windows"}.get(system)
    arch = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64"}.get(
        machine
    )
    if os_name is None or arch is None:
        raise SystemExit(f"unsupported release builder platform: {system}-{machine}")
    return f"{os_name}-{arch}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root-document", required=True, type=Path)
    parser.add_argument("--release-private-key", required=True, type=Path)
    parser.add_argument(
        "--trusted-root-public-key",
        type=Path,
        default=ROOT / "crates/update-all/trust/root-public-key.txt",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--manifest-generation", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    commit, timestamp = exact_source()
    version = product_version()
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
    env = {
        **os.environ,
        "CARGO_TARGET_DIR": str(cargo_target),
        "DEV_TOOLS_GIT_COMMIT": commit,
        "DEV_TOOLS_GIT_DIRTY": "0",
        "DEV_TOOLS_TRUST_ROOT_PUBLIC_KEY": trusted_root,
        "SOURCE_DATE_EPOCH": timestamp,
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    subprocess.run(
        [
            "cargo",
            "build",
            "--release",
            "--locked",
            "--bin",
            "update-all",
            "--bin",
            "dev-cache",
            "--bin",
            "skills-sync",
        ],
        cwd=ROOT,
        env=env,
        check=True,
    )
    subprocess.run(
        [sys.executable, str(ROOT / "sync-configs/scripts/build_zipapp.py")],
        cwd=ROOT,
        env=env,
        check=True,
    )
    suffix = ".exe" if target.startswith("windows-") else ""
    artifacts = {
        "update-all": cargo_target / "release" / f"update-all{suffix}",
        "dev-cache": cargo_target / "release" / f"dev-cache{suffix}",
        "skills-sync": cargo_target / "release" / f"skills-sync{suffix}",
        "sync-configs": ROOT / f"sync-configs/dist/sync-configs-{version}.pyz",
    }
    summaries: list[dict[str, object]] = []
    for product in PRODUCTS:
        destination = output / "releases" / product
        command = [
            sys.executable,
            str(SIGNER),
            "--product",
            product,
            "--version",
            version,
            "--target",
            target,
            "--artifact",
            str(artifacts[product]),
            "--root-document",
            str(args.root_document),
            "--release-private-key",
            str(args.release_private_key),
            "--trusted-root-public-key",
            str(args.trusted_root_public_key),
            "--manifest-generation",
            str(args.manifest_generation),
            "--output",
            str(destination),
        ]
        summaries.append(json.loads(run(*command, env=env)))
    shutil.rmtree(build_root)
    print(
        json.dumps(
            {
                "commit": commit,
                "source_date_epoch": int(timestamp),
                "target": target,
                "version": version,
                "products": summaries,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
