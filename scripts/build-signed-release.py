#!/usr/bin/env python3
"""Build one authenticated Dev Tools product release from an exact artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from urllib.parse import quote

from release_signing import (
    canonical_json,
    envelope,
    load_root_document,
    read_private_key,
    read_public_key,
    require_authorized_release_key,
    verify_root_document,
    write_json,
)


PRODUCTS = {"update-all", "dev-auth", "dev-cache", "sync-configs", "skills-sync"}
OWNER = "FutureDevGuys"
REPOSITORY = "dev-tools"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--product", required=True, choices=sorted(PRODUCTS))
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--root-document", required=True, type=Path)
    parser.add_argument("--release-private-key", required=True, type=Path)
    parser.add_argument(
        "--trusted-root-public-key",
        type=Path,
        default=Path(__file__).parents[1] / "crates/update-all/trust/root-public-key.txt",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--manifest-generation", required=True, type=int)
    parser.add_argument("--source-commit")
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.artifact.is_file():
        raise SystemExit(f"artifact does not exist: {args.artifact}")
    if args.manifest_generation < 1:
        raise SystemExit("manifest generation must be positive")
    if args.product == "dev-auth":
        if args.source_commit is None or len(args.source_commit) != 40:
            raise SystemExit("dev-auth source commit must be 40 hexadecimal characters")
        try:
            bytes.fromhex(args.source_commit)
        except ValueError as exc:
            raise SystemExit(
                "dev-auth source commit must be 40 hexadecimal characters"
            ) from exc
    elif args.source_commit is not None:
        raise SystemExit("source commit is supported only by the dev-auth v2 manifest")

    release_key = read_private_key(args.release_private_key)
    trusted_root = read_public_key(args.trusted_root_public_key)
    root_document = load_root_document(args.root_document)
    verify_root_document(root_document, trusted_root)
    release_id = require_authorized_release_key(root_document, release_key)

    tag = f"{args.product}/v{args.version}"
    suffix = ".pyz" if args.product == "sync-configs" else (".exe" if args.target.startswith("windows-") else "")
    artifact_name = f"{args.product}-{args.version}-{args.target}{suffix}"
    artifact_bytes = args.artifact.read_bytes()
    artifact_digest = hashlib.sha256(artifact_bytes).hexdigest()
    artifact_url = (
        f"https://github.com/{OWNER}/{REPOSITORY}/releases/download/"
        f"{quote(tag, safe='')}/{quote(artifact_name)}"
    )

    manifest = {
        "schema": (
            "dev-auth-product-v2"
            if args.product == "dev-auth"
            else "dev-tools-product-v1"
        ),
        "product": args.product,
        "generation": args.manifest_generation,
        "version": args.version,
        "engine_protocol": 1,
        "artifacts": {
            args.target: {
                "url": artifact_url,
                "length": len(artifact_bytes),
                "sha256": artifact_digest,
            }
        },
    }
    if args.product == "dev-auth":
        manifest["source_commit"] = args.source_commit.lower()

    destination = args.output.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise SystemExit(f"release output directory is not empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(args.artifact, destination / artifact_name)
    write_json(
        destination / "dev-tools-root.json",
        root_document,
    )
    write_json(
        destination / f"{args.product}-stable.json",
        envelope(manifest, release_id, release_key),
    )
    summary = {
        "artifact": artifact_name,
        "length": len(artifact_bytes),
        "product": args.product,
        "sha256": artifact_digest,
        "tag": tag,
        "target": args.target,
        "version": args.version,
    }
    if args.product == "dev-auth":
        summary["source_commit"] = args.source_commit.lower()
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
