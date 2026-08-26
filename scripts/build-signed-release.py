#!/usr/bin/env python3
"""Build one authenticated Dev Tools product release from an exact artifact."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import stat
import sys
from pathlib import Path
from urllib.parse import quote

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError as exc:  # pragma: no cover - operator prerequisite
    raise SystemExit("cryptography with Ed25519 support is required") from exc


PRODUCTS = {"update-all", "dev-cache", "sync-configs", "skills-sync"}
OWNER = "FutureDevGuys"
REPOSITORY = "dev-tools"


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def read_private_key(path: Path) -> Ed25519PrivateKey:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise SystemExit(f"private key file must be owner-only: {path}")
    raw = path.read_text(encoding="ascii").strip()
    try:
        secret = bytes.fromhex(raw)
    except ValueError as exc:
        raise SystemExit(f"private key file is not 32-byte hexadecimal: {path}") from exc
    if len(secret) != 32:
        raise SystemExit(f"private key file is not 32-byte hexadecimal: {path}")
    return Ed25519PrivateKey.from_private_bytes(secret)


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes_raw().hex()


def key_id(prefix: str, key: Ed25519PrivateKey) -> str:
    digest = hashlib.sha256(bytes.fromhex(public_hex(key))).hexdigest()[:16]
    return f"{prefix}-{digest}"


def envelope(document: dict[str, object], key_name: str, key: Ed25519PrivateKey) -> dict[str, object]:
    signature = base64.b64encode(key.sign(canonical_json(document))).decode("ascii")
    return {
        "signed": document,
        "signatures": [{"key_id": key_name, "signature": signature}],
    }


def root_envelope(
    document: dict[str, object], keys: list[Ed25519PrivateKey]
) -> dict[str, object]:
    signed = canonical_json(document)
    return {
        "signed": document,
        "signatures": [
            {
                "key_id": key_id("root", key),
                "signature": base64.b64encode(key.sign(signed)).decode("ascii"),
            }
            for key in keys
        ],
    }


def write_json(path: Path, value: object) -> None:
    path.write_bytes(canonical_json(value) + b"\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--product", required=True, choices=sorted(PRODUCTS))
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--root-private-key", required=True, type=Path)
    parser.add_argument(
        "--additional-root-private-key",
        action="append",
        default=[],
        type=Path,
        help="Add a next-root signature for a sequential trust-root rotation",
    )
    parser.add_argument("--release-private-key", required=True, type=Path)
    parser.add_argument(
        "--trusted-root-public-key",
        type=Path,
        default=Path(__file__).parents[1] / "crates/update-all/trust/root-public-key.txt",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--root-generation", required=True, type=int)
    parser.add_argument("--manifest-generation", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.artifact.is_file():
        raise SystemExit(f"artifact does not exist: {args.artifact}")
    if args.root_generation < 1 or args.manifest_generation < 1:
        raise SystemExit("release generations must be positive")

    root_key = read_private_key(args.root_private_key)
    additional_root_keys = [read_private_key(path) for path in args.additional_root_private_key]
    release_key = read_private_key(args.release_private_key)
    trusted_root = args.trusted_root_public_key.read_text(encoding="ascii").strip()
    if public_hex(root_key) != trusted_root:
        raise SystemExit("root private key does not match the compiled trust root")

    tag = f"{args.product}/v{args.version}"
    suffix = ".pyz" if args.product == "sync-configs" else (".exe" if args.target.startswith("windows-") else "")
    artifact_name = f"{args.product}-{args.version}-{args.target}{suffix}"
    artifact_bytes = args.artifact.read_bytes()
    artifact_digest = hashlib.sha256(artifact_bytes).hexdigest()
    artifact_url = (
        f"https://github.com/{OWNER}/{REPOSITORY}/releases/download/"
        f"{quote(tag, safe='')}/{quote(artifact_name)}"
    )

    release_id = key_id("release", release_key)
    root_document = {
        "schema": "dev-tools-root-v1",
        "generation": args.root_generation,
        "release_keys": [
            {
                "key_id": release_id,
                "public_key": public_hex(release_key),
                "revoked": False,
            }
        ],
    }
    manifest = {
        "schema": "dev-tools-product-v1",
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

    destination = args.output.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise SystemExit(f"release output directory is not empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.artifact, destination / artifact_name)
    write_json(
        destination / "dev-tools-root.json",
        root_envelope(root_document, [root_key, *additional_root_keys]),
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
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
