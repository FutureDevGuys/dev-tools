#!/usr/bin/env python3
"""Authorize release keys with an operationally offline Dev Tools root key."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from release_signing import (
    key_id,
    public_hex,
    read_private_key,
    read_public_key,
    root_envelope,
    write_json,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root-private-key", action="append", required=True, type=Path)
    parser.add_argument("--release-public-key", action="append", default=[], type=Path)
    parser.add_argument(
        "--revoked-release-public-key",
        action="append",
        default=[],
        type=Path,
    )
    parser.add_argument("--trusted-root-public-key", required=True, type=Path)
    parser.add_argument("--generation", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.generation < 1:
        raise SystemExit("root generation must be positive")
    if args.output.exists():
        raise SystemExit(f"root document output already exists: {args.output}")
    root_keys = [read_private_key(path) for path in args.root_private_key]
    trusted_root = read_public_key(args.trusted_root_public_key)
    if not any(public_hex(key) == public_hex(trusted_root) for key in root_keys):
        raise SystemExit("no root private key matches the compiled trust root")
    active = [read_public_key(path) for path in args.release_public_key]
    revoked = [read_public_key(path) for path in args.revoked_release_public_key]
    if not active:
        raise SystemExit("at least one active release public key is required")
    records = [
        {
            "key_id": key_id("release", key),
            "public_key": public_hex(key),
            "revoked": is_revoked,
        }
        for is_revoked, keys in ((False, active), (True, revoked))
        for key in keys
    ]
    identities = [str(record["key_id"]) for record in records]
    if len(identities) != len(set(identities)):
        raise SystemExit("release public keys must be unique")
    records.sort(key=lambda record: str(record["key_id"]))
    document = {
        "schema": "dev-tools-root-v1",
        "generation": args.generation,
        "release_keys": records,
    }
    write_json(args.output, root_envelope(document, root_keys))
    print(
        json.dumps(
            {
                "generation": args.generation,
                "release_keys": len(active),
                "revoked_release_keys": len(revoked),
                "root_signatures": len(root_keys),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
