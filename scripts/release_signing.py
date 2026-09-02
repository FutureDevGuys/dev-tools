"""Shared deterministic Ed25519 release metadata helpers."""

from __future__ import annotations

import base64
import hashlib
import json
import stat
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _read_hex(path: Path, *, label: str) -> bytes:
    raw = path.read_text(encoding="ascii").strip()
    try:
        value = bytes.fromhex(raw)
    except ValueError as exc:
        raise SystemExit(f"{label} is not 32-byte hexadecimal: {path}") from exc
    if len(value) != 32:
        raise SystemExit(f"{label} is not 32-byte hexadecimal: {path}")
    return value


def read_private_key(path: Path) -> Ed25519PrivateKey:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise SystemExit(f"private key file must be owner-only: {path}")
    return Ed25519PrivateKey.from_private_bytes(_read_hex(path, label="private key file"))


def read_public_key(path: Path) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(_read_hex(path, label="public key file"))


def public_bytes(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    if isinstance(key, Ed25519PrivateKey):
        return key.public_key().public_bytes_raw()
    return key.public_bytes_raw()


def public_hex(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    return public_bytes(key).hex()


def key_id(prefix: str, key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    digest = hashlib.sha256(public_bytes(key)).hexdigest()[:16]
    return f"{prefix}-{digest}"


def envelope(
    document: dict[str, object],
    key_name: str,
    key: Ed25519PrivateKey,
) -> dict[str, object]:
    signature = base64.b64encode(key.sign(canonical_json(document))).decode("ascii")
    return {
        "signed": document,
        "signatures": [{"key_id": key_name, "signature": signature}],
    }


def root_envelope(
    document: dict[str, object],
    keys: list[Ed25519PrivateKey],
) -> dict[str, object]:
    signed = canonical_json(document)
    signatures = [
        {
            "key_id": key_id("root", key),
            "signature": base64.b64encode(key.sign(signed)).decode("ascii"),
        }
        for key in keys
    ]
    signatures.sort(key=lambda row: str(row["key_id"]))
    return {"signed": document, "signatures": signatures}


def write_json(path: Path, value: object) -> None:
    path.write_bytes(canonical_json(value) + b"\n")


def load_root_document(path: Path) -> dict[str, object]:
    try:
        envelope_value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"root document is not valid JSON: {path}") from exc
    if not isinstance(envelope_value, dict) or set(envelope_value) != {
        "signed",
        "signatures",
    }:
        raise SystemExit("root document envelope has unsupported fields")
    signed = envelope_value["signed"]
    signatures = envelope_value["signatures"]
    if not isinstance(signed, dict) or set(signed) != {
        "schema",
        "generation",
        "release_keys",
    }:
        raise SystemExit("root document has unsupported fields")
    if signed["schema"] != "dev-tools-root-v1":
        raise SystemExit("root document schema is unsupported")
    generation = signed["generation"]
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise SystemExit("root document generation must be positive")
    release_keys = signed["release_keys"]
    if not isinstance(release_keys, list) or not release_keys:
        raise SystemExit("root document must authorize at least one release key")
    seen: set[str] = set()
    for record in release_keys:
        if not isinstance(record, dict) or set(record) != {
            "key_id",
            "public_key",
            "revoked",
        }:
            raise SystemExit("root document release key has unsupported fields")
        public = record["public_key"]
        if not isinstance(public, str):
            raise SystemExit("root document release public key is invalid")
        try:
            public_bytes_value = bytes.fromhex(public)
        except ValueError as exc:
            raise SystemExit("root document release public key is invalid") from exc
        if len(public_bytes_value) != 32:
            raise SystemExit("root document release public key is invalid")
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes_value)
        expected_id = key_id("release", public_key)
        if record["key_id"] != expected_id or expected_id in seen:
            raise SystemExit("root document release key identity is invalid or duplicated")
        if not isinstance(record["revoked"], bool):
            raise SystemExit("root document release revocation state is invalid")
        seen.add(expected_id)
    if not isinstance(signatures, list) or not signatures:
        raise SystemExit("root document has no signatures")
    for signature in signatures:
        if not isinstance(signature, dict) or set(signature) != {"key_id", "signature"}:
            raise SystemExit("root document signature has unsupported fields")
        if not all(isinstance(signature[field], str) for field in ("key_id", "signature")):
            raise SystemExit("root document signature is invalid")
    return envelope_value


def verify_root_document(
    envelope_value: dict[str, object],
    trusted_root: Ed25519PublicKey,
) -> None:
    signed = canonical_json(envelope_value["signed"])
    for signature in envelope_value["signatures"]:  # type: ignore[union-attr]
        try:
            raw = base64.b64decode(signature["signature"], validate=True)
            trusted_root.verify(raw, signed)
            return
        except (InvalidSignature, ValueError, TypeError):
            continue
    raise SystemExit("root document signature is invalid")


def require_authorized_release_key(
    envelope_value: dict[str, object],
    release_key: Ed25519PrivateKey,
) -> str:
    return require_authorized_release_public_key(envelope_value, release_key.public_key())


def require_authorized_release_public_key(
    envelope_value: dict[str, object],
    release_key: Ed25519PublicKey,
) -> str:
    release_id = key_id("release", release_key)
    release_public = public_hex(release_key)
    signed = envelope_value["signed"]
    for record in signed["release_keys"]:  # type: ignore[index]
        if record["key_id"] == release_id and record["public_key"] == release_public:
            if record["revoked"]:
                raise SystemExit("release key is revoked by the root document")
            return release_id
    raise SystemExit("release key is not authorized by the root document")


def authorized_release_public_key(
    envelope_value: dict[str, object],
    release_id: str,
) -> Ed25519PublicKey:
    signed = envelope_value["signed"]
    for record in signed["release_keys"]:  # type: ignore[index]
        if record["key_id"] != release_id:
            continue
        if record["revoked"]:
            raise SystemExit("release key is revoked by the root document")
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(record["public_key"]))
    raise SystemExit("release key identifier is not authorized by the root document")
