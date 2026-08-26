from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build-signed-release.py"
ROOT_SCRIPT = ROOT / "scripts" / "build-root-document.py"
SCRIPTS_ROOT = ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from release_signing import (  # noqa: E402
    load_root_document,
    read_public_key,
    verify_root_document,
)


def write_key(path: Path, key: Ed25519PrivateKey) -> None:
    path.write_text(key.private_bytes_raw().hex(), encoding="ascii")
    path.chmod(0o600)


def write_public_key(path: Path, key: Ed25519PrivateKey) -> None:
    path.write_text(key.public_key().public_bytes_raw().hex() + "\n", encoding="ascii")


def test_tracked_root_document_matches_compiled_trust_root() -> None:
    root_document = load_root_document(ROOT / "release-trust/dev-tools-root.json")
    trusted_root = read_public_key(
        ROOT / "crates/update-all/trust/root-public-key.txt"
    )
    verify_root_document(root_document, trusted_root)
    active = [
        record
        for record in root_document["signed"]["release_keys"]
        if not record["revoked"]
    ]
    assert len(active) == 1


def build_root_document(
    tmp_path: Path,
    *,
    root_files: list[Path],
    release: Ed25519PrivateKey,
    generation: int = 1,
) -> tuple[Path, Path]:
    trust = tmp_path / "root.pub"
    release_public = tmp_path / "release.pub"
    document = tmp_path / "dev-tools-root.json"
    write_public_key(trust, Ed25519PrivateKey.from_private_bytes(bytes([3]) * 32))
    write_public_key(release_public, release)
    command = [
        sys.executable,
        str(ROOT_SCRIPT),
        "--trusted-root-public-key",
        str(trust),
        "--release-public-key",
        str(release_public),
        "--generation",
        str(generation),
        "--output",
        str(document),
    ]
    for root_file in root_files:
        command.extend(["--root-private-key", str(root_file)])
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    return document, trust


def test_release_recipe_is_deterministic_and_binds_artifact(tmp_path: Path) -> None:
    root = Ed25519PrivateKey.from_private_bytes(bytes([3]) * 32)
    release = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
    root_file = tmp_path / "root.key"
    release_file = tmp_path / "release.key"
    artifact = tmp_path / "dev-cache"
    write_key(root_file, root)
    write_key(release_file, release)
    artifact.write_bytes(b"fixture artifact")
    artifact.chmod(0o755)
    root_document, trust = build_root_document(
        tmp_path,
        root_files=[root_file],
        release=release,
    )
    outputs = []
    for name in ("one", "two"):
        output = tmp_path / name
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--product",
                "dev-cache",
                "--version",
                "1.2.3",
                "--target",
                "linux-x86_64",
                "--artifact",
                str(artifact),
                "--root-document",
                str(root_document),
                "--release-private-key",
                str(release_file),
                "--trusted-root-public-key",
                str(trust),
                "--manifest-generation",
                "2",
                "--output",
                str(output),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        assert result.returncode == 0, result.stderr
        outputs.append(output)
    for filename in ("dev-tools-root.json", "dev-cache-stable.json"):
        assert (outputs[0] / filename).read_bytes() == (outputs[1] / filename).read_bytes()
    manifest = json.loads((outputs[0] / "dev-cache-stable.json").read_text())
    signed = manifest["signed"]
    assert signed["product"] == "dev-cache"
    assert signed["generation"] == 2
    assert signed["artifacts"]["linux-x86_64"]["length"] == len(b"fixture artifact")
    assert (outputs[0] / "dev-cache-1.2.3-linux-x86_64").stat().st_mode & 0o111


def test_release_recipe_emits_dual_root_signatures_for_rotation(tmp_path: Path) -> None:
    current = Ed25519PrivateKey.from_private_bytes(bytes([11]) * 32)
    next_key = Ed25519PrivateKey.from_private_bytes(bytes([13]) * 32)
    release = Ed25519PrivateKey.from_private_bytes(bytes([17]) * 32)
    current_file = tmp_path / "current.key"
    next_file = tmp_path / "next.key"
    trust = tmp_path / "root.pub"
    write_key(current_file, current)
    write_key(next_file, next_key)
    trust.write_text(current.public_key().public_bytes_raw().hex() + "\n", encoding="ascii")
    release_public = tmp_path / "release.pub"
    write_public_key(release_public, release)
    output = tmp_path / "dev-tools-root.json"

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT_SCRIPT),
            "--root-private-key",
            str(current_file),
            "--root-private-key",
            str(next_file),
            "--release-public-key",
            str(release_public),
            "--trusted-root-public-key",
            str(trust),
            "--generation",
            "2",
            "--output",
            str(output),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    envelope = json.loads(output.read_text())
    assert len(envelope["signatures"]) == 2
    assert all(row["key_id"].startswith("root-") for row in envelope["signatures"])


def test_product_release_rejects_a_key_not_authorized_by_root_document(tmp_path: Path) -> None:
    root = Ed25519PrivateKey.from_private_bytes(bytes([3]) * 32)
    authorized = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
    unauthorized = Ed25519PrivateKey.from_private_bytes(bytes([19]) * 32)
    root_file = tmp_path / "root.key"
    unauthorized_file = tmp_path / "unauthorized.key"
    artifact = tmp_path / "dev-cache"
    write_key(root_file, root)
    write_key(unauthorized_file, unauthorized)
    artifact.write_bytes(b"fixture artifact")
    root_document, trust = build_root_document(
        tmp_path,
        root_files=[root_file],
        release=authorized,
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--product",
            "dev-cache",
            "--version",
            "1.2.3",
            "--target",
            "linux-x86_64",
            "--artifact",
            str(artifact),
            "--root-document",
            str(root_document),
            "--release-private-key",
            str(unauthorized_file),
            "--trusted-root-public-key",
            str(trust),
            "--manifest-generation",
            "1",
            "--output",
            str(tmp_path / "release"),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "not authorized" in result.stderr
