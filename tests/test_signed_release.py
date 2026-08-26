from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build-signed-release.py"


def write_key(path: Path, key: Ed25519PrivateKey) -> None:
    path.write_text(key.private_bytes_raw().hex(), encoding="ascii")
    path.chmod(0o600)


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
    trust = tmp_path / "root.pub"
    trust.write_text(root.public_key().public_bytes_raw().hex() + "\n", encoding="ascii")
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
                "--root-private-key",
                str(root_file),
                "--release-private-key",
                str(release_file),
                "--trusted-root-public-key",
                str(trust),
                "--root-generation",
                "1",
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
    release_file = tmp_path / "release.key"
    artifact = tmp_path / "update-all"
    trust = tmp_path / "root.pub"
    write_key(current_file, current)
    write_key(next_file, next_key)
    write_key(release_file, release)
    artifact.write_bytes(b"release artifact")
    trust.write_text(current.public_key().public_bytes_raw().hex() + "\n", encoding="ascii")
    output = tmp_path / "release"

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--product",
            "update-all",
            "--version",
            "1.2.3",
            "--target",
            "linux-x86_64",
            "--artifact",
            str(artifact),
            "--root-private-key",
            str(current_file),
            "--additional-root-private-key",
            str(next_file),
            "--release-private-key",
            str(release_file),
            "--trusted-root-public-key",
            str(trust),
            "--root-generation",
            "2",
            "--manifest-generation",
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
    envelope = json.loads((output / "dev-tools-root.json").read_text())
    assert len(envelope["signatures"]) == 2
    assert all(row["key_id"].startswith("root-") for row in envelope["signatures"])
