from __future__ import annotations

import json
import importlib.util
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
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


def load_release_set_module():
    path = ROOT / "scripts/build-release-set.py"
    spec = importlib.util.spec_from_file_location("build_release_set", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_builder_remaps_checkout_output_and_home_paths(tmp_path: Path) -> None:
    module = load_release_set_module()
    environment = module.release_environment("a" * 40, "1", tmp_path)
    flags = environment["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
    assert f"--remap-path-prefix={ROOT.resolve()}=/dev-tools/source" in flags
    assert f"--remap-path-prefix={tmp_path.resolve()}=/dev-tools/output" in flags
    assert f"--remap-path-prefix={Path.home().resolve()}=/dev-tools/home" in flags
    assert "RUSTFLAGS" not in environment
    assert environment["DEV_AUTH_SOURCE_COMMIT"] == "a" * 40


def test_release_builder_captures_zipapp_stdout(monkeypatch) -> None:
    module = load_release_set_module()
    observed = {}

    def fake_run(*args, **kwargs):
        observed.update(kwargs)

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    module.build_sync_configs({"TEST": "1"})
    assert observed["stdout"] is subprocess.PIPE
    assert observed["text"] is True
    assert observed["check"] is True


def test_release_builder_source_identity_uses_the_declared_public_git(
    monkeypatch, tmp_path: Path
) -> None:
    module = load_release_set_module()
    public_git = tmp_path / "git"
    public_git.write_text("fixture", encoding="utf-8")
    public_git.chmod(0o755)
    calls = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        if "rev-parse" in args:
            return "a" * 40
        return "123" if "--format=%ct" in args else ""

    monkeypatch.setattr(module, "run", fake_run)

    assert module.exact_source(public_git) == ("a" * 40, "123")
    assert calls
    assert all(call[0][0] == str(public_git) for call in calls)


def test_release_builder_public_git_is_absolute_executable_and_path_independent(
    monkeypatch, tmp_path: Path
) -> None:
    module = load_release_set_module()
    public_git = tmp_path / "native-git"
    public_git.write_text("fixture", encoding="utf-8")
    public_git.chmod(0o755)
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    (attacker / "git").write_text("fixture", encoding="utf-8")
    (attacker / "git").chmod(0o755)
    monkeypatch.setenv("PATH", str(attacker))

    assert module.resolve_public_git(public_git) == public_git.resolve()
    with pytest.raises(SystemExit, match="absolute executable"):
        module.resolve_public_git(Path("git"))


def test_release_builder_keeps_independent_product_versions() -> None:
    module = load_release_set_module()
    versions = module.product_versions()

    expected = {
        product: tomllib.loads(
            (ROOT / "crates" / product / "Cargo.toml").read_text(encoding="utf-8")
        )["package"]["version"]
        for product in ("update-all", "dev-auth", "dev-cache", "skills-sync")
    }
    expected["sync-configs"] = tomllib.loads(
        (ROOT / "sync-configs" / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]

    assert versions == expected


def test_release_builder_maps_independent_manifest_generations() -> None:
    module = load_release_set_module()

    assert module.manifest_generations(["6"], ("update-all",)) == {
        "update-all": 6
    }
    assert module.manifest_generations(
        ["update-all=6", "dev-cache=9"],
        ("update-all", "dev-cache"),
    ) == {"update-all": 6, "dev-cache": 9}


def test_release_builder_names_linux_macos_and_windows_targets(monkeypatch) -> None:
    module = load_release_set_module()
    for system, machine, expected in [
        ("Linux", "x86_64", "linux-x86_64"),
        ("Darwin", "arm64", "macos-aarch64"),
        ("Windows", "AMD64", "windows-x86_64"),
    ]:
        monkeypatch.setattr(module.platform, "system", lambda value=system: value)
        monkeypatch.setattr(module.platform, "machine", lambda value=machine: value)
        assert module.target_id() == expected


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
    artifact = tmp_path / "dev-auth"
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
                "dev-auth",
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
                "--source-commit",
                "a" * 40,
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
    for filename in ("dev-tools-root.json", "dev-auth-stable.json"):
        assert (outputs[0] / filename).read_bytes() == (outputs[1] / filename).read_bytes()
    manifest = json.loads((outputs[0] / "dev-auth-stable.json").read_text())
    signed = manifest["signed"]
    assert signed["product"] == "dev-auth"
    assert signed["schema"] == "dev-auth-product-v2"
    assert signed["generation"] == 2
    assert signed["source_commit"] == "a" * 40
    assert signed["artifacts"]["linux-x86_64"]["length"] == len(b"fixture artifact")
    assert (outputs[0] / "dev-auth-1.2.3-linux-x86_64").stat().st_mode & 0o111


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
