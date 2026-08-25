from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT)
    return subprocess.run(
        [sys.executable, "-m", "syncconfigs.cli", *args],
        cwd=PROJECT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def test_version_has_canonical_product_identity() -> None:
    result = run_cli("--version")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "sync-configs 0.1.0"


def write_manifest(path: Path, source: Path, target: Path, marker: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "default_mode: copy",
                "entries:",
                "  - name: editor",
                "    profiles: [desktop, linux]",
                f"    source: {source}",
                f"    target: {target}",
                f"    pre_script: {sys.executable} -c \"open(r'{marker}', 'w').write('pre')\"",
                f"    post_script: {sys.executable} -c \"open(r'{marker}', 'a').write('post')\"",
                "",
            ]
        ),
        encoding="utf-8",
    )


def test_dry_run_is_structured_and_executes_no_hooks_or_writes(tmp_path: Path) -> None:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    marker = tmp_path / "hook-ran"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("theme = 'dark'\n", encoding="utf-8")
    write_manifest(manifest, source, target, marker)

    result = run_cli(
        "--config",
        str(manifest),
        "--profile",
        "desktop",
        "--dry-run",
        "--format",
        "json",
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload == {
        "dry_run": True,
        "exit_code": 0,
        "outcome": "completed",
        "profiles": ["desktop"],
        "schema_version": 1,
    }
    assert not target.exists()
    assert not marker.exists()


def test_external_profile_map_preserves_order_and_deduplicates(tmp_path: Path) -> None:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    marker = tmp_path / "hook-ran"
    manifest = tmp_path / "manifest.yaml"
    profile_map = tmp_path / "profiles.yaml"
    source.write_text("theme = 'dark'\n", encoding="utf-8")
    write_manifest(manifest, source, target, marker)
    profile_map.write_text(
        "profiles:\n  workstation: [linux, desktop, linux]\n",
        encoding="utf-8",
    )

    result = run_cli(
        "--config",
        str(manifest),
        "--profile-map",
        str(profile_map),
        "--host-profile",
        "workstation",
        "--profile",
        "desktop",
        "--validate",
        "--format",
        "json",
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["profiles"] == ["linux", "desktop"]
    assert not target.exists()
    assert not marker.exists()


def test_external_profile_map_can_select_a_generic_nested_list(tmp_path: Path) -> None:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    marker = tmp_path / "hook-ran"
    manifest = tmp_path / "manifest.yaml"
    profile_map = tmp_path / "profiles.yaml"
    source.write_text("theme = 'dark'\n", encoding="utf-8")
    write_manifest(manifest, source, target, marker)
    profile_map.write_text(
        "profiles:\n  workstation:\n    title: Example\n    selected: [linux, desktop]\n",
        encoding="utf-8",
    )

    result = run_cli(
        "--config",
        str(manifest),
        "--profile-map",
        str(profile_map),
        "--profile-map-field",
        "selected",
        "--host-profile",
        "workstation",
        "--validate",
        "--format",
        "json",
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["profiles"] == ["linux", "desktop"]


def test_copy_convergence_is_idempotent(tmp_path: Path) -> None:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("theme = 'dark'\n", encoding="utf-8")
    manifest.write_text(
        "\n".join(
            [
                "default_mode: copy",
                "entries:",
                "  - name: editor",
                f"    source: {source}",
                f"    target: {target}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    first = run_cli("--config", str(manifest), "--no-color")
    second = run_cli("--config", str(manifest), "--no-color")

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert target.read_text(encoding="utf-8") == source.read_text(encoding="utf-8")
    assert "Performed (1):" in first.stdout
    assert "1 updated, 0 up-to-date" in first.stdout
    assert "0 updated, 1 up-to-date" in second.stdout


def test_help_uses_the_canonical_command_name() -> None:
    result = run_cli("--help")

    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("usage: sync-configs ")
