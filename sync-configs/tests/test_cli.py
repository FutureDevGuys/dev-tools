from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
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
    metadata = tomllib.loads((PROJECT / "pyproject.toml").read_text(encoding="utf-8"))
    assert result.stdout.strip() == f"sync-configs {metadata['project']['version']}"


def test_toml_overlay_reports_commented_paths_without_activating_or_disclosing_values(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.toml"
    target = tmp_path / "target.toml"
    manifest = tmp_path / "manifest.yaml"
    source.write_text(
        '[model_providers.bridge]\nenv_key = "SOURCE_PRIVATE"\nmodel = "new"\n',
        encoding="utf-8",
    )
    target.write_text(
        '[model_providers.bridge]\n  # env_key = "TARGET_PRIVATE"\nauth = "STALE_PRIVATE"\n',
        encoding="utf-8",
    )
    manifest.write_text(
        "\n".join(
            [
                "entries:",
                "  - name: codex",
                f"    source: {source}",
                f"    target: {target}",
                "    mode: toml_overlay",
                "    commented_target_policy: respect",
                "    mutually_exclusive_sibling_keys:",
                "      - under: model_providers.*",
                "        keys: [auth, env_key]",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = run_cli("--config", str(manifest), "--no-color")

    assert result.returncode == 0, result.stderr
    assert "Suppressed by comments" in result.stdout
    assert "model_providers.bridge.env_key" in result.stdout
    assert "SOURCE_PRIVATE" not in result.stdout
    assert "TARGET_PRIVATE" not in result.stdout
    assert "STALE_PRIVATE" not in result.stdout
    parsed = tomllib.loads(target.read_text(encoding="utf-8"))["model_providers"]["bridge"]
    assert "env_key" not in parsed
    assert parsed["auth"] == "STALE_PRIVATE"
    assert parsed["model"] == "new"


def test_json_state_precondition_blocks_read_only_with_exact_remediation(tmp_path: Path) -> None:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    state = tmp_path / "state.json"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("managed\n", encoding="utf-8")
    manifest.write_text(
        "\n".join(
            [
                "state_preconditions:",
                "  - type: json_fields",
                f"    path: {state}",
                "    fields:",
                "      current_version: 1",
                "      pending: null",
                "    remediation: Run ./bootstrap.sh --migration-target current",
                "entries:",
                "  - name: fixture",
                f"    source: {source}",
                f"    target: {target}",
                "    mode: copy",
                "",
            ]
        ),
        encoding="utf-8",
    )

    blocked = run_cli("--config", str(manifest), "--dry-run")
    assert blocked.returncode == 1
    assert "Run ./bootstrap.sh --migration-target current" in blocked.stderr
    assert not state.exists()
    assert not target.exists()

    state.write_text('{"current_version": 1, "pending": null}\n', encoding="utf-8")
    current = run_cli("--config", str(manifest), "--dry-run")
    assert current.returncode == 0, current.stderr
    assert not target.exists()


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


def test_external_profile_map_accepts_versioned_caller_metadata(tmp_path: Path) -> None:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    marker = tmp_path / "hook-ran"
    manifest = tmp_path / "manifest.yaml"
    profile_map = tmp_path / "profiles.yaml"
    source.write_text("theme = 'dark'\n", encoding="utf-8")
    write_manifest(manifest, source, target, marker)
    profile_map.write_text(
        "schema_version: 1\nprofiles:\n  workstation:\n    selected: [linux, desktop]\n",
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
