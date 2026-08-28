from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


PROJECT = Path(__file__).resolve().parents[1]


def write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def sudo_fixture(
    tmp_path: Path, *, authentication_succeeds: bool = True, cached: bool = False
) -> tuple[dict[str, str], Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "sudo.log"
    state = tmp_path / "sudo.state"
    if cached:
        state.touch()
    write_executable(
        fake_bin / "sudo",
        "#!/bin/sh\n"
        "set -eu\n"
        "printf '%s\\n' \"$*\" >> \"$SYNC_CONFIGS_SUDO_LOG\"\n"
        "if [ \"${1:-}\" = -n ] && [ \"${2:-}\" = -v ]; then\n"
        "  [ -f \"$SYNC_CONFIGS_SUDO_STATE\" ]\n"
        "  exit\n"
        "fi\n"
        "if [ \"${1:-}\" = -v ]; then\n"
        + (
            "  touch \"$SYNC_CONFIGS_SUDO_STATE\"\n  exit 0\n"
            if authentication_succeeds
            else "  exit 1\n"
        )
        + "fi\n"
        "if [ \"${1:-}\" = -n ] && [ \"${2:-}\" = -- ]; then\n"
        "  shift 2\n"
        "  [ -f \"$SYNC_CONFIGS_SUDO_STATE\" ] || exit 1\n"
        "  exec \"$@\"\n"
        "fi\n"
        "exit 2\n",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{fake_bin}:{environment['PATH']}",
            "PYTHONPATH": str(PROJECT),
            "SYNC_CONFIGS_SUDO_LOG": str(log),
            "SYNC_CONFIGS_SUDO_STATE": str(state),
        }
    )
    return environment, log


def run_cli(manifest: Path, environment: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "syncconfigs.cli",
            "--config",
            str(manifest),
            "--no-color",
            *args,
        ],
        cwd=PROJECT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def write_manifest(
    path: Path,
    source: Path,
    target: Path,
    marker: Path,
    *,
    profiles: str = "",
) -> None:
    path.write_text(
        "\n".join(
            [
                "entries:",
                "  - name: privileged-hooks",
                *([f"    profiles: [{profiles}]"] if profiles else []),
                f"    source: {source}",
                f"    target: {target}",
                "    mode: copy",
                f"    pre_script: {sys.executable} -c \"open(r'{marker}', 'w').write('pre')\"",
                "    pre_script_privilege: sudo",
                f"    post_script: {sys.executable} -c \"open(r'{marker}', 'a').write('post')\"",
                "    post_script_privilege: sudo",
                "    post_script_on_fail: abort",
                "",
            ]
        ),
        encoding="utf-8",
    )


def test_privileged_scripts_authenticate_once_and_reuse_sudo_session(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    marker = tmp_path / "marker"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("managed\n", encoding="utf-8")
    write_manifest(manifest, source, target, marker)
    environment, sudo_log = sudo_fixture(tmp_path)

    result = run_cli(manifest, environment)

    assert result.returncode == 0, result.stderr
    assert target.read_text(encoding="utf-8") == "managed\n"
    assert marker.read_text(encoding="utf-8") == "prepost"
    lines = sudo_log.read_text(encoding="utf-8").splitlines()
    assert lines[0:2] == ["-n -v", "-v"]
    assert len([line for line in lines if line.startswith("-n -- ")]) == 2
    assert lines.count("-v") == 1


def test_existing_native_sudo_timestamp_is_reused_without_prompt(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    marker = tmp_path / "marker"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("managed\n", encoding="utf-8")
    write_manifest(manifest, source, target, marker)
    environment, sudo_log = sudo_fixture(tmp_path, cached=True)

    result = run_cli(manifest, environment)

    assert result.returncode == 0, result.stderr
    lines = sudo_log.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "-n -v"
    assert "-v" not in lines
    assert len([line for line in lines if line.startswith("-n -- ")]) == 2


def test_disabled_or_dry_run_privileged_scripts_never_request_sudo(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    marker = tmp_path / "marker"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("managed\n", encoding="utf-8")
    write_manifest(manifest, source, target, marker, profiles="enabled")
    environment, sudo_log = sudo_fixture(tmp_path)

    disabled = run_cli(manifest, environment, "--profile", "different")
    dry_run = run_cli(manifest, environment, "--profile", "enabled", "--dry-run")

    assert disabled.returncode == 0, disabled.stderr
    assert dry_run.returncode == 0, dry_run.stderr
    assert not sudo_log.exists()
    assert not target.exists()
    assert not marker.exists()


def test_sudo_authentication_failure_stops_before_hooks_or_sync(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    marker = tmp_path / "marker"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("managed\n", encoding="utf-8")
    write_manifest(manifest, source, target, marker)
    environment, sudo_log = sudo_fixture(tmp_path, authentication_succeeds=False)

    result = run_cli(manifest, environment)

    assert result.returncode == 1
    assert "unable to authenticate one shared sudo session" in result.stderr
    assert sudo_log.read_text(encoding="utf-8").splitlines() == ["-n -v", "-v"]
    assert not target.exists()
    assert not marker.exists()


def test_invalid_or_orphan_script_privilege_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.write_text("managed\n", encoding="utf-8")
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT)
    for field, value, expected in (
        ("pre_script_privilege", "root", "must be one of"),
        ("post_script_privilege", "sudo", "requires post_script"),
    ):
        manifest = tmp_path / f"{field}-{value}.yaml"
        manifest.write_text(
            "\n".join(
                [
                    "entries:",
                    "  - name: invalid",
                    f"    source: {source}",
                    f"    target: {target}",
                    f"    {field}: {value}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        result = run_cli(manifest, environment, "--validate")
        assert result.returncode == 1
        assert expected in result.stderr
