from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys

import pytest

grp = pytest.importorskip("grp")
pwd = pytest.importorskip("pwd")

PROJECT = Path(__file__).resolve().parents[1]


def write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def sudo_fixture(
    tmp_path: Path,
    *,
    drift_source: Path | None = None,
    drift_target: Path | None = None,
    fail_file_install: bool = False,
    drift_before_move: Path | None = None,
    corrupt_after_move: Path | None = None,
) -> tuple[dict[str, str], Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "sudo.log"
    state = tmp_path / "sudo.state"
    write_executable(
        fake_bin / "sudo",
        "#!/bin/sh\n"
        "set -eu\n"
        'printf \'%s\\n\' "$*" >> "$SYNC_CONFIGS_SUDO_LOG"\n'
        'if [ "${1:-}" = -n ] && [ "${2:-}" = -v ]; then\n'
        '  [ -f "$SYNC_CONFIGS_SUDO_STATE" ]\n'
        "  exit\n"
        "fi\n"
        'if [ "${1:-}" = -v ]; then\n'
        '  touch "$SYNC_CONFIGS_SUDO_STATE"\n'
        '  if [ -n "${SYNC_CONFIGS_DRIFT_SOURCE:-}" ]; then\n'
        "    printf 'drifted\\n' > \"$SYNC_CONFIGS_DRIFT_SOURCE\"\n"
        "  fi\n"
        '  if [ -n "${SYNC_CONFIGS_DRIFT_TARGET:-}" ]; then\n'
        "    printf 'drifted\\n' > \"$SYNC_CONFIGS_DRIFT_TARGET\"\n"
        "  fi\n"
        "  exit 0\n"
        "fi\n"
        'if [ "${1:-}" = -n ] && [ "${2:-}" = -- ]; then\n'
        "  shift 2\n"
        '  [ -f "$SYNC_CONFIGS_SUDO_STATE" ] || exit 1\n'
        "  command_name=${1##*/}\n"
        '  if [ "${SYNC_CONFIGS_FAIL_FILE_INSTALL:-0}" = 1 ] && '
        '[ "$command_name" = install ] && [ "${2:-}" != -d ]; then\n'
        "    exit 42\n"
        "  fi\n"
        '  "$@"\n'
        "  command_status=$?\n"
        '  if [ "$command_status" = 0 ] && [ "$command_name" = install ] && '
        '[ "${2:-}" != -d ] && [ -n "${SYNC_CONFIGS_DRIFT_BEFORE_MOVE:-}" ]; then\n'
        "    printf 'drifted-before-move\\n' > \"$SYNC_CONFIGS_DRIFT_BEFORE_MOVE\"\n"
        "  fi\n"
        '  if [ "$command_status" = 0 ] && [ "$command_name" = mv ] && '
        '[ -n "${SYNC_CONFIGS_CORRUPT_AFTER_MOVE:-}" ]; then\n'
        "    printf 'corrupt\\n' > \"$SYNC_CONFIGS_CORRUPT_AFTER_MOVE\"\n"
        "  fi\n"
        '  exit "$command_status"\n'
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
    if drift_source is not None:
        environment["SYNC_CONFIGS_DRIFT_SOURCE"] = str(drift_source)
    if drift_target is not None:
        environment["SYNC_CONFIGS_DRIFT_TARGET"] = str(drift_target)
    if fail_file_install:
        environment["SYNC_CONFIGS_FAIL_FILE_INSTALL"] = "1"
    if drift_before_move is not None:
        environment["SYNC_CONFIGS_DRIFT_BEFORE_MOVE"] = str(drift_before_move)
    if corrupt_after_move is not None:
        environment["SYNC_CONFIGS_CORRUPT_AFTER_MOVE"] = str(corrupt_after_move)
    return environment, log


def run_cli(
    manifest: Path, environment: dict[str, str], *args: str
) -> subprocess.CompletedProcess[str]:
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


def current_identity() -> tuple[str, str]:
    return pwd.getpwuid(os.geteuid()).pw_name, grp.getgrgid(os.getegid()).gr_name


def write_manifest(
    path: Path,
    source: Path,
    target: Path,
    *,
    profiles: str = "",
    reconcile_existing: bool = True,
    file_mode: int = 0o600,
    parent_mode: int | None = None,
) -> None:
    owner, group = current_identity()
    if parent_mode is None:
        parent_mode = stat.S_IMODE(target.parent.stat().st_mode)
    path.write_text(
        "\n".join(
            [
                "entries:",
                "  - name: privileged-config",
                *([f"    profiles: [{profiles}]"] if profiles else []),
                f"    source: {source}",
                f"    target: {target}",
                "    mode: copy",
                "    target_privilege: sudo",
                f"    target_owner: {owner}",
                f"    target_group: {group}",
                f"    target_parent_mode: '{parent_mode:04o}'",
                "    permissions:",
                f"      file: '{file_mode:04o}'",
                f"    reconcile_existing: {str(reconcile_existing).lower()}",
                "",
            ]
        ),
        encoding="utf-8",
    )


def sudo_history(path: Path) -> list[list[str]]:
    return [shlex.split(line) for line in path.read_text(encoding="utf-8").splitlines()]


def expected_system_command(name: str) -> str:
    command = shutil.which(name, path=os.defpath)
    assert command is not None
    return command


def test_privileged_copy_authenticates_once_then_second_pass_invokes_no_sudo(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("managed\n", encoding="utf-8")
    write_manifest(manifest, source, target)
    environment, sudo_log = sudo_fixture(tmp_path)

    first = run_cli(manifest, environment)

    assert first.returncode == 0, first.stderr
    assert target.read_text(encoding="utf-8") == "managed\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    first_history = sudo_history(sudo_log)
    assert first_history[:2] == [["-n", "-v"], ["-v"]]
    temporary = Path(first_history[2][-1])
    assert temporary.name.startswith(".target.conf.sync-configs-")
    owner, group = current_identity()
    assert first_history[2:] == [
        [
            "-n",
            "--",
            expected_system_command("install"),
            "-o",
            str(pwd.getpwnam(owner).pw_uid),
            "-g",
            str(grp.getgrnam(group).gr_gid),
            "-m",
            "0600",
            "--",
            str(source),
            str(temporary),
        ],
        [
            "-n",
            "--",
            expected_system_command("mv"),
            "-f",
            "--",
            str(temporary),
            str(target),
        ],
    ]

    second = run_cli(manifest, environment)

    assert second.returncode == 0, second.stderr
    assert sudo_history(sudo_log) == first_history


def test_dry_run_and_disabled_profile_never_authenticate_or_mutate(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("managed\n", encoding="utf-8")
    write_manifest(manifest, source, target, profiles="enabled")
    environment, sudo_log = sudo_fixture(tmp_path)

    disabled = run_cli(manifest, environment, "--profile", "different")
    dry_run = run_cli(manifest, environment, "--profile", "enabled", "--dry-run")

    assert disabled.returncode == 0, disabled.stderr
    assert dry_run.returncode == 0, dry_run.stderr
    assert not sudo_log.exists()
    assert not target.exists()


def test_all_selected_privileged_entries_validate_before_authentication(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.conf"
    unsafe_source = tmp_path / "unsafe.conf"
    target = tmp_path / "target.conf"
    unsafe_target = tmp_path / "unsafe-target.conf"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("managed\n", encoding="utf-8")
    unsafe_source.symlink_to(source)
    write_manifest(manifest, source, target)
    second = manifest.read_text(encoding="utf-8").splitlines()[1:]
    second = [
        line.replace(str(source), str(unsafe_source)).replace(
            str(target), str(unsafe_target)
        )
        for line in second
    ]
    manifest.write_text(
        manifest.read_text(encoding="utf-8") + "\n" + "\n".join(second) + "\n",
        encoding="utf-8",
    )
    environment, sudo_log = sudo_fixture(tmp_path)

    result = run_cli(manifest, environment)

    assert result.returncode == 1
    assert "must not be a symbolic link" in result.stderr
    assert not sudo_log.exists()
    assert not target.exists()
    assert not unsafe_target.exists()


def test_manifest_rejects_unbounded_privileged_target_shapes_before_sudo(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    source.write_text("managed\n", encoding="utf-8")
    owner, group = current_identity()
    parent_mode = stat.S_IMODE(tmp_path.stat().st_mode)
    valid_fields = [
        "    mode: copy",
        "    target_privilege: sudo",
        f"    target_owner: {owner}",
        f"    target_group: {group}",
        f"    target_parent_mode: '{parent_mode:04o}'",
        "    permissions:",
        "      file: '0600'",
    ]
    cases = [
        (
            [line for line in valid_fields if "target_owner" not in line],
            "requires target_owner and target_group",
            str(target),
            str(source),
        ),
        (
            [line.replace("mode: copy", "mode: toml_overlay") for line in valid_fields],
            "supports only mode: copy",
            str(target),
            str(source),
        ),
        (
            valid_fields,
            "literal absolute target path",
            "relative-target.conf",
            str(source),
        ),
        (
            valid_fields,
            "literal source path",
            str(target),
            f"'{source.parent}/*.conf'",
        ),
        (
            ["    mode: copy", f"    target_owner: {owner}"],
            "require target_privilege: sudo",
            str(target),
            str(source),
        ),
    ]
    environment, sudo_log = sudo_fixture(tmp_path)

    for index, (fields, expected, target_value, source_value) in enumerate(cases):
        manifest = tmp_path / f"invalid-{index}.yaml"
        manifest.write_text(
            "\n".join(
                [
                    "entries:",
                    "  - name: invalid",
                    f"    source: {source_value}",
                    f"    target: {target_value}",
                    *fields,
                    "",
                ]
            ),
            encoding="utf-8",
        )
        result = run_cli(manifest, environment, "--validate")
        assert result.returncode == 1
        assert expected in result.stderr

    assert not sudo_log.exists()


def test_target_drift_after_authentication_fails_before_install(tmp_path: Path) -> None:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("managed\n", encoding="utf-8")
    write_manifest(manifest, source, target)
    environment, sudo_log = sudo_fixture(tmp_path, drift_target=target)

    result = run_cli(manifest, environment)

    assert result.returncode == 1
    assert "state drifted between plan and apply" in result.stdout
    assert target.read_text(encoding="utf-8") == "drifted\n"
    assert sudo_history(sudo_log) == [["-n", "-v"], ["-v"]]


def test_existing_parent_mode_is_reconciled_without_reowning_parent(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "etc"
    parent.mkdir(mode=0o700)
    source = tmp_path / "source.conf"
    target = parent / "target.conf"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("managed\n", encoding="utf-8")
    write_manifest(manifest, source, target, parent_mode=0o755)
    environment, sudo_log = sudo_fixture(tmp_path)

    result = run_cli(manifest, environment)

    assert result.returncode == 0, result.stderr
    history = sudo_history(sudo_log)
    assert history[:2] == [["-n", "-v"], ["-v"]]
    assert history[2] == [
        "-n",
        "--",
        expected_system_command("chmod"),
        "0755",
        "--",
        str(parent),
    ]
    temporary = Path(history[3][-1])
    owner, group = current_identity()
    assert history[3:] == [
        [
            "-n",
            "--",
            expected_system_command("install"),
            "-o",
            str(pwd.getpwnam(owner).pw_uid),
            "-g",
            str(grp.getgrnam(group).gr_gid),
            "-m",
            "0600",
            "--",
            str(source),
            str(temporary),
        ],
        [
            "-n",
            "--",
            expected_system_command("mv"),
            "-f",
            "--",
            str(temporary),
            str(target),
        ],
    ]
    assert stat.S_IMODE(parent.stat().st_mode) == 0o755
    assert target.read_text(encoding="utf-8") == "managed\n"


def test_source_drift_after_authentication_fails_before_install(tmp_path: Path) -> None:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("managed\n", encoding="utf-8")
    write_manifest(manifest, source, target)
    environment, sudo_log = sudo_fixture(tmp_path, drift_source=source)

    result = run_cli(manifest, environment)

    assert result.returncode == 1
    assert "state drifted between plan and apply" in result.stdout
    assert not target.exists()
    assert sudo_history(sudo_log) == [["-n", "-v"], ["-v"]]


def test_failed_staged_install_preserves_prior_target(tmp_path: Path) -> None:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("new\n", encoding="utf-8")
    target.write_text("old\n", encoding="utf-8")
    target.chmod(0o600)
    write_manifest(manifest, source, target)
    environment, sudo_log = sudo_fixture(tmp_path, fail_file_install=True)

    result = run_cli(manifest, environment)

    assert result.returncode == 1
    assert "privileged file install failed with exit 42" in result.stdout
    assert target.read_text(encoding="utf-8") == "old\n"
    assert [Path(row[2]).name for row in sudo_history(sudo_log)[2:]] == ["install"]
    assert not privileged_temporary_candidates(target)


def test_target_drift_during_staging_fails_before_atomic_replace(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("new\n", encoding="utf-8")
    target.write_text("old\n", encoding="utf-8")
    target.chmod(0o600)
    write_manifest(manifest, source, target)
    environment, sudo_log = sudo_fixture(tmp_path, drift_before_move=target)

    result = run_cli(manifest, environment)

    assert result.returncode == 1
    assert "state drifted immediately before atomic replace" in result.stdout
    assert target.read_text(encoding="utf-8") == "drifted-before-move\n"
    assert [Path(row[2]).name for row in sudo_history(sudo_log)[2:]] == [
        "install",
        "rm",
    ]
    assert not privileged_temporary_candidates(target)


def privileged_temporary_candidates(target: Path) -> list[Path]:
    return list(target.parent.glob(f".{target.name}.sync-configs-*.tmp"))


def test_post_replace_verification_detects_corruption(tmp_path: Path) -> None:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("managed\n", encoding="utf-8")
    write_manifest(manifest, source, target)
    environment, sudo_log = sudo_fixture(tmp_path, corrupt_after_move=target)

    result = run_cli(manifest, environment)

    assert result.returncode == 1
    assert "failed exact postcondition verification" in result.stdout
    assert target.read_text(encoding="utf-8") == "corrupt\n"
    assert [Path(row[2]).name for row in sudo_history(sudo_log)[2:]] == [
        "install",
        "mv",
    ]


def test_multiple_privileged_targets_share_one_sudo_session(tmp_path: Path) -> None:
    source_one = tmp_path / "one.conf"
    source_two = tmp_path / "two.conf"
    target_one = tmp_path / "one-target.conf"
    target_two = tmp_path / "two-target.conf"
    first_manifest = tmp_path / "first.yaml"
    second_manifest = tmp_path / "second.yaml"
    manifest = tmp_path / "manifest.yaml"
    source_one.write_text("one\n", encoding="utf-8")
    source_two.write_text("two\n", encoding="utf-8")
    write_manifest(first_manifest, source_one, target_one)
    write_manifest(second_manifest, source_two, target_two)
    manifest.write_text(
        first_manifest.read_text(encoding="utf-8")
        + "\n"
        + "\n".join(second_manifest.read_text(encoding="utf-8").splitlines()[1:])
        + "\n",
        encoding="utf-8",
    )
    environment, sudo_log = sudo_fixture(tmp_path)

    first = run_cli(manifest, environment)

    assert first.returncode == 0, first.stderr
    history = sudo_history(sudo_log)
    assert history[:2] == [["-n", "-v"], ["-v"]]
    assert [Path(row[2]).name for row in history[2:]] == [
        "install",
        "mv",
        "install",
        "mv",
    ]
    assert target_one.read_text(encoding="utf-8") == "one\n"
    assert target_two.read_text(encoding="utf-8") == "two\n"

    second = run_cli(manifest, environment)

    assert second.returncode == 0, second.stderr
    assert sudo_history(sudo_log) == history


def test_parent_metadata_only_drift_does_not_reinstall_target(tmp_path: Path) -> None:
    parent = tmp_path / "managed-parent"
    parent.mkdir(mode=0o755)
    source = tmp_path / "source.conf"
    target = parent / "target.conf"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("managed\n", encoding="utf-8")
    target.write_text("managed\n", encoding="utf-8")
    target.chmod(0o600)
    original_inode = target.stat().st_ino
    write_manifest(manifest, source, target, parent_mode=0o700)
    environment, sudo_log = sudo_fixture(tmp_path)

    result = run_cli(manifest, environment)

    assert result.returncode == 0, result.stderr
    assert stat.S_IMODE(parent.stat().st_mode) == 0o700
    assert target.stat().st_ino == original_inode
    history = sudo_history(sudo_log)
    assert [Path(row[2]).name for row in history[2:]] == ["chmod"]
    assert history[2] == [
        "-n",
        "--",
        expected_system_command("chmod"),
        "0700",
        "--",
        str(parent),
    ]


def test_differing_existing_target_without_reconcile_is_nonmutating(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("managed\n", encoding="utf-8")
    target.write_text("local\n", encoding="utf-8")
    target.chmod(0o600)
    write_manifest(manifest, source, target, reconcile_existing=False)
    environment, sudo_log = sudo_fixture(tmp_path)

    result = run_cli(manifest, environment)

    assert result.returncode == 0, result.stderr
    assert "Skipped (existing target)" in result.stdout
    assert target.read_text(encoding="utf-8") == "local\n"
    assert not sudo_log.exists()


def test_unknown_identity_and_symlink_target_fail_before_sudo(tmp_path: Path) -> None:
    source = tmp_path / "source.conf"
    real_target = tmp_path / "real-target.conf"
    target = tmp_path / "target.conf"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("managed\n", encoding="utf-8")
    real_target.write_text("local\n", encoding="utf-8")
    target.symlink_to(real_target)
    write_manifest(manifest, source, target)
    environment, sudo_log = sudo_fixture(tmp_path)

    symlink_result = run_cli(manifest, environment)

    assert symlink_result.returncode == 1
    assert "must not be a symbolic link" in symlink_result.stderr
    assert not sudo_log.exists()

    target.unlink()
    text = manifest.read_text(encoding="utf-8")
    owner, _ = current_identity()
    manifest.write_text(
        text.replace(
            f"target_owner: {owner}",
            "target_owner: sync-configs-user-that-does-not-exist",
        ),
        encoding="utf-8",
    )
    identity_result = run_cli(manifest, environment)

    assert identity_result.returncode == 1
    assert "unknown target_owner" in identity_result.stderr
    assert not sudo_log.exists()
