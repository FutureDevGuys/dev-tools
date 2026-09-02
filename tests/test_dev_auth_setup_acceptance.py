from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts" / "dev-auth-setup-acceptance.sh"


def installed_fake(tmp_path: Path) -> tuple[Path, Path]:
    executable = tmp_path / "product" / "versions" / "0.3.6" / "dev-auth"
    executable.parent.mkdir(parents=True)
    calls = tmp_path / "calls"
    executable.write_text(
        """#!/usr/bin/bash
set -euo pipefail
printf '%q ' \"$@\" >>\"$DEV_AUTH_TEST_CALLS\"
printf '\\n' >>\"$DEV_AUTH_TEST_CALLS\"
case \"${1-} ${2-}\" in
  'setup discover')
    printf '{\"schema\":\"fixture\"}\\n'
    ;;
  'setup plan')
    output=
    while (($# > 0)); do
      if [[ $1 == --output ]]; then
        shift
        output=$1
      fi
      shift
    done
    printf '{}\\n' >\"$output\"
    printf 'setup_plan_sha256=fixture-digest\\n'
    ;;
  'setup apply')
    printf 'changed=false\\nverified=true\\nnext_action=ready\\n'
    ;;
  'setup verify')
    printf 'changed=false\\nverified=true\\nnext_action=ready\\n'
    ;;
  *)
    printf 'unexpected fixture invocation\\n' >&2
    exit 2
    ;;
esac
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable, calls


def output_path(stdout: str, key: str) -> Path:
    values = [line.removeprefix(f"{key}=") for line in stdout.splitlines() if line.startswith(f"{key}=")]
    assert len(values) == 1
    return Path(values[0])


def test_user_only_acceptance_runs_two_complete_passes_and_keeps_private_evidence(
    tmp_path: Path,
) -> None:
    executable, calls = installed_fake(tmp_path)
    deployment = tmp_path / "deployment.toml"
    deployment.write_text('schema = "dev-auth-deployment-v1"\n', encoding="utf-8")
    temp_parent = tmp_path / "private-temp"
    temp_parent.mkdir()
    result = subprocess.run(
        [
            str(HARNESS),
            "--dev-auth",
            str(executable),
            "--deployment",
            str(deployment),
            "--mode",
            "user-only",
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "DEV_AUTH_TEST_CALLS": str(calls),
            "TMPDIR": str(temp_parent),
        },
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    invocations = calls.read_text(encoding="utf-8").splitlines()
    assert len(invocations) == 7
    assert invocations[0].startswith("setup discover")
    assert sum(line.startswith("setup plan") for line in invocations) == 2
    assert sum(line.startswith("setup apply") for line in invocations) == 2
    assert sum(line.startswith("setup verify") for line in invocations) == 2
    log_path = output_path(result.stdout, "log_path")
    plan_path = output_path(result.stdout, "plan_path")
    assert plan_path.exists()
    assert stat.S_IMODE(log_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(log_path.parent.stat().st_mode) == 0o700
    assert "pass-2/apply" in log_path.read_text(encoding="utf-8")


def test_acceptance_rejects_a_noninstalled_binary(tmp_path: Path) -> None:
    executable = tmp_path / "dev-auth"
    executable.write_text("#!/usr/bin/bash\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    deployment = tmp_path / "deployment.toml"
    deployment.write_text('schema = "dev-auth-deployment-v1"\n', encoding="utf-8")

    result = subprocess.run(
        [
            str(HARNESS),
            "--dev-auth",
            str(executable),
            "--deployment",
            str(deployment),
            "--mode",
            "user-only",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "standalone" in result.stderr


def test_strong_acceptance_never_executes_repository_code_as_root() -> None:
    source = HARNESS.read_text(encoding="utf-8")

    assert source.startswith("#!/usr/bin/bash\n")
    assert "--root-phase" not in source
    assert "${BASH" not in source
    assert 'sudo -- "$0"' not in source
    assert "/usr/bin/sudo -v" in source
    assert "privileged=(/usr/bin/sudo -n --)" in source
    assert '"${privileged[@]}" "$dev_auth_bin" setup plan' in source
    assert '"${privileged[@]}" "$dev_auth_bin" setup apply' in source
    assert '"${privileged[@]}" "$dev_auth_bin" setup verify' in source
