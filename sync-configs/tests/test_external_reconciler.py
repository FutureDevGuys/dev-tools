from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


PROJECT = Path(__file__).resolve().parents[1]


def run_cli(manifest: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "syncconfigs.cli",
            "--config",
            str(manifest),
            *arguments,
        ],
        cwd=PROJECT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def fake_reconciler(tmp_path: Path) -> tuple[Path, Path, Path]:
    program = tmp_path / "owner-tool"
    marker = tmp_path / "converged"
    log = tmp_path / "argv.jsonl"
    program.write_text(
        f"""#!/usr/bin/python3
import hashlib
import json
from pathlib import Path
import sys

args = sys.argv[1:]
with Path({str(log)!r}).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(args) + "\\n")
operation = args[1]
marker = Path({str(marker)!r})
result = {{
    "schema": "dev-tools-reconcile-result-v1",
    "changed": False,
    "verified": False,
    "deferred": False,
    "input_required": [],
    "next_action": "none",
    "diagnostics": [],
}}
if operation == "plan":
    output = Path(args[args.index("--output") + 1])
    source = Path(args[args.index("--source") + 1])
    output.write_text(json.dumps({{"source": str(source)}}), encoding="utf-8")
    output.chmod(0o600)
    result["changed"] = not marker.exists()
    result["verified"] = marker.exists()
    result["next_action"] = "apply" if not marker.exists() else "none"
elif operation == "apply":
    plan = Path(args[args.index("--plan") + 1])
    expected = args[args.index("--sha256") + 1]
    if hashlib.sha256(plan.read_bytes()).hexdigest() != expected:
        raise SystemExit(91)
    changed = not marker.exists()
    marker.write_text("ready\\n", encoding="utf-8")
    result["changed"] = changed
    result["verified"] = True
elif operation == "verify":
    result["verified"] = marker.exists()
    result["next_action"] = "none" if marker.exists() else "apply"
else:
    raise SystemExit(92)
print(json.dumps(result, sort_keys=True))
""",
        encoding="utf-8",
    )
    program.chmod(0o755)
    return program, marker, log


def manifest_for(tmp_path: Path, program: Path) -> Path:
    source = tmp_path / "desired.toml"
    source.write_text('version = 2\n', encoding="utf-8")
    manifest = tmp_path / "sync.yaml"
    manifest.write_text(
        "\n".join(
            [
                "reconcilers:",
                "  - name: dev-auth-user-config",
                "    group: Identity",
                "    subgroup: Dev Auth",
                f"    executable: {program}",
                f"    source: {source}",
                "    scope: user",
                "    privilege: user",
                "    protocol: dev-tools-reconcile-v1",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return manifest


def test_typed_reconciler_uses_exact_grammar_and_is_idempotent(tmp_path: Path) -> None:
    program, marker, log = fake_reconciler(tmp_path)
    manifest = manifest_for(tmp_path, program)

    first = run_cli(manifest, "--no-color")
    second = run_cli(manifest, "--no-color")

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert marker.read_text(encoding="utf-8") == "ready\n"
    assert "Identity / Dev Auth" in first.stdout
    assert "Performed" in first.stdout
    assert "Up-to-date" in second.stdout
    invocations = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert [invocation[0:2] for invocation in invocations] == [
        ["reconcile", "plan"],
        ["reconcile", "apply"],
        ["reconcile", "verify"],
        ["reconcile", "plan"],
        ["reconcile", "apply"],
        ["reconcile", "verify"],
    ]
    assert all("--format" in invocation and "json" in invocation for invocation in invocations)


def test_typed_reconciler_json_is_structured_and_color_free(tmp_path: Path) -> None:
    program, _marker, _log = fake_reconciler(tmp_path)
    manifest = manifest_for(tmp_path, program)

    result = run_cli(manifest, "--format", "json")

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["outcome"] == "completed"
    assert payload["reconcilers"][0]["name"] == "dev-auth-user-config"
    assert payload["reconcilers"][0]["schema"] == "dev-tools-reconcile-result-v1"
    assert payload["reconcilers"][0]["changed"] is True
    assert "\x1b[" not in result.stdout


def test_reconciler_rejects_arbitrary_command_surfaces(tmp_path: Path) -> None:
    program, _marker, _log = fake_reconciler(tmp_path)
    manifest = manifest_for(tmp_path, program)
    manifest.write_text(
        manifest.read_text(encoding="utf-8") + "    command: owner-tool do-anything\n",
        encoding="utf-8",
    )

    result = run_cli(manifest, "--validate")

    assert result.returncode == 1
    assert "unsupported keys" in result.stderr


def test_reconciler_rejects_public_plan_custody(tmp_path: Path) -> None:
    program, marker, _log = fake_reconciler(tmp_path)
    manifest = manifest_for(tmp_path, program)
    program.write_text(
        program.read_text(encoding="utf-8").replace(
            "output.chmod(0o600)", "output.chmod(0o644)"
        ),
        encoding="utf-8",
    )

    result = run_cli(manifest, "--no-color")

    assert result.returncode == 1
    assert not marker.exists()
    assert "unsafe plan" in result.stdout


def test_reconciler_rejects_hardlinked_plan_custody(tmp_path: Path) -> None:
    program, marker, _log = fake_reconciler(tmp_path)
    manifest = manifest_for(tmp_path, program)
    program.write_text(
        program.read_text(encoding="utf-8").replace(
            "output.chmod(0o600)",
            'output.chmod(0o600)\n    output.with_name("second-link").hardlink_to(output)',
        ),
        encoding="utf-8",
    )

    result = run_cli(manifest, "--no-color")

    assert result.returncode == 1
    assert not marker.exists()
    assert "unsafe plan" in result.stdout
