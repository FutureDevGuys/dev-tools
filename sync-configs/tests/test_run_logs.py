from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from syncconfigs import run_logs


PROJECT = Path(__file__).resolve().parents[1]


def run_cli(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT)
    environment["SYNC_CONFIGS_LOG_ROOT"] = str(tmp_path / "runs")
    return subprocess.run(
        [sys.executable, "-m", "syncconfigs.cli", *args],
        cwd=PROJECT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def write_manifest(tmp_path: Path, *, hook_secret: str | None = None) -> Path:
    source = tmp_path / "source.conf"
    target = tmp_path / "target.conf"
    manifest = tmp_path / "manifest.yaml"
    source.write_text("managed\n", encoding="utf-8")
    lines = [
        "entries:",
        "  - name: fixture",
        f"    source: {source}",
        f"    target: {target}",
        "    mode: copy",
    ]
    if hook_secret is not None:
        lines.append(
            f"    post_script: {sys.executable} -c \"print('{hook_secret}')\""
        )
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest


def only_run(root: Path) -> Path:
    runs = [path for path in root.iterdir() if path.is_dir()]
    assert len(runs) == 1
    return runs[0]


def test_default_events_log_is_owner_only_and_value_free(tmp_path: Path) -> None:
    secret = "DO_NOT_PERSIST_THIS_VALUE"
    manifest = write_manifest(tmp_path, hook_secret=secret)

    result = run_cli(tmp_path, "--config", str(manifest), "--no-color")

    assert result.returncode == 0, result.stderr
    run_dir = only_run(tmp_path / "runs")
    assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((run_dir / "run.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((run_dir / "events.jsonl").stat().st_mode) == 0o600
    assert not (run_dir / "console.log").exists()
    persisted = (run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert secret not in persisted
    assert str(manifest) not in persisted
    assert "fixture" not in persisted
    assert "post_script" in persisted
    metadata = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert metadata["schema_version"] == 1
    assert metadata["status"] == "completed"
    assert metadata["exit_code"] == 0
    assert metadata["log_style"] == "events"


def test_transcript_is_explicit_and_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(run_logs, "TRANSCRIPT_LIMIT_BYTES", 80)
    root = tmp_path / "runs"
    recorder = run_logs.RunRecorder.start(
        root=root,
        style="transcript",
        level="info",
        dry_run=False,
    )
    with recorder.capture_console():
        print("x" * 400)
    recorder.finish(exit_code=0)

    transcript = (only_run(root) / "console.log").read_text(encoding="utf-8")
    assert len(transcript.encode("utf-8")) <= 80
    assert "truncated" in transcript


def test_logging_failure_warns_and_does_not_break_convergence(tmp_path: Path) -> None:
    manifest = write_manifest(tmp_path)
    unusable_root = tmp_path / "not-a-directory"
    unusable_root.write_text("occupied\n", encoding="utf-8")
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT)
    environment["SYNC_CONFIGS_LOG_ROOT"] = str(unusable_root)

    result = subprocess.run(
        [sys.executable, "-m", "syncconfigs.cli", "--config", str(manifest)],
        cwd=PROJECT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert "warning: sync-configs logging unavailable" in result.stderr


def test_logs_commands_list_show_and_prune_without_logging_themselves(tmp_path: Path) -> None:
    manifest = write_manifest(tmp_path)
    first = run_cli(tmp_path, "--config", str(manifest))
    assert first.returncode == 0, first.stderr
    run_dir = only_run(tmp_path / "runs")

    listed = run_cli(tmp_path, "logs", "list", "--json")
    assert listed.returncode == 0, listed.stderr
    assert [item["run_id"] for item in json.loads(listed.stdout)] == [run_dir.name]
    explicit = run_cli(
        tmp_path,
        "logs",
        "list",
        "--log-root",
        str(tmp_path / "runs"),
        "--json",
    )
    assert explicit.returncode == 0, explicit.stderr
    shown = run_cli(tmp_path, "logs", "show", run_dir.name)
    assert shown.returncode == 0, shown.stderr
    assert json.loads(shown.stdout)["run_id"] == run_dir.name
    escaped = run_cli(tmp_path, "logs", "show", "../run.json")
    assert escaped.returncode != 0

    preview = run_cli(tmp_path, "logs", "prune", "--dry-run", "--max-runs", "0")
    assert preview.returncode == 0, preview.stderr
    assert run_dir.exists()
    applied = run_cli(tmp_path, "logs", "prune", "--max-runs", "0")
    assert applied.returncode == 0, applied.stderr
    assert not run_dir.exists()
    assert not (tmp_path / "runs" / "console.log").exists()


def create_completed_run(root: Path, name: str, started_at: datetime, size: int = 0) -> Path:
    run_dir = root / name
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": name,
                "status": "completed",
                "started_at": started_at.isoformat().replace("+00:00", "Z"),
            }
        ),
        encoding="utf-8",
    )
    if size:
        (run_dir / "payload").write_bytes(b"x" * size)
    return run_dir


def test_retention_prunes_completed_runs_by_age_count_and_bytes(tmp_path: Path) -> None:
    root = tmp_path / "runs"
    now = datetime(2026, 9, 1, tzinfo=timezone.utc)
    old = create_completed_run(root, "run-20260701T000000.000000Z-1-00000001", now - timedelta(days=62))
    first = create_completed_run(root, "run-20260830T000000.000000Z-1-00000002", now - timedelta(days=2), 80)
    second = create_completed_run(root, "run-20260831T000000.000000Z-1-00000003", now - timedelta(days=1), 80)
    running = root / "run-20260901T000000.000000Z-1-00000004"
    running.mkdir()
    (running / "run.json").write_text('{"status":"running"}\n', encoding="utf-8")

    report = run_logs.prune_runs(
        root,
        policy=run_logs.RetentionPolicy(max_age_days=30, max_runs=2, max_bytes=320),
        now=now,
        dry_run=False,
    )

    assert old.name in report.removed
    assert first.name in report.removed
    assert second.exists()
    assert running.exists()


def test_off_style_creates_no_log_root(tmp_path: Path) -> None:
    manifest = write_manifest(tmp_path)
    result = run_cli(tmp_path, "--config", str(manifest), "--log-style", "off")
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "runs").exists()
