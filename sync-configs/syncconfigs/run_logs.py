"""Bounded, owner-only diagnostic run artifacts for sync-configs."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator, TextIO


EVENT_LIMIT_BYTES = 8 * 1024 * 1024
TRANSCRIPT_LIMIT_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_AGE_DAYS = 30
DEFAULT_MAX_RUNS = 100
DEFAULT_MAX_BYTES = 128 * 1024 * 1024
RUN_ID_PATTERN = re.compile(r"^run-[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-[0-9]+-[0-9a-f]{8}$")
LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40, "critical": 50}


class LogError(ValueError):
    """A run-log request is invalid or cannot be read safely."""


@dataclass(frozen=True)
class RetentionPolicy:
    max_age_days: int = DEFAULT_MAX_AGE_DAYS
    max_runs: int = DEFAULT_MAX_RUNS
    max_bytes: int = DEFAULT_MAX_BYTES

    def __post_init__(self) -> None:
        if self.max_age_days < 0 or self.max_runs < 0 or self.max_bytes < 0:
            raise LogError("retention limits must be non-negative")


@dataclass(frozen=True)
class PruneReport:
    removed: tuple[str, ...]
    retained: tuple[str, ...]
    reclaimed_bytes: int
    dry_run: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "dry_run": self.dry_run,
            "reclaimed_bytes": self.reclaimed_bytes,
            "removed": list(self.removed),
            "retained": list(self.retained),
        }


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def default_log_root() -> Path:
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data).expanduser().resolve() / "sync-configs" / "runs"
        return (Path.home() / "AppData" / "Local" / "sync-configs" / "runs").resolve()
    state_home = os.environ.get("XDG_STATE_HOME")
    base = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    return base.resolve() / "sync-configs" / "runs"


def resolve_log_root(value: str | os.PathLike[str] | None) -> Path:
    raw = value if value is not None else os.environ.get("SYNC_CONFIGS_LOG_ROOT")
    if raw is None:
        return default_log_root()
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise LogError("log root must be an absolute path")
    return path.resolve(strict=False)


def _mkdir_owner_only(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise OSError(f"log root is not a real directory: {path}")
    path.chmod(0o700)


def _atomic_json(path: Path, payload: dict[str, object]) -> None:
    encoded = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


@dataclass
class _TranscriptBudget:
    limit: int
    written: int = 0
    truncated: bool = False
    failed: bool = False


class _BoundedTee:
    def __init__(
        self, console: TextIO, transcript: TextIO, budget: _TranscriptBudget
    ) -> None:
        self.console = console
        self.transcript = transcript
        self.budget = budget

    @property
    def encoding(self) -> str:
        return getattr(self.console, "encoding", None) or "utf-8"

    def isatty(self) -> bool:
        return self.console.isatty()

    def fileno(self) -> int:
        return self.console.fileno()

    def flush(self) -> None:
        self.console.flush()
        try:
            self.transcript.flush()
        except OSError:
            self.budget.failed = True

    def _write_transcript(self, value: str) -> None:
        if self.budget.failed:
            return
        try:
            self.transcript.write(value)
        except OSError:
            self.budget.failed = True

    def write(self, value: str) -> int:
        result = self.console.write(value)
        if self.budget.truncated:
            return result
        encoded = value.encode("utf-8", errors="replace")
        remaining = max(0, self.budget.limit - self.budget.written)
        if len(encoded) <= remaining:
            self._write_transcript(value)
            if self.budget.failed:
                return result
            self.budget.written += len(encoded)
            return result
        marker = b"\n[transcript truncated at configured byte limit]\n"
        content_remaining = max(0, remaining - len(marker))
        if content_remaining:
            prefix = encoded[:content_remaining].decode("utf-8", errors="ignore")
            self._write_transcript(prefix)
            if self.budget.failed:
                return result
            self.budget.written += len(prefix.encode("utf-8"))
        marker_text = marker[: max(0, self.budget.limit - self.budget.written)].decode(
            "utf-8", errors="ignore"
        )
        self._write_transcript(marker_text)
        if self.budget.failed:
            return result
        self.budget.written += len(marker_text.encode("utf-8"))
        self.budget.truncated = True
        return result


class NullRunRecorder:
    """No-op recorder used for disabled or unavailable logging."""

    enabled = False

    @contextlib.contextmanager
    def capture_console(self) -> Iterator[None]:
        yield

    def event(self, kind: str, *, level: str = "info", **fields: object) -> None:
        del kind, level, fields

    def record_status_records(self, records: Iterable[object]) -> None:
        del records

    def record_summary(self, stats: dict[str, int], total: int) -> None:
        del stats, total

    def finish(self, *, exit_code: int, interrupted: bool = False) -> None:
        del exit_code, interrupted


class RunRecorder:
    """Own one bounded diagnostic run directory."""

    enabled = True

    def __init__(
        self,
        *,
        root: Path,
        run_dir: Path,
        run_id: str,
        style: str,
        level: str,
        dry_run: bool,
        started_at: datetime,
    ) -> None:
        self.root = root
        self.run_dir = run_dir
        self.run_id = run_id
        self.style = style
        self.level = level
        self.dry_run = dry_run
        self.started_at = started_at
        self.event_bytes = 0
        self.events_truncated = False
        self.transcript_truncated = False
        self._disabled = False
        self._warned = False
        self._counts: dict[str, int] = {}
        if style in {"events", "both"}:
            descriptor = os.open(
                self.run_dir / "events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            os.close(descriptor)
        self._write_metadata(status="running", exit_code=None, ended_at=None)
        self.event("run_started", level="info", dry_run=dry_run)

    @classmethod
    def start(
        cls,
        *,
        root: Path,
        style: str,
        level: str,
        dry_run: bool,
    ) -> RunRecorder | NullRunRecorder:
        if style == "off":
            return NullRunRecorder()
        if style not in {"events", "transcript", "both"}:
            raise LogError(f"unsupported log style: {style}")
        if level not in LEVELS:
            raise LogError(f"unsupported log level: {level}")
        _mkdir_owner_only(root)
        started_at = utc_now()
        run_id = (
            f"run-{started_at.strftime('%Y%m%dT%H%M%S.%fZ')}-{os.getpid()}-"
            f"{uuid.uuid4().hex[:8]}"
        )
        run_dir = root / run_id
        run_dir.mkdir(mode=0o700)
        return cls(
            root=root,
            run_dir=run_dir,
            run_id=run_id,
            style=style,
            level=level,
            dry_run=dry_run,
            started_at=started_at,
        )

    def _warn_and_disable(self, exc: BaseException) -> None:
        self._disabled = True
        if not self._warned:
            print(f"warning: sync-configs logging unavailable: {type(exc).__name__}", file=sys.stderr)
            self._warned = True

    def _write_metadata(
        self, *, status: str, exit_code: int | None, ended_at: datetime | None
    ) -> None:
        payload: dict[str, object] = {
            "schema_version": 1,
            "run_id": self.run_id,
            "product": "sync-configs",
            "status": status,
            "started_at": timestamp(self.started_at),
            "dry_run": self.dry_run,
            "log_style": self.style,
            "log_level": self.level,
            "events_truncated": self.events_truncated,
            "transcript_truncated": self.transcript_truncated,
        }
        if ended_at is not None:
            payload["ended_at"] = timestamp(ended_at)
        if exit_code is not None:
            payload["exit_code"] = exit_code
        if self._counts:
            payload["summary"] = self._counts
        _atomic_json(self.run_dir / "run.json", payload)

    def event(self, kind: str, *, level: str = "info", **fields: object) -> None:
        if self._disabled or self.style not in {"events", "both"}:
            return
        if LEVELS[level] < LEVELS[self.level] or self.events_truncated:
            return
        payload = {
            "schema_version": 1,
            "timestamp": timestamp(utc_now()),
            "level": level,
            "kind": kind,
            **fields,
        }
        encoded = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
        if self.event_bytes + len(encoded) > EVENT_LIMIT_BYTES:
            self.events_truncated = True
            return
        try:
            path = self.run_dir / "events.jsonl"
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(descriptor, "ab") as handle:
                handle.write(encoded)
                handle.flush()
            self.event_bytes += len(encoded)
        except OSError as exc:
            self._warn_and_disable(exc)

    def record_status_records(self, records: Iterable[object]) -> None:
        for record in records:
            status = str(getattr(record, "status_key", "unknown"))
            entry = getattr(record, "entry", None)
            message = str(getattr(record, "message", ""))
            level = "error" if status in {"errors", "script_error"} else (
                "warning" if status in {"skipped_existing", "missing_source", "script_skipped", "deferred", "input_required"} else "info"
            )
            fields: dict[str, object] = {"status": status}
            if entry is not None:
                identity = (
                    f"{getattr(entry, 'scope_label', '')}\0{getattr(entry, 'name', 'unknown')}"
                ).encode("utf-8", errors="replace")
                fields["entry_id"] = hashlib.sha256(identity).hexdigest()[:16]
            if "pre_script" in message:
                fields["phase"] = "pre_script"
            elif "post_script" in message:
                fields["phase"] = "post_script"
            self.event("entry_status", level=level, **fields)

    def record_summary(self, stats: dict[str, int], total: int) -> None:
        self._counts = {key: int(value) for key, value in sorted(stats.items()) if value}
        self._counts["total"] = int(total)
        self.event("run_summary", level="info", counts=self._counts)

    @contextlib.contextmanager
    def capture_console(self) -> Iterator[None]:
        if self._disabled or self.style not in {"transcript", "both"}:
            yield
            return
        try:
            descriptor = os.open(
                self.run_dir / "console.log", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
            )
        except OSError as exc:
            self._warn_and_disable(exc)
            yield
            return
        with os.fdopen(descriptor, "w", encoding="utf-8", errors="replace") as transcript:
            budget = _TranscriptBudget(TRANSCRIPT_LIMIT_BYTES)
            stdout = _BoundedTee(sys.stdout, transcript, budget)
            stderr = _BoundedTee(sys.stderr, transcript, budget)
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                yield
            stdout.flush()
            stderr.flush()
            self.transcript_truncated = budget.truncated
        if budget.failed:
            self._warn_and_disable(OSError("transcript write failed"))

    def finish(self, *, exit_code: int, interrupted: bool = False) -> None:
        if self._disabled:
            return
        try:
            status = "interrupted" if interrupted else ("completed" if exit_code == 0 else "failed")
            self.event("run_finished", level="info" if exit_code == 0 else "error", status=status, exit_code=exit_code)
            self._write_metadata(status=status, exit_code=exit_code, ended_at=utc_now())
            prune_runs(self.root, RetentionPolicy(), dry_run=False)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            self._warn_and_disable(exc)


def start_safely(
    *, root: Path, style: str, level: str, dry_run: bool
) -> RunRecorder | NullRunRecorder:
    try:
        return RunRecorder.start(root=root, style=style, level=level, dry_run=dry_run)
    except (OSError, ValueError) as exc:
        print(f"warning: sync-configs logging unavailable: {type(exc).__name__}", file=sys.stderr)
        return NullRunRecorder()


def _safe_run_dir(root: Path, run_id: str) -> Path:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise LogError("invalid run identifier")
    path = root / run_id
    if path.is_symlink() or not path.is_dir():
        raise LogError(f"run not found: {run_id}")
    return path


def _read_metadata(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise LogError(f"missing run metadata: {path.parent.name}")
    if path.stat().st_size > EVENT_LIMIT_BYTES:
        raise LogError(f"run metadata is too large: {path.parent.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LogError(f"invalid run metadata: {path.parent.name}") from exc
    if not isinstance(value, dict):
        raise LogError(f"invalid run metadata: {path.parent.name}")
    return value


def list_runs(root: Path) -> list[dict[str, object]]:
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise LogError("log root is not a real directory")
    results: list[dict[str, object]] = []
    for path in root.iterdir():
        if not RUN_ID_PATTERN.fullmatch(path.name) or path.is_symlink() or not path.is_dir():
            continue
        try:
            metadata = _read_metadata(path / "run.json")
        except LogError:
            continue
        metadata["run_id"] = path.name
        results.append(metadata)
    results.sort(key=lambda item: str(item.get("started_at", "")), reverse=True)
    return results


def show_run(root: Path, run_id: str) -> dict[str, object]:
    return _read_metadata(_safe_run_dir(root, run_id) / "run.json")


def _directory_size(path: Path) -> int:
    total = 0
    for root, directories, files in os.walk(path, followlinks=False):
        directories[:] = [
            name for name in directories if not (Path(root) / name).is_symlink()
        ]
        for name in files:
            candidate = Path(root) / name
            if not candidate.is_symlink():
                with contextlib.suppress(OSError):
                    total += candidate.stat().st_size
    return total


def _parse_started_at(metadata: dict[str, object], path: Path) -> datetime:
    raw = metadata.get("started_at")
    if isinstance(raw, str):
        with contextlib.suppress(ValueError):
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)


def prune_runs(
    root: Path,
    policy: RetentionPolicy,
    *,
    now: datetime | None = None,
    dry_run: bool,
) -> PruneReport:
    if not root.exists():
        return PruneReport((), (), 0, dry_run)
    if root.is_symlink() or not root.is_dir():
        raise LogError("log root is not a real directory")
    current_time = (now or utc_now()).astimezone(timezone.utc)
    completed: list[tuple[datetime, Path, int]] = []
    retained_other: list[str] = []
    for path in root.iterdir():
        if not RUN_ID_PATTERN.fullmatch(path.name) or path.is_symlink() or not path.is_dir():
            continue
        try:
            metadata = _read_metadata(path / "run.json")
        except LogError:
            retained_other.append(path.name)
            continue
        if metadata.get("status") not in {"completed", "failed", "interrupted"}:
            retained_other.append(path.name)
            continue
        completed.append((_parse_started_at(metadata, path), path, _directory_size(path)))
    completed.sort(key=lambda item: (item[0], item[1].name))
    removal: set[Path] = {
        path
        for started, path, _ in completed
        if current_time - started > timedelta(days=policy.max_age_days)
    }
    survivors = [item for item in completed if item[1] not in removal]
    excess_count = max(0, len(survivors) - policy.max_runs)
    removal.update(path for _, path, _ in survivors[:excess_count])
    survivors = [item for item in survivors if item[1] not in removal]
    total_bytes = sum(size for _, _, size in survivors)
    for _, path, size in survivors:
        if total_bytes <= policy.max_bytes:
            break
        removal.add(path)
        total_bytes -= size
    ordered_removal = [item for item in completed if item[1] in removal]
    reclaimed = sum(size for _, _, size in ordered_removal)
    if not dry_run:
        for _, path, _ in ordered_removal:
            shutil.rmtree(path)
    retained = sorted(
        [path.name for _, path, _ in completed if path not in removal] + retained_other
    )
    return PruneReport(
        removed=tuple(path.name for _, path, _ in ordered_removal),
        retained=tuple(retained),
        reclaimed_bytes=reclaimed,
        dry_run=dry_run,
    )
