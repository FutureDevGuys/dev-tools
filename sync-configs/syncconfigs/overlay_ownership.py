"""Ownership receipts for opt-in JSON/TOML overlay key retirement."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


PathKey = tuple[str, ...]


@dataclass(frozen=True)
class FileSnapshot:
    existed: bool
    symlink_target: str | None = None
    content: bytes | None = None
    mode: int | None = None


def snapshot_file(path: Path) -> FileSnapshot:
    if path.is_symlink():
        return FileSnapshot(existed=True, symlink_target=os.readlink(path))
    if path.exists():
        return FileSnapshot(
            existed=True,
            content=path.read_bytes(),
            mode=stat.S_IMODE(path.stat().st_mode),
        )
    return FileSnapshot(existed=False)


def restore_file(path: Path, snapshot: FileSnapshot) -> None:
    if path.exists() or path.is_symlink():
        path.unlink()
    if not snapshot.existed:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if snapshot.symlink_target is not None:
        path.symlink_to(snapshot.symlink_target)
        return
    path.write_bytes(snapshot.content or b"")
    if snapshot.mode is not None:
        path.chmod(snapshot.mode)


def default_state_root() -> Path:
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / "sync-configs" / "state"
    xdg_state = os.environ.get("XDG_STATE_HOME")
    if xdg_state:
        return Path(xdg_state) / "sync-configs"
    return Path.home() / ".local" / "state" / "sync-configs"


def validate_managed_id(value: str) -> str:
    if not value or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in value):
        raise ValueError("managed overlay id must contain only letters, numbers, '.', '_', or '-'")
    return value


def receipt_path(managed_id: str, state_root: Path | None = None) -> Path:
    return (state_root or default_state_root()) / "overlays" / f"{validate_managed_id(managed_id)}.json"


def load_paths(path: Path, managed_id: str) -> set[PathKey]:
    if not path.exists():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read overlay ownership receipt {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1 or payload.get("managed_overlay_id") != managed_id:
        raise ValueError(f"invalid overlay ownership receipt: {path}")
    raw_paths = payload.get("managed_paths")
    if not isinstance(raw_paths, list):
        raise ValueError(f"overlay ownership receipt has invalid managed_paths: {path}")
    paths: set[PathKey] = set()
    for raw in raw_paths:
        if not isinstance(raw, list) or not raw or not all(isinstance(part, str) and part for part in raw):
            raise ValueError(f"overlay ownership receipt contains invalid path: {path}")
        key = tuple(raw)
        if key in paths:
            raise ValueError(f"overlay ownership receipt contains duplicate path {key}: {path}")
        paths.add(key)
    return paths


def payload(managed_id: str, paths: Iterable[PathKey]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "managed_overlay_id": managed_id,
        "managed_paths": [list(path) for path in sorted(set(paths))],
    }


def write_paths_atomic(path: Path, managed_id: str, paths: Iterable[PathKey]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(payload(managed_id, paths), handle, indent=2)
            handle.write("\n")
        os.replace(temporary, path)
    except OSError as exc:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise ValueError(f"cannot write overlay ownership receipt {path}: {exc}") from exc
