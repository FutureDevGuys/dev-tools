#!/usr/bin/env -S python3
"""Overlay JSON settings from a source file onto a target file.

The source JSON object is treated as the portable baseline. Source values win
when both files define the same key, while target-only keys are retained.

If the target is a symlink, it is materialized as a normal file even when the
merged JSON content is already current.
"""

from __future__ import annotations

import argparse
import copy
import dataclasses
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from . import overlay_ownership


@dataclasses.dataclass(frozen=True)
class OverlayResult:
    changed: bool
    added: int
    overwritten: int
    replaced: int
    removed: int
    text: str
    materialized_symlink: bool = False
    ownership_changed: bool = False


def load_json_object_text(text: str, label: str) -> dict[str, Any]:
    if not text.strip():
        return {}
    try:
        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"Duplicate JSON key {key!r} in {label}")
                result[key] = value
            return result

        data = json.loads(text, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Failed to parse JSON {label}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"JSON {label} must contain a top-level object")
    return data


def load_json_object_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return load_json_object_text(path.read_text(encoding="utf-8"), str(path))


def iter_leaf_paths(path: tuple[str, ...], value: Any) -> Iterable[tuple[tuple[str, ...], Any]]:
    if isinstance(value, dict) and value:
        for key, child in value.items():
            yield from iter_leaf_paths((*path, str(key)), child)
        return
    yield path, value


def iter_missing_paths(
    source: dict[str, Any],
    target: dict[str, Any],
    path: tuple[str, ...] = (),
) -> Iterable[tuple[tuple[str, ...], Any]]:
    for key, source_value in source.items():
        key_text = str(key)
        if key_text not in target:
            yield from iter_leaf_paths((*path, key_text), source_value)
            continue

        target_value = target[key_text]
        if isinstance(source_value, dict) and isinstance(target_value, dict):
            yield from iter_missing_paths(source_value, target_value, (*path, key_text))


def iter_conflicting_paths(
    source: dict[str, Any],
    target: dict[str, Any],
    path: tuple[str, ...] = (),
) -> Iterable[tuple[tuple[str, ...], Any]]:
    for key, source_value in source.items():
        key_text = str(key)
        if key_text not in target:
            continue

        target_value = target[key_text]
        if isinstance(source_value, dict) and isinstance(target_value, dict):
            yield from iter_conflicting_paths(source_value, target_value, (*path, key_text))
            continue
        if source_value != target_value:
            yield from iter_leaf_paths((*path, key_text), source_value)


def semantic_source_wins_overlay(source: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(source)
    for key, target_value in target.items():
        if key not in merged:
            merged[key] = copy.deepcopy(target_value)
            continue
        if isinstance(merged[key], dict) and isinstance(target_value, dict):
            merged[key] = semantic_source_wins_overlay(merged[key], target_value)
    return merged


def remove_object_path(data: dict[str, Any], path: tuple[str, ...]) -> bool:
    if not path:
        return False
    current: dict[str, Any] = data
    parents: list[tuple[dict[str, Any], str]] = []
    for part in path[:-1]:
        value = current.get(part)
        if not isinstance(value, dict):
            return False
        parents.append((current, part))
        current = value
    if path[-1] not in current:
        return False
    current.pop(path[-1])
    for parent, key in reversed(parents):
        child = parent.get(key)
        if isinstance(child, dict) and not child:
            parent.pop(key)
        else:
            break
    return True


def parse_json_pointer(pointer: str) -> tuple[str, ...]:
    if pointer == "":
        return ()
    if not pointer.startswith("/"):
        raise ValueError(f"JSON pointer must be empty or start with '/': {pointer}")
    parts = []
    for raw_part in pointer.split("/")[1:]:
        parts.append(raw_part.replace("~1", "/").replace("~0", "~"))
    return tuple(parts)


def get_pointer_value(data: dict[str, Any], pointer: str) -> Any:
    current: Any = data
    for part in parse_json_pointer(pointer):
        if not isinstance(current, dict) or part not in current:
            raise ValueError(f"JSON pointer not found in source: {pointer}")
        current = current[part]
    return current


def set_pointer_value(data: dict[str, Any], pointer: str, value: Any) -> dict[str, Any]:
    path = parse_json_pointer(pointer)
    if not path:
        if not isinstance(value, dict):
            raise ValueError("Replacing the JSON document root requires an object value")
        return copy.deepcopy(value)

    current: dict[str, Any] = data
    for part in path[:-1]:
        next_value = current.get(part)
        if next_value is None:
            next_value = {}
            current[part] = next_value
        if not isinstance(next_value, dict):
            raise ValueError(f"Cannot set JSON pointer through non-object path: {pointer}")
        current = next_value
    current[path[-1]] = copy.deepcopy(value)
    return data


def render_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def overlay_json_objects(
    source: dict[str, Any],
    target: dict[str, Any],
    *,
    replace_json_pointers: Iterable[str] = (),
) -> tuple[dict[str, Any], int, int, int]:
    added = len(list(iter_missing_paths(source, target)))
    overwritten = len(list(iter_conflicting_paths(source, target)))
    merged = semantic_source_wins_overlay(source, target)

    replaced = 0
    for pointer in replace_json_pointers:
        replacement = get_pointer_value(source, pointer)
        before = get_pointer_value(merged, pointer) if pointer else merged
        if before != replacement:
            replaced += 1
        merged = set_pointer_value(merged, pointer, replacement)

    return merged, added, overwritten, replaced


def overlay_json_text(
    source_text: str,
    target_text: str,
    *,
    replace_json_pointers: Iterable[str] = (),
    retired_paths: Iterable[tuple[str, ...]] = (),
) -> OverlayResult:
    source_data = load_json_object_text(source_text, "source")
    target_data = load_json_object_text(target_text, "target")
    pruned_target = copy.deepcopy(target_data)
    removed = sum(1 for path in retired_paths if remove_object_path(pruned_target, path))
    merged, added, overwritten, replaced = overlay_json_objects(
        source_data,
        pruned_target,
        replace_json_pointers=replace_json_pointers,
    )
    updated = target_text if merged == target_data else render_json(merged)
    return OverlayResult(
        changed=updated != target_text,
        added=added,
        overwritten=overwritten,
        replaced=replaced,
        removed=removed,
        text=updated,
    )


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_temp_path = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
        text=True,
    )
    temp_path = Path(raw_temp_path)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def overlay_json_file(
    source_path: Path,
    target_path: Path,
    *,
    dry_run: bool = False,
    replace_json_pointers: Iterable[str] = (),
    reconcile_removed_keys: bool = False,
    managed_overlay_id: str | None = None,
    state_root: Path | None = None,
) -> OverlayResult:
    source_text = source_path.read_text(encoding="utf-8")
    target_text = target_path.read_text(encoding="utf-8") if target_path.exists() else ""
    materialize_symlink = target_path.is_symlink()
    ownership_path: Path | None = None
    prior_paths: set[tuple[str, ...]] = set()
    current_paths: set[tuple[str, ...]] = set()
    if reconcile_removed_keys:
        if managed_overlay_id is None:
            raise ValueError("managed_overlay_id is required when reconcile_removed_keys is enabled")
        ownership_path = overlay_ownership.receipt_path(managed_overlay_id, state_root)
        prior_paths = overlay_ownership.load_paths(ownership_path, managed_overlay_id)
        source_data = load_json_object_text(source_text, "source")
        current_paths = {path for path, _ in iter_leaf_paths((), source_data)}
    result = overlay_json_text(
        source_text,
        target_text,
        replace_json_pointers=replace_json_pointers,
        retired_paths=prior_paths - current_paths,
    )
    ownership_changed = ownership_path is not None and prior_paths != current_paths
    if materialize_symlink:
        result = dataclasses.replace(result, changed=True, materialized_symlink=True)
    if ownership_changed:
        result = dataclasses.replace(result, changed=True, ownership_changed=True)
    if not dry_run and (result.changed or ownership_changed):
        original = overlay_ownership.snapshot_file(target_path)
        try:
            if result.text != target_text or materialize_symlink:
                write_text_atomic(target_path, result.text)
            if ownership_path is not None:
                overlay_ownership.write_paths_atomic(ownership_path, managed_overlay_id or "", current_paths)
        except (OSError, ValueError):
            overlay_ownership.restore_file(target_path, original)
            raise
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Baseline JSON object to overlay from.")
    parser.add_argument("target", type=Path, help="Target JSON object to update.")
    parser.add_argument(
        "--replace-json-pointer",
        action="append",
        default=[],
        help=(
            "RFC 6901 JSON pointer to replace exactly from source after the recursive overlay. "
            "Repeat for multiple authoritative subtrees."
        ),
    )
    parser.add_argument("--dry-run", action="store_true", help="Report the merge without writing.")
    parser.add_argument("--check", action="store_true", help="Exit non-zero when the target differs.")
    parser.add_argument("--reconcile-removed-keys", action="store_true")
    parser.add_argument("--managed-overlay-id")
    parser.add_argument("--state-root", type=Path)
    args = parser.parse_args(argv)

    try:
        result = overlay_json_file(
            args.source.expanduser(),
            args.target.expanduser(),
            dry_run=args.dry_run or args.check,
            replace_json_pointers=args.replace_json_pointer,
            reconcile_removed_keys=args.reconcile_removed_keys,
            managed_overlay_id=args.managed_overlay_id,
            state_root=args.state_root,
        )
    except (OSError, TypeError, ValueError) as exc:
        print(f"error: {exc}")
        return 1

    if result.changed:
        verb = "would-update" if args.dry_run or args.check else "updated"
        materialized = " materialized_symlink=1" if result.materialized_symlink else ""
        print(
            f"{verb} {args.target.expanduser()} added={result.added} "
            f"overwritten={result.overwritten} replaced={result.replaced} "
            f"removed={result.removed} ownership_changed={int(result.ownership_changed)}{materialized}"
        )
        return 1 if args.check else 0

    print(f"up-to-date {args.target.expanduser()} added=0 overwritten=0 replaced=0 removed=0 ownership_changed=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
