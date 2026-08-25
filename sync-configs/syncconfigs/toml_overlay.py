#!/usr/bin/env -S python3
"""Overlay TOML settings from a source file onto a target file.

The source TOML is treated as the portable baseline. Source values win when
both files define the same key, while target-only keys are retained.

If the target is a symlink, it is materialized as a normal file even when the
merged TOML content is already current.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import math
import os
import re
import sys
import tempfile
import tomllib
from collections import OrderedDict
from pathlib import Path
from typing import Any, Iterable

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from . import overlay_ownership


BARE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")


@dataclasses.dataclass(frozen=True)
class TomlAssignment:
    path: tuple[str, ...]
    value: Any


@dataclasses.dataclass(frozen=True)
class TableSection:
    path: tuple[str, ...]
    start: int
    end: int


@dataclasses.dataclass(frozen=True)
class OverlayResult:
    changed: bool
    added: int
    overwritten: int
    removed: int
    text: str
    materialized_symlink: bool = False
    ownership_changed: bool = False


@dataclasses.dataclass(frozen=True)
class PruneResult:
    changed: bool
    removed: int
    text: str
    materialized_symlink: bool = False


def render_toml_key(key: str) -> str:
    if BARE_KEY_RE.match(key):
        return key
    return json.dumps(key, ensure_ascii=False)


def render_toml_key_path(path: Iterable[str]) -> str:
    return ".".join(render_toml_key(part) for part in path)


def render_toml_value(value: Any) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value):
            return "nan"
        if math.isinf(value):
            return "inf" if value > 0 else "-inf"
        return repr(value)
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        return value.isoformat()
    if isinstance(value, list):
        return "[" + ", ".join(render_toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        pairs = (
            f"{render_toml_key(str(key))} = {render_toml_value(item)}"
            for key, item in value.items()
        )
        return "{ " + ", ".join(pairs) + " }"
    raise TypeError(f"Unsupported TOML value type: {type(value).__name__}")


def parse_toml_key_path(raw: str) -> tuple[str, ...]:
    parts: list[str] = []
    index = 0
    length = len(raw)

    while index < length:
        while index < length and raw[index].isspace():
            index += 1
        if index >= length:
            break

        if raw[index] == '"':
            start = index
            index += 1
            escaped = False
            while index < length:
                char = raw[index]
                index += 1
                if escaped:
                    escaped = False
                    continue
                if char == "\\":
                    escaped = True
                    continue
                if char == '"':
                    break
            else:
                raise ValueError(f"Unterminated TOML basic string key: {raw!r}")
            parts.append(json.loads(raw[start:index]))
        elif raw[index] == "'":
            index += 1
            start = index
            while index < length and raw[index] != "'":
                index += 1
            if index >= length:
                raise ValueError(f"Unterminated TOML literal string key: {raw!r}")
            parts.append(raw[start:index])
            index += 1
        else:
            start = index
            while index < length and raw[index] != ".":
                index += 1
            key = raw[start:index].strip()
            if not key:
                raise ValueError(f"Empty TOML key segment: {raw!r}")
            parts.append(key)

        while index < length and raw[index].isspace():
            index += 1
        if index < length:
            if raw[index] != ".":
                raise ValueError(f"Expected '.' in TOML key path: {raw!r}")
            index += 1

    return tuple(parts)


def _extract_table_header(line: str) -> tuple[str, bool] | None:
    stripped = line.strip()
    if not stripped.startswith("["):
        return None

    array_table = stripped.startswith("[[")
    start = 2 if array_table else 1
    end_token = "]]" if array_table else "]"
    quote: str | None = None
    escaped = False
    index = start
    while index < len(stripped):
        char = stripped[index]
        if quote == '"':
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = None
        elif quote == "'":
            if char == "'":
                quote = None
        elif char in {"'", '"'}:
            quote = char
        elif stripped.startswith(end_token, index):
            trailer = stripped[index + len(end_token):].strip()
            if trailer and not trailer.startswith("#"):
                return None
            return stripped[start:index].strip(), array_table
        index += 1

    return None


def extract_table_header_path(line: str) -> tuple[tuple[str, ...], bool] | None:
    header = _extract_table_header(line)
    if header is None:
        return None
    raw_path, array_table = header
    return parse_toml_key_path(raw_path), array_table


def find_table_sections(text: str) -> tuple[list[str], dict[tuple[str, ...], TableSection], int]:
    lines = text.splitlines(keepends=True)
    headers: list[tuple[int, tuple[str, ...]]] = []
    for index, line in enumerate(lines):
        header = extract_table_header_path(line)
        if header is None:
            continue
        path, array_table = header
        if array_table:
            continue
        headers.append((index, path))

    sections: dict[tuple[str, ...], TableSection] = {}
    for header_index, (start, path) in enumerate(headers):
        end = headers[header_index + 1][0] if header_index + 1 < len(headers) else len(lines)
        sections[path] = TableSection(path=path, start=start, end=end)

    first_header = headers[0][0] if headers else len(lines)
    return lines, sections, first_header


def load_toml_text(text: str, label: str) -> dict[str, Any]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Failed to parse TOML {label}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"TOML {label} must parse to a table")
    return data


def iter_leaf_assignments(path: tuple[str, ...], value: Any) -> Iterable[TomlAssignment]:
    if isinstance(value, dict) and value:
        for key, child in value.items():
            yield from iter_leaf_assignments((*path, str(key)), child)
        return
    yield TomlAssignment(path=path, value=value)


def iter_missing_assignments(
    source: dict[str, Any],
    target: dict[str, Any],
    path: tuple[str, ...] = (),
) -> Iterable[TomlAssignment]:
    for key, source_value in source.items():
        key_text = str(key)
        if key_text not in target:
            yield from iter_leaf_assignments((*path, key_text), source_value)
            continue

        target_value = target[key_text]
        if isinstance(source_value, dict) and isinstance(target_value, dict):
            yield from iter_missing_assignments(source_value, target_value, (*path, key_text))


def iter_conflicting_assignments(
    source: dict[str, Any],
    target: dict[str, Any],
    path: tuple[str, ...] = (),
) -> Iterable[TomlAssignment]:
    for key, source_value in source.items():
        key_text = str(key)
        if key_text not in target:
            continue

        target_value = target[key_text]
        if isinstance(source_value, dict) and isinstance(target_value, dict):
            yield from iter_conflicting_assignments(source_value, target_value, (*path, key_text))
            continue
        if source_value != target_value:
            yield from iter_leaf_assignments((*path, key_text), source_value)


def semantic_target_wins_overlay(source: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    merged = dict(target)
    for key, source_value in source.items():
        if key not in merged:
            merged[key] = source_value
            continue
        if isinstance(source_value, dict) and isinstance(merged[key], dict):
            merged[key] = semantic_target_wins_overlay(source_value, merged[key])
    return merged


def semantic_source_wins_overlay(source: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    merged = dict(source)
    for key, target_value in target.items():
        if key not in merged:
            merged[key] = target_value
            continue
        if isinstance(merged[key], dict) and isinstance(target_value, dict):
            merged[key] = semantic_source_wins_overlay(merged[key], target_value)
    return merged


def semantic_prune_source_keys(source: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    remaining = dict(target)
    for key, source_value in source.items():
        if key not in remaining:
            continue
        target_value = remaining[key]
        if isinstance(source_value, dict) and isinstance(target_value, dict):
            nested = semantic_prune_source_keys(source_value, target_value)
            if nested:
                remaining[key] = nested
            else:
                remaining.pop(key)
            continue
        remaining.pop(key)
    return remaining


def _assignment_separator(line: str) -> int | None:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if quote == '"':
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = None
            continue
        if quote == "'":
            if char == "'":
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "#":
            return None
        elif char == "=":
            return index
    return None


def assignment_line_paths(text: str) -> dict[int, tuple[str, ...]]:
    paths: dict[int, tuple[str, ...]] = {}
    table_path: tuple[str, ...] = ()
    for index, line in enumerate(text.splitlines(keepends=True)):
        header = extract_table_header_path(line)
        if header is not None:
            table_path, _ = header
            continue
        separator = _assignment_separator(line)
        if separator is None:
            continue
        raw_key = line[:separator].strip()
        if raw_key:
            paths[index] = (*table_path, *parse_toml_key_path(raw_key))
    return paths


def remove_empty_table_headers(lines: list[str]) -> list[str]:
    changed = True
    while changed:
        changed = False
        headers = [
            index
            for index, line in enumerate(lines)
            if line and extract_table_header_path(line) is not None
        ]
        for header_offset in range(len(headers) - 1, -1, -1):
            start = headers[header_offset]
            end = headers[header_offset + 1] if header_offset + 1 < len(headers) else len(lines)
            body = lines[start + 1:end]
            if any(line.strip() and not line.lstrip().startswith("#") for line in body):
                continue
            lines[start] = ""
            changed = True
    return lines


def normalize_pruned_text(lines: list[str]) -> str:
    compact: list[str] = []
    previous_blank = True
    for line in lines:
        if not line:
            continue
        blank = not line.strip()
        if blank and previous_blank:
            continue
        compact.append(line)
        previous_blank = blank
    while compact and not compact[-1].strip():
        compact.pop()
    if not compact:
        return ""
    return _ensure_trailing_newline("".join(compact))


def prune_toml_paths(target_text: str, retired_paths: Iterable[tuple[str, ...]]) -> PruneResult:
    retired = set(retired_paths)
    target_paths = assignment_line_paths(target_text)
    removed_indexes = {index for index, path in target_paths.items() if path in retired}
    if not removed_indexes:
        return PruneResult(changed=False, removed=0, text=target_text)
    lines = target_text.splitlines(keepends=True)
    for index in removed_indexes:
        lines[index] = ""
    updated = normalize_pruned_text(remove_empty_table_headers(lines))
    load_toml_text(updated, "pruned output")
    return PruneResult(changed=updated != target_text, removed=len(removed_indexes), text=updated)


def _section_insert_index(lines: list[str], section: TableSection | None, fallback_end: int) -> int:
    if section is None:
        start = -1
        end = fallback_end
    else:
        start = section.start
        end = section.end

    index = end
    while index > start + 1 and not lines[index - 1].strip():
        index -= 1
    return index


def _assignment_lines(assignments: list[TomlAssignment]) -> list[str]:
    return [
        f"{render_toml_key(assignment.path[-1])} = {render_toml_value(assignment.value)}\n"
        for assignment in assignments
    ]


def _ensure_trailing_newline(text: str) -> str:
    if not text:
        return text
    if text.endswith("\n"):
        return text
    return text + "\n"


def apply_missing_assignments(target_text: str, assignments: list[TomlAssignment]) -> str:
    if not assignments:
        return target_text

    lines, sections, first_header = find_table_sections(target_text)
    grouped: "OrderedDict[tuple[str, ...], list[TomlAssignment]]" = OrderedDict()
    for assignment in assignments:
        if not assignment.path:
            continue
        grouped.setdefault(assignment.path[:-1], []).append(assignment)

    insertions: dict[int, list[str]] = {}
    append_groups: list[tuple[tuple[str, ...], list[TomlAssignment]]] = []
    for parent_path, group in grouped.items():
        if not parent_path:
            insert_index = _section_insert_index(lines, None, first_header)
            insertions.setdefault(insert_index, []).extend(_assignment_lines(group))
        elif parent_path in sections:
            insert_index = _section_insert_index(lines, sections[parent_path], len(lines))
            insertions.setdefault(insert_index, []).extend(_assignment_lines(group))
        else:
            append_groups.append((parent_path, group))

    updated_lines = list(lines)
    for insert_index in sorted(insertions, reverse=True):
        new_lines = insertions[insert_index]
        if insert_index > 0 and updated_lines and updated_lines[insert_index - 1].strip():
            new_lines = ["\n", *new_lines]
        updated_lines[insert_index:insert_index] = new_lines

    updated = "".join(updated_lines)
    if append_groups:
        updated = _ensure_trailing_newline(updated)
        if updated.strip():
            updated += "\n"
        appended: list[str] = []
        for parent_path, group in append_groups:
            appended.append(f"[{render_toml_key_path(parent_path)}]\n")
            appended.extend(_assignment_lines(group))
            appended.append("\n")
        updated += "".join(appended).rstrip() + "\n"

    return updated


def replace_assignment_values(
    target_text: str, assignments: list[TomlAssignment]
) -> str:
    if not assignments:
        return target_text

    replacements = {assignment.path: assignment.value for assignment in assignments}
    lines = target_text.splitlines(keepends=True)
    for index, path in assignment_line_paths(target_text).items():
        if path not in replacements:
            continue
        separator = _assignment_separator(lines[index])
        if separator is None:
            continue
        ending = "\r\n" if lines[index].endswith("\r\n") else "\n"
        key = lines[index][:separator].rstrip()
        lines[index] = f"{key} = {render_toml_value(replacements[path])}{ending}"
    return "".join(lines)


def overlay_toml_text(
    source_text: str,
    target_text: str,
    *,
    conflict_policy: str = "source",
    preserve_target_layout: bool = False,
    retired_paths: Iterable[tuple[str, ...]] = (),
) -> OverlayResult:
    if conflict_policy not in {"source", "target"}:
        raise ValueError("conflict_policy must be 'source' or 'target'")

    source_data = load_toml_text(source_text, "source")
    prune_result = prune_toml_paths(target_text, retired_paths)
    target_text = prune_result.text
    target_data = load_toml_text(target_text, "target")

    added = len(list(iter_missing_assignments(source_data, target_data)))
    overwritten = 0

    if conflict_policy == "target":
        assignments = list(iter_missing_assignments(source_data, target_data))
        if not assignments:
            return OverlayResult(changed=prune_result.changed, added=0, overwritten=0, removed=prune_result.removed, text=target_text)

        if not target_text.strip():
            updated = _ensure_trailing_newline(source_text)
        else:
            updated = apply_missing_assignments(target_text, assignments)
        expected_data = semantic_target_wins_overlay(source_data, target_data)
    else:
        overwritten = len(list(iter_conflicting_assignments(source_data, target_data)))
        target_only_assignments = list(iter_missing_assignments(target_data, source_data))
        if not source_text.strip():
            updated = target_text
        elif preserve_target_layout and target_text.strip():
            conflicting_assignments = list(
                iter_conflicting_assignments(source_data, target_data)
            )
            missing_assignments = list(iter_missing_assignments(source_data, target_data))
            updated = replace_assignment_values(target_text, conflicting_assignments)
            updated = apply_missing_assignments(updated, missing_assignments)
        else:
            updated = apply_missing_assignments(source_text, target_only_assignments)
        expected_data = semantic_source_wins_overlay(source_data, target_data)

    updated_data = load_toml_text(updated, "merged output")
    if updated_data != expected_data:
        raise ValueError("Merged TOML output did not match the expected semantic overlay")

    return OverlayResult(
        changed=updated != target_text,
        added=added,
        overwritten=overwritten,
        removed=prune_result.removed,
        text=updated,
    )


def merge_missing_toml_text(source_text: str, target_text: str) -> OverlayResult:
    return overlay_toml_text(source_text, target_text, conflict_policy="target")


def prune_toml_text(source_text: str, target_text: str) -> PruneResult:
    source_data = load_toml_text(source_text, "source")
    target_data = load_toml_text(target_text, "target")
    source_paths = set(assignment_line_paths(source_text).values())
    target_paths = assignment_line_paths(target_text)
    removed_indexes = {index for index, path in target_paths.items() if path in source_paths}
    if not removed_indexes:
        return PruneResult(changed=False, removed=0, text=target_text)

    lines = target_text.splitlines(keepends=True)
    for index in removed_indexes:
        lines[index] = ""
    updated = normalize_pruned_text(remove_empty_table_headers(lines))
    expected_data = semantic_prune_source_keys(source_data, target_data)
    updated_data = load_toml_text(updated, "pruned output")
    if updated_data != expected_data:
        raise ValueError(
            "Pruned TOML output did not match source-owned key removal; normalize the target structure before retrying"
        )
    return PruneResult(changed=updated != target_text, removed=len(removed_indexes), text=updated)


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


def overlay_toml_file(
    source_path: Path,
    target_path: Path,
    *,
    dry_run: bool = False,
    conflict_policy: str = "source",
    preserve_target_layout: bool = False,
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
        current_paths = set(assignment_line_paths(source_text).values())
    result = overlay_toml_text(
        source_text,
        target_text,
        conflict_policy=conflict_policy,
        preserve_target_layout=preserve_target_layout,
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


def merge_missing_toml_file(source_path: Path, target_path: Path, *, dry_run: bool = False) -> OverlayResult:
    return overlay_toml_file(source_path, target_path, dry_run=dry_run, conflict_policy="target")


def prune_toml_file(source_path: Path, target_path: Path, *, dry_run: bool = False) -> PruneResult:
    source_text = source_path.read_text(encoding="utf-8")
    if not target_path.exists() and not target_path.is_symlink():
        return PruneResult(changed=False, removed=0, text="")
    target_text = target_path.read_text(encoding="utf-8")
    materialize_symlink = target_path.is_symlink()
    result = prune_toml_text(source_text, target_text)
    if materialize_symlink and result.changed:
        result = dataclasses.replace(result, materialized_symlink=True)
    if result.changed and not dry_run:
        if result.text:
            write_text_atomic(target_path, result.text)
        else:
            target_path.unlink()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Baseline TOML file to read missing keys from.")
    parser.add_argument("target", type=Path, help="Target TOML file to update.")
    parser.add_argument(
        "--conflicts",
        choices=("source", "target"),
        default="source",
        help="Which file wins when both define a key with a different value.",
    )
    parser.add_argument("--reconcile-removed-keys", action="store_true")
    parser.add_argument("--managed-overlay-id")
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--dry-run", action="store_true", help="Report the merge without writing.")
    parser.add_argument("--check", action="store_true", help="Exit non-zero when the target is missing source keys.")
    parser.add_argument(
        "--remove",
        action="store_true",
        help="Remove source-owned keys from the target while retaining target-only keys.",
    )
    args = parser.parse_args(argv)

    try:
        if args.remove:
            prune_result = prune_toml_file(
                args.source.expanduser(),
                args.target.expanduser(),
                dry_run=args.dry_run or args.check,
            )
            if prune_result.changed:
                verb = "would-remove" if args.dry_run or args.check else "removed"
                materialized = " materialized_symlink=1" if prune_result.materialized_symlink else ""
                print(f"{verb} {args.target.expanduser()} removed={prune_result.removed}{materialized}")
                return 1 if args.check else 0
            print(f"up-to-date {args.target.expanduser()} removed=0")
            return 0

        result = overlay_toml_file(
            args.source.expanduser(),
            args.target.expanduser(),
            dry_run=args.dry_run or args.check,
            conflict_policy=args.conflicts,
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
            f"{verb} {args.target.expanduser()} "
            f"added={result.added} overwritten={result.overwritten} removed={result.removed} "
            f"ownership_changed={int(result.ownership_changed)}{materialized}"
        )
        return 1 if args.check else 0

    print(f"up-to-date {args.target.expanduser()} added=0 overwritten=0 removed=0 ownership_changed=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
