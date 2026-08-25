#!/usr/bin/env python3
"""Classify an existing target against a repo-managed source."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
from pathlib import Path
from typing import Literal


Policy = Literal["safe", "strict", "takeover"]


@dataclasses.dataclass(frozen=True)
class Classification:
    source: str
    target: str
    policy: Policy
    state: str
    action: str
    backup_required: bool


def _tree_snapshot(path: Path) -> tuple[tuple[str, str, bytes | str], ...] | None:
    if path.is_symlink():
        return None
    if path.is_file():
        return ((".", "file", path.read_bytes()),)
    if not path.is_dir():
        return None

    records: list[tuple[str, str, bytes | str]] = []
    for child in sorted(path.rglob("*")):
        relative = child.relative_to(path).as_posix()
        if child.is_symlink():
            records.append((relative, "symlink", os.readlink(child)))
        elif child.is_dir():
            records.append((relative, "dir", ""))
        elif child.is_file():
            records.append((relative, "file", child.read_bytes()))
        else:
            records.append((relative, "other", ""))
    return tuple(records)


def paths_equal(left: Path, right: Path) -> bool:
    try:
        return _tree_snapshot(left) == _tree_snapshot(right)
    except OSError:
        return False


def classify_path(
    source: Path,
    target: Path,
    *,
    policy: Policy = "safe",
    skeleton: Path | None = None,
) -> Classification:
    if target.is_symlink():
        try:
            managed = target.resolve(strict=False) == source.resolve(strict=False)
        except OSError:
            managed = False
        state = "managed_link" if managed else "conflict"
    elif not target.exists():
        state = "absent"
    elif paths_equal(source, target):
        state = "identical_source"
    elif skeleton is not None and skeleton.exists() and paths_equal(skeleton, target):
        state = "skeleton_default"
    else:
        state = "conflict"

    if state == "managed_link":
        action, backup = "none", False
    elif state == "absent":
        action, backup = "create", False
    elif policy == "takeover":
        action, backup = "replace", True
    elif policy == "strict":
        action, backup = "block", False
    elif state == "identical_source":
        action, backup = "adopt", False
    elif state == "skeleton_default":
        action, backup = "replace", True
    else:
        action, backup = "block", False

    return Classification(
        source=str(source),
        target=str(target),
        policy=policy,
        state=state,
        action=action,
        backup_required=backup,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("target", type=Path)
    parser.add_argument("--policy", choices=("safe", "strict", "takeover"), default="safe")
    parser.add_argument("--skeleton", type=Path)
    parser.add_argument("--format", choices=("human", "json"), default="human")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = classify_path(args.source, args.target, policy=args.policy, skeleton=args.skeleton)
    payload = dataclasses.asdict(result)
    if args.format == "json":
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"{result.state}: {result.action} {result.target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
