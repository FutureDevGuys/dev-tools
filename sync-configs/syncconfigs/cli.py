#!/usr/bin/env -S python
"""Converge manifest-managed config surfaces into expected local paths."""

from __future__ import annotations

import argparse
import contextlib
import fnmatch
import glob
import importlib.resources
import io
import json
import ntpath
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
TOOLS_DIR = SCRIPT_DIR.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from . import json_overlay, managed_path_policy, toml_overlay
import yaml


MODES = {"symlink", "copy", "json_overlay", "toml_overlay"}
DIRECTORY_STRATEGIES = {"as_directory", "children", "recursive"}
SCRIPT_ON_FAIL_POLICIES = {"abort", "skip", "continue"}
PYTHON_HOOK_COMMANDS = {"python", "python3"}
SHELL_META_CHARS = re.compile(r"[\n;&|<>`$]")

DESCRIPTION = """\
Converge manifest-managed config surfaces to local paths.

Automatically applies a <config>.override.yaml file when present to override entries by source
and prefers on-disk *.override sources when available.

Configs can be split into:
  - a root YAML (for defaults and optional inline entries)
  - an entries directory tree via `entries_dir` (recursive `*.yaml`/`*.yml`)

For entries loaded from `entries_dir`, relative `source` paths are resolved from the
root config directory (not each nested YAML file path).

Globbing is supported in source only:
  - `*` and `?` for wildcards
  - `**` for recursive matches
  - targets must be literal paths (no globs)

Expanded sources can be filtered with gitignore-style rules:
  - `exclude` and `include` lists on entries
  - explicit `ignore_files`
  - autodiscovered `.gitignore`, `.ignore`, `.rgignore`, `.fdignore`
  - a default junk baseline from `sync_default_filters.gitignore`

When a glob matches multiple paths, each match is synced to:
  <target>/<relative path from glob root>

Glob root is computed as the leading non-glob path segments of `source`.
For example, `../configs/**/*.json` uses `../configs` as the root and
`**/*.json` as the pattern, so `../configs/app/a.json` targets
`<target>/app/a.json`.

Per-entry hooks:
  - `pre_script`: shell command to run before syncing this entry
  - `post_script`: shell command to run after a successful sync
  - Scripts run from the root config directory via the platform shell
  - Simple `python`/`python3` hooks run through the current interpreter before
    falling back to the platform shell
  - `pre_script_on_fail` controls behavior on pre-script failure:
      abort (default) — count as error, skip this entry
      skip — count as skipped, log warning
      continue — log warning, proceed with sync
  - `post_script_on_fail` controls behavior on post-script failure:
      abort — count as error for this entry
      continue (default) — log warning, keep sync status
  - `--dry-run` reports scripts without executing them

Entry modes:
  - `symlink`: link the target to the repo source
  - `copy`: copy the repo source to the target
  - `json_overlay`: overlay source JSON into the target, preferring source values on conflicts,
    and materializing a symlink target into a normal file
  - `toml_overlay`: overlay source TOML into the target, preferring source values on conflicts,
    and materializing a symlink target into a normal file

Output is buffered and printed grouped by status at the end:
  - Performed entries (always shown)
  - Skipped / missing / error entries (always shown)
  - Up-to-date entries (collapsed by default, use --verbose to expand)

Optional entry `profiles` let you gate sync targets behind one or more named profiles:
  - entries without `profiles` run by default
  - entries with `profiles` do not run unless a matching `--profile` is passed
  - if any `--profile` values are passed, only matching profiled entries run
  - use `--list-profiles` to print current profile names from the configured entries
  - use `--host-profile` to activate sync profiles from metadata/convergence

The command owns only config convergence. Package installation, privileged
system state, and workstation policy belong to callers.
"""

EXAMPLE_ROOT_CONFIG = """\
# Root sync configuration (sync_targets.yaml)
# - Keep defaults here
# - Place most entries under `entries_dir` for maintainability
default_mode: symlink
entries_dir: ./sync_targets.d

entries:
  # Optional inline entries are still supported
  - name: single_file
    source: ../cli/codex/config.toml
    target: ~/.codex/config.toml
"""

EXAMPLE_ENTRY_FILE_CONFIG = """\
# Example entry file (sync_targets.d/00-example.yaml)
# - source supports globbing (`*`, `?`, `**`), target must be a literal path
# - for directory sources (no glob), `directory_strategy` controls expansion
entries:
  # Single file (defaults to root default_mode)
  - name: codex_config
    group: CLI
    subgroup: Codex
    source: ../cli/codex/config.toml
    target: ~/.codex/config.toml
    mode: toml_overlay

  # Profile-gated entry:
  # - runs only when one of the named profiles is requested
  # - if any --profile flags are passed, unprofiled entries are skipped
  # - name: windows_terminal
  #   group: CLI
  #   subgroup: Windows
  #   profiles: [selected_profile]
  #   source: ../cli/windows-terminal/settings.json
  #   target: ~/.config/example/windows-terminal/settings.json

  # Glob: preserve relative paths under target
  - name: all_mcp_json
    group: MCP
    subgroup: Servers
    source: ../mcp/*.json
    target: ~/MCPs

  # Directory with explicit options
  - name: example_commands
    group: CLI
    subgroup: Example
    source: ../cli/example/commands
    target: ~/.example/commands
    mode: copy
    directory_strategy: as_directory
    permissions:
      file: "0644"
      dir: "0755"
      recursive: true

  # Entry with pre/post hooks:
  # - name: claude_agents
  #   group: CLI
  #   subgroup: Claude
  #   source: ../cli/claude/agents/*.md
  #   target: ~/.claude/agents
  #   mode: copy
  #   pre_script: python ../scripts/convert_codex_agents.py
  #   pre_script_on_fail: abort      # abort | skip | continue (default: abort)
  #   post_script: echo "agents synced"
  #   post_script_on_fail: continue  # abort | continue (default: continue)

  # Optional keys and alternative modes:
  # - name: prompts_recursive
  #   source: ../prompts
  #   target: ~/.codex/prompts
  #   mode: symlink
  #   directory_strategy: recursive   # as_directory | children | recursive
  #   exclude:
  #     - "__pycache__/"
  #     - "*.pyc"
  #   include:
  #     - "bin/**"
  #   ignore_files:
  #     - .gitignore
  #   discover_ignore_files: true
  #   use_default_filters: true
  #   source_permissions:
  #     file: "0755"
  #
  # JSON/TOML overlay:
  # - name: claude_user_config_json
  #   source: ../cli/claude/.claude.json
  #   target: ~/.claude.json
  #   mode: json_overlay
  #
  # - name: codex_config_toml
  #   source: ../cli/codex/config.toml
  #   target: ~/.codex/config.toml
  #   mode: toml_overlay
"""

DEFAULT_IGNORE_FILE_NAMES = (".gitignore", ".ignore", ".rgignore", ".fdignore")
DEFAULT_FILTERS_RESOURCE = importlib.resources.files("syncconfigs").joinpath(
    "default_filters.gitignore"
)

STATUS_KEYS = (
    "performed",
    "up_to_date",
    "skipped_existing",
    "missing_source",
    "script_error",
    "script_skipped",
    "errors",
)

STATUS_LABELS = {
    "performed": "[do]",
    "up_to_date": "[skip]",
    "skipped_existing": "[skip]",
    "missing_source": "[skip]",
    "script_error": "[error]",
    "script_skipped": "[skip]",
    "info": "[info]",
    "errors": "[error]",
}

STATUS_COLORS = {
    "performed": "32",  # green
    "up_to_date": "36",  # cyan
    "skipped_existing": "33",  # yellow
    "missing_source": "31",  # red
    "script_error": "31",  # red
    "script_skipped": "33",  # yellow
    "info": "34",  # blue
    "errors": "31",  # red
}

# Display order and headers for buffered output grouping.
STATUS_GROUP_ORDER = (
    ("performed", "Performed"),
    ("script_error", "Script Errors"),
    ("script_skipped", "Script Skipped"),
    ("skipped_existing", "Skipped (existing target)"),
    ("missing_source", "Skipped (missing source)"),
    ("errors", "Errors"),
    ("up_to_date", "Up-to-date"),
)


def normalize_user_path(
    raw_path: str,
    *,
    platform: str | None = None,
    user_home: str | None = None,
    temp_dir: str | None = None,
) -> str:
    platform_name = platform or os.name
    pathmod = ntpath if platform_name == "nt" else os.path

    expanded = os.path.expandvars(raw_path)
    if raw_path.startswith("~") and user_home is not None:
        if raw_path == "~":
            expanded = user_home
        elif raw_path.startswith("~/") or raw_path.startswith("~\\"):
            suffix = raw_path[2:].replace("\\", "/")
            suffix_parts = PurePosixPath(suffix).parts
            expanded = pathmod.join(user_home, *suffix_parts) if suffix_parts else user_home
        else:
            expanded = os.path.expanduser(expanded)
    else:
        expanded = os.path.expanduser(expanded)

    if platform_name != "nt":
        return expanded

    unix_style = expanded.replace("\\", "/")
    temp_root = temp_dir or tempfile.gettempdir()
    temp_mappings = ("/tmp", "/var/tmp")
    for prefix in temp_mappings:
        if unix_style == prefix or unix_style.startswith(f"{prefix}/"):
            remainder = unix_style[len(prefix):].lstrip("/")
            if not remainder:
                return temp_root
            remainder_parts = PurePosixPath(remainder).parts
            return pathmod.join(temp_root, *remainder_parts)

    return expanded.replace("/", pathmod.sep)


def colorize(text: str, color_code: Optional[str], use_color: bool) -> str:
    if not use_color or not color_code:
        return text
    return f"\033[{color_code}m{text}\033[0m"


def format_status(status_key: str, use_color: bool) -> str:
    raw_label = STATUS_LABELS.get(status_key, status_key)
    padded = raw_label.ljust(7)
    color_code = STATUS_COLORS.get(status_key)
    return colorize(padded, color_code, use_color)


def compose_scope_label(group: Optional[str], subgroup: Optional[str]) -> str:
    parts = [part for part in (group, subgroup) if part]
    return " / ".join(parts) if parts else "root"


def increment_group_stat(group_stats, entry: "Entry", status: str) -> None:
    key = (entry.group, entry.subgroup)
    group_stats[key][status] = group_stats[key].get(status, 0) + 1


def format_group_label(group: Optional[str], subgroup: Optional[str]) -> str:
    base = group or "root"
    if subgroup:
        return f"{base} / {subgroup}"
    return base


def format_count(count: int, status_key: str, use_color: bool) -> str:
    return colorize(str(count), STATUS_COLORS.get(status_key), use_color)


def format_exception(exc: Exception) -> str:
    message = str(exc).strip()
    if message:
        return f"{exc.__class__.__name__}: {message}"
    return exc.__class__.__name__


def print_status(
    status_key: str,
    message: str,
    use_color: bool,
    *,
    stream=sys.stdout,
    entry: "Entry" | None = None,
    widths: "PrintWidths" | None = None,
) -> None:
    prefix = format_status(status_key, use_color)

    if entry is not None and widths is not None:
        scope = entry.scope_label.ljust(widths.scope)
        name = entry.name.ljust(widths.name)
        if message:
            formatted = f"{scope} {name} {message}"
        else:
            formatted = f"{scope} {name}"
    else:
        formatted = message

    print(f"{prefix} {formatted}", file=stream)


@dataclass
class Entry:
    name: str
    source: Path
    target: Path
    mode: str
    directory_strategy: str = "as_directory"
    profiles: tuple[str, ...] = ()
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    ignore_files: tuple[str, ...] = ()
    discover_ignore_files: bool = True
    use_default_filters: bool = True
    group: Optional[str] = None
    subgroup: Optional[str] = None
    scope_label: str = "root"
    permissions: "PermissionPolicy | None" = None
    source_permissions: "PermissionPolicy | None" = None
    pre_script: Optional[str] = None
    pre_script_on_fail: str = "abort"
    post_script: Optional[str] = None
    post_script_on_fail: str = "continue"
    reconcile_existing: bool = False
    reconcile_removed_keys: bool = False
    managed_overlay_id: Optional[str] = None


@dataclass
class PrintWidths:
    scope: int
    name: int


@dataclass
class StatusRecord:
    """A single buffered status line to be printed after all entries are processed.

    All buffered output is flushed to stdout as a grouped report.
    """
    status_key: str
    message: str
    entry: Optional["Entry"] = None
    script_output: Optional[str] = None


class ConfigError(Exception):
    """Raised when the configuration file contains invalid data."""


@dataclass(frozen=True)
class IgnoreRule:
    pattern: str
    negated: bool
    dir_only: bool
    anchored: bool
    basename_only: bool


@dataclass(frozen=True)
class PermissionPolicy:
    file_mode: int | None = None
    dir_mode: int | None = None
    recursive: bool = False


def normalize_permission_mode(value: object, key: str) -> int:
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise ConfigError(f"Entry '{key}' must not be empty.")
        base = 8
    elif isinstance(value, int) and not isinstance(value, bool):
        raw = str(value)
        base = 8
    else:
        raise ConfigError(
            f"Entry '{key}' must be an octal string like '0755' or an integer."
        )

    try:
        mode = int(raw, base)
    except ValueError as exc:
        raise ConfigError(
            f"Entry '{key}' must be a valid octal permission value, got: {value!r}"
        ) from exc

    if mode < 0 or mode > 0o7777:
        raise ConfigError(
            f"Entry '{key}' must be between 0000 and 7777, got: {value!r}"
        )
    return mode


def parse_permission_policy(value: object, key: str) -> PermissionPolicy | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ConfigError(
            f"Entry '{key}' must be a mapping with optional 'file', 'dir', and 'recursive' keys."
        )

    unknown = sorted(set(value) - {"file", "dir", "recursive"})
    if unknown:
        raise ConfigError(
            f"Entry '{key}' contains unsupported keys: {unknown}"
        )

    file_mode = None
    if "file" in value:
        file_mode = normalize_permission_mode(value["file"], f"{key}.file")

    dir_mode = None
    if "dir" in value:
        dir_mode = normalize_permission_mode(value["dir"], f"{key}.dir")

    recursive = parse_bool_option(value.get("recursive"), f"{key}.recursive", False)

    if file_mode is None and dir_mode is None:
        raise ConfigError(
            f"Entry '{key}' must define at least one of 'file' or 'dir'."
        )

    return PermissionPolicy(file_mode=file_mode, dir_mode=dir_mode, recursive=recursive)


def format_permission_mode(mode: int | None) -> str:
    if mode is None:
        return "-"
    return f"{mode:04o}"


def parse_pattern_list(value: object, key: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ConfigError(f"Entry '{key}' must be a list of strings.")
    parsed: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ConfigError(f"Entry '{key}' must contain only strings.")
        stripped = item.strip()
        if stripped:
            parsed.append(stripped)
    return tuple(parsed)


def parse_profiles(value: object) -> tuple[str, ...]:
    return parse_pattern_list(value, "profiles")


def parse_bool_option(value: object, key: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ConfigError(f"Entry '{key}' must be a boolean if provided.")
    return value


def ordered_unique_profiles(values: Iterable[str]) -> tuple[str, ...]:
    profiles: list[str] = []
    for value in values:
        profile = str(value).strip()
        if profile and profile not in profiles:
            profiles.append(profile)
    return tuple(profiles)


def mapped_profiles(
    profile_map_path: str,
    host_profile: str,
    selection_field: str | None = None,
) -> tuple[str, ...]:
    path = Path(normalize_user_path(profile_map_path)).resolve()
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"Cannot read profile map {path}: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != {"profiles"}:
        raise ConfigError("Profile map must contain only a top-level 'profiles' object.")
    profiles = payload["profiles"]
    if not isinstance(profiles, dict) or not all(isinstance(key, str) for key in profiles):
        raise ConfigError("Profile map 'profiles' must be an object with string keys.")
    if host_profile not in profiles:
        raise ConfigError(f"Unknown profile-map selection: {host_profile}")
    selected = profiles[host_profile]
    if selection_field:
        if not isinstance(selected, dict) or selection_field not in selected:
            raise ConfigError(
                f"Profile map selection '{host_profile}' has no '{selection_field}' field."
            )
        selected = selected[selection_field]
    if not isinstance(selected, list) or not all(isinstance(item, str) for item in selected):
        raise ConfigError(f"Profile map selection '{host_profile}' must be a list of strings.")
    return ordered_unique_profiles(selected)


def parse_ignore_rule(raw: str) -> IgnoreRule | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None

    negated = line.startswith("!")
    if negated:
        line = line[1:]
    line = line.strip()
    if not line:
        return None

    dir_only = line.endswith("/")
    if dir_only:
        line = line[:-1]
    anchored = line.startswith("/")
    if anchored:
        line = line[1:]
    if not line:
        return None

    return IgnoreRule(
        pattern=line,
        negated=negated,
        dir_only=dir_only,
        anchored=anchored,
        basename_only="/" not in line,
    )


def iter_ignore_file_rules(path: Path) -> list[IgnoreRule]:
    return parse_ignore_file_rules(path.read_text())


def parse_ignore_file_rules(contents: str) -> list[IgnoreRule]:
    rules: list[IgnoreRule] = []
    for line in contents.splitlines():
        rule = parse_ignore_rule(line)
        if rule is not None:
            rules.append(rule)
    return rules


def path_parts(path: str) -> tuple[str, ...]:
    normalized = path.strip("/")
    if not normalized:
        return ()
    return tuple(part for part in normalized.split("/") if part not in ("", "."))


def match_path_segments(path_parts_seq: tuple[str, ...], pattern_parts: tuple[str, ...]) -> bool:
    if not pattern_parts:
        return not path_parts_seq
    if pattern_parts[0] == "**":
        rest = pattern_parts[1:]
        if not rest:
            return True
        return any(
            match_path_segments(path_parts_seq[idx:], rest)
            for idx in range(len(path_parts_seq) + 1)
        )
    if not path_parts_seq:
        return False
    if not fnmatch.fnmatchcase(path_parts_seq[0], pattern_parts[0]):
        return False
    return match_path_segments(path_parts_seq[1:], pattern_parts[1:])


def match_rule_to_path(rule: IgnoreRule, rel_path: str, is_dir: bool) -> bool:
    rel = rel_path.strip("/")
    if not rel:
        return False

    candidates: list[tuple[str, bool]] = []
    if is_dir:
        candidates.append((rel, True))
    else:
        candidates.append((rel, False))
        pure = PurePosixPath(rel)
        for parent in pure.parents:
            parent_str = parent.as_posix()
            if parent_str != ".":
                candidates.append((parent_str, True))

    pattern_parts = path_parts(rule.pattern)
    for candidate_path, candidate_is_dir in candidates:
        if rule.dir_only and not candidate_is_dir:
            continue
        candidate_parts = path_parts(candidate_path)
        if rule.basename_only:
            if any(fnmatch.fnmatchcase(part, rule.pattern) for part in candidate_parts):
                return True
            continue
        if rule.anchored:
            if match_path_segments(candidate_parts, pattern_parts):
                return True
            continue
        for idx in range(len(candidate_parts)):
            if match_path_segments(candidate_parts[idx:], pattern_parts):
                return True
    return False


def load_default_filter_rules() -> list[IgnoreRule]:
    try:
        contents = DEFAULT_FILTERS_RESOURCE.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return []
    return parse_ignore_file_rules(contents)


def resolve_ignore_files(entry: Entry, root: Path) -> list[Path]:
    paths: list[Path] = []
    if entry.discover_ignore_files:
        for name in DEFAULT_IGNORE_FILE_NAMES:
            candidate = root / name
            if candidate.exists():
                paths.append(candidate)
    for raw in entry.ignore_files:
        candidate = Path(normalize_user_path(raw))
        if not candidate.is_absolute():
            candidate = (root / candidate).resolve()
        else:
            candidate = candidate.resolve()
        if candidate.exists():
            paths.append(candidate)
    deduped: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        if path not in seen:
            seen.add(path)
            deduped.append(path)
    return deduped


def candidate_rel_path(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def should_keep_candidate(
    entry: Entry,
    root: Path,
    path: Path,
    is_dir: bool,
    default_rules: list[IgnoreRule],
) -> bool:
    rel_path = candidate_rel_path(root, path)
    ignore_file_paths = resolve_ignore_files(entry, root)
    try:
        candidate_resolved = path.resolve(strict=False)
    except OSError:
        candidate_resolved = path.absolute()
    if any(candidate_resolved == ignore_path.resolve(strict=False) for ignore_path in ignore_file_paths):
        return False

    rules: list[IgnoreRule] = []
    if entry.use_default_filters:
        rules.extend(default_rules)
    for ignore_file in ignore_file_paths:
        rules.extend(iter_ignore_file_rules(ignore_file))
    rules.extend(rule for pattern in entry.exclude if (rule := parse_ignore_rule(pattern)) is not None)

    excluded = False
    for rule in rules:
        if match_rule_to_path(rule, rel_path, is_dir):
            excluded = not rule.negated

    include_rules = [
        rule for pattern in entry.include
        if (rule := parse_ignore_rule(pattern)) is not None
    ]
    if include_rules:
        included = any(match_rule_to_path(rule, rel_path, is_dir) for rule in include_rules)
        if not included:
            return False
        excluded = False

    return not excluded


def entry_uses_filters(entry: Entry) -> bool:
    return bool(
        entry.include
        or entry.exclude
        or entry.ignore_files
        or not entry.discover_ignore_files
        or not entry.use_default_filters
    )


def default_config_path() -> Path:
    if os.name == "nt" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "sync-configs" / "manifest.yaml"
    config_home = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return config_home / "sync-configs" / "manifest.yaml"


def parse_args(script_dir: Path) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sync-configs",
        description=textwrap.dedent(DESCRIPTION),
        epilog=textwrap.dedent(
            """\
Examples:
  # Use the default platform configuration
  sync-configs

  # Initialize starter config files
  sync-configs --init
  sync-configs --init --force-init

  # Use a specific config file
  sync-configs --config /path/to/manifest.yaml

  # Run only entries assigned to one or more named profiles
  sync-configs --list-profiles
  sync-configs --dry-run --profile <selected-profile>
  sync-configs --dry-run --profile-map /path/to/profiles.yaml --host-profile <host-profile>

  # Print root + entry file examples
  sync-configs --print-example
"""
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config",
        type=str,
        default=str(default_config_path()),
        help=(
            "Path to the YAML manifest (default: the platform sync-configs config directory)."
            " If a sibling <name>.override.yaml exists, it will be applied first."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=sorted(MODES),
        help="Override the default mode for all entries that do not explicitly set one.",
    )
    parser.add_argument(
        "--no-source-overrides",
        action="store_true",
        help=(
            "Disable preferring <source>.override<ext> (or <source>.override when no ext) when those files exist."
        ),
    )
    parser.add_argument(
        "--profile",
        action="append",
        default=[],
        help=(
            "Activate a named profile. May be passed multiple times or with comma-separated"
            " values. If any profiles are provided, only entries matching them run."
        ),
    )
    parser.add_argument(
        "--host-profile",
        help=(
            "Select profiles for a named host from --profile-map."
            " Explicit --profile values are appended after mapped profiles."
        ),
    )
    parser.add_argument(
        "--profile-map",
        help="Path to an external YAML profile map owned by the caller.",
    )
    parser.add_argument(
        "--profile-map-field",
        help=(
            "Optional list field within a selected profile-map object. This keeps richer "
            "caller-owned profile documents outside the sync-configs schema."
        ),
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List current sync profile names from the configured sync target entries and exit.",
    )
    parser.add_argument(
        "--print-example",
        action="store_true",
        help="Print example root config and entry-file templates, then exit.",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help=(
            "Initialize config scaffolding at --config path: root YAML + entries dir + sample entry file."
        ),
    )
    parser.add_argument(
        "--force-init",
        action="store_true",
        help="Allow --init to overwrite existing scaffold files.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only print the actions without making filesystem changes.",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate the selected manifest and profile map without writes or hooks.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format. JSON output never includes configuration values.",
    )
    parser.add_argument(
        "--managed-path-policy",
        choices=("safe", "strict", "takeover"),
        default="safe",
        help=(
            "Existing-target policy: safe adopts exact source or fresh skeleton files; "
            "strict blocks every unmanaged target; takeover backs up and replaces conflicts."
        ),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show all entries in the final report, including up-to-date ones.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output (enabled by default).",
    )
    args = parser.parse_args()
    normalized_profiles: list[str] = []
    for raw in args.profile:
        for part in raw.split(","):
            profile = part.strip()
            if profile:
                normalized_profiles.append(profile)
    if args.host_profile and not args.profile_map:
        parser.error("--host-profile requires --profile-map.")
    if args.profile_map and not args.host_profile:
        parser.error("--profile-map requires --host-profile.")
    if args.profile_map_field and not args.profile_map:
        parser.error("--profile-map-field requires --profile-map.")
    if args.host_profile:
        try:
            normalized_profiles = [
                *mapped_profiles(
                    args.profile_map,
                    args.host_profile,
                    args.profile_map_field,
                ),
                *normalized_profiles,
            ]
        except ConfigError as exc:
            parser.error(str(exc))
    args.profile = ordered_unique_profiles(normalized_profiles)
    if args.force_init and not args.init:
        parser.error("--force-init requires --init.")
    return args


def candidate_override_path(source: Path) -> Path:
    name = source.name
    if ".override" in name:
        return source
    if source.suffix:
        return source.with_name(f"{source.stem}.override{source.suffix}")
    return source.with_name(f"{name}.override")


def has_glob_pattern(path: Path) -> bool:
    return glob.has_magic(str(path))


def split_glob_path(path: Path) -> tuple[Path, str]:
    parts = path.parts
    root_parts: list[str] = []
    pattern_parts: list[str] = []
    found_magic = False

    for part in parts:
        if not found_magic and not glob.has_magic(part):
            root_parts.append(part)
        else:
            found_magic = True
            pattern_parts.append(part)

    if not found_magic:
        return path.parent, path.name

    root = Path(*root_parts) if root_parts else Path(".")
    pattern = str(Path(*pattern_parts))
    return root, pattern


def derive_glob_name(entry: "Entry", relative: Path, target: Path) -> str:
    if entry.name and entry.name != str(entry.target):
        if relative == Path("."):
            return entry.name
        return f"{entry.name}/{relative.as_posix()}"
    return str(target)


def validate_directory_target(entry: "Entry", kind: str) -> None:
    if entry.target.suffix:
        raise ConfigError(
            f"Entry '{entry.name}' uses {kind} expansion and requires a directory-like "
            f"target, got file-like path: {entry.target}"
        )


def expand_glob_entry(entry: "Entry") -> list["Entry"]:
    validate_directory_target(entry, "glob")
    root, pattern = split_glob_path(entry.source)
    default_rules = load_default_filter_rules()
    matches = sorted(
        match
        for match in root.glob(pattern)
        if should_keep_candidate(entry, root, match, match.is_dir(), default_rules)
    )
    if not matches:
        return []

    expanded: list[Entry] = []
    for match in matches:
        relative = match.relative_to(root)
        target = entry.target / relative
        expanded.append(
            Entry(
                name=derive_glob_name(entry, relative, target),
                source=match,
                target=target,
                mode=entry.mode,
                directory_strategy=entry.directory_strategy,
                profiles=entry.profiles,
                include=entry.include,
                exclude=entry.exclude,
                ignore_files=entry.ignore_files,
                discover_ignore_files=entry.discover_ignore_files,
                use_default_filters=entry.use_default_filters,
                group=entry.group,
                subgroup=entry.subgroup,
                scope_label=entry.scope_label,
                permissions=entry.permissions,
                source_permissions=entry.source_permissions,
                reconcile_existing=entry.reconcile_existing,
            )
        )
    return expanded


def expand_directory_entry(entry: "Entry") -> list["Entry"]:
    strategy = entry.directory_strategy
    if strategy == "as_directory":
        if entry_uses_filters(entry):
            raise ConfigError(
                f"Entry '{entry.name}' uses filters but directory_strategy 'as_directory' syncs "
                "the directory as a single unit."
            )
        return [entry]

    validate_directory_target(entry, strategy)
    default_rules = load_default_filter_rules()

    if strategy == "children":
        matches = sorted(
            match
            for match in entry.source.iterdir()
            if should_keep_candidate(entry, entry.source, match, match.is_dir(), default_rules)
        )
        if not matches:
            return [entry]

        expanded: list[Entry] = []
        for match in matches:
            target = entry.target / match.name
            expanded.append(
                Entry(
                    name=derive_glob_name(entry, Path(match.name), target),
                    source=match,
                    target=target,
                    mode=entry.mode,
                    directory_strategy="as_directory",
                    profiles=entry.profiles,
                    include=(),
                    exclude=(),
                    ignore_files=(),
                    discover_ignore_files=True,
                    use_default_filters=True,
                    group=entry.group,
                    subgroup=entry.subgroup,
                    scope_label=entry.scope_label,
                    permissions=entry.permissions,
                    source_permissions=entry.source_permissions,
                    reconcile_existing=entry.reconcile_existing,
                )
            )
        return expanded

    if strategy == "recursive":
        matches = sorted(
            path
            for path in entry.source.rglob("*")
            if path.is_file()
            and should_keep_candidate(entry, entry.source, path, False, default_rules)
        )
        if not matches:
            return [entry]

        expanded: list[Entry] = []
        for match in matches:
            relative = match.relative_to(entry.source)
            target = entry.target / relative
            expanded.append(
                Entry(
                    name=derive_glob_name(entry, relative, target),
                    source=match,
                    target=target,
                    mode=entry.mode,
                    directory_strategy="as_directory",
                    profiles=entry.profiles,
                    include=(),
                    exclude=(),
                    ignore_files=(),
                    discover_ignore_files=True,
                    use_default_filters=True,
                    group=entry.group,
                    subgroup=entry.subgroup,
                    scope_label=entry.scope_label,
                    permissions=entry.permissions,
                    source_permissions=entry.source_permissions,
                    reconcile_existing=entry.reconcile_existing,
                )
            )
        return expanded

    raise ConfigError(
        f"Unsupported directory_strategy '{strategy}'. Allowed values: {sorted(DIRECTORY_STRATEGIES)}"
    )


def expand_entries(entries: list["Entry"]) -> list["Entry"]:
    expanded: list[Entry] = []

    for entry in entries:
        if has_glob_pattern(entry.source):
            expanded.extend(expand_glob_entry(entry))
            continue

        if entry.source.exists() and entry.source.is_dir():
            expanded.extend(expand_directory_entry(entry))
            continue

        if entry_uses_filters(entry):
            raise ConfigError(
                f"Entry '{entry.name}' uses filters but source is not an expanded glob or directory entry."
            )

        expanded.append(entry)

    return expanded


def apply_source_overrides(entries: list[Entry], prefer_overrides: bool) -> list[Entry]:
    if not prefer_overrides:
        return entries

    selected_sources = {entry.source for entry in entries}
    updated: list[Entry] = []
    for entry in entries:
        override_path = candidate_override_path(entry.source)
        # Directory/glob expansion may select both `name.json` and
        # `name.override.json` as independently managed files.  In that case
        # the override is data for its own target (and, for MCP fragments, for
        # the aggregate merger); it must not silently replace the base file's
        # source as well.
        chosen_source = (
            override_path
            if override_path.exists() and override_path not in selected_sources
            else entry.source
        )
        updated.append(
            Entry(
                name=entry.name,
                source=chosen_source,
                target=entry.target,
                mode=entry.mode,
                directory_strategy=entry.directory_strategy,
                profiles=entry.profiles,
                include=entry.include,
                exclude=entry.exclude,
                ignore_files=entry.ignore_files,
                discover_ignore_files=entry.discover_ignore_files,
                use_default_filters=entry.use_default_filters,
                group=entry.group,
                subgroup=entry.subgroup,
                scope_label=entry.scope_label,
                permissions=entry.permissions,
                source_permissions=entry.source_permissions,
                reconcile_existing=entry.reconcile_existing,
                reconcile_removed_keys=entry.reconcile_removed_keys,
                managed_overlay_id=entry.managed_overlay_id,
            )
        )
    return updated


def canonical_target_key(path: Path) -> Path:
    candidate = path if path.is_absolute() else Path.cwd() / path
    normalized = os.path.abspath(os.fspath(candidate))
    return Path(normalized)


def source_identity(entry: Entry) -> tuple[Path, str]:
    try:
        resolved = entry.source.resolve(strict=False)
    except OSError:
        resolved = entry.source.absolute()

    if entry.source.is_file():
        kind = "file"
    elif entry.source.is_dir():
        kind = "dir"
    elif entry.source.exists():
        kind = "path"
    else:
        kind = "missing"
    return resolved, kind


def permission_signature(policy: PermissionPolicy | None) -> tuple[int | None, int | None, bool] | None:
    if policy is None:
        return None
    return (policy.file_mode, policy.dir_mode, policy.recursive)


def entry_signature(
    entry: Entry,
) -> tuple[str, Path, str, tuple[int | None, int | None, bool] | None, tuple[int | None, int | None, bool] | None]:
    source_key, source_kind = source_identity(entry)
    return (
        entry.mode,
        source_key,
        source_kind,
        permission_signature(entry.permissions),
        permission_signature(entry.source_permissions),
    )


def dedupe_and_validate_duplicate_targets(
    entries: list[Entry], use_color: bool, widths: PrintWidths
) -> tuple[list[Entry], int]:
    buckets: dict[Path, list[Entry]] = defaultdict(list)
    for entry in entries:
        buckets[canonical_target_key(entry.target)].append(entry)

    deduped: list[Entry] = []
    processed_targets: set[Path] = set()
    error_count = 0

    for entry in entries:
        key = canonical_target_key(entry.target)
        if key in processed_targets:
            continue
        processed_targets.add(key)

        grouped = buckets[key]
        if len(grouped) == 1:
            deduped.append(grouped[0])
            continue

        signatures = {entry_signature(item) for item in grouped}
        if len(signatures) == 1:
            deduped.append(grouped[0])
            print_status(
                "info",
                "deduplicated "
                f"{len(grouped) - 1} equivalent duplicate target entries for "
                f"{grouped[0].target}; keeping first",
                use_color,
                entry=grouped[0],
                widths=widths,
            )
            continue

        modes = {item.mode for item in grouped}
        if len(modes) > 1:
            reason = "mode mismatch"
        else:
            reason = "source mismatch"

        for item in grouped:
            print_status(
                "errors",
                "duplicate target conflict "
                f"({reason}) for {item.target} [mode={item.mode}, source={item.source}]",
                use_color,
                stream=sys.stderr,
                entry=item,
                widths=widths,
            )
            error_count += 1

    return deduped, error_count


def resolve_config_path(config_arg: str, script_dir: Path) -> Path:
    config_path = Path(normalize_user_path(config_arg))
    if not config_path.is_absolute():
        return (script_dir / config_path).resolve()
    return config_path


def find_override_path(config_path: Path) -> Path | None:
    override_path = config_path.with_name(
        f"{config_path.stem}.override{config_path.suffix}"
    )
    if override_path.exists():
        return override_path
    return None


def merge_entries(base: list["Entry"], overrides: list["Entry"]) -> list["Entry"]:
    override_map = {entry.source: entry for entry in overrides}
    merged: list[Entry] = []

    for entry in base:
        replacement = override_map.pop(entry.source, None)
        if replacement is not None:
            merged.append(replacement)
        else:
            merged.append(entry)

    merged.extend(override_map.values())
    return merged


def load_yaml_mapping(config_path: Path) -> dict:
    try:
        payload = yaml.safe_load(config_path.read_text())
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {config_path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Failed to parse YAML config: {exc}") from exc

    if not isinstance(payload, dict):
        raise ConfigError(f"Config root must be a mapping: {config_path}")
    return payload


def parse_entries_block(
    entries_raw: object, config_dir: Path, resolved_default_mode: str
) -> list[Entry]:
    if not isinstance(entries_raw, list):
        raise ConfigError("Config 'entries' must be a list.")

    entries: List[Entry] = []
    for entry in entries_raw:
        if not isinstance(entry, dict):
            raise ConfigError("Each entry must be a mapping.")

        try:
            source_raw = entry["source"]
            target_raw = entry["target"]
        except KeyError as exc:
            raise ConfigError(
                "Entries must define both 'source' and 'target'."
            ) from exc

        if not isinstance(source_raw, str):
            raise ConfigError("Entry 'source' must be a string.")
        if not isinstance(target_raw, str):
            raise ConfigError("Entry 'target' must be a string.")
        if glob.has_magic(str(target_raw)):
            raise ConfigError(
                "Entry 'target' does not support glob patterns; only 'source' may include globs."
            )

        mode_raw = entry.get("mode", resolved_default_mode)
        if mode_raw not in MODES:
            raise ConfigError(
                f"Unsupported mode '{mode_raw}'. Allowed values: {sorted(MODES)}"
            )

        directory_strategy = entry.get("directory_strategy", "as_directory")
        if directory_strategy not in DIRECTORY_STRATEGIES:
            raise ConfigError(
                "Unsupported directory_strategy "
                f"'{directory_strategy}'. Allowed values: {sorted(DIRECTORY_STRATEGIES)}"
            )
        profiles = parse_profiles(entry.get("profiles"))
        include = parse_pattern_list(entry.get("include"), "include")
        exclude = parse_pattern_list(entry.get("exclude"), "exclude")
        ignore_files = parse_pattern_list(entry.get("ignore_files"), "ignore_files")
        discover_ignore_files = parse_bool_option(
            entry.get("discover_ignore_files"), "discover_ignore_files", True
        )
        use_default_filters = parse_bool_option(
            entry.get("use_default_filters"), "use_default_filters", True
        )
        permissions = parse_permission_policy(entry.get("permissions"), "permissions")
        source_permissions = parse_permission_policy(
            entry.get("source_permissions"), "source_permissions"
        )

        pre_script = entry.get("pre_script")
        if pre_script is not None and not isinstance(pre_script, str):
            raise ConfigError("Entry 'pre_script' must be a string if provided.")
        pre_script_on_fail = entry.get("pre_script_on_fail", "abort")
        if pre_script_on_fail not in SCRIPT_ON_FAIL_POLICIES:
            raise ConfigError(
                f"Unsupported pre_script_on_fail '{pre_script_on_fail}'. "
                f"Allowed values: {sorted(SCRIPT_ON_FAIL_POLICIES)}"
            )

        post_script = entry.get("post_script")
        if post_script is not None and not isinstance(post_script, str):
            raise ConfigError("Entry 'post_script' must be a string if provided.")
        post_script_on_fail = entry.get("post_script_on_fail", "continue")
        if post_script_on_fail not in SCRIPT_ON_FAIL_POLICIES:
            raise ConfigError(
                f"Unsupported post_script_on_fail '{post_script_on_fail}'. "
                f"Allowed values: {sorted(SCRIPT_ON_FAIL_POLICIES)}"
            )

        reconcile_removed_keys = parse_bool_option(
            entry.get("reconcile_removed_keys"), "reconcile_removed_keys", False
        )
        reconcile_existing = parse_bool_option(
            entry.get("reconcile_existing"), "reconcile_existing", False
        )
        if reconcile_existing and mode_raw != "copy":
            raise ConfigError("Entry 'reconcile_existing' is supported only for copy mode.")
        managed_overlay_id = entry.get("managed_overlay_id")
        if managed_overlay_id is not None and (
            not isinstance(managed_overlay_id, str) or not managed_overlay_id.strip()
        ):
            raise ConfigError("Entry 'managed_overlay_id' must be a non-empty string if provided.")
        if reconcile_removed_keys:
            if mode_raw not in {"json_overlay", "toml_overlay"}:
                raise ConfigError("Entry 'reconcile_removed_keys' is supported only for overlay modes.")
            if managed_overlay_id is None:
                raise ConfigError(
                    "Entry 'managed_overlay_id' is required when reconcile_removed_keys is enabled."
                )

        source_path = Path(normalize_user_path(source_raw))
        if not source_path.is_absolute():
            source_path = (config_dir / source_path).resolve()
        else:
            source_path = source_path.resolve()

        target_path = Path(normalize_user_path(str(target_raw)))

        if mode_raw in {"symlink", "json_overlay", "toml_overlay"} and permissions is not None:
            raise ConfigError(
                "Entry 'permissions' is only supported for copy mode; "
                "use 'source_permissions' to chmod a symlinked source path."
            )

        name = entry.get("name") or str(target_path)

        group = entry.get("group")
        if group is not None and not isinstance(group, str):
            raise ConfigError("Entry 'group' must be a string if provided.")

        subgroup = entry.get("subgroup")
        if subgroup is not None and not isinstance(subgroup, str):
            raise ConfigError("Entry 'subgroup' must be a string if provided.")

        entries.append(
            Entry(
                name=name,
                source=source_path,
                target=target_path,
                mode=mode_raw,
                directory_strategy=directory_strategy,
                profiles=profiles,
                include=include,
                exclude=exclude,
                ignore_files=ignore_files,
                discover_ignore_files=discover_ignore_files,
                use_default_filters=use_default_filters,
                group=group,
                subgroup=subgroup,
                scope_label=compose_scope_label(group, subgroup),
                permissions=permissions,
                source_permissions=source_permissions,
                pre_script=pre_script,
                pre_script_on_fail=pre_script_on_fail,
                post_script=post_script,
                post_script_on_fail=post_script_on_fail,
                reconcile_existing=reconcile_existing,
                reconcile_removed_keys=reconcile_removed_keys,
                managed_overlay_id=managed_overlay_id,
            )
        )

    return entries


def load_entries_from_dir(
    base_config_path: Path, entries_dir_raw: object, resolved_default_mode: str
) -> list[Entry]:
    if not isinstance(entries_dir_raw, str):
        raise ConfigError("Config 'entries_dir' must be a string path.")

    entries_dir = Path(normalize_user_path(entries_dir_raw))
    if not entries_dir.is_absolute():
        entries_dir = (base_config_path.parent / entries_dir).resolve()
    else:
        entries_dir = entries_dir.resolve()

    if not entries_dir.exists():
        raise ConfigError(f"entries_dir does not exist: {entries_dir}")
    if not entries_dir.is_dir():
        raise ConfigError(f"entries_dir is not a directory: {entries_dir}")

    config_files = sorted(
        path
        for path in entries_dir.rglob("*")
        if path.is_file() and path.suffix in {".yaml", ".yml"}
    )
    entries: list[Entry] = []
    for config_file in config_files:
        payload = load_yaml_mapping(config_file)
        entries_raw = payload.get("entries")
        if entries_raw is None:
            raise ConfigError(
                f"Config file in entries_dir must contain 'entries': {config_file}"
            )
        file_entries = parse_entries_block(
            entries_raw, base_config_path.parent, resolved_default_mode
        )
        entries.extend(file_entries)

    return entries


def load_config(config_path: Path, default_mode: str | None) -> Iterable[Entry]:
    payload = load_yaml_mapping(config_path)

    config_default = payload.get("default_mode")
    resolved_default_mode = default_mode or config_default or "symlink"
    if resolved_default_mode not in MODES:
        raise ConfigError(
            f"Unsupported default_mode '{resolved_default_mode}'. Allowed values: {sorted(MODES)}"
        )

    entries: list[Entry] = []
    entries_raw = payload.get("entries", [])
    if entries_raw:
        entries.extend(
            parse_entries_block(entries_raw, config_path.parent, resolved_default_mode)
        )
    elif entries_raw is not None and not isinstance(entries_raw, list):
        raise ConfigError("Config 'entries' must be a list.")

    entries_dir_raw = payload.get("entries_dir")
    if entries_dir_raw is not None:
        entries.extend(load_entries_from_dir(config_path, entries_dir_raw, resolved_default_mode))

    return entries


def select_entries_for_profiles(
    entries: Iterable[Entry], active_profiles: Iterable[str]
) -> list[Entry]:
    active = {profile.strip() for profile in active_profiles if profile.strip()}
    selected: list[Entry] = []
    for entry in entries:
        if not active:
            if not entry.profiles:
                selected.append(entry)
            continue

        if set(entry.profiles) & active:
            selected.append(entry)
    return selected


def collect_profile_names(entries: Iterable[Entry]) -> list[str]:
    names = {
        profile
        for entry in entries
        for profile in entry.profiles
        if profile.strip()
    }
    return sorted(names)


def print_example_configs() -> None:
    print("# --- sync_targets.yaml ---")
    print(textwrap.dedent(EXAMPLE_ROOT_CONFIG).rstrip())
    print("\n# --- sync_targets.d/00-example.yaml ---")
    print(textwrap.dedent(EXAMPLE_ENTRY_FILE_CONFIG).rstrip())


def derive_init_paths(config_path: Path) -> tuple[Path, Path, Path]:
    root_path = config_path
    if root_path.name == "sync_targets.yaml":
        entries_dir = root_path.parent / "sync_targets.d"
    else:
        entries_dir = root_path.parent / f"{root_path.stem}.d"
    example_file = entries_dir / "00-example.yaml"
    return root_path, entries_dir, example_file


def build_init_root_yaml(entries_dir_name: str) -> str:
    return textwrap.dedent(
        f"""\
        # Root sync configuration.
        # Most entries should live under the entries directory tree.
        default_mode: symlink
        entries_dir: ./{entries_dir_name}
        """
    ).strip() + "\n"


def build_init_entry_yaml() -> str:
    return textwrap.dedent(EXAMPLE_ENTRY_FILE_CONFIG).rstrip() + "\n"


def run_init(config_path: Path, force: bool, use_color: bool) -> int:
    root_path, entries_dir, example_file = derive_init_paths(config_path)
    conflicts: list[Path] = []

    for path in (root_path, example_file):
        if path.exists() and not force:
            conflicts.append(path)

    if conflicts:
        for path in conflicts:
            print_status(
                "errors",
                f"refusing to overwrite existing file (use --force-init): {path}",
                use_color,
                stream=sys.stderr,
            )
        return 1

    if entries_dir.exists() and not entries_dir.is_dir():
        print_status(
            "errors",
            f"entries path exists and is not a directory: {entries_dir}",
            use_color,
            stream=sys.stderr,
        )
        return 1

    entries_dir.mkdir(parents=True, exist_ok=True)

    root_content = build_init_root_yaml(entries_dir.name)
    example_content = build_init_entry_yaml()

    root_path.write_text(root_content)
    example_file.write_text(example_content)

    print_status("performed", f"wrote {root_path}", use_color)
    print_status("performed", f"wrote {example_file}", use_color)
    print_status(
        "info",
        f"next: sync-configs --config {root_path}",
        use_color,
    )
    return 0


def ensure_parent(path: Path, dry_run: bool, force: bool) -> None:
    if dry_run:
        return

    current = Path(path.anchor) if path.is_absolute() else Path()
    for part in path.parts:
        if path.is_absolute() and part == path.anchor:
            continue
        current = current / part if current != Path() else Path(part)

        if current.is_symlink():
            # A managed directory link is a valid parent boundary.  Replacing
            # it with a real directory makes sync-configs fight consumers such
            # as Ansible that intentionally own the directory as one symlink.
            if current.is_dir():
                continue
            if not force:
                raise NotADirectoryError(
                    "target parent is a symlink that does not resolve to a directory "
                    f"(use --force to replace): {current}"
                )
            current.unlink()
            current.mkdir(exist_ok=True)
            continue

        if current.exists():
            if current.is_dir():
                continue
            if not force:
                raise NotADirectoryError(
                    "target parent exists but is not a directory "
                    f"(use --force to replace): {current}"
                )
            remove_target(current, dry_run=False)
            current.mkdir(exist_ok=True)
            continue

        current.mkdir(exist_ok=True)


def targets_match(entry: Entry) -> bool:
    target = entry.target
    if not target.exists() and not target.is_symlink():
        return False

    try:
        if entry.mode == "symlink" and target.is_symlink():
            return Path(os.path.realpath(target)) == entry.source
        if entry.mode == "copy":
            if target.is_symlink():
                return False
            if target.is_file() and entry.source.is_file():
                return (
                    target.read_bytes() == entry.source.read_bytes()
                    and permission_policy_matches(target, entry.permissions)
                )
            if target.is_dir() and entry.source.is_dir():
                return permission_policy_matches(target, entry.permissions)
    except OSError:
        return False
    return False


def copy_content_matches(entry: Entry) -> bool:
    target = entry.target
    if entry.mode != "copy":
        return False
    if target.is_symlink():
        return False

    try:
        if target.is_file() and entry.source.is_file():
            return target.read_bytes() == entry.source.read_bytes()
        if target.is_dir() and entry.source.is_dir():
            return True
    except OSError:
        return False
    return False


def identical_file_can_be_adopted_as_symlink(entry: Entry) -> bool:
    if entry.mode != "symlink" or entry.target.is_symlink():
        return False
    try:
        return (
            entry.source.is_file()
            and entry.target.is_file()
            and entry.source.read_bytes() == entry.target.read_bytes()
        )
    except OSError:
        return False


def remove_target(path: Path, dry_run: bool) -> None:
    if dry_run:
        return
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def backup_target(path: Path, dry_run: bool) -> Path:
    """Move a conflicting target into the owner-only sync-configs backup tree."""
    home = Path.home().resolve()
    resolved = path.resolve(strict=False)
    try:
        relative = resolved.relative_to(home)
    except ValueError:
        relative = Path("_absolute", *resolved.parts[1:])
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        backup_root = Path(os.environ["LOCALAPPDATA"]) / "sync-configs" / "backups"
    else:
        state_home = Path(os.environ.get("XDG_STATE_HOME", home / ".local/state"))
        backup_root = state_home / "sync-configs" / "backups"
    candidate = backup_root / relative
    suffix = 0
    while candidate.exists() or candidate.is_symlink():
        suffix += 1
        candidate = backup_root / f"{relative}.backup-{suffix}"
    if not dry_run:
        candidate.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(candidate))
    return candidate


def create_symlink(entry: Entry, dry_run: bool) -> None:
    if dry_run:
        return
    target_is_dir = entry.source.is_dir()
    entry.target.symlink_to(entry.source, target_is_directory=target_is_dir)


def stat_permission_bits(path: Path) -> int:
    return path.stat().st_mode & 0o7777


def permission_policy_matches(path: Path, policy: PermissionPolicy | None) -> bool:
    if policy is None:
        return True
    if path.is_dir():
        if policy.dir_mode is None:
            return True
        return stat_permission_bits(path) == policy.dir_mode
    if policy.file_mode is None:
        return True
    return stat_permission_bits(path) == policy.file_mode


def apply_permission_policy(path: Path, policy: PermissionPolicy | None, dry_run: bool) -> None:
    if policy is None:
        return
    if dry_run:
        return

    if path.is_dir():
        if policy.dir_mode is not None:
            os.chmod(path, policy.dir_mode)
        if policy.recursive:
            for child in sorted(path.rglob("*")):
                if child.is_dir():
                    if policy.dir_mode is not None:
                        os.chmod(child, policy.dir_mode)
                elif policy.file_mode is not None:
                    os.chmod(child, policy.file_mode)
        return

    if policy.file_mode is not None:
        os.chmod(path, policy.file_mode)


def copy_entry(entry: Entry, dry_run: bool) -> None:
    if dry_run:
        return
    if entry.source.is_dir():
        shutil.copytree(entry.source, entry.target)
    else:
        shutil.copy2(entry.source, entry.target)
    apply_permission_policy(entry.target, entry.permissions, dry_run=False)


def script_command_name(command: str) -> str:
    """Return a normalized executable name from POSIX or Windows-ish command text."""
    name = ntpath.basename(os.path.basename(command)).lower()
    for suffix in (".exe", ".cmd", ".bat"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def current_python_hook_argv(script: str) -> list[str] | None:
    """Convert simple python hook commands to argv using this interpreter."""
    stripped = script.strip()
    if not stripped or SHELL_META_CHARS.search(stripped):
        return None

    try:
        parts = shlex.split(stripped, posix=os.name != "nt")
    except ValueError:
        return None

    if not parts or script_command_name(parts[0]) not in PYTHON_HOOK_COMMANDS:
        return None
    if not sys.executable:
        return None
    return [sys.executable, *parts[1:]]


def run_entry_script(
    script: str,
    config_dir: Path,
    dry_run: bool,
) -> subprocess.CompletedProcess[str] | None:
    """Run a per-entry hook script from the config directory.

    Scripts are executed via the shell so pipes, env vars, and other shell
    syntax work out of the box.  When *dry_run* is ``True`` the script is
    **not** executed and ``None`` is returned.
    """
    if dry_run:
        return None
    python_argv = current_python_hook_argv(script)
    if python_argv is not None:
        try:
            return subprocess.run(
                python_argv,
                shell=False,
                cwd=str(config_dir),
                capture_output=True,
                text=True,
            )
        except OSError:
            pass
    return subprocess.run(
        script,
        shell=True,
        cwd=str(config_dir),
        capture_output=True,
        text=True,
    )


def format_status_line(
    status_key: str,
    message: str,
    use_color: bool,
    entry: Optional["Entry"] = None,
    widths: Optional["PrintWidths"] = None,
) -> str:
    """Build a formatted status line without printing it."""
    prefix = format_status(status_key, use_color)

    if entry is not None and widths is not None:
        scope = entry.scope_label.ljust(widths.scope)
        name = entry.name.ljust(widths.name)
        if message:
            formatted = f"{scope} {name} {message}"
        else:
            formatted = f"{scope} {name}"
    else:
        formatted = message

    return f"{prefix} {formatted}"


def flush_status_buffer(
    buffer: list[StatusRecord],
    use_color: bool,
    widths: PrintWidths,
    verbose: bool = False,
) -> None:
    """Print buffered status records grouped by status category.

    Groups are printed in the order defined by ``STATUS_GROUP_ORDER``.
    Up-to-date entries are collapsed to a single count line unless
    *verbose* is ``True``.
    """
    grouped: dict[str, list[StatusRecord]] = defaultdict(list)
    for record in buffer:
        grouped[record.status_key].append(record)

    for status_key, header in STATUS_GROUP_ORDER:
        records = grouped.get(status_key, [])
        if not records:
            continue

        # Collapse up-to-date entries unless --verbose
        if status_key == "up_to_date" and not verbose:
            label = colorize(
                f"{header} ({len(records)} entries, use --verbose to list)",
                STATUS_COLORS.get(status_key),
                use_color,
            )
            print(f"\n{label}")
            continue

        color_code = STATUS_COLORS.get(status_key)
        label = colorize(f"{header} ({len(records)}):", color_code, use_color)
        print(f"\n{label}")
        for record in records:
            line = format_status_line(
                record.status_key,
                record.message,
                use_color,
                entry=record.entry,
                widths=widths,
            )
            print(f"  {line}")
            if record.script_output:
                for output_line in record.script_output.strip().splitlines():
                    print(f"    {output_line}")

    # Print records with status keys not in STATUS_GROUP_ORDER (e.g. "info")
    shown_keys = {key for key, _ in STATUS_GROUP_ORDER}
    for status_key, records in grouped.items():
        if status_key in shown_keys or not records:
            continue
        for record in records:
            line = format_status_line(
                record.status_key,
                record.message,
                use_color,
                entry=record.entry,
                widths=widths,
            )
            print(f"  {line}")


def process_entry(
    entry: Entry,
    dry_run: bool,
    force: bool,
    buffer: list[StatusRecord],
    managed_path_policy_name: str = "safe",
) -> str:
    """Sync a single entry, appending status records to *buffer*.

    Returns the final status key for this entry (used for stats).
    """
    if not entry.source.exists():
        buffer.append(StatusRecord(
            status_key="missing_source",
            message=f"source missing ({entry.source})",
            entry=entry,
        ))
        return "missing_source"

    try:
        ensure_parent(entry.target.parent, dry_run, force=force)
    except OSError as exc:
        raise OSError(
            f"failed to create parent directory for target {entry.target}: {exc}"
        ) from exc

    try:
        apply_permission_policy(entry.source, entry.source_permissions, dry_run)
    except OSError as exc:
        raise OSError(
            f"failed to chmod source {entry.source}: {exc}"
        ) from exc

    if entry.mode == "json_overlay":
        if not entry.source.is_file():
            raise OSError(f"json_overlay source must be a file: {entry.source}")
        if entry.target.exists() and entry.target.is_dir():
            raise OSError(f"json_overlay target must be a file path: {entry.target}")
        try:
            result = json_overlay.overlay_json_file(
                entry.source,
                entry.target,
                dry_run=dry_run,
                reconcile_removed_keys=entry.reconcile_removed_keys,
                managed_overlay_id=entry.managed_overlay_id,
            )
        except (TypeError, ValueError) as exc:
            raise OSError(f"failed to overlay JSON {entry.source} -> {entry.target}: {exc}") from exc
        if result.changed:
            verb = "would overlay" if dry_run else "overlay"
            overlay_notes = [
                f"added={result.added}",
                f"overwritten={result.overwritten}",
                f"replaced={result.replaced}",
                f"removed={result.removed}",
                f"ownership_changed={int(result.ownership_changed)}",
            ]
            if result.materialized_symlink:
                overlay_notes.append("materialized_symlink=1")
            buffer.append(StatusRecord(
                status_key="performed",
                message=(
                    f"{verb} JSON {entry.source} -> {entry.target} "
                    f"({', '.join(overlay_notes)})"
                ),
                entry=entry,
            ))
            return "performed"
        buffer.append(StatusRecord(
            status_key="up_to_date",
            message="JSON overlay already up to date",
            entry=entry,
        ))
        return "up_to_date"

    if entry.mode == "toml_overlay":
        if not entry.source.is_file():
            raise OSError(f"toml_overlay source must be a file: {entry.source}")
        if entry.target.exists() and entry.target.is_dir():
            raise OSError(f"toml_overlay target must be a file path: {entry.target}")
        try:
            result = toml_overlay.overlay_toml_file(
                entry.source,
                entry.target,
                dry_run=dry_run,
                reconcile_removed_keys=entry.reconcile_removed_keys,
                managed_overlay_id=entry.managed_overlay_id,
            )
        except (TypeError, ValueError) as exc:
            raise OSError(f"failed to overlay TOML {entry.source} -> {entry.target}: {exc}") from exc
        if result.changed:
            verb = "would overlay" if dry_run else "overlay"
            overlay_notes = [
                f"added={result.added}",
                f"overwritten={result.overwritten}",
                f"removed={result.removed}",
                f"ownership_changed={int(result.ownership_changed)}",
            ]
            if result.materialized_symlink:
                overlay_notes.append("materialized_symlink=1")
            buffer.append(StatusRecord(
                status_key="performed",
                message=(
                    f"{verb} TOML {entry.source} -> {entry.target} "
                    f"({', '.join(overlay_notes)})"
                ),
                entry=entry,
            ))
            return "performed"
        buffer.append(StatusRecord(
            status_key="up_to_date",
            message="TOML overlay already up to date",
            entry=entry,
        ))
        return "up_to_date"

    if targets_match(entry):
        buffer.append(StatusRecord(
            status_key="up_to_date",
            message="already up to date",
            entry=entry,
        ))
        return "up_to_date"

    if (
        entry.mode == "copy"
        and entry.target.exists()
        and copy_content_matches(entry)
        and not permission_policy_matches(entry.target, entry.permissions)
    ):
        buffer.append(StatusRecord(
            status_key="performed",
            message=(
                f"chmod {entry.target} to file={format_permission_mode(entry.permissions.file_mode if entry.permissions else None)} "
                f"dir={format_permission_mode(entry.permissions.dir_mode if entry.permissions else None)}"
            ),
            entry=entry,
        ))
        try:
            apply_permission_policy(entry.target, entry.permissions, dry_run)
        except OSError as exc:
            raise OSError(
                f"failed to chmod target {entry.target}: {exc}"
            ) from exc
        return "performed"

    if entry.target.exists() or entry.target.is_symlink():
        adopt_identical_file = identical_file_can_be_adopted_as_symlink(entry)
        classification = None
        if entry.mode == "symlink":
            skeleton = None
            try:
                relative_target = entry.target.resolve(strict=False).relative_to(Path.home().resolve())
                skeleton = Path("/etc/skel") / relative_target
            except ValueError:
                pass
            classification = managed_path_policy.classify_path(
                entry.source,
                entry.target,
                policy=managed_path_policy_name,
                skeleton=skeleton,
            )
        if entry.mode == "symlink" and not entry.target.is_symlink():
            try:
                if entry.target.resolve() == entry.source.resolve():
                    buffer.append(StatusRecord(
                        status_key="up_to_date",
                        message="target already resolves to source via symlinked parent",
                        entry=entry,
                    ))
                    return "up_to_date"
            except OSError:
                pass
        may_replace = bool(
            force
            or entry.reconcile_existing
            or adopt_identical_file
            or (classification is not None and classification.action in {"adopt", "replace"})
        )
        if not may_replace:
            buffer.append(StatusRecord(
                status_key="skipped_existing",
                message=(
                    f"target exists ({entry.target}), managed-path policy "
                    f"{managed_path_policy_name} classified it as "
                    f"{classification.state if classification else 'conflict'}; "
                    "use --managed-path-policy takeover to replace"
                ),
                entry=entry,
            ))
            return "skipped_existing"
        target_was_backed_up = False
        if classification is not None and classification.backup_required:
            backup_path = backup_target(entry.target, dry_run)
            buffer.append(StatusRecord(
                status_key="info",
                message=f"backing up existing target {entry.target} -> {backup_path}",
                entry=entry,
            ))
            target_was_backed_up = True
        buffer.append(StatusRecord(
            status_key="info",
            message=(
                f"adopting identical file as managed symlink {entry.target}"
                if adopt_identical_file
                else f"removing existing target {entry.target}"
            ),
            entry=entry,
        ))
        if not target_was_backed_up:
            try:
                remove_target(entry.target, dry_run)
            except OSError as exc:
                raise OSError(
                    f"failed to remove existing target {entry.target}: {exc}"
                ) from exc

    action = "symlink" if entry.mode == "symlink" else "copy"
    buffer.append(StatusRecord(
        status_key="performed",
        message=f"{action} {entry.source} -> {entry.target}",
        entry=entry,
    ))

    try:
        if entry.mode == "symlink":
            create_symlink(entry, dry_run)
        else:
            copy_entry(entry, dry_run)
    except OSError as exc:
        raise OSError(
            f"failed to {action} {entry.source} -> {entry.target}: {exc}"
        ) from exc

    return "performed"


def print_summary(
    stats: dict[str, int], total: int, group_stats, use_color: bool
) -> None:
    if total == 0:
        return
    updated = stats.get("performed", 0)
    up_to_date = stats.get("up_to_date", 0)
    skipped_existing = stats.get("skipped_existing", 0)
    missing_source = stats.get("missing_source", 0)
    script_error = stats.get("script_error", 0)
    script_skipped = stats.get("script_skipped", 0)
    errors = stats.get("errors", 0)
    skipped_total = skipped_existing + missing_source + script_skipped
    error_total = errors + script_error

    summary = (
        "\nSummary: "
        f"{format_count(updated, 'performed', use_color)} updated, "
        f"{format_count(up_to_date, 'up_to_date', use_color)} up-to-date, "
        f"{format_count(skipped_total, 'skipped_existing', use_color)} skipped "
        f"(existing: {format_count(skipped_existing, 'skipped_existing', use_color)}, "
        f"missing: {format_count(missing_source, 'missing_source', use_color)}"
    )
    if script_skipped:
        summary += f", script: {format_count(script_skipped, 'script_skipped', use_color)}"
    summary += (
        f"), "
        f"{format_count(error_total, 'errors', use_color)} errors"
    )
    if script_error:
        summary += f" (script: {format_count(script_error, 'script_error', use_color)})"
    summary += f" across {total} entries."

    print(summary)

    if group_stats:
        print("\nGroup Breakdown:")
        sorted_groups = sorted(
            group_stats.items(),
            key=lambda item: ((item[0][0] or ""), (item[0][1] or "")),
        )
        label_width = max(
            len(format_group_label(group, subgroup))
            for (group, subgroup), _ in sorted_groups
        )
        for (group, subgroup), counts in sorted_groups:
            total_group = sum(counts.get(key, 0) for key in STATUS_KEYS)
            if total_group == 0:
                continue
            label = format_group_label(group, subgroup)
            group_skipped = (
                counts.get("skipped_existing", 0)
                + counts.get("missing_source", 0)
                + counts.get("script_skipped", 0)
            )
            group_errors = counts.get("errors", 0) + counts.get("script_error", 0)
            print(
                f"  {label.ljust(label_width)}  "
                f"{format_count(counts.get('performed', 0), 'performed', use_color)} updated, "
                f"{format_count(counts.get('up_to_date', 0), 'up_to_date', use_color)} up-to-date, "
                f"{format_count(group_skipped, 'skipped_existing', use_color)} skipped, "
                f"{format_count(group_errors, 'errors', use_color)} errors"
            )


def run(args: argparse.Namespace, script_dir: Path) -> int:
    use_color = not args.no_color
    config_path = resolve_config_path(args.config, script_dir)
    # Typed reconciliation hooks consume the same selected profile set without
    # teaching this generic overlay engine about individual domains.
    os.environ["SYNC_CONFIGS_ACTIVE_PROFILES"] = ",".join(dict.fromkeys(args.profile))

    if args.print_example:
        print_example_configs()
        return 0

    if args.init:
        return run_init(config_path, force=args.force_init, use_color=use_color)

    if args.validate:
        try:
            all_entries = list(load_config(config_path, default_mode=args.mode))
            override_path = find_override_path(config_path)
            if override_path:
                all_entries.extend(load_config(override_path, default_mode=args.mode))
            select_entries_for_profiles(all_entries, args.profile)
        except ConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print("valid")
        return 0

    if args.list_profiles:
        try:
            all_entries = list(load_config(config_path, default_mode=args.mode))
            override_path = find_override_path(config_path)
            if override_path:
                all_entries.extend(load_config(override_path, default_mode=args.mode))
        except ConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        for profile in collect_profile_names(all_entries):
            print(profile)
        return 0

    try:
        entries = select_entries_for_profiles(
            load_config(config_path, default_mode=args.mode),
            args.profile,
        )
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    override_entries: list[Entry] = []
    override_path = find_override_path(config_path)
    if override_path:
        try:
            override_entries = select_entries_for_profiles(
                load_config(override_path, default_mode=args.mode),
                args.profile,
            )
        except ConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    # --- Pre-scripts: run before expansion so generated files are available ---
    config_dir = config_path.parent
    buffer: list[StatusRecord] = []
    stats: dict[str, int] = {key: 0 for key in STATUS_KEYS}
    group_stats = defaultdict(lambda: {key: 0 for key in STATUS_KEYS})

    # Collect entries with post-scripts for later execution.
    post_script_entries: list[Entry] = []
    entries_to_expand: list[Entry] = []

    for entry in entries:
        if entry.pre_script:
            if args.dry_run:
                buffer.append(StatusRecord(
                    status_key="info",
                    message=f"pre_script (dry-run): {entry.pre_script}",
                    entry=entry,
                ))
            else:
                result = run_entry_script(entry.pre_script, config_dir, dry_run=False)
                assert result is not None  # not dry_run so always returns a result
                script_combined = (result.stdout + result.stderr).strip() or None
                if result.returncode != 0:
                    on_fail = entry.pre_script_on_fail
                    if on_fail == "abort":
                        buffer.append(StatusRecord(
                            status_key="script_error",
                            message=f"pre_script failed (exit {result.returncode}, on_fail=abort): {entry.pre_script}",
                            entry=entry,
                            script_output=script_combined,
                        ))
                        stats["script_error"] = stats.get("script_error", 0) + 1
                        increment_group_stat(group_stats, entry, "script_error")
                        continue  # skip this entry entirely
                    elif on_fail == "skip":
                        buffer.append(StatusRecord(
                            status_key="script_skipped",
                            message=f"pre_script failed (exit {result.returncode}, on_fail=skip): {entry.pre_script}",
                            entry=entry,
                            script_output=script_combined,
                        ))
                        stats["script_skipped"] = stats.get("script_skipped", 0) + 1
                        increment_group_stat(group_stats, entry, "script_skipped")
                        continue  # skip this entry
                    else:  # continue
                        buffer.append(StatusRecord(
                            status_key="info",
                            message=f"pre_script failed (exit {result.returncode}, on_fail=continue): {entry.pre_script}",
                            entry=entry,
                            script_output=script_combined,
                        ))
                else:
                    buffer.append(StatusRecord(
                        status_key="performed",
                        message=f"pre_script ok: {entry.pre_script}",
                        entry=entry,
                        script_output=script_combined,
                    ))

        if entry.post_script:
            post_script_entries.append(entry)
        entries_to_expand.append(entry)

    # --- Expand, merge, and deduplicate ---
    entries = expand_entries(entries_to_expand)
    if override_entries:
        override_entries = expand_entries(override_entries)
        entries = merge_entries(entries, override_entries)

    entries = apply_source_overrides(
        entries, prefer_overrides=not args.no_source_overrides
    )

    if not entries and not buffer:
        print("No entries defined in config; nothing to do.")
        return 0

    widths = PrintWidths(
        scope=max((len(entry.scope_label) for entry in entries), default=0),
        name=max((len(entry.name) for entry in entries), default=0),
    )

    entries, duplicate_conflicts = dedupe_and_validate_duplicate_targets(
        entries, use_color=use_color, widths=widths
    )
    if duplicate_conflicts:
        print_status(
            "errors",
            "aborting before sync due to duplicate target conflicts",
            use_color,
            stream=sys.stderr,
        )
        return 1

    # --- Main processing loop: sync each entry ---
    for entry in entries:
        try:
            status = process_entry(
                entry,
                dry_run=args.dry_run,
                force=args.managed_path_policy == "takeover",
                managed_path_policy_name=args.managed_path_policy,
                buffer=buffer,
            )
            stats[status] = stats.get(status, 0) + 1
            increment_group_stat(group_stats, entry, status)
        except Exception as exc:
            buffer.append(StatusRecord(
                status_key="errors",
                message=format_exception(exc),
                entry=entry,
            ))
            stats["errors"] = stats.get("errors", 0) + 1
            increment_group_stat(group_stats, entry, "errors")
            continue

    # --- Post-scripts: run after all entries are processed ---
    for entry in post_script_entries:
        if args.dry_run:
            buffer.append(StatusRecord(
                status_key="info",
                message=f"post_script (dry-run): {entry.post_script}",
                entry=entry,
            ))
        else:
            assert entry.post_script is not None
            result = run_entry_script(entry.post_script, config_dir, dry_run=False)
            assert result is not None
            script_combined = (result.stdout + result.stderr).strip() or None
            if result.returncode != 0:
                on_fail = entry.post_script_on_fail
                if on_fail == "abort":
                    buffer.append(StatusRecord(
                        status_key="script_error",
                        message=f"post_script failed (exit {result.returncode}, on_fail=abort): {entry.post_script}",
                        entry=entry,
                        script_output=script_combined,
                    ))
                    stats["script_error"] = stats.get("script_error", 0) + 1
                    increment_group_stat(group_stats, entry, "script_error")
                else:  # skip or continue — post-sync, so both just warn
                    buffer.append(StatusRecord(
                        status_key="info",
                        message=f"post_script failed (exit {result.returncode}, on_fail={on_fail}): {entry.post_script}",
                        entry=entry,
                        script_output=script_combined,
                    ))
            else:
                buffer.append(StatusRecord(
                    status_key="performed",
                    message=f"post_script ok: {entry.post_script}",
                    entry=entry,
                    script_output=script_combined,
                ))

    # --- Buffered output: print all status records grouped by category ---
    flush_status_buffer(
        buffer, use_color=use_color, widths=widths, verbose=args.verbose,
    )

    # Total includes expanded entries plus any pre-script-filtered entries.
    total = (
        len(entries)
        + stats.get("script_error", 0)
        + stats.get("script_skipped", 0)
    )
    print_summary(
        stats, total=total, group_stats=group_stats, use_color=use_color
    )
    error_total = stats.get("errors", 0) + stats.get("script_error", 0)
    return 1 if error_total else 0


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    args = parse_args(script_dir)
    if args.format == "text":
        return run(args, script_dir)

    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        exit_code = run(args, script_dir)
    print(json.dumps({
        "schema_version": 1,
        "outcome": "completed" if exit_code == 0 else "failed",
        "exit_code": exit_code,
        "dry_run": bool(args.dry_run),
        "profiles": list(args.profile),
    }, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
