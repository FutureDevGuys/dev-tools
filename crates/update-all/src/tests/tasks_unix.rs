use super::*;
use crate::config::BootstrapConfig;
use crate::test_support::{env_guard, write_executable as write_executable_atomic};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

struct EnvVarGuard {
    key: &'static str,
    old: Option<OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: impl Into<OsString>) -> Self {
        let old = env::var_os(key);
        env::set_var(key, value.into());
        Self { key, old }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(old) = self.old.take() {
            env::set_var(self.key, old);
        } else {
            env::remove_var(self.key);
        }
    }
}

fn write_executable(path: &Path, content: &str) {
    write_executable_atomic(path, content).unwrap();
}

fn read_counter(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|_| "0".to_string())
}

#[test]
fn sudo_keepalive_drop_stops_thread() {
    let stop = Arc::new(AtomicBool::new(false));
    let active_pid = Arc::new(Mutex::new(None));
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let stop_for_thread = stop.clone();
    let handle = thread::spawn(move || {
        started_tx.send(()).unwrap();
        while !stop_for_thread.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(1));
        }
        done_tx.send(()).unwrap();
    });
    let keepalive = SudoKeepalive {
        stop: stop.clone(),
        active_pid,
        handle: Some(handle),
    };
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();

    drop(keepalive);

    let stopped_by_drop = done_rx.recv_timeout(Duration::from_millis(50)).is_ok();
    if !stopped_by_drop {
        stop.store(true, Ordering::SeqCst);
        let _ = done_rx.recv_timeout(Duration::from_secs(1));
    }
    assert!(
        stopped_by_drop,
        "drop should stop the sudo keepalive thread"
    );
}

fn test_context(privilege_session: Arc<PrivilegeSession>) -> SyncContext {
    SyncContext {
        flags: Sections {
            exclude: BTreeSet::new(),
            only: None,
        },
        host_os: HostOs::Linux,
        updater_config: UpdaterConfig {
            run_all_detected: false,
            include: BTreeSet::new(),
            exclude: BTreeSet::new(),
            privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
            custom_tasks: BTreeMap::new(),
            bootstrap: BootstrapConfig {
                enabled: false,
                windows_foundations: Vec::new(),
            },
        },
        completions_mode: "off".to_string(),
        completion_providers: "npm".to_string(),
        completion_discover: "0".to_string(),
        completion_strict: "warn".to_string(),
        completion_report: "compact".to_string(),
        filter_progress_noise: false,
        emit_plain: false,
        event_tx: None,
        run_log: None,
        rc_root: PathBuf::new(),
        completion_config_path: None,
        completion_catalog_path: PathBuf::new(),
        completion_registry_path: PathBuf::new(),
        task_policies: TaskPolicies {
            npm_install: TaskPolicy::new(10, 0, 0),
            pipx_upgrade: TaskPolicy::new(10, 0, 0),
            system_update: TaskPolicy::new(10, 0, 0),
            aur_update: TaskPolicy::new(10, 0, 0),
            tool_update: TaskPolicy::new(10, 0, 0),
            extra: BTreeMap::new(),
        },
        interactive_runtime: InteractiveRuntimeConfig {
            mode: InteractiveExecutionMode::AutoFallback,
            stall_seconds: 20,
            max_line_bytes: 262_144,
            max_capture_bytes: 16_777_216,
            retry_once: true,
        },
        note_verbosity: crate::config::NoteVerbosity::Failures,
        debug_report: false,
        privilege_session,
        runtime_control: None,
    }
}

#[test]
fn sudo_preflight_runs_once_per_session() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let count_file = temp.path().join("sudo-preflight-count");

    write_executable(
        &bin_dir.join("sudo"),
        r#"#!/bin/sh
set -eu
count_file="${SUDO_STUB_COUNT_FILE:?missing count file}"
if [ "${1:-}" = "-v" ]; then
  count=0
  if [ -f "$count_file" ]; then
    count="$(cat "$count_file")"
  fi
  count=$((count + 1))
  printf '%s\n' "$count" > "$count_file"
  exit 0
fi
if [ "${1:-}" = "-n" ]; then
  shift
  if [ "${1:-}" = "-v" ]; then
    exit 0
  fi
  if [ "${1:-}" = "--" ]; then
    shift
  fi
  exec "$@"
fi
echo "unsupported sudo args: $*" >&2
exit 2
"#,
    );

    let old_path = env::var_os("PATH").unwrap_or_default();
    let merged_path = format!("{}:{}", bin_dir.display(), old_path.to_string_lossy());
    let _path_guard = EnvVarGuard::set("PATH", merged_path);
    let _count_guard = EnvVarGuard::set(
        "SUDO_STUB_COUNT_FILE",
        count_file.as_os_str().to_os_string(),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let first = TaskSpec {
        id: "elevated-a".to_string(),
        label: "Elevated A".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: "true".to_string(),
            args: Vec::new(),
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: true,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };
    let second = TaskSpec {
        id: "elevated-b".to_string(),
        label: "Elevated B".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: "true".to_string(),
            args: Vec::new(),
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: true,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };

    ensure_sudo_preflight_once(&ctx, &first).unwrap();
    ensure_sudo_preflight_once(&ctx, &second).unwrap();

    let count = fs::read_to_string(&count_file).unwrap();
    assert_eq!(count.trim(), "1");
}

#[test]
fn command_policy_retries_transient_network_failure_once_by_default() {
    let temp = TempDir::new().unwrap();
    let script = temp.path().join("flaky-network");
    let counter = temp.path().join("counter");
    write_executable(
        &script,
        r#"#!/bin/sh
count_file="$1"
count=0
if [ -f "$count_file" ]; then
  count="$(cat "$count_file")"
fi
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
if [ "$count" -eq 1 ]; then
  printf '%s\n' 'npm error code ETIMEDOUT' >&2
  exit 1
fi
printf '%s\n' 'ok'
"#,
    );
    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let out = ctx
        .run_command_with_policy(
            "demo",
            script.to_str().unwrap(),
            vec![counter.to_string_lossy().to_string()],
            &TaskPolicy::new(10, 0, 0),
            false,
        )
        .unwrap();

    assert!(out.contains("ok"));
    assert_eq!(read_counter(&counter).trim(), "2");
}

#[test]
fn command_policy_does_not_retry_deterministic_failure_without_policy_retry() {
    let temp = TempDir::new().unwrap();
    let script = temp.path().join("source-validation-fails");
    let counter = temp.path().join("counter");
    write_executable(
        &script,
        r#"#!/bin/sh
count_file="$1"
count=0
if [ -f "$count_file" ]; then
  count="$(cat "$count_file")"
fi
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
printf '%s\n' '==> ERROR: One or more files did not pass the validity check!' >&2
exit 1
"#,
    );
    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let result = ctx.run_command_with_policy(
        "demo",
        script.to_str().unwrap(),
        vec![counter.to_string_lossy().to_string()],
        &TaskPolicy::new(10, 0, 0),
        false,
    );

    assert!(result.is_err());
    assert_eq!(read_counter(&counter).trim(), "1");
}

#[test]
fn npm_refreshes_package_when_current_version_is_missing() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    let npm_root = temp.path().join("npm-root");
    let install_marker = temp.path().join("installed");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&npm_root).unwrap();

    write_executable(
        &bin_dir.join("npm"),
        r#"#!/bin/sh
set -eu

if [ "$1" = "root" ] && [ "${2:-}" = "-g" ]; then
  printf '%s\n' "${NPM_STUB_ROOT:?missing root}"
  exit 0
fi

if [ "$1" = "list" ] && [ "${2:-}" = "-g" ]; then
  cat <<'JSON'
{"dependencies":{"missing-current":{"overridden":false}}}
JSON
  exit 0
fi

if [ "$1" = "outdated" ] && [ "${2:-}" = "-g" ]; then
  if [ -f "${NPM_STUB_INSTALLED:?missing marker}" ]; then
    printf '%s\n' '{}'
  else
    cat <<'JSON'
{"missing-current":{"wanted":"1.2.3","latest":"1.2.3","dependent":"global","location":"/tmp/missing-current"}}
JSON
  fi
  exit 1
fi

if [ "$1" = "view" ]; then
  printf '%s\n' '{}'
  exit 0
fi

if [ "$1" = "install" ]; then
  shift
  found=0
  for arg in "$@"; do
    if [ "$arg" = "missing-current@1.2.3" ]; then
      found=1
    fi
  done
  if [ "$found" -ne 1 ]; then
    printf '%s\n' "missing expected install target: $*" >&2
    exit 2
  fi
  touch "${NPM_STUB_INSTALLED:?missing marker}"
  printf '%s\n' 'installed missing-current'
  exit 0
fi

printf '%s\n' "unexpected npm args: $*" >&2
exit 2
"#,
    );

    let old_path = env::var_os("PATH").unwrap_or_default();
    let merged_path = format!("{}:{}", bin_dir.display(), old_path.to_string_lossy());
    let _path_guard = EnvVarGuard::set("PATH", merged_path);
    let _root_guard = EnvVarGuard::set("NPM_STUB_ROOT", npm_root.as_os_str().to_os_string());
    let _marker_guard = EnvVarGuard::set(
        "NPM_STUB_INSTALLED",
        install_marker.as_os_str().to_os_string(),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let result = npm::task_npm_sync(&ctx).unwrap();

    assert_eq!(result.status, TaskStatus::Completed, "{result:#?}");
    assert!(install_marker.is_file());
    let rows = &result.report_sections[0].rows;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "missing-current");
    assert_eq!(rows[0].status, TaskReportStatus::Updated);
    assert_eq!(rows[0].before.as_deref(), Some("missing metadata"));
    assert_eq!(rows[0].after.as_deref(), Some("1.2.3"));
    assert_eq!(
        rows[0].note.as_deref(),
        Some("current version unavailable; reinstalled selected target")
    );
}

#[test]
fn npm_uses_global_list_version_for_scoped_package_when_current_version_is_missing() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    let npm_root = temp.path().join("npm-root");
    let install_marker = temp.path().join("installed");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&npm_root).unwrap();

    write_executable(
        &bin_dir.join("npm"),
        r#"#!/bin/sh
set -eu

if [ "$1" = "root" ] && [ "${2:-}" = "-g" ]; then
  printf '%s\n' "${NPM_STUB_ROOT:?missing root}"
  exit 0
fi

if [ "$1" = "list" ] && [ "${2:-}" = "-g" ]; then
  cat <<'JSON'
{"dependencies":{"@qwen-code/qwen-code":{"version":"0.15.11","overridden":false}}}
JSON
  exit 0
fi

if [ "$1" = "outdated" ] && [ "${2:-}" = "-g" ]; then
  cat <<'JSON'
{"@qwen-code/qwen-code":{"wanted":"0.15.11","latest":"0.15.11","dependent":"global"}}
JSON
  exit 1
fi

if [ "$1" = "view" ]; then
  printf '%s\n' '"0.15.11"'
  exit 0
fi

if [ "$1" = "install" ]; then
  touch "${NPM_STUB_INSTALLED:?missing marker}"
  printf '%s\n' 'unexpected install'
  exit 0
fi

printf '%s\n' "unexpected npm args: $*" >&2
exit 2
"#,
    );

    let old_path = env::var_os("PATH").unwrap_or_default();
    let merged_path = format!("{}:{}", bin_dir.display(), old_path.to_string_lossy());
    let _path_guard = EnvVarGuard::set("PATH", merged_path);
    let _root_guard = EnvVarGuard::set("NPM_STUB_ROOT", npm_root.as_os_str().to_os_string());
    let _marker_guard = EnvVarGuard::set(
        "NPM_STUB_INSTALLED",
        install_marker.as_os_str().to_os_string(),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let result = npm::task_npm_sync(&ctx).unwrap();

    assert_eq!(result.status, TaskStatus::Completed, "{result:#?}");
    assert!(!install_marker.exists());
    let rows = &result.report_sections[0].rows;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "@qwen-code/qwen-code");
    assert_eq!(rows[0].status, TaskReportStatus::Unchanged);
    assert_eq!(rows[0].before.as_deref(), Some("0.15.11"));
    assert_eq!(rows[0].after.as_deref(), Some("0.15.11"));
    assert_eq!(rows[0].note.as_deref(), Some("target version is not newer"));
}

#[test]
fn npm_uses_package_location_version_when_current_version_is_missing() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    let npm_root = temp.path().join("npm-root");
    let package_dir = npm_root.join("node_modules").join("location-version");
    let install_marker = temp.path().join("installed");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&package_dir).unwrap();
    fs::write(package_dir.join("package.json"), r#"{"version":"1.2.3"}"#).unwrap();

    write_executable(
        &bin_dir.join("npm"),
        r#"#!/bin/sh
set -eu

if [ "$1" = "root" ] && [ "${2:-}" = "-g" ]; then
  printf '%s\n' "${NPM_STUB_ROOT:?missing root}"
  exit 0
fi

if [ "$1" = "list" ] && [ "${2:-}" = "-g" ]; then
  cat <<'JSON'
{"dependencies":{"location-version":{"overridden":false}}}
JSON
  exit 0
fi

if [ "$1" = "outdated" ] && [ "${2:-}" = "-g" ]; then
  printf '{"location-version":{"wanted":"1.2.3","latest":"1.2.3","dependent":"global","location":"%s"}}\n' "${NPM_STUB_PACKAGE_DIR:?missing package dir}"
  exit 1
fi

if [ "$1" = "view" ]; then
  printf '%s\n' '"1.2.3"'
  exit 0
fi

if [ "$1" = "install" ]; then
  touch "${NPM_STUB_INSTALLED:?missing marker}"
  printf '%s\n' 'unexpected install'
  exit 0
fi

printf '%s\n' "unexpected npm args: $*" >&2
exit 2
"#,
    );

    let old_path = env::var_os("PATH").unwrap_or_default();
    let merged_path = format!("{}:{}", bin_dir.display(), old_path.to_string_lossy());
    let _path_guard = EnvVarGuard::set("PATH", merged_path);
    let _root_guard = EnvVarGuard::set("NPM_STUB_ROOT", npm_root.as_os_str().to_os_string());
    let _package_guard = EnvVarGuard::set(
        "NPM_STUB_PACKAGE_DIR",
        package_dir.as_os_str().to_os_string(),
    );
    let _marker_guard = EnvVarGuard::set(
        "NPM_STUB_INSTALLED",
        install_marker.as_os_str().to_os_string(),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let result = npm::task_npm_sync(&ctx).unwrap();

    assert_eq!(result.status, TaskStatus::Completed);
    assert!(!install_marker.exists());
    let rows = &result.report_sections[0].rows;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "location-version");
    assert_eq!(rows[0].status, TaskReportStatus::Unchanged);
    assert_eq!(rows[0].before.as_deref(), Some("1.2.3"));
    assert_eq!(rows[0].after.as_deref(), Some("1.2.3"));
    assert_eq!(rows[0].note.as_deref(), Some("target version is not newer"));
}

#[test]
fn npm_no_updates_reports_installed_global_versions() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    let npm_root = temp.path().join("npm-root");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&npm_root).unwrap();

    write_executable(
        &bin_dir.join("npm"),
        r#"#!/bin/sh
set -eu

if [ "$1" = "root" ] && [ "${2:-}" = "-g" ]; then
  printf '%s\n' "${NPM_STUB_ROOT:?missing root}"
  exit 0
fi

if [ "$1" = "outdated" ] && [ "${2:-}" = "-g" ]; then
  printf '%s\n' '{}'
  exit 0
fi

if [ "$1" = "list" ] && [ "${2:-}" = "-g" ]; then
  cat <<'JSON'
{"dependencies":{"codex":{"version":"0.133.0"},"@qwen-code/qwen-code":{"version":"0.15.11"}}}
JSON
  exit 0
fi

if [ "$1" = "install" ]; then
  printf '%s\n' "install should not run when nothing is outdated" >&2
  exit 2
fi

printf '%s\n' "unexpected npm args: $*" >&2
exit 2
"#,
    );

    let old_path = env::var_os("PATH").unwrap_or_default();
    let merged_path = format!("{}:{}", bin_dir.display(), old_path.to_string_lossy());
    let _path_guard = EnvVarGuard::set("PATH", merged_path);
    let _root_guard = EnvVarGuard::set("NPM_STUB_ROOT", npm_root.as_os_str().to_os_string());

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let result = npm::task_npm_sync(&ctx).unwrap();

    assert_eq!(result.status, TaskStatus::Completed);
    let rows = &result.report_sections[0].rows;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].name, "@qwen-code/qwen-code");
    assert_eq!(rows[0].status, TaskReportStatus::Unchanged);
    assert_eq!(rows[0].before.as_deref(), Some("0.15.11"));
    assert_eq!(rows[0].after.as_deref(), Some("0.15.11"));
    assert_eq!(rows[0].note.as_deref(), Some("installed"));
    assert_eq!(rows[1].name, "codex");
    assert_eq!(rows[1].before.as_deref(), Some("0.133.0"));
    assert_eq!(rows[1].after.as_deref(), Some("0.133.0"));
    assert_eq!(rows[1].note.as_deref(), Some("installed"));
}

#[test]
fn npm_report_does_not_infer_codex_from_path_when_not_npm_owned() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    let npm_root = temp.path().join("npm-root");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&npm_root).unwrap();

    write_executable(
        &bin_dir.join("codex"),
        r#"#!/bin/sh
printf '%s\n' "codex 0.137.0"
"#,
    );
    write_executable(
        &bin_dir.join("npm"),
        r#"#!/bin/sh
set -eu

if [ "$1" = "root" ] && [ "${2:-}" = "-g" ]; then
  printf '%s\n' "${NPM_STUB_ROOT:?missing root}"
  exit 0
fi

if [ "$1" = "outdated" ] && [ "${2:-}" = "-g" ]; then
  printf '%s\n' '{}'
  exit 0
fi

if [ "$1" = "list" ] && [ "${2:-}" = "-g" ]; then
  cat <<'JSON'
{"dependencies":{"@qwen-code/qwen-code":{"version":"0.15.11"}}}
JSON
  exit 0
fi

printf '%s\n' "unexpected npm args: $*" >&2
exit 2
"#,
    );

    let old_path = env::var_os("PATH").unwrap_or_default();
    let merged_path = format!("{}:{}", bin_dir.display(), old_path.to_string_lossy());
    let _path_guard = EnvVarGuard::set("PATH", merged_path);
    let _root_guard = EnvVarGuard::set("NPM_STUB_ROOT", npm_root.as_os_str().to_os_string());

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let result = npm::task_npm_sync(&ctx).unwrap();

    assert_eq!(result.status, TaskStatus::Completed);
    let rows = &result.report_sections[0].rows;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "@qwen-code/qwen-code");
    assert!(rows.iter().all(|row| row.name != "codex"), "{rows:#?}");
}

#[test]
fn external_manager_preflight_skip_reports_current_version() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();

    write_executable(
        &bin_dir.join("uv"),
        r#"#!/bin/sh
set -eu
if [ "${1:-}" = "--version" ]; then
  printf '%s\n' "uv 0.11.11 (stub linux)"
  exit 0
fi
exit 1
"#,
    );
    write_executable(
        &bin_dir.join("pacman"),
        r#"#!/bin/sh
set -eu
if [ "${1:-}" = "-Qqo" ]; then
  printf '%s\n' "uv"
  exit 0
fi
exit 1
"#,
    );

    let old_path = env::var_os("PATH").unwrap_or_default();
    let merged_path = format!("{}:{}", bin_dir.display(), old_path.to_string_lossy());
    let _path_guard = EnvVarGuard::set("PATH", merged_path);
    let spec = TaskSpec {
        id: "uv".to_string(),
        label: "UV".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Managed(ManagedTaskExecutor::Completions),
        category: "language".to_string(),
    };

    let result =
        preflight_external_manager_skip(HostOs::Linux, &spec, "uv").expect("preflight skip");

    assert_eq!(result.status, TaskStatus::Skipped);
    assert!(
        result.details[0].contains("uv is owned by pacman package uv"),
        "{:?}",
        result.details
    );
    assert_eq!(result.report_sections.len(), 1);
    assert_eq!(result.report_sections[0].key, "version_lines");
    let row = &result.report_sections[0].rows[0];
    assert_eq!(row.name, "uv");
    assert_eq!(row.status, TaskReportStatus::Skipped);
    assert_eq!(row.before.as_deref(), Some("0.11.11"));
    assert_eq!(row.after.as_deref(), Some("0.11.11"));
    assert_eq!(
        row.note.as_deref(),
        Some("managed by external package manager")
    );
}

#[test]
fn sudo_preflight_failure_is_cached_per_session() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let count_file = temp.path().join("sudo-preflight-count");

    write_executable(
        &bin_dir.join("sudo"),
        r#"#!/bin/sh
set -eu
count_file="${SUDO_STUB_COUNT_FILE:?missing count file}"
if [ "${1:-}" = "-v" ]; then
  count=0
  if [ -f "$count_file" ]; then
    count="$(cat "$count_file")"
  fi
  count=$((count + 1))
  printf '%s\n' "$count" > "$count_file"
  echo "sudo: a password is required" >&2
  exit 1
fi
echo "unsupported sudo args: $*" >&2
exit 2
"#,
    );

    let old_path = env::var_os("PATH").unwrap_or_default();
    let merged_path = format!("{}:{}", bin_dir.display(), old_path.to_string_lossy());
    let _path_guard = EnvVarGuard::set("PATH", merged_path);
    let _count_guard = EnvVarGuard::set(
        "SUDO_STUB_COUNT_FILE",
        count_file.as_os_str().to_os_string(),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "elevated-a".to_string(),
        label: "Elevated A".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: "true".to_string(),
            args: Vec::new(),
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: true,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };

    let first = ensure_sudo_preflight_once(&ctx, &spec)
        .expect_err("expected failing preflight")
        .to_string();
    let second = ensure_sudo_preflight_once(&ctx, &spec)
        .expect_err("expected cached failing preflight")
        .to_string();
    let count = fs::read_to_string(&count_file).unwrap();

    assert!(first.contains("sudo preflight failed"), "{first}");
    assert_eq!(second, first);
    assert_eq!(count.trim(), "1");
}

#[test]
fn successful_sudo_preflight_clears_cached_runtime_error() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();

    write_executable(
        &bin_dir.join("sudo"),
        r#"#!/bin/sh
set -eu
if [ "${1:-}" = "-v" ]; then
  exit 0
fi
if [ "${1:-}" = "-n" ]; then
  shift
  if [ "${1:-}" = "-v" ]; then
    exit 0
  fi
  if [ "${1:-}" = "--" ]; then
    shift
  fi
  exec "$@"
fi
echo "unsupported sudo args: $*" >&2
exit 2
"#,
    );

    let old_path = env::var_os("PATH").unwrap_or_default();
    let merged_path = format!("{}:{}", bin_dir.display(), old_path.to_string_lossy());
    let _path_guard = EnvVarGuard::set("PATH", merged_path);

    let privilege_session = Arc::new(PrivilegeSession::default());
    record_sudo_runtime_error(
        &privilege_session,
        "sudo keepalive error: password required",
    );
    let ctx = test_context(privilege_session.clone());
    let spec = TaskSpec {
        id: "elevated-a".to_string(),
        label: "Elevated A".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: "true".to_string(),
            args: Vec::new(),
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: true,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };

    ensure_sudo_preflight_once(&ctx, &spec).unwrap();

    assert_eq!(sudo_runtime_error(&privilege_session), None);
}

#[test]
fn sudo_session_task_respects_skip_mode() {
    let mut ctx = test_context(Arc::new(PrivilegeSession::default()));
    ctx.updater_config.privilege_mode = crate::updaters::PrivilegeMode::Skip;

    let spec = TaskSpec {
        id: "needs-sudo-session".to_string(),
        label: "Needs Sudo Session".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: "true".to_string(),
            args: Vec::new(),
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: true,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };

    let cmd = match &spec.kind {
        TaskKind::Command(cmd) => cmd.clone(),
        _ => panic!("expected command task"),
    };
    let result = run_command_task(&ctx, &spec, &cmd).expect("task result");
    assert_eq!(result.status, TaskStatus::Skipped);
    assert!(result
        .details
        .first()
        .map(|d| d.contains("requires elevation; skipped"))
        .unwrap_or(false));
}

#[test]
fn ui_suspend_waits_for_ack() {
    let mut ctx = test_context(Arc::new(PrivilegeSession::default()));
    let (raw_tx, rx) = mpsc::channel::<DashboardEvent>();
    ctx.event_tx = Some(DashboardSender::new(raw_tx, None));

    let ui_thread = thread::spawn(move || {
        let event = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("suspend event");
        match event {
            DashboardEvent::UiSuspendRequested { reason, ack } => {
                assert_eq!(reason, "test-suspend");
                ack.expect("ack sender").send(()).expect("send ack");
            }
            _ => panic!("expected UiSuspendRequested"),
        }
    });

    assert!(ctx.request_ui_suspend_and_wait("test-suspend", Duration::from_secs(1)));
    ui_thread.join().expect("ui thread");
}

#[test]
fn ui_resume_returns_false_when_ack_missing() {
    let mut ctx = test_context(Arc::new(PrivilegeSession::default()));
    let (raw_tx, rx) = mpsc::channel::<DashboardEvent>();
    ctx.event_tx = Some(DashboardSender::new(raw_tx, None));

    let ui_thread = thread::spawn(move || {
        let event = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("resume event");
        match event {
            DashboardEvent::UiResumeRequested { ack: _ } => {}
            _ => panic!("expected UiResumeRequested"),
        }
    });

    assert!(!ctx.request_ui_resume_and_wait(Duration::from_millis(50)));
    ui_thread.join().expect("ui thread");
}

fn collect_log_view_ui_events(
    rx: mpsc::Receiver<DashboardEvent>,
) -> thread::JoinHandle<Vec<&'static str>> {
    thread::spawn(move || {
        let mut events = Vec::new();
        for _ in 0..2 {
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(DashboardEvent::UiSuspendRequested { reason, ack }) => {
                    assert!(
                        reason.contains("opening log viewer for"),
                        "unexpected suspend reason: {reason}"
                    );
                    if let Some(ack) = ack {
                        ack.send(()).expect("send suspend ack");
                    }
                    events.push("suspend");
                }
                Ok(DashboardEvent::UiResumeRequested { ack }) => {
                    if let Some(ack) = ack {
                        ack.send(()).expect("send resume ack");
                    }
                    events.push("resume");
                }
                Ok(other) => panic!("unexpected dashboard event: {other:?}"),
                Err(_) => break,
            }
        }
        events
    })
}

fn collect_log_view_events_until_resume(
    rx: mpsc::Receiver<DashboardEvent>,
    suspend_seen: mpsc::Sender<()>,
) -> thread::JoinHandle<(Vec<&'static str>, Vec<String>)> {
    thread::spawn(move || {
        let mut transitions = Vec::new();
        let mut runtime_lines = Vec::new();
        let mut announced_suspend = false;
        loop {
            match rx.recv_timeout(Duration::from_secs(2)) {
                Ok(DashboardEvent::UiSuspendRequested { reason, ack }) => {
                    assert!(
                        reason.contains("opening log viewer for"),
                        "unexpected suspend reason: {reason}"
                    );
                    if let Some(ack) = ack {
                        ack.send(()).expect("send suspend ack");
                    }
                    transitions.push("suspend");
                    if !announced_suspend {
                        suspend_seen.send(()).expect("send suspend seen");
                        announced_suspend = true;
                    }
                }
                Ok(DashboardEvent::UiResumeRequested { ack }) => {
                    if let Some(ack) = ack {
                        ack.send(()).expect("send resume ack");
                    }
                    transitions.push("resume");
                    break;
                }
                Ok(DashboardEvent::LogLine(record)) => runtime_lines.push(record.line),
                Ok(other) => panic!("unexpected dashboard event: {other:?}"),
                Err(err) => panic!("timed out collecting log view events: {err}"),
            }
        }
        (transitions, runtime_lines)
    })
}

#[test]
fn open_log_view_uses_foreground_pager_and_resumes_dashboard() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let kitty_called_file = temp.path().join("kitty-called");
    let less_args_file = temp.path().join("less-args");
    write_executable(
        &bin_dir.join("kitty"),
        r#"#!/bin/sh
printf '%s\n' "$@" > "${KITTY_CALLED_FILE:?missing kitty called file}"
exit 0
"#,
    );
    write_executable(
        &bin_dir.join("less"),
        r#"#!/bin/sh
printf '%s\n' "$@" > "${LESS_ARGS_FILE:?missing less args file}"
exit 0
"#,
    );

    let run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    fs::write(run_log.run_dir().join("task-npm.log"), "npm log line\n").unwrap();
    let (raw_tx, rx) = mpsc::channel::<DashboardEvent>();
    let tx = DashboardSender::new(raw_tx, Some(run_log.clone()));
    let ui_thread = collect_log_view_ui_events(rx);

    let _path_guard = EnvVarGuard::set("PATH", bin_dir.as_os_str().to_os_string());
    let _kitty_guard = EnvVarGuard::set(
        "KITTY_CALLED_FILE",
        kitty_called_file.as_os_str().to_os_string(),
    );
    let _less_guard = EnvVarGuard::set("LESS_ARGS_FILE", less_args_file.as_os_str().to_os_string());

    open_requested_log_view(
        &tx,
        Some(&run_log),
        &LogViewTarget::Task {
            id: "npm".to_string(),
        },
    )
    .unwrap();

    let events = ui_thread.join().expect("ui thread");
    assert_eq!(events, vec!["suspend", "resume"]);
    let less_args = fs::read_to_string(&less_args_file).unwrap();
    assert!(less_args.contains("+F"), "{less_args}");
    assert!(less_args.contains("-R"), "{less_args}");
    assert!(less_args.contains("-S"), "{less_args}");
    assert!(less_args.contains("task-npm.log"), "{less_args}");
    assert!(
        !kitty_called_file.exists(),
        "log view should not open a popup terminal"
    );
}

#[test]
fn completed_run_control_drain_opens_foreground_log_view_and_resumes_dashboard() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let kitty_called_file = temp.path().join("kitty-called");
    let less_args_file = temp.path().join("less-args");
    write_executable(
        &bin_dir.join("kitty"),
        r#"#!/bin/sh
printf '%s\n' "$@" > "${KITTY_CALLED_FILE:?missing kitty called file}"
exit 0
"#,
    );
    write_executable(
        &bin_dir.join("less"),
        r#"#!/bin/sh
printf '%s\n' "$@" > "${LESS_ARGS_FILE:?missing less args file}"
exit 0
"#,
    );

    let run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    fs::write(run_log.run_dir().join("run.log"), "run log line\n").unwrap();
    let (raw_event_tx, event_rx) = mpsc::channel::<DashboardEvent>();
    let event_tx = DashboardSender::new(raw_event_tx, Some(run_log.clone()));
    let (control_tx, control_rx) = mpsc::channel::<UiControlEvent>();
    let ui_thread = collect_log_view_ui_events(event_rx);

    let _path_guard = EnvVarGuard::set("PATH", bin_dir.as_os_str().to_os_string());
    let _kitty_guard = EnvVarGuard::set(
        "KITTY_CALLED_FILE",
        kitty_called_file.as_os_str().to_os_string(),
    );
    let _less_guard = EnvVarGuard::set("LESS_ARGS_FILE", less_args_file.as_os_str().to_os_string());

    control_tx
        .send(UiControlEvent::OpenLog {
            target: LogViewTarget::Run,
        })
        .unwrap();

    assert!(drain_completed_run_ui_controls(
        &control_rx,
        &event_tx,
        Some(&run_log)
    ));

    let events = ui_thread.join().expect("ui thread");
    assert_eq!(events, vec!["suspend", "resume"]);
    let less_args = fs::read_to_string(&less_args_file).unwrap();
    assert!(less_args.contains("run.log"), "{less_args}");
    assert!(
        !kitty_called_file.exists(),
        "log view should not open a popup terminal"
    );
}

#[test]
fn active_open_log_control_returns_before_foreground_pager_exits() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let less_args_file = temp.path().join("less-args");
    let release_file = temp.path().join("release-pager");
    write_executable(
        &bin_dir.join("less"),
        r#"#!/bin/sh
printf '%s\n' "$@" > "${LESS_ARGS_FILE:?missing less args file}"
while [ ! -f "${PAGER_RELEASE_FILE:?missing release file}" ]; do
  sleep 0.05
done
exit 0
"#,
    );

    let run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    fs::write(run_log.run_dir().join("task-npm.log"), "npm log line\n").unwrap();
    let (raw_tx, rx) = mpsc::channel::<DashboardEvent>();
    let tx = DashboardSender::new(raw_tx, Some(run_log.clone()));
    let ui_thread = collect_log_view_ui_events(rx);
    let pager_path =
        env::join_paths([bin_dir.as_path(), Path::new("/usr/bin"), Path::new("/bin")]).unwrap();
    let _path_guard = EnvVarGuard::set("PATH", pager_path);
    let _less_guard = EnvVarGuard::set("LESS_ARGS_FILE", less_args_file.as_os_str().to_os_string());
    let _release_guard = EnvVarGuard::set(
        "PAGER_RELEASE_FILE",
        release_file.as_os_str().to_os_string(),
    );

    let release_for_thread = release_file.clone();
    let release_thread = thread::spawn(move || {
        thread::sleep(Duration::from_millis(600));
        fs::write(release_for_thread, b"done").unwrap();
    });

    let started = std::time::Instant::now();
    let mut active_log_viewer = None;
    handle_active_open_log_control(
        &tx,
        Some(&run_log),
        LogViewTarget::Task {
            id: "npm".to_string(),
        },
        &mut active_log_viewer,
    );
    let elapsed = started.elapsed();

    release_thread.join().expect("release thread");
    let events = ui_thread.join().expect("ui thread");
    assert_eq!(events, vec!["suspend", "resume"]);
    assert!(
        elapsed < Duration::from_millis(200),
        "active log view handler blocked scheduler for {elapsed:?}"
    );
    assert!(less_args_file.exists(), "foreground pager was not launched");
}

#[test]
fn active_open_log_control_ignores_second_request_while_pager_is_open() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let less_args_file = temp.path().join("less-args");
    let release_file = temp.path().join("release-pager");
    let starts_file = temp.path().join("pager-starts");
    write_executable(
        &bin_dir.join("less"),
        r#"#!/bin/sh
printf '%s\n' 'start' >> "${PAGER_STARTS_FILE:?missing starts file}"
printf '%s\n' "$@" > "${LESS_ARGS_FILE:?missing less args file}"
while [ ! -f "${PAGER_RELEASE_FILE:?missing release file}" ]; do
  sleep 0.05
done
exit 0
"#,
    );

    let run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    fs::write(run_log.run_dir().join("task-npm.log"), "npm log line\n").unwrap();
    let (raw_tx, rx) = mpsc::channel::<DashboardEvent>();
    let tx = DashboardSender::new(raw_tx, Some(run_log.clone()));
    let (suspend_seen_tx, suspend_seen_rx) = mpsc::channel::<()>();
    let ui_thread = collect_log_view_events_until_resume(rx, suspend_seen_tx);
    let pager_path =
        env::join_paths([bin_dir.as_path(), Path::new("/usr/bin"), Path::new("/bin")]).unwrap();
    let _path_guard = EnvVarGuard::set("PATH", pager_path);
    let _less_guard = EnvVarGuard::set("LESS_ARGS_FILE", less_args_file.as_os_str().to_os_string());
    let _release_guard = EnvVarGuard::set(
        "PAGER_RELEASE_FILE",
        release_file.as_os_str().to_os_string(),
    );
    let _starts_guard =
        EnvVarGuard::set("PAGER_STARTS_FILE", starts_file.as_os_str().to_os_string());

    let mut active_log_viewer = None;
    handle_active_open_log_control(
        &tx,
        Some(&run_log),
        LogViewTarget::Task {
            id: "npm".to_string(),
        },
        &mut active_log_viewer,
    );
    suspend_seen_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("first pager suspend event");

    handle_active_open_log_control(
        &tx,
        Some(&run_log),
        LogViewTarget::Task {
            id: "npm".to_string(),
        },
        &mut active_log_viewer,
    );

    fs::write(&release_file, b"done").unwrap();
    if let Some(handle) = active_log_viewer.take() {
        handle.join().expect("active log viewer thread");
    }
    let (events, runtime_lines) = ui_thread.join().expect("ui thread");

    assert_eq!(events, vec!["suspend", "resume"]);
    let starts = fs::read_to_string(&starts_file).unwrap();
    assert_eq!(
        starts.lines().count(),
        1,
        "expected exactly one pager launch, got {starts:?}"
    );
    assert!(
        runtime_lines
            .iter()
            .any(|line| line.contains("log viewer already open")),
        "missing already-open runtime log in {runtime_lines:?}"
    );
}

#[test]
fn interactive_sudo_session_stays_dashboard_managed() {
    let cmd = CommandTask {
        program: "arch-update".to_string(),
        args: vec!["-s".to_string()],
        mode: None,
        command_candidates: Vec::new(),
        pre_commands: Vec::new(),
        report_commands: Vec::new(),
        report_patterns: Vec::new(),
        report_scoped_deltas: Vec::new(),
        policy_key: "system_update".to_string(),
        requires_elevation: false,
        needs_sudo_session: true,
        interactive: true,
        external_window: false,
        shell: false,
        windows_bridge: false,
        report_parser: None,
        plain_header: None,
        plain_start: None,
        success_details: Vec::new(),
        external_manager_skip: false,
    };

    assert_eq!(
        interactive_execution_path(HostOs::Linux, &cmd),
        InteractiveExecutionPath::DashboardManaged
    );
}

#[test]
fn uv_preflight_skips_when_owned_by_pacman() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let count_file = temp.path().join("uv-count");

    write_executable(
        &bin_dir.join("uv"),
        &format!(
            r#"#!/bin/sh
	set -eu
	if [ "${{1:-}}" = "--version" ]; then
	  printf 'uv 0.11.11\n'
	  exit 0
	fi
	count_file="{}"
	count=0
	if [ -f "$count_file" ]; then
  count="$(cat "$count_file")"
fi
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
echo "uv should not have been executed" >&2
exit 99
"#,
            count_file.display()
        ),
    );

    write_executable(
        &bin_dir.join("pacman"),
        r#"#!/bin/sh
set -eu
if [ "${1:-}" = "-Qqo" ] && [ -n "${2:-}" ]; then
  printf 'uv\n'
  exit 0
fi
exit 1
"#,
    );

    let old_path = env::var_os("PATH").unwrap_or_default();
    let merged_path = format!("{}:{}", bin_dir.display(), old_path.to_string_lossy());
    let _path_guard = EnvVarGuard::set("PATH", merged_path);

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "uv".to_string(),
        label: "UV".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: "uv".to_string(),
            args: vec!["self".to_string(), "update".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: true,
        }),
        category: "language".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("task result");

    assert_eq!(result.status, TaskStatus::Skipped);
    assert!(result.details[0].contains("owned by pacman package uv"));
    assert!(result
        .advisories
        .iter()
        .any(|advisory| advisory.summary.contains("external package manager pacman")));
    assert!(
        !count_file.exists(),
        "uv self update should not have been executed"
    );
}

#[test]
fn external_manager_skip_is_command_metadata_not_uv_specific() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let count_file = temp.path().join("custom-count");

    write_executable(
        &bin_dir.join("custom-self-updater"),
        &format!(
            r#"#!/bin/sh
	set -eu
	if [ "${{1:-}}" = "--version" ]; then
	  printf 'custom-self-updater 1.2.3\n'
	  exit 0
	fi
	count_file="{}"
	count=0
	if [ -f "$count_file" ]; then
  count="$(cat "$count_file")"
fi
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
echo "custom updater should not have been executed" >&2
exit 99
"#,
            count_file.display()
        ),
    );

    write_executable(
        &bin_dir.join("pacman"),
        r#"#!/bin/sh
set -eu
if [ "${1:-}" = "-Qqo" ] && [ -n "${2:-}" ]; then
  printf 'custom-pkg\n'
  exit 0
fi
exit 1
"#,
    );

    let old_path = env::var_os("PATH").unwrap_or_default();
    let merged_path = format!("{}:{}", bin_dir.display(), old_path.to_string_lossy());
    let _path_guard = EnvVarGuard::set("PATH", merged_path);

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "custom-self-updater".to_string(),
        label: "Custom Self Updater".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: "custom-self-updater".to_string(),
            args: vec!["self".to_string(), "update".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: true,
        }),
        category: "custom".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("task result");

    assert_eq!(result.status, TaskStatus::Skipped);
    assert!(result.details[0].contains("owned by pacman package custom-pkg"));
    assert!(result
        .advisories
        .iter()
        .any(|advisory| advisory.summary.contains("external package manager pacman")));
    assert!(
        !count_file.exists(),
        "custom updater self update should not have been executed"
    );
}

#[test]
fn interactive_sudo_session_supports_dashboard_input_when_capture_enabled() {
    let cmd = CommandTask {
        program: "arch-update".to_string(),
        args: vec!["-s".to_string()],
        mode: None,
        command_candidates: Vec::new(),
        pre_commands: Vec::new(),
        report_commands: Vec::new(),
        report_patterns: Vec::new(),
        report_scoped_deltas: Vec::new(),
        policy_key: "system_update".to_string(),
        requires_elevation: false,
        needs_sudo_session: true,
        interactive: true,
        external_window: false,
        shell: false,
        windows_bridge: false,
        report_parser: None,
        plain_header: None,
        plain_start: None,
        success_details: Vec::new(),
        external_manager_skip: false,
    };

    assert!(command_supports_dashboard_input(
        &cmd,
        &InteractiveRuntimeConfig {
            mode: InteractiveExecutionMode::AutoFallback,
            stall_seconds: 20,
            max_line_bytes: 262_144,
            max_capture_bytes: 16_777_216,
            retry_once: true,
        }
    ));
}

#[test]
fn interactive_external_window_still_wins_when_requested() {
    let cmd = CommandTask {
        program: "arch-update".to_string(),
        args: vec!["-s".to_string()],
        mode: None,
        command_candidates: Vec::new(),
        pre_commands: Vec::new(),
        report_commands: Vec::new(),
        report_patterns: Vec::new(),
        report_scoped_deltas: Vec::new(),
        policy_key: "system_update".to_string(),
        requires_elevation: false,
        needs_sudo_session: true,
        interactive: true,
        external_window: true,
        shell: false,
        windows_bridge: false,
        report_parser: None,
        plain_header: None,
        plain_start: None,
        success_details: Vec::new(),
        external_manager_skip: false,
    };

    assert_eq!(
        interactive_execution_path(HostOs::Linux, &cmd),
        InteractiveExecutionPath::ExternalWindow
    );
}

#[test]
fn pre_commands_do_not_inherit_primary_external_window_path() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let terminal_count = temp.path().join("terminal-count");
    let pre_count = temp.path().join("pre-count");
    let main_count = temp.path().join("main-count");

    write_executable(
        &bin_dir.join("kitty"),
        &format!(
            r#"#!/bin/sh
set -eu
count_file="{}"
count=0
if [ -f "$count_file" ]; then
  count="$(cat "$count_file")"
fi
printf '%s\n' "$((count + 1))" > "$count_file"
prev=
last=
for arg in "$@"; do
  prev="$last"
  last="$arg"
done
if [ "$prev" = "bash" ]; then
  exec /bin/bash "$last"
fi
exit 2
"#,
            terminal_count.display()
        ),
    );
    write_executable(
        &bin_dir.join("pre-step"),
        &format!(
            r#"#!/bin/sh
set -eu
printf '1\n' > "{}"
"#,
            pre_count.display()
        ),
    );
    write_executable(
        &bin_dir.join("main-step"),
        &format!(
            r#"#!/bin/sh
set -eu
printf '1\n' > "{}"
"#,
            main_count.display()
        ),
    );

    let old_path = env::var_os("PATH").unwrap_or_default();
    let merged_path = format!("{}:{}", bin_dir.display(), old_path.to_string_lossy());
    let _path_guard = EnvVarGuard::set("PATH", merged_path);

    let mut ctx = test_context(Arc::new(PrivilegeSession::default()));
    ctx.run_log = Some(Arc::new(
        crate::logging::RunLogSink::new(temp.path(), false).expect("run log"),
    ));

    let spec = TaskSpec {
        id: "custom-external".to_string(),
        label: "Custom External".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: "main-step".to_string(),
            args: Vec::new(),
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: vec![CommandPreCommand {
                program: "pre-step".to_string(),
                args: Vec::new(),
            }],
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: true,
            external_window: true,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "custom".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("task result");

    assert_eq!(result.status, TaskStatus::Completed);
    assert_eq!(read_counter(&pre_count).trim(), "1");
    assert_eq!(read_counter(&main_count).trim(), "1");
    assert_eq!(
        read_counter(&terminal_count).trim(),
        "1",
        "only the primary command should use the external terminal launcher"
    );
}

#[test]
fn sudo_runtime_error_blocks_sudo_session_task_before_launch() {
    let privilege_session = Arc::new(PrivilegeSession::default());
    record_sudo_runtime_error(
        &privilege_session,
        "sudo keepalive error: password required",
    );
    let ctx = test_context(privilege_session);
    let spec = TaskSpec {
        id: "arch-update-services".to_string(),
        label: "Arch-Update Services".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: "arch-update".to_string(),
            args: vec!["-s".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: true,
            needs_sudo_session: true,
            interactive: true,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("command task result");
    assert_eq!(result.status, TaskStatus::Failed);
    assert!(result.details[0].contains("sudo session is unavailable before launch"));
}

#[test]
fn sudo_session_tasks_launch_with_noninteractive_sudo_after_preflight() {
    let cmd = CommandTask {
        program: "arch-update".to_string(),
        args: vec!["-s".to_string()],
        mode: None,
        command_candidates: Vec::new(),
        pre_commands: Vec::new(),
        report_commands: Vec::new(),
        report_patterns: Vec::new(),
        report_scoped_deltas: Vec::new(),
        policy_key: "system_update".to_string(),
        requires_elevation: true,
        needs_sudo_session: true,
        interactive: false,
        external_window: false,
        shell: false,
        windows_bridge: false,
        report_parser: None,
        plain_header: None,
        plain_start: None,
        success_details: Vec::new(),
        external_manager_skip: false,
    };

    let (program, args) = build_command_invocation(HostOs::Linux, &cmd);
    assert_eq!(program, "sudo");
    assert_eq!(args.first().map(String::as_str), Some("-n"));
    assert_eq!(args.get(1).map(String::as_str), Some("--"));
    assert_eq!(
        Path::new(args.get(2).map(String::as_str).unwrap_or_default())
            .file_name()
            .and_then(|name| name.to_str()),
        Some("arch-update")
    );
    assert_eq!(args.get(3).map(String::as_str), Some("-s"));
}

#[test]
fn interactive_elevated_command_authenticates_and_runs_in_one_sudo_wrapper() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let sudo_log = temp.path().join("sudo.log");
    let sudo_state = temp.path().join("sudo-state");
    let reached_file = temp.path().join("arch-update-reached");

    write_executable(
        &bin_dir.join("sudo"),
        r#"#!/bin/sh
set -eu
log="${SUDO_STUB_LOG:?missing sudo log}"
state="${SUDO_STUB_STATE:?missing sudo state}"
printf 'sudo %s\n' "$*" >> "$log"
if [ "${1:-}" = "-v" ]; then
  printf '%s\n' "$PPID" > "$state"
  exit 0
fi
if [ "${1:-}" = "-n" ]; then
  shift
  if [ "${1:-}" = "-v" ]; then
    exit 0
  fi
  if [ "${1:-}" = "--" ]; then
    shift
  fi
  if [ ! -f "$state" ] || [ "$(cat "$state")" != "$$" ]; then
    echo "sudo: a password is required" >&2
    exit 1
  fi
  exec "$@"
fi
echo "unsupported sudo args: $*" >&2
exit 2
"#,
    );
    write_executable(
        &bin_dir.join("arch-update"),
        r#"#!/bin/sh
set -eu
printf 'reached\n' > "${ARCH_UPDATE_REACHED:?missing reached file}"
printf 'arch-update %s\n' "$*"
"#,
    );

    let old_path = env::var_os("PATH").unwrap_or_default();
    let merged_path = format!("{}:{}", bin_dir.display(), old_path.to_string_lossy());
    let _path_guard = EnvVarGuard::set("PATH", merged_path);
    let _sudo_log_guard = EnvVarGuard::set("SUDO_STUB_LOG", sudo_log.as_os_str().to_os_string());
    let _sudo_state_guard =
        EnvVarGuard::set("SUDO_STUB_STATE", sudo_state.as_os_str().to_os_string());
    let _reached_guard = EnvVarGuard::set(
        "ARCH_UPDATE_REACHED",
        reached_file.as_os_str().to_os_string(),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "arch-update-services".to_string(),
        label: "Arch-Update Services".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: "arch-update".to_string(),
            args: vec!["-s".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: true,
            needs_sudo_session: true,
            interactive: true,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("command task result");
    let sudo_log_after_run = fs::read_to_string(&sudo_log).unwrap_or_default();

    assert_eq!(
        result.status,
        TaskStatus::Completed,
        "{result:#?}\nsudo log:\n{sudo_log_after_run}"
    );
    assert!(reached_file.exists(), "arch-update command was not reached");
    let sudo_log = fs::read_to_string(sudo_log).unwrap();
    let sudo_lines = sudo_log.lines().collect::<Vec<_>>();
    let wrapper_auth = sudo_lines
        .iter()
        .position(|line| *line == "sudo -v")
        .unwrap_or_else(|| panic!("expected in-wrapper sudo -v:\n{sudo_log}"));
    let wrapper_launch = sudo_lines
        .iter()
        .position(|line| line.starts_with("sudo -n --"))
        .unwrap_or_else(|| panic!("expected protected sudo launch:\n{sudo_log}"));
    assert!(sudo_log.contains("sudo -n -v"), "{sudo_log}");
    assert!(
        wrapper_auth < wrapper_launch,
        "sudo -v should precede protected command in the same wrapper:\n{sudo_log}"
    );
}

#[test]
fn yay_conflict_recovery_excludes_target_and_resumes_without_owner_removal() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let log_file = temp.path().join("recovery.log");
    let log_file_str = log_file.display().to_string();
    write_executable(
        &bin_dir.join("yay"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'yay %s\n' "$*" >> "$log_file"
case "${{1:-}}" in
  -Syu)
    if [ "${{3:-}}" = "--ignore" ] && [ "${{4:-}}" = "exodus-debug" ]; then
      cat <<'EOF'
:: 1 package to upgrade/install.
1  core/linux-lts  6.18.28-1 -> 6.18.32-1
EOF
      exit 0
	fi
    cat <<'EOF' >&2
error: failed to commit transaction (conflicting files)
exodus-debug: /usr/lib/debug/.build-id/be/ffc50b8076e4eac5a913fca05e8f10eb93fa0b.debug exists in filesystem (owned by pinokio-bin-debug)
Errors occurred, no packages were upgraded.
EOF
    exit 1
    ;;
esac
echo "unexpected yay args: $*" >&2
exit 2
"#,
            log_file_str
        ),
    );
    write_executable(
        &bin_dir.join("sudo"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'sudo %s\n' "$*" >> "$log_file"
if [ "${{1:-}}" = "-n" ]; then
  shift
  if [ "${{1:-}}" = "--" ]; then
    shift
  fi
  exec "$@"
fi
echo "unsupported sudo args: $*" >&2
exit 2
"#,
            log_file_str
        ),
    );
    write_executable(
        &bin_dir.join("pacman"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'pacman %s\n' "$*" >> "$log_file"
echo "pacman should not be used for default conflict recovery" >&2
exit 9
"#,
            log_file_str
        ),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "yay".to_string(),
        label: "Yay".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: bin_dir.join("yay").display().to_string(),
            args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };

    let cmd = match &spec.kind {
        TaskKind::Command(cmd) => cmd.clone(),
        _ => panic!("expected command task"),
    };
    let result = run_command_task(&ctx, &spec, &cmd).expect("task result");
    assert_eq!(result.status, TaskStatus::Completed);
    assert!(result.details.iter().any(|detail| detail
        .contains("continued bulk update with conflicting package excluded: exodus-debug")));
    assert!(result.advisories.iter().any(|advisory| {
        advisory.code == "package-conflict-excluded"
            && advisory.severity == AdvisorySeverity::Warning
            && !advisory.blocks_dependents
            && advisory.summary.contains("exodus-debug")
    }));
    assert!(result
        .report_sections
        .iter()
        .any(|section| section.key == "package_recovery"));
    let recovery_section = result
        .report_sections
        .iter()
        .find(|section| section.key == "package_recovery")
        .expect("package recovery section");
    let exclusion_row = recovery_section
        .rows
        .iter()
        .find(|row| row.name == "exodus-debug")
        .expect("target exclusion row");
    assert_eq!(exclusion_row.status, TaskReportStatus::Info);
    assert_eq!(exclusion_row.before.as_deref(), Some("bulk conflict"));
    assert_eq!(exclusion_row.after.as_deref(), Some("ignored"));
    assert!(exclusion_row
        .note
        .as_deref()
        .is_some_and(|note| note.contains("pinokio-bin-debug")));

    let log = fs::read_to_string(&log_file).unwrap();
    assert!(log.contains("yay -Syu --noconfirm"));
    assert!(log.contains("yay -Syu --noconfirm --ignore exodus-debug"));
    assert!(!log.contains("pacman "));
    assert!(!log.contains("yay -S --noconfirm pinokio-bin-debug"));
    assert!(!log.contains("yay -S --noconfirm exodus-debug"));
}

#[test]
fn yay_conflict_recovery_reports_ignore_retry_failure_without_owner_removal() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let log_file = temp.path().join("recovery-remove-fail.log");
    let log_file_str = log_file.display().to_string();

    write_executable(
        &bin_dir.join("yay"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'yay %s\n' "$*" >> "$log_file"
if [ "${{1:-}}" = "-Syu" ] && [ "${{3:-}}" = "--ignore" ]; then
  echo "resume failed after ignore" >&2
  exit 1
fi
cat <<'EOF' >&2
error: failed to commit transaction (conflicting files)
exodus-debug: /usr/lib/debug/.build-id/be/ffc50b8076e4eac5a913fca05e8f10eb93fa0b.debug exists in filesystem (owned by pinokio-bin-debug)
Errors occurred, no packages were upgraded.
EOF
exit 1
"#,
            log_file_str
        ),
    );
    write_executable(
        &bin_dir.join("pacman"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'pacman %s\n' "$*" >> "$log_file"
echo "pacman should not be used for default conflict recovery" >&2
exit 9
"#,
            log_file_str
        ),
    );
    write_executable(
        &bin_dir.join("sudo"),
        r#"#!/bin/sh
set -eu
if [ "${1:-}" = "-n" ]; then
  shift
  if [ "${1:-}" = "--" ]; then
    shift
  fi
  exec "$@"
fi
exit 2
"#,
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "yay".to_string(),
        label: "Yay".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: bin_dir.join("yay").display().to_string(),
            args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("task result");
    assert_eq!(result.status, TaskStatus::Failed);
    assert!(result.details[0].contains("recovery resumed bulk update failed"));
    assert!(result
        .report_sections
        .iter()
        .any(|section| section.key == "package_recovery"));
    let recovery_section = result
        .report_sections
        .iter()
        .find(|section| section.key == "package_recovery")
        .expect("package recovery section");
    assert!(recovery_section.rows.iter().any(|row| {
        row.name == "exodus-debug"
            && row.status == TaskReportStatus::Failed
            && row
                .note
                .as_deref()
                .is_some_and(|note| note.contains("resume failed after ignore"))
    }));
    let log = fs::read_to_string(&log_file).unwrap();
    assert!(log.contains("yay -Syu --noconfirm --ignore exodus-debug"));
    assert!(!log.contains("pacman "));
    assert!(!log.contains("yay -S --noconfirm pinokio-bin-debug"));
}

#[test]
fn yay_conflict_recovery_reports_resume_failure() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let log_file = temp.path().join("recovery-resume-fail.log");
    let log_file_str = log_file.display().to_string();
    let cache_dir = temp.path().join("cache").join("yay").join("exodus");
    fs::create_dir_all(&cache_dir).unwrap();
    let cached_pkg = cache_dir.join("exodus-debug-26.3.11-1-x86_64.pkg.tar.zst");
    fs::write(&cached_pkg, b"stub archive").unwrap();
    let cached_pkg_str = cached_pkg.display().to_string();

    write_executable(
        &bin_dir.join("yay"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'yay %s\n' "$*" >> "$log_file"
if [ "${{1:-}}" = "-Syu" ] && [ "${{3:-}}" = "--ignore" ]; then
  echo "resume failed" >&2
  exit 1
	fi
	cat <<'EOF' >&2
:: 2 packages to upgrade/install.
2  core/linux-lts  6.18.28-1 -> 6.18.32-1
1  aur/exodus-debug 26.3.10-1 -> 26.3.11-1
error: failed to commit transaction (conflicting files)
exodus-debug: /usr/lib/debug/.build-id/be/ffc50b8076e4eac5a913fca05e8f10eb93fa0b.debug exists in filesystem (owned by pinokio-bin-debug)
Errors occurred, no packages were upgraded.
 -> error installing: [{}] - exit status 1
EOF
exit 1
"#,
            log_file_str, cached_pkg_str
        ),
    );
    write_executable(
        &bin_dir.join("sudo"),
        r#"#!/bin/sh
set -eu
if [ "${1:-}" = "-n" ]; then
  shift
  if [ "${1:-}" = "--" ]; then
    shift
  fi
  exec "$@"
fi
exit 2
"#,
    );
    write_executable(
        &bin_dir.join("pacman"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'pacman %s\n' "$*" >> "$log_file"
exit 0
"#,
            log_file_str
        ),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "yay".to_string(),
        label: "Yay".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: bin_dir.join("yay").display().to_string(),
            args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: Some(BuiltinReportParser::Yay),
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("task result");
    assert_eq!(result.status, TaskStatus::Failed);
    assert!(result.details[0].contains("recovery resumed bulk update failed"));
    let yay_section = result
        .report_sections
        .iter()
        .find(|section| section.key == "yay_packages")
        .expect("original yay package report should be preserved");
    let names = yay_section
        .rows
        .iter()
        .map(|row| row.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["core/linux-lts", "aur/exodus-debug"]);
}

#[test]
fn yay_conflict_recovery_does_not_restore_owner_after_ignore_resume() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let log_file = temp.path().join("recovery-restore-fail.log");
    let log_file_str = log_file.display().to_string();
    let cache_dir = temp.path().join("cache").join("yay").join("exodus");
    fs::create_dir_all(&cache_dir).unwrap();
    let cached_pkg = cache_dir.join("exodus-debug-26.3.11-1-x86_64.pkg.tar.zst");
    fs::write(&cached_pkg, b"stub archive").unwrap();
    let cached_pkg_str = cached_pkg.display().to_string();

    write_executable(
        &bin_dir.join("yay"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'yay %s\n' "$*" >> "$log_file"
if [ "${{1:-}}" = "-S" ] && [ "${{3:-}}" = "pinokio-bin-debug" ]; then
  echo "restore failed" >&2
  exit 1
fi
case "${{1:-}}" in
  -Syu)
    if [ "${{3:-}}" = "--ignore" ]; then
      printf 'there is nothing to do\n'
      exit 0
    fi
    cat <<'EOF' >&2
error: failed to commit transaction (conflicting files)
exodus-debug: /usr/lib/debug/.build-id/be/ffc50b8076e4eac5a913fca05e8f10eb93fa0b.debug exists in filesystem (owned by pinokio-bin-debug)
Errors occurred, no packages were upgraded.
 -> error installing: [{}] - exit status 1
EOF
    exit 1
    ;;
  -S)
    printf 'installing %s\n' "${{3:-}}"
    exit 0
    ;;
esac
echo "unexpected yay args: $*" >&2
exit 2
"#,
            log_file_str, cached_pkg_str
        ),
    );
    write_executable(
        &bin_dir.join("sudo"),
        r#"#!/bin/sh
set -eu
if [ "${1:-}" = "-n" ]; then
  shift
  if [ "${1:-}" = "--" ]; then
    shift
  fi
  exec "$@"
fi
exit 2
"#,
    );
    write_executable(
        &bin_dir.join("pacman"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'pacman %s\n' "$*" >> "$log_file"
exit 0
"#,
            log_file_str
        ),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "yay".to_string(),
        label: "Yay".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: bin_dir.join("yay").display().to_string(),
            args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("task result");
    assert_eq!(result.status, TaskStatus::Completed);
    assert!(result.details.iter().any(|detail| detail
        .contains("continued bulk update with conflicting package excluded: exodus-debug")));
    let log = fs::read_to_string(&log_file).unwrap();
    assert!(log.contains("yay -Syu --noconfirm --ignore exodus-debug"));
    assert!(!log.contains("yay -S --noconfirm pinokio-bin-debug"));
    assert!(!log.contains("pacman "));
}

#[test]
fn yay_source_validity_recovery_clears_cache_retries_and_resumes() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let log_file = temp.path().join("recovery-source-validity.log");
    let log_file_str = log_file.display().to_string();
    let home_dir = temp.path().join("home");
    let source_dir = home_dir.join(".cache").join("yay").join("foo-bin");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("artifact"), b"cached").unwrap();
    let _home = EnvVarGuard::set("HOME", home_dir.as_os_str());

    write_executable(
        &bin_dir.join("yay"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'yay %s\n' "$*" >> "$log_file"
if [ "${{1:-}}" = "-S" ] && [ "${{3:-}}" = "foo-bin" ]; then
  printf 'installed foo-bin\n'
  exit 0
fi
if [ "${{1:-}}" = "-S" ] && [ "${{3:-}}" = "--answerclean" ] && [ "${{9:-}}" = "foo-bin" ]; then
  printf 'installed foo-bin\n'
  exit 0
fi
if [ "${{1:-}}" = "-Syu" ] && [ "${{3:-}}" = "--ignore" ]; then
  printf 'there is nothing to do\n'
  exit 0
fi
cat <<'EOF' >&2
==> ERROR: One or more files did not pass the validity check!
 -> error downloading sources: HOME_PLACEHOLDER/.cache/yay/foo-bin
 -> error making: foo-bin-exit status 1
EOF
exit 1
"#,
            log_file_str
        )
        .replace("HOME_PLACEHOLDER", &home_dir.display().to_string()),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "yay".to_string(),
        label: "Yay".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: bin_dir.join("yay").display().to_string(),
            args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("task result");
    assert_eq!(result.status, TaskStatus::Completed);
    assert!(result
        .details
        .iter()
        .any(|detail| detail.contains("auto-recovered source/build failure for foo-bin")));
    assert!(!source_dir.exists());
    let recovery_section = result
        .report_sections
        .iter()
        .find(|section| section.key == "package_recovery")
        .expect("package recovery section");
    let cleanup_row = recovery_section
        .rows
        .iter()
        .find(|row| row.name == source_dir.display().to_string())
        .expect("source cleanup recovery row");
    assert_eq!(cleanup_row.status, TaskReportStatus::Skipped);
    assert_eq!(summarize_task_items(&result), "recovered=1 removed=1");

    let log = fs::read_to_string(&log_file).unwrap();
    assert!(log.contains(
        "yay -S --noconfirm --answerclean All --answerdiff None --answeredit None foo-bin"
    ));
    assert!(log.contains("yay -Syu --noconfirm --ignore foo-bin"));
}

#[test]
fn yay_source_validity_recovery_uses_yay_metadata_without_yay_task_id() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let log_file = temp.path().join("configured-aur-recovery.log");
    let log_file_str = log_file.display().to_string();
    let home_dir = temp.path().join("home");
    let source_dir = home_dir.join(".cache").join("yay").join("foo-bin");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("artifact"), b"cached").unwrap();
    let _home = EnvVarGuard::set("HOME", home_dir.as_os_str());

    write_executable(
        &bin_dir.join("yay"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'yay %s\n' "$*" >> "$log_file"
if [ "${{1:-}}" = "-S" ] && [ "${{3:-}}" = "--answerclean" ] && [ "${{9:-}}" = "foo-bin" ]; then
  printf 'installed foo-bin\n'
  exit 0
fi
if [ "${{1:-}}" = "-Syu" ] && [ "${{3:-}}" = "--ignore" ]; then
  printf 'there is nothing to do\n'
  exit 0
fi
cat <<'EOF' >&2
==> ERROR: One or more files did not pass the validity check!
 -> error downloading sources: HOME_PLACEHOLDER/.cache/yay/foo-bin
 -> error making: foo-bin-exit status 1
EOF
exit 1
"#,
            log_file_str
        )
        .replace("HOME_PLACEHOLDER", &home_dir.display().to_string()),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "aur-helper".to_string(),
        label: "AUR Helper".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: bin_dir.join("yay").display().to_string(),
            args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "aur_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: Some(BuiltinReportParser::Yay),
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("task result");
    assert_eq!(result.status, TaskStatus::Completed);
    assert!(result
        .details
        .iter()
        .any(|detail| detail.contains("auto-recovered source/build failure for foo-bin")));
    assert!(!source_dir.exists());
    assert!(result
        .report_sections
        .iter()
        .any(|section| section.key == "package_recovery"));

    let log = fs::read_to_string(&log_file).unwrap();
    assert!(log.contains(
        "yay -S --noconfirm --answerclean All --answerdiff None --answeredit None foo-bin"
    ));
    assert!(log.contains("yay -Syu --noconfirm --ignore foo-bin"));
}

#[test]
fn yay_source_validity_recovery_excludes_unresolved_package_after_flagged_retry() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let log_file = temp.path().join("recovery-source-validity-failure.log");
    let log_file_str = log_file.display().to_string();
    let home_dir = temp.path().join("home");
    let source_dir = home_dir.join(".cache").join("yay").join("foo-bin");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("artifact"), b"cached").unwrap();
    let _home = EnvVarGuard::set("HOME", home_dir.as_os_str());

    write_executable(
        &bin_dir.join("yay"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'yay %s\n' "$*" >> "$log_file"
if [ "${{1:-}}" = "-Syu" ] && [ "${{3:-}}" = "--ignore" ]; then
  cat <<'EOF'
:: 1 package to upgrade/install.
1  core/linux-lts  6.18.28-1 -> 6.18.32-1
EOF
  exit 0
fi
if [ "${{1:-}}" = "-S" ] && [ "${{3:-}}" = "--answerclean" ]; then
  cat <<'EOF' >&2
==> ERROR: One or more files did not pass the validity check!
 -> error downloading sources: HOME_PLACEHOLDER/.cache/yay/foo-bin
 -> error making: foo-bin-exit status 1
EOF
  exit 1
fi
cat <<'EOF' >&2
==> ERROR: One or more files did not pass the validity check!
 -> error downloading sources: HOME_PLACEHOLDER/.cache/yay/foo-bin
 -> error making: foo-bin-exit status 1
EOF
exit 1
"#,
            log_file_str
        )
        .replace("HOME_PLACEHOLDER", &home_dir.display().to_string()),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "yay".to_string(),
        label: "Yay".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: bin_dir.join("yay").display().to_string(),
            args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("task result");
    assert_eq!(result.status, TaskStatus::Completed);
    assert!(result
        .details
        .iter()
        .any(|detail| detail
            .contains("continued bulk update with unresolved package excluded: foo-bin")));
    assert!(result.advisories.iter().any(|advisory| {
        advisory.code == "upstream-source-drift"
            && !advisory.blocks_dependents
            && advisory
                .remediation
                .contains("upstream source or checksum drift")
    }));
    assert!(result
        .report_sections
        .iter()
        .any(|section| section.title == "Package Recovery Actions"));
    let recovery_section = result
        .report_sections
        .iter()
        .find(|section| section.key == "package_recovery")
        .expect("package recovery section");
    let cleanup_row = recovery_section
        .rows
        .iter()
        .find(|row| row.name == source_dir.display().to_string())
        .expect("source cleanup recovery row");
    assert_eq!(cleanup_row.status, TaskReportStatus::Skipped);
    let package_row = recovery_section
        .rows
        .iter()
        .find(|row| row.name == "foo-bin")
        .expect("unresolved package exclusion row");
    assert_eq!(package_row.status, TaskReportStatus::Info);
    assert_eq!(package_row.before.as_deref(), Some("failed"));
    assert_eq!(package_row.after.as_deref(), Some("ignored"));
    assert_eq!(
        summarize_task_items(&result),
        "info=1 removed=1 advisories=1"
    );

    let log = fs::read_to_string(&log_file).unwrap();
    assert!(log.contains(
        "yay -S --noconfirm --answerclean All --answerdiff None --answeredit None foo-bin"
    ));
    assert!(log.contains("yay -Syu --noconfirm --ignore foo-bin"));
}

#[test]
fn yay_source_recovery_ignores_mixed_build_failures_and_dependents() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let log_file = temp.path().join("recovery-mixed-build-dependency.log");
    let log_file_str = log_file.display().to_string();
    let home_dir = temp.path().join("home");
    let gibo_dir = home_dir.join(".cache").join("yay").join("gibo-bin");
    fs::create_dir_all(&gibo_dir).unwrap();
    fs::write(gibo_dir.join("artifact"), b"cached").unwrap();
    let _home = EnvVarGuard::set("HOME", home_dir.as_os_str());

    write_executable(
        &bin_dir.join("yay"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'yay %s\n' "$*" >> "$log_file"
if [ "${{1:-}}" = "-Syu" ] && [ "${{3:-}}" = "--ignore" ]; then
  if [ "${{4:-}}" != "gibo-bin,lib32-gst-plugins-base-libs,lib32-gstreamer" ]; then
    printf 'unexpected ignore list: %s\n' "${{4:-}}" >&2
    exit 9
  fi
  cat <<'EOF'
 -> gibo-bin: ignoring package upgrade (3.0.16-2 => 3.0.22-1)
 -> lib32-gst-plugins-base-libs: ignoring package upgrade (1.28.1-3 => 1.28.3-1)
 -> lib32-gstreamer: ignoring package upgrade (1.28.1-3 => 1.28.3-1)
there is nothing to do
EOF
  exit 0
fi
if [ "${{1:-}}" = "-S" ] && [ "${{9:-}}" = "gibo-bin" ]; then
  cat <<'EOF' >&2
==> ERROR: One or more files did not pass the validity check!
 -> error downloading sources: HOME_PLACEHOLDER/.cache/yay/gibo-bin
 -> error making: gibo-bin-exit status 1
EOF
  exit 1
fi
cat <<'EOF' >&2
1  core/linux-lts                      6.18.28-1 -> 6.18.33-1
2  aur/gibo-bin                        3.0.16-2  -> 3.0.22-1
3  aur/lib32-gst-plugins-base-libs     1.28.1-3  -> 1.28.3-1
4  aur/lib32-gstreamer                 1.28.1-3  -> 1.28.3-1
AUR Dependency (1): lib32-gstreamer-1.28.3-1
AUR Explicit (2): gibo-bin-3.0.22-1, lib32-gst-plugins-base-libs-1.28.3-1
upgrading linux-lts...
==> ERROR: One or more files did not pass the validity check!
 -> error downloading sources: HOME_PLACEHOLDER/.cache/yay/gibo-bin
 -> error making: gibo-bin-exit status 1
gstreamer/subprojects/gstreamer/libs/gst/helpers/ptp/meson.build:26:4: ERROR: Problem encountered: PTP not supported without Rust compiler
==> ERROR: A failure occurred in build().
 -> error making: lib32-gstreamer - exit status 4
gibo-bin - exit status 1
EOF
exit 1
"#,
            log_file_str
        )
        .replace("HOME_PLACEHOLDER", &home_dir.display().to_string()),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "yay".to_string(),
        label: "Yay".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: bin_dir.join("yay").display().to_string(),
            args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: Some(BuiltinReportParser::Yay),
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("task result");
    assert_eq!(result.status, TaskStatus::Completed);
    assert!(result.advisories.iter().any(|advisory| {
        advisory.code == "package-recovery-exclusions" && !advisory.blocks_dependents
    }));

    let yay_rows = &result
        .report_sections
        .iter()
        .find(|section| section.key == "yay_packages")
        .expect("yay package report")
        .rows;
    assert_eq!(
        yay_rows
            .iter()
            .find(|row| row.name == "core/linux-lts")
            .expect("linux row")
            .status,
        TaskReportStatus::Updated
    );
    for package in [
        "aur/gibo-bin",
        "aur/lib32-gst-plugins-base-libs",
        "aur/lib32-gstreamer",
    ] {
        let row = yay_rows
            .iter()
            .find(|row| row.name == package)
            .unwrap_or_else(|| panic!("missing {package} row"));
        assert_eq!(row.status, TaskReportStatus::Skipped, "{row:?}");
        assert_eq!(
            row.note.as_deref(),
            Some("excluded from resumed bulk update")
        );
    }

    let recovery_rows = &result
        .report_sections
        .iter()
        .find(|section| section.key == "package_recovery")
        .expect("package recovery report")
        .rows;
    assert!(recovery_rows.iter().any(|row| {
        row.name == "lib32-gstreamer"
            && row.status == TaskReportStatus::Info
            && row
                .note
                .as_deref()
                .is_some_and(|note| note.contains("PTP not supported without Rust compiler"))
    }));
    assert!(recovery_rows.iter().any(|row| {
        row.name == "lib32-gst-plugins-base-libs"
            && row.status == TaskReportStatus::Info
            && row.note.as_deref().is_some_and(|note| {
                note.contains("dependent package grouped with an unresolved package-level failure")
            })
    }));

    let log = fs::read_to_string(&log_file).unwrap();
    assert!(log.contains(
        "yay -Syu --noconfirm --ignore gibo-bin,lib32-gst-plugins-base-libs,lib32-gstreamer"
    ));
}

#[test]
fn yay_source_recovery_handles_mixed_recovered_and_excluded_packages() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let log_file = temp.path().join("recovery-source-mixed-list.log");
    let log_file_str = log_file.display().to_string();
    let home_dir = temp.path().join("home");
    let alpha_dir = home_dir.join(".cache").join("yay").join("alpha-bin");
    let beta_dir = home_dir.join(".cache").join("yay").join("beta-bin");
    fs::create_dir_all(&alpha_dir).unwrap();
    fs::create_dir_all(&beta_dir).unwrap();
    fs::write(alpha_dir.join("artifact"), b"cached").unwrap();
    fs::write(beta_dir.join("artifact"), b"cached").unwrap();
    let _home = EnvVarGuard::set("HOME", home_dir.as_os_str());

    write_executable(
        &bin_dir.join("yay"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'yay %s\n' "$*" >> "$log_file"
if [ "${{1:-}}" = "-Syu" ] && [ "${{3:-}}" = "--ignore" ] && [ "${{4:-}}" = "alpha-bin,beta-bin" ]; then
  cat <<'EOF'
:: 1 package to upgrade/install.
1  core/linux-lts  6.18.28-1 -> 6.18.32-1
EOF
  exit 0
fi
if [ "${{1:-}}" = "-S" ] && [ "${{9:-}}" = "alpha-bin" ]; then
  cat <<'EOF'
1  aur/alpha-bin  1.0.0-1 -> 1.0.1-1
EOF
  exit 0
fi
if [ "${{1:-}}" = "-S" ] && [ "${{9:-}}" = "beta-bin" ]; then
  cat <<'EOF' >&2
==> ERROR: One or more files did not pass the validity check!
 -> error downloading sources: HOME_PLACEHOLDER/.cache/yay/beta-bin
 -> error making: beta-bin-exit status 1
EOF
  exit 1
fi
cat <<'EOF' >&2
==> ERROR: One or more files did not pass the validity check!
 -> error downloading sources: HOME_PLACEHOLDER/.cache/yay/alpha-bin
error downloading sources: HOME_PLACEHOLDER/.cache/yay/beta-bin
 -> error making: beta-bin-exit status 1
EOF
exit 1
"#,
            log_file_str
        )
        .replace("HOME_PLACEHOLDER", &home_dir.display().to_string()),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "yay".to_string(),
        label: "Yay".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: bin_dir.join("yay").display().to_string(),
            args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: Some(BuiltinReportParser::Yay),
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("task result");
    assert_eq!(result.status, TaskStatus::Completed);
    assert!(result.details.iter().any(|detail| {
        detail.contains("continued bulk update with unresolved package excluded: beta-bin")
    }));
    let recovery_section = result
        .report_sections
        .iter()
        .find(|section| section.key == "package_recovery")
        .expect("package recovery section");
    assert!(recovery_section.rows.iter().any(|row| {
        row.name == "alpha-bin"
            && row.status == TaskReportStatus::Updated
            && row.before.as_deref() == Some("failed")
            && row.after.as_deref() == Some("installed")
    }));
    assert!(recovery_section.rows.iter().any(|row| {
        row.name == "beta-bin"
            && row.status == TaskReportStatus::Info
            && row.before.as_deref() == Some("failed")
            && row.after.as_deref() == Some("ignored")
    }));

    let log = fs::read_to_string(&log_file).unwrap();
    assert!(log.contains(
        "yay -S --noconfirm --answerclean All --answerdiff None --answeredit None alpha-bin"
    ));
    assert!(log.contains(
        "yay -S --noconfirm --answerclean All --answerdiff None --answeredit None beta-bin"
    ));
    assert!(log.contains("yay -Syu --noconfirm --ignore alpha-bin,beta-bin"));
}

#[test]
fn yay_source_validity_retry_failure_preserves_original_package_report() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let log_file = temp
        .path()
        .join("recovery-source-validity-original-report.log");
    let log_file_str = log_file.display().to_string();
    let home_dir = temp.path().join("home");
    let source_dir = home_dir.join(".cache").join("yay").join("foo-bin");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("artifact"), b"cached").unwrap();
    let _home = EnvVarGuard::set("HOME", home_dir.as_os_str());

    write_executable(
        &bin_dir.join("yay"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'yay %s\n' "$*" >> "$log_file"
if [ "${{1:-}}" = "-Syu" ]; then
  cat <<'EOF' >&2
:: 2 packages to upgrade/install.
2  core/linux-lts  6.18.28-1 -> 6.18.32-1
1  aur/foo-bin     1.0.0-1   -> 1.0.1-1
==> ERROR: One or more files did not pass the validity check!
 -> error downloading sources: HOME_PLACEHOLDER/.cache/yay/foo-bin
 -> error making: foo-bin-exit status 1
EOF
  exit 1
fi
cat <<'EOF' >&2
==> ERROR: One or more files did not pass the validity check!
 -> error downloading sources: HOME_PLACEHOLDER/.cache/yay/foo-bin
 -> error making: foo-bin-exit status 1
EOF
exit 1
"#,
            log_file_str
        )
        .replace("HOME_PLACEHOLDER", &home_dir.display().to_string()),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "yay".to_string(),
        label: "Yay".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: bin_dir.join("yay").display().to_string(),
            args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: Some(BuiltinReportParser::Yay),
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("task result");
    assert_eq!(result.status, TaskStatus::Failed);
    let yay_section = result
        .report_sections
        .iter()
        .find(|section| section.key == "yay_packages")
        .expect("original yay package report should be preserved");
    let names = yay_section
        .rows
        .iter()
        .map(|row| row.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["core/linux-lts", "aur/foo-bin"]);
    for row in &yay_section.rows {
        assert_eq!(row.status, TaskReportStatus::Blocked);
        assert_eq!(
            row.note.as_deref(),
            Some("listed before failed transaction; update not confirmed")
        );
    }
    assert!(result
        .report_sections
        .iter()
        .any(|section| section.key == "package_recovery"));

    let log = fs::read_to_string(&log_file).unwrap();
    assert!(log.contains(
        "yay -S --noconfirm --answerclean All --answerdiff None --answeredit None foo-bin"
    ));
}

#[test]
fn yay_source_cleanup_failure_preserves_original_package_report() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let log_file = temp
        .path()
        .join("recovery-source-cleanup-original-report.log");
    let log_file_str = log_file.display().to_string();
    let home_dir = temp.path().join("home");
    let blocked_parent = temp.path().join("blocked-parent");
    let source_dir = blocked_parent.join("foo-bin");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("artifact"), b"cached").unwrap();
    let mut blocked_perms = fs::metadata(&blocked_parent).unwrap().permissions();
    blocked_perms.set_mode(0o500);
    fs::set_permissions(&blocked_parent, blocked_perms).unwrap();
    let _home = EnvVarGuard::set("HOME", home_dir.as_os_str());

    write_executable(
        &bin_dir.join("yay"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'yay %s\n' "$*" >> "$log_file"
cat <<'EOF' >&2
:: 2 packages to upgrade/install.
2  core/linux-lts  6.18.28-1 -> 6.18.32-1
1  aur/foo-bin     1.0.0-1   -> 1.0.1-1
==> ERROR: One or more files did not pass the validity check!
 -> error downloading sources: SOURCE_PLACEHOLDER
 -> error making: foo-bin-exit status 1
EOF
exit 1
"#,
            log_file_str
        )
        .replace("SOURCE_PLACEHOLDER", &source_dir.display().to_string()),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "yay".to_string(),
        label: "Yay".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: bin_dir.join("yay").display().to_string(),
            args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: Some(BuiltinReportParser::Yay),
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("task result");
    let mut restored_perms = fs::metadata(&blocked_parent).unwrap().permissions();
    restored_perms.set_mode(0o700);
    fs::set_permissions(&blocked_parent, restored_perms).unwrap();

    assert_eq!(result.status, TaskStatus::Failed);
    assert!(result.details[0].contains("could not clear package cache/worktree"));
    let yay_section = result
        .report_sections
        .iter()
        .find(|section| section.key == "yay_packages")
        .expect("original yay package report should be preserved");
    let names = yay_section
        .rows
        .iter()
        .map(|row| row.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["core/linux-lts", "aur/foo-bin"]);
    for row in &yay_section.rows {
        assert_eq!(row.status, TaskReportStatus::Blocked);
        assert_eq!(
            row.note.as_deref(),
            Some("listed before failed transaction; update not confirmed")
        );
    }
    assert!(result
        .report_sections
        .iter()
        .any(|section| section.key == "package_recovery"));

    let log = fs::read_to_string(&log_file).unwrap();
    assert!(log.contains("yay -Syu --noconfirm"));
    assert!(!log.contains("yay -S --noconfirm --answerclean"));
}

#[test]
fn yay_source_validity_recovery_preserves_package_conflict_diagnostic() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let log_file = temp.path().join("recovery-source-validity-conflict.log");
    let log_file_str = log_file.display().to_string();
    let home_dir = temp.path().join("home");
    let source_dir = home_dir.join(".cache").join("yay").join("foo-bin");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("artifact"), b"cached").unwrap();
    let _home = EnvVarGuard::set("HOME", home_dir.as_os_str());

    write_executable(
        &bin_dir.join("yay"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'yay %s\n' "$*" >> "$log_file"
if [ "${{1:-}}" = "-Syu" ]; then
  cat <<'EOF' >&2
error: unresolvable package conflicts detected
:: jack2-1.9.22-2 and pipewire-jack-1:1.6.5-1 are in conflict
error: failed to prepare transaction (conflicting dependencies)
==> ERROR: One or more files did not pass the validity check!
 -> error downloading sources: HOME_PLACEHOLDER/.cache/yay/foo-bin
 -> error making: foo-bin-exit status 1
EOF
  exit 1
fi
cat <<'EOF' >&2
==> ERROR: One or more files did not pass the validity check!
 -> error downloading sources: HOME_PLACEHOLDER/.cache/yay/foo-bin
 -> error making: foo-bin-exit status 1
EOF
exit 1
"#,
            log_file_str
        )
        .replace("HOME_PLACEHOLDER", &home_dir.display().to_string()),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "yay".to_string(),
        label: "Yay".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: bin_dir.join("yay").display().to_string(),
            args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("task result");
    let recovery_rows = result
        .report_sections
        .iter()
        .find(|section| section.title == "Package Recovery Actions")
        .expect("package recovery section")
        .rows
        .iter()
        .filter_map(|row| row.note.as_deref())
        .collect::<Vec<_>>();

    assert!(
        recovery_rows
            .iter()
            .any(|note| note.contains("package dependency conflict involving jack2, pipewire-jack")),
        "{recovery_rows:?}"
    );
}

#[test]
fn yay_transaction_blocker_prevents_package_recovery_and_preserves_evidence() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let log_file = temp.path().join("recovery-source-multi-blocker.log");
    let log_file_str = log_file.display().to_string();
    let home_dir = temp.path().join("home");
    let source_dir = home_dir.join(".cache").join("yay").join("gibo-bin");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("artifact"), b"cached").unwrap();
    let _home = EnvVarGuard::set("HOME", home_dir.as_os_str());

    write_executable(
        &bin_dir.join("yay"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'yay %s\n' "$*" >> "$log_file"
if [ "${{1:-}}" = "-Syu" ]; then
  cat <<'EOF' >&2
:: 3 packages to upgrade/install.
3  core/linux-lts             6.18.28-1      -> 6.18.32-2
2  aur/gibo-bin               3.0.16-2       -> 3.0.22-1
1  aur/source-drift-demo-bin   26.429.61741-1 -> 26.513.20950-2
==> ERROR: One or more files did not pass the validity check!
 -> error downloading sources: HOME_PLACEHOLDER/.cache/yay/gibo-bin
error downloading sources: HOME_PLACEHOLDER/.cache/yay/source-drift-demo-bin
error: unresolvable package conflicts detected
:: jack2-1.9.22-2 and pipewire-jack-1:1.6.5-1 are in conflict
error: failed to prepare transaction (conflicting dependencies)
 -> error making: gibo-bin-exit status 1
EOF
  exit 1
fi
cat <<'EOF' >&2
==> ERROR: One or more files did not pass the validity check!
 -> error downloading sources: HOME_PLACEHOLDER/.cache/yay/gibo-bin
 -> error making: gibo-bin-exit status 1
EOF
exit 1
"#,
            log_file_str
        )
        .replace("HOME_PLACEHOLDER", &home_dir.display().to_string()),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "yay".to_string(),
        label: "Yay".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: bin_dir.join("yay").display().to_string(),
            args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: Some(BuiltinReportParser::Yay),
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("task result");

    assert_eq!(result.status, TaskStatus::Failed);
    assert!(result.details.iter().any(|detail| {
        detail.contains("automatic mutation is not safe")
            && detail.contains("package dependency conflict involving jack2, pipewire-jack")
    }));
    assert!(source_dir.join("artifact").is_file());
    let command_log = fs::read_to_string(&log_file).unwrap();
    assert_eq!(command_log.lines().count(), 1, "{command_log}");
    assert!(
        command_log.contains("yay -Syu --noconfirm"),
        "{command_log}"
    );

    let yay_section = result
        .report_sections
        .iter()
        .find(|section| section.key == "yay_packages")
        .expect("original yay package report should be preserved");
    let names = yay_section
        .rows
        .iter()
        .map(|row| row.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "core/linux-lts",
            "aur/gibo-bin",
            "aur/source-drift-demo-bin"
        ]
    );
    for row in &yay_section.rows {
        assert_eq!(row.status, TaskReportStatus::Blocked);
        assert_eq!(
            row.note.as_deref(),
            Some("listed before failed transaction; update not confirmed")
        );
    }

    let recovery_rows = result
        .report_sections
        .iter()
        .find(|section| section.key == "package_recovery")
        .expect("package recovery section")
        .rows
        .iter()
        .collect::<Vec<_>>();
    assert!(
        recovery_rows
            .iter()
            .any(|row| row.name == "source-drift-demo-bin"
                && row.status == TaskReportStatus::Info
                && row
                    .note
                    .as_deref()
                    .is_some_and(|note| note.contains("source/checksum drift"))),
        "{recovery_rows:?}"
    );
    assert!(
        recovery_rows
            .iter()
            .filter_map(|row| row.note.as_deref())
            .any(|note| note.contains("package dependency conflict involving jack2, pipewire-jack")),
        "{recovery_rows:?}"
    );
}

#[test]
fn yay_source_validity_recovery_repairs_unreadable_user_cache_directory() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let home_dir = temp.path().join("home");
    let source_dir = home_dir.join(".cache").join("yay").join("foo-bin");
    let unreadable_dir = source_dir.join("pkg");
    fs::create_dir_all(&unreadable_dir).unwrap();
    fs::write(unreadable_dir.join("artifact"), b"cached").unwrap();
    let mut perms = fs::metadata(&unreadable_dir).unwrap().permissions();
    perms.set_mode(0o111);
    fs::set_permissions(&unreadable_dir, perms).unwrap();
    let _home = EnvVarGuard::set("HOME", home_dir.as_os_str());

    remove_yay_cleanup_path(&source_dir, "foo-bin").expect("cleanup should repair permissions");

    assert!(!source_dir.exists());
}

#[test]
fn yay_cleanup_permission_repair_is_limited_to_expected_cache_path() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let home_dir = temp.path().join("home");
    let outside_dir = temp.path().join("outside-cache");
    let unreadable_dir = outside_dir.join("pkg");
    fs::create_dir_all(&unreadable_dir).unwrap();
    fs::write(unreadable_dir.join("artifact"), b"cached").unwrap();
    let mut perms = fs::metadata(&unreadable_dir).unwrap().permissions();
    perms.set_mode(0o111);
    fs::set_permissions(&unreadable_dir, perms).unwrap();
    let _home = EnvVarGuard::set("HOME", home_dir.as_os_str());

    let err = remove_yay_cleanup_path(&outside_dir, "foo-bin").expect_err("outside path");

    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(outside_dir.exists());
    let mut repaired = fs::metadata(&unreadable_dir).unwrap().permissions();
    repaired.set_mode(0o755);
    fs::set_permissions(&unreadable_dir, repaired).unwrap();
}

#[test]
fn yay_package_recovery_plan_accepts_attributed_build_failure_without_cleanup() {
    let recovery = RecoveryPlan::diagnose(
        PackageManagerKind::PacmanLike,
        vec![RecoveryCause::BuildFailure {
            package: Some("demo-bin".to_string()),
            summary: "AUR build() failed".to_string(),
        }],
    );

    let plan = build_yay_package_recovery_plan(
        "==> ERROR: A failure occurred in build().\n -> error making: demo-bin-exit status 4",
        Some(&recovery),
    )
    .expect("attributed build failure should be recoverable");

    assert_eq!(
        plan.packages,
        vec![YayPackageRecoveryTargetPlan {
            package: "demo-bin".to_string(),
            kind: YayPackageRecoveryKind::BuildFailure,
            cause_summary: Some("AUR build() failed".to_string()),
            cleanup_paths: Vec::new(),
        }]
    );
}

#[test]
fn yay_package_recovery_plan_rejects_unattributed_build_failure() {
    let recovery = RecoveryPlan::diagnose(
        PackageManagerKind::PacmanLike,
        vec![
            RecoveryCause::BuildFailure {
                package: Some("demo-bin".to_string()),
                summary: "AUR build() failed".to_string(),
            },
            RecoveryCause::BuildFailure {
                package: None,
                summary: "unattributed build failure".to_string(),
            },
        ],
    );

    assert!(build_yay_package_recovery_plan(
        "==> ERROR: A failure occurred in build().\n -> error making: demo-bin-exit status 4",
        Some(&recovery),
    )
    .is_none());
}

#[test]
fn yay_attributed_build_failure_retries_then_resumes_without_cache_cleanup() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let log_file = temp.path().join("attributed-build-recovery.log");
    let home_dir = temp.path().join("home");
    let cache_dir = home_dir.join(".cache").join("yay").join("demo-bin");
    fs::create_dir_all(&cache_dir).unwrap();
    fs::write(cache_dir.join("artifact"), b"preserve").unwrap();
    let _home = EnvVarGuard::set("HOME", home_dir.as_os_str());

    write_executable(
        &bin_dir.join("yay"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'yay %s\n' "$*" >> "$log_file"
if [ "${{1:-}}" = "-Syu" ] && [ "${{3:-}}" = "--ignore" ] && [ "${{4:-}}" = "demo-bin" ]; then
  cat <<'EOF'
1  core/linux-lts  6.18.28-1 -> 6.18.32-1
 -> demo-bin: ignoring package upgrade (1.0.0-1 => 1.1.0-1)
EOF
  exit 0
fi
cat <<'EOF' >&2
:: 2 packages to upgrade/install.
2  core/linux-lts  6.18.28-1 -> 6.18.32-1
1  aur/demo-bin    1.0.0-1   -> 1.1.0-1
AUR Explicit (1): demo-bin-1.1.0-1
==> ERROR: A failure occurred in build().
 -> error making: demo-bin-exit status 4
demo-bin - exit status 4
EOF
exit 1
"#,
            log_file.display()
        ),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "yay".to_string(),
        label: "Yay".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: bin_dir.join("yay").display().to_string(),
            args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: Some(BuiltinReportParser::Yay),
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("task result");

    assert_eq!(result.status, TaskStatus::Completed);
    assert!(cache_dir.join("artifact").is_file());
    assert!(result.advisories.iter().any(|advisory| {
        advisory.code == "package-recovery-exclusions" && !advisory.blocks_dependents
    }));
    let yay_rows = &result
        .report_sections
        .iter()
        .find(|section| section.key == "yay_packages")
        .expect("yay package report")
        .rows;
    assert!(yay_rows.iter().any(|row| {
        row.name == "aur/demo-bin"
            && row.status == TaskReportStatus::Skipped
            && row.note.as_deref() == Some("excluded from resumed bulk update")
    }));
    let recovery_rows = &result
        .report_sections
        .iter()
        .find(|section| section.key == "package_recovery")
        .expect("package recovery section")
        .rows;
    assert!(recovery_rows.iter().any(|row| {
        row.name == "demo-bin"
            && row.status == TaskReportStatus::Info
            && row.after.as_deref() == Some("ignored")
    }));
    let log = fs::read_to_string(&log_file).unwrap();
    assert!(log.contains(
        "yay -S --noconfirm --answerclean All --answerdiff None --answeredit None demo-bin"
    ));
    assert!(log.contains("yay -Syu --noconfirm --ignore demo-bin"));
}

#[test]
fn yay_transaction_conflict_prevents_unrelated_source_recovery() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let log_file = temp.path().join("transaction-conflict.log");
    let log_file_str = log_file.display().to_string();
    let home_dir = temp.path().join("home");
    let source_dir = home_dir.join(".cache").join("yay").join("windsurf");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("artifact"), b"cached").unwrap();
    let _home = EnvVarGuard::set("HOME", home_dir.as_os_str());

    write_executable(
        &bin_dir.join("yay"),
        &format!(
            r#"#!/bin/sh
set -eu
log_file="{}"
printf 'yay %s\n' "$*" >> "$log_file"
cat <<'EOF' >&2
install: cannot stat 'usr/share/windsurf/resources/app/out/media/code-iconsvg.svg': No such file or directory
 -> error making: windsurf-exit status 4
error: failed to commit transaction (conflicting files)
/usr/lib/debug/.build-id/be/ffc50b8076e4eac5a913fca05e8f10eb93fa0b exists in both 'mullvad-vpn-bin-debug' and 'pinokio-bin-debug'
Errors occurred, no packages were upgraded.
EOF
exit 1
"#,
            log_file_str
        ),
    );

    let ctx = test_context(Arc::new(PrivilegeSession::default()));
    let spec = TaskSpec {
        id: "yay".to_string(),
        label: "Yay".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: bin_dir.join("yay").display().to_string(),
            args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        }),
        category: "system".to_string(),
    };
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("expected command task");
    };

    let result = run_command_task(&ctx, &spec, cmd).expect("task result");

    assert_eq!(result.status, TaskStatus::Failed);
    assert!(result.details[0].contains("package install transaction hit conflicting files"));
    assert!(source_dir.exists());
    let log = fs::read_to_string(&log_file).unwrap();
    assert!(!log.contains("--answerclean"));
}

#[test]
fn async_outcome_prefers_canceled_over_failed() {
    assert_eq!(
        resolve_async_outcome(false, false, false),
        AsyncRunOutcome::Success
    );
    assert_eq!(
        resolve_async_outcome(false, true, false),
        AsyncRunOutcome::Deferred
    );
    assert_eq!(
        resolve_async_outcome(true, true, false),
        AsyncRunOutcome::Failed
    );
    assert_eq!(
        resolve_async_outcome(false, false, true),
        AsyncRunOutcome::Canceled
    );
    assert_eq!(
        resolve_async_outcome(true, true, true),
        AsyncRunOutcome::Canceled
    );
}
