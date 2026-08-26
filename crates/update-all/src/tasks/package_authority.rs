//! Catalog-driven package-provider authority reconciliation.
//!
//! This module is the Rust boundary around the repository-owned package resolver
//! and executor. It intentionally carries manager/package observations as data so
//! updater tasks do not need program-specific ownership branches.

use super::{SyncContext, TaskReportRow, TaskReportSection, TaskReportStatus};
use crate::updaters::HostOs;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static PACKAGE_AUTHORITY_ACTIVE: AtomicBool = AtomicBool::new(false);
const PACKAGE_AUTHORITY_GATE_TIMEOUT: Duration = Duration::from_secs(30);
const PACKAGE_AUTHORITY_MAX_ARTIFACT_BYTES: usize = 65_536;

/// Input describing installed packages observed by one updater backend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct PackageAuthorityRequest {
    /// Operating-system name used to materialize catalog targets.
    pub os_name: String,
    /// Linux-family name used to select the desired provider.
    pub linux_family: String,
    /// Backend that produced the installed-package observation.
    pub observed_backend: String,
    /// Installed package names observed through that backend.
    pub observed_packages: Vec<String>,
    /// Whether desired-only providers must run their direct command health probe.
    pub verify_desired: bool,
}

/// Ordered package conflict observed in pacman's removal question.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct UpgradeConflictPair {
    pub incoming: String,
    pub remove: String,
}

/// Read-only transaction proof request passed to the repository package executor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct UpgradeConflictProbeRequest {
    pub conflicts: Vec<UpgradeConflictPair>,
    pub package_database_fingerprint: String,
}

/// Bounded result returned by the libalpm-backed transaction proof.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(super) struct UpgradeConflictProbeResult {
    pub approved_removals: Vec<String>,
    pub eligible: bool,
    pub package_database_fingerprint: String,
    pub projected_additions: Vec<String>,
    pub projected_removals: Vec<String>,
    pub rejection_reason: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct PackageDatabaseFingerprintResult {
    #[serde(default)]
    error: String,
    package_database_fingerprint: String,
}

/// Final reconciliation state for one logical catalog package.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum PackageAuthorityStatus {
    /// Desired ownership already matched the installed host state.
    Unchanged,
    /// A recognized provider was replaced by the desired provider.
    Reconciled,
    /// Safe convergence could not be proved or completed.
    Blocked,
}

/// Structured outcome for one observed logical package.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(super) struct PackageAuthorityPackageOutcome {
    /// Logical catalog package identifier.
    pub package_id: String,
    /// Backend/package identity that triggered reconciliation.
    pub observed_backend: String,
    /// Installed package name reported by the observed backend.
    pub observed_package: String,
    /// Desired backend selected for the current host.
    pub desired_backend: String,
    /// Desired package name selected for the current host.
    pub desired_package: String,
    /// Final package-level reconciliation state.
    pub status: PackageAuthorityStatus,
    /// Recognized provider identities removed after verification.
    pub removed_packages: Vec<String>,
    /// Human-readable explanation suitable for updater reports.
    pub note: String,
}

/// Aggregate result returned by the repository package executor.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(super) struct PackageAuthorityOutcome {
    /// Whether provider ownership changed on the host.
    pub changed: bool,
    /// Observed packages confirmed as desired for the current backend.
    pub desired_packages: Vec<String>,
    /// Observed packages that must not be updated by their current backend.
    pub excluded_packages: Vec<String>,
    /// Per-logical-package reconciliation outcomes.
    pub packages: Vec<PackageAuthorityPackageOutcome>,
}

impl PackageAuthorityOutcome {
    fn empty() -> Self {
        Self {
            changed: false,
            desired_packages: Vec::new(),
            excluded_packages: Vec::new(),
            packages: Vec::new(),
        }
    }

    /// Merge another backend observation into this reconciliation result.
    pub(super) fn merge(&mut self, mut other: Self) {
        self.changed = self.changed || other.changed;
        self.desired_packages.append(&mut other.desired_packages);
        self.desired_packages.sort();
        self.desired_packages.dedup();
        self.excluded_packages.append(&mut other.excluded_packages);
        self.excluded_packages.sort();
        self.excluded_packages.dedup();
        // O(n*m) for package-level outcomes across manager passes (expected: <20 rows).
        for incoming in other.packages.drain(..) {
            if let Some(existing) = self.packages.iter_mut().find(|existing| {
                existing.package_id == incoming.package_id
                    && existing.observed_backend == incoming.observed_backend
                    && existing.observed_package == incoming.observed_package
            }) {
                if !(existing.status == PackageAuthorityStatus::Reconciled
                    && incoming.status == PackageAuthorityStatus::Unchanged)
                {
                    *existing = incoming;
                }
            } else {
                self.packages.push(incoming);
            }
        }
    }

    /// Return whether the named desired provider has a non-blocked health result.
    pub(super) fn desired_provider_is_healthy(&self, package_name: &str) -> bool {
        self.packages.iter().any(|package| {
            package.desired_package == package_name
                && package.status != PackageAuthorityStatus::Blocked
        })
    }
}

/// Error returned when the generic package-authority bridge cannot run safely.
#[derive(Debug)]
pub(super) enum PackageAuthorityError {
    /// The optional installed resolver or executor could not be found.
    HelperUnavailable { path: PathBuf },
    /// A helper process exited unsuccessfully.
    InvocationFailed { detail: String },
    /// A helper returned malformed structured output.
    InvalidPayload { detail: String },
}

impl fmt::Display for PackageAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HelperUnavailable { path } => write!(
                formatter,
                "package authority helper is unavailable at {}; install the optional package-authority support files or disable UPDATE_ALL_PACKAGE_AUTHORITY",
                path.display()
            ),
            Self::InvocationFailed { detail } => write!(
                formatter,
                "package authority helper failed: {detail}; review the package reconciliation artifacts and retry"
            ),
            Self::InvalidPayload { detail } => write!(
                formatter,
                "package authority helper returned invalid output: {detail}; validate the package tooling and retry"
            ),
        }
    }
}

impl std::error::Error for PackageAuthorityError {}

struct PackageAuthorityGateGuard;

impl PackageAuthorityGateGuard {
    fn acquire() -> Result<Self, PackageAuthorityError> {
        let started = Instant::now();
        while PACKAGE_AUTHORITY_ACTIVE
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            if started.elapsed() >= PACKAGE_AUTHORITY_GATE_TIMEOUT {
                return Err(PackageAuthorityError::InvocationFailed {
                    detail: "reconciliation gate remained busy for 30 seconds".to_string(),
                });
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(Self)
    }
}

impl Drop for PackageAuthorityGateGuard {
    fn drop(&mut self) {
        PACKAGE_AUTHORITY_ACTIVE.store(false, Ordering::SeqCst);
    }
}

fn artifact_component(input: &str) -> Result<&str, PackageAuthorityError> {
    if input.is_empty()
        || !input
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(PackageAuthorityError::InvalidPayload {
            detail: "observed backend is not a safe artifact name".to_string(),
        });
    }
    Ok(input)
}

fn write_artifact(path: &Path, payload: &[u8]) -> Result<(), PackageAuthorityError> {
    fs::write(path, payload).map_err(|error| PackageAuthorityError::InvocationFailed {
        detail: format!("could not write {}: {error}", path.display()),
    })
}

fn write_bounded_conflict_artifact(
    path: &Path,
    payload: &[u8],
) -> Result<(), PackageAuthorityError> {
    if payload.len() > PACKAGE_AUTHORITY_MAX_ARTIFACT_BYTES {
        return Err(PackageAuthorityError::InvalidPayload {
            detail: format!(
                "structured package authority artifact exceeded {} bytes",
                PACKAGE_AUTHORITY_MAX_ARTIFACT_BYTES
            ),
        });
    }
    write_artifact(path, payload)
}

fn valid_package_database_fingerprint(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn python_executable() -> PathBuf {
    if let Some(configured) = std::env::var_os("UPDATE_ALL_PYTHON_BIN") {
        let candidate = PathBuf::from(configured);
        if candidate.is_file() {
            return candidate;
        }
    }
    for candidate in ["/usr/bin/python3", "/usr/local/bin/python3"] {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return path;
        }
    }
    PathBuf::from("python3")
}

fn package_executor_helper(source_root: &Path) -> Result<PathBuf, PackageAuthorityError> {
    if cfg!(debug_assertions) && std::env::var("UPDATE_ALL_TEST_FIXTURE").as_deref() == Ok("1") {
        if let Some(path) = std::env::var_os("UPDATE_ALL_TEST_PACKAGE_EXECUTOR") {
            let helper = PathBuf::from(path);
            if helper.is_file() {
                return Ok(helper);
            }
        }
    }
    let helper = source_root
        .parent()
        .ok_or_else(|| PackageAuthorityError::HelperUnavailable {
            path: source_root.to_path_buf(),
        })?
        .join("package_execute.py");
    if !helper.is_file() {
        return Err(PackageAuthorityError::HelperUnavailable { path: helper });
    }
    Ok(helper)
}

fn invoke_package_executor(
    helper: &Path,
    request_path: &Path,
    operation: &str,
) -> Result<Vec<u8>, PackageAuthorityError> {
    let output = Command::new(python_executable())
        .arg(helper)
        .args(["--plan-file", &request_path.to_string_lossy()])
        .args(["--os", "linux"])
        .args(["--operation", operation])
        .output()
        .map_err(|error| PackageAuthorityError::InvocationFailed {
            detail: format!("could not start package executor: {error}"),
        })?;
    if !output.status.success() {
        return Err(PackageAuthorityError::InvocationFailed {
            detail: format!("package executor exited with {}", output.status),
        });
    }
    Ok(output.stdout)
}

pub(super) fn package_database_fingerprint(
    source_root: &Path,
    run_dir: &Path,
    phase: &str,
) -> Result<String, PackageAuthorityError> {
    let _gate = PackageAuthorityGateGuard::acquire()?;
    let helper = package_executor_helper(source_root)?;
    let phase = artifact_component(phase)?;
    fs::create_dir_all(run_dir).map_err(|error| PackageAuthorityError::InvocationFailed {
        detail: format!("could not create {}: {error}", run_dir.display()),
    })?;
    let request_path = run_dir.join(format!("package-conflict-{phase}-request.json"));
    let result_path = run_dir.join(format!("package-conflict-{phase}-result.json"));
    write_bounded_conflict_artifact(&request_path, b"{}\n")?;
    let output = invoke_package_executor(&helper, &request_path, "pacman-db-fingerprint")?;
    write_bounded_conflict_artifact(&result_path, &output)?;
    let result: PackageDatabaseFingerprintResult =
        serde_json::from_slice(&output).map_err(|error| PackageAuthorityError::InvalidPayload {
            detail: error.to_string(),
        })?;
    if !result.error.is_empty()
        || !valid_package_database_fingerprint(&result.package_database_fingerprint)
    {
        return Err(PackageAuthorityError::InvocationFailed {
            detail: if result.error.is_empty() {
                "package database fingerprint was missing or invalid".to_string()
            } else {
                result.error
            },
        });
    }
    Ok(result.package_database_fingerprint)
}

pub(super) fn verify_upgrade_conflicts(
    source_root: &Path,
    run_dir: &Path,
    request: &UpgradeConflictProbeRequest,
) -> Result<UpgradeConflictProbeResult, PackageAuthorityError> {
    let _gate = PackageAuthorityGateGuard::acquire()?;
    let helper = package_executor_helper(source_root)?;
    fs::create_dir_all(run_dir).map_err(|error| PackageAuthorityError::InvocationFailed {
        detail: format!("could not create {}: {error}", run_dir.display()),
    })?;
    let request_path = run_dir.join("package-conflict-probe-request.json");
    let result_path = run_dir.join("package-conflict-probe-result.json");
    let request_payload = serde_json::to_vec_pretty(request).map_err(|error| {
        PackageAuthorityError::InvalidPayload {
            detail: error.to_string(),
        }
    })?;
    write_bounded_conflict_artifact(&request_path, &request_payload)?;
    let output = invoke_package_executor(&helper, &request_path, "verify-upgrade-conflict")?;
    write_bounded_conflict_artifact(&result_path, &output)?;
    serde_json::from_slice(&output).map_err(|error| PackageAuthorityError::InvalidPayload {
        detail: error.to_string(),
    })
}

fn detect_linux_family(source_root: &Path) -> Result<String, PackageAuthorityError> {
    let tools_root =
        source_root
            .parent()
            .ok_or_else(|| PackageAuthorityError::HelperUnavailable {
                path: source_root.to_path_buf(),
            })?;
    let helper = tools_root.join("package_catalog.py");
    if !helper.is_file() {
        return Err(PackageAuthorityError::HelperUnavailable { path: helper });
    }
    let mut command = Command::new(python_executable());
    command.arg(&helper).arg("--detect-linux-family");
    if cfg!(debug_assertions) && std::env::var("UPDATE_ALL_TEST_FIXTURE").as_deref() == Ok("1") {
        if let Ok(family) = std::env::var("UPDATE_ALL_TEST_LINUX_FAMILY") {
            let ansible_family = match family.as_str() {
                "arch" => "Archlinux",
                "debian" => "Debian",
                "rhel" => "RedHat",
                "alpine" => "Alpine",
                "generic" => "Other",
                _ => {
                    return Err(PackageAuthorityError::InvalidPayload {
                        detail: format!("unsupported test Linux family override: {family}"),
                    });
                }
            };
            command.args(["--ansible-os-family", ansible_family]);
        }
    }
    let output = command
        .output()
        .map_err(|error| PackageAuthorityError::InvocationFailed {
            detail: format!("could not detect Linux package family: {error}"),
        })?;
    if !output.status.success() {
        return Err(PackageAuthorityError::InvocationFailed {
            detail: format!(
                "Linux package-family detection exited with {}",
                output.status
            ),
        });
    }
    let family = String::from_utf8(output.stdout)
        .map_err(|error| PackageAuthorityError::InvalidPayload {
            detail: format!("Linux package-family output is not UTF-8: {error}"),
        })?
        .trim()
        .to_string();
    if family.is_empty() {
        return Err(PackageAuthorityError::InvalidPayload {
            detail: "Linux package-family detection returned an empty value".to_string(),
        });
    }
    Ok(family)
}

/// Purpose: Reconcile provider authority for one updater task on the current host.
///
/// # Arguments
/// * `ctx` - Active updater context containing host and artifact information.
/// * `observed_backend` - Package backend whose installed state triggered the check.
/// * `observed_packages` - Installed packages observed through that backend.
/// * `verify_desired` - Whether desired-only providers must run direct health probes.
///
/// # Returns
/// A structured outcome; unsupported hosts and explicitly disabled runs are empty no-ops.
///
/// # Panics
/// This function does not intentionally panic.
///
/// # Examples
/// ```ignore
/// let outcome = reconcile_for_task(&ctx, "npm", installed_packages, false)?;
/// assert!(!outcome.excluded_packages.iter().any(|name| name.is_empty()));
/// # Ok::<(), PackageAuthorityError>(())
/// ```
pub(super) fn reconcile_for_task(
    ctx: &SyncContext,
    observed_backend: &str,
    observed_packages: Vec<String>,
    verify_desired: bool,
) -> Result<PackageAuthorityOutcome, PackageAuthorityError> {
    let configured_mode = std::env::var("UPDATE_ALL_PACKAGE_AUTHORITY").ok();
    let explicitly_enabled = configured_mode
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case("on"));
    let test_mode_disabled = cfg!(test)
        && !configured_mode
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("on"));
    if ctx.host_os != HostOs::Linux || !explicitly_enabled || test_mode_disabled {
        return Ok(PackageAuthorityOutcome::empty());
    }
    let source_root = crate::build_info::package_support_root();
    let linux_family = detect_linux_family(&source_root)?;
    let artifact_dir = ctx
        .run_log
        .as_ref()
        .map(|run_log| run_log.run_dir().to_path_buf())
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!(
                "update-all-package-authority-{}",
                std::process::id()
            ))
        });
    reconcile_installed_providers(
        &source_root,
        &artifact_dir,
        &PackageAuthorityRequest {
            os_name: ctx.host_os.as_str().to_string(),
            linux_family,
            observed_backend: observed_backend.to_string(),
            observed_packages,
            verify_desired,
        },
    )
}

/// Convert reconciliation outcomes into the shared updater report format.
pub(super) fn report_section(outcome: &PackageAuthorityOutcome) -> Option<TaskReportSection> {
    if outcome.packages.is_empty() {
        return None;
    }
    let rows = outcome
        .packages
        .iter()
        .map(|package| TaskReportRow {
            name: package.observed_package.clone(),
            status: match package.status {
                PackageAuthorityStatus::Unchanged => TaskReportStatus::Unchanged,
                PackageAuthorityStatus::Reconciled => TaskReportStatus::Updated,
                PackageAuthorityStatus::Blocked => TaskReportStatus::Blocked,
            },
            before: Some(format!(
                "{}:{}",
                package.observed_backend, package.observed_package
            )),
            after: Some(format!(
                "{}:{}",
                package.desired_backend, package.desired_package
            )),
            note: Some(package.note.clone()),
        })
        .collect();
    Some(TaskReportSection {
        key: "package_authority".to_string(),
        title: "Package Provider Reconciliation".to_string(),
        rows,
    })
}

/// Purpose: Reconcile installed provider identities against the package catalog.
///
/// # Arguments
/// * `source_root` - Installed package-authority support root.
/// * `run_dir` - Run artifact directory where helper plans and results are preserved.
/// * `request` - Host/backend observations to reconcile.
///
/// # Returns
/// A structured provider-authority outcome, or a typed bridge error.
///
/// # Panics
/// This function does not intentionally panic.
///
/// # Examples
/// ```ignore
/// let outcome = reconcile_installed_providers(source_root, run_dir, &request)?;
/// assert!(outcome.packages.iter().all(|package| package.note.len() > 0));
/// # Ok::<(), PackageAuthorityError>(())
/// ```
pub(super) fn reconcile_installed_providers(
    source_root: &Path,
    run_dir: &Path,
    request: &PackageAuthorityRequest,
) -> Result<PackageAuthorityOutcome, PackageAuthorityError> {
    let _gate = PackageAuthorityGateGuard::acquire()?;
    let tools_root =
        source_root
            .parent()
            .ok_or_else(|| PackageAuthorityError::HelperUnavailable {
                path: source_root.to_path_buf(),
            })?;
    let catalog_helper = tools_root.join("package_catalog.py");
    let executor_helper = tools_root.join("package_execute.py");
    for helper in [&catalog_helper, &executor_helper] {
        if !helper.is_file() {
            return Err(PackageAuthorityError::HelperUnavailable {
                path: helper.to_path_buf(),
            });
        }
    }

    let backend = artifact_component(&request.observed_backend)?;
    fs::create_dir_all(run_dir).map_err(|error| PackageAuthorityError::InvocationFailed {
        detail: format!("could not create {}: {error}", run_dir.display()),
    })?;
    let artifact_key = if request.verify_desired {
        format!("{backend}-verify")
    } else {
        backend.to_string()
    };
    let request_path = run_dir.join(format!("package-authority-{artifact_key}-request.json"));
    let plan_path = run_dir.join(format!("package-authority-{artifact_key}-plan.json"));
    let result_path = run_dir.join(format!("package-authority-{artifact_key}-result.json"));
    let request_payload = serde_json::to_vec_pretty(request).map_err(|error| {
        PackageAuthorityError::InvalidPayload {
            detail: error.to_string(),
        }
    })?;
    write_artifact(&request_path, &request_payload)?;

    let mut catalog_command = Command::new(python_executable());
    catalog_command
        .arg(&catalog_helper)
        .args(["--os", &request.os_name])
        .args(["--linux-family", &request.linux_family])
        .args(["--operation", "reconcile"])
        .args(["--observed-backend", &request.observed_backend])
        .args(["--format", "json"]);
    // O(n) where n = observed installed packages (expected: 0-1000).
    for package in &request.observed_packages {
        catalog_command.args(["--observed-package", package]);
    }
    if request.verify_desired {
        catalog_command.arg("--verify-desired");
    }
    let catalog_output =
        catalog_command
            .output()
            .map_err(|error| PackageAuthorityError::InvocationFailed {
                detail: format!("could not start package catalog helper: {error}"),
            })?;
    if !catalog_output.status.success() {
        return Err(PackageAuthorityError::InvocationFailed {
            detail: format!(
                "package catalog helper exited with {}",
                catalog_output.status
            ),
        });
    }
    write_artifact(&plan_path, &catalog_output.stdout)?;

    let executor_output = Command::new(python_executable())
        .arg(&executor_helper)
        .args(["--plan-file", &plan_path.to_string_lossy()])
        .args(["--os", &request.os_name])
        .args(["--operation", "reconcile"])
        .output()
        .map_err(|error| PackageAuthorityError::InvocationFailed {
            detail: format!("could not start package authority executor: {error}"),
        })?;
    if !executor_output.status.success() {
        return Err(PackageAuthorityError::InvocationFailed {
            detail: format!(
                "package authority executor exited with {}",
                executor_output.status
            ),
        });
    }
    write_artifact(&result_path, &executor_output.stdout)?;
    serde_json::from_slice(&executor_output.stdout).map_err(|error| {
        PackageAuthorityError::InvalidPayload {
            detail: error.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{
        package_database_fingerprint, reconcile_installed_providers, verify_upgrade_conflicts,
        PackageAuthorityError, PackageAuthorityGateGuard, PackageAuthorityRequest,
        PackageAuthorityStatus, UpgradeConflictPair, UpgradeConflictProbeRequest,
    };
    use std::fs;
    use std::sync::mpsc;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn upgrade_conflict_bridge_persists_bounded_request_and_result() {
        let temp = TempDir::new().unwrap();
        let repo_root = temp.path().join("repo");
        let source_root = repo_root.join("tools/update-all");
        let tools_root = repo_root.join("tools");
        let run_dir = temp.path().join("run");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(
            tools_root.join("package_execute.py"),
            r#"import json
import sys
operation = sys.argv[sys.argv.index("--operation") + 1]
if operation == "pacman-db-fingerprint":
    print(json.dumps({"package_database_fingerprint": "sha256:" + "a" * 64}))
elif operation == "verify-upgrade-conflict":
    request_path = sys.argv[sys.argv.index("--plan-file") + 1]
    request = json.load(open(request_path, encoding="utf-8"))
    print(json.dumps({
        "approved_removals": [pair["remove"] for pair in request["conflicts"]],
        "eligible": True,
        "package_database_fingerprint": request["package_database_fingerprint"],
        "projected_additions": [pair["incoming"] for pair in request["conflicts"]],
        "projected_removals": [pair["remove"] for pair in request["conflicts"]],
        "rejection_reason": "",
    }))
else:
    raise SystemExit(2)
"#,
        )
        .unwrap();

        let fingerprint = package_database_fingerprint(&source_root, &run_dir, "before").unwrap();
        let request = UpgradeConflictProbeRequest {
            conflicts: vec![UpgradeConflictPair {
                incoming: "replacement-core".to_string(),
                remove: "retired-addon".to_string(),
            }],
            package_database_fingerprint: fingerprint.clone(),
        };
        let result = verify_upgrade_conflicts(&source_root, &run_dir, &request).unwrap();

        assert!(result.eligible);
        assert_eq!(result.package_database_fingerprint, fingerprint);
        assert_eq!(result.approved_removals, vec!["retired-addon"]);
        assert_eq!(result.projected_additions, vec!["replacement-core"]);
        assert!(run_dir
            .join("package-conflict-before-result.json")
            .is_file());
        assert!(run_dir
            .join("package-conflict-probe-request.json")
            .is_file());
        assert!(run_dir.join("package-conflict-probe-result.json").is_file());
    }

    #[test]
    fn process_wide_gate_serializes_reconciliation() {
        let first = PackageAuthorityGateGuard::acquire().unwrap();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let contender = std::thread::spawn(move || {
            let second = PackageAuthorityGateGuard::acquire().unwrap();
            acquired_tx.send(()).unwrap();
            drop(second);
        });

        assert!(acquired_rx.recv_timeout(Duration::from_millis(50)).is_err());
        drop(first);
        acquired_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        contender.join().unwrap();
    }

    #[test]
    fn reconciles_recognized_provider_after_desired_health_check() {
        let temp = TempDir::new().unwrap();
        let repo_root = temp.path().join("repo");
        let source_root = repo_root.join("tools/update-all");
        let tools_root = repo_root.join("tools");
        let run_dir = temp.path().join("run");
        fs::create_dir_all(&source_root).unwrap();
        fs::create_dir_all(&run_dir).unwrap();
        fs::write(
            tools_root.join("package_catalog.py"),
            r#"import json
print(json.dumps({"operation":"reconcile","authority_packages":[]}))
"#,
        )
        .unwrap();
        fs::write(
            tools_root.join("package_execute.py"),
            r#"import json
print(json.dumps({
  "changed": True,
  "desired_packages": [],
  "excluded_packages": ["former-cli"],
  "packages": [{
    "package_id": "linux-demo-cli",
    "observed_backend": "npm",
    "observed_package": "former-cli",
    "desired_backend": "aur",
    "desired_package": "demo-cli",
    "status": "reconciled",
    "removed_packages": ["former-cli"],
    "note": "direct desired-provider command health probe passed"
  }]
}))
"#,
        )
        .unwrap();
        let request = PackageAuthorityRequest {
            os_name: "linux".to_string(),
            linux_family: "arch".to_string(),
            observed_backend: "npm".to_string(),
            observed_packages: vec!["former-cli".to_string()],
            verify_desired: false,
        };

        let outcome = reconcile_installed_providers(&source_root, &run_dir, &request).unwrap();

        assert!(outcome.changed);
        assert_eq!(outcome.excluded_packages, vec!["former-cli"]);
        assert_eq!(
            outcome.packages[0].status,
            PackageAuthorityStatus::Reconciled
        );
        assert!(run_dir.join("package-authority-npm-request.json").is_file());
        assert!(run_dir.join("package-authority-npm-plan.json").is_file());
        assert!(run_dir.join("package-authority-npm-result.json").is_file());
    }

    #[test]
    fn missing_helper_returns_typed_error_without_mutation() {
        let temp = TempDir::new().unwrap();
        let source_root = temp.path().join("repo/tools/update-all");
        let run_dir = temp.path().join("run");
        fs::create_dir_all(&source_root).unwrap();
        let request = PackageAuthorityRequest {
            os_name: "linux".to_string(),
            linux_family: "arch".to_string(),
            observed_backend: "npm".to_string(),
            observed_packages: Vec::new(),
            verify_desired: false,
        };

        let error = reconcile_installed_providers(&source_root, &run_dir, &request)
            .expect_err("missing helper must fail");

        assert!(matches!(
            error,
            PackageAuthorityError::HelperUnavailable { .. }
        ));
        assert!(!run_dir.exists());
    }

    #[test]
    fn helper_failure_returns_typed_invocation_error() {
        let temp = TempDir::new().unwrap();
        let source_root = temp.path().join("repo/tools/update-all");
        let tools_root = temp.path().join("repo/tools");
        let run_dir = temp.path().join("run");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(
            tools_root.join("package_catalog.py"),
            "raise SystemExit(3)\n",
        )
        .unwrap();
        fs::write(tools_root.join("package_execute.py"), "print('{}')\n").unwrap();
        let request = PackageAuthorityRequest {
            os_name: "linux".to_string(),
            linux_family: "arch".to_string(),
            observed_backend: "npm".to_string(),
            observed_packages: Vec::new(),
            verify_desired: false,
        };

        let error = reconcile_installed_providers(&source_root, &run_dir, &request)
            .expect_err("failed catalog helper must return an invocation error");

        assert!(matches!(
            error,
            PackageAuthorityError::InvocationFailed { .. }
        ));
    }

    #[test]
    fn malformed_executor_output_returns_typed_payload_error() {
        let temp = TempDir::new().unwrap();
        let source_root = temp.path().join("repo/tools/update-all");
        let tools_root = temp.path().join("repo/tools");
        let run_dir = temp.path().join("run");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(
            tools_root.join("package_catalog.py"),
            r#"import json
print(json.dumps({"operation":"reconcile","authority_packages":[]}))
"#,
        )
        .unwrap();
        fs::write(
            tools_root.join("package_execute.py"),
            "print('{not-json')\n",
        )
        .unwrap();
        let request = PackageAuthorityRequest {
            os_name: "linux".to_string(),
            linux_family: "arch".to_string(),
            observed_backend: "npm".to_string(),
            observed_packages: Vec::new(),
            verify_desired: false,
        };

        let error = reconcile_installed_providers(&source_root, &run_dir, &request)
            .expect_err("malformed executor output must return a payload error");

        assert!(matches!(
            error,
            PackageAuthorityError::InvalidPayload { .. }
        ));
        assert!(run_dir.join("package-authority-npm-result.json").is_file());
    }
}
