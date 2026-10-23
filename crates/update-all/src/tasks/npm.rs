use crate::tasks::package_authority;
use crate::tasks::recovery::{PackageManagerKind, RecoveryAction, RecoveryCause, RecoveryPlan};
use crate::tasks::{
    command_error_summary, AdvisorySeverity, SyncContext, TaskAdvisory, TaskReportRow,
    TaskReportSection, TaskReportStatus, TaskResult, TaskStatus, TASK_NPM,
};
use crate::ui::{LogLevel, LogStream};
use crate::util::process::{process_exit_output, run_capture_stdout_allow_exit_codes, which};
use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const NPM_OUTDATED_TIMEOUT_SECS: u64 = 60;
const MISSING_NPM_CURRENT_VERSION: &str = "missing metadata";

#[derive(Clone, Debug, Deserialize)]
struct NpmOutdatedEntry {
    current: Option<String>,
    wanted: Option<String>,
    latest: Option<String>,
    location: Option<String>,
}

#[derive(Clone, Debug)]
struct PlannedUpdate {
    package: String,
    current: String,
    target: String,
    note: Option<String>,
}

#[derive(Clone, Debug)]
struct ManifestProtocolIssue {
    field: String,
    dependency: String,
    spec: String,
    protocol: String,
}

#[derive(Clone, Debug)]
struct NpmGlobalLayout {
    prefix: PathBuf,
    root: PathBuf,
}

fn npm_global_path(npm_bin: &str, subcommand: &str) -> Result<PathBuf> {
    let raw = run_capture_stdout_allow_exit_codes(
        npm_bin,
        [subcommand, "-g"],
        Some(Duration::from_secs(30)),
        &[],
    )?;
    let path = raw
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| anyhow::anyhow!("npm {subcommand} -g returned an empty path"))?;
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        anyhow::bail!(
            "npm {subcommand} -g returned a non-absolute path: {}",
            path.display()
        );
    }
    Ok(path)
}

fn lexical_absolute_path(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    Some(normalized)
}

#[cfg(unix)]
fn unix_path_authority_issue(owner_uid: u32, current_uid: u32, mode: u32) -> Option<&'static str> {
    if owner_uid == 0 {
        return Some("is owned by root");
    }
    if owner_uid != current_uid {
        return Some("is not owned by the current user");
    }
    if mode & 0o300 != 0o300 {
        return Some("is not writable and searchable by its owner");
    }
    None
}

#[cfg(unix)]
fn current_unix_uid() -> Result<u32> {
    static CURRENT_UID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    if let Some(uid) = CURRENT_UID.get() {
        return Ok(*uid);
    }
    let id_path = ["/usr/bin/id", "/bin/id"]
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .context("could not find a trusted absolute id executable")?;
    let uid_output = Command::new(id_path)
        .arg("-u")
        .output()
        .context("could not determine the current Unix user id")?;
    if !uid_output.status.success() {
        anyhow::bail!("id -u exited with {}", uid_output.status);
    }
    let current_uid = String::from_utf8(uid_output.stdout)
        .context("id -u returned non-UTF-8 output")?
        .trim()
        .parse::<u32>()
        .context("id -u returned an invalid user id")?;
    let _ = CURRENT_UID.set(current_uid);
    Ok(current_uid)
}

#[cfg(unix)]
fn platform_path_authority_issue(path: &Path) -> Result<Option<String>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::metadata(path)
        .with_context(|| format!("could not inspect npm mutation path {}", path.display()))?;
    if !metadata.is_dir() {
        return Ok(Some(format!("{} is not a directory", path.display())));
    }
    let current_uid = current_unix_uid()?;
    Ok(
        unix_path_authority_issue(metadata.uid(), current_uid, metadata.permissions().mode())
            .map(|reason| format!("{} {reason}", path.display())),
    )
}

#[cfg(windows)]
fn platform_path_authority_issue(path: &Path) -> Result<Option<String>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("could not inspect npm mutation path {}", path.display()))?;
    if !metadata.is_dir() {
        return Ok(Some(format!("{} is not a directory", path.display())));
    }
    if metadata.permissions().readonly() {
        return Ok(Some(format!("{} is read-only", path.display())));
    }
    let trusted_roots = ["USERPROFILE", "LOCALAPPDATA", "APPDATA"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .filter_map(|root| fs::canonicalize(root).ok())
        .collect::<Vec<_>>();
    if trusted_roots.iter().any(|root| path.starts_with(root)) {
        Ok(None)
    } else {
        Ok(Some(format!(
            "{} is outside the current user's Windows profile roots",
            path.display()
        )))
    }
}

#[cfg(not(any(unix, windows)))]
fn platform_path_authority_issue(path: &Path) -> Result<Option<String>> {
    Ok(Some(format!(
        "ownership checks are unsupported for {} on this platform",
        path.display()
    )))
}

fn npm_mutation_layout(
    npm_bin: &str,
    planned_packages: &[(String, Option<PathBuf>)],
) -> Result<NpmGlobalLayout, String> {
    let prefix_raw = npm_global_path(npm_bin, "prefix")
        .map_err(|error| format!("could not resolve npm global prefix: {error}"))?;
    let root_raw = npm_global_path(npm_bin, "root")
        .map_err(|error| format!("could not resolve npm global root: {error}"))?;
    let prefix = fs::canonicalize(&prefix_raw).map_err(|error| {
        format!(
            "could not canonicalize npm global prefix {}: {error}",
            prefix_raw.display()
        )
    })?;
    let root = fs::canonicalize(&root_raw).map_err(|error| {
        format!(
            "could not canonicalize npm global root {}: {error}",
            root_raw.display()
        )
    })?;
    if !root.starts_with(&prefix) {
        return Err(format!(
            "npm global root {} is outside global prefix {}",
            root.display(),
            prefix.display()
        ));
    }

    let mut mutation_paths = vec![prefix.clone(), root.clone()];
    #[cfg(not(windows))]
    {
        let prefix_bin = prefix.join("bin");
        if prefix_bin.exists() {
            mutation_paths.push(prefix_bin);
        }
    }
    for (package, reported_location) in planned_packages {
        let package_path = reported_location
            .clone()
            .unwrap_or_else(|| root.join(package));
        let path = package_path.as_path();
        let normalized = if path.exists() {
            fs::canonicalize(path).map_err(|error| {
                format!(
                    "could not canonicalize planned npm package location {}: {error}",
                    path.display()
                )
            })?
        } else {
            lexical_absolute_path(path).ok_or_else(|| {
                format!(
                    "planned npm package location is not a safe absolute path: {}",
                    path.display()
                )
            })?
        };
        if !normalized.starts_with(&root) || normalized == root {
            return Err(format!(
                "planned npm package location {} is outside global root {}",
                normalized.display(),
                root.display()
            ));
        }
        if normalized.exists() {
            mutation_paths.push(normalized);
        }
    }
    mutation_paths.sort();
    mutation_paths.dedup();
    for path in &mutation_paths {
        if let Some(issue) = platform_path_authority_issue(path)
            .map_err(|error| format!("npm global authority inspection failed: {error}"))?
        {
            return Err(issue);
        }
    }
    Ok(NpmGlobalLayout { prefix, root })
}

fn npm_authority_blocked_result(
    reason: String,
    packages: &BTreeMap<String, NpmOutdatedEntry>,
    excluded_packages: &BTreeSet<String>,
    system_managed_packages: &BTreeMap<String, String>,
    authority_outcome: Option<&package_authority::PackageAuthorityOutcome>,
) -> TaskResult {
    let remediation = "Update package-manager-owned Node/npm packages through their owning system manager. Move unowned global npm packages to a user-owned, user-writable npm prefix or a supported per-user Node installation, then rerun update-all; update-all will not infer sudo or rewrite ownership.".to_string();
    let mut rows = vec![TaskReportRow {
        name: "global npm tree".to_string(),
        status: TaskReportStatus::Blocked,
        before: Some("installed".to_string()),
        after: None,
        note: Some(reason.clone()),
    }];
    for (package, entry) in packages {
        if let Some(owner) = system_managed_packages.get(package) {
            rows.push(TaskReportRow {
                name: package.clone(),
                status: TaskReportStatus::Skipped,
                before: normalize_version(entry.current.as_deref()),
                after: None,
                note: Some(format!("excluded because it is owned by {owner}")),
            });
            continue;
        }
        if excluded_packages.contains(package) {
            continue;
        }
        rows.push(TaskReportRow {
            name: package.clone(),
            status: TaskReportStatus::Blocked,
            before: normalize_version(entry.current.as_deref())
                .or_else(|| Some(MISSING_NPM_CURRENT_VERSION.to_string())),
            after: None,
            note: Some(format!(
                "unowned global-root residue; not mutated; requested target: {}",
                match select_target(entry) {
                    Some(target) => target,
                    None => "unknown".to_string(),
                }
            )),
        });
    }
    let mut result = TaskResult::completed("NPM");
    result.details.push(format!(
        "Blocked npm global updates before mutation: {reason}"
    ));
    result.advisories.push(TaskAdvisory {
        severity: AdvisorySeverity::Error,
        code: "npm-global-authority-blocked".to_string(),
        summary: "NPM global update authority could not be established".to_string(),
        remediation,
        blocks_dependents: true,
    });
    result.report_sections.push(TaskReportSection {
        key: "npm_authority".to_string(),
        title: "NPM Global Authority".to_string(),
        rows,
    });
    if let Some(outcome) = authority_outcome {
        if let Some(section) = package_authority::report_section(outcome) {
            result.report_sections.push(section);
        }
    }
    result
}

fn npm_mutation_candidates(
    packages: &BTreeMap<String, NpmOutdatedEntry>,
    installed_versions: &BTreeMap<String, String>,
    excluded_packages: &BTreeSet<String>,
) -> Vec<(String, Option<PathBuf>)> {
    packages
        .iter()
        .filter(|(package, entry)| {
            if excluded_packages.contains(*package) {
                return false;
            }
            let Some(target) = select_target(entry) else {
                return false;
            };
            let current = npm_outdated_current_version(package, entry, installed_versions);
            current.as_deref().is_none_or(|current| {
                version_update_decision(current, &target) != VersionDecision::NotNewer
            })
        })
        .map(|(package, entry)| {
            (
                package.clone(),
                entry.location.as_deref().map(PathBuf::from),
            )
        })
        .collect()
}

fn preflight_npm_mutation(
    ctx: &SyncContext,
    npm_bin: &str,
    packages: &BTreeMap<String, NpmOutdatedEntry>,
    installed_versions: &BTreeMap<String, String>,
    excluded_packages: &BTreeSet<String>,
    system_managed_packages: &BTreeMap<String, String>,
    authority_outcome: Option<&package_authority::PackageAuthorityOutcome>,
) -> Option<TaskResult> {
    let candidates = npm_mutation_candidates(packages, installed_versions, excluded_packages);
    if candidates.is_empty() {
        return None;
    }
    match npm_mutation_layout(npm_bin, &candidates) {
        Ok(layout) => {
            ctx.log_line(
                TASK_NPM,
                LogLevel::Info,
                LogStream::Meta,
                format!(
                    "verified user-owned npm mutation authority for prefix {} and root {}",
                    layout.prefix.display(),
                    layout.root.display()
                ),
            );
            None
        }
        Err(reason) => {
            ctx.log_line(
                TASK_NPM,
                LogLevel::Error,
                LogStream::Meta,
                format!("blocked npm global updates before mutation: {reason}"),
            );
            Some(npm_authority_blocked_result(
                reason,
                packages,
                excluded_packages,
                system_managed_packages,
                authority_outcome,
            ))
        }
    }
}

#[cfg(target_os = "linux")]
fn successful_command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let output = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!output.is_empty()).then_some(output)
}

#[cfg(target_os = "linux")]
fn linux_system_manager_owner(path: &Path) -> Option<String> {
    let path = path.to_string_lossy();
    successful_command_output("pacman", &["-Qqo", path.as_ref()])
        .map(|package| format!("pacman package {package}"))
        .or_else(|| {
            successful_command_output("dpkg-query", &["-S", path.as_ref()]).and_then(|output| {
                let package = output.split(':').next()?.trim();
                (!package.is_empty()).then(|| format!("dpkg package {package}"))
            })
        })
        .or_else(|| {
            successful_command_output("rpm", &["-qf", path.as_ref()])
                .map(|package| format!("rpm package {package}"))
        })
        .or_else(|| {
            successful_command_output("apk", &["info", "-W", path.as_ref()]).and_then(|output| {
                let package = output.split_once(" is owned by ")?.1.trim();
                (!package.is_empty()).then(|| format!("apk package {package}"))
            })
        })
}

#[cfg(not(target_os = "linux"))]
fn linux_system_manager_owner(_path: &Path) -> Option<String> {
    None
}

fn npm_system_managed_packages(
    npm_bin: &str,
    packages: &BTreeMap<String, NpmOutdatedEntry>,
) -> BTreeMap<String, String> {
    let Ok(root) = npm_global_path(npm_bin, "root") else {
        return BTreeMap::new();
    };
    packages
        .iter()
        .filter_map(|(package, entry)| {
            let location = entry
                .location
                .as_deref()
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join(package));
            if !location.exists() {
                return None;
            }
            let manifest = location.join("package.json");
            let probe = if manifest.is_file() {
                manifest.as_path()
            } else {
                location.as_path()
            };
            linux_system_manager_owner(probe).map(|owner| (package.clone(), owner))
        })
        .collect()
}

fn npm_install_authority_failure_result(
    plans: &[PlannedUpdate],
    detail: String,
    mut rows: Vec<TaskReportRow>,
    advisories: Vec<TaskAdvisory>,
    authority_outcome: Option<&package_authority::PackageAuthorityOutcome>,
) -> TaskResult {
    let remediation = "Review the reported denial and verify package state before explicitly retrying. Use a user-owned, user-writable NPM prefix or the owning system package manager as appropriate; update-all will not infer sudo, rewrite ownership, or roll back partial changes.".to_string();
    let observed = rows
        .iter()
        .map(|row| row.name.clone())
        .collect::<BTreeSet<_>>();
    rows.extend(plans
        .iter()
        .filter(|plan| !observed.contains(&plan.package))
        .map(|plan| TaskReportRow {
            name: plan.package.clone(),
            status: TaskReportStatus::Blocked,
            before: Some(plan.current.clone()),
            after: None,
            note: Some(format!(
                "installation reported an authority denial; no further automatic mutation; requested target: {}; installed state unverified; partial changes may remain",
                plan.target
            )),
        })
        );
    let mut result = TaskResult::completed("NPM");
    result.details.push(format!(
        "Blocked npm update after reported authority failure; no further automatic installs or recovery: {detail}"
    ));
    result.advisories = advisories;
    result.advisories.push(TaskAdvisory {
        severity: AdvisorySeverity::Error,
        code: "npm-global-authority-blocked".to_string(),
        summary: "NPM global update authority failed during installation".to_string(),
        remediation,
        blocks_dependents: true,
    });
    result.report_sections.push(TaskReportSection {
        key: "npm_authority".to_string(),
        title: "NPM Global Authority".to_string(),
        rows,
    });
    if let Some(outcome) = authority_outcome {
        if let Some(section) = package_authority::report_section(outcome) {
            result.report_sections.push(section);
        }
    }
    result
}

fn npm_storage_failure_result(
    plans: &[PlannedUpdate],
    detail: String,
    mut rows: Vec<TaskReportRow>,
    advisories: Vec<TaskAdvisory>,
    authority_outcome: Option<&package_authority::PackageAuthorityOutcome>,
) -> TaskResult {
    let observed = rows
        .iter()
        .map(|row| row.name.clone())
        .collect::<BTreeSet<_>>();
    rows.extend(
        plans
            .iter()
            .filter(|plan| !observed.contains(&plan.package))
            .map(|plan| TaskReportRow {
                name: plan.package.clone(),
                status: TaskReportStatus::Blocked,
                before: Some(plan.current.clone()),
                after: None,
                note: Some(format!(
                    "storage exhausted; target {} not verified; partial changes may remain",
                    plan.target
                )),
            }),
    );
    let mut result = TaskResult::failed(
        "NPM",
        format!("Reported storage exhaustion; no further automatic installs or recovery: {detail}"),
    );
    result.advisories = advisories;
    result.advisories.push(TaskAdvisory {
        severity: AdvisorySeverity::Error,
        code: "npm-storage-exhausted".to_string(),
        summary: "NPM reported exhausted storage; package post-state is not assumed".to_string(),
        remediation: "Inspect capacity or quota on the affected npm prefix/cache/temp filesystem and verify package state before explicitly retrying. Partial changes were not rolled back.".to_string(),
        blocks_dependents: true,
    });
    result.report_sections.push(TaskReportSection {
        key: "npm_packages".to_string(),
        title: "NPM Package Results".to_string(),
        rows,
    });
    if let Some(section) = authority_outcome.and_then(package_authority::report_section) {
        result.report_sections.push(section);
    }
    result
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NpmInstallStop {
    Storage,
    Authority,
}

fn npm_terminal_install_failure_result(
    stop: NpmInstallStop,
    plans: &[PlannedUpdate],
    detail: String,
    rows: Vec<TaskReportRow>,
    advisories: Vec<TaskAdvisory>,
    authority_outcome: Option<&package_authority::PackageAuthorityOutcome>,
) -> TaskResult {
    match stop {
        NpmInstallStop::Storage => {
            npm_storage_failure_result(plans, detail, rows, advisories, authority_outcome)
        }
        NpmInstallStop::Authority => {
            npm_install_authority_failure_result(plans, detail, rows, advisories, authority_outcome)
        }
    }
}

#[derive(Debug)]
struct NpmRecoveryFailure {
    detail: String,
    stop: Option<NpmInstallStop>,
}

impl From<String> for NpmRecoveryFailure {
    fn from(detail: String) -> Self {
        // Keep ADR0038's existing storage handling for health/metadata errors.
        // Authority, unlike storage, is never inferred from these strings.
        let stop = crate::util::process::storage_exhaustion_output(&detail)
            .then_some(NpmInstallStop::Storage);
        Self { detail, stop }
    }
}

fn record_verified_npm_plan(
    successful_plans: &mut Vec<PlannedUpdate>,
    verified_rows: &mut Vec<TaskReportRow>,
    plan: &PlannedUpdate,
    note: String,
) {
    let mut verified_plan = plan.clone();
    verified_plan.note = Some(note.clone());
    successful_plans.push(verified_plan);
    verified_rows.push(TaskReportRow {
        name: plan.package.clone(),
        status: TaskReportStatus::Updated,
        before: Some(plan.current.clone()),
        after: Some(plan.target.clone()),
        note: Some(note),
    });
}

fn npm_rows_with_verified(
    mut rows: Vec<TaskReportRow>,
    verified_rows: &[TaskReportRow],
) -> Vec<TaskReportRow> {
    let observed = rows
        .iter()
        .map(|row| row.name.clone())
        .collect::<BTreeSet<_>>();
    rows.extend(
        verified_rows
            .iter()
            .filter(|row| !observed.contains(&row.name))
            .cloned(),
    );
    rows
}

impl std::fmt::Display for NpmRecoveryFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

fn npm_recovery_error(error: anyhow::Error) -> NpmRecoveryFailure {
    let stop = if crate::util::process::process_storage_exhausted(&error) {
        Some(NpmInstallStop::Storage)
    } else if crate::util::process::process_permission_denied(&error) {
        Some(NpmInstallStop::Authority)
    } else {
        None
    };
    NpmRecoveryFailure {
        detail: command_error_summary(&error),
        stop,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct BlockedInstallScript {
    package: String,
    version: String,
    lifecycle: String,
}

fn parse_blocked_install_scripts(output: &str) -> Vec<BlockedInstallScript> {
    let mut blocked = BTreeSet::new();
    // O(n) where n = npm output lines (expected: 10-1000).
    for line in output.lines() {
        let trimmed = line.trim();
        let Some(payload) = trimmed.strip_prefix("npm warn install-scripts") else {
            continue;
        };
        let Some((package_spec, lifecycle_payload)) = payload.trim().split_once(" (") else {
            continue;
        };
        let Some(lifecycle) = lifecycle_payload.strip_suffix(')') else {
            continue;
        };
        let Some((package, version)) = split_npm_package_version(package_spec.trim()) else {
            continue;
        };
        blocked.insert(BlockedInstallScript {
            package,
            version,
            lifecycle: lifecycle.to_string(),
        });
    }
    blocked.into_iter().collect()
}

fn split_npm_package_version(package_spec: &str) -> Option<(String, String)> {
    let version_separator = package_spec.rfind('@')?;
    if version_separator == 0 {
        return None;
    }
    if package_spec.starts_with('@') {
        let scope_separator = package_spec.find('/')?;
        if version_separator < scope_separator {
            return None;
        }
    }
    let (package, version_with_separator) = package_spec.split_at(version_separator);
    let version = version_with_separator.strip_prefix('@')?;
    if package.is_empty() || version.is_empty() {
        return None;
    }
    Some((package.to_string(), version.to_string()))
}

fn npm_install_args(plans: &[PlannedUpdate]) -> Vec<String> {
    let mut args = vec![
        "install".to_string(),
        "-g".to_string(),
        "--no-audit".to_string(),
        "--no-fund".to_string(),
        "--prefer-online".to_string(),
    ];
    args.extend(plans.iter().map(|p| format!("{}@{}", p.package, p.target)));
    args
}

fn npm_install_args_with_allowed_scripts(
    plan: &PlannedUpdate,
    allowed_packages: &BTreeSet<String>,
) -> Vec<String> {
    let mut args = vec![
        "install".to_string(),
        "-g".to_string(),
        "--no-audit".to_string(),
        "--no-fund".to_string(),
        "--prefer-online".to_string(),
        format!(
            "--allow-scripts={}",
            allowed_packages
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        ),
    ];
    args.push(format!("{}@{}", plan.package, plan.target));
    args
}

fn append_retry_note(note: Option<&str>) -> Option<String> {
    match note {
        Some(existing) if !existing.is_empty() => Some(format!(
            "{existing}; retried individually after batch failure"
        )),
        _ => Some("retried individually after batch failure".to_string()),
    }
}

fn blocked_script_for_package<'a>(
    blocked: &'a [BlockedInstallScript],
    package: &str,
) -> Option<&'a BlockedInstallScript> {
    blocked.iter().find(|script| script.package == package)
}

fn recover_unhealthy_npm_root(
    ctx: &SyncContext,
    npm_bin: &str,
    plan: &PlannedUpdate,
) -> Result<String, NpmRecoveryFailure> {
    let mut isolated_args = npm_install_args(std::slice::from_ref(plan));
    // Lifecycle recovery needs warnings even when the user's ordinary npm
    // output is quiet. This is an invocation override, never persisted trust.
    isolated_args.push("--loglevel=warn".to_string());
    let isolated_output = ctx
        .run_npm_install_with_policy(npm_bin, isolated_args)
        .map_err(npm_recovery_error)?;
    let closure = parse_blocked_install_scripts(&isolated_output);
    if closure.is_empty() {
        verify_installed_npm_root(npm_bin, plan)?;
        return Ok(
            "isolated reinstall restored root health without script authorization".to_string(),
        );
    }

    for script in &closure {
        if let Some(issue) =
            npm_view_manifest_protocol_issue_checked(npm_bin, &script.package, &script.version)?
        {
            return Err(format!(
                "automatic lifecycle recovery rejected non-registry closure member {}@{}: {}",
                script.package,
                script.version,
                describe_manifest_protocol_issue(&issue)
            )
            .into());
        }
    }

    let allowed_packages = closure
        .iter()
        .map(|script| &script.package)
        .cloned()
        .collect::<BTreeSet<_>>();
    let retry_output = ctx
        .run_npm_install_with_policy(
            npm_bin,
            npm_install_args_with_allowed_scripts(plan, &allowed_packages),
        )
        .map_err(npm_recovery_error)?;
    let still_blocked = parse_blocked_install_scripts(&retry_output);
    if !still_blocked.is_empty() {
        return Err(format!(
            "isolated lifecycle retry still blocked: {}",
            still_blocked
                .iter()
                .map(|script| format!(
                    "{}@{} ({})",
                    script.package, script.version, script.lifecycle
                ))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .into());
    }
    verify_installed_npm_root(npm_bin, plan)?;
    Ok(format!(
        "isolated registry-only lifecycle closure authorized once: {}",
        allowed_packages.into_iter().collect::<Vec<_>>().join(", ")
    ))
}

fn record_blocked_install_script(
    report_rows: &mut Vec<TaskReportRow>,
    advisories: &mut Vec<TaskAdvisory>,
    plan: &PlannedUpdate,
    script: &BlockedInstallScript,
    reason: &str,
) {
    report_rows.push(TaskReportRow {
        name: plan.package.clone(),
        status: TaskReportStatus::Blocked,
        before: Some(plan.current.clone()),
        after: None,
        note: Some(format!(
            "install script blocked ({}); {reason}; requested target: {}; installed state unverified",
            script.lifecycle, plan.target
        )),
    });
    advisories.push(TaskAdvisory {
        severity: AdvisorySeverity::Warning,
        code: "npm-install-script-blocked".to_string(),
        summary: format!(
            "{}@{} did not run its {} lifecycle script",
            script.package, script.version, script.lifecycle
        ),
        remediation: reason.to_string(),
        blocks_dependents: false,
    });
}

fn record_unassociated_blocked_install_script(
    lifecycle_rows: &mut Vec<TaskReportRow>,
    advisories: &mut Vec<TaskAdvisory>,
    script: &BlockedInstallScript,
) {
    let reason = "transitive or unattributed lifecycle warning; planned roots are evaluated independently from verified post-install state";
    lifecycle_rows.push(TaskReportRow {
        name: script.package.clone(),
        status: TaskReportStatus::Info,
        before: None,
        after: Some(script.version.clone()),
        note: Some(format!(
            "install script blocked ({}); {reason}",
            script.lifecycle
        )),
    });
    advisories.push(TaskAdvisory {
        severity: AdvisorySeverity::Warning,
        code: "npm-install-script-blocked".to_string(),
        summary: format!(
            "{}@{} did not run its {} lifecycle script",
            script.package, script.version, script.lifecycle
        ),
        remediation: reason.to_string(),
        blocks_dependents: false,
    });
}

fn record_associated_lifecycle_diagnostic(
    lifecycle_rows: &mut Vec<TaskReportRow>,
    advisories: &mut Vec<TaskAdvisory>,
    plan: &PlannedUpdate,
    script: &BlockedInstallScript,
) {
    let reason = "planned root health is verified independently; automatic recovery is attempted only if that verification fails";
    lifecycle_rows.push(TaskReportRow {
        name: plan.package.clone(),
        status: TaskReportStatus::Info,
        before: Some(plan.current.clone()),
        after: None,
        note: Some(format!(
            "root-attributable install script warning ({}); {reason}; requested target: {}",
            script.lifecycle, plan.target
        )),
    });
    advisories.push(TaskAdvisory {
        severity: AdvisorySeverity::Warning,
        code: "npm-install-script-blocked".to_string(),
        summary: format!(
            "{}@{} did not run its {} lifecycle script",
            script.package, script.version, script.lifecycle
        ),
        remediation: reason.to_string(),
        blocks_dependents: false,
    });
}

fn describe_manifest_protocol_issue(issue: &ManifestProtocolIssue) -> String {
    format!(
        "published manifest uses non-registry dependency source {} in {} for {} ({})",
        issue.protocol, issue.field, issue.dependency, issue.spec
    )
}

pub fn task_npm_sync(ctx: &SyncContext) -> Result<TaskResult> {
    let mut details = Vec::new();
    let mut advisories = Vec::new();
    let mut report_rows: Vec<TaskReportRow> = Vec::new();
    let mut lifecycle_rows: Vec<TaskReportRow> = Vec::new();
    let npm_bin = if cfg!(windows) && which("npm.cmd").is_some() {
        "npm.cmd"
    } else {
        "npm"
    };
    let installed_global_versions = npm_list_global_versions(npm_bin);
    let mut authority_outcome = None;
    let mut excluded_packages = BTreeSet::new();
    ctx.log_line(
        TASK_NPM,
        LogLevel::Info,
        LogStream::Meta,
        format!("checking npm outdated packages via {npm_bin}"),
    );
    let outdated = match run_capture_stdout_allow_exit_codes(
        npm_bin,
        ["outdated", "-g", "--json"],
        Some(Duration::from_secs(NPM_OUTDATED_TIMEOUT_SECS)),
        &[1],
    ) {
        Ok(output) => output,
        Err(e) => {
            if let Some(output) = process_exit_output(&e) {
                ctx.log_line(
                    TASK_NPM,
                    LogLevel::Info,
                    LogStream::Meta,
                    format!("incomplete npm discovery output; no update plan accepted:\n{output}"),
                );
            }
            let detail = format!("npm outdated failed: {}", command_error_summary(&e));
            ctx.log_line(TASK_NPM, LogLevel::Error, LogStream::Meta, detail.clone());
            let rows = vec![TaskReportRow {
                name: "npm outdated".to_string(),
                status: TaskReportStatus::Failed,
                before: Some("-".to_string()),
                after: Some("-".to_string()),
                note: Some(detail.clone()),
            }];
            let mut result = TaskResult::failed("NPM", detail);
            result.details.push(build_report_counts_line(&rows));
            result.report_sections.push(TaskReportSection {
                key: "npm_packages".to_string(),
                title: "NPM Package Results".to_string(),
                rows,
            });
            if let Some(outcome) = authority_outcome.as_ref() {
                if let Some(section) = package_authority::report_section(outcome) {
                    result.report_sections.push(section);
                }
            }
            result.advisories = dedupe_advisories(advisories);
            return Ok(result);
        }
    };

    let parsed_outdated = match parse_npm_outdated_payload(&outdated) {
        Ok(entries) => entries,
        Err(e) => {
            let detail = format!(
                "npm outdated returned invalid structured output ({e}); refusing the unscoped npm update -g fallback"
            );
            ctx.log_line(TASK_NPM, LogLevel::Error, LogStream::Meta, detail.clone());
            let mut result = TaskResult::failed("NPM", detail.clone());
            result.report_sections.push(TaskReportSection {
                key: "npm_packages".to_string(),
                title: "NPM Package Results".to_string(),
                rows: vec![TaskReportRow {
                    name: "npm outdated".to_string(),
                    status: TaskReportStatus::Failed,
                    before: None,
                    after: None,
                    note: Some(detail),
                }],
            });
            if let Some(outcome) = authority_outcome.as_ref() {
                if let Some(section) = package_authority::report_section(outcome) {
                    result.report_sections.push(section);
                }
            }
            result.advisories = dedupe_advisories(advisories);
            return Ok(result);
        }
    };

    let system_managed_packages = npm_system_managed_packages(npm_bin, &parsed_outdated);
    for (package, owner) in &system_managed_packages {
        excluded_packages.insert(package.clone());
        ctx.log_line(
            TASK_NPM,
            LogLevel::Info,
            LogStream::Meta,
            format!("- {package}: excluded from npm mutation ({owner})"),
        );
    }
    if let Some(blocked) = preflight_npm_mutation(
        ctx,
        npm_bin,
        &parsed_outdated,
        &installed_global_versions,
        &excluded_packages,
        &system_managed_packages,
        None,
    ) {
        return Ok(blocked);
    }

    let observed_outdated_packages = parsed_outdated
        .keys()
        .filter(|package| {
            installed_global_versions.contains_key(*package)
                && !excluded_packages.contains(*package)
        })
        .cloned()
        .collect::<Vec<_>>();
    if !observed_outdated_packages.is_empty() {
        match package_authority::reconcile_for_task(ctx, "npm", observed_outdated_packages, false) {
            Ok(outcome) => {
                excluded_packages.extend(outcome.excluded_packages.iter().cloned());
                authority_outcome = Some(outcome);
            }
            Err(error) => {
                let detail = format!("package-provider reconciliation skipped: {error}");
                ctx.log_line(TASK_NPM, LogLevel::Warn, LogStream::Meta, detail.clone());
                advisories.push(TaskAdvisory {
                    severity: AdvisorySeverity::Warning,
                    code: "package-authority-unavailable".to_string(),
                    summary: "Package-provider reconciliation was unavailable".to_string(),
                    remediation: detail,
                    blocks_dependents: false,
                });
            }
        }
    }

    let unobserved_outdated_packages = parsed_outdated
        .keys()
        .filter(|package| {
            !installed_global_versions.contains_key(*package)
                && !excluded_packages.contains(*package)
        })
        .cloned()
        .collect::<Vec<_>>();
    if !unobserved_outdated_packages.is_empty() {
        match package_authority::reconcile_for_task(ctx, "npm", unobserved_outdated_packages, false)
        {
            Ok(outcome) => {
                excluded_packages.extend(outcome.excluded_packages.iter().cloned());
                if let Some(existing) = authority_outcome.as_mut() {
                    existing.merge(outcome);
                } else {
                    authority_outcome = Some(outcome);
                }
            }
            Err(error) => {
                let detail = format!(
                    "package-provider reconciliation for npm outdated inventory skipped: {error}"
                );
                ctx.log_line(TASK_NPM, LogLevel::Warn, LogStream::Meta, detail.clone());
                advisories.push(TaskAdvisory {
                    severity: AdvisorySeverity::Warning,
                    code: "package-authority-unavailable".to_string(),
                    summary: "Package-provider reconciliation was unavailable".to_string(),
                    remediation: detail,
                    blocks_dependents: false,
                });
            }
        }
    }

    if !npm_mutation_candidates(
        &parsed_outdated,
        &installed_global_versions,
        &excluded_packages,
    )
    .is_empty()
    {
        let notice = match npm_global_root(npm_bin)
            .and_then(|root| observe_npm_hidden_directories(&root))
        {
            Ok(observed) if observed.count > 0 => Some(TaskAdvisory {
                severity: AdvisorySeverity::Warning,
                code: "npm-hidden-directories-preserved".to_string(),
                summary: format!(
                    "Update All left {} unclassified hidden NPM director{} unchanged",
                    observed.count,
                    if observed.count == 1 { "y" } else { "ies" }
                ),
                remediation: format!(
                    "Names do not establish that these directories are disposable or recoverable. If NPM reports a conflict, review them before explicitly retrying; Update All will not delete or restore them. Observed paths: {}{}",
                    observed
                        .samples
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                    if observed.count > observed.samples.len() {
                        format!(
                            " ({} more omitted)",
                            observed.count - observed.samples.len()
                        )
                    } else {
                        String::new()
                    }
                ),
                blocks_dependents: false,
            }),
            Ok(_) => None,
            Err(error) => Some(TaskAdvisory {
                severity: AdvisorySeverity::Warning,
                code: "npm-hidden-directory-inspection-incomplete".to_string(),
                summary: "Read-only hidden NPM directory inspection did not complete".to_string(),
                remediation: format!(
                    "Update All performed no directory cleanup. Inspection failed: {error}. NPM's own update behavior is unchanged."
                ),
                blocks_dependents: false,
            }),
        };
        if let Some(notice) = notice {
            ctx.log_line(
                TASK_NPM,
                LogLevel::Warn,
                LogStream::Meta,
                format!("{}: {}", notice.summary, notice.remediation),
            );
            advisories.push(notice);
        }
    }

    if !parsed_outdated.is_empty() {
        ctx.log_line(
            TASK_NPM,
            LogLevel::Info,
            LogStream::Meta,
            format!(
                "npm outdated detected {} package(s); validating targets",
                parsed_outdated.len()
            ),
        );

        let installed_versions = if parsed_outdated
            .values()
            .any(|entry| normalize_version(entry.current.as_deref()).is_none())
        {
            npm_list_global_versions(npm_bin)
        } else {
            BTreeMap::new()
        };
        let mut plans = Vec::new();
        let mut blocked_manifest_packages: Vec<String> = Vec::new();
        for (pkg, entry) in &parsed_outdated {
            let current = npm_outdated_current_version(pkg, entry, &installed_versions);
            let current_missing = current.is_none();
            let current = current.unwrap_or_else(|| MISSING_NPM_CURRENT_VERSION.to_string());
            if excluded_packages.contains(pkg) {
                let note = system_managed_packages.get(pkg).map_or_else(
                    || {
                        "non-desired provider excluded from npm update and handed to reconciliation"
                            .to_string()
                    },
                    |owner| format!("owned by {owner}; update through that manager"),
                );
                ctx.log_line(
                    TASK_NPM,
                    LogLevel::Info,
                    LogStream::Meta,
                    format!("- {pkg}: skipped ({note})"),
                );
                report_rows.push(TaskReportRow {
                    name: pkg.clone(),
                    status: TaskReportStatus::Skipped,
                    before: Some(current),
                    after: None,
                    note: Some(note),
                });
                continue;
            }
            let Some(target_seed) = select_target(entry) else {
                ctx.log_line(
                    TASK_NPM,
                    LogLevel::Warn,
                    LogStream::Meta,
                    format!("- {pkg}: skipped (missing wanted/latest version; current={current})"),
                );
                report_rows.push(TaskReportRow {
                    name: pkg.clone(),
                    status: TaskReportStatus::Skipped,
                    before: Some(current),
                    after: None,
                    note: Some("missing wanted/latest version".to_string()),
                });
                continue;
            };

            let decision = version_update_decision(&current, &target_seed);
            match decision {
                VersionDecision::Newer => {
                    if let Some(issue) =
                        npm_view_manifest_protocol_issue(npm_bin, pkg, &target_seed)
                    {
                        let issue_detail = describe_manifest_protocol_issue(&issue);
                        ctx.log_line(
                            TASK_NPM,
                            LogLevel::Warn,
                            LogStream::Meta,
                            format!("- {pkg}: blocked before install ({issue_detail})"),
                        );
                        blocked_manifest_packages.push(format!("{pkg}@{target_seed}"));
                        advisories.push(TaskAdvisory {
                            severity: AdvisorySeverity::Warning,
                            code: "npm-invalid-published-manifest".to_string(),
                            summary: format!("{pkg}@{target_seed}: {issue_detail}"),
                            remediation: "This package needs to be republished without local-only dependency protocols such as workspace:, file:, link:, portal:, or patch: in its published manifest.".to_string(),
                            blocks_dependents: false,
                        });
                        report_rows.push(TaskReportRow {
                            name: pkg.clone(),
                            status: TaskReportStatus::Failed,
                            before: Some(current),
                            after: None,
                            note: Some(format!(
                                "{issue_detail}; requested target: {target_seed}; not mutated"
                            )),
                        });
                        continue;
                    }
                    ctx.log_line(
                        TASK_NPM,
                        LogLevel::Info,
                        LogStream::Meta,
                        format!("- {pkg}: {current} -> {target_seed}"),
                    );
                    plans.push(PlannedUpdate {
                        package: pkg.clone(),
                        current,
                        target: target_seed,
                        note: None,
                    });
                }
                VersionDecision::Unknown if current_missing => {
                    if let Some(issue) =
                        npm_view_manifest_protocol_issue(npm_bin, pkg, &target_seed)
                    {
                        let issue_detail = describe_manifest_protocol_issue(&issue);
                        ctx.log_line(
                            TASK_NPM,
                            LogLevel::Warn,
                            LogStream::Meta,
                            format!("- {pkg}: blocked before install ({issue_detail})"),
                        );
                        blocked_manifest_packages.push(format!("{pkg}@{target_seed}"));
                        advisories.push(TaskAdvisory {
                            severity: AdvisorySeverity::Warning,
                            code: "npm-invalid-published-manifest".to_string(),
                            summary: format!("{pkg}@{target_seed}: {issue_detail}"),
                            remediation: "This package needs to be republished without local-only dependency protocols such as workspace:, file:, link:, portal:, or patch: in its published manifest.".to_string(),
                            blocks_dependents: false,
                        });
                        report_rows.push(TaskReportRow {
                            name: pkg.clone(),
                            status: TaskReportStatus::Failed,
                            before: Some(current),
                            after: None,
                            note: Some(format!(
                                "{issue_detail}; requested target: {target_seed}; not mutated"
                            )),
                        });
                        continue;
                    }
                    ctx.log_line(
                        TASK_NPM,
                        LogLevel::Info,
                        LogStream::Meta,
                        format!(
                            "- {pkg}: reinstalling {target_seed} because installed version metadata is unavailable"
                        ),
                    );
                    plans.push(PlannedUpdate {
                        package: pkg.clone(),
                        current,
                        target: target_seed,
                        note: Some(
                            "current version unavailable; reinstalled selected target".to_string(),
                        ),
                    });
                }
                VersionDecision::NotNewer | VersionDecision::Unknown => {
                    let view_target = npm_view_latest_version(npm_bin, pkg);
                    let Some(view_target) = view_target else {
                        ctx.log_line(
                            TASK_NPM,
                            LogLevel::Warn,
                            LogStream::Meta,
                            format!(
                                "- {pkg}: skipped ({current} vs {target_seed}; npm view did not provide a newer version)"
                            ),
                        );
                        report_rows.push(TaskReportRow {
                            name: pkg.clone(),
                            status: TaskReportStatus::Unchanged,
                            before: Some(current),
                            after: Some(target_seed),
                            note: Some("npm view did not provide a newer version".to_string()),
                        });
                        continue;
                    };

                    if version_update_decision(&current, &view_target) == VersionDecision::Newer {
                        if let Some(issue) =
                            npm_view_manifest_protocol_issue(npm_bin, pkg, &view_target)
                        {
                            let issue_detail = describe_manifest_protocol_issue(&issue);
                            ctx.log_line(
                                TASK_NPM,
                                LogLevel::Warn,
                                LogStream::Meta,
                                format!("- {pkg}: blocked before install ({issue_detail})"),
                            );
                            blocked_manifest_packages.push(format!("{pkg}@{view_target}"));
                            advisories.push(TaskAdvisory {
                                severity: AdvisorySeverity::Warning,
                                code: "npm-invalid-published-manifest".to_string(),
                                summary: format!("{pkg}@{view_target}: {issue_detail}"),
                                remediation: "This package needs to be republished without local-only dependency protocols such as workspace:, file:, link:, portal:, or patch: in its published manifest.".to_string(),
                                blocks_dependents: false,
                            });
                            report_rows.push(TaskReportRow {
                                name: pkg.clone(),
                                status: TaskReportStatus::Failed,
                                before: Some(current),
                                after: None,
                                note: Some(format!(
                                    "{issue_detail}; requested target: {view_target}; not mutated"
                                )),
                            });
                            continue;
                        }
                        ctx.log_line(
                            TASK_NPM,
                            LogLevel::Info,
                            LogStream::Meta,
                            format!(
                                "- {pkg}: {current} -> {view_target} (verified via npm view; outdated reported {target_seed})"
                            ),
                        );
                        plans.push(PlannedUpdate {
                            package: pkg.clone(),
                            current,
                            target: view_target,
                            note: Some("verified via npm view".to_string()),
                        });
                    } else {
                        ctx.log_line(
                            TASK_NPM,
                            LogLevel::Warn,
                            LogStream::Meta,
                            format!(
                                "- {pkg}: skipped (target {target_seed} and npm view {view_target} are not newer than {current})"
                            ),
                        );
                        report_rows.push(TaskReportRow {
                            name: pkg.clone(),
                            status: TaskReportStatus::Unchanged,
                            before: Some(current),
                            after: Some(view_target),
                            note: Some("target version is not newer".to_string()),
                        });
                    }
                }
            }
        }

        if !blocked_manifest_packages.is_empty() {
            details.push(format!(
                "Blocked {} npm package(s) before install due to invalid published metadata: {}.",
                blocked_manifest_packages.len(),
                blocked_manifest_packages.join(", ")
            ));
        }

        if plans.is_empty() {
            ctx.log_line(
                TASK_NPM,
                LogLevel::Info,
                LogStream::Meta,
                "npm outdated found entries, but no safe updates were selected",
            );
        } else {
            let args = npm_install_args(&plans);
            ctx.log_line(
                TASK_NPM,
                LogLevel::Info,
                LogStream::Meta,
                format!("running npm install for {} package(s)", plans.len()),
            );
            let mut successful_plans: Vec<PlannedUpdate> = Vec::new();
            // Successful provider exit is not root verification. Retain the
            // latter separately if a later root stops the task early.
            let mut verified_rows = Vec::new();
            match ctx.run_npm_install_with_policy(npm_bin, args) {
                Ok(install_out) => {
                    if ctx.emit_plain {
                        crate::ua_out!("{install_out}");
                    }
                    advisories.extend(collect_npm_advisories(&install_out));
                    let blocked_scripts = parse_blocked_install_scripts(&install_out);
                    let planned_packages = plans
                        .iter()
                        .map(|plan| plan.package.as_str())
                        .collect::<BTreeSet<_>>();
                    let unassociated_scripts = blocked_scripts
                        .iter()
                        .filter(|script| !planned_packages.contains(script.package.as_str()))
                        .collect::<Vec<_>>();
                    for script in &unassociated_scripts {
                        record_unassociated_blocked_install_script(
                            &mut lifecycle_rows,
                            &mut advisories,
                            script,
                        );
                    }
                    for plan in &plans {
                        let Some(script) =
                            blocked_script_for_package(&blocked_scripts, &plan.package)
                        else {
                            successful_plans.push(plan.clone());
                            continue;
                        };
                        record_associated_lifecycle_diagnostic(
                            &mut lifecycle_rows,
                            &mut advisories,
                            plan,
                            script,
                        );
                        match verify_installed_npm_root(npm_bin, plan) {
                            Ok(()) => record_verified_npm_plan(&mut successful_plans, &mut verified_rows, plan,
                                "root version, manifest, and executable health verified despite lifecycle warning".to_string()),
                            Err(initial_health_failure) => {
                                match recover_unhealthy_npm_root(ctx, npm_bin, plan) {
                                    Ok(recovery_note) => record_verified_npm_plan(&mut successful_plans, &mut verified_rows, plan, recovery_note),
                                    Err(recovery_failure) => {
                                        if let Some(stop) = recovery_failure.stop {
                                            return Ok(npm_terminal_install_failure_result(stop, &plans, recovery_failure.to_string(), npm_rows_with_verified(report_rows, &verified_rows), advisories, authority_outcome.as_ref()));
                                        }
                                        record_blocked_install_script(
                                            &mut report_rows, &mut advisories, plan, script,
                                            &format!("root health failed ({initial_health_failure}); bounded recovery failed ({recovery_failure})"),
                                        );
                                    },
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    if crate::util::process::process_storage_exhausted(&e) {
                        return Ok(npm_storage_failure_result(
                            &plans,
                            command_error_summary(&e),
                            npm_rows_with_verified(report_rows, &verified_rows),
                            advisories,
                            authority_outcome.as_ref(),
                        ));
                    }
                    if crate::util::process::process_permission_denied(&e) {
                        let detail = format!("npm install authority failure: {e}");
                        ctx.log_line(
                            TASK_NPM,
                            LogLevel::Error,
                            LogStream::Meta,
                            format!(
                                "{detail}; suppressing per-package retries and refusing elevation"
                            ),
                        );
                        return Ok(npm_install_authority_failure_result(
                            &plans,
                            detail,
                            npm_rows_with_verified(report_rows, &verified_rows),
                            advisories,
                            authority_outcome.as_ref(),
                        ));
                    }
                    let retry_plan = RecoveryPlan {
                        kind: PackageManagerKind::Npm,
                        causes: vec![RecoveryCause::PartialBatchFailure],
                        actions: vec![RecoveryAction::RetryIndividually],
                    };
                    ctx.log_line(
                        TASK_NPM,
                        LogLevel::Warn,
                        LogStream::Meta,
                        format!(
                            "{} planned {:?} after batched install failed ({e})",
                            retry_plan.kind.label(),
                            retry_plan.actions
                        ),
                    );
                    details.push(format!(
                        "NPM Recovery: Batched npm install failed; retrying {} package(s) individually.",
                        plans.len()
                    ));
                    let mut failed_retry_count = 0usize;
                    for plan in &plans {
                        let retry_plan = [plan.clone()];
                        match ctx
                            .run_npm_install_with_policy(npm_bin, npm_install_args(&retry_plan))
                        {
                            Ok(retry_out) => {
                                if ctx.emit_plain {
                                    crate::ua_out!("{retry_out}");
                                }
                                advisories.extend(collect_npm_advisories(&retry_out));
                                let blocked_scripts = parse_blocked_install_scripts(&retry_out);
                                if let Some(script) =
                                    blocked_script_for_package(&blocked_scripts, &plan.package)
                                {
                                    record_associated_lifecycle_diagnostic(
                                        &mut lifecycle_rows,
                                        &mut advisories,
                                        plan,
                                        script,
                                    );
                                    let health = verify_installed_npm_root(npm_bin, plan);
                                    let recovery = match health {
                                        Ok(()) => Ok(
                                            "retried individually; root health verified despite lifecycle warning"
                                                .to_string(),
                                        ),
                                        Err(initial_health_failure) => {
                                            recover_unhealthy_npm_root(ctx, npm_bin, plan).map_err(
                                                |mut recovery_failure| {
                                                    recovery_failure.detail = format!(
                                                        "root health failed ({initial_health_failure}); bounded recovery failed ({recovery_failure})"
                                                    );
                                                    if crate::util::process::storage_exhaustion_output(&recovery_failure.detail) {
                                                        recovery_failure.stop = Some(NpmInstallStop::Storage);
                                                    }
                                                    recovery_failure
                                                },
                                            )
                                        }
                                    };
                                    match recovery {
                                        Ok(note) => record_verified_npm_plan(
                                            &mut successful_plans,
                                            &mut verified_rows,
                                            plan,
                                            note,
                                        ),
                                        Err(reason) => {
                                            if let Some(stop) = reason.stop {
                                                return Ok(npm_terminal_install_failure_result(
                                                    stop,
                                                    &plans,
                                                    reason.to_string(),
                                                    npm_rows_with_verified(
                                                        report_rows,
                                                        &verified_rows,
                                                    ),
                                                    advisories,
                                                    authority_outcome.as_ref(),
                                                ));
                                            }
                                            failed_retry_count += 1;
                                            record_blocked_install_script(
                                                &mut report_rows,
                                                &mut advisories,
                                                plan,
                                                script,
                                                &reason.to_string(),
                                            );
                                        }
                                    }
                                } else if blocked_scripts.is_empty() {
                                    successful_plans.push(PlannedUpdate {
                                        package: plan.package.clone(),
                                        current: plan.current.clone(),
                                        target: plan.target.clone(),
                                        note: append_retry_note(plan.note.as_deref()),
                                    });
                                } else {
                                    failed_retry_count += 1;
                                    for script in &blocked_scripts {
                                        record_unassociated_blocked_install_script(
                                            &mut lifecycle_rows,
                                            &mut advisories,
                                            script,
                                        );
                                    }
                                }
                            }
                            Err(retry_err) => {
                                if crate::util::process::process_storage_exhausted(&retry_err) {
                                    return Ok(npm_storage_failure_result(
                                        &plans,
                                        command_error_summary(&retry_err),
                                        npm_rows_with_verified(report_rows, &verified_rows),
                                        advisories,
                                        authority_outcome.as_ref(),
                                    ));
                                }
                                if crate::util::process::process_permission_denied(&retry_err) {
                                    return Ok(npm_install_authority_failure_result(
                                        &plans,
                                        command_error_summary(&retry_err),
                                        npm_rows_with_verified(report_rows, &verified_rows),
                                        advisories,
                                        authority_outcome.as_ref(),
                                    ));
                                }
                                failed_retry_count += 1;
                                ctx.log_line(
                                    TASK_NPM,
                                    LogLevel::Error,
                                    LogStream::Meta,
                                    format!(
                                        "- {}: install failed after batch retry ({retry_err})",
                                        plan.package
                                    ),
                                );
                                report_rows.push(TaskReportRow {
                                    name: plan.package.clone(),
                                    status: TaskReportStatus::Failed,
                                    before: Some(plan.current.clone()),
                                    after: None,
                                    note: Some(format!(
                                        "install command failed after batch retry: {retry_err}; requested target: {}; installed state unverified",
                                        plan.target
                                    )),
                                });
                            }
                        }
                    }
                    if successful_plans.is_empty()
                        && report_rows
                            .iter()
                            .any(|row| row.status == TaskReportStatus::Failed)
                    {
                        let detail = format!("npm install failed: {e}");
                        ctx.log_line(TASK_NPM, LogLevel::Error, LogStream::Meta, detail.clone());
                        let mut result = TaskResult::failed("NPM", detail);
                        result.details.push(build_report_counts_line(&report_rows));
                        if !report_rows.is_empty() {
                            result.report_sections.push(TaskReportSection {
                                key: "npm_packages".to_string(),
                                title: "NPM Package Results".to_string(),
                                rows: report_rows,
                            });
                        }
                        if let Some(outcome) = authority_outcome.as_ref() {
                            if let Some(section) = package_authority::report_section(outcome) {
                                result.report_sections.push(section);
                            }
                        }
                        result.advisories = dedupe_advisories(advisories);
                        return Ok(result);
                    }
                    details.push(format!(
                        "Recovered {} npm package(s) via per-package retry; {} still failed.",
                        successful_plans.len(),
                        failed_retry_count
                    ));
                }
            }

            let post_outdated = run_capture_stdout_allow_exit_codes(
                npm_bin,
                ["outdated", "-g", "--json"],
                Some(Duration::from_secs(NPM_OUTDATED_TIMEOUT_SECS)),
                &[1],
            )
            .ok()
            .and_then(|payload| parse_npm_outdated_payload(&payload).ok())
            .unwrap_or_default();

            ctx.log_line(
                TASK_NPM,
                LogLevel::Info,
                LogStream::Meta,
                "npm results per package:",
            );
            let result_row_start = report_rows.len();
            let installed_versions = npm_list_global_versions(npm_bin);
            let installed_root = npm_global_root(npm_bin)
                .map_err(|error| format!("could not resolve npm global root: {error}"));
            for plan in &successful_plans {
                if let Some(observed_entry) = post_outdated.get(&plan.package) {
                    let observed = normalize_version(observed_entry.current.as_deref())
                        .unwrap_or_else(|| MISSING_NPM_CURRENT_VERSION.to_string());
                    ctx.log_line(
                        TASK_NPM,
                        LogLevel::Warn,
                        LogStream::Meta,
                        format!(
                            "- {}: still outdated (target {}, observed {}, started at {})",
                            plan.package, plan.target, observed, plan.current
                        ),
                    );
                    report_rows.push(TaskReportRow {
                        name: plan.package.clone(),
                        status: TaskReportStatus::Failed,
                        before: Some(plan.current.clone()),
                        after: Some(observed.clone()),
                        note: Some(format!(
                            "still outdated after install; target {}; observed {observed}",
                            plan.target
                        )),
                    });
                } else {
                    let health = installed_root
                        .as_ref()
                        .map_err(Clone::clone)
                        .and_then(|root| {
                            verify_installed_npm_root_with_state(plan, &installed_versions, root)
                        });
                    let recovery_note = match health {
                        Ok(()) => None,
                        Err(initial_health_failure) => {
                            verified_rows.retain(|row| row.name != plan.package);
                            match recover_unhealthy_npm_root(ctx, npm_bin, plan) {
                                Ok(note) => Some(note),
                                Err(recovery_failure) => {
                                    if let Some(stop) = recovery_failure.stop {
                                        return Ok(npm_terminal_install_failure_result(
                                            stop,
                                            &plans,
                                            recovery_failure.to_string(),
                                            npm_rows_with_verified(report_rows, &verified_rows),
                                            advisories,
                                            authority_outcome.as_ref(),
                                        ));
                                    }
                                    let reason = format!(
                                        "root executable health failed ({initial_health_failure}); bounded recovery failed ({recovery_failure})"
                                    );
                                    report_rows.push(TaskReportRow {
                                        name: plan.package.clone(),
                                        status: TaskReportStatus::Blocked,
                                        before: Some(plan.current.clone()),
                                        after: installed_versions.get(&plan.package).cloned(),
                                        note: Some(reason.clone()),
                                    });
                                    advisories.push(TaskAdvisory {
                                    severity: AdvisorySeverity::Error,
                                    code: "npm-root-health-blocked".to_string(),
                                    summary: format!("{}: {reason}", plan.package),
                                    remediation: "Review the package's install diagnostics and repair its declared executable before rerunning; no lifecycle trust was persisted.".to_string(),
                                    blocks_dependents: true,
                                });
                                    continue;
                                }
                            }
                        }
                    };
                    let suffix = plan
                        .note
                        .as_deref()
                        .map(|v| format!(" ({v})"))
                        .unwrap_or_default();
                    ctx.log_line(
                        TASK_NPM,
                        LogLevel::Info,
                        LogStream::Meta,
                        format!(
                            "- {}: updated {} -> {}{}",
                            plan.package, plan.current, plan.target, suffix
                        ),
                    );
                    report_rows.push(TaskReportRow {
                        name: plan.package.clone(),
                        status: TaskReportStatus::Updated,
                        before: Some(plan.current.clone()),
                        after: Some(plan.target.clone()),
                        note: recovery_note.or_else(|| plan.note.clone()),
                    });
                }
            }
            let verified_updates = report_rows[result_row_start..]
                .iter()
                .filter(|row| row.status == TaskReportStatus::Updated)
                .count();
            details.push(format!("Updated {} npm package(s).", verified_updates));
        }
    } else {
        ctx.log_line(
            TASK_NPM,
            LogLevel::Info,
            LogStream::Meta,
            "npm outdated reported no global package updates",
        );
        report_rows.extend(npm_unchanged_version_rows(npm_bin));
        if report_rows.is_empty() {
            report_rows.push(TaskReportRow {
                name: "npm".to_string(),
                status: TaskReportStatus::Unchanged,
                before: Some("-".to_string()),
                after: Some("-".to_string()),
                note: Some("no updates".to_string()),
            });
        }
    }

    if !report_rows.is_empty() {
        details.push(build_report_counts_line(&report_rows));
    }
    let advisories = dedupe_advisories(advisories);

    let mut result = TaskResult {
        label: "NPM".to_string(),
        status: if report_rows
            .iter()
            .any(|row| row.status == TaskReportStatus::Failed)
            && !report_rows
                .iter()
                .any(|row| row.status == TaskReportStatus::Updated)
        {
            TaskStatus::Failed
        } else {
            TaskStatus::Completed
        },
        details,
        advisories,
        report_sections: Vec::new(),
    };
    if !report_rows.is_empty() {
        result.report_sections.push(TaskReportSection {
            key: "npm_packages".to_string(),
            title: "NPM Package Results".to_string(),
            rows: report_rows,
        });
    }
    if !lifecycle_rows.is_empty() {
        result.report_sections.push(TaskReportSection {
            key: "npm_lifecycle_diagnostics".to_string(),
            title: "NPM Lifecycle Diagnostics".to_string(),
            rows: lifecycle_rows,
        });
    }
    if let Some(outcome) = authority_outcome.as_ref() {
        if let Some(section) = package_authority::report_section(outcome) {
            result.report_sections.push(section);
        }
    }
    Ok(result)
}

fn collect_npm_advisories(output: &str) -> Vec<TaskAdvisory> {
    let mut advisories = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains("npm warn ebadengine") {
            advisories.push(TaskAdvisory {
                severity: AdvisorySeverity::Warning,
                code: "npm-engine-mismatch".to_string(),
                summary: "One or more npm packages reported an unsupported Node engine"
                    .to_string(),
                remediation:
                    "Use a supported Node release for the affected package set or pin package versions that support the installed Node version.".to_string(),
                blocks_dependents: false,
            });
            continue;
        }
        if lower.starts_with("npm warn")
            && lower.contains("allow-scripts")
            && !lower.starts_with("npm warn install-scripts")
        {
            advisories.push(TaskAdvisory {
                severity: AdvisorySeverity::Warning,
                code: "npm-allow-scripts-config".to_string(),
                summary: trimmed.to_string(),
                remediation:
                    "Review npm configuration for deprecated allow-scripts usage and remove or replace it before the next npm major release.".to_string(),
                blocks_dependents: false,
            });
            continue;
        }
        if lower.contains("npm warn deprecated ") {
            advisories.push(TaskAdvisory {
                severity: AdvisorySeverity::Info,
                code: "npm-deprecated-package".to_string(),
                summary: trimmed.to_string(),
                remediation:
                    "Review the deprecated dependency chain and update or replace the affected package when practical.".to_string(),
                blocks_dependents: false,
            });
        }
    }
    dedupe_advisories(advisories)
}

fn dedupe_advisories(advisories: Vec<TaskAdvisory>) -> Vec<TaskAdvisory> {
    let mut seen = BTreeMap::<(String, String), TaskAdvisory>::new();
    for advisory in advisories {
        seen.entry((advisory.code.clone(), advisory.summary.clone()))
            .or_insert(advisory);
    }
    seen.into_values().collect()
}

const NPM_HIDDEN_DIRECTORY_SAMPLES: usize = 5;

#[derive(Default)]
struct NpmHiddenDirectories {
    count: usize,
    samples: BTreeSet<PathBuf>,
}

impl NpmHiddenDirectories {
    fn observe(&mut self, path: PathBuf) {
        self.count = self.count.saturating_add(1);
        self.samples.insert(path);
        if self.samples.len() > NPM_HIDDEN_DIRECTORY_SAMPLES {
            self.samples.pop_last();
        }
    }
}

// This is observation only: neither a name nor an installed canonical copy
// grants Update All authority to remove a provider's potentially retained data.
fn observe_npm_hidden_directories(root: &Path) -> Result<NpmHiddenDirectories> {
    if !root.is_absolute() {
        anyhow::bail!("npm global root is not an absolute path");
    }
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("could not inspect npm global root {}", root.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        anyhow::bail!("npm global root {} is not a real directory", root.display());
    }
    let mut observed = NpmHiddenDirectories::default();
    observe_npm_hidden_directories_in_dir(root, &mut observed, true)?;
    Ok(observed)
}

fn observe_npm_hidden_directories_in_dir(
    dir: &Path,
    observed: &mut NpmHiddenDirectories,
    inspect_scopes: bool,
) -> Result<()> {
    for entry in fs::read_dir(dir)
        .with_context(|| format!("could not read npm directory {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("could not read entry in {}", dir.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("could not inspect npm entry {}", entry.path().display()))?;
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if is_hidden_hyphenated_directory_name(&name) {
            observed.observe(entry.path());
        } else if inspect_scopes && name.starts_with('@') {
            // Exactly one real scope level, never a recursive package walk.
            observe_npm_hidden_directories_in_dir(&entry.path(), observed, false)?;
        }
    }
    Ok(())
}

fn npm_global_root(npm_bin: &str) -> Result<PathBuf> {
    let raw = run_capture_stdout_allow_exit_codes(
        npm_bin,
        ["root", "-g"],
        Some(Duration::from_secs(30)),
        &[],
    )?;
    let root = raw
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| anyhow::anyhow!("npm root -g returned an empty path"))?;
    Ok(PathBuf::from(root))
}

fn verify_installed_npm_root(npm_bin: &str, plan: &PlannedUpdate) -> Result<(), String> {
    let versions = npm_list_global_versions(npm_bin);
    let root = npm_global_root(npm_bin)
        .map_err(|error| format!("could not resolve npm global root: {error}"))?;
    verify_installed_npm_root_with_state(plan, &versions, &root)
}

fn verify_installed_npm_root_with_state(
    plan: &PlannedUpdate,
    versions: &BTreeMap<String, String>,
    root: &Path,
) -> Result<(), String> {
    let observed = versions
        .get(&plan.package)
        .cloned()
        .ok_or_else(|| format!("{} is absent from npm list -g", plan.package))?;
    if observed != plan.target {
        return Err(format!(
            "installed version mismatch: expected {}, observed {observed}",
            plan.target
        ));
    }

    let package_dir = root.join(&plan.package);
    let manifest_path = package_dir.join("package.json");
    let manifest_raw = fs::read_to_string(&manifest_path)
        .map_err(|error| format!("could not read {}: {error}", manifest_path.display()))?;
    let manifest: Value = serde_json::from_str(&manifest_raw)
        .map_err(|error| format!("invalid {}: {error}", manifest_path.display()))?;
    let manifest_version = manifest
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{} has no string version", manifest_path.display()))?;
    if manifest_version != plan.target {
        return Err(format!(
            "installed manifest version mismatch: expected {}, observed {manifest_version}",
            plan.target
        ));
    }

    let mut bins = BTreeMap::new();
    match manifest.get("bin") {
        None | Some(Value::Null) => return Ok(()),
        Some(Value::String(path)) => {
            let name = plan
                .package
                .rsplit('/')
                .next()
                .unwrap_or(plan.package.as_str());
            bins.insert(name.to_string(), path.clone());
        }
        Some(Value::Object(entries)) => {
            for (name, path) in entries {
                let path = path
                    .as_str()
                    .ok_or_else(|| format!("manifest bin target for {name} is not a string"))?;
                bins.insert(name.clone(), path.to_string());
            }
        }
        Some(_) => return Err("manifest bin field is neither a string nor an object".to_string()),
    }
    if bins.is_empty() {
        return Ok(());
    }

    for (name, relative) in &bins {
        let path = Path::new(relative);
        if path.is_absolute()
            || path
                .components()
                .any(|component| component == std::path::Component::ParentDir)
        {
            return Err(format!(
                "manifest bin target for {name} escapes the package root"
            ));
        }
        let target = package_dir.join(path);
        if !target.is_file() {
            return Err(format!(
                "manifest bin target for {name} is missing: {}",
                target.display()
            ));
        }
    }

    let Some((primary, _)) = bins.first_key_value() else {
        return Ok(());
    };
    let prefix_bin = root
        .parent()
        .and_then(Path::parent)
        .map(|prefix| prefix.join("bin").join(primary));
    let executable = prefix_bin
        .filter(|path| path.is_file())
        .or_else(|| which(primary))
        .ok_or_else(|| format!("declared global executable {primary} is not available"))?;
    for candidate in [["--version"], ["version"], ["--help"]] {
        if run_capture_stdout_allow_exit_codes(
            executable.to_string_lossy().as_ref(),
            candidate,
            Some(Duration::from_secs(10)),
            &[],
        )
        .is_ok()
        {
            return Ok(());
        }
    }
    Err(format!(
        "declared global executable {primary} failed bounded version/help probes"
    ))
}

fn is_hidden_hyphenated_directory_name(name: &str) -> bool {
    if name == ".bin" {
        return false;
    }

    let Some(rest) = name.strip_prefix('.') else {
        return false;
    };
    !rest.is_empty() && rest.contains('-')
}

fn parse_npm_outdated_payload(raw: &str) -> Result<BTreeMap<String, NpmOutdatedEntry>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "{}" {
        return Ok(BTreeMap::new());
    }

    parse_json_payload(trimmed)
}

fn parse_json_payload<T>(raw: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    let trimmed = raw.trim();
    if let Ok(value) = serde_json::from_str::<T>(trimmed) {
        return Ok(value);
    }

    if let Some(value) = parse_first_json_object(trimmed) {
        return Ok(value);
    }

    anyhow::bail!("missing JSON object in command output")
}

fn parse_first_json_object<T>(input: &str) -> Option<T>
where
    T: DeserializeOwned,
{
    for (start, ch) in input.char_indices() {
        if ch != '{' {
            continue;
        }
        let Some(candidate) = balanced_json_object_at(input, start) else {
            continue;
        };
        if let Ok(value) = serde_json::from_str::<T>(candidate) {
            return Some(value);
        }
    }
    None
}

fn balanced_json_object_at(input: &str, start: usize) -> Option<&str> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (offset, ch) in input[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    let end = start + offset + ch.len_utf8();
                    return input.get(start..end);
                }
            }
            _ => {}
        }
    }
    None
}

fn select_target(entry: &NpmOutdatedEntry) -> Option<String> {
    normalize_version(entry.latest.as_deref())
        .or_else(|| normalize_version(entry.wanted.as_deref()))
}

fn npm_list_global_versions(npm_bin: &str) -> BTreeMap<String, String> {
    run_capture_stdout_allow_exit_codes(
        npm_bin,
        ["list", "-g", "--depth=0", "--json"],
        Some(Duration::from_secs(30)),
        &[1],
    )
    .ok()
    .map(|payload| parse_npm_list_versions(&payload))
    .unwrap_or_default()
}

fn npm_unchanged_version_rows(npm_bin: &str) -> Vec<TaskReportRow> {
    npm_list_global_versions(npm_bin)
        .into_iter()
        .map(|(name, version)| TaskReportRow {
            name,
            status: TaskReportStatus::Unchanged,
            before: Some(version.clone()),
            after: Some(version),
            note: Some("installed".to_string()),
        })
        .collect()
}

fn parse_npm_list_versions(raw: &str) -> BTreeMap<String, String> {
    let trimmed = raw.trim();
    let json = match parse_json_payload::<Value>(trimmed) {
        Ok(json) => json,
        Err(_) => return BTreeMap::new(),
    };
    let Some(dependencies) = json.get("dependencies").and_then(Value::as_object) else {
        return BTreeMap::new();
    };

    dependencies
        .iter()
        .filter_map(|(name, value)| {
            value
                .get("version")
                .and_then(Value::as_str)
                .and_then(|version| normalize_version(Some(version)))
                .map(|version| (name.clone(), version))
        })
        .collect()
}

fn npm_outdated_current_version(
    pkg: &str,
    entry: &NpmOutdatedEntry,
    installed_versions: &BTreeMap<String, String>,
) -> Option<String> {
    normalize_version(entry.current.as_deref())
        .or_else(|| installed_versions.get(pkg).cloned())
        .or_else(|| {
            entry
                .location
                .as_deref()
                .and_then(npm_package_location_version)
        })
}

fn npm_package_location_version(location: &str) -> Option<String> {
    let package_json = Path::new(location).join("package.json");
    let raw = fs::read_to_string(package_json).ok()?;
    let json = serde_json::from_str::<Value>(&raw).ok()?;
    json.get("version")
        .and_then(Value::as_str)
        .and_then(|version| normalize_version(Some(version)))
}

fn normalize_version(input: Option<&str>) -> Option<String> {
    let v = input?.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("n/a") {
        return None;
    }
    Some(v.to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VersionDecision {
    Newer,
    NotNewer,
    Unknown,
}

fn version_update_decision(current: &str, target: &str) -> VersionDecision {
    match semver_cmp(target, current) {
        Some(cmp) if cmp > 0 => VersionDecision::Newer,
        Some(_) => VersionDecision::NotNewer,
        None => VersionDecision::Unknown,
    }
}

fn npm_view_latest_version(npm_bin: &str, package: &str) -> Option<String> {
    let first = run_capture_stdout_allow_exit_codes(
        npm_bin,
        ["view", package, "version", "--json"],
        Some(Duration::from_secs(30)),
        &[1],
    )
    .ok()
    .and_then(|payload| parse_npm_view_version(&payload));
    if first.is_some() {
        return first;
    }

    run_capture_stdout_allow_exit_codes(
        npm_bin,
        ["view", package, "version"],
        Some(Duration::from_secs(30)),
        &[1],
    )
    .ok()
    .and_then(|payload| parse_npm_view_version(&payload))
}

fn npm_view_manifest_protocol_issue(
    npm_bin: &str,
    package: &str,
    version: &str,
) -> Option<ManifestProtocolIssue> {
    read_npm_registry_manifest(npm_bin, package, version)
        .ok()
        .and_then(|payload| parse_npm_manifest_protocol_issue(&payload))
}

fn npm_view_manifest_protocol_issue_checked(
    npm_bin: &str,
    package: &str,
    version: &str,
) -> Result<Option<ManifestProtocolIssue>, String> {
    let payload = read_npm_registry_manifest(npm_bin, package, version)?;
    parse_npm_manifest_protocol_issue_checked(&payload, package, version).map_err(|_| {
        format!(
            "registry manifest is invalid for {package}@{version}; no script authorization granted"
        )
    })
}

fn read_npm_registry_manifest(
    npm_bin: &str,
    package: &str,
    version: &str,
) -> Result<String, String> {
    let spec = format!("{package}@{version}");
    // A full-manifest query avoids the legitimately empty output of selected
    // fields on packages without dependencies. npm 12 wraps it in an array.
    run_capture_stdout_allow_exit_codes(
        npm_bin,
        ["view", spec.as_str(), "--json"],
        Some(Duration::from_secs(30)),
        &[],
    )
    .map_err(|_| {
        format!("registry manifest observation failed for {spec}; no script authorization granted")
    })
}

fn parse_npm_manifest_protocol_issue(raw: &str) -> Option<ManifestProtocolIssue> {
    let json: Value = parse_json_payload(raw.trim()).ok()?;
    inspect_npm_manifest_dependency_sources(&json)
        .ok()
        .flatten()
}

fn parse_npm_manifest_protocol_issue_checked(
    raw: &str,
    package: &str,
    version: &str,
) -> Result<Option<ManifestProtocolIssue>, String> {
    let json: Value =
        serde_json::from_str(raw.trim()).map_err(|_| "invalid registry JSON".to_string())?;
    let manifest = match &json {
        Value::Array(entries) if entries.len() == 1 => &entries[0],
        Value::Object(_) => &json,
        _ => return Err("registry result must contain exactly one manifest".to_string()),
    };
    if manifest.get("name").and_then(Value::as_str) != Some(package)
        || manifest.get("version").and_then(Value::as_str) != Some(version)
    {
        return Err("registry manifest identity does not match requested package".to_string());
    }
    inspect_npm_manifest_dependency_sources(&json)
}

fn inspect_npm_manifest_dependency_sources(
    json: &Value,
) -> Result<Option<ManifestProtocolIssue>, String> {
    let json = if let Value::Array(entries) = json {
        entries
            .first()
            .filter(|_| entries.len() == 1)
            .ok_or_else(|| "registry result must contain exactly one manifest".to_string())?
    } else {
        json
    };
    let object = json
        .as_object()
        .ok_or_else(|| "registry manifest must be an object".to_string())?;
    for field in ["dependencies", "optionalDependencies", "peerDependencies"] {
        let Some(value) = object.get(field) else {
            continue;
        };
        let map = value
            .as_object()
            .ok_or_else(|| format!("registry {field} must be an object"))?;
        for (dependency, spec) in map {
            let spec = spec
                .as_str()
                .ok_or_else(|| "registry dependency selector must be a string".to_string())?;
            if let Some(protocol) = non_registry_dependency_source(spec) {
                return Ok(Some(ManifestProtocolIssue {
                    field: field.to_string(),
                    dependency: dependency.clone(),
                    spec: spec.to_string(),
                    protocol: protocol.to_string(),
                }));
            }
        }
    }
    Ok(None)
}

fn non_registry_dependency_source(spec: &str) -> Option<&'static str> {
    let trimmed = spec.trim();
    for protocol in [
        "workspace:",
        "file:",
        "link:",
        "portal:",
        "patch:",
        "git:",
        "git+",
        "git://",
        "github:",
        "http:",
        "https:",
    ] {
        if trimmed.starts_with(protocol) {
            return Some(protocol.trim_end_matches(':'));
        }
    }
    if trimmed.starts_with('/')
        || trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || (trimmed.starts_with('~')
            && (trimmed == "~" || trimmed.contains('/') || trimmed.contains('\\')))
    {
        return Some("path");
    }
    None
}

fn parse_npm_view_version(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(json) = serde_json::from_str::<Value>(trimmed) {
        match json {
            Value::String(v) => return normalize_version(Some(&v)),
            Value::Array(values) => {
                for value in values {
                    if let Value::String(v) = value {
                        if let Some(normalized) = normalize_version(Some(&v)) {
                            return Some(normalized);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let line = trimmed
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())?;
    normalize_version(Some(line.trim_matches('"')))
}

fn semver_cmp(left: &str, right: &str) -> Option<i8> {
    let a = parse_semver(left)?;
    let b = parse_semver(right)?;

    if a.main != b.main {
        return Some(if a.main > b.main { 1 } else { -1 });
    }

    match (&a.pre, &b.pre) {
        (None, None) => Some(0),
        (None, Some(_)) => Some(1),
        (Some(_), None) => Some(-1),
        (Some(ap), Some(bp)) => {
            let max = ap.len().max(bp.len());
            for idx in 0..max {
                match (ap.get(idx), bp.get(idx)) {
                    (Some(lv), Some(rv)) => {
                        if lv == rv {
                            continue;
                        }
                        return Some(compare_prerelease_part(lv, rv));
                    }
                    (Some(_), None) => return Some(1),
                    (None, Some(_)) => return Some(-1),
                    (None, None) => break,
                }
            }
            Some(0)
        }
    }
}

fn compare_prerelease_part(left: &PrereleasePart, right: &PrereleasePart) -> i8 {
    match (left, right) {
        (PrereleasePart::Num(l), PrereleasePart::Num(r)) => {
            if l == r {
                0
            } else if l > r {
                1
            } else {
                -1
            }
        }
        (PrereleasePart::Text(l), PrereleasePart::Text(r)) => {
            if l == r {
                0
            } else if l > r {
                1
            } else {
                -1
            }
        }
        (PrereleasePart::Num(_), PrereleasePart::Text(_)) => -1,
        (PrereleasePart::Text(_), PrereleasePart::Num(_)) => 1,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ParsedSemver {
    main: Vec<u64>,
    pre: Option<Vec<PrereleasePart>>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PrereleasePart {
    Num(u64),
    Text(String),
}

fn parse_semver(input: &str) -> Option<ParsedSemver> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let trimmed = trimmed.strip_prefix('v').unwrap_or(trimmed);
    let (version_core, _build_meta) = trimmed.split_once('+').unwrap_or((trimmed, ""));
    let (main, pre) = version_core.split_once('-').unwrap_or((version_core, ""));

    let mut main_parts = Vec::new();
    for part in main.split('.') {
        if part.is_empty() {
            return None;
        }
        let value = part.parse::<u64>().ok()?;
        main_parts.push(value);
    }
    while main_parts.len() < 3 {
        main_parts.push(0);
    }

    let pre_parts = if pre.is_empty() {
        None
    } else {
        let mut parsed = Vec::new();
        for part in pre.split('.') {
            if part.is_empty() {
                return None;
            }
            if let Ok(n) = part.parse::<u64>() {
                parsed.push(PrereleasePart::Num(n));
            } else {
                parsed.push(PrereleasePart::Text(part.to_string()));
            }
        }
        Some(parsed)
    };

    Some(ParsedSemver {
        main: main_parts,
        pre: pre_parts,
    })
}

fn build_report_counts_line(rows: &[TaskReportRow]) -> String {
    let mut deferred = 0usize;
    let mut unconfirmed = 0usize;
    let mut updated = 0usize;
    let mut refreshed = 0usize;
    let mut unchanged = 0usize;
    let mut failed = 0usize;
    let mut blocked = 0usize;
    let mut skipped = 0usize;
    let mut info = 0usize;
    for row in rows {
        match row.status {
            TaskReportStatus::Updated => updated += 1,
            TaskReportStatus::Refreshed => refreshed += 1,
            TaskReportStatus::Passed => updated += 1,
            TaskReportStatus::Unchanged => unchanged += 1,
            TaskReportStatus::Failed => failed += 1,
            TaskReportStatus::Blocked => blocked += 1,
            TaskReportStatus::Deferred => deferred += 1,
            TaskReportStatus::Unconfirmed => unconfirmed += 1,
            TaskReportStatus::Skipped => skipped += 1,
            TaskReportStatus::Info => info += 1,
        }
    }
    let mut summary = format!(
        "NPM package report: updated={updated} refreshed={refreshed} unchanged={unchanged} failed={failed} blocked={blocked} skipped={skipped} info={info}"
    );
    if deferred > 0 {
        summary.push_str(&format!(" deferred={deferred}"));
    }
    if unconfirmed > 0 {
        summary.push_str(&format!(" unconfirmed={unconfirmed}"));
    }
    summary
}

#[cfg(test)]
mod tests {
    #[test]
    fn npm_hidden_directory_observation_is_bounded_and_never_recursive() {
        let temp = tempfile::TempDir::new().unwrap();
        for name in [
            ".bin",
            ".notes",
            "ordinary",
            "@scope",
            "ordinary/.nested-hidden",
        ] {
            fs::create_dir_all(temp.path().join(name)).unwrap();
        }
        for index in 0..12 {
            let name = format!(".retained-{index:02}");
            fs::create_dir_all(temp.path().join(&name)).unwrap();
            fs::write(temp.path().join(name).join("only-copy"), "preserve").unwrap();
        }
        fs::create_dir_all(temp.path().join("@scope/.scoped-retained")).unwrap();
        fs::write(temp.path().join(".hidden-file"), "preserve").unwrap();
        let observed = observe_npm_hidden_directories(temp.path()).unwrap();
        assert_eq!(observed.count, 13);
        assert_eq!(observed.samples.len(), NPM_HIDDEN_DIRECTORY_SAMPLES);
        assert_eq!(
            observed.samples.first().unwrap(),
            &temp.path().join(".retained-00")
        );
        assert_eq!(
            observed.samples.last().unwrap(),
            &temp.path().join(".retained-04")
        );
        for index in 0..12 {
            assert_eq!(
                fs::read_to_string(temp.path().join(format!(".retained-{index:02}/only-copy")))
                    .unwrap(),
                "preserve"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn npm_hidden_directory_observation_skips_symlinks_and_reports_unreadable_roots() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::TempDir::new().unwrap();
        let outside = tempfile::TempDir::new().unwrap();
        fs::create_dir_all(outside.path().join(".outside-retained")).unwrap();
        symlink(outside.path(), root.path().join(".linked-retained")).unwrap();
        symlink(outside.path(), root.path().join("@linked")).unwrap();
        assert_eq!(
            observe_npm_hidden_directories(root.path()).unwrap().count,
            0
        );
        assert!(observe_npm_hidden_directories(&root.path().join("@linked")).is_err());
        assert!(observe_npm_hidden_directories(&root.path().join("absent")).is_err());
        assert!(observe_npm_hidden_directories(Path::new("relative")).is_err());
        let scope = root.path().join("@unreadable");
        fs::create_dir(&scope).unwrap();
        fs::set_permissions(&scope, fs::Permissions::from_mode(0o000)).unwrap();
        let result = observe_npm_hidden_directories(root.path());
        fs::set_permissions(&scope, fs::Permissions::from_mode(0o700)).unwrap();
        // The product explicitly rejects root-owned global mutation already.
        if current_unix_uid().unwrap() != 0 {
            assert!(
                result.is_err(),
                "an incomplete scan cannot report a clean empty result"
            );
        }
        assert!(outside.path().join(".outside-retained").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn npm_global_path_ignores_stderr_diagnostics() {
        let _lock = crate::test_support::env_guard();
        let temp = tempfile::TempDir::new().unwrap();
        let npm = temp.path().join("npm");
        crate::test_support::write_executable(
            &npm,
            "#!/bin/sh\nprintf '/user-owned/prefix\\n'\nprintf 'cache routing unavailable; using the original tool\\n' >&2\n",
        ).unwrap();
        assert_eq!(
            super::npm_global_path(npm.to_str().unwrap(), "prefix").unwrap(),
            std::path::PathBuf::from("/user-owned/prefix")
        );
    }
    use super::*;

    #[test]
    fn npm_registry_tilde_ranges_are_not_local_dependency_paths() {
        for selector in ["~1.0.0", "~1.0", "~1", "~ 1.0.0", "~1.0.0 || ~2.0.0"] {
            let manifest = serde_json::json!({
                "name": "fixture-root", "version": "1.0.0",
                "dependencies": {"fixture-dependency": selector}
            });
            assert!(
                parse_npm_manifest_protocol_issue_checked(
                    &manifest.to_string(),
                    "fixture-root",
                    "1.0.0"
                )
                .unwrap()
                .is_none(),
                "registry range rejected: {selector}"
            );
        }
        for selector in [
            "~",
            "~/local",
            "~other/local",
            "~\\local",
            "./local",
            "../local",
            "/local",
            "file:local",
            "git+https://example.invalid/repository",
        ] {
            assert!(
                non_registry_dependency_source(selector).is_some(),
                "local source admitted: {selector}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_npm_authority_rejects_root_and_non_writable_ownership() {
        assert_eq!(
            unix_path_authority_issue(0, 1000, 0o755),
            Some("is owned by root")
        );
        assert_eq!(
            unix_path_authority_issue(1000, 1000, 0o555),
            Some("is not writable and searchable by its owner")
        );
        assert_eq!(unix_path_authority_issue(1000, 1000, 0o755), None);
    }

    #[test]
    fn npm_manifest_protocol_issue_tolerates_noisy_json_output() {
        let issue = parse_npm_manifest_protocol_issue(
            r#"
npm WARN config ignoring workspace config
{
  "dependencies": {
    "local-lib": "workspace:*"
  },
  "optionalDependencies": {},
  "peerDependencies": {}
}
"#,
        )
        .expect("manifest protocol issue");

        assert_eq!(issue.field, "dependencies");
        assert_eq!(issue.dependency, "local-lib");
        assert_eq!(issue.spec, "workspace:*");
        assert_eq!(issue.protocol, "workspace");
    }

    #[test]
    fn npm_manifest_protocol_issue_skips_braced_warning_noise() {
        let issue = parse_npm_manifest_protocol_issue(
            r#"
npm WARN config ignoring unsupported setting {workspace}
{
  "dependencies": {
    "local-lib": "file:../local-lib"
  }
}
"#,
        )
        .expect("manifest protocol issue");

        assert_eq!(issue.field, "dependencies");
        assert_eq!(issue.dependency, "local-lib");
        assert_eq!(issue.spec, "file:../local-lib");
        assert_eq!(issue.protocol, "file");
    }

    #[test]
    fn npm_advisories_include_allow_scripts_warning() {
        let advisories = collect_npm_advisories(
            "npm warn Unknown env config \"allow-scripts\". This will stop working in the next major version of npm.\n",
        );

        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].code, "npm-allow-scripts-config");
        assert_eq!(advisories[0].severity, AdvisorySeverity::Warning);
        assert!(advisories[0].summary.contains("allow-scripts"));
    }

    #[test]
    fn npm_advisories_dedupe_deprecated_warnings() {
        let advisories = collect_npm_advisories(
            "npm WARN deprecated uuid@10.0.0: use uuid 11\nnpm WARN deprecated uuid@10.0.0: use uuid 11\n",
        );

        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].code, "npm-deprecated-package");
        assert_eq!(advisories[0].severity, AdvisorySeverity::Info);
    }

    #[test]
    fn blocked_install_scripts_parser_associates_multiline_warning_with_package() {
        let blocked = parse_blocked_install_scripts(
            r#"changed 2 packages in 9s
npm warn install-scripts 1 package had install scripts blocked because they are not covered by allowScripts:
npm warn install-scripts   @anthropic-ai/claude-code@2.1.205 (postinstall: node install.cjs)
npm warn install-scripts
npm warn install-scripts Run `npm install -g --allow-scripts=@anthropic-ai/claude-code` to allow these scripts once
"#,
        );

        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].package, "@anthropic-ai/claude-code");
        assert_eq!(blocked[0].version, "2.1.205");
        assert_eq!(blocked[0].lifecycle, "postinstall: node install.cjs");
    }

    #[test]
    fn blocked_install_scripts_parser_deduplicates_package_version_and_lifecycle() {
        let blocked = parse_blocked_install_scripts(
            r#"
npm warn install-scripts helper@1.2.3 (postinstall: node install.cjs)
npm warn install-scripts helper@1.2.3 (postinstall: node install.cjs)
npm warn install-scripts helper@1.2.3 (prepare: node prepare.cjs)
"#,
        );

        assert_eq!(blocked.len(), 2);
        assert_eq!(blocked[0].lifecycle, "postinstall: node install.cjs");
        assert_eq!(blocked[1].lifecycle, "prepare: node prepare.cjs");
    }

    #[test]
    fn scoped_allow_scripts_retry_targets_only_the_blocked_desired_package() {
        let plan = PlannedUpdate {
            package: "@scope/desired-cli".to_string(),
            current: "1.0.0".to_string(),
            target: "2.0.0".to_string(),
            note: None,
        };

        let allowed = BTreeSet::from([
            "@scope/desired-cli".to_string(),
            "registry-helper".to_string(),
        ]);
        let args = npm_install_args_with_allowed_scripts(&plan, &allowed);

        assert_eq!(
            args,
            vec![
                "install",
                "-g",
                "--no-audit",
                "--no-fund",
                "--prefer-online",
                "--allow-scripts=@scope/desired-cli,registry-helper",
                "@scope/desired-cli@2.0.0",
            ]
        );
    }
}

#[cfg(test)]
mod outcome_evidence_tests {
    use super::*;
    #[test]
    fn npm_lifecycle_diagnostics_do_not_invent_an_installed_version() {
        let plan = PlannedUpdate {
            package: "first".into(),
            current: "1.0.0".into(),
            target: "2.0.0".into(),
            note: None,
        };
        let script = BlockedInstallScript {
            package: "first".into(),
            version: "2.0.0".into(),
            lifecycle: "install".into(),
        };
        let mut rows = Vec::new();
        let mut advisories = Vec::new();
        record_blocked_install_script(
            &mut rows,
            &mut advisories,
            &plan,
            &script,
            "health unverified",
        );
        record_associated_lifecycle_diagnostic(&mut rows, &mut advisories, &plan, &script);
        for row in rows {
            assert!(row.after.is_none(), "{row:?}");
            assert!(row.note.as_deref().unwrap().contains("2.0.0"));
        }
    }
}
