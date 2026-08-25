//! Shared package-manager recovery classification and planning.

use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PackageManagerKind {
    PacmanLike,
    Npm,
    Winget,
    Scoop,
    Apt,
    Dnf,
    Unknown,
}

impl PackageManagerKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::PacmanLike => "Pacman Recovery",
            Self::Npm => "NPM Recovery",
            Self::Winget => "Winget Recovery",
            Self::Scoop => "Scoop Recovery",
            Self::Apt => "Apt Recovery",
            Self::Dnf => "DNF Recovery",
            Self::Unknown => "Package Recovery",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PackageConflictPair {
    pub(crate) incoming: String,
    pub(crate) remove: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryCause {
    FileConflict {
        owners: Vec<String>,
    },
    PackageConflict {
        packages: Vec<String>,
        pairs: Vec<PackageConflictPair>,
    },
    LockOrBusy {
        summary: String,
    },
    SourceChecksumDrift {
        package: Option<String>,
    },
    BuildFailure {
        package: Option<String>,
        summary: String,
    },
    InvalidManifest {
        package: Option<String>,
    },
    InstallerHashMismatch,
    PartialBatchFailure,
    RunningProcess {
        packages: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryAction {
    RetryWhole,
    RetryIndividually,
    InstallArchive { package: String, archive: String },
    RemoveOptionalPackage { package: String },
    SkipOptionalPackage { package: String },
    ResumeWithIgnore { packages: Vec<String> },
    VerifiedRepositoryRetirement,
    DiagnoseOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryPlan {
    pub(crate) kind: PackageManagerKind,
    pub(crate) causes: Vec<RecoveryCause>,
    pub(crate) actions: Vec<RecoveryAction>,
}

impl RecoveryPlan {
    pub(crate) fn diagnose(kind: PackageManagerKind, causes: Vec<RecoveryCause>) -> Self {
        Self {
            kind,
            causes,
            actions: vec![RecoveryAction::DiagnoseOnly],
        }
    }

    pub(crate) fn retry_whole(kind: PackageManagerKind, causes: Vec<RecoveryCause>) -> Self {
        Self {
            kind,
            causes,
            actions: vec![RecoveryAction::RetryWhole],
        }
    }
}

pub(crate) fn package_manager_kind_for_task(task_id: &str, program: &str) -> PackageManagerKind {
    let task = task_id.to_ascii_lowercase();
    let program_name = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .trim_end_matches(".exe")
        .trim_end_matches(".cmd")
        .to_ascii_lowercase();
    if matches!(task.as_str(), "yay" | "pacman")
        || matches!(program_name.as_str(), "yay" | "pacman")
    {
        PackageManagerKind::PacmanLike
    } else if task == "npm" || program_name == "npm" {
        PackageManagerKind::Npm
    } else if task.starts_with("winget-") || program_name == "winget" {
        PackageManagerKind::Winget
    } else if task.starts_with("scoop") || program_name == "scoop" {
        PackageManagerKind::Scoop
    } else if task == "apt" || matches!(program_name.as_str(), "apt" | "apt-get") {
        PackageManagerKind::Apt
    } else if task == "dnf" || program_name == "dnf" {
        PackageManagerKind::Dnf
    } else {
        PackageManagerKind::Unknown
    }
}

pub(crate) fn classify_package_recovery(
    kind: PackageManagerKind,
    output: &str,
) -> Option<RecoveryPlan> {
    let lower = output.to_ascii_lowercase();
    match kind {
        PackageManagerKind::PacmanLike => classify_pacman_like(output, &lower),
        PackageManagerKind::Npm => classify_npm(&lower),
        PackageManagerKind::Winget => classify_winget(output, &lower),
        PackageManagerKind::Scoop => classify_scoop(output, &lower),
        PackageManagerKind::Apt | PackageManagerKind::Dnf => {
            classify_conservative_linux(kind, &lower)
        }
        PackageManagerKind::Unknown => classify_unknown(&lower),
    }
}

fn classify_pacman_like(output: &str, lower: &str) -> Option<RecoveryPlan> {
    if lower.contains("failed to commit transaction (conflicting files)") {
        let owners = collect_owned_by_packages(output);
        return Some(RecoveryPlan::diagnose(
            PackageManagerKind::PacmanLike,
            vec![RecoveryCause::FileConflict { owners }],
        ));
    }
    let mut causes = Vec::new();
    if lower.contains("unresolvable package conflicts")
        || lower.contains("conflicting dependencies")
    {
        causes.push(RecoveryCause::PackageConflict {
            packages: collect_conflicting_packages(output),
            pairs: collect_conflict_removal_pairs(output),
        });
    }
    let source_packages = if lower.contains("one or more files did not pass the validity check")
        || lower.contains("error downloading sources:")
    {
        collect_yay_source_drift_packages(output)
    } else {
        Vec::new()
    };
    if lower.contains("one or more files did not pass the validity check")
        || lower.contains("error downloading sources:")
    {
        if source_packages.is_empty() {
            causes.push(RecoveryCause::SourceChecksumDrift {
                package: parse_yay_error_making_package(output),
            });
        } else {
            causes.extend(source_packages.iter().cloned().into_iter().map(|package| {
                RecoveryCause::SourceChecksumDrift {
                    package: Some(package),
                }
            }));
        }
    }
    let build_packages = collect_yay_build_failure_packages(output, &source_packages);
    if !build_packages.is_empty() {
        causes.extend(
            build_packages
                .into_iter()
                .map(|package| RecoveryCause::BuildFailure {
                    summary: yay_build_failure_summary(output, Some(&package)),
                    package: Some(package),
                }),
        );
    } else if lower.contains("a failure occurred in build()") {
        let package = parse_yay_error_making_package(output)
            .filter(|package| !source_packages.iter().any(|source| source == package));
        causes.push(RecoveryCause::BuildFailure {
            summary: yay_build_failure_summary(output, package.as_deref()),
            package,
        });
    }
    if !causes.is_empty() {
        if let Some(lock_plan) = classify_lock_or_busy(PackageManagerKind::PacmanLike, lower) {
            causes.extend(lock_plan.causes);
        }
    }
    if !causes.is_empty() {
        let verified_repository_retirement = causes.len() == 1
            && matches!(
                &causes[0],
                RecoveryCause::PackageConflict { pairs, .. } if !pairs.is_empty()
            )
            && !contains_unrelated_pacman_error(output);
        return Some(if verified_repository_retirement {
            RecoveryPlan {
                kind: PackageManagerKind::PacmanLike,
                causes,
                actions: vec![RecoveryAction::VerifiedRepositoryRetirement],
            }
        } else {
            RecoveryPlan::diagnose(PackageManagerKind::PacmanLike, causes)
        });
    }
    classify_lock_or_busy(PackageManagerKind::PacmanLike, lower)
}

fn contains_unrelated_pacman_error(output: &str) -> bool {
    output.lines().any(|line| {
        let lower = line.trim().to_ascii_lowercase();
        lower.contains("error:")
            && !lower.contains("error: unresolvable package conflicts detected")
            && !lower.contains("error: failed to prepare transaction (conflicting dependencies)")
            && !lower.contains("error installing repo packages")
    })
}

fn classify_npm(lower: &str) -> Option<RecoveryPlan> {
    if lower.contains("unsupported url type")
        || lower.contains("eunsupportedprotocol")
        || lower.contains("workspace:")
        || lower.contains("file:")
    {
        return Some(RecoveryPlan::diagnose(
            PackageManagerKind::Npm,
            vec![RecoveryCause::InvalidManifest { package: None }],
        ));
    }
    if lower.contains("npm") && lower.contains("install") && lower.contains("failed") {
        return Some(RecoveryPlan {
            kind: PackageManagerKind::Npm,
            causes: vec![RecoveryCause::PartialBatchFailure],
            actions: vec![RecoveryAction::RetryIndividually],
        });
    }
    classify_lock_or_busy(PackageManagerKind::Npm, lower)
}

fn classify_winget(output: &str, lower: &str) -> Option<RecoveryPlan> {
    if output
        .lines()
        .any(|line| line.trim().contains("Installer hash does not match."))
    {
        return Some(RecoveryPlan::diagnose(
            PackageManagerKind::Winget,
            vec![RecoveryCause::InstallerHashMismatch],
        ));
    }
    if lower.contains("no suitable installer found for manifest")
        || lower.contains("error processing package dependencies")
    {
        return Some(RecoveryPlan::diagnose(
            PackageManagerKind::Winget,
            vec![RecoveryCause::InvalidManifest { package: None }],
        ));
    }
    classify_lock_or_busy(PackageManagerKind::Winget, lower)
}

fn classify_scoop(output: &str, lower: &str) -> Option<RecoveryPlan> {
    let packages = output
        .lines()
        .filter_map(parse_scoop_running_instance_line)
        .collect::<Vec<_>>();
    if !packages.is_empty() {
        return Some(RecoveryPlan::diagnose(
            PackageManagerKind::Scoop,
            vec![RecoveryCause::RunningProcess { packages }],
        ));
    }
    classify_lock_or_busy(PackageManagerKind::Scoop, lower)
}

fn classify_conservative_linux(kind: PackageManagerKind, lower: &str) -> Option<RecoveryPlan> {
    if lower.contains("could not get lock")
        || lower.contains("unable to acquire the dpkg frontend lock")
        || lower.contains("failed to synchronize cache")
        || lower.contains("failed to obtain lock")
        || lower.contains("waiting for process with pid")
        || lower.contains("db.lck")
        || lower.contains("database lock")
    {
        return Some(RecoveryPlan::retry_whole(
            kind,
            vec![RecoveryCause::LockOrBusy {
                summary: "package-manager lock is held by another process".to_string(),
            }],
        ));
    }
    if lower.contains("conflicting packages")
        || lower.contains("conflicts with")
        || lower.contains("unmet dependencies")
        || lower.contains("broken packages")
    {
        return Some(RecoveryPlan::diagnose(
            kind,
            vec![RecoveryCause::FileConflict { owners: Vec::new() }],
        ));
    }
    None
}

fn classify_unknown(lower: &str) -> Option<RecoveryPlan> {
    if lower.contains("lock") || lower.contains("resource busy") || lower.contains("file in use") {
        return Some(RecoveryPlan::diagnose(
            PackageManagerKind::Unknown,
            vec![RecoveryCause::LockOrBusy {
                summary: "command output suggests a busy file or held lock".to_string(),
            }],
        ));
    }
    None
}

fn classify_lock_or_busy(kind: PackageManagerKind, lower: &str) -> Option<RecoveryPlan> {
    if lower.contains("resource busy")
        || lower.contains("ebusy")
        || lower.contains("file in use")
        || lower.contains("used by another process")
        || lower.contains("could not get lock")
        || lower.contains("unable to lock database")
        || lower.contains("db.lck")
        || lower.contains("database lock")
    {
        return Some(RecoveryPlan::retry_whole(
            kind,
            vec![RecoveryCause::LockOrBusy {
                summary: "package-manager resource is busy or locked".to_string(),
            }],
        ));
    }
    None
}

fn collect_owned_by_packages(input: &str) -> Vec<String> {
    let mut owners = BTreeSet::new();
    let mut rest = input;
    let needle = "(owned by ";
    while let Some(start) = rest.find(needle) {
        let after = &rest[start + needle.len()..];
        let Some(end) = after.find(')') else {
            break;
        };
        let owner = after[..end].trim();
        if !owner.is_empty() {
            owners.insert(owner.to_string());
        }
        rest = &after[end + 1..];
    }
    owners.into_iter().collect()
}

fn collect_conflicting_packages(input: &str) -> Vec<String> {
    let mut packages = BTreeSet::new();
    for line in input.lines() {
        let trimmed = line.trim().trim_start_matches("::").trim();
        let Some((package_list, _)) = trimmed.split_once(" are in conflict") else {
            continue;
        };
        for package in package_list.split(" and ") {
            let name = strip_arch_version_suffix(package.trim());
            if !name.is_empty() {
                packages.insert(name.to_string());
            }
        }
    }
    packages.into_iter().collect()
}

fn collect_conflict_removal_pairs(input: &str) -> Vec<PackageConflictPair> {
    let mut seen = BTreeSet::new();
    let mut pairs = Vec::new();
    for line in input.lines() {
        let trimmed = line.trim().trim_start_matches("::").trim();
        let Some((package_list, question)) = trimmed.split_once(" are in conflict. Remove ") else {
            continue;
        };
        let Some(remove_prompt) = question.strip_suffix("? [y/N]") else {
            continue;
        };
        let Some((incoming_versioned, remove_versioned)) = package_list.split_once(" and ") else {
            continue;
        };
        let incoming = strip_arch_version_suffix(incoming_versioned.trim());
        let remove_from_pair = strip_arch_version_suffix(remove_versioned.trim());
        let remove = remove_prompt.trim();
        if incoming.is_empty() || remove.is_empty() || remove_from_pair != remove {
            continue;
        }
        if seen.insert((incoming.to_string(), remove.to_string())) {
            pairs.push(PackageConflictPair {
                incoming: incoming.to_string(),
                remove: remove.to_string(),
            });
        }
    }
    pairs
}

fn strip_arch_version_suffix(package: &str) -> &str {
    let mut parts = package.rsplitn(3, '-');
    let Some(release) = parts.next() else {
        return package;
    };
    let Some(version) = parts.next() else {
        return package;
    };
    let Some(name) = parts.next() else {
        return package;
    };
    if release.chars().next().is_some_and(|ch| ch.is_ascii_digit())
        && version
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric())
    {
        name
    } else {
        package
    }
}

fn parse_yay_error_making_package(input: &str) -> Option<String> {
    parse_yay_error_making_packages(input).into_iter().next()
}

fn parse_yay_error_making_packages(input: &str) -> Vec<String> {
    input
        .lines()
        .filter_map(parse_yay_error_making_package_line)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn parse_yay_error_making_package_line(line: &str) -> Option<String> {
    let rest = line.trim().strip_prefix("-> error making:")?.trim();
    let package = rest
        .split_once("-exit status")
        .or_else(|| rest.split_once(" - exit status"))
        .map(|(pkg, _)| pkg.trim())?;
    (!package.is_empty()).then_some(package.to_string())
}

fn collect_yay_source_drift_packages(input: &str) -> Vec<String> {
    let mut packages = BTreeSet::new();
    for line in input.lines() {
        let trimmed = line.trim();
        let source_path = trimmed
            .strip_prefix("-> error downloading sources:")
            .or_else(|| trimmed.strip_prefix("error downloading sources:"))
            .map(str::trim)
            .filter(|path| !path.is_empty());
        if let Some(source_path) = source_path {
            if let Some(package) = source_path
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty())
            {
                packages.insert(package.to_string());
            }
        }
    }
    for package in parse_yay_error_making_packages_near_source_failure(input) {
        packages.insert(package);
    }
    packages.into_iter().collect()
}

fn parse_yay_error_making_packages_near_source_failure(input: &str) -> Vec<String> {
    let lines = input.lines().collect::<Vec<_>>();
    let mut packages = BTreeSet::new();
    for (idx, line) in lines.iter().enumerate() {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("one or more files did not pass the validity check")
            && !lower.contains("error downloading sources:")
        {
            continue;
        }
        let end = usize::min(idx + 8, lines.len());
        for candidate in &lines[idx..end] {
            let lower = candidate.to_ascii_lowercase();
            if lower.contains("a failure occurred in build()")
                || lower.contains("error: problem encountered:")
                || lower.contains("meson.build")
                || lower.contains("ninja: build stopped")
            {
                break;
            }
            if let Some(package) = parse_yay_error_making_package_line(candidate) {
                packages.insert(package);
            }
        }
    }
    packages.into_iter().collect()
}

fn collect_yay_build_failure_packages(input: &str, source_packages: &[String]) -> Vec<String> {
    let source_packages = source_packages.iter().collect::<BTreeSet<_>>();
    let lines = input.lines().collect::<Vec<_>>();
    let mut packages = BTreeSet::new();
    for (idx, line) in lines.iter().enumerate() {
        let Some(package) = parse_yay_error_making_package_line(line) else {
            continue;
        };
        if source_packages.contains(&package) {
            continue;
        }
        let start = idx.saturating_sub(24);
        let context = lines[start..=idx].join("\n").to_ascii_lowercase();
        if context.contains("a failure occurred in build()")
            || context.contains("error: problem encountered:")
            || context.contains("meson.build")
            || context.contains("ninja: build stopped")
        {
            packages.insert(package);
        }
    }
    packages.into_iter().collect()
}

fn yay_build_failure_summary(input: &str, package: Option<&str>) -> String {
    let lines = input.lines().collect::<Vec<_>>();
    let mut fallback = None;
    for (idx, line) in lines.iter().enumerate() {
        if let Some(target) = package {
            if parse_yay_error_making_package_line(line).as_deref() != Some(target) {
                continue;
            }
        } else if parse_yay_error_making_package_line(line).is_none() {
            continue;
        }
        let start = idx.saturating_sub(24);
        for candidate in lines[start..=idx].iter().rev() {
            let trimmed = candidate.trim();
            let lower = trimmed.to_ascii_lowercase();
            if let Some((_, summary)) = trimmed.split_once("ERROR:") {
                let summary = summary.trim();
                if summary.contains("A failure occurred in build()") {
                    fallback = Some("AUR build() failed".to_string());
                    continue;
                }
                if !summary.is_empty() {
                    return summary.to_string();
                }
            }
            if lower.contains("a failure occurred in build()") {
                fallback = Some("AUR build() failed".to_string());
            }
        }
    }
    fallback.unwrap_or_else(|| "AUR package build failed".to_string())
}

fn parse_scoop_running_instance_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let prefix = "ERROR The following instances of \"";
    let suffix = "\" are still running. Close them and try again.";
    if !trimmed.starts_with(prefix) || !trimmed.ends_with(suffix) {
        return None;
    }
    let body = &trimmed[prefix.len()..trimmed.len() - suffix.len()];
    let body = body.trim();
    (!body.is_empty()).then_some(body.to_string())
}
