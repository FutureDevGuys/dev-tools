//! End-to-end convergence orchestration.
//!
//! Parsing, static authority checks, and every selected privileged plan happen
//! before authentication. Hooks remain an explicit trusted shell boundary;
//! reconcilers remain an exact structured protocol boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Error as AnyError;
use thiserror::Error;

use crate::cli::{Cli, ManagedPathPolicy as CliManagedPathPolicy, SyncMode};
use crate::filesystem::{
    apply_source_permissions, converge_entry, expand_entries, ConvergeOptions, EntryStatus,
    ExpansionOptions, ManagedPathPolicy,
};
use crate::hooks::{
    EntryConvergence, HookDecision, HookPlan, HookRunMode, HookShell, HookState, PostHookDecision,
};
use crate::interrupt::Interrupted;
use crate::manifest::{
    check_state_preconditions, collect_profile_names, deduplicate_and_validate_targets,
    load_manifest, load_profile_map, select_entries_for_profiles, select_reconcilers_for_profiles,
    CommentedTargetPolicy, Entry, LoadOptions, Manifest, ManifestError, Mode, Privilege,
    Reconciler, ReconcilerScope, ScriptFailurePolicy,
};
use crate::overlay::json::{overlay_json_file, JsonOverlayOptions};
use crate::overlay::toml::{
    overlay_toml_file, CommentedTargetPolicy as OverlayCommentedTargetPolicy,
    ExclusiveSiblingGroup as OverlayExclusiveSiblingGroup, TomlConflictPolicy, TomlOverlayOptions,
};
use crate::paths::{
    canonical_target_key, is_absolute_for, resolve_config_path, PathContext, PathError,
    PathPlatform,
};
use crate::privilege::{discover_trusted_sudo, PrivilegeError, PrivilegeSession};
use crate::privileged_target::{
    apply_privileged_plans, plan_selected_privileged_entries, revalidate_privileged_plans,
    PrivilegedCommands, PrivilegedCopyPlan, PrivilegedTargetError, PrivilegedTargetOutcome,
    SystemIdentityResolver,
};
use crate::reconciler::{
    resolve_executable as resolve_reconciler_executable, ReconcilerError, ReconcilerPrivilege,
    ReconcilerRunner, ReconcilerSpec,
};
use crate::report::{ReconcilerSummary, Record, Report, Status};
use crate::scaffold::{initialize, render_examples, ScaffoldError, ScaffoldPaths};

const RECONCILER_TIMEOUT: Duration = Duration::from_secs(120);
const RECONCILER_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;

/// Expose the fixed production timeout to contract tests without making it
/// caller-configurable.
#[cfg(any(debug_assertions, feature = "test-support"))]
#[doc(hidden)]
pub const fn reconciler_timeout_for_test() -> Duration {
    RECONCILER_TIMEOUT
}

#[derive(Debug)]
pub enum RunOutput {
    Convergence(Report),
    Validation(Report),
    Profiles(Vec<String>),
    Examples(String),
    Initialized(ScaffoldPaths),
}

impl RunOutput {
    pub fn report(&self) -> Option<&Report> {
        match self {
            Self::Convergence(report) | Self::Validation(report) => Some(report),
            Self::Profiles(_) | Self::Examples(_) | Self::Initialized(_) => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error(transparent)]
    Interrupted(#[from] Interrupted),
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Filesystem(#[from] crate::filesystem::FilesystemError),
    #[error(transparent)]
    Hook(#[from] crate::hooks::HookError),
    #[error(transparent)]
    Privilege(#[from] PrivilegeError),
    #[error(transparent)]
    PrivilegedTarget(#[from] PrivilegedTargetError),
    #[error(transparent)]
    Reconciler(#[from] ReconcilerError),
    #[error(transparent)]
    Scaffold(#[from] ScaffoldError),
    #[error("structured overlay failed: {0}")]
    Overlay(#[source] AnyError),
    #[error("--profile-map and --host-profile must be used together")]
    IncompleteProfileMap,
    #[error("the platform configuration directory is unavailable")]
    MissingConfigHome,
    #[error("the platform state directory is unavailable")]
    MissingStateHome,
    #[error("sudo is unavailable or unsafe")]
    MissingSudo,
    #[error("another sync-configs convergence is already running")]
    Busy,
    #[error("cannot acquire the convergence lock")]
    Lock(#[source] AnyError),
}

impl EngineError {
    pub const fn is_interrupted(&self) -> bool {
        matches!(
            self,
            Self::Interrupted(_)
                | Self::Hook(crate::hooks::HookError::Interrupted)
                | Self::Hook(crate::hooks::HookError::Privilege(
                    PrivilegeError::Interrupted,
                ))
                | Self::Privilege(PrivilegeError::Interrupted)
                | Self::PrivilegedTarget(PrivilegedTargetError::PrivilegedCommand {
                    source: PrivilegeError::Interrupted,
                    ..
                })
                | Self::Reconciler(ReconcilerError::Interrupted)
        )
    }
}

struct LoadedRequest {
    manifest: Manifest,
    profiles: Vec<String>,
    path_context: PathContext,
}

struct SelectedReconciler {
    manifest: Reconciler,
    spec: ReconcilerSpec,
}

pub fn execute(cli: &Cli) -> Result<RunOutput, EngineError> {
    let mut profiles = normalized_profiles(&cli.profile);
    execute_observed(cli, &mut profiles)
}

/// Execute one request while returning the exact profile selection observed by
/// the engine. The CLI uses this to keep machine output bound to the same
/// profile-map read that governed convergence.
pub fn execute_observed(
    cli: &Cli,
    observed_profiles: &mut Vec<String>,
) -> Result<RunOutput, EngineError> {
    execute_observed_with_run_id(cli, observed_profiles, None)
}

pub(crate) fn execute_observed_with_run_id(
    cli: &Cli,
    observed_profiles: &mut Vec<String>,
    run_id: Option<&str>,
) -> Result<RunOutput, EngineError> {
    if cli.print_example {
        if let Ok(path_context) = PathContext::from_current_environment() {
            if let Ok(profiles) = resolve_profiles(cli, &path_context) {
                *observed_profiles = profiles;
            }
        }
        return Ok(RunOutput::Examples(render_examples()));
    }

    let path_context = PathContext::from_current_environment()?;
    let config = config_path(cli, &path_context)?;
    if cli.init {
        if let Ok(profiles) = resolve_profiles(cli, &path_context) {
            *observed_profiles = profiles;
        }
        return Ok(RunOutput::Initialized(initialize(&config, cli.force_init)?));
    }

    let loaded = load_request(cli, path_context, config)?;
    *observed_profiles = loaded.profiles.clone();
    if cli.list_profiles {
        return Ok(RunOutput::Profiles(collect_profile_names(&loaded.manifest)));
    }
    if cli.validate {
        return validate_request(cli, &loaded).map(RunOutput::Validation);
    }

    converge(cli, loaded, run_id).map(RunOutput::Convergence)
}

fn validate_request(cli: &Cli, loaded: &LoadedRequest) -> Result<Report, EngineError> {
    crate::interrupt::check()?;
    check_state_preconditions(&loaded.manifest)?;
    let selected_entries = select_entries_for_profiles(&loaded.manifest.entries, &loaded.profiles)
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let selected_reconcilers =
        select_reconcilers_for_profiles(&loaded.manifest.reconcilers, &loaded.profiles);
    let config_dir = loaded
        .manifest
        .path
        .parent()
        .unwrap_or_else(|| Path::new("/"));

    // Validation exercises every selected authority boundary, but HookRunMode::Validate
    // guarantees that no hook is executed and no sudo session is requested.
    let hooks = HookPlan::prepare(
        selected_entries.iter(),
        config_dir,
        HookShell::current()?,
        HookRunMode::Validate,
    )?;
    hooks.validate_privileged_authority()?;
    let privileged_targets_selected = selected_entries
        .iter()
        .any(|entry| entry.target_privilege == Privilege::Sudo);
    if privileged_targets_selected {
        let identities = SystemIdentityResolver::resolve()?;
        let _plans = plan_selected_privileged_entries(
            &selected_entries,
            cli.managed_path_policy == CliManagedPathPolicy::Takeover,
            &identities,
        )?;
        let _commands = PrivilegedCommands::resolve()?;
    }
    let runner = ReconcilerRunner {
        environment: reconciler_environment(&loaded.profiles),
        sudo_path: None,
        timeout: RECONCILER_TIMEOUT,
        output_limit: RECONCILER_OUTPUT_LIMIT,
    };
    let privileged_reconciler_selected = selected_reconcilers
        .iter()
        .any(|reconciler| reconciler.privilege == Privilege::Sudo);
    for reconciler in selected_reconcilers {
        let spec = ReconcilerSpec {
            name: reconciler.name.clone(),
            executable: resolve_reconciler_executable(&reconciler.executable)?,
            source: reconciler.source.clone(),
            privilege: match reconciler.privilege {
                Privilege::User => ReconcilerPrivilege::User,
                Privilege::Sudo => ReconcilerPrivilege::Sudo,
            },
            protocol: reconciler.protocol.clone(),
        };
        runner.validate(&spec)?;
    }
    if hooks.declares_privilege() || privileged_targets_selected || privileged_reconciler_selected {
        let _session = PrivilegeSession::new(resolve_sudo().ok_or(EngineError::MissingSudo)?)?;
    }

    let expansion_options = ExpansionOptions {
        prefer_source_overrides: !cli.no_source_overrides,
        environment: loaded.path_context.environment.clone(),
        home: loaded.path_context.home.clone(),
    };
    let mut expanded = Vec::new();
    for entry in &selected_entries {
        expanded.extend(expand_entries(
            std::slice::from_ref(entry),
            &expansion_options,
        )?);
    }
    let _deduplicated =
        deduplicate_and_validate_targets(expanded, &loaded.path_context, &loaded.manifest.path)?;
    crate::interrupt::check()?;

    Ok(Report {
        profiles: loaded.profiles.clone(),
        ..Report::default()
    })
}

fn load_request(
    cli: &Cli,
    path_context: PathContext,
    config: PathBuf,
) -> Result<LoadedRequest, EngineError> {
    let mut options = LoadOptions::default().with_path_context(path_context.clone());
    options.mode_override = cli.mode.map(mode_from_cli);
    options.prefer_source_overrides = !cli.no_source_overrides;
    let manifest = load_manifest(&config, &options)?;
    let profiles = resolve_profiles(cli, &path_context)?;

    Ok(LoadedRequest {
        manifest,
        profiles,
        path_context,
    })
}

fn converge(cli: &Cli, loaded: LoadedRequest, run_id: Option<&str>) -> Result<Report, EngineError> {
    crate::interrupt::check()?;
    check_state_preconditions(&loaded.manifest)?;

    let selected_entries = select_entries_for_profiles(&loaded.manifest.entries, &loaded.profiles)
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let selected_reconcilers =
        select_reconcilers_for_profiles(&loaded.manifest.reconcilers, &loaded.profiles)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();

    let config_dir = loaded
        .manifest
        .path
        .parent()
        .unwrap_or_else(|| Path::new("/"));
    let hook_mode = if cli.dry_run {
        HookRunMode::DryRun
    } else {
        HookRunMode::Apply
    };
    let hooks = HookPlan::prepare(
        selected_entries.iter(),
        config_dir,
        HookShell::current()?,
        hook_mode,
    )?
    .with_context(crate::hooks::HookContext::new(
        loaded.manifest.path.clone(),
        &loaded.profiles,
        run_id,
        loaded.path_context.clone(),
    ));
    hooks.validate_privileged_authority()?;

    // Privileged entry planning resolves identities and snapshots every target
    // before either authentication or hook execution.
    let identities = if selected_entries
        .iter()
        .any(|entry| entry.target_privilege == Privilege::Sudo)
    {
        Some(SystemIdentityResolver::resolve()?)
    } else {
        None
    };
    let privileged_plans = if let Some(identities) = identities.as_ref() {
        plan_selected_privileged_entries(
            &selected_entries,
            cli.managed_path_policy == CliManagedPathPolicy::Takeover,
            identities,
        )?
    } else {
        Vec::new()
    };

    let mut runner = ReconcilerRunner {
        environment: reconciler_environment(&loaded.profiles),
        sudo_path: None,
        timeout: RECONCILER_TIMEOUT,
        output_limit: RECONCILER_OUTPUT_LIMIT,
    };
    let reconciler_specs = selected_reconcilers
        .into_iter()
        .map(|manifest| {
            let spec = ReconcilerSpec {
                name: manifest.name.clone(),
                executable: resolve_reconciler_executable(&manifest.executable)?,
                source: manifest.source.clone(),
                privilege: match manifest.privilege {
                    Privilege::User => ReconcilerPrivilege::User,
                    Privilege::Sudo => ReconcilerPrivilege::Sudo,
                },
                protocol: manifest.protocol.clone(),
            };
            runner.validate(&spec)?;
            Ok(SelectedReconciler { manifest, spec })
        })
        .collect::<Result<Vec<_>, ReconcilerError>>()?;

    // Validate every currently observable source boundary before any lock,
    // authentication, or trusted hook side effect. Duplicate targets can be
    // rejected here only when every involved entry is guaranteed to remain
    // eligible: a failed pre-hook with `abort` or `skip` intentionally removes
    // its entry before Python 0.1.13's target-deduplication boundary. The full
    // active graph is expanded and validated again after pre-hooks.
    let preflight_expansion_options = ExpansionOptions {
        prefer_source_overrides: !cli.no_source_overrides,
        environment: loaded.path_context.environment.clone(),
        home: loaded.path_context.home.clone(),
    };
    let mut preflight_expanded = Vec::new();
    for entry in &selected_entries {
        let expanded = expand_entries(std::slice::from_ref(entry), &preflight_expansion_options)?;
        if entry.pre_script.is_none() || entry.pre_script_on_fail == ScriptFailurePolicy::Continue {
            preflight_expanded.extend(expanded);
        }
    }
    let _preflight_targets = deduplicate_and_validate_targets(
        preflight_expanded,
        &loaded.path_context,
        &loaded.manifest.path,
    )?;
    crate::interrupt::check()?;

    // Serialize the complete mutating phase, including trusted hooks and
    // reconcilers. Validation and dry-run remain strictly read-only and never
    // create lock metadata.
    let _convergence_lock = if cli.dry_run {
        None
    } else {
        let path = state_root(&loaded.path_context)?.join("convergence.lock");
        match dev_tools_installation::InstallationLock::try_acquire(&path)
            .map_err(EngineError::Lock)?
        {
            Some(lock) => Some(lock),
            None => return Err(EngineError::Busy),
        }
    };
    crate::interrupt::check()?;

    let privileged_reconciler = reconciler_specs
        .iter()
        .any(|reconciler| reconciler.manifest.privilege == Privilege::Sudo);
    // Only a privileged pre-hook needs authentication before pre-hook
    // execution. Privileged targets, reconcilers, and post-hooks authenticate
    // at their later protocol boundaries after all available preflight.
    let mut session = if !cli.dry_run && hooks.requires_pre_privilege() {
        let mut session = PrivilegeSession::new(resolve_sudo().ok_or(EngineError::MissingSudo)?)?;
        hooks.authenticate(&mut session)?;
        Some(session)
    } else {
        None
    };
    crate::interrupt::check()?;

    let mut report = Report {
        dry_run: cli.dry_run,
        profiles: loaded.profiles.clone(),
        ..Report::default()
    };
    let mut eligible = vec![true; selected_entries.len()];
    let pre_records = hooks.run_pre_hooks(session.as_ref())?;
    crate::interrupt::check()?;
    for pre in pre_records {
        let Some(index) = selected_entries
            .iter()
            .position(|entry| std::ptr::eq(entry, pre.entry))
        else {
            continue;
        };
        let Some(execution) = pre.execution else {
            continue;
        };
        let status = execution.status();
        let record_status = match (pre.decision, status.state) {
            (HookDecision::Abort, _) => {
                eligible[index] = false;
                Status::ScriptError
            }
            (HookDecision::Skip, _) => {
                eligible[index] = false;
                Status::ScriptSkipped
            }
            (_, HookState::FailedContinue) => Status::Info,
            (_, HookState::Planned) => Status::Info,
            (_, HookState::Succeeded) => Status::Performed,
            (_, HookState::FailedAbort | HookState::FailedSkip) => Status::ScriptError,
        };
        report.records.push(Record {
            status: record_status,
            scope: pre.entry.scope_label(),
            name: pre.entry.name.clone(),
            message: hook_message("pre_script", status.state, status.exit_code),
            output: combined_hook_output(&execution),
        });
    }

    let expansion_options = ExpansionOptions {
        prefer_source_overrides: !cli.no_source_overrides,
        environment: loaded.path_context.environment.clone(),
        home: loaded.path_context.home.clone(),
    };
    let mut expanded_with_origin = Vec::new();
    let mut origin_convergence = vec![None; selected_entries.len()];
    for (index, entry) in selected_entries.iter().enumerate() {
        crate::interrupt::check()?;
        if !eligible[index] {
            origin_convergence[index] = Some(EntryConvergence::Failed);
            continue;
        }
        match expand_entries(std::slice::from_ref(entry), &expansion_options) {
            Ok(expanded) if expanded.is_empty() => {
                origin_convergence[index] = Some(EntryConvergence::Skipped);
            }
            Ok(expanded) => {
                expanded_with_origin.extend(expanded.into_iter().map(|entry| (entry, index)));
            }
            Err(error) => {
                origin_convergence[index] = Some(EntryConvergence::Failed);
                report.records.push(error_record(entry, &error));
            }
        }
    }

    let mut origin_by_target: BTreeMap<PathBuf, Vec<usize>> = BTreeMap::new();
    for (entry, origin) in &expanded_with_origin {
        let origins = origin_by_target
            .entry(canonical_target_key(&entry.target, &loaded.path_context))
            .or_default();
        if !origins.contains(origin) {
            origins.push(*origin);
        }
    }
    let expanded = deduplicate_and_validate_targets(
        expanded_with_origin
            .into_iter()
            .map(|(entry, _)| entry)
            .collect(),
        &loaded.path_context,
        &loaded.manifest.path,
    )?;
    crate::interrupt::check()?;

    let active_targets = expanded
        .iter()
        .map(|entry| canonical_target_key(&entry.target, &loaded.path_context))
        .collect::<BTreeSet<_>>();
    let mut active_privileged_by_target = BTreeMap::new();
    let privileged_origins = selected_entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.target_privilege == Privilege::Sudo)
        .map(|(index, _)| index);
    for (plan, origin) in privileged_plans.into_iter().zip(privileged_origins) {
        let key = canonical_target_key(&plan.entry.target, &loaded.path_context);
        if eligible[origin] && active_targets.contains(&key) {
            active_privileged_by_target.entry(key).or_insert(plan);
        }
    }
    let active_privileged_plans = active_privileged_by_target
        .into_values()
        .collect::<Vec<_>>();
    let active_privileged_plans = if active_privileged_plans.is_empty() {
        Vec::new()
    } else {
        let identities = identities
            .as_ref()
            .ok_or(PrivilegedTargetError::Unsupported)?;
        // Revalidate the complete active batch after pre-hooks and expansion.
        // No target, helper, or sudo mutation may precede this all-target gate.
        revalidate_privileged_plans(&active_privileged_plans, identities)?
    };
    let privileged_target_mutation = active_privileged_plans
        .iter()
        .any(PrivilegedCopyPlan::needs_mutation);
    let privileged_commands = if !cli.dry_run && privileged_target_mutation {
        // Resolve every fixed privileged helper before asking the user to
        // authenticate. A missing/unsafe command must remain mutation-free.
        Some(PrivilegedCommands::resolve()?)
    } else {
        None
    };
    crate::interrupt::check()?;
    if !cli.dry_run && (privileged_target_mutation || privileged_reconciler) {
        if session.is_none() {
            session = Some(PrivilegeSession::new(
                resolve_sudo().ok_or(EngineError::MissingSudo)?,
            )?);
        }
        let active_session = session.as_mut().ok_or(EngineError::MissingSudo)?;
        active_session.ensure_authenticated()?;
        if privileged_reconciler {
            runner.sudo_path = Some(active_session.sudo_path().to_path_buf());
        }
    }
    crate::interrupt::check()?;
    let privileged_by_target = active_privileged_plans
        .into_iter()
        .map(|plan| {
            (
                canonical_target_key(&plan.entry.target, &loaded.path_context),
                plan,
            )
        })
        .collect::<BTreeMap<_, _>>();

    let backup_root = backup_root(&loaded.path_context)?;
    for entry in &expanded {
        crate::interrupt::check()?;
        let key = canonical_target_key(&entry.target, &loaded.path_context);
        let origins = origin_by_target.get(&key);
        let outcome = if let Some(plan) = privileged_by_target.get(&key) {
            let Some(identities) = identities.as_ref() else {
                report.records.push(error_record(
                    entry,
                    &"privileged target identity resolver is unavailable",
                ));
                if let Some(origins) = origins {
                    for origin in origins {
                        merge_convergence(
                            &mut origin_convergence[*origin],
                            EntryConvergence::Failed,
                        );
                    }
                }
                continue;
            };
            match apply_privileged_plans(
                std::slice::from_ref(plan),
                cli.dry_run,
                identities,
                session.as_mut(),
                privileged_commands.as_ref(),
            ) {
                Ok(outcomes) => {
                    let outcome = outcomes
                        .into_iter()
                        .next()
                        .unwrap_or(PrivilegedTargetOutcome::UpToDate);
                    record_privileged(entry, outcome, &mut report);
                    convergence_from_privileged(outcome)
                }
                Err(error) => {
                    crate::interrupt::check()?;
                    report.records.push(error_record(entry, &error));
                    EntryConvergence::Failed
                }
            }
        } else {
            converge_unprivileged(cli, entry, &backup_root, &loaded.path_context, &mut report)
        };
        if let Some(origins) = origins {
            for origin in origins {
                merge_convergence(&mut origin_convergence[*origin], outcome);
            }
        }
        crate::interrupt::check()?;
    }

    for reconciler in &reconciler_specs {
        crate::interrupt::check()?;
        if cli.dry_run && reconciler.manifest.privilege == Privilege::Sudo {
            let summary = reconciler_summary(
                &reconciler.manifest,
                false,
                false,
                true,
                Vec::new(),
                "privilege_required".to_owned(),
                vec!["dry_run_no_auth".to_owned()],
            );
            report.records.push(Record {
                status: Status::Deferred,
                scope: reconciler.manifest.scope_label(),
                name: reconciler.manifest.name.clone(),
                message: "reconciler deferred because dry-run cannot authenticate".to_owned(),
                output: None,
            });
            report.reconcilers.push(summary);
            continue;
        }
        match runner.run(&reconciler.spec, cli.dry_run) {
            Ok(result) => {
                let status = if !result.input_required.is_empty() {
                    Status::InputRequired
                } else if result.deferred {
                    Status::Deferred
                } else if result.changed {
                    Status::Performed
                } else if result.verified {
                    Status::UpToDate
                } else {
                    Status::Deferred
                };
                report.records.push(Record {
                    status,
                    scope: reconciler.manifest.scope_label(),
                    name: reconciler.manifest.name.clone(),
                    message: format!("reconciler next={}", result.next_action),
                    output: None,
                });
                report.reconcilers.push(reconciler_summary(
                    &reconciler.manifest,
                    result.changed,
                    result.verified,
                    result.deferred,
                    result.input_required,
                    result.next_action,
                    result.diagnostics,
                ));
            }
            Err(ReconcilerError::Interrupted) => return Err(Interrupted.into()),
            Err(error) => report.records.push(Record {
                status: Status::Errors,
                scope: reconciler.manifest.scope_label(),
                name: reconciler.manifest.name.clone(),
                message: error.to_string(),
                output: None,
            }),
        }
        crate::interrupt::check()?;
    }

    let post_convergence = |entry: &Entry| {
        selected_entries
            .iter()
            .position(|candidate| std::ptr::eq(candidate, entry))
            .and_then(|index| origin_convergence[index])
            .unwrap_or(EntryConvergence::Skipped)
    };
    if !cli.dry_run && hooks.requires_eligible_post_privilege(post_convergence) {
        if session.is_none() {
            session = Some(PrivilegeSession::new(
                resolve_sudo().ok_or(EngineError::MissingSudo)?,
            )?);
        }
        hooks.authenticate(session.as_mut().ok_or(EngineError::MissingSudo)?)?;
    }
    crate::interrupt::check()?;
    let post_records = hooks.run_post_hooks(session.as_ref(), post_convergence)?;
    crate::interrupt::check()?;
    for post in post_records {
        let state = post.execution.status().state;
        let record_status = match (post.decision, state) {
            (PostHookDecision::Abort, _) => Status::ScriptError,
            (_, HookState::FailedAbort) => Status::ScriptError,
            (_, HookState::FailedSkip | HookState::FailedContinue | HookState::Planned) => {
                Status::Info
            }
            (_, HookState::Succeeded) => Status::Performed,
        };
        report.records.push(Record {
            status: record_status,
            scope: post.entry.scope_label(),
            name: post.entry.name.clone(),
            message: hook_message("post_script", state, post.execution.status().exit_code),
            output: combined_hook_output(&post.execution),
        });
    }

    Ok(report)
}

fn converge_unprivileged(
    cli: &Cli,
    entry: &Entry,
    backup_root: &Path,
    path_context: &PathContext,
    report: &mut Report,
) -> EntryConvergence {
    let result = match entry.mode {
        Mode::Symlink | Mode::Copy => {
            let previous_sources = Vec::new();
            let skeleton = skeleton_for(entry, path_context);
            converge_entry(
                entry,
                &ConvergeOptions {
                    dry_run: cli.dry_run,
                    managed_path_policy: managed_path_policy(cli.managed_path_policy),
                    backup_root,
                    previous_sources: &previous_sources,
                    skeleton: skeleton.as_deref(),
                    max_backup_candidates: 64,
                },
            )
            .map(|outcome| {
                let status = match outcome.status {
                    EntryStatus::Changed | EntryStatus::WouldChange => Status::Performed,
                    EntryStatus::UpToDate => Status::UpToDate,
                    EntryStatus::MissingSource => Status::MissingSource,
                    EntryStatus::SkippedExisting => Status::SkippedExisting,
                };
                report.records.push(Record {
                    status,
                    scope: entry.scope_label(),
                    name: entry.name.clone(),
                    message: filesystem_message(outcome.status, cli.dry_run),
                    output: None,
                });
                match outcome.status {
                    EntryStatus::Changed | EntryStatus::WouldChange => EntryConvergence::Changed,
                    EntryStatus::UpToDate => EntryConvergence::UpToDate,
                    EntryStatus::MissingSource => EntryConvergence::MissingSource,
                    EntryStatus::SkippedExisting => EntryConvergence::Skipped,
                }
            })
            .map_err(AnyError::from)
        }
        Mode::JsonOverlay => converge_json_overlay(cli, entry, report),
        Mode::TomlOverlay => converge_toml_overlay(cli, entry, report),
    };
    match result {
        Ok(outcome) => outcome,
        Err(error) => {
            report.records.push(error_record(entry, &error));
            EntryConvergence::Failed
        }
    }
}

fn converge_json_overlay(
    cli: &Cli,
    entry: &Entry,
    report: &mut Report,
) -> Result<EntryConvergence, AnyError> {
    if !entry.source.try_exists()? {
        report.records.push(Record {
            status: Status::MissingSource,
            scope: entry.scope_label(),
            name: entry.name.clone(),
            message: "source is absent".to_owned(),
            output: None,
        });
        return Ok(EntryConvergence::MissingSource);
    }
    let source_permissions_changed = apply_source_permissions(entry, cli.dry_run)?;
    let result = overlay_json_file(
        &entry.source,
        &entry.target,
        &JsonOverlayOptions {
            dry_run: cli.dry_run,
            replace_json_pointers: Vec::new(),
            reconcile_removed_keys: entry.reconcile_removed_keys,
            managed_overlay_id: entry.managed_overlay_id.clone(),
            state_root: None,
        },
    )?;
    let changed = result.changed || source_permissions_changed;
    report.records.push(Record {
        status: if changed {
            Status::Performed
        } else {
            Status::UpToDate
        },
        scope: entry.scope_label(),
        name: entry.name.clone(),
        message: if changed {
            if cli.dry_run {
                "would overlay JSON".to_owned()
            } else {
                "overlaid JSON".to_owned()
            }
        } else {
            "JSON overlay already up to date".to_owned()
        },
        output: None,
    });
    Ok(if changed {
        EntryConvergence::Changed
    } else {
        EntryConvergence::UpToDate
    })
}

fn converge_toml_overlay(
    cli: &Cli,
    entry: &Entry,
    report: &mut Report,
) -> Result<EntryConvergence, AnyError> {
    if !entry.source.try_exists()? {
        report.records.push(Record {
            status: Status::MissingSource,
            scope: entry.scope_label(),
            name: entry.name.clone(),
            message: "source is absent".to_owned(),
            output: None,
        });
        return Ok(EntryConvergence::MissingSource);
    }
    let source_permissions_changed = apply_source_permissions(entry, cli.dry_run)?;
    let options = TomlOverlayOptions {
        dry_run: cli.dry_run,
        conflict_policy: TomlConflictPolicy::Source,
        preserve_target_layout: true,
        reconcile_removed_keys: entry.reconcile_removed_keys,
        managed_overlay_id: entry.managed_overlay_id.clone(),
        state_root: None,
        commented_target_policy: match entry.commented_target_policy {
            CommentedTargetPolicy::Respect => OverlayCommentedTargetPolicy::Respect,
            CommentedTargetPolicy::Activate => OverlayCommentedTargetPolicy::Activate,
            CommentedTargetPolicy::Error => OverlayCommentedTargetPolicy::Error,
        },
        exclusive_sibling_groups: entry
            .exclusive_sibling_groups
            .iter()
            .map(|group| OverlayExclusiveSiblingGroup {
                parent_pattern: group.under.clone(),
                keys: group.keys.clone(),
            })
            .collect(),
    };
    let result = overlay_toml_file(&entry.source, &entry.target, &options)?;
    for path in &result.suppressed {
        report.records.push(Record {
            status: Status::SuppressedComment,
            scope: entry.scope_label(),
            name: entry.name.clone(),
            message: format!(
                "kept commented TOML path {} inactive",
                crate::overlay::toml::render_toml_key_path(path)
            ),
            output: None,
        });
    }
    let changed = result.changed || source_permissions_changed;
    report.records.push(Record {
        status: if changed {
            Status::Performed
        } else {
            Status::UpToDate
        },
        scope: entry.scope_label(),
        name: entry.name.clone(),
        message: if changed {
            if cli.dry_run {
                "would overlay TOML".to_owned()
            } else {
                "overlaid TOML".to_owned()
            }
        } else {
            "TOML overlay already up to date".to_owned()
        },
        output: None,
    });
    Ok(if changed {
        EntryConvergence::Changed
    } else {
        EntryConvergence::UpToDate
    })
}

fn record_privileged(entry: &Entry, outcome: PrivilegedTargetOutcome, report: &mut Report) {
    let (status, message) = match outcome {
        PrivilegedTargetOutcome::Changed => (Status::Performed, "installed privileged file"),
        PrivilegedTargetOutcome::WouldChange => {
            (Status::Performed, "would install privileged file")
        }
        PrivilegedTargetOutcome::UpToDate => {
            (Status::UpToDate, "privileged file already up to date")
        }
        PrivilegedTargetOutcome::SkippedExisting => (
            Status::SkippedExisting,
            "existing privileged target is unmanaged",
        ),
    };
    report.records.push(Record {
        status,
        scope: entry.scope_label(),
        name: entry.name.clone(),
        message: message.to_owned(),
        output: None,
    });
}

fn convergence_from_privileged(outcome: PrivilegedTargetOutcome) -> EntryConvergence {
    match outcome {
        PrivilegedTargetOutcome::Changed | PrivilegedTargetOutcome::WouldChange => {
            EntryConvergence::Changed
        }
        PrivilegedTargetOutcome::UpToDate => EntryConvergence::UpToDate,
        PrivilegedTargetOutcome::SkippedExisting => EntryConvergence::Skipped,
    }
}

fn merge_convergence(slot: &mut Option<EntryConvergence>, next: EntryConvergence) {
    let rank = |value| match value {
        EntryConvergence::UpToDate => 0,
        EntryConvergence::Changed => 1,
        EntryConvergence::Skipped => 2,
        EntryConvergence::MissingSource => 3,
        EntryConvergence::Failed => 4,
    };
    if slot.is_none_or(|current| rank(next) > rank(current)) {
        *slot = Some(next);
    }
}

fn reconciler_summary(
    reconciler: &Reconciler,
    changed: bool,
    verified: bool,
    deferred: bool,
    input_required: Vec<String>,
    next_action: String,
    diagnostics: Vec<String>,
) -> ReconcilerSummary {
    ReconcilerSummary {
        schema: crate::report::RECONCILER_RESULT_SCHEMA,
        name: reconciler.name.clone(),
        group: reconciler.group.clone(),
        subgroup: reconciler.subgroup.clone(),
        scope: match reconciler.scope {
            ReconcilerScope::User => "user",
            ReconcilerScope::System => "system",
        }
        .to_owned(),
        changed,
        verified,
        deferred,
        input_required,
        next_action,
        diagnostics,
    }
}

pub fn fallback_profiles_for_output(cli: &Cli) -> Vec<String> {
    normalized_profiles(&cli.profile)
}

fn resolve_profiles(cli: &Cli, path_context: &PathContext) -> Result<Vec<String>, EngineError> {
    if cli.profile_map.is_some() != cli.host_profile.is_some() {
        return Err(EngineError::IncompleteProfileMap);
    }

    let mut profiles = Vec::new();
    let mut seen = BTreeSet::new();
    if let (Some(profile_map), Some(host_profile)) = (&cli.profile_map, &cli.host_profile) {
        for profile in load_profile_map(
            profile_map,
            host_profile,
            cli.profile_map_field.as_deref(),
            path_context,
        )? {
            if seen.insert(profile.clone()) {
                profiles.push(profile);
            }
        }
    }
    for profile in normalized_profiles(&cli.profile) {
        if seen.insert(profile.clone()) {
            profiles.push(profile);
        }
    }
    Ok(profiles)
}

fn normalized_profiles(profiles: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    for profile in profiles {
        let profile = profile.trim();
        if !profile.is_empty() && !result.iter().any(|existing| existing == profile) {
            result.push(profile.to_owned());
        }
    }
    result
}

fn filesystem_message(status: EntryStatus, dry_run: bool) -> String {
    match status {
        EntryStatus::Changed => "converged filesystem target",
        EntryStatus::WouldChange if dry_run => "would converge filesystem target",
        EntryStatus::WouldChange => "converged filesystem target",
        EntryStatus::UpToDate => "already up to date",
        EntryStatus::MissingSource => "source is absent",
        EntryStatus::SkippedExisting => "existing target is unmanaged",
    }
    .to_owned()
}

fn hook_message(phase: &str, state: HookState, exit_code: Option<i32>) -> String {
    match state {
        HookState::Planned => format!("{phase} planned"),
        HookState::Succeeded => format!("{phase} completed"),
        HookState::FailedAbort => format!(
            "{phase} failed (exit {}, on_fail=abort)",
            exit_code.unwrap_or(-1)
        ),
        HookState::FailedSkip => format!(
            "{phase} failed (exit {}, on_fail=skip)",
            exit_code.unwrap_or(-1)
        ),
        HookState::FailedContinue => format!(
            "{phase} failed (exit {}, on_fail=continue)",
            exit_code.unwrap_or(-1)
        ),
    }
}

fn combined_hook_output(execution: &crate::hooks::HookExecution) -> Option<String> {
    if execution.stdout().is_empty() && execution.stderr().is_empty() {
        return None;
    }
    let mut output = Vec::with_capacity(execution.stdout().len() + execution.stderr().len());
    output.extend_from_slice(execution.stdout());
    output.extend_from_slice(execution.stderr());
    let output = String::from_utf8_lossy(&output).trim().to_owned();
    (!output.is_empty()).then_some(output)
}

fn error_record(entry: &Entry, error: &dyn std::fmt::Display) -> Record {
    Record {
        status: Status::Errors,
        scope: entry.scope_label(),
        name: entry.name.clone(),
        message: error.to_string(),
        output: None,
    }
}

fn mode_from_cli(mode: SyncMode) -> Mode {
    match mode {
        SyncMode::Symlink => Mode::Symlink,
        SyncMode::Copy => Mode::Copy,
        SyncMode::JsonOverlay => Mode::JsonOverlay,
        SyncMode::TomlOverlay => Mode::TomlOverlay,
    }
}

fn managed_path_policy(policy: CliManagedPathPolicy) -> ManagedPathPolicy {
    match policy {
        CliManagedPathPolicy::Safe => ManagedPathPolicy::Safe,
        CliManagedPathPolicy::Strict => ManagedPathPolicy::Strict,
        CliManagedPathPolicy::Takeover => ManagedPathPolicy::Takeover,
    }
}

fn config_path(cli: &Cli, context: &PathContext) -> Result<PathBuf, EngineError> {
    if let Some(path) = &cli.config {
        if let Some(raw) = path.to_str() {
            return Ok(resolve_config_path(raw, context)?);
        }
        return Ok(if path.is_absolute() {
            path.clone()
        } else {
            context.cwd.join(path)
        });
    }
    let base = match context.platform {
        PathPlatform::Windows => absolute_environment_path(context, "APPDATA")
            .or_else(|| absolute_home(context).map(|home| home.join("AppData/Roaming")))
            .ok_or(EngineError::MissingConfigHome)?,
        PathPlatform::Posix => absolute_environment_path(context, "XDG_CONFIG_HOME")
            .or_else(|| absolute_home(context).map(|home| home.join(".config")))
            .ok_or(EngineError::MissingConfigHome)?,
    };
    Ok(base.join("sync-configs/manifest.yaml"))
}

fn backup_root(context: &PathContext) -> Result<PathBuf, EngineError> {
    Ok(state_root(context)?.join("backups"))
}

fn state_root(context: &PathContext) -> Result<PathBuf, EngineError> {
    let base = match context.platform {
        PathPlatform::Windows => absolute_environment_path(context, "LOCALAPPDATA")
            .or_else(|| absolute_home(context).map(|home| home.join("AppData/Local")))
            .ok_or(EngineError::MissingStateHome)?,
        PathPlatform::Posix => absolute_environment_path(context, "XDG_STATE_HOME")
            .or_else(|| absolute_home(context).map(|home| home.join(".local/state")))
            .ok_or(EngineError::MissingStateHome)?,
    };
    Ok(base.join("sync-configs"))
}

fn absolute_environment_path(context: &PathContext, name: &str) -> Option<PathBuf> {
    environment_value(context, name)
        .map(PathBuf::from)
        .filter(|path| is_absolute_for(path, context.platform))
}

fn absolute_home(context: &PathContext) -> Option<&Path> {
    context
        .home
        .as_deref()
        .filter(|path| is_absolute_for(path, context.platform))
}

fn environment_value<'a>(context: &'a PathContext, name: &str) -> Option<&'a OsString> {
    if context.platform == PathPlatform::Windows {
        context.environment.iter().find_map(|(key, value)| {
            key.to_str()
                .is_some_and(|key| key.eq_ignore_ascii_case(name))
                .then_some(value)
        })
    } else {
        context.environment.get(OsStr::new(name))
    }
}

fn skeleton_for(entry: &Entry, context: &PathContext) -> Option<PathBuf> {
    if context.platform != PathPlatform::Posix {
        return None;
    }
    let home = context.home.as_ref()?;
    let relative = entry.target.strip_prefix(home).ok()?;
    Some(Path::new("/etc/skel").join(relative))
}

fn reconciler_environment(profiles: &[String]) -> BTreeMap<OsString, OsString> {
    let mut environment: BTreeMap<OsString, OsString> = env::vars_os().collect();
    environment.insert(
        OsString::from("SYNC_CONFIGS_ACTIVE_PROFILES"),
        OsString::from(profiles.join(",")),
    );
    environment
}

fn resolve_sudo() -> Option<PathBuf> {
    discover_trusted_sudo(env::var_os("PATH").as_deref())
}
