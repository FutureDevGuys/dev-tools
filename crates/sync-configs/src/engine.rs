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
use crate::manifest::{
    check_state_preconditions, collect_profile_names, deduplicate_and_validate_targets,
    load_manifest, load_profile_map, select_entries_for_profiles, select_reconcilers_for_profiles,
    CommentedTargetPolicy, Entry, LoadOptions, Manifest, ManifestError, Mode, Privilege,
    Reconciler, ReconcilerScope,
};
use crate::overlay::json::{overlay_json_file, JsonOverlayOptions};
use crate::overlay::toml::{
    overlay_toml_file, CommentedTargetPolicy as OverlayCommentedTargetPolicy,
    ExclusiveSiblingGroup as OverlayExclusiveSiblingGroup, TomlConflictPolicy, TomlOverlayOptions,
};
use crate::paths::{
    canonical_target_key, resolve_config_path, PathContext, PathError, PathPlatform,
};
use crate::privilege::{PrivilegeError, PrivilegeSession};
use crate::privileged_target::{
    apply_privileged_plans, plan_selected_privileged_entries, PrivilegedCommands,
    PrivilegedCopyPlan, PrivilegedTargetError, PrivilegedTargetOutcome, SystemIdentityResolver,
};
use crate::reconciler::{ReconcilerError, ReconcilerPrivilege, ReconcilerRunner, ReconcilerSpec};
use crate::report::{ReconcilerSummary, Record, Report, Status};
use crate::scaffold::{initialize, render_examples, ScaffoldError, ScaffoldPaths};

const RECONCILER_TIMEOUT: Duration = Duration::from_secs(30);
const RECONCILER_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;

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
    if cli.print_example {
        return Ok(RunOutput::Examples(render_examples()));
    }

    let path_context = PathContext::from_current_environment()?;
    let config = config_path(cli, &path_context)?;
    if cli.init {
        return Ok(RunOutput::Initialized(initialize(&config, cli.force_init)?));
    }

    let loaded = load_request(cli, path_context, config)?;
    if cli.list_profiles {
        return Ok(RunOutput::Profiles(collect_profile_names(&loaded.manifest)));
    }
    if cli.validate {
        // Selection is intentionally evaluated during validation so bad host
        // maps and profile combinations fail without hooks or writes.
        let _ = select_entries_for_profiles(&loaded.manifest.entries, &loaded.profiles);
        let _ = select_reconcilers_for_profiles(&loaded.manifest.reconcilers, &loaded.profiles);
        return Ok(RunOutput::Validation(Report {
            profiles: loaded.profiles,
            ..Report::default()
        }));
    }

    converge(cli, loaded).map(RunOutput::Convergence)
}

fn load_request(
    cli: &Cli,
    path_context: PathContext,
    config: PathBuf,
) -> Result<LoadedRequest, EngineError> {
    if cli.profile_map.is_some() != cli.host_profile.is_some() {
        return Err(EngineError::IncompleteProfileMap);
    }
    let mut options = LoadOptions::default().with_path_context(path_context.clone());
    options.mode_override = cli.mode.map(mode_from_cli);
    options.prefer_source_overrides = !cli.no_source_overrides;
    let manifest = load_manifest(&config, &options)?;

    let mut profiles = Vec::new();
    let mut seen = BTreeSet::new();
    if let (Some(profile_map), Some(host_profile)) = (&cli.profile_map, &cli.host_profile) {
        for profile in load_profile_map(
            profile_map,
            host_profile,
            cli.profile_map_field.as_deref(),
            &path_context,
        )? {
            if seen.insert(profile.clone()) {
                profiles.push(profile);
            }
        }
    }
    for profile in &cli.profile {
        let profile = profile.trim();
        if !profile.is_empty() && seen.insert(profile.to_owned()) {
            profiles.push(profile.to_owned());
        }
    }

    Ok(LoadedRequest {
        manifest,
        profiles,
        path_context,
    })
}

fn converge(cli: &Cli, loaded: LoadedRequest) -> Result<Report, EngineError> {
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
    )?;

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
                executable: manifest.executable.clone(),
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

    let privileged_reconciler = reconciler_specs
        .iter()
        .any(|reconciler| reconciler.manifest.privilege == Privilege::Sudo);
    // Hooks and privileged reconcilers are selected before expansion and need
    // the shared session at their protocol boundary. Privileged file targets
    // deliberately do not authenticate yet: pre-hooks, expansion, and target
    // deduplication can still prove that no target mutation is eligible.
    let needs_early_authentication =
        !cli.dry_run && (hooks.requires_privilege() || privileged_reconciler);
    let mut session = if needs_early_authentication {
        let mut session = PrivilegeSession::new(resolve_sudo().ok_or(EngineError::MissingSudo)?)?;
        session.ensure_authenticated()?;
        runner.sudo_path = Some(session.sudo_path().to_path_buf());
        Some(session)
    } else {
        None
    };

    let mut report = Report {
        dry_run: cli.dry_run,
        profiles: loaded.profiles.clone(),
        ..Report::default()
    };
    let mut eligible = vec![true; selected_entries.len()];
    let pre_records = hooks.run_pre_hooks(session.as_ref())?;
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

    let origin_by_target = expanded_with_origin
        .iter()
        .map(|(entry, origin)| {
            (
                canonical_target_key(&entry.target, &loaded.path_context),
                *origin,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let expanded = deduplicate_and_validate_targets(
        expanded_with_origin
            .into_iter()
            .map(|(entry, _)| entry)
            .collect(),
        &loaded.path_context,
        &loaded.manifest.path,
    )?;

    let active_targets = expanded
        .iter()
        .map(|entry| canonical_target_key(&entry.target, &loaded.path_context))
        .collect::<BTreeSet<_>>();
    let active_privileged_plans = privileged_plans
        .into_iter()
        .filter(|plan| {
            active_targets.contains(&canonical_target_key(
                &plan.entry.target,
                &loaded.path_context,
            ))
        })
        .collect::<Vec<_>>();
    let privileged_commands = if !cli.dry_run
        && active_privileged_plans
            .iter()
            .any(PrivilegedCopyPlan::needs_mutation)
    {
        // Resolve every fixed privileged helper before asking the user to
        // authenticate. A missing/unsafe command must remain mutation-free.
        let commands = PrivilegedCommands::resolve()?;
        if session.is_none() {
            let mut target_session =
                PrivilegeSession::new(resolve_sudo().ok_or(EngineError::MissingSudo)?)?;
            target_session.ensure_authenticated()?;
            session = Some(target_session);
        }
        Some(commands)
    } else {
        None
    };
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
        let key = canonical_target_key(&entry.target, &loaded.path_context);
        let origin = origin_by_target.get(&key).copied();
        let outcome = if let Some(plan) = privileged_by_target.get(&key) {
            let Some(identities) = identities.as_ref() else {
                report.records.push(error_record(
                    entry,
                    &"privileged target identity resolver is unavailable",
                ));
                if let Some(origin) = origin {
                    merge_convergence(&mut origin_convergence[origin], EntryConvergence::Failed);
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
                    report.records.push(error_record(entry, &error));
                    EntryConvergence::Failed
                }
            }
        } else {
            converge_unprivileged(cli, entry, &backup_root, &loaded.path_context, &mut report)
        };
        if let Some(origin) = origin {
            merge_convergence(&mut origin_convergence[origin], outcome);
        }
    }

    for reconciler in &reconciler_specs {
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
            Err(error) => report.records.push(Record {
                status: Status::Errors,
                scope: reconciler.manifest.scope_label(),
                name: reconciler.manifest.name.clone(),
                message: error.to_string(),
                output: None,
            }),
        }
    }

    let post_records = hooks.run_post_hooks(session.as_ref(), |entry| {
        selected_entries
            .iter()
            .position(|candidate| std::ptr::eq(candidate, entry))
            .and_then(|index| origin_convergence[index])
            .unwrap_or(EntryConvergence::Skipped)
    })?;
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
        PathPlatform::Windows => environment_value(context, "APPDATA")
            .map(PathBuf::from)
            .ok_or(EngineError::MissingConfigHome)?,
        PathPlatform::Posix => environment_value(context, "XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| context.home.as_ref().map(|home| home.join(".config")))
            .ok_or(EngineError::MissingConfigHome)?,
    };
    Ok(base.join("sync-configs/manifest.yaml"))
}

fn backup_root(context: &PathContext) -> Result<PathBuf, EngineError> {
    Ok(state_root(context)?.join("backups"))
}

fn state_root(context: &PathContext) -> Result<PathBuf, EngineError> {
    let base = match context.platform {
        PathPlatform::Windows => environment_value(context, "LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or(EngineError::MissingStateHome)?,
        PathPlatform::Posix => environment_value(context, "XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| context.home.as_ref().map(|home| home.join(".local/state")))
            .ok_or(EngineError::MissingStateHome)?,
    };
    Ok(base.join("sync-configs"))
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
    let mut candidates = ["/usr/bin/sudo", "/bin/sudo", "/usr/local/bin/sudo"]
        .into_iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if let Some(path) = env::var_os("PATH") {
        candidates.extend(
            env::split_paths(&path)
                .filter(|directory| directory.is_absolute())
                .map(|directory| directory.join("sudo")),
        );
    }
    let mut seen = BTreeSet::new();
    candidates.into_iter().find(|candidate| {
        seen.insert(candidate.clone()) && PrivilegeSession::new(candidate.clone()).is_ok()
    })
}
