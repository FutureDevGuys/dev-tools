use super::generator::{
    canonical_help_ir_is_healthy, completion_command_plans, generate_tool_completion_with_context,
    help_fallback_identity_components, select_completion_command_plan, CompletionCommandPlan,
    CompletionGenerationContext, CompletionGenerationRequest, GeneratedCompletion,
};
use super::native::{
    provider_bundled_artifact_identity, stored_artifact_is_healthy, NativeCandidateOrigin,
    NativeProbeSession, NATIVE_PROTOCOL_REGISTRY_VERSION, NATIVE_TRUST_CLASSIFICATION_VERSION,
};
use super::registry::{
    Registry, RegistryBundledCompletion, RegistryCommandCandidate, RegistryCompletionRecipe,
};
use super::state::{
    CompletionBindingMemo, CompletionCandidateMemo, CompletionCandidateSlot,
    CompletionIdentityMemo, CompletionIdentityStore, CompletionIssueMemo, CompletionIssueStore,
};
use super::{
    candidate_payload_basename, completion_provider_no_configured_tools,
    completion_provider_progress, filter_completion_catalog_for_providers, managed_completion_dir,
    managed_payload_basename, publish_public_completion_snapshot, read_usable_completion_payload,
    remove_managed_overlay_shim, tool_key, validate_completion_overlay_names,
    write_bytes_if_changed, write_managed_overlay_shim, CompletionArtifactClassification,
    CompletionBindingIdentity, CompletionCandidateIdentity, CompletionProviderInventoryRecord,
    CompletionProviderInventoryStatus, CompletionShell, CompletionSyncArgs, CompletionSyncOutcome,
    CompletionSyncRecord, CompletionSyncRecordStatus, CompletionSyncResult,
};
use crate::config::{load_runtime_config, merge_user_completion_catalog};
use crate::util::cancel;
use crate::util::process::{run_capture, which};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const PROVIDER_INVENTORY_TIMEOUT_DEFAULT_SECS: u64 = 120;
const INVENTORY_SHELL_PLACEHOLDER: &str = "zsh";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ToolOrigin {
    Registry,
    Ambient,
}

#[derive(Clone, Debug)]
struct ToolMetadata {
    command: Option<String>,
    command_candidates: Vec<RegistryCommandCandidate>,
    bundled_completions: Vec<RegistryBundledCompletion>,
    completion_recipes: Vec<RegistryCompletionRecipe>,
    trust_dynamic: bool,
    priority: Option<i64>,
    managed_required: bool,
    origin: ToolOrigin,
}

impl Default for ToolMetadata {
    fn default() -> Self {
        Self {
            command: None,
            command_candidates: Vec::new(),
            bundled_completions: Vec::new(),
            completion_recipes: Vec::new(),
            trust_dynamic: false,
            priority: None,
            managed_required: false,
            origin: ToolOrigin::Ambient,
        }
    }
}

#[derive(Default)]
struct CatalogIndex {
    enabled_by_provider: BTreeMap<String, BTreeSet<String>>,
    all_by_provider: BTreeMap<String, BTreeSet<String>>,
    disabled_by_provider: BTreeMap<String, BTreeSet<String>>,
    metadata: BTreeMap<(String, String), ToolMetadata>,
    known_providers: BTreeSet<String>,
    disabled_providers: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct InventoryCandidate {
    slot: CompletionCandidateSlot,
    binding: CompletionBindingIdentity,
    provider: String,
    tool: String,
    installation: String,
    provider_native_seed: String,
    provider_bin_dir: PathBuf,
    metadata: ToolMetadata,
}

#[derive(Clone, Debug)]
struct ProviderInventory {
    provider: String,
    status: CompletionProviderInventoryStatus,
    reason: Option<String>,
    candidates: BTreeMap<CompletionCandidateSlot, InventoryCandidate>,
    explicit_removals: BTreeSet<String>,
}

impl ProviderInventory {
    fn complete(provider: &str) -> Self {
        Self {
            provider: provider.to_string(),
            status: CompletionProviderInventoryStatus::Complete,
            reason: None,
            candidates: BTreeMap::new(),
            explicit_removals: BTreeSet::new(),
        }
    }

    fn failed(provider: &str, reason: impl Into<String>) -> Self {
        Self {
            provider: provider.to_string(),
            status: CompletionProviderInventoryStatus::Failed,
            reason: Some(reason.into()),
            candidates: BTreeMap::new(),
            explicit_removals: BTreeSet::new(),
        }
    }

    fn make_partial(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        self.status = CompletionProviderInventoryStatus::Partial;
        self.reason = Some(match self.reason.take() {
            Some(existing) if !existing.is_empty() => format!("{existing};{reason}"),
            _ => reason,
        });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CandidateOutcomeKind {
    Generated,
    Unchanged,
    ProbedUnchanged,
    Reused,
    Retained,
}

#[derive(Clone, Debug)]
struct CandidateOutcome {
    kind: CandidateOutcomeKind,
    reason: Option<String>,
}

impl CandidateOutcome {
    fn new(kind: CandidateOutcomeKind) -> Self {
        Self { kind, reason: None }
    }

    fn retained(reason: impl Into<String>) -> Self {
        Self {
            kind: CandidateOutcomeKind::Retained,
            reason: Some(reason.into()),
        }
    }
}

#[derive(Clone)]
struct PreparedPlan {
    plan: CompletionCommandPlan,
    identity: CompletionCandidateIdentity,
    native_resolution_fingerprint: String,
    resolution_fingerprint: String,
}

pub(super) fn run_completion_sync(args: CompletionSyncArgs) -> Result<CompletionSyncResult> {
    if args.shells.is_empty() {
        anyhow::bail!("completion sync requires at least one selected shell");
    }
    let root = super::ManagedCompletionRoot::new(args.managed_root.clone())?;
    let _sync_lock = root.lock_sync()?;
    let public_mode = args.rc_root.is_none();
    let generation_root = args
        .rc_root
        .clone()
        .unwrap_or_else(|| args.managed_root.join("cache/generation"));
    let registry_text = match fs::read_to_string(&args.catalog_path) {
        Ok(text) => text,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && args.catalog_path == args.managed_root.join("cache/managed-tools.json") =>
        {
            r#"{"schema_version":1,"providers":[],"tools":[]}"#.to_string()
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read catalog {}", args.catalog_path.display()));
        }
    };
    let base_registry: Registry = serde_json::from_str(&registry_text).context("parse catalog")?;
    let runtime_cfg = load_runtime_config(args.config_path.clone())?;
    let registry = merge_user_completion_catalog(base_registry, Some(&runtime_cfg));
    let validation_registry =
        filter_completion_catalog_for_providers(&registry, &args.providers_csv);
    validate_completion_overlay_names(&validation_registry)?;
    let index = build_catalog_index(&registry);

    let identity_store = CompletionIdentityStore::new(&args.managed_root)?;
    let previous_memo = identity_store.load()?;
    let mut candidates = previous_memo
        .candidates
        .iter()
        .cloned()
        .map(|memo| (memo.slot.clone(), memo))
        .collect::<BTreeMap<_, _>>();
    let previous_bindings = previous_memo
        .bindings
        .iter()
        .cloned()
        .map(|memo| (memo.binding.clone(), memo))
        .collect::<BTreeMap<_, _>>();

    let mut events = Vec::new();
    let mut inventories = Vec::new();
    let mut outcomes = BTreeMap::<CompletionCandidateSlot, CandidateOutcome>::new();
    let mut direct_records = Vec::<CompletionSyncRecord>::new();
    let mut retired = Vec::<(CompletionCandidateMemo, String)>::new();
    let mut authoritative_providers = BTreeSet::new();
    let report = args.report.trim().to_ascii_lowercase();
    let provider_budget = Duration::from_secs(
        env::var("UPDATE_ALL_COMPLETION_PROVIDER_TIMEOUT")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(PROVIDER_INVENTORY_TIMEOUT_DEFAULT_SECS)
            .max(1),
    );

    for provider in selected_providers(&args.providers_csv) {
        if report == "verbose" {
            events.push(format!("__UA_COMP_INFO|provider_scan|{provider}:"));
        }
        let mut inventory =
            collect_provider_inventory(&provider, args.discover, &index, &report, &mut events);
        expand_inventory_shells(&mut inventory, &args.shells);
        inventory.explicit_removals.extend(
            index
                .disabled_by_provider
                .get(&provider)
                .cloned()
                .unwrap_or_default(),
        );

        if !args.discover
            && index.known_providers.contains(&provider)
            && inventory.candidates.is_empty()
        {
            let message = completion_provider_no_configured_tools(&provider);
            if let Some(callback) = &args.progress_cb {
                callback(message);
            }
            if report == "verbose" {
                events.push(format!("__UA_COMP_INFO|provider_empty|{provider}:"));
            }
        }

        let retired_before_provider = retired.len();
        apply_explicit_removals(
            &provider,
            &inventory.explicit_removals,
            &mut candidates,
            &mut outcomes,
            &mut retired,
        );

        let provider_start = Instant::now();
        let total = inventory.candidates.len();
        let mut processed = 0usize;
        let mut retirement_blocked = false;
        let observed_slots = inventory
            .candidates
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();

        if inventory.status != CompletionProviderInventoryStatus::Failed {
            let inventory_candidates = inventory.candidates.values().cloned().collect::<Vec<_>>();
            for item in &inventory_candidates {
                if cancel::is_cancel_requested() {
                    return Err(anyhow::anyhow!(crate::Cancelled));
                }
                if provider_start.elapsed() > provider_budget {
                    inventory.make_partial("provider_budget_exhausted");
                    events.push(format!(
                        "__UA_COMP_INFO|provider_budget_exceeded|{}:",
                        inventory.provider
                    ));
                    break;
                }
                if let Some(callback) = &args.progress_cb {
                    callback(format!(
                        "completion-sync {}: probing {} ({}/{})",
                        inventory.provider,
                        item.tool,
                        processed + 1,
                        total
                    ));
                }
                let candidate_ready = process_candidate(
                    item,
                    &generation_root,
                    &args.managed_root,
                    &mut candidates,
                    &mut outcomes,
                    &mut direct_records,
                )?;
                retirement_blocked |= !candidate_ready;
                processed += 1;
            }
        }

        if inventory.status == CompletionProviderInventoryStatus::Complete && !retirement_blocked {
            let absent = candidates
                .keys()
                .filter(|slot| slot.provider == provider && !observed_slots.contains(*slot))
                .cloned()
                .collect::<Vec<_>>();
            for slot in absent {
                if let Some(memo) = candidates.remove(&slot) {
                    outcomes.remove(&slot);
                    retired.push((memo, "authoritative_inventory_absent".to_string()));
                }
            }
        } else {
            let retention_reason = if retirement_blocked {
                "candidate_probe_failed_retirement_blocked"
            } else {
                inventory
                    .reason
                    .as_deref()
                    .unwrap_or("inventory_incomplete")
            };
            mark_provider_retained(&provider, retention_reason, &candidates, &mut outcomes);
            if retirement_blocked {
                events.push(format!(
                    "__UA_COMP_INFO|provider_retirement_blocked|{}:{retention_reason}",
                    inventory.provider
                ));
            }
            if inventory.status == CompletionProviderInventoryStatus::Failed {
                record_inventory_failure(
                    &index,
                    &provider,
                    inventory.reason.as_deref().unwrap_or("inventory_failed"),
                    &mut direct_records,
                );
            }
        }

        if inventory.status == CompletionProviderInventoryStatus::Complete
            && !retirement_blocked
            && retired.len() > retired_before_provider
        {
            authoritative_providers.insert(provider.clone());
        }

        if processed > 0 {
            if let Some(callback) = &args.progress_cb {
                let provider_generated = outcomes
                    .iter()
                    .filter(|(slot, outcome)| {
                        slot.provider == provider && outcome.kind == CandidateOutcomeKind::Generated
                    })
                    .count();
                let provider_unchanged = outcomes
                    .iter()
                    .filter(|(slot, outcome)| {
                        slot.provider == provider
                            && matches!(
                                outcome.kind,
                                CandidateOutcomeKind::Unchanged
                                    | CandidateOutcomeKind::ProbedUnchanged
                                    | CandidateOutcomeKind::Reused
                                    | CandidateOutcomeKind::Retained
                            )
                    })
                    .count();
                callback(completion_provider_progress(
                    &provider,
                    processed,
                    total,
                    provider_generated,
                    provider_unchanged,
                    direct_records
                        .iter()
                        .filter(|record| record.provider == provider)
                        .count(),
                    provider_start.elapsed(),
                ));
            }
        }

        let inventory_record = CompletionProviderInventoryRecord {
            provider: provider.clone(),
            status: inventory.status,
            candidates: inventory.candidates.len(),
            reason: inventory.reason.clone(),
        };
        push_inventory_event(&mut events, &inventory_record);
        inventories.push(inventory_record);
    }

    let (binding_memos, mut candidate_records, activation_updates) = activate_bindings(
        args.rc_root.as_deref(),
        &args.managed_root,
        &candidates,
        &previous_bindings,
        &outcomes,
    )?;
    direct_records.append(&mut candidate_records);

    prune_retired_candidate_artifacts(&generation_root, &candidates, &retired)?;
    if let Some(rc_root) = args.rc_root.as_deref() {
        for provider in &authoritative_providers {
            let keep = candidates
                .values()
                .filter(|memo| &memo.slot.provider == provider)
                .map(|memo| memo.binding.command.clone())
                .collect::<BTreeSet<_>>();
            super::prune_managed_provider_artifacts(rc_root, provider, keep)?;
        }
        if !retired.is_empty() {
            super::prune_orphan_managed_overlay_shims(rc_root)?;
        }
    }

    for (memo, reason) in &retired {
        direct_records.push(record_for_shell(
            CompletionSyncRecord::with_artifact_details(
                &memo.slot.provider,
                &memo.binding.command,
                CompletionSyncRecordStatus::Retired,
                Some(&memo.artifact_path),
                Some(reason.clone()),
                memo.artifact_classification,
                memo.successful_recipe
                    .as_ref()
                    .map(|recipe| recipe.report_name()),
            ),
            &memo.slot.shell,
        ));
    }

    let mut next_memo = CompletionIdentityMemo::default();
    next_memo.candidates = candidates.values().cloned().collect();
    next_memo.bindings = binding_memos;
    identity_store.save_if_changed(&next_memo)?;

    direct_records.sort_by(|left, right| {
        (
            &left.tool,
            &left.provider,
            record_status_sort_key(left.status),
        )
            .cmp(&(
                &right.tool,
                &right.provider,
                record_status_sort_key(right.status),
            ))
    });
    for record in &direct_records {
        push_record_event(&mut events, record);
    }
    let issues = direct_records
        .iter()
        .filter_map(|record| {
            let outcome = match record.status {
                CompletionSyncRecordStatus::Retained => "retained_previous",
                CompletionSyncRecordStatus::Skipped => "unsupported",
                CompletionSyncRecordStatus::Failed => "failed",
                _ => return None,
            };
            Some(CompletionIssueMemo {
                shell: record.shell.clone(),
                provider: record.provider.clone(),
                command: record.tool.clone(),
                outcome: outcome.to_string(),
                reason: record.reason.clone(),
            })
        })
        .collect::<Vec<_>>();
    CompletionIssueStore::new(&args.managed_root)?.save_if_changed(&issues)?;

    let generated = outcomes
        .values()
        .filter(|outcome| outcome.kind == CandidateOutcomeKind::Generated)
        .count()
        + activation_updates;
    let unchanged = outcomes
        .values()
        .filter(|outcome| {
            matches!(
                outcome.kind,
                CandidateOutcomeKind::Unchanged
                    | CandidateOutcomeKind::ProbedUnchanged
                    | CandidateOutcomeKind::Reused
                    | CandidateOutcomeKind::Retained
            )
        })
        .count();
    let skipped = direct_records
        .iter()
        .filter(|record| {
            matches!(
                record.status,
                CompletionSyncRecordStatus::Skipped | CompletionSyncRecordStatus::Failed
            )
        })
        .count();

    if report == "json" {
        let payload = serde_json::json!({
            "generated": generated,
            "unchanged": unchanged,
            "skipped": skipped,
            "inventories": inventories,
        });
        events.push(format!("__UA_COMP_REPORT_JSON|{payload}"));
    }
    events.push(format!(
        "__UA_COMP_SUMMARY|generated={generated}|unchanged={unchanged}|skipped={skipped}"
    ));
    let publication = if public_mode {
        Some(publish_public_completion_snapshot(
            &args.managed_root,
            &args.shells,
            &next_memo.bindings,
            &candidates,
            &mut events,
        )?)
    } else {
        None
    };
    let outcome = summarize_sync_outcome(&direct_records, publication.as_ref());

    Ok(CompletionSyncResult {
        generated,
        unchanged,
        skipped,
        inventories,
        events,
        records: direct_records,
        catalog_used: args.catalog_path,
        effective_catalog: registry,
        outcome,
        shells: args
            .shells
            .iter()
            .map(|shell| shell.as_event_name().to_string())
            .collect(),
    })
}

fn summarize_sync_outcome(
    records: &[CompletionSyncRecord],
    publication: Option<&super::CompletionSnapshotPublishOutcome>,
) -> CompletionSyncOutcome {
    if records
        .iter()
        .any(|record| record.status == CompletionSyncRecordStatus::Failed)
    {
        return CompletionSyncOutcome::Failed;
    }
    if publication.is_some_and(|outcome| {
        matches!(
            outcome,
            super::CompletionSnapshotPublishOutcome::Published { .. }
                | super::CompletionSnapshotPublishOutcome::Repaired { .. }
        )
    }) {
        if records
            .iter()
            .any(|record| record.status == CompletionSyncRecordStatus::Retired)
        {
            CompletionSyncOutcome::Removed
        } else {
            CompletionSyncOutcome::Published
        }
    } else if records
        .iter()
        .any(|record| record.status == CompletionSyncRecordStatus::Retained)
    {
        CompletionSyncOutcome::RetainedPrevious
    } else if records
        .iter()
        .any(|record| record.status == CompletionSyncRecordStatus::ProbedUnchanged)
    {
        CompletionSyncOutcome::ProbedUnchanged
    } else if !records.is_empty()
        && records.iter().all(|record| {
            matches!(
                record.status,
                CompletionSyncRecordStatus::Skipped | CompletionSyncRecordStatus::Shadowed
            )
        })
    {
        CompletionSyncOutcome::Unsupported
    } else {
        CompletionSyncOutcome::Reused
    }
}

fn build_catalog_index(registry: &Registry) -> CatalogIndex {
    let mut index = CatalogIndex::default();
    for provider in &registry.providers {
        index.known_providers.insert(provider.name.clone());
        if !provider.enabled.unwrap_or(true) {
            index.disabled_providers.insert(provider.name.clone());
        }
    }
    for tool in &registry.tools {
        let provider = tool.provider.as_deref().unwrap_or("npm").trim().to_string();
        let name = tool.name.trim().to_string();
        if provider.is_empty() || name.is_empty() {
            continue;
        }
        index
            .all_by_provider
            .entry(provider.clone())
            .or_default()
            .insert(name.clone());
        let enabled = tool.enabled.unwrap_or(true);
        if enabled {
            index
                .enabled_by_provider
                .entry(provider.clone())
                .or_default()
                .insert(name.clone());
        } else {
            index
                .disabled_by_provider
                .entry(provider.clone())
                .or_default()
                .insert(name.clone());
        }
        index.metadata.insert(
            tool_key(&provider, &name),
            ToolMetadata {
                command: tool.command.clone(),
                command_candidates: tool.command_candidates.clone(),
                bundled_completions: tool.bundled_completions.clone(),
                completion_recipes: tool.completion_recipes.clone(),
                trust_dynamic: tool.trust_dynamic,
                priority: tool.priority,
                managed_required: tool.managed_required.unwrap_or(false),
                origin: if tool.ambient {
                    ToolOrigin::Ambient
                } else {
                    ToolOrigin::Registry
                },
            },
        );
    }
    index
}

fn selected_providers(csv: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    csv.split(',')
        .map(str::trim)
        .filter(|provider| !provider.is_empty())
        .filter_map(|provider| {
            seen.insert(provider.to_string())
                .then(|| provider.to_string())
        })
        .collect()
}

fn collect_provider_inventory(
    provider: &str,
    discover: bool,
    index: &CatalogIndex,
    report: &str,
    events: &mut Vec<String>,
) -> ProviderInventory {
    if index.disabled_providers.contains(provider) {
        let mut inventory = ProviderInventory::complete(provider);
        inventory.reason = Some("configured_provider_disabled".to_string());
        inventory.explicit_removals.insert("*".to_string());
        return inventory;
    }

    match provider {
        "npm" => collect_npm_inventory(discover, index),
        "pipx" => collect_pipx_inventory(discover, index),
        "uv" => collect_uv_inventory(discover, index, report, events),
        "go" => collect_go_inventory(discover, index),
        "path" => collect_configured_inventory("path", index, PathBuf::new(), "path", true),
        other => ProviderInventory::failed(other, "unsupported_provider"),
    }
}

fn collect_configured_inventory(
    provider: &str,
    index: &CatalogIndex,
    provider_bin_dir: PathBuf,
    installation: &str,
    authoritative: bool,
) -> ProviderInventory {
    let mut inventory = ProviderInventory::complete(provider);
    if !authoritative {
        inventory.make_partial("discovery_disabled_configured_subset");
    }
    for tool in index
        .enabled_by_provider
        .get(provider)
        .cloned()
        .unwrap_or_default()
    {
        insert_inventory_candidate(
            &mut inventory,
            inventory_candidate(
                provider,
                &tool,
                format!("configured:{tool}"),
                installation.to_string(),
                format!("configured:{provider}:{tool}"),
                provider_bin_dir.clone(),
                metadata_for(index, provider, &tool),
            ),
        );
    }
    inventory
}

fn collect_npm_inventory(discover: bool, index: &CatalogIndex) -> ProviderInventory {
    let configured = index
        .enabled_by_provider
        .get("npm")
        .cloned()
        .unwrap_or_default();
    if !discover && configured.is_empty() {
        let mut inventory = ProviderInventory::complete("npm");
        inventory.make_partial("discovery_disabled_configured_subset");
        return inventory;
    }
    let prefix = match run_capture("npm", ["prefix", "-g"], Some(Duration::from_secs(5))) {
        Ok(value) => value.lines().next().unwrap_or("").trim().to_string(),
        Err(error) => {
            return ProviderInventory::failed("npm", format!("npm_prefix_failed:{error}"))
        }
    };
    if prefix.is_empty() {
        return ProviderInventory::failed("npm", "npm_prefix_empty");
    }
    let bin_dir = Path::new(&prefix).join("bin");
    let mut inventory = ProviderInventory::complete("npm");
    if !discover {
        inventory.make_partial("discovery_disabled_configured_subset");
    }
    let tools = if discover {
        let entries = match fs::read_dir(&bin_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return inventory;
            }
            Err(error) => {
                return ProviderInventory::failed("npm", format!("npm_bin_read_failed:{error}"));
            }
        };
        let enabled = index
            .enabled_by_provider
            .get("npm")
            .cloned()
            .unwrap_or_default();
        let catalog = index
            .all_by_provider
            .get("npm")
            .cloned()
            .unwrap_or_default();
        let mut tools = BTreeSet::new();
        let mut entry_error = false;
        for entry in entries {
            match entry {
                Ok(entry) => {
                    if let Some(name) = entry.file_name().to_str() {
                        if let Some(name) = super::normalize_npm_discovered_tool(name) {
                            if enabled.contains(&name) || !catalog.contains(&name) {
                                tools.insert(name);
                            }
                        }
                    } else {
                        entry_error = true;
                    }
                }
                Err(_) => entry_error = true,
            }
        }
        if entry_error {
            inventory.make_partial("npm_bin_entry_read_failed");
        }
        tools
    } else {
        configured
    };

    for tool in tools {
        insert_inventory_candidate(
            &mut inventory,
            inventory_candidate(
                "npm",
                &tool,
                format!("npm:{tool}"),
                prefix.clone(),
                format!("npm-prefix:{prefix};entry-point:{tool}"),
                bin_dir.clone(),
                metadata_for(index, "npm", &tool),
            ),
        );
    }
    inventory
}

#[derive(Deserialize)]
struct PipxState {
    #[serde(default)]
    venvs: BTreeMap<String, PipxVenv>,
}

#[derive(Deserialize)]
struct PipxVenv {
    metadata: Option<PipxMetadata>,
}

#[derive(Deserialize)]
struct PipxMetadata {
    main_package: Option<PipxMainPackage>,
}

#[derive(Deserialize)]
struct PipxMainPackage {
    package: Option<String>,
    package_or_url: Option<String>,
    package_version: Option<String>,
    apps: Option<Vec<String>>,
}

fn collect_pipx_inventory(discover: bool, index: &CatalogIndex) -> ProviderInventory {
    if !discover {
        return collect_configured_inventory(
            "pipx",
            index,
            PathBuf::new(),
            "pipx-configured",
            false,
        );
    }
    let list_json = match run_capture("pipx", ["list", "--json"], Some(Duration::from_secs(10))) {
        Ok(value) => value,
        Err(error) => {
            return ProviderInventory::failed("pipx", format!("pipx_list_failed:{error}"))
        }
    };
    let state: PipxState = match serde_json::from_str(&list_json) {
        Ok(value) => value,
        Err(error) => {
            return ProviderInventory::failed("pipx", format!("pipx_parse_failed:{error}"));
        }
    };
    let disabled = index
        .disabled_by_provider
        .get("pipx")
        .cloned()
        .unwrap_or_default();
    let mut inventory = ProviderInventory::complete("pipx");
    for (venv_name, venv) in state.venvs {
        let Some(main) = venv.metadata.and_then(|metadata| metadata.main_package) else {
            inventory.make_partial(format!("pipx_metadata_missing:{venv_name}"));
            continue;
        };
        let Some(apps) = main.apps.clone() else {
            inventory.make_partial(format!("pipx_apps_missing:{venv_name}"));
            continue;
        };
        let native = format!(
            "pipx-package:{};source:{};version:{}",
            main.package.as_deref().unwrap_or(&venv_name),
            main.package_or_url.as_deref().unwrap_or(""),
            main.package_version.as_deref().unwrap_or("")
        );
        for app in apps {
            if disabled.contains(&app) {
                continue;
            }
            insert_inventory_candidate(
                &mut inventory,
                inventory_candidate(
                    "pipx",
                    &app,
                    format!("pipx:{app}"),
                    format!("pipx-venv:{venv_name}"),
                    native.clone(),
                    PathBuf::new(),
                    metadata_for(index, "pipx", &app),
                ),
            );
        }
    }
    inventory
}

#[derive(Deserialize, Serialize)]
struct UvTools {
    #[serde(default)]
    tools: Vec<UvTool>,
}

#[derive(Deserialize, Serialize)]
struct UvTool {
    name: String,
    #[serde(flatten)]
    metadata: BTreeMap<String, serde_json::Value>,
}

fn collect_uv_inventory(
    discover: bool,
    index: &CatalogIndex,
    report: &str,
    events: &mut Vec<String>,
) -> ProviderInventory {
    if !discover {
        return collect_configured_inventory("uv", index, PathBuf::new(), "uv-configured", false);
    }
    let disabled = index
        .disabled_by_provider
        .get("uv")
        .cloned()
        .unwrap_or_default();
    let json_result = run_capture(
        "uv",
        ["tool", "list", "--json"],
        Some(Duration::from_secs(10)),
    );
    if let Ok(json) = &json_result {
        match serde_json::from_str::<UvTools>(json) {
            Ok(parsed) => {
                let mut inventory = ProviderInventory::complete("uv");
                for tool in parsed.tools {
                    if disabled.contains(&tool.name) {
                        continue;
                    }
                    let metadata_bytes = serde_json::to_vec(&tool).unwrap_or_default();
                    let native = format!("uv-tool-metadata-sha256:{}", sha256_hex(&metadata_bytes));
                    insert_inventory_candidate(
                        &mut inventory,
                        inventory_candidate(
                            "uv",
                            &tool.name,
                            format!("uv:{}", tool.name),
                            format!("uv-tool:{}", tool.name),
                            native,
                            PathBuf::new(),
                            metadata_for(index, "uv", &tool.name),
                        ),
                    );
                }
                return inventory;
            }
            Err(error) => {
                if report == "verbose" {
                    events.push(format!(
                        "__UA_COMP_INFO|uv|json_discovery_parse_failed:{error}"
                    ));
                }
            }
        }
    } else if report == "verbose" {
        events.push("__UA_COMP_INFO|uv|json_discovery_unsupported".to_string());
    }

    let plain = match run_capture("uv", ["tool", "list"], Some(Duration::from_secs(10))) {
        Ok(value) => value,
        Err(error) => {
            return ProviderInventory::failed("uv", format!("uv_tool_list_failed:{error}"));
        }
    };
    let tools = super::parse_uv_tool_list(&plain);
    if tools.is_empty() {
        return ProviderInventory::failed("uv", "uv_tool_list_unusable");
    }
    let mut inventory = ProviderInventory::complete("uv");
    inventory.make_partial(match json_result {
        Ok(_) => "uv_json_parse_failed_plain_fallback",
        Err(_) => "uv_json_unavailable_plain_fallback",
    });
    for tool in tools {
        if disabled.contains(&tool) {
            continue;
        }
        insert_inventory_candidate(
            &mut inventory,
            inventory_candidate(
                "uv",
                &tool,
                format!("uv:{tool}"),
                format!("uv-tool:{tool}"),
                format!("uv-plain-entry:{tool}"),
                PathBuf::new(),
                metadata_for(index, "uv", &tool),
            ),
        );
    }
    inventory
}

fn collect_go_inventory(discover: bool, index: &CatalogIndex) -> ProviderInventory {
    if !discover {
        return collect_configured_inventory("go", index, PathBuf::new(), "go-configured", false);
    }
    let gobin = match run_capture("go", ["env", "GOBIN"], Some(Duration::from_secs(5))) {
        Ok(value) => value.lines().next().unwrap_or("").trim().to_string(),
        Err(error) => {
            return ProviderInventory::failed("go", format!("go_env_gobin_failed:{error}"))
        }
    };
    let bin_dir = if gobin.is_empty() {
        let gopath = match run_capture("go", ["env", "GOPATH"], Some(Duration::from_secs(5))) {
            Ok(value) => value,
            Err(error) => {
                return ProviderInventory::failed("go", format!("go_env_gopath_failed:{error}"));
            }
        };
        let Some(root) = env::split_paths(gopath.lines().next().unwrap_or("").trim()).next() else {
            return ProviderInventory::failed("go", "go_bin_dir_empty");
        };
        root.join("bin")
    } else {
        PathBuf::from(gobin)
    };
    let entries = match fs::read_dir(&bin_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ProviderInventory::complete("go");
        }
        Err(error) => {
            return ProviderInventory::failed("go", format!("go_bin_read_failed:{error}"))
        }
    };
    let disabled = index
        .disabled_by_provider
        .get("go")
        .cloned()
        .unwrap_or_default();
    let mut inventory = ProviderInventory::complete("go");
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                inventory.make_partial("go_bin_entry_read_failed");
                continue;
            }
        };
        if !entry.path().is_file() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            inventory.make_partial("go_bin_non_utf8_entry");
            continue;
        };
        if disabled.contains(&name) {
            continue;
        }
        insert_inventory_candidate(
            &mut inventory,
            inventory_candidate(
                "go",
                &name,
                format!("go:{name}"),
                bin_dir.display().to_string(),
                format!("go-bin-entry:{name}"),
                bin_dir.clone(),
                metadata_for(index, "go", &name),
            ),
        );
    }
    inventory
}

fn inventory_candidate(
    provider: &str,
    tool: &str,
    source: String,
    installation: String,
    provider_native_seed: String,
    provider_bin_dir: PathBuf,
    metadata: ToolMetadata,
) -> InventoryCandidate {
    InventoryCandidate {
        slot: CompletionCandidateSlot {
            shell: INVENTORY_SHELL_PLACEHOLDER.to_string(),
            provider: provider.to_string(),
            source,
            command: tool.to_string(),
        },
        binding: CompletionBindingIdentity {
            shell: INVENTORY_SHELL_PLACEHOLDER.to_string(),
            command: tool.to_string(),
        },
        provider: provider.to_string(),
        tool: tool.to_string(),
        installation,
        provider_native_seed,
        provider_bin_dir,
        metadata,
    }
}

fn expand_inventory_shells(inventory: &mut ProviderInventory, shells: &[CompletionShell]) {
    let base = std::mem::take(&mut inventory.candidates);
    for candidate in base.into_values() {
        for shell in shells.iter().copied() {
            let mut expanded = candidate.clone();
            expanded.slot.shell = shell.as_event_name().to_string();
            expanded.binding.shell = shell.as_event_name().to_string();
            insert_inventory_candidate(inventory, expanded);
        }
    }
}

fn insert_inventory_candidate(inventory: &mut ProviderInventory, candidate: InventoryCandidate) {
    if inventory.candidates.contains_key(&candidate.slot) {
        inventory.make_partial(format!(
            "duplicate_candidate_slot:{}:{}",
            candidate.slot.source, candidate.slot.command
        ));
        return;
    }
    inventory
        .candidates
        .insert(candidate.slot.clone(), candidate);
}

fn metadata_for(index: &CatalogIndex, provider: &str, tool: &str) -> ToolMetadata {
    index
        .metadata
        .get(&tool_key(provider, tool))
        .cloned()
        .unwrap_or_default()
}

fn apply_explicit_removals(
    provider: &str,
    removals: &BTreeSet<String>,
    candidates: &mut BTreeMap<CompletionCandidateSlot, CompletionCandidateMemo>,
    outcomes: &mut BTreeMap<CompletionCandidateSlot, CandidateOutcome>,
    retired: &mut Vec<(CompletionCandidateMemo, String)>,
) {
    if removals.is_empty() {
        return;
    }
    let slots = candidates
        .keys()
        .filter(|slot| {
            slot.provider == provider
                && (removals.contains("*") || removals.contains(&slot.command))
        })
        .cloned()
        .collect::<Vec<_>>();
    for slot in slots {
        if let Some(memo) = candidates.remove(&slot) {
            outcomes.remove(&slot);
            retired.push((memo, "configured_removal".to_string()));
        }
    }
}

fn mark_provider_retained(
    provider: &str,
    reason: &str,
    candidates: &BTreeMap<CompletionCandidateSlot, CompletionCandidateMemo>,
    outcomes: &mut BTreeMap<CompletionCandidateSlot, CandidateOutcome>,
) {
    for slot in candidates.keys().filter(|slot| slot.provider == provider) {
        outcomes
            .entry(slot.clone())
            .or_insert_with(|| CandidateOutcome::retained(reason.to_string()));
    }
}

fn process_candidate(
    item: &InventoryCandidate,
    rc_root: &Path,
    managed_root: &Path,
    candidates: &mut BTreeMap<CompletionCandidateSlot, CompletionCandidateMemo>,
    outcomes: &mut BTreeMap<CompletionCandidateSlot, CandidateOutcome>,
    direct_records: &mut Vec<CompletionSyncRecord>,
) -> Result<bool> {
    let prior = candidates.get(&item.slot).cloned();
    let expected_artifact = expected_artifact_path(rc_root, item)?;
    let plans = completion_command_plans(
        &item.provider,
        &item.tool,
        &item.provider_bin_dir,
        item.metadata.command.as_deref(),
        &item.metadata.command_candidates,
    );
    let mut prepared = Vec::new();
    let mut preparation_error = None;
    for (index, plan) in plans.into_iter().enumerate() {
        match prepare_plan(item, plan, index) {
            Ok(plan) => prepared.push(plan),
            Err(error) => preparation_error = Some(error),
        }
    }

    if let Some(prior) = &prior {
        if let Some(reused) = prepared.iter().find(|prepared| {
            let resolution_matches = if prior.canonical_ir_path.is_some() {
                prior.resolution_fingerprint == prepared.resolution_fingerprint
            } else {
                prior.native_resolution_fingerprint.as_deref()
                    == Some(prepared.native_resolution_fingerprint.as_str())
            };
            prior.identity == prepared.identity
                && resolution_matches
                && prior.artifact_path == expected_artifact
                && memo_artifact_is_healthy(prior, managed_root)
        }) {
            let mut memo = prior.clone();
            memo.priority = item.metadata.priority;
            memo.managed_required = item.metadata.managed_required;
            memo.identity = reused.identity.clone();
            memo.resolution_fingerprint = reused.resolution_fingerprint.clone();
            memo.native_resolution_fingerprint = Some(reused.native_resolution_fingerprint.clone());
            candidates.insert(item.slot.clone(), memo);
            outcomes.insert(
                item.slot.clone(),
                CandidateOutcome::new(CandidateOutcomeKind::Reused),
            );
            return Ok(true);
        }
    }

    let cached_help_reprocess = prior.as_ref().and_then(|prior| {
        prepared.iter().find(|prepared| {
            prior.identity == prepared.identity
                && prior.native_resolution_fingerprint.as_deref()
                    == Some(prepared.native_resolution_fingerprint.as_str())
                && prior.resolution_fingerprint != prepared.resolution_fingerprint
                && prior.artifact_path == expected_artifact
                && memo_artifact_is_healthy(prior, managed_root)
                && prior.canonical_ir_path.is_some()
        })
    });

    let mut session = NativeProbeSession::from_env();
    let (selected, reuse_help_evidence) = if let Some(prepared) = cached_help_reprocess {
        (Some(prepared.clone()), true)
    } else {
        let selectable = prepared
            .iter()
            .map(|prepared| prepared.plan.clone())
            .collect::<Vec<_>>();
        let selected_plan = match select_completion_command_plan(&selectable, &mut session) {
            Ok(selected) => selected,
            Err(error) => {
                return retain_or_record_failure(
                    item,
                    prior,
                    error,
                    managed_root,
                    candidates,
                    outcomes,
                    direct_records,
                );
            }
        };
        let selected = selected_plan.and_then(|selected| {
            prepared
                .iter()
                .find(|prepared| prepared.plan == selected)
                .cloned()
        });
        (selected, false)
    };
    let Some(selected) = selected else {
        let reason = preparation_error.unwrap_or_else(|| "command_unavailable".to_string());
        return retain_or_record_failure(
            item,
            prior,
            reason,
            managed_root,
            candidates,
            outcomes,
            direct_records,
        );
    };

    let native_origin = match item.metadata.origin {
        ToolOrigin::Registry => NativeCandidateOrigin::Managed,
        ToolOrigin::Ambient => NativeCandidateOrigin::Ambient,
    };
    let previous_recipe = prior
        .as_ref()
        .filter(|memo| memo.identity == selected.identity)
        .and_then(|memo| memo.successful_recipe.as_ref());
    let candidate_identity = serde_json::to_vec(&selected.identity)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| anyhow::anyhow!("encode completion candidate identity: {error}"))?;
    match generate_tool_completion_with_context(
        CompletionGenerationRequest {
            provider: &item.provider,
            tool: &item.tool,
            shell: CompletionShell::parse(&item.slot.shell)
                .map_err(|error| anyhow::anyhow!("invalid candidate shell: {error:#}"))?,
            rc_root,
            command: &selected.plan.command,
            provider_bin_dir: &item.provider_bin_dir,
            bundled_completions: &item.metadata.bundled_completions,
            catalog_recipes: &item.metadata.completion_recipes,
            previous_recipe,
            origin: native_origin,
            trust_dynamic: item.metadata.trust_dynamic,
        },
        CompletionGenerationContext {
            managed_root,
            candidate_identity: &candidate_identity,
            reuse_help_evidence,
            previous_canonical_ir: prior.as_ref().and_then(|memo| {
                memo.canonical_ir_path
                    .as_deref()
                    .zip(memo.canonical_ir_digest.as_deref())
            }),
        },
        &mut session,
    ) {
        Ok(Some(completion)) => {
            finish_probed_candidate(item, prior, selected, completion, candidates, outcomes)
        }
        Ok(None) => {
            if prior.is_none() && item.metadata.origin == ToolOrigin::Registry {
                if let Some(completion) = import_static_completion(rc_root, item)? {
                    return finish_probed_candidate(
                        item, prior, selected, completion, candidates, outcomes,
                    );
                }
            }
            retain_or_record_failure(
                item,
                prior,
                "unsupported_generator".to_string(),
                managed_root,
                candidates,
                outcomes,
                direct_records,
            )
        }
        Err(error) => retain_or_record_failure(
            item,
            prior,
            error,
            managed_root,
            candidates,
            outcomes,
            direct_records,
        ),
    }
}

fn prepare_plan(
    item: &InventoryCandidate,
    mut plan: CompletionCommandPlan,
    index: usize,
) -> std::result::Result<PreparedPlan, String> {
    let exact_executable = absolutize_existing_path(&plan.command.program)
        .ok_or_else(|| format!("executable_missing:{}", plan.command.program.display()))?;
    let executable_digest = sha256_file(&exact_executable)
        .map_err(|error| format!("executable_identity_failed:{error}"))?;
    let executable_dir = exact_executable
        .parent()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    let identity = CompletionCandidateIdentity {
        provider: item.provider.clone(),
        installation: format!("{};executable-dir={executable_dir}", item.installation),
        command_entry_point: item.binding.command.clone(),
        exact_executable: exact_executable.clone(),
        launch_argv: std::iter::once(exact_executable.display().to_string())
            .chain(plan.command.args.iter().cloned())
            .collect(),
        provider_native_identity: format!(
            "{};executable-sha256={executable_digest}",
            item.provider_native_seed
        ),
    };
    plan.command.program = exact_executable.clone();
    let shell = CompletionShell::parse(&item.slot.shell).map_err(|error| error.to_string())?;
    let bundled_artifact_fingerprint = provider_bundled_artifact_identity(
        shell,
        &item.binding.command,
        &plan.command,
        &item.provider_bin_dir,
        &item.metadata.bundled_completions,
    )?;
    let native_fingerprint_bytes = serde_json::to_vec(&serde_json::json!({
        "native_protocol_registry_version": NATIVE_PROTOCOL_REGISTRY_VERSION,
        "native_trust_classification_version": NATIVE_TRUST_CLASSIFICATION_VERSION,
        "shell": shell.as_event_name(),
        "index": index,
        "program": &exact_executable,
        "args": &plan.command.args,
        "selection_probe_args": &plan.selection_probe_args,
        "bundled_completions": &item.metadata.bundled_completions,
        "bundled_artifact_fingerprint": bundled_artifact_fingerprint,
        "completion_recipes": &item.metadata.completion_recipes,
        "trust_dynamic": item.metadata.trust_dynamic,
        "origin": match item.metadata.origin {
            ToolOrigin::Registry => "managed",
            ToolOrigin::Ambient => "ambient",
        },
    }))
    .map_err(|error| error.to_string())?;
    let native_resolution_fingerprint = sha256_hex(&native_fingerprint_bytes);
    let fingerprint_bytes = serde_json::to_vec(&serde_json::json!({
        "native_resolution_fingerprint": &native_resolution_fingerprint,
        "help_fallback": help_fallback_identity_components(),
    }))
    .map_err(|error| error.to_string())?;
    Ok(PreparedPlan {
        plan,
        identity,
        native_resolution_fingerprint,
        resolution_fingerprint: sha256_hex(&fingerprint_bytes),
    })
}

fn finish_probed_candidate(
    item: &InventoryCandidate,
    prior: Option<CompletionCandidateMemo>,
    selected: PreparedPlan,
    completion: GeneratedCompletion,
    candidates: &mut BTreeMap<CompletionCandidateSlot, CompletionCandidateMemo>,
    outcomes: &mut BTreeMap<CompletionCandidateSlot, CandidateOutcome>,
) -> Result<bool> {
    let artifact_digest = sha256_file(&completion.path)?;
    let identity_changed = prior.as_ref().is_some_and(|prior| {
        prior.identity != selected.identity
            || prior.resolution_fingerprint != selected.resolution_fingerprint
    });
    let same_canonical_completion = prior.as_ref().is_some_and(|prior| {
        match (
            prior.canonical_ir_digest.as_deref(),
            completion.canonical_ir_digest.as_deref(),
        ) {
            (Some(previous), Some(current)) => previous == current,
            (None, None) => prior.artifact_digest == artifact_digest,
            _ => false,
        }
    });
    let kind = if identity_changed && same_canonical_completion {
        CandidateOutcomeKind::ProbedUnchanged
    } else if completion.changed {
        CandidateOutcomeKind::Generated
    } else {
        CandidateOutcomeKind::Unchanged
    };
    let memo = CompletionCandidateMemo {
        slot: item.slot.clone(),
        binding: item.binding.clone(),
        identity: selected.identity,
        resolution_fingerprint: selected.resolution_fingerprint,
        native_resolution_fingerprint: Some(selected.native_resolution_fingerprint),
        artifact_path: completion.path,
        artifact_digest,
        canonical_ir_path: completion.canonical_ir_path,
        canonical_ir_digest: completion.canonical_ir_digest,
        artifact_classification: Some(completion.classification),
        successful_recipe: completion.native_recipe,
        priority: item.metadata.priority,
        managed_required: item.metadata.managed_required,
    };
    candidates.insert(item.slot.clone(), memo);
    outcomes.insert(item.slot.clone(), CandidateOutcome::new(kind));
    Ok(true)
}

fn retain_or_record_failure(
    item: &InventoryCandidate,
    prior: Option<CompletionCandidateMemo>,
    reason: String,
    managed_root: &Path,
    candidates: &mut BTreeMap<CompletionCandidateSlot, CompletionCandidateMemo>,
    outcomes: &mut BTreeMap<CompletionCandidateSlot, CandidateOutcome>,
    direct_records: &mut Vec<CompletionSyncRecord>,
) -> Result<bool> {
    if let Some(prior) = prior.filter(|memo| memo_artifact_is_healthy(memo, managed_root)) {
        candidates.insert(item.slot.clone(), prior);
        outcomes.insert(
            item.slot.clone(),
            CandidateOutcome::retained(reason.clone()),
        );
        if item.metadata.managed_required {
            direct_records.push(record_for_shell(
                CompletionSyncRecord::with_status(
                    &item.provider,
                    &item.tool,
                    CompletionSyncRecordStatus::Failed,
                    None,
                    Some(format!("managed_required:{reason}")),
                ),
                &item.slot.shell,
            ));
        }
        return Ok(false);
    }

    let status = if item.metadata.managed_required {
        CompletionSyncRecordStatus::Failed
    } else if reason == "unsupported_generator" || item.metadata.origin == ToolOrigin::Ambient {
        CompletionSyncRecordStatus::Skipped
    } else {
        CompletionSyncRecordStatus::Failed
    };
    let reason = if item.metadata.managed_required {
        format!("managed_required:{reason}")
    } else {
        reason
    };
    direct_records.push(record_for_shell(
        CompletionSyncRecord::with_status(&item.provider, &item.tool, status, None, Some(reason)),
        &item.slot.shell,
    ));
    Ok(false)
}

fn import_static_completion(
    rc_root: &Path,
    item: &InventoryCandidate,
) -> Result<Option<GeneratedCompletion>> {
    let shell = CompletionShell::parse(&item.slot.shell)?;
    if shell != CompletionShell::Zsh {
        return Ok(None);
    }
    let managed_dir = managed_completion_dir(rc_root);
    let static_path = managed_dir.join(format!("_{}", item.tool));
    let Some(payload) = read_usable_completion_payload(&static_path) else {
        return Ok(None);
    };
    fs::create_dir_all(&managed_dir)
        .with_context(|| format!("create managed completion dir {}", managed_dir.display()))?;
    let managed_path = expected_artifact_path(rc_root, item)?;
    let changed = write_bytes_if_changed(&managed_path, payload.as_bytes())
        .with_context(|| format!("write {}", managed_path.display()))?;
    Ok(Some(GeneratedCompletion {
        path: managed_path,
        changed,
        classification: CompletionArtifactClassification::Static,
        native_recipe: None,
        canonical_ir_path: None,
        canonical_ir_digest: None,
    }))
}

fn expected_artifact_path(rc_root: &Path, item: &InventoryCandidate) -> Result<PathBuf> {
    let shell = CompletionShell::parse(&item.slot.shell)?;
    Ok(
        managed_completion_dir(rc_root).join(candidate_payload_basename(
            shell,
            &item.provider,
            &item.tool,
        )),
    )
}

fn memo_artifact_is_healthy(memo: &CompletionCandidateMemo, managed_root: &Path) -> bool {
    let artifact_is_healthy = fs::read(&memo.artifact_path).is_ok_and(|bytes| {
        stored_artifact_is_healthy(&memo.binding.shell, &memo.binding.command, &bytes)
    }) && sha256_file(&memo.artifact_path)
        .is_ok_and(|digest| digest == memo.artifact_digest);
    let canonical_ir_is_healthy = match (
        memo.canonical_ir_path.as_deref(),
        memo.canonical_ir_digest.as_deref(),
    ) {
        (None, None) => true,
        (Some(path), Some(digest)) => canonical_help_ir_is_healthy(managed_root, path, digest),
        _ => false,
    };
    artifact_is_healthy && canonical_ir_is_healthy
}

fn record_inventory_failure(
    index: &CatalogIndex,
    provider: &str,
    reason: &str,
    records: &mut Vec<CompletionSyncRecord>,
) {
    let tools = index
        .enabled_by_provider
        .get(provider)
        .cloned()
        .unwrap_or_default();
    if tools.is_empty() {
        records.push(CompletionSyncRecord::with_status(
            provider,
            "provider_init",
            CompletionSyncRecordStatus::Skipped,
            None,
            Some(reason.to_string()),
        ));
        return;
    }
    for tool in tools {
        let metadata = metadata_for(index, provider, &tool);
        records.push(CompletionSyncRecord::with_status(
            provider,
            &tool,
            if metadata.managed_required {
                CompletionSyncRecordStatus::Failed
            } else {
                CompletionSyncRecordStatus::Skipped
            },
            None,
            Some(if metadata.managed_required {
                format!("managed_required:{reason}")
            } else {
                reason.to_string()
            }),
        ));
    }
}

fn activate_bindings(
    legacy_rc_root: Option<&Path>,
    managed_root: &Path,
    candidates: &BTreeMap<CompletionCandidateSlot, CompletionCandidateMemo>,
    previous_bindings: &BTreeMap<CompletionBindingIdentity, CompletionBindingMemo>,
    outcomes: &BTreeMap<CompletionCandidateSlot, CandidateOutcome>,
) -> Result<(Vec<CompletionBindingMemo>, Vec<CompletionSyncRecord>, usize)> {
    let mut grouped = BTreeMap::<CompletionBindingIdentity, Vec<&CompletionCandidateMemo>>::new();
    for memo in candidates.values() {
        grouped.entry(memo.binding.clone()).or_default().push(memo);
    }
    let mut all_bindings = grouped.keys().cloned().collect::<BTreeSet<_>>();
    all_bindings.extend(previous_bindings.keys().cloned());

    let mut next_bindings = Vec::new();
    let mut records = Vec::new();
    let mut activation_updates = 0usize;
    for binding in all_bindings {
        let mut binding_candidates = grouped.remove(&binding).unwrap_or_default();
        binding_candidates.sort_by(|left, right| left.slot.cmp(&right.slot));
        let healthy = binding_candidates
            .iter()
            .copied()
            .filter(|memo| memo_artifact_is_healthy(memo, managed_root))
            .collect::<Vec<_>>();
        let previous = previous_bindings.get(&binding);
        let path_winner = which(&binding.command);
        let winner = select_binding_winner(&healthy, previous, path_winner.as_deref());
        let overlay_changed = if let Some(winner) = winner {
            let changed = if let Some(rc_root) = legacy_rc_root {
                write_managed_overlay_shim(rc_root, &winner.slot.provider, &winner.binding.command)?
                    .changed
            } else {
                false
            };
            next_bindings.push(CompletionBindingMemo {
                binding: binding.clone(),
                active_candidate: winner.slot.clone(),
            });
            changed
        } else {
            legacy_rc_root
                .map(|rc_root| remove_managed_overlay_shim(rc_root, &binding.command))
                .transpose()?
                .unwrap_or(false)
        };
        let activation_only_update = match winner {
            Some(winner) => outcomes.get(&winner.slot).map_or(true, |outcome| {
                outcome.kind != CandidateOutcomeKind::Generated
            }),
            None => true,
        };
        if overlay_changed && activation_only_update {
            activation_updates += 1;
        }

        for memo in binding_candidates {
            let outcome = outcomes
                .get(&memo.slot)
                .cloned()
                .unwrap_or_else(|| CandidateOutcome::new(CandidateOutcomeKind::Reused));
            let is_winner = winner.is_some_and(|winner| winner.slot == memo.slot);
            if is_winner {
                let (status, reason) =
                    if overlay_changed && outcome.kind != CandidateOutcomeKind::Generated {
                        (
                            CompletionSyncRecordStatus::Generated,
                            Some("active_binding_changed".to_string()),
                        )
                    } else {
                        (outcome_status(outcome.kind), outcome.reason)
                    };
                records.push(record_for_shell(
                    CompletionSyncRecord::with_artifact_details(
                        &memo.slot.provider,
                        &binding.command,
                        status,
                        Some(&memo.artifact_path),
                        reason,
                        memo.artifact_classification,
                        memo.successful_recipe
                            .as_ref()
                            .map(|recipe| recipe.report_name()),
                    ),
                    &binding.shell,
                ));
            } else {
                let reason = if let Some(winner) = winner {
                    format!(
                        "shadowed_by:{}:{};candidate_status={}",
                        winner.slot.provider,
                        winner.identity.exact_executable.display(),
                        outcome_name(outcome.kind)
                    )
                } else if let Some(path) = &path_winner {
                    format!(
                        "shadowed_by_path:{};candidate_status={}",
                        path.display(),
                        outcome_name(outcome.kind)
                    )
                } else {
                    format!("shadowed;candidate_status={}", outcome_name(outcome.kind))
                };
                records.push(record_for_shell(
                    CompletionSyncRecord::with_artifact_details(
                        &memo.slot.provider,
                        &binding.command,
                        CompletionSyncRecordStatus::Shadowed,
                        Some(&memo.artifact_path),
                        Some(reason),
                        memo.artifact_classification,
                        memo.successful_recipe
                            .as_ref()
                            .map(|recipe| recipe.report_name()),
                    ),
                    &binding.shell,
                ));
            }
        }
    }
    Ok((next_bindings, records, activation_updates))
}

fn select_binding_winner<'a>(
    candidates: &[&'a CompletionCandidateMemo],
    previous: Option<&CompletionBindingMemo>,
    path_winner: Option<&Path>,
) -> Option<&'a CompletionCandidateMemo> {
    if candidates.is_empty() {
        return None;
    }
    if let Some(max_priority) = candidates.iter().filter_map(|memo| memo.priority).max() {
        let pool = candidates
            .iter()
            .copied()
            .filter(|memo| memo.priority == Some(max_priority))
            .collect::<Vec<_>>();
        return choose_from_pool(&pool, previous, path_winner);
    }
    if let Some(path_winner) = path_winner {
        let exact = candidates
            .iter()
            .copied()
            .filter(|memo| memo.identity.exact_executable == path_winner)
            .collect::<Vec<_>>();
        if !exact.is_empty() {
            return choose_from_pool(&exact, previous, Some(path_winner));
        }
        let canonical_winner = fs::canonicalize(path_winner).ok();
        let canonical = candidates
            .iter()
            .copied()
            .filter(|memo| {
                canonical_winner.as_ref().is_some_and(|winner| {
                    fs::canonicalize(&memo.identity.exact_executable)
                        .is_ok_and(|candidate| candidate == *winner)
                })
            })
            .collect::<Vec<_>>();
        if !canonical.is_empty() {
            return choose_from_pool(&canonical, previous, Some(path_winner));
        }
        return None;
    }
    choose_from_pool(candidates, previous, None)
}

fn choose_from_pool<'a>(
    candidates: &[&'a CompletionCandidateMemo],
    previous: Option<&CompletionBindingMemo>,
    path_winner: Option<&Path>,
) -> Option<&'a CompletionCandidateMemo> {
    if let Some(path_winner) = path_winner {
        if let Some(exact) = candidates
            .iter()
            .copied()
            .find(|memo| memo.identity.exact_executable == path_winner)
        {
            return Some(exact);
        }
    }
    if let Some(previous) = previous {
        if let Some(previous_candidate) = candidates
            .iter()
            .copied()
            .find(|memo| memo.slot == previous.active_candidate)
        {
            return Some(previous_candidate);
        }
    }
    candidates.first().copied()
}

fn prune_retired_candidate_artifacts(
    generation_root: &Path,
    candidates: &BTreeMap<CompletionCandidateSlot, CompletionCandidateMemo>,
    retired: &[(CompletionCandidateMemo, String)],
) -> Result<()> {
    let retained_paths = candidates
        .values()
        .map(|memo| memo.artifact_path.clone())
        .collect::<BTreeSet<_>>();
    let managed_dir = managed_completion_dir(generation_root);
    for (memo, _) in retired {
        if retained_paths.contains(&memo.artifact_path) {
            continue;
        }
        if memo.artifact_path.parent() != Some(managed_dir.as_path()) {
            continue;
        }
        let Some(name) = memo
            .artifact_path
            .file_name()
            .and_then(|value| value.to_str())
        else {
            continue;
        };
        if !name.starts_with("_managed_") {
            continue;
        }
        match fs::remove_file(&memo.artifact_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "remove retired completion candidate {}",
                        memo.artifact_path.display()
                    )
                });
            }
        }
    }
    Ok(())
}

fn push_inventory_event(events: &mut Vec<String>, inventory: &CompletionProviderInventoryRecord) {
    let status = match inventory.status {
        CompletionProviderInventoryStatus::Complete => "complete",
        CompletionProviderInventoryStatus::Partial => "partial",
        CompletionProviderInventoryStatus::Failed => "failed",
    };
    events.push(format!(
        "__UA_COMP_INVENTORY|{}|{}|candidates={}|reason={}",
        inventory.provider,
        status,
        inventory.candidates,
        inventory.reason.as_deref().unwrap_or("-")
    ));
}

fn record_for_shell(mut record: CompletionSyncRecord, shell: &str) -> CompletionSyncRecord {
    record.shell = Some(shell.to_string());
    record
}

fn push_record_event(events: &mut Vec<String>, record: &CompletionSyncRecord) {
    let artifact = record.artifact.as_deref().unwrap_or("-");
    let reason = record.reason.as_deref().unwrap_or("-");
    let classification = record
        .classification
        .map(CompletionArtifactClassification::as_str)
        .unwrap_or("-");
    let recipe = record.recipe.as_deref().unwrap_or("-");
    let tag = match record.status {
        CompletionSyncRecordStatus::Generated => "GENERATED",
        CompletionSyncRecordStatus::Unchanged => "UNCHANGED",
        CompletionSyncRecordStatus::ProbedUnchanged => "PROBED_UNCHANGED",
        CompletionSyncRecordStatus::Reused => "REUSED",
        CompletionSyncRecordStatus::Retained => "RETAINED",
        CompletionSyncRecordStatus::Shadowed => "SHADOWED",
        CompletionSyncRecordStatus::Retired => "RETIRED",
        CompletionSyncRecordStatus::Skipped => "SKIPPED",
        CompletionSyncRecordStatus::Failed => "FAILED",
    };
    events.push(format!(
        "__UA_COMP_{tag}|{}|{}|{}|{}|{}|classification={classification}|recipe={recipe}",
        record.provider,
        record.tool,
        record.shell.as_deref().unwrap_or("-"),
        artifact,
        reason
    ));
}

fn outcome_status(kind: CandidateOutcomeKind) -> CompletionSyncRecordStatus {
    match kind {
        CandidateOutcomeKind::Generated => CompletionSyncRecordStatus::Generated,
        CandidateOutcomeKind::Unchanged => CompletionSyncRecordStatus::Unchanged,
        CandidateOutcomeKind::ProbedUnchanged => CompletionSyncRecordStatus::ProbedUnchanged,
        CandidateOutcomeKind::Reused => CompletionSyncRecordStatus::Reused,
        CandidateOutcomeKind::Retained => CompletionSyncRecordStatus::Retained,
    }
}

fn outcome_name(kind: CandidateOutcomeKind) -> &'static str {
    match kind {
        CandidateOutcomeKind::Generated => "generated",
        CandidateOutcomeKind::Unchanged => "unchanged",
        CandidateOutcomeKind::ProbedUnchanged => "probed_unchanged",
        CandidateOutcomeKind::Reused => "reused",
        CandidateOutcomeKind::Retained => "retained",
    }
}

fn record_status_sort_key(status: CompletionSyncRecordStatus) -> u8 {
    match status {
        CompletionSyncRecordStatus::Generated => 0,
        CompletionSyncRecordStatus::ProbedUnchanged => 1,
        CompletionSyncRecordStatus::Reused => 2,
        CompletionSyncRecordStatus::Unchanged => 3,
        CompletionSyncRecordStatus::Retained => 4,
        CompletionSyncRecordStatus::Shadowed => 5,
        CompletionSyncRecordStatus::Retired => 6,
        CompletionSyncRecordStatus::Skipped => 7,
        CompletionSyncRecordStatus::Failed => 8,
    }
}

fn absolutize_existing_path(path: &Path) -> Option<PathBuf> {
    if !path.is_file() {
        return None;
    }
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    env::current_dir().ok().map(|current| current.join(path))
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::test_support::{env_guard, write_executable};
    use serde_json::{json, Value};
    use std::env;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
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

        fn remove(key: &'static str) -> Self {
            let old = env::var_os(key);
            env::remove_var(key);
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

    #[derive(Debug, PartialEq, Eq)]
    struct TreeEntry {
        path: PathBuf,
        kind: &'static str,
        mode: u32,
        inode: u64,
        len: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
        digest: Option<String>,
    }

    struct TestLayout {
        _temp: TempDir,
        catalog: PathBuf,
        config: PathBuf,
        rc_root: PathBuf,
        managed_root: PathBuf,
    }

    impl TestLayout {
        fn new() -> Self {
            let temp = TempDir::new().unwrap();
            let catalog = temp.path().join("managed-tools.json");
            let config = temp.path().join("config.toml");
            let rc_root = temp.path().join("rc");
            let managed_root = temp.path().join("managed-root");
            fs::write(&config, "").unwrap();
            fs::create_dir_all(&rc_root).unwrap();
            Self {
                _temp: temp,
                catalog,
                config,
                rc_root,
                managed_root,
            }
        }

        fn sync(&self, providers: &str, discover: bool) -> CompletionSyncResult {
            run_completion_sync(CompletionSyncArgs {
                providers_csv: providers.to_string(),
                discover,
                report: "compact".to_string(),
                catalog_path: self.catalog.clone(),
                config_path: Some(self.config.clone()),
                rc_root: Some(self.rc_root.clone()),
                managed_root: self.managed_root.clone(),
                shells: vec![CompletionShell::Zsh],
                progress_cb: None,
            })
            .unwrap()
        }

        fn sync_public(
            &self,
            providers: &str,
            discover: bool,
            shells: Vec<CompletionShell>,
        ) -> CompletionSyncResult {
            run_completion_sync(CompletionSyncArgs {
                providers_csv: providers.to_string(),
                discover,
                report: "compact".to_string(),
                catalog_path: self.catalog.clone(),
                config_path: Some(self.config.clone()),
                rc_root: None,
                managed_root: self.managed_root.clone(),
                shells,
                progress_cb: None,
            })
            .unwrap()
        }
    }

    fn clean_probe_environment() -> Vec<EnvVarGuard> {
        [
            "UPDATE_ALL_COMPLETION_PROVIDER_TIMEOUT",
            "UPDATE_ALL_COMPLETION_PROBE_TIMEOUT_MS",
            "UPDATE_ALL_COMPLETION_PROBE_HARD_TIMEOUT",
            "UPDATE_ALL_COMPLETION_TOTAL_TIMEOUT_MS",
            "UPDATE_ALL_COMPLETION_TOTAL_TIMEOUT",
            "UPDATE_ALL_COMPLETION_ATTEMPT_LIMIT",
            "UPDATE_ALL_COMPLETION_STDOUT_LIMIT",
            "UPDATE_ALL_COMPLETION_STDERR_LIMIT",
            "UPDATE_ALL_COMPLETION_HELP_DEPTH",
            "UPDATE_ALL_COMPLETION_HELP_PROBE_LIMIT",
        ]
        .into_iter()
        .map(EnvVarGuard::remove)
        .collect()
    }

    fn path_with_first(paths: &[&Path]) -> EnvVarGuard {
        let mut entries = paths
            .iter()
            .map(|path| path.to_path_buf())
            .collect::<Vec<_>>();
        if let Some(existing) = env::var_os("PATH") {
            entries.extend(env::split_paths(&existing));
        }
        EnvVarGuard::set("PATH", env::join_paths(entries).unwrap())
    }

    fn write_catalog(path: &Path, providers: &[&str], tools: Vec<Value>) {
        let providers = providers
            .iter()
            .map(|provider| json!({"name": provider, "enabled": true}))
            .collect::<Vec<_>>();
        fs::write(
            path,
            serde_json::to_vec_pretty(&json!({
                "schema_version": 1,
                "providers": providers,
                "tools": tools,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn configured_candidate(tool: &str, provider: &str, program: &Path, argv: &[&str]) -> Value {
        json!({
            "name": tool,
            "provider": provider,
            "enabled": true,
            "managed_required": true,
            "command_candidates": [{
                "program": program,
                "args": argv,
                "probe_args": [],
            }],
        })
    }

    fn explicit_command_candidate(
        tool: &str,
        provider: &str,
        program: &Path,
        priority: Option<i64>,
    ) -> Value {
        let mut value = json!({
            "name": tool,
            "provider": provider,
            "enabled": true,
            "managed_required": true,
            "command": program,
        });
        if let Some(priority) = priority {
            value["priority"] = json!(priority);
        }
        value
    }

    fn shell_single_quote(value: &Path) -> String {
        format!("'{}'", value.to_string_lossy().replace('\'', "'\\''"))
    }

    fn write_identity_runner(path: &Path, counter: &Path, fail_marker: &Path) {
        let script = r#"#!/bin/sh
set -eu
counter=@COUNTER@
fail_marker=@FAIL_MARKER@
if [ -e "$fail_marker" ]; then
  exit 97
fi
count=0
if [ -r "$counter" ]; then
  count=$(cat "$counter")
fi
count=$((count + 1))
printf '%s\n' "$count" > "$counter"
identity=${1:-}
if [ "$#" -gt 0 ]; then
  shift
fi
if [ "${1:-}" = "completion" ] && [ "${2:-}" = "zsh" ]; then
  cat <<'EOF'
#compdef demo
_demo() {
  _arguments '--stable[stable artifact]'
}
EOF
  exit 0
fi
if [ "${1:-}" = "--help" ]; then
  printf 'Usage: demo\n'
  exit 0
fi
printf 'unexpected identity=%s argv=%s\n' "$identity" "$*" >&2
exit 1
"#
        .replace("@COUNTER@", &shell_single_quote(counter))
        .replace("@FAIL_MARKER@", &shell_single_quote(fail_marker));
        write_executable(path, &script).unwrap();
    }

    fn write_help_identity_runner(path: &Path, counter: &Path, fail_marker: &Path) {
        let script = r#"#!/bin/sh
set -eu
counter=@COUNTER@
fail_marker=@FAIL_MARKER@
if [ -e "$fail_marker" ]; then
  exit 97
fi
count=0
if [ -r "$counter" ]; then
  count=$(cat "$counter")
fi
count=$((count + 1))
printf '%s\n' "$count" > "$counter"
identity=${1:-}
if [ "$#" -gt 0 ]; then
  shift
fi
if [ "$#" -eq 1 ] && [ "$1" = "--help" ]; then
  cat <<'EOF'
Usage: demo [OPTIONS]

Options:
  --format <FORMAT>  Output format [possible values: json, text]
  --verbose          Increase verbosity
EOF
  exit 0
fi
printf 'unsupported identity=%s argv=%s\n' "$identity" "$*" >&2
exit 1
"#
        .replace("@COUNTER@", &shell_single_quote(counter))
        .replace("@FAIL_MARKER@", &shell_single_quote(fail_marker));
        write_executable(path, &script).unwrap();
    }

    fn write_public_help_runner(path: &Path, counter: &Path, fail_marker: &Path) {
        let script = r#"#!/bin/sh
set -eu
counter=@COUNTER@
fail_marker=@FAIL_MARKER@
if [ -e "$fail_marker" ]; then
  exit 97
fi
count=0
if [ -r "$counter" ]; then
  count=$(cat "$counter")
fi
count=$((count + 1))
printf '%s\n' "$count" > "$counter"
case " $* " in
  *" --help "*)
    cat <<'EOF'
Usage: demo [OPTIONS]

Options:
  --format <FORMAT>  Output format [possible values: json, text]
EOF
    exit 0
    ;;
esac
exit 1
"#
        .replace("@COUNTER@", &shell_single_quote(counter))
        .replace("@FAIL_MARKER@", &shell_single_quote(fail_marker));
        write_executable(path, &script).unwrap();
    }

    fn write_native_command(path: &Path, command: &str, marker: &str) {
        let script = r#"#!/bin/sh
set -eu
if [ "${1:-}" = "completion" ] && [ "${2:-}" = "zsh" ]; then
  cat <<'EOF'
#compdef @COMMAND@
_@COMMAND@() {
  _arguments '--provider[@MARKER@]'
}
EOF
  exit 0
fi
if [ "${1:-}" = "--help" ]; then
  printf 'Usage: @COMMAND@\n'
  exit 0
fi
exit 1
"#
        .replace("@COMMAND@", command)
        .replace("@MARKER@", marker);
        write_executable(path, &script).unwrap();
    }

    fn read_counter(path: &Path) -> u64 {
        fs::read_to_string(path)
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0)
    }

    fn inventory_status(
        result: &CompletionSyncResult,
        provider: &str,
    ) -> CompletionProviderInventoryStatus {
        result
            .inventories
            .iter()
            .find(|inventory| inventory.provider == provider)
            .unwrap()
            .status
    }

    fn record_status(
        result: &CompletionSyncResult,
        provider: &str,
        tool: &str,
    ) -> CompletionSyncRecordStatus {
        result
            .records
            .iter()
            .find(|record| record.provider == provider && record.tool == tool)
            .unwrap_or_else(|| {
                panic!(
                    "missing completion record for {provider}/{tool}: {:#?}",
                    result.records
                )
            })
            .status
    }

    fn overlay_target(rc_root: &Path, command: &str) -> String {
        fs::read_to_string(
            rc_root
                .join("shell/completions-managed")
                .join(format!("_{command}")),
        )
        .unwrap()
    }

    fn tree_fingerprint(root: &Path, omit_identity_memo: bool) -> Vec<TreeEntry> {
        let mut entries = Vec::new();
        if omit_identity_memo {
            let mut children = fs::read_dir(root)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            children.sort();
            for child in children {
                collect_tree_entries(root, &child, true, &mut entries);
            }
        } else {
            collect_tree_entries(root, root, false, &mut entries);
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        entries
    }

    fn collect_tree_entries(
        root: &Path,
        path: &Path,
        omit_identity_memo: bool,
        entries: &mut Vec<TreeEntry>,
    ) {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("inspect {}: {error}", path.display()),
        };
        let relative = path.strip_prefix(root).unwrap().to_path_buf();
        if omit_identity_memo && relative == Path::new("identity-memo.json") {
            return;
        }
        let file_type = metadata.file_type();
        let kind = if file_type.is_dir() {
            "dir"
        } else if file_type.is_file() {
            "file"
        } else if file_type.is_symlink() {
            "symlink"
        } else {
            "other"
        };
        let digest = file_type
            .is_file()
            .then(|| sha256_hex(&fs::read(path).unwrap()));
        entries.push(TreeEntry {
            path: relative,
            kind,
            mode: metadata.mode(),
            inode: metadata.ino(),
            len: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
            digest,
        });
        if file_type.is_dir() {
            let mut children = fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            children.sort();
            for child in children {
                collect_tree_entries(root, &child, omit_identity_memo, entries);
            }
        }
    }

    #[test]
    fn identity_change_with_identical_artifact_updates_only_memo_then_reuses() {
        let _env = env_guard();
        let _probe_environment = clean_probe_environment();
        let layout = TestLayout::new();
        let bin = layout._temp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let runner = bin.join("demo");
        let counter = layout._temp.path().join("probe-count");
        let fail_marker = layout._temp.path().join("fail-if-probed");
        write_identity_runner(&runner, &counter, &fail_marker);
        let _path = path_with_first(&[&bin]);

        write_catalog(
            &layout.catalog,
            &["uv"],
            vec![configured_candidate("demo", "uv", &runner, &["A"])],
        );
        let first = layout.sync_public("uv", false, vec![CompletionShell::Zsh]);
        assert_eq!(
            record_status(&first, "uv", "demo"),
            CompletionSyncRecordStatus::Generated
        );
        assert!(read_counter(&counter) > 0);

        let memo_before = fs::read(layout.managed_root.join("identity-memo.json")).unwrap();
        let immutable_before = tree_fingerprint(&layout.managed_root, true);
        let current_before = fs::read(layout.managed_root.join("current")).unwrap();

        write_catalog(
            &layout.catalog,
            &["uv"],
            vec![configured_candidate("demo", "uv", &runner, &["B"])],
        );
        let second = layout.sync_public("uv", false, vec![CompletionShell::Zsh]);
        assert_eq!(
            record_status(&second, "uv", "demo"),
            CompletionSyncRecordStatus::ProbedUnchanged
        );
        assert_eq!(second.generated, 0);
        assert!(second.records.iter().all(|record| {
            record.status != CompletionSyncRecordStatus::Generated
                && record.status != CompletionSyncRecordStatus::Retired
        }));
        assert_eq!(
            immutable_before,
            tree_fingerprint(&layout.managed_root, true),
            "identity-only refresh mutated immutable managed-root publication data"
        );
        assert_eq!(
            current_before,
            fs::read(layout.managed_root.join("current")).unwrap()
        );
        let memo_after = fs::read(layout.managed_root.join("identity-memo.json")).unwrap();
        assert_ne!(memo_before, memo_after);
        let memo_json: Value = serde_json::from_slice(&memo_after).unwrap();
        assert!(memo_json["candidates"][0]["identity"]["launch_argv"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some("B")));

        fs::write(&fail_marker, "fail on probe\n").unwrap();
        let probes_before_third = read_counter(&counter);
        let root_before_third = tree_fingerprint(&layout.managed_root, false);
        let third = layout.sync_public("uv", false, vec![CompletionShell::Zsh]);
        assert_eq!(
            record_status(&third, "uv", "demo"),
            CompletionSyncRecordStatus::Reused
        );
        assert_eq!(read_counter(&counter), probes_before_third);
        assert_eq!(
            root_before_third,
            tree_fingerprint(&layout.managed_root, false)
        );
    }

    #[test]
    fn changed_help_identity_with_identical_canonical_ir_is_probed_unchanged_then_reused() {
        let _env = env_guard();
        let _probe_environment = clean_probe_environment();
        let layout = TestLayout::new();
        let bin = layout._temp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let runner = bin.join("demo");
        let counter = layout._temp.path().join("help-probe-count");
        let fail_marker = layout._temp.path().join("fail-if-help-probed");
        write_help_identity_runner(&runner, &counter, &fail_marker);
        let _path = path_with_first(&[&bin]);

        write_catalog(
            &layout.catalog,
            &["uv"],
            vec![configured_candidate("demo", "uv", &runner, &["A"])],
        );
        let first = layout.sync_public("uv", false, vec![CompletionShell::Zsh]);
        assert_eq!(
            record_status(&first, "uv", "demo"),
            CompletionSyncRecordStatus::Generated
        );
        assert!(read_counter(&counter) > 0);

        let memo_before = fs::read(layout.managed_root.join("identity-memo.json")).unwrap();
        let managed_before = tree_fingerprint(&layout.managed_root, true);
        let rc_before = tree_fingerprint(&layout.rc_root, false);

        write_catalog(
            &layout.catalog,
            &["uv"],
            vec![configured_candidate("demo", "uv", &runner, &["B"])],
        );
        let second = layout.sync_public("uv", false, vec![CompletionShell::Zsh]);
        assert_eq!(
            record_status(&second, "uv", "demo"),
            CompletionSyncRecordStatus::ProbedUnchanged
        );
        assert_eq!(second.generated, 0);
        assert_eq!(managed_before, tree_fingerprint(&layout.managed_root, true));
        assert_eq!(rc_before, tree_fingerprint(&layout.rc_root, false));
        let memo_after = fs::read(layout.managed_root.join("identity-memo.json")).unwrap();
        assert_ne!(memo_before, memo_after);

        let evidence_root = layout._temp.path().join(".managed-root-help-evidence");
        assert!(evidence_root.is_dir());
        fs::write(&fail_marker, "fail on probe\n").unwrap();
        let probes_before_third = read_counter(&counter);
        let managed_before_third = tree_fingerprint(&layout.managed_root, false);
        let rc_before_third = tree_fingerprint(&layout.rc_root, false);
        let evidence_before_third = tree_fingerprint(&evidence_root, false);
        let third = layout.sync_public("uv", false, vec![CompletionShell::Zsh]);
        assert_eq!(
            record_status(&third, "uv", "demo"),
            CompletionSyncRecordStatus::Reused
        );
        assert_eq!(read_counter(&counter), probes_before_third);
        assert_eq!(
            managed_before_third,
            tree_fingerprint(&layout.managed_root, false)
        );
        assert_eq!(rc_before_third, tree_fingerprint(&layout.rc_root, false));
        assert_eq!(
            evidence_before_third,
            tree_fingerprint(&evidence_root, false)
        );
    }

    #[test]
    fn partial_inventory_retains_absent_binding_until_complete_inventory_retires_it() {
        let _env = env_guard();
        let _probe_environment = clean_probe_environment();
        let layout = TestLayout::new();
        let bin = layout._temp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let mode = layout._temp.path().join("inventory-mode");
        let uv = bin.join("uv");
        let uv_script = r#"#!/bin/sh
set -eu
mode=$(cat @MODE@)
if [ "${1:-}" = "tool" ] && [ "${2:-}" = "list" ] && [ "${3:-}" = "--json" ]; then
  case "$mode" in
    complete_ab)
      printf '%s\n' '{"tools":[{"name":"a","version":"1"},{"name":"b","version":"1"}]}'
      ;;
    partial_a)
      printf '%s\n' 'not-json'
      ;;
    complete_a)
      printf '%s\n' '{"tools":[{"name":"a","version":"1"}]}'
      ;;
    *)
      exit 2
      ;;
  esac
  exit 0
fi
if [ "${1:-}" = "tool" ] && [ "${2:-}" = "list" ]; then
  if [ "$mode" = "partial_a" ]; then
    printf '%s\n' 'a 1.0'
    exit 0
  fi
fi
exit 2
"#
        .replace("@MODE@", &shell_single_quote(&mode));
        write_executable(&uv, &uv_script).unwrap();
        write_native_command(&bin.join("a"), "a", "a");
        write_native_command(&bin.join("b"), "b", "b");
        let _path = path_with_first(&[&bin]);
        write_catalog(
            &layout.catalog,
            &["uv"],
            vec![
                json!({
                    "name": "a",
                    "provider": "uv",
                    "enabled": true,
                    "ambient": true,
                    "trust_dynamic": true,
                }),
                json!({
                    "name": "b",
                    "provider": "uv",
                    "enabled": true,
                    "ambient": true,
                    "trust_dynamic": true,
                }),
            ],
        );

        fs::write(&mode, "complete_ab\n").unwrap();
        let first = layout.sync("uv", true);
        assert_eq!(
            inventory_status(&first, "uv"),
            CompletionProviderInventoryStatus::Complete
        );
        assert!(layout
            .rc_root
            .join("shell/completions/_managed_uv_b")
            .is_file());
        assert!(layout
            .rc_root
            .join("shell/completions-managed/_b")
            .is_file());

        fs::write(&mode, "partial_a\n").unwrap();
        let second = layout.sync("uv", true);
        assert_eq!(
            inventory_status(&second, "uv"),
            CompletionProviderInventoryStatus::Partial
        );
        assert_eq!(
            record_status(&second, "uv", "b"),
            CompletionSyncRecordStatus::Retained
        );
        assert!(!second.records.iter().any(|record| {
            record.provider == "uv"
                && record.tool == "b"
                && record.status == CompletionSyncRecordStatus::Retired
        }));
        assert!(layout
            .rc_root
            .join("shell/completions/_managed_uv_b")
            .is_file());
        assert!(layout
            .rc_root
            .join("shell/completions-managed/_b")
            .is_file());

        fs::write(&mode, "complete_a\n").unwrap();
        let third = layout.sync("uv", true);
        assert_eq!(
            inventory_status(&third, "uv"),
            CompletionProviderInventoryStatus::Complete
        );
        assert_eq!(
            record_status(&third, "uv", "b"),
            CompletionSyncRecordStatus::Retired
        );
        assert!(!layout
            .rc_root
            .join("shell/completions/_managed_uv_b")
            .exists());
        assert!(!layout.rc_root.join("shell/completions-managed/_b").exists());
    }

    #[test]
    fn same_binding_uses_path_winner_and_reports_other_provider_shadowed() {
        let _env = env_guard();
        let _probe_environment = clean_probe_environment();
        let layout = TestLayout::new();
        let path_bin = layout._temp.path().join("path-bin");
        let uv_bin = layout._temp.path().join("uv-bin");
        fs::create_dir_all(&path_bin).unwrap();
        fs::create_dir_all(&uv_bin).unwrap();
        let path_demo = path_bin.join("demo");
        let uv_demo = uv_bin.join("demo");
        write_native_command(&path_demo, "demo", "path");
        write_native_command(&uv_demo, "demo", "uv");
        let _path = path_with_first(&[&uv_bin, &path_bin]);
        write_catalog(
            &layout.catalog,
            &["path", "uv"],
            vec![
                explicit_command_candidate("demo", "path", &path_demo, None),
                explicit_command_candidate("demo", "uv", &uv_demo, None),
            ],
        );

        let result = layout.sync("path,uv", false);
        assert_eq!(
            record_status(&result, "path", "demo"),
            CompletionSyncRecordStatus::Shadowed
        );
        assert_eq!(
            record_status(&result, "uv", "demo"),
            CompletionSyncRecordStatus::Generated
        );
        assert!(!result
            .records
            .iter()
            .any(|record| record.status == CompletionSyncRecordStatus::Failed));
        let overlay = overlay_target(&layout.rc_root, "demo");
        assert!(overlay.contains("# update-all-managed-target: _managed_uv_demo"));
        assert!(layout
            .rc_root
            .join("shell/completions/_managed_path_demo")
            .is_file());
        assert!(layout
            .rc_root
            .join("shell/completions/_managed_uv_demo")
            .is_file());
    }

    #[test]
    fn explicit_priority_overrides_path_without_treating_loser_as_error() {
        let _env = env_guard();
        let _probe_environment = clean_probe_environment();
        let layout = TestLayout::new();
        let path_bin = layout._temp.path().join("path-bin");
        let uv_bin = layout._temp.path().join("uv-bin");
        fs::create_dir_all(&path_bin).unwrap();
        fs::create_dir_all(&uv_bin).unwrap();
        let path_demo = path_bin.join("demo");
        let uv_demo = uv_bin.join("demo");
        write_native_command(&path_demo, "demo", "path");
        write_native_command(&uv_demo, "demo", "uv");
        let _path = path_with_first(&[&uv_bin, &path_bin]);
        write_catalog(
            &layout.catalog,
            &["path", "uv"],
            vec![
                explicit_command_candidate("demo", "path", &path_demo, Some(100)),
                explicit_command_candidate("demo", "uv", &uv_demo, None),
            ],
        );

        let result = layout.sync("path,uv", false);
        assert_eq!(
            record_status(&result, "path", "demo"),
            CompletionSyncRecordStatus::Generated
        );
        assert_eq!(
            record_status(&result, "uv", "demo"),
            CompletionSyncRecordStatus::Shadowed
        );
        assert!(!result
            .records
            .iter()
            .any(|record| record.status == CompletionSyncRecordStatus::Failed));
        let overlay = overlay_target(&layout.rc_root, "demo");
        assert!(overlay.contains("# update-all-managed-target: _managed_path_demo"));
    }

    #[test]
    fn bundled_artifact_presence_and_content_change_invalidate_reuse_then_stabilize() {
        let _env = env_guard();
        let _probe_environment = clean_probe_environment();
        let layout = TestLayout::new();
        let bin = layout._temp.path().join("bin");
        let completions = bin.join("completions");
        fs::create_dir_all(&completions).unwrap();
        let runner = bin.join("demo");
        let counter = layout._temp.path().join("probe-count");
        let fail_marker = layout._temp.path().join("fail-if-probed");
        write_identity_runner(&runner, &counter, &fail_marker);
        let bundled = completions.join("demo.zsh");
        let _path = path_with_first(&[&bin]);
        let mut candidate = configured_candidate("demo", "uv", &runner, &["A"]);
        candidate["bundled_completions"] = json!([{
            "shell": "zsh",
            "path": "completions/demo.zsh",
            "id": "provider-zsh",
        }]);
        write_catalog(&layout.catalog, &["uv"], vec![candidate]);

        let artifact_x = "#compdef demo\n_demo() {\n  _arguments '--stable[stable artifact]'\n}\n";
        let artifact_y = "#compdef demo\n_demo() {\n  _arguments '--mutate[mutate artifact]'\n}\n";
        assert_eq!(
            artifact_x.len(),
            artifact_y.len(),
            "the content-change regression must not be satisfiable by hashing file length alone"
        );

        let first = layout.sync_public("uv", false, vec![CompletionShell::Zsh]);
        assert_eq!(
            record_status(&first, "uv", "demo"),
            CompletionSyncRecordStatus::Generated
        );
        let probes_after_first = read_counter(&counter);
        assert!(probes_after_first > 0);
        let artifact_path = first
            .records
            .iter()
            .find(|record| record.provider == "uv" && record.tool == "demo")
            .and_then(|record| record.artifact.as_deref())
            .map(PathBuf::from)
            .unwrap();
        assert_eq!(fs::read_to_string(&artifact_path).unwrap(), artifact_x);

        let immutable_before_presence = tree_fingerprint(&layout.managed_root, true);
        let rc_before_presence = tree_fingerprint(&layout.rc_root, false);
        let current_before_presence = fs::read(layout.managed_root.join("current")).unwrap();
        let memo_before_presence =
            fs::read(layout.managed_root.join("identity-memo.json")).unwrap();
        fs::write(&bundled, artifact_x).unwrap();

        let second = layout.sync_public("uv", false, vec![CompletionShell::Zsh]);
        assert_eq!(
            record_status(&second, "uv", "demo"),
            CompletionSyncRecordStatus::ProbedUnchanged,
            "a missing bundled artifact becoming present must invalidate strong reuse"
        );
        assert_eq!(second.generated, 0);
        assert_eq!(read_counter(&counter), probes_after_first);
        assert_eq!(
            immutable_before_presence,
            tree_fingerprint(&layout.managed_root, true)
        );
        assert_eq!(rc_before_presence, tree_fingerprint(&layout.rc_root, false));
        assert_eq!(
            current_before_presence,
            fs::read(layout.managed_root.join("current")).unwrap()
        );
        assert_ne!(
            memo_before_presence,
            fs::read(layout.managed_root.join("identity-memo.json")).unwrap()
        );

        fs::write(&fail_marker, "fail on process probe\n").unwrap();
        let managed_before_third = tree_fingerprint(&layout.managed_root, false);
        let rc_before_third = tree_fingerprint(&layout.rc_root, false);
        let third = layout.sync_public("uv", false, vec![CompletionShell::Zsh]);
        assert_eq!(
            record_status(&third, "uv", "demo"),
            CompletionSyncRecordStatus::Reused
        );
        assert_eq!(read_counter(&counter), probes_after_first);
        assert_eq!(
            managed_before_third,
            tree_fingerprint(&layout.managed_root, false)
        );
        assert_eq!(rc_before_third, tree_fingerprint(&layout.rc_root, false));

        fs::write(&bundled, artifact_y).unwrap();
        let fourth = layout.sync_public("uv", false, vec![CompletionShell::Zsh]);
        assert_eq!(
            record_status(&fourth, "uv", "demo"),
            CompletionSyncRecordStatus::Generated,
            "same-path bundled content changes must invalidate strong reuse"
        );
        assert_eq!(read_counter(&counter), probes_after_first);
        assert_eq!(fs::read_to_string(&artifact_path).unwrap(), artifact_y);

        let managed_before_fifth = tree_fingerprint(&layout.managed_root, false);
        let rc_before_fifth = tree_fingerprint(&layout.rc_root, false);
        let fifth = layout.sync_public("uv", false, vec![CompletionShell::Zsh]);
        assert_eq!(
            record_status(&fifth, "uv", "demo"),
            CompletionSyncRecordStatus::Reused
        );
        assert_eq!(read_counter(&counter), probes_after_first);
        assert_eq!(
            managed_before_fifth,
            tree_fingerprint(&layout.managed_root, false)
        );
        assert_eq!(rc_before_fifth, tree_fingerprint(&layout.rc_root, false));
    }

    #[test]
    fn second_unchanged_run_performs_zero_probes_and_zero_managed_root_mutation() {
        let _env = env_guard();
        let _probe_environment = clean_probe_environment();
        let layout = TestLayout::new();
        let bin = layout._temp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let runner = bin.join("demo");
        let counter = layout._temp.path().join("probe-count");
        let fail_marker = layout._temp.path().join("unused-fail-marker");
        write_identity_runner(&runner, &counter, &fail_marker);
        let _path = path_with_first(&[&bin]);
        write_catalog(
            &layout.catalog,
            &["uv"],
            vec![configured_candidate("demo", "uv", &runner, &["A"])],
        );

        let first = layout.sync("uv", false);
        assert_eq!(
            record_status(&first, "uv", "demo"),
            CompletionSyncRecordStatus::Generated
        );
        let probes_after_first = read_counter(&counter);
        let managed_before = tree_fingerprint(&layout.managed_root, false);
        let rc_before = tree_fingerprint(&layout.rc_root, false);
        assert!(!layout.managed_root.join(".sync.lock").exists());

        let second = layout.sync("uv", false);
        assert_eq!(
            record_status(&second, "uv", "demo"),
            CompletionSyncRecordStatus::Reused
        );
        assert_eq!(read_counter(&counter), probes_after_first);
        assert_eq!(
            managed_before,
            tree_fingerprint(&layout.managed_root, false)
        );
        assert_eq!(rc_before, tree_fingerprint(&layout.rc_root, false));
        assert!(!layout.managed_root.join(".sync.lock").exists());
        assert!(second
            .events
            .iter()
            .all(|event| !event.starts_with("__UA_COMP_PUBLIC|")));
    }

    #[test]
    fn public_sync_publishes_active_bindings_for_all_five_shells_then_is_probe_free() {
        let _env = env_guard();
        let _probe_environment = clean_probe_environment();
        let layout = TestLayout::new();
        let bin = layout._temp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let runner = bin.join("demo");
        let counter = layout._temp.path().join("probe-count");
        let fail_marker = layout._temp.path().join("fail-if-probed");
        write_public_help_runner(&runner, &counter, &fail_marker);
        let _path = path_with_first(&[&bin]);
        write_catalog(
            &layout.catalog,
            &["path"],
            vec![configured_candidate("demo", "path", &runner, &[])],
        );

        let rc_before = tree_fingerprint(&layout.rc_root, false);
        let shells = CompletionShell::all().to_vec();
        let first = layout.sync_public("path", false, shells.clone());
        assert_eq!(first.outcome, CompletionSyncOutcome::Published);
        let status = crate::completions::ManagedCompletionRoot::new(layout.managed_root.clone())
            .unwrap()
            .status()
            .unwrap();
        assert_eq!(status.available_shells.len(), 5);
        assert_eq!(status.active_bindings.len(), 5);
        let snapshot = status.current_snapshot.unwrap();
        for shell in shells {
            let path = layout
                .managed_root
                .join("snapshots")
                .join(&snapshot)
                .join("views")
                .join(shell.as_event_name())
                .join(shell.view_file_name());
            let payload = fs::read_to_string(path).unwrap();
            assert!(payload.contains("update-all managed binding: demo@path"));
            assert!(
                stored_artifact_is_healthy(shell.as_event_name(), "demo", payload.as_bytes()),
                "published aggregate failed validation for {}",
                shell.as_event_name()
            );
        }
        assert_eq!(rc_before, tree_fingerprint(&layout.rc_root, false));

        fs::write(&fail_marker, "fail on unexpected probe\n").unwrap();
        let probes = read_counter(&counter);
        let before = tree_fingerprint(&layout.managed_root, false);
        let second = layout.sync_public("path", false, CompletionShell::all().to_vec());
        assert_eq!(second.outcome, CompletionSyncOutcome::Reused);
        assert_eq!(read_counter(&counter), probes);
        assert_eq!(before, tree_fingerprint(&layout.managed_root, false));
    }
}
