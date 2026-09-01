mod generator;
pub(crate) mod registry;
mod store;

use crate::completions::generator::{
    generate_tool_completion, write_bytes_if_changed, GeneratedCompletion,
};
use crate::completions::registry::{Registry, RegistryCommandCandidate, RegistryTool};
use crate::completions::store::{
    CompletionSnapshotPublishOutcome, ManagedCompletionRoot, ManagedCompletionRootStatus,
};
use crate::config::{load_runtime_config, merge_user_completion_catalog};
use anyhow::{Context, Result};
use clap::CommandFactory;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::util::cancel;
use crate::util::process::{run_capture, which};
use std::process::Command;

const MANAGED_OVERLAY_MARKER: &str = "# managed by update-all; overlay shim";
const POWERSHELL_SELF_COMPLETION_FILE: &str = "update-all.generated.ps1";

#[derive(Clone)]
pub struct CompletionSyncArgs {
    pub providers_csv: String,
    pub discover: bool,
    pub report: String,
    pub catalog_path: PathBuf,
    pub config_path: Option<PathBuf>,
    pub rc_root: PathBuf,
    pub managed_root: PathBuf,
    pub progress_cb: Option<Arc<dyn Fn(String) + Send + Sync>>,
}

#[derive(Debug)]
pub struct CompletionSyncResult {
    pub generated: usize,
    pub unchanged: usize,
    pub skipped: usize,
    pub events: Vec<String>,
    pub records: Vec<CompletionSyncRecord>,
    pub catalog_used: PathBuf,
    pub effective_catalog: Registry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionSyncRecord {
    pub provider: String,
    pub tool: String,
    pub status: CompletionSyncRecordStatus,
    pub artifact: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionSyncRecordStatus {
    Generated,
    Unchanged,
    Skipped,
    Failed,
}

impl CompletionSyncRecord {
    fn generated(provider: &str, tool: &str, artifact: &Path) -> Self {
        Self {
            provider: provider.to_string(),
            tool: tool.to_string(),
            status: CompletionSyncRecordStatus::Generated,
            artifact: Some(artifact.display().to_string()),
            reason: None,
        }
    }

    fn unchanged(provider: &str, tool: &str, artifact: &Path) -> Self {
        Self {
            provider: provider.to_string(),
            tool: tool.to_string(),
            status: CompletionSyncRecordStatus::Unchanged,
            artifact: Some(artifact.display().to_string()),
            reason: Some("unchanged".to_string()),
        }
    }

    fn skipped(provider: &str, tool: &str, reason: impl Into<String>) -> Self {
        Self {
            provider: provider.to_string(),
            tool: tool.to_string(),
            status: CompletionSyncRecordStatus::Skipped,
            artifact: None,
            reason: Some(reason.into()),
        }
    }

    fn failed(provider: &str, tool: &str, reason: impl Into<String>) -> Self {
        Self {
            provider: provider.to_string(),
            tool: tool.to_string(),
            status: CompletionSyncRecordStatus::Failed,
            artifact: None,
            reason: Some(reason.into()),
        }
    }
}

#[derive(Clone)]
pub struct CompletionInstallArgs {
    pub shell: String,
    pub rc_root: PathBuf,
    pub powershell_root: Option<PathBuf>,
}

#[derive(Debug)]
pub struct CompletionInstallResult {
    pub events: Vec<String>,
}

#[derive(Clone)]
pub struct CompletionApplyArgs {
    pub shell: String,
    pub rc_root: PathBuf,
    pub powershell_root: Option<PathBuf>,
    pub registry_path: PathBuf,
    pub managed_catalog_path: Option<PathBuf>,
    pub discover: bool,
    pub audit_mode: String,
}

#[derive(Debug)]
pub struct CompletionApplyResult {
    pub events: Vec<String>,
}

#[derive(Debug)]
pub struct CompletionInitResult {
    pub shell_code: String,
}

#[derive(Debug)]
pub struct CompletionStatusResult {
    pub status: ManagedCompletionRootStatus,
}

#[derive(Debug)]
struct CompletionApplyFailure {
    events: Vec<String>,
}

impl fmt::Display for CompletionApplyFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, event) in self.events.iter().enumerate() {
            if idx > 0 {
                f.write_str("\n")?;
            }
            f.write_str(event)?;
        }
        Ok(())
    }
}

impl std::error::Error for CompletionApplyFailure {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolOrigin {
    Registry,
    Ambient,
}

fn tool_key(provider: &str, tool: &str) -> (String, String) {
    (provider.to_string(), tool.to_string())
}

fn completion_provider_progress(
    provider: &str,
    probed: usize,
    total: usize,
    generated: usize,
    unchanged: usize,
    skipped: usize,
    elapsed: Duration,
) -> String {
    format!(
        "completion-sync {provider}: probed {probed}/{total} generated={generated} unchanged={unchanged} skipped={skipped} elapsed={}s",
        elapsed.as_secs()
    )
}

fn completion_provider_no_configured_tools(provider: &str) -> String {
    format!("completion-sync {provider}: no configured tools (discover=0)")
}

#[derive(Clone, Debug, Default)]
struct CompletionCommandMetadata {
    command: Option<String>,
    command_candidates: Vec<RegistryCommandCandidate>,
}

fn managed_required_reason(reason: &str, required: bool) -> String {
    if required {
        format!("managed_required:{reason}")
    } else {
        reason.to_string()
    }
}

fn tool_is_managed_required(
    managed_required_tools: &BTreeSet<(String, String)>,
    provider: &str,
    tool: &str,
) -> bool {
    managed_required_tools.contains(&tool_key(provider, tool))
}

fn provider_has_managed_required(
    managed_required_tools: &BTreeSet<(String, String)>,
    provider: &str,
) -> bool {
    managed_required_tools
        .iter()
        .any(|(required_provider, _)| required_provider == provider)
}

fn completion_record_from_skip(provider: &str, tool: &str, reason: &str) -> CompletionSyncRecord {
    if reason.starts_with("managed_required:") {
        CompletionSyncRecord::failed(provider, tool, reason)
    } else if tool == "provider_init"
        || reason == "unsupported_generator"
        || reason.starts_with("provider_init:")
    {
        CompletionSyncRecord::skipped(provider, tool, reason)
    } else {
        CompletionSyncRecord::failed(provider, tool, reason)
    }
}

fn push_completion_generated(
    events: &mut Vec<String>,
    records: &mut Vec<CompletionSyncRecord>,
    provider: &str,
    tool: &str,
    artifact: &Path,
) {
    events.push(format!(
        "__UA_COMP_GENERATED|{provider}|{tool}|{}",
        artifact.display()
    ));
    records.push(CompletionSyncRecord::generated(provider, tool, artifact));
}

fn push_completion_unchanged(
    events: &mut Vec<String>,
    records: &mut Vec<CompletionSyncRecord>,
    provider: &str,
    tool: &str,
    artifact: &Path,
) {
    events.push(format!(
        "__UA_COMP_UNCHANGED|{provider}|{tool}|{}",
        artifact.display()
    ));
    records.push(CompletionSyncRecord::unchanged(provider, tool, artifact));
}

fn push_completion_skipped(
    events: &mut Vec<String>,
    records: &mut Vec<CompletionSyncRecord>,
    provider: &str,
    tool: &str,
    reason: impl Into<String>,
) {
    let reason = reason.into();
    events.push(format!("__UA_COMP_SKIPPED|{provider}|{tool}|{reason}"));
    records.push(completion_record_from_skip(provider, tool, &reason));
}

fn push_provider_init_skips(
    events: &mut Vec<String>,
    records: &mut Vec<CompletionSyncRecord>,
    tools_by_provider: &BTreeMap<String, BTreeSet<String>>,
    managed_required_tools: &BTreeSet<(String, String)>,
    provider: &str,
    reason: &str,
    compact_reason: &str,
    report: &str,
) -> usize {
    if report != "json" {
        events.push(format!("{provider}:provider_init:{compact_reason}"));
    }

    let configured_tools = tools_by_provider.get(provider).cloned().unwrap_or_default();
    if configured_tools.is_empty() {
        let reason = managed_required_reason(
            reason,
            provider_has_managed_required(managed_required_tools, provider),
        );
        push_completion_skipped(events, records, provider, "provider_init", reason);
        return 1;
    }

    let mut count = 0usize;
    for tool in configured_tools {
        let required = tool_is_managed_required(managed_required_tools, provider, &tool);
        let reason = managed_required_reason(reason, required);
        events.push(format!("__UA_COMP_SKIPPED|{provider}|{tool}|{reason}"));
        if required {
            records.push(CompletionSyncRecord::failed(provider, &tool, reason));
        } else {
            records.push(CompletionSyncRecord::skipped(provider, &tool, reason));
        }
        count += 1;
    }
    count
}

fn finish_generated_completion(
    rc_root: &Path,
    events: &mut Vec<String>,
    records: &mut Vec<CompletionSyncRecord>,
    keep_by_provider: &mut BTreeMap<String, BTreeSet<String>>,
    generated: &mut usize,
    unchanged: &mut usize,
    provider: &str,
    tool: &str,
    completion: GeneratedCompletion,
) -> Result<()> {
    let overlay = write_managed_overlay_shim(rc_root, provider, tool)?;
    keep_by_provider
        .entry(provider.to_string())
        .or_default()
        .insert(tool.to_string());
    if completion.changed || overlay.changed {
        *generated += 1;
        push_completion_generated(events, records, provider, tool, &completion.path);
    } else {
        *unchanged += 1;
        push_completion_unchanged(events, records, provider, tool, &completion.path);
    }
    Ok(())
}

fn finish_existing_completion_if_available(
    rc_root: &Path,
    events: &mut Vec<String>,
    records: &mut Vec<CompletionSyncRecord>,
    keep_by_provider: &mut BTreeMap<String, BTreeSet<String>>,
    generated: &mut usize,
    unchanged: &mut usize,
    provider: &str,
    tool: &str,
) -> Result<bool> {
    let Some(completion) = existing_completion_payload(rc_root, provider, tool)? else {
        return Ok(false);
    };
    finish_generated_completion(
        rc_root,
        events,
        records,
        keep_by_provider,
        generated,
        unchanged,
        provider,
        tool,
        completion,
    )?;
    Ok(true)
}

fn existing_completion_payload(
    rc_root: &Path,
    provider: &str,
    tool: &str,
) -> Result<Option<GeneratedCompletion>> {
    let managed_dir = managed_completion_dir(rc_root);
    let managed_path = managed_dir.join(managed_payload_basename(provider, tool));
    if usable_completion_payload_file(&managed_path) {
        return Ok(Some(GeneratedCompletion {
            path: managed_path,
            changed: false,
        }));
    }

    let static_path = managed_dir.join(format!("_{tool}"));
    let Some(payload) = read_usable_completion_payload(&static_path) else {
        return Ok(None);
    };
    fs::create_dir_all(&managed_dir)
        .with_context(|| format!("create managed completion dir {}", managed_dir.display()))?;
    let changed = write_bytes_if_changed(&managed_path, payload.as_bytes())
        .with_context(|| format!("write {}", managed_path.display()))?;
    Ok(Some(GeneratedCompletion {
        path: managed_path,
        changed,
    }))
}

fn usable_completion_payload_file(path: &Path) -> bool {
    read_usable_completion_payload(path).is_some()
}

fn read_usable_completion_payload(path: &Path) -> Option<String> {
    let payload = fs::read_to_string(path).ok()?;
    usable_completion_payload(&payload).then_some(payload)
}

fn usable_completion_payload(payload: &str) -> bool {
    let trimmed = payload.trim();
    !trimmed.is_empty()
        && (trimmed.contains("#compdef")
            || trimmed.contains("_arguments")
            || trimmed.starts_with("compdef ")
            || trimmed.contains("\ncompdef "))
}

fn enabled_catalog_tool(
    tools_by_provider: &BTreeMap<String, BTreeSet<String>>,
    provider: &str,
    tool: &str,
) -> bool {
    tools_by_provider
        .get(provider)
        .is_some_and(|tools| tools.contains(tool))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CompletionShell {
    Bash,
    Elvish,
    Fish,
    Zsh,
    PowerShell,
}

impl CompletionShell {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "bash" => Ok(Self::Bash),
            "elvish" => Ok(Self::Elvish),
            "fish" => Ok(Self::Fish),
            "zsh" => Ok(Self::Zsh),
            "powershell" | "pwsh" | "ps1" => Ok(Self::PowerShell),
            other => anyhow::bail!(
                "unsupported shell '{}' (supported: bash, elvish, fish, zsh, powershell)",
                other
            ),
        }
    }

    pub(crate) fn as_event_name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Elvish => "elvish",
            Self::Fish => "fish",
            Self::Zsh => "zsh",
            Self::PowerShell => "powershell",
        }
    }

    pub(crate) fn view_file_name(self) -> &'static str {
        match self {
            Self::Bash => "update-all.bash",
            Self::Elvish => "update-all.elv",
            Self::Fish => "update-all.fish",
            Self::Zsh => "_update-all",
            Self::PowerShell => "update-all.ps1",
        }
    }
}

pub fn generate_update_all_completion(shell: &str) -> Result<String> {
    let shell = CompletionShell::parse(shell)?;
    let mut command = crate::cli::RunCli::command();
    let mut out = Vec::new();

    match shell {
        CompletionShell::Bash => clap_complete::generate(
            clap_complete::shells::Bash,
            &mut command,
            "update-all",
            &mut out,
        ),
        CompletionShell::Elvish => clap_complete::generate(
            clap_complete::shells::Elvish,
            &mut command,
            "update-all",
            &mut out,
        ),
        CompletionShell::Fish => clap_complete::generate(
            clap_complete::shells::Fish,
            &mut command,
            "update-all",
            &mut out,
        ),
        CompletionShell::Zsh => clap_complete::generate(
            clap_complete::shells::Zsh,
            &mut command,
            "update-all",
            &mut out,
        ),
        CompletionShell::PowerShell => clap_complete::generate(
            clap_complete::shells::PowerShell,
            &mut command,
            "update-all",
            &mut out,
        ),
    }

    String::from_utf8(out).context("encode update-all completion output")
}

pub fn completion_sync(args: CompletionSyncArgs) -> Result<CompletionSyncResult> {
    let registry_text = fs::read_to_string(&args.catalog_path)
        .with_context(|| format!("read catalog {}", args.catalog_path.display()))?;
    let base_registry: Registry = serde_json::from_str(&registry_text).context("parse catalog")?;
    let runtime_cfg = load_runtime_config(args.config_path.clone())?;
    let registry = merge_user_completion_catalog(base_registry, Some(&runtime_cfg));
    let validation_registry =
        filter_completion_catalog_for_providers(&registry, &args.providers_csv);
    validate_completion_overlay_names(&validation_registry)?;

    let disabled_providers: BTreeSet<String> = registry
        .providers
        .iter()
        .filter(|p| !p.enabled.unwrap_or(true))
        .map(|p| p.name.as_str())
        .map(str::to_string)
        .collect();
    let known_providers: BTreeSet<String> = registry
        .providers
        .iter()
        .map(|p| p.name.as_str())
        .map(str::to_string)
        .collect();

    let mut tools_by_provider: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut catalog_tools_by_provider: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut managed_required_tools: BTreeSet<(String, String)> = BTreeSet::new();
    let mut tool_origins: BTreeMap<(String, String), ToolOrigin> = BTreeMap::new();
    let mut command_metadata: BTreeMap<(String, String), CompletionCommandMetadata> =
        BTreeMap::new();
    for tool in &registry.tools {
        let provider = tool.provider.as_deref().unwrap_or("npm");
        let key = tool_key(provider, &tool.name);
        catalog_tools_by_provider
            .entry(provider.to_string())
            .or_default()
            .insert(tool.name.clone());
        tool_origins.insert(
            key.clone(),
            if tool.ambient {
                ToolOrigin::Ambient
            } else {
                ToolOrigin::Registry
            },
        );
        command_metadata.insert(
            key,
            CompletionCommandMetadata {
                command: tool.command.clone(),
                command_candidates: tool.command_candidates.clone(),
            },
        );
        if !tool.enabled.unwrap_or(true) {
            continue;
        }
        tools_by_provider
            .entry(provider.to_string())
            .or_default()
            .insert(tool.name.clone());
        if tool.managed_required.unwrap_or(false) {
            managed_required_tools.insert(tool_key(provider, &tool.name));
        }
    }

    let mut events = Vec::new();
    let mut records = Vec::new();
    let mut generated = 0usize;
    let mut unchanged = 0usize;
    let mut skipped = 0usize;
    let mut keep_by_provider: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    let report = args.report.to_lowercase();
    let heartbeat_secs = env::var("UPDATE_ALL_COMPLETION_HEARTBEAT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(2);
    let heartbeat = Duration::from_secs(heartbeat_secs.max(1));

    for provider in args
        .providers_csv
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        if disabled_providers.contains(provider) {
            continue;
        }
        if report == "verbose" {
            events.push(format!("__UA_COMP_INFO|provider_scan|{provider}:"));
        }
        if !args.discover
            && known_providers.contains(provider)
            && tools_by_provider
                .get(provider)
                .is_none_or(BTreeSet::is_empty)
        {
            let msg = completion_provider_no_configured_tools(provider);
            if let Some(cb) = &args.progress_cb {
                cb(msg.clone());
            }
            if report == "verbose" {
                events.push(format!("__UA_COMP_INFO|provider_empty|{provider}:"));
            }
            continue;
        }

        match provider {
            "npm" => {
                let start = Instant::now();
                let mut last_heartbeat = Instant::now();
                let budget = env::var("UPDATE_ALL_COMPLETION_PROVIDER_TIMEOUT")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(120);
                let budget = Duration::from_secs(budget.max(1));

                let prefix =
                    match run_capture("npm", ["prefix", "-g"], Some(Duration::from_secs(5))) {
                        Ok(value) => value,
                        Err(e) => {
                            skipped += push_provider_init_skips(
                                &mut events,
                                &mut records,
                                &tools_by_provider,
                                &managed_required_tools,
                                "npm",
                                &format!("npm_prefix_failed:{e}"),
                                "npm_prefix_failed",
                                &report,
                            );
                            continue;
                        }
                    };
                let prefix = prefix.lines().next().unwrap_or("").trim().to_string();
                if prefix.is_empty() {
                    skipped += push_provider_init_skips(
                        &mut events,
                        &mut records,
                        &tools_by_provider,
                        &managed_required_tools,
                        "npm",
                        "npm_prefix_empty",
                        "npm_prefix_empty",
                        &report,
                    );
                    continue;
                }
                let bin_dir = Path::new(&prefix).join("bin");

                let registry_set = tools_by_provider.get("npm").cloned().unwrap_or_default();
                let catalog_set = catalog_tools_by_provider
                    .get("npm")
                    .cloned()
                    .unwrap_or_default();
                let mut tools: BTreeMap<String, ToolOrigin> = if args.discover {
                    let mut discovered = BTreeSet::new();
                    if let Ok(entries) = fs::read_dir(&bin_dir) {
                        for e in entries.flatten() {
                            if let Some(name) = e.file_name().to_str() {
                                if let Some(normalized) = normalize_npm_discovered_tool(name) {
                                    discovered.insert(normalized);
                                }
                            }
                        }
                    }
                    discovered
                        .into_iter()
                        .filter(|tool| registry_set.contains(tool) || !catalog_set.contains(tool))
                        .map(|tool| {
                            let origin = tool_origins
                                .get(&tool_key("npm", &tool))
                                .copied()
                                .unwrap_or_else(|| {
                                    if registry_set.contains(&tool) {
                                        ToolOrigin::Registry
                                    } else {
                                        ToolOrigin::Ambient
                                    }
                                });
                            (tool, origin)
                        })
                        .collect()
                } else {
                    registry_set
                        .iter()
                        .cloned()
                        .map(|tool| {
                            let origin = tool_origins
                                .get(&tool_key("npm", &tool))
                                .copied()
                                .unwrap_or(ToolOrigin::Registry);
                            (tool, origin)
                        })
                        .collect()
                };

                let total = tools.len();
                let mut probed = 0usize;
                let generated_before = generated;
                let unchanged_before = unchanged;
                let skipped_before = skipped;

                for (tool_name, origin) in tools {
                    if cancel::is_cancel_requested() {
                        return Err(anyhow::anyhow!(crate::Cancelled));
                    }
                    if start.elapsed() > budget {
                        events.push("__UA_COMP_INFO|provider_budget_exceeded|npm:".to_string());
                        break;
                    }

                    if let Some(cb) = &args.progress_cb {
                        cb(format!(
                            "completion-sync npm: probing {tool_name} ({}/{})",
                            probed + 1,
                            total
                        ));
                    }

                    let metadata = command_metadata
                        .get(&tool_key("npm", &tool_name))
                        .cloned()
                        .unwrap_or_default();
                    match generate_tool_completion(
                        "npm",
                        &tool_name,
                        &bin_dir,
                        &args.rc_root,
                        metadata.command.as_deref(),
                        &metadata.command_candidates,
                    ) {
                        Ok(Some(completion)) => {
                            finish_generated_completion(
                                &args.rc_root,
                                &mut events,
                                &mut records,
                                &mut keep_by_provider,
                                &mut generated,
                                &mut unchanged,
                                "npm",
                                &tool_name,
                                completion,
                            )?;
                            if report != "json" {
                                events.push(format!("npm:{tool_name}"));
                            }
                        }
                        Ok(None) => {
                            if origin == ToolOrigin::Registry
                                && finish_existing_completion_if_available(
                                    &args.rc_root,
                                    &mut events,
                                    &mut records,
                                    &mut keep_by_provider,
                                    &mut generated,
                                    &mut unchanged,
                                    "npm",
                                    &tool_name,
                                )?
                            {
                                if report != "json" {
                                    events.push(format!("npm:{tool_name}"));
                                }
                            } else if origin == ToolOrigin::Registry {
                                skipped += 1;
                                let reason = managed_required_reason(
                                    "unsupported_generator",
                                    tool_is_managed_required(
                                        &managed_required_tools,
                                        "npm",
                                        &tool_name,
                                    ),
                                );
                                push_completion_skipped(
                                    &mut events,
                                    &mut records,
                                    "npm",
                                    &tool_name,
                                    reason,
                                );
                                if report != "json" {
                                    events.push(format!("npm:{tool_name}:unsupported_generator"));
                                }
                            }
                        }
                        Err(e) => {
                            if origin == ToolOrigin::Registry
                                && finish_existing_completion_if_available(
                                    &args.rc_root,
                                    &mut events,
                                    &mut records,
                                    &mut keep_by_provider,
                                    &mut generated,
                                    &mut unchanged,
                                    "npm",
                                    &tool_name,
                                )?
                            {
                                if report != "json" {
                                    events.push(format!("npm:{tool_name}"));
                                }
                            } else {
                                skipped += 1;
                                push_completion_skipped(
                                    &mut events,
                                    &mut records,
                                    "npm",
                                    &tool_name,
                                    e.to_string(),
                                );
                            }
                        }
                    }

                    probed += 1;
                    if last_heartbeat.elapsed() >= heartbeat {
                        last_heartbeat = Instant::now();
                        let msg = completion_provider_progress(
                            "npm",
                            probed,
                            total,
                            generated.saturating_sub(generated_before),
                            unchanged.saturating_sub(unchanged_before),
                            skipped.saturating_sub(skipped_before),
                            start.elapsed(),
                        );
                        if let Some(cb) = &args.progress_cb {
                            cb(msg.clone());
                        }
                        if report == "verbose" {
                            events.push(format!("__UA_COMP_INFO|heartbeat|{msg}"));
                        }
                    }
                }
            }
            "pipx" => {
                let mut apps = BTreeSet::new();
                if args.discover {
                    let list_json = match run_capture(
                        "pipx",
                        ["list", "--json"],
                        Some(Duration::from_secs(10)),
                    ) {
                        Ok(value) => value,
                        Err(e) => {
                            skipped += push_provider_init_skips(
                                &mut events,
                                &mut records,
                                &tools_by_provider,
                                &managed_required_tools,
                                "pipx",
                                &format!("pipx_list_failed:{e}"),
                                "pipx_list_failed",
                                &report,
                            );
                            continue;
                        }
                    };
                    let state: PipxState = match serde_json::from_str(&list_json) {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            skipped += push_provider_init_skips(
                                &mut events,
                                &mut records,
                                &tools_by_provider,
                                &managed_required_tools,
                                "pipx",
                                &format!("pipx_parse_failed:{e}"),
                                "pipx_parse_failed",
                                &report,
                            );
                            continue;
                        }
                    };
                    for (_, venv) in state.venvs {
                        if let Some(main) = venv.metadata.and_then(|m| m.main_package) {
                            if let Some(a) = main.apps {
                                for app in a {
                                    apps.insert(app);
                                }
                            }
                        }
                    }
                } else if let Some(registry_apps) = tools_by_provider.get("pipx") {
                    apps.extend(registry_apps.iter().cloned());
                }
                for app in apps {
                    let metadata = command_metadata
                        .get(&tool_key("pipx", &app))
                        .cloned()
                        .unwrap_or_default();
                    match generate_tool_completion(
                        "pipx",
                        &app,
                        Path::new(""),
                        &args.rc_root,
                        metadata.command.as_deref(),
                        &metadata.command_candidates,
                    ) {
                        Ok(Some(completion)) => {
                            finish_generated_completion(
                                &args.rc_root,
                                &mut events,
                                &mut records,
                                &mut keep_by_provider,
                                &mut generated,
                                &mut unchanged,
                                "pipx",
                                &app,
                                completion,
                            )?;
                        }
                        Ok(None) => {
                            if !enabled_catalog_tool(&tools_by_provider, "pipx", &app)
                                || !finish_existing_completion_if_available(
                                    &args.rc_root,
                                    &mut events,
                                    &mut records,
                                    &mut keep_by_provider,
                                    &mut generated,
                                    &mut unchanged,
                                    "pipx",
                                    &app,
                                )?
                            {
                                skipped += 1;
                                let reason = managed_required_reason(
                                    "unsupported_generator",
                                    tool_is_managed_required(&managed_required_tools, "pipx", &app),
                                );
                                push_completion_skipped(
                                    &mut events,
                                    &mut records,
                                    "pipx",
                                    &app,
                                    reason,
                                );
                            }
                        }
                        Err(e) => {
                            if !enabled_catalog_tool(&tools_by_provider, "pipx", &app)
                                || !finish_existing_completion_if_available(
                                    &args.rc_root,
                                    &mut events,
                                    &mut records,
                                    &mut keep_by_provider,
                                    &mut generated,
                                    &mut unchanged,
                                    "pipx",
                                    &app,
                                )?
                            {
                                skipped += 1;
                                push_completion_skipped(
                                    &mut events,
                                    &mut records,
                                    "pipx",
                                    &app,
                                    e.to_string(),
                                );
                            }
                        }
                    }
                }
            }
            "uv" => {
                let mut tools = BTreeSet::new();
                if args.discover {
                    let mut tried_json = false;
                    if let Ok(tools_json) = run_capture(
                        "uv",
                        ["tool", "list", "--json"],
                        Some(Duration::from_secs(10)),
                    ) {
                        tried_json = true;
                        match serde_json::from_str::<UvTools>(&tools_json) {
                            Ok(parsed) => {
                                for tool in parsed.tools {
                                    tools.insert(tool.name);
                                }
                            }
                            Err(e) => {
                                if report == "verbose" {
                                    events.push(format!(
                                        "__UA_COMP_INFO|uv|json_discovery_parse_failed:{e}"
                                    ));
                                }
                            }
                        }
                    } else if report == "verbose" {
                        events.push("__UA_COMP_INFO|uv|json_discovery_unsupported".to_string());
                    }

                    if tools.is_empty() {
                        let plain = match run_capture(
                            "uv",
                            ["tool", "list"],
                            Some(Duration::from_secs(10)),
                        ) {
                            Ok(value) => value,
                            Err(e) => {
                                let reason = if tried_json {
                                    format!("uv_tool_list_plain_failed:{e}")
                                } else {
                                    format!("uv_tool_list_failed:{e}")
                                };
                                skipped += push_provider_init_skips(
                                    &mut events,
                                    &mut records,
                                    &tools_by_provider,
                                    &managed_required_tools,
                                    "uv",
                                    &reason,
                                    "uv_tool_list_failed",
                                    &report,
                                );
                                continue;
                            }
                        };
                        let parsed = parse_uv_tool_list(&plain);
                        if parsed.is_empty() {
                            skipped += push_provider_init_skips(
                                &mut events,
                                &mut records,
                                &tools_by_provider,
                                &managed_required_tools,
                                "uv",
                                "uv_tool_list_empty",
                                "uv_tool_list_empty",
                                &report,
                            );
                            continue;
                        }
                        tools.extend(parsed);
                    }
                } else if let Some(registry_tools) = tools_by_provider.get("uv") {
                    tools.extend(registry_tools.iter().cloned());
                }
                for name in tools {
                    let metadata = command_metadata
                        .get(&tool_key("uv", &name))
                        .cloned()
                        .unwrap_or_default();
                    match generate_tool_completion(
                        "uv",
                        &name,
                        Path::new(""),
                        &args.rc_root,
                        metadata.command.as_deref(),
                        &metadata.command_candidates,
                    ) {
                        Ok(Some(completion)) => {
                            finish_generated_completion(
                                &args.rc_root,
                                &mut events,
                                &mut records,
                                &mut keep_by_provider,
                                &mut generated,
                                &mut unchanged,
                                "uv",
                                &name,
                                completion,
                            )?;
                        }
                        Ok(None) => {
                            if !enabled_catalog_tool(&tools_by_provider, "uv", &name)
                                || !finish_existing_completion_if_available(
                                    &args.rc_root,
                                    &mut events,
                                    &mut records,
                                    &mut keep_by_provider,
                                    &mut generated,
                                    &mut unchanged,
                                    "uv",
                                    &name,
                                )?
                            {
                                skipped += 1;
                                let reason = managed_required_reason(
                                    "unsupported_generator",
                                    tool_is_managed_required(&managed_required_tools, "uv", &name),
                                );
                                push_completion_skipped(
                                    &mut events,
                                    &mut records,
                                    "uv",
                                    &name,
                                    reason,
                                );
                            }
                        }
                        Err(e) => {
                            if !enabled_catalog_tool(&tools_by_provider, "uv", &name)
                                || !finish_existing_completion_if_available(
                                    &args.rc_root,
                                    &mut events,
                                    &mut records,
                                    &mut keep_by_provider,
                                    &mut generated,
                                    &mut unchanged,
                                    "uv",
                                    &name,
                                )?
                            {
                                skipped += 1;
                                push_completion_skipped(
                                    &mut events,
                                    &mut records,
                                    "uv",
                                    &name,
                                    e.to_string(),
                                );
                            }
                        }
                    }
                }
            }
            "go" => {
                let mut tools = BTreeSet::new();
                if args.discover {
                    let gobin =
                        match run_capture("go", ["env", "GOBIN"], Some(Duration::from_secs(5))) {
                            Ok(value) => value,
                            Err(e) => {
                                skipped += push_provider_init_skips(
                                    &mut events,
                                    &mut records,
                                    &tools_by_provider,
                                    &managed_required_tools,
                                    "go",
                                    &format!("go_env_gobin_failed:{e}"),
                                    "go_env_gobin_failed",
                                    &report,
                                );
                                continue;
                            }
                        };
                    let gobin_dir = gobin.lines().next().unwrap_or("").trim().to_string();
                    let go_bin_dir = if gobin_dir.is_empty() {
                        let gopath = match run_capture(
                            "go",
                            ["env", "GOPATH"],
                            Some(Duration::from_secs(5)),
                        ) {
                            Ok(value) => value,
                            Err(e) => {
                                skipped += push_provider_init_skips(
                                    &mut events,
                                    &mut records,
                                    &tools_by_provider,
                                    &managed_required_tools,
                                    "go",
                                    &format!("go_env_gopath_failed:{e}"),
                                    "go_env_gopath_failed",
                                    &report,
                                );
                                continue;
                            }
                        };
                        match std::env::split_paths(gopath.lines().next().unwrap_or("").trim())
                            .next()
                        {
                            Some(path) => path.join("bin"),
                            None => {
                                skipped += push_provider_init_skips(
                                    &mut events,
                                    &mut records,
                                    &tools_by_provider,
                                    &managed_required_tools,
                                    "go",
                                    "go_bin_dir_empty",
                                    "go_bin_dir_empty",
                                    &report,
                                );
                                continue;
                            }
                        }
                    } else {
                        PathBuf::from(gobin_dir)
                    };
                    if let Ok(entries) = fs::read_dir(&go_bin_dir) {
                        for e in entries.flatten() {
                            if let Some(name) = e.file_name().to_str() {
                                tools.insert(name.to_string());
                            }
                        }
                    }
                } else if let Some(registry_tools) = tools_by_provider.get("go") {
                    tools.extend(registry_tools.iter().cloned());
                }
                for name in tools {
                    let metadata = command_metadata
                        .get(&tool_key("go", &name))
                        .cloned()
                        .unwrap_or_default();
                    match generate_tool_completion(
                        "go",
                        &name,
                        Path::new(""),
                        &args.rc_root,
                        metadata.command.as_deref(),
                        &metadata.command_candidates,
                    ) {
                        Ok(Some(completion)) => {
                            finish_generated_completion(
                                &args.rc_root,
                                &mut events,
                                &mut records,
                                &mut keep_by_provider,
                                &mut generated,
                                &mut unchanged,
                                "go",
                                &name,
                                completion,
                            )?;
                        }
                        Ok(None) => {
                            if !enabled_catalog_tool(&tools_by_provider, "go", &name)
                                || !finish_existing_completion_if_available(
                                    &args.rc_root,
                                    &mut events,
                                    &mut records,
                                    &mut keep_by_provider,
                                    &mut generated,
                                    &mut unchanged,
                                    "go",
                                    &name,
                                )?
                            {
                                skipped += 1;
                                let reason = managed_required_reason(
                                    "unsupported_generator",
                                    tool_is_managed_required(&managed_required_tools, "go", &name),
                                );
                                push_completion_skipped(
                                    &mut events,
                                    &mut records,
                                    "go",
                                    &name,
                                    reason,
                                );
                            }
                        }
                        Err(e) => {
                            if !enabled_catalog_tool(&tools_by_provider, "go", &name)
                                || !finish_existing_completion_if_available(
                                    &args.rc_root,
                                    &mut events,
                                    &mut records,
                                    &mut keep_by_provider,
                                    &mut generated,
                                    &mut unchanged,
                                    "go",
                                    &name,
                                )?
                            {
                                skipped += 1;
                                push_completion_skipped(
                                    &mut events,
                                    &mut records,
                                    "go",
                                    &name,
                                    e.to_string(),
                                );
                            }
                        }
                    }
                }
            }
            "path" => {
                let registry_set = tools_by_provider.get("path").cloned().unwrap_or_default();
                let total = registry_set.len();
                let generated_before = generated;
                let unchanged_before = unchanged;
                let skipped_before = skipped;
                let provider_start = Instant::now();
                let mut probed = 0usize;
                let empty_bin_dir = Path::new("");

                for (idx, tool_name) in registry_set.into_iter().enumerate() {
                    if cancel::is_cancel_requested() {
                        return Err(anyhow::anyhow!(crate::Cancelled));
                    }

                    if let Some(cb) = &args.progress_cb {
                        cb(format!(
                            "completion-sync path: probing {tool_name} ({}/{})",
                            idx + 1,
                            total
                        ));
                    }

                    let metadata = command_metadata
                        .get(&tool_key("path", &tool_name))
                        .cloned()
                        .unwrap_or_default();
                    match generate_tool_completion(
                        "path",
                        &tool_name,
                        empty_bin_dir,
                        &args.rc_root,
                        metadata.command.as_deref(),
                        &metadata.command_candidates,
                    ) {
                        Ok(Some(completion)) => {
                            finish_generated_completion(
                                &args.rc_root,
                                &mut events,
                                &mut records,
                                &mut keep_by_provider,
                                &mut generated,
                                &mut unchanged,
                                "path",
                                &tool_name,
                                completion,
                            )?;
                        }
                        Ok(None) => {
                            if !enabled_catalog_tool(&tools_by_provider, "path", &tool_name)
                                || !finish_existing_completion_if_available(
                                    &args.rc_root,
                                    &mut events,
                                    &mut records,
                                    &mut keep_by_provider,
                                    &mut generated,
                                    &mut unchanged,
                                    "path",
                                    &tool_name,
                                )?
                            {
                                skipped += 1;
                                let reason = managed_required_reason(
                                    "unsupported_generator",
                                    tool_is_managed_required(
                                        &managed_required_tools,
                                        "path",
                                        &tool_name,
                                    ),
                                );
                                push_completion_skipped(
                                    &mut events,
                                    &mut records,
                                    "path",
                                    &tool_name,
                                    reason,
                                );
                            }
                        }
                        Err(e) => {
                            if !enabled_catalog_tool(&tools_by_provider, "path", &tool_name)
                                || !finish_existing_completion_if_available(
                                    &args.rc_root,
                                    &mut events,
                                    &mut records,
                                    &mut keep_by_provider,
                                    &mut generated,
                                    &mut unchanged,
                                    "path",
                                    &tool_name,
                                )?
                            {
                                skipped += 1;
                                push_completion_skipped(
                                    &mut events,
                                    &mut records,
                                    "path",
                                    &tool_name,
                                    e.to_string(),
                                );
                            }
                        }
                    }
                    probed += 1;
                }
                if probed > 0 {
                    let provider_generated = generated.saturating_sub(generated_before);
                    let provider_unchanged = unchanged.saturating_sub(unchanged_before);
                    let provider_skipped = skipped.saturating_sub(skipped_before);
                    if let Some(cb) = &args.progress_cb {
                        cb(completion_provider_progress(
                            "path",
                            probed,
                            total,
                            provider_generated,
                            provider_unchanged,
                            provider_skipped,
                            provider_start.elapsed(),
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    for provider in args
        .providers_csv
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        prune_managed_provider_artifacts(
            &args.rc_root,
            provider,
            keep_by_provider.get(provider).cloned().unwrap_or_default(),
        )?;
    }
    prune_orphan_managed_overlay_shims(&args.rc_root)?;

    if report == "json" {
        let payload = serde_json::json!({
            "generated": generated,
            "unchanged": unchanged,
            "skipped": skipped,
        });
        events.push(format!("__UA_COMP_REPORT_JSON|{}", payload));
    }

    events.push(format!(
        "__UA_COMP_SUMMARY|generated={generated}|unchanged={unchanged}|skipped={skipped}"
    ));
    publish_public_self_completion_snapshot(&args.managed_root, &mut events)?;

    Ok(CompletionSyncResult {
        generated,
        unchanged,
        skipped,
        events,
        records,
        catalog_used: args.catalog_path,
        effective_catalog: registry,
    })
}

pub fn completion_init(shell: &str, managed_root: PathBuf) -> Result<CompletionInitResult> {
    let shell = CompletionShell::parse(shell)?;
    let root = ManagedCompletionRoot::new(managed_root)?;
    Ok(CompletionInitResult {
        shell_code: root.init_script(shell)?,
    })
}

pub fn completion_status(managed_root: PathBuf) -> Result<CompletionStatusResult> {
    let root = ManagedCompletionRoot::new(managed_root)?;
    Ok(CompletionStatusResult {
        status: root.status()?,
    })
}

pub(crate) fn filter_completion_catalog_for_providers(
    catalog: &Registry,
    providers_csv: &str,
) -> Registry {
    let selected_providers = providers_csv
        .split(',')
        .map(str::trim)
        .filter(|provider| !provider.is_empty())
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if selected_providers.is_empty() {
        return catalog.clone();
    }

    Registry {
        schema_version: catalog.schema_version,
        providers: catalog
            .providers
            .iter()
            .filter(|provider| selected_providers.contains(provider.name.as_str()))
            .cloned()
            .collect(),
        tools: catalog
            .tools
            .iter()
            .filter(|tool| {
                selected_providers.contains(tool.provider.as_deref().unwrap_or("npm").trim())
            })
            .cloned()
            .collect(),
    }
}

fn validate_completion_overlay_names(registry: &Registry) -> Result<()> {
    let mut owners = BTreeMap::new();
    for tool in registry
        .tools
        .iter()
        .filter(|tool| tool.enabled.unwrap_or(true))
    {
        let name = tool.name.trim();
        if name.is_empty() {
            continue;
        }
        let provider = tool.provider.as_deref().unwrap_or("npm").trim();
        if provider.is_empty() {
            continue;
        }
        if let Some(existing) = owners.insert(name.to_string(), provider.to_string()) {
            if existing != provider {
                anyhow::bail!(
                    "completion tool '{name}' is configured for multiple providers ({existing}, {provider}); managed overlay shims are keyed by tool name, so disable one entry or choose a unique command name"
                );
            }
        }
    }
    Ok(())
}

fn normalize_npm_discovered_tool(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    for suffix in [".cmd", ".ps1", ".exe", ".bat"] {
        if lower.ends_with(suffix) && trimmed.len() > suffix.len() {
            return Some(trimmed[..trimmed.len() - suffix.len()].to_string());
        }
    }
    Some(trimmed.to_string())
}

pub fn completion_install(args: CompletionInstallArgs) -> Result<CompletionInstallResult> {
    match CompletionShell::parse(&args.shell)? {
        CompletionShell::Bash | CompletionShell::Elvish | CompletionShell::Fish => {
            anyhow::bail!(
                "legacy completion install only supports zsh and powershell; use `update-all completions init {}` for read-only startup wiring",
                args.shell
            )
        }
        CompletionShell::Zsh => completion_install_zsh(args.rc_root),
        CompletionShell::PowerShell => {
            let powershell_root = args
                .powershell_root
                .context("missing PowerShell root for powershell completion install")?;
            completion_install_powershell(&powershell_root)
        }
    }
}

fn completion_install_zsh(rc_root: PathBuf) -> Result<CompletionInstallResult> {
    let bootstrap_dir = rc_root.join("shell/bootstrap/completions");
    let manifest_dir = rc_root.join("shell/manifests/phases");
    let manifest_path = manifest_dir.join("10-bootstrap.list");
    let completion_init_dir = rc_root.join("shell/completion-init");
    let managed_completion_dir = managed_completion_dir(&rc_root);
    let overlay_completion_dir = managed_overlay_dir(&rc_root);
    let bootstrap_file = bootstrap_dir.join("20-update-all-managed-fpath.zsh");
    let retired_completion_init_file = completion_init_dir.join("15-update-all-managed.zsh");
    let self_completion_path = managed_completion_dir.join("_update-all");
    fs::create_dir_all(&bootstrap_dir)
        .with_context(|| format!("create bootstrap dir {}", bootstrap_dir.to_string_lossy()))?;
    fs::create_dir_all(&manifest_dir)
        .with_context(|| format!("create manifest dir {}", manifest_dir.to_string_lossy()))?;
    fs::create_dir_all(&managed_completion_dir).with_context(|| {
        format!(
            "create managed completion dir {}",
            managed_completion_dir.to_string_lossy()
        )
    })?;
    fs::create_dir_all(&overlay_completion_dir).with_context(|| {
        format!(
            "create managed overlay dir {}",
            overlay_completion_dir.to_string_lossy()
        )
    })?;

    let bootstrap_payload = r#"# managed by update-all; binary-owned completion bootstrap
emulate -L zsh
setopt localoptions no_aliases
: "${RC_ROOT:=$HOME/.shellrc.d}"
typeset -gUa fpath
for _rc_comp_dir in \
  "$RC_ROOT/shell/completions-managed" \
  "$RC_ROOT/shell/completions"
do
  [[ -d "$_rc_comp_dir" ]] || continue
  if [[ -O "$_rc_comp_dir" ]]; then
    fpath=("$_rc_comp_dir" $fpath)
  fi
done
unset _rc_comp_dir
"#;
    let bootstrap_changed =
        write_bytes_if_changed(&bootstrap_file, bootstrap_payload.as_bytes())
            .with_context(|| format!("write {}", bootstrap_file.to_string_lossy()))?;
    let manifest_changed = ensure_manifest_entry(
        &manifest_path,
        "shell/bootstrap/completions/20-update-all-managed-fpath.zsh",
    )?;
    let retired_marker_removed = remove_owned_completion_marker(&retired_completion_init_file)?;
    let self_changed = write_bytes_if_changed(
        &self_completion_path,
        generate_update_all_completion("zsh")?.as_bytes(),
    )
    .with_context(|| format!("write {}", self_completion_path.to_string_lossy()))?;

    let self_status = if self_changed {
        "__UA_COMP_GENERATED"
    } else {
        "__UA_COMP_UNCHANGED"
    };
    let apply_status = if bootstrap_changed || manifest_changed || retired_marker_removed {
        "installed"
    } else {
        "unchanged"
    };

    Ok(CompletionInstallResult {
        events: vec![
            format!(
                "{self_status}|self|update-all|{}",
                self_completion_path.display()
            ),
            format!(
                "__UA_COMP_APPLY|zsh|{apply_status}|{}",
                bootstrap_file.display()
            ),
        ],
    })
}

fn remove_owned_completion_marker(path: &Path) -> Result<bool> {
    let body = match fs::read_to_string(path) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    if !body.starts_with("# managed by update-all;") {
        anyhow::bail!(
            "refusing to remove unowned completion-init file {}",
            path.display()
        );
    }
    fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    Ok(true)
}

fn completion_install_powershell(powershell_root: &Path) -> Result<CompletionInstallResult> {
    let module_dir = powershell_root.join("modules");
    let self_completion_path = module_dir.join(POWERSHELL_SELF_COMPLETION_FILE);
    fs::create_dir_all(&module_dir)
        .with_context(|| format!("create PowerShell module dir {}", module_dir.display()))?;
    let self_changed = write_bytes_if_changed(
        &self_completion_path,
        generate_update_all_completion("powershell")?.as_bytes(),
    )
    .with_context(|| format!("write {}", self_completion_path.display()))?;
    let self_status = if self_changed {
        "__UA_COMP_GENERATED"
    } else {
        "__UA_COMP_UNCHANGED"
    };
    let apply_status = if self_changed {
        "installed"
    } else {
        "unchanged"
    };

    Ok(CompletionInstallResult {
        events: vec![
            format!(
                "{self_status}|self|update-all|{}",
                self_completion_path.display()
            ),
            format!(
                "__UA_COMP_APPLY|powershell|{apply_status}|{}",
                self_completion_path.display()
            ),
        ],
    })
}

fn ensure_manifest_entry(manifest_path: &Path, entry: &str) -> Result<bool> {
    let existing = fs::read_to_string(manifest_path).unwrap_or_default();
    if existing
        .lines()
        .map(str::trim)
        .any(|line| !line.is_empty() && !line.starts_with('#') && line == entry)
    {
        return Ok(false);
    }

    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(entry);
    updated.push('\n');
    fs::write(manifest_path, updated)
        .with_context(|| format!("write {}", manifest_path.to_string_lossy()))?;
    Ok(true)
}

pub fn completion_apply(args: CompletionApplyArgs) -> Result<CompletionApplyResult> {
    let shell = CompletionShell::parse(&args.shell)?;

    let mut events = Vec::new();
    let audit_mode = args.audit_mode.trim().to_ascii_lowercase();
    match audit_mode.as_str() {
        "off" => {
            events.push(format!(
                "__UA_COMP_APPLY|{}|audit_skipped|mode_off",
                shell.as_event_name()
            ));
            return Ok(CompletionApplyResult { events });
        }
        "fast" | "strict" => {}
        _ => anyhow::bail!(
            "invalid --audit '{}': expected off|fast|strict",
            args.audit_mode
        ),
    }

    if shell == CompletionShell::PowerShell {
        return completion_apply_powershell(args, audit_mode, events);
    }

    if which("zsh").is_none() {
        let msg = "__UA_COMP_APPLY|zsh|audit_skipped|zsh_not_found".to_string();
        if audit_mode == "strict" {
            anyhow::bail!("{msg}");
        }
        events.push(msg);
        return Ok(CompletionApplyResult { events });
    }

    let audit_script = args.rc_root.join("commands/zsh/completion_audit.zsh");
    if !audit_script.is_file() {
        let msg = format!(
            "__UA_COMP_APPLY|zsh|audit_skipped|script_missing:{}",
            audit_script.display()
        );
        if audit_mode == "strict" {
            anyhow::bail!("{msg}");
        }
        events.push(msg);
        return Ok(CompletionApplyResult { events });
    }

    let strict_mode = if audit_mode == "strict" {
        "fail"
    } else {
        "hybrid"
    };
    let mode = if audit_mode == "strict" {
        "deep"
    } else {
        "fast"
    };
    let mut cmd = Command::new("zsh");
    cmd.args([
        audit_script.to_string_lossy().as_ref(),
        "--mode",
        mode,
        "--strict",
        strict_mode,
        "--discover",
        if args.discover { "1" } else { "0" },
        "--registry",
        args.registry_path.to_string_lossy().as_ref(),
        "--rc-root",
        args.rc_root.to_string_lossy().as_ref(),
    ]);
    if let Some(managed_catalog_path) = &args.managed_catalog_path {
        cmd.args([
            "--managed-catalog",
            managed_catalog_path.to_string_lossy().as_ref(),
        ]);
    }

    let out = cmd.output().context("run completion audit")?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    for line in combined.lines() {
        if line.trim().is_empty() {
            continue;
        }
        events.push(format!("__UA_COMP_AUDIT|{line}"));
    }

    if !out.status.success() {
        events.push(format!(
            "__UA_COMP_APPLY|zsh|audit_failed|exit={}",
            out.status.code().unwrap_or(1)
        ));
        return Err(CompletionApplyFailure { events }.into());
    }
    events.push("__UA_COMP_APPLY|zsh|audit_ok".to_string());

    Ok(CompletionApplyResult { events })
}

fn completion_apply_powershell(
    args: CompletionApplyArgs,
    audit_mode: String,
    mut events: Vec<String>,
) -> Result<CompletionApplyResult> {
    let powershell_root = args
        .powershell_root
        .context("missing PowerShell root for powershell completion audit")?;
    let module_dir = powershell_root.join("modules");
    let repo_generated = module_dir.join("completions.generated.ps1");
    let self_generated = module_dir.join(POWERSHELL_SELF_COMPLETION_FILE);
    let pwsh = find_powershell_command();

    if pwsh.is_none() {
        let msg = "__UA_COMP_APPLY|powershell|audit_skipped|powershell_not_found".to_string();
        if audit_mode == "strict" {
            anyhow::bail!("{msg}");
        }
        events.push(msg);
        return Ok(CompletionApplyResult { events });
    }

    let mut missing = Vec::new();
    if !repo_generated.is_file() {
        missing.push(repo_generated.display().to_string());
    }
    if !self_generated.is_file() {
        missing.push(self_generated.display().to_string());
    }
    if !missing.is_empty() {
        let msg = format!(
            "__UA_COMP_APPLY|powershell|audit_skipped|missing:{}",
            missing.join(",")
        );
        if audit_mode == "strict" {
            anyhow::bail!("{msg}");
        }
        events.push(msg);
        return Ok(CompletionApplyResult { events });
    }

    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
. '{}'
. '{}'
[System.Management.Automation.CommandCompletion]::CompleteInput('update-all completion power', 'update-all completion power'.Length, $null) | Out-Null
'ok'
"#,
        powershell_single_quote_path(&repo_generated),
        powershell_single_quote_path(&self_generated)
    );

    let out = Command::new(pwsh.unwrap_or_else(|| "pwsh".to_string()))
        .args(["-NoProfile", "-Command", script.as_str()])
        .output()
        .context("run PowerShell completion audit")?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    for line in combined.lines() {
        if !line.trim().is_empty() && line.trim() != "ok" {
            events.push(format!("__UA_COMP_AUDIT|{line}"));
        }
    }
    if !out.status.success() {
        events.push(format!(
            "__UA_COMP_APPLY|powershell|audit_failed|exit={}",
            out.status.code().unwrap_or(1)
        ));
        return Err(CompletionApplyFailure { events }.into());
    }

    events.push("__UA_COMP_APPLY|powershell|audit_ok".to_string());
    Ok(CompletionApplyResult { events })
}

fn find_powershell_command() -> Option<String> {
    ["pwsh", "powershell.exe", "powershell"]
        .iter()
        .find(|cmd| which(cmd).is_some())
        .map(|cmd| (*cmd).to_string())
}

fn powershell_single_quote_path(path: &Path) -> String {
    path.to_string_lossy().replace('\'', "''")
}

fn managed_completion_dir(rc_root: &Path) -> PathBuf {
    rc_root.join("shell/completions")
}

fn managed_overlay_dir(rc_root: &Path) -> PathBuf {
    rc_root.join("shell/completions-managed")
}

fn publish_public_self_completion_snapshot(
    managed_root: &Path,
    events: &mut Vec<String>,
) -> Result<()> {
    let root = ManagedCompletionRoot::new(managed_root.to_path_buf())?;
    let mut payloads = BTreeMap::new();
    for shell in [
        CompletionShell::Bash,
        CompletionShell::Elvish,
        CompletionShell::Fish,
        CompletionShell::PowerShell,
        CompletionShell::Zsh,
    ] {
        payloads.insert(
            shell,
            generate_update_all_completion(shell.as_event_name())?,
        );
    }

    match root.publish_shell_completions(&payloads)? {
        CompletionSnapshotPublishOutcome::Published { snapshot } => {
            events.push(format!("__UA_COMP_PUBLIC|published|{}", snapshot.display()));
        }
        CompletionSnapshotPublishOutcome::Unchanged { snapshot } => {
            events.push(format!("__UA_COMP_PUBLIC|unchanged|{}", snapshot.display()));
        }
    }

    Ok(())
}

fn managed_payload_basename(provider: &str, tool: &str) -> String {
    format!("_managed_{provider}_{tool}")
}

fn managed_overlay_basename(tool: &str) -> String {
    format!("_{tool}")
}

struct ManagedOverlayWrite {
    changed: bool,
}

fn write_managed_overlay_shim(
    rc_root: &Path,
    provider: &str,
    tool: &str,
) -> Result<ManagedOverlayWrite> {
    let overlay_dir = managed_overlay_dir(rc_root);
    fs::create_dir_all(&overlay_dir)
        .with_context(|| format!("create overlay dir {}", overlay_dir.display()))?;
    let payload_basename = managed_payload_basename(provider, tool);
    let payload_path = managed_completion_dir(rc_root).join(&payload_basename);
    if !payload_path.is_file() {
        anyhow::bail!(
            "missing managed payload for overlay shim: {}",
            payload_path.display()
        );
    }

    let overlay_path = overlay_dir.join(managed_overlay_basename(tool));
    let payload = format!(
        "{MANAGED_OVERLAY_MARKER}\n# update-all-managed-target: {payload_basename}\n#compdef {tool}\n: \"${{RC_ROOT:=$HOME/.shellrc.d}}\"\n[[ -r \"$RC_ROOT/shell/completions/{payload_basename}\" ]] || return 1\nsource \"$RC_ROOT/shell/completions/{payload_basename}\"\n"
    );
    let changed = write_bytes_if_changed(&overlay_path, payload.as_bytes())
        .with_context(|| format!("write {}", overlay_path.display()))?;
    Ok(ManagedOverlayWrite { changed })
}

fn prune_managed_provider_artifacts(
    rc_root: &Path,
    provider: &str,
    keep_tools: BTreeSet<String>,
) -> Result<()> {
    let managed_dir = managed_completion_dir(rc_root);
    let prefix = format!("_managed_{provider}_");
    let Ok(entries) = fs::read_dir(&managed_dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !name.starts_with(&prefix) {
            continue;
        }
        let tool_name = &name[prefix.len()..];
        if keep_tools.contains(tool_name) {
            continue;
        }
        fs::remove_file(&path)
            .with_context(|| format!("remove stale managed completion {}", path.display()))?;
    }
    Ok(())
}

fn prune_orphan_managed_overlay_shims(rc_root: &Path) -> Result<()> {
    let overlay_dir = managed_overlay_dir(rc_root);
    let managed_dir = managed_completion_dir(rc_root);
    let Ok(entries) = fs::read_dir(&overlay_dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let body = match fs::read_to_string(&path) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if !body.starts_with(MANAGED_OVERLAY_MARKER) {
            continue;
        }
        let target = body
            .lines()
            .find_map(|line| line.strip_prefix("# update-all-managed-target: "))
            .map(str::trim);
        let Some(target) = target else {
            fs::remove_file(&path)
                .with_context(|| format!("remove malformed overlay shim {}", path.display()))?;
            continue;
        };
        if !managed_dir.join(target).is_file() {
            fs::remove_file(&path)
                .with_context(|| format!("remove orphan overlay shim {}", path.display()))?;
        }
    }
    Ok(())
}

#[derive(Deserialize, Debug)]
struct PipxState {
    venvs: BTreeMap<String, PipxVenv>,
}

#[derive(Deserialize, Debug)]
struct PipxVenv {
    metadata: Option<PipxMetadata>,
}

#[derive(Deserialize, Debug)]
struct PipxMetadata {
    main_package: Option<PipxMainPackage>,
}

#[derive(Deserialize, Debug)]
struct PipxMainPackage {
    #[allow(dead_code)] // Reason: accepted for forward-compatible JSON parsing.
    package: String,
    #[allow(dead_code)] // Reason: accepted for forward-compatible JSON parsing.
    package_or_url: String,
    #[allow(dead_code)] // Reason: accepted for forward-compatible JSON parsing.
    package_version: Option<String>,
    apps: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
struct UvTools {
    tools: Vec<UvTool>,
}

#[derive(Deserialize, Debug)]
struct UvTool {
    name: String,
}

fn parse_uv_tool_list(text: &str) -> BTreeSet<String> {
    let mut tools = BTreeSet::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower == "installed tools"
            || lower == "name"
            || trimmed.chars().all(|c| c == '-' || c == ' ')
        {
            continue;
        }
        let Some(name) = trimmed.split_whitespace().next() else {
            continue;
        };
        if !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            tools.insert(name.to_string());
        }
    }
    tools
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    #[test]
    fn owned_completion_marker_is_removed_without_touching_unowned_files() {
        let temp = TempDir::new().unwrap();
        let owned = temp.path().join("owned.zsh");
        fs::write(&owned, "# managed by update-all; marker\nreturn 0\n").unwrap();
        assert!(remove_owned_completion_marker(&owned).unwrap());
        assert!(!owned.exists());
        assert!(!remove_owned_completion_marker(&owned).unwrap());

        let unowned = temp.path().join("unowned.zsh");
        fs::write(&unowned, "return 0\n").unwrap();
        assert!(remove_owned_completion_marker(&unowned).is_err());
        assert!(unowned.is_file());
    }

    #[test]
    fn completion_skip_records_classify_provider_init_without_hiding_required_failures() {
        let records = vec![
            completion_record_from_skip("uv", "provider_init", "uv_tool_list_empty"),
            completion_record_from_skip("path", "broken", "generator_probe_timeout"),
            completion_record_from_skip("npm", "unsupported", "unsupported_generator"),
            completion_record_from_skip(
                "path",
                "required",
                "managed_required:unsupported_generator",
            ),
            completion_record_from_skip("npm", "codex", "provider_init:npm_prefix_failed"),
        ];

        assert_eq!(records.len(), 5);
        assert_eq!(records[0].status, CompletionSyncRecordStatus::Skipped);
        assert_eq!(records[0].reason.as_deref(), Some("uv_tool_list_empty"));
        assert_eq!(records[1].status, CompletionSyncRecordStatus::Failed);
        assert_eq!(records[2].status, CompletionSyncRecordStatus::Skipped);
        assert_eq!(records[3].status, CompletionSyncRecordStatus::Failed);
        assert_eq!(
            records[3].reason.as_deref(),
            Some("managed_required:unsupported_generator")
        );
        assert_eq!(records[4].status, CompletionSyncRecordStatus::Skipped);
    }

    #[test]
    fn completion_sync_reports_selected_providers_with_no_configured_tools() {
        let temp = TempDir::new().unwrap();
        let catalog_path = temp.path().join("managed-tools.json");
        let config_path = temp.path().join("config.toml");
        let rc_root = temp.path().join("rc");
        fs::write(
            &catalog_path,
            r#"{
  "schema_version": 1,
  "providers": [
    {"name": "pipx", "enabled": true},
    {"name": "uv", "enabled": true},
    {"name": "go", "enabled": true}
  ],
  "tools": []
}"#,
        )
        .unwrap();
        fs::write(&config_path, "").unwrap();
        fs::create_dir_all(&rc_root).unwrap();

        let progress = Arc::new(Mutex::new(Vec::new()));
        let progress_for_cb = Arc::clone(&progress);
        let result = completion_sync(CompletionSyncArgs {
            providers_csv: "pipx,uv,go".to_string(),
            discover: false,
            report: "compact".to_string(),
            catalog_path,
            config_path: Some(config_path),
            rc_root,
            managed_root: temp.path().join("managed-root"),
            progress_cb: Some(Arc::new(move |line| {
                progress_for_cb.lock().unwrap().push(line);
            })),
        })
        .unwrap();

        assert_eq!(result.records.len(), 0);
        let progress = progress.lock().unwrap();
        assert!(progress
            .iter()
            .any(|line| { line == "completion-sync pipx: no configured tools (discover=0)" }));
        assert!(progress
            .iter()
            .any(|line| { line == "completion-sync uv: no configured tools (discover=0)" }));
        assert!(progress
            .iter()
            .any(|line| { line == "completion-sync go: no configured tools (discover=0)" }));
    }

    #[test]
    fn generate_update_all_completion_supports_five_shells() {
        for shell in ["bash", "elvish", "fish", "powershell", "zsh"] {
            let payload = generate_update_all_completion(shell).unwrap();
            assert!(
                !payload.trim().is_empty(),
                "expected non-empty completion for {shell}"
            );
        }
    }
}
