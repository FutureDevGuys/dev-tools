mod engine;
mod generator;
mod native;
pub(crate) mod registry;
mod state;
mod store;

use crate::completions::generator::write_bytes_if_changed;
use crate::completions::registry::Registry;
use crate::completions::store::{
    CompletionSnapshotPublishOutcome, ManagedCompletionBindingStatus, ManagedCompletionRoot,
    ManagedCompletionRootStatus,
};
use anyhow::{Context, Result};
use clap::CommandFactory;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::util::process::which;
use std::process::Command;

const MANAGED_OVERLAY_MARKER: &str = "# managed by update-all; overlay shim";
const POWERSHELL_SELF_COMPLETION_FILE: &str = "update-all.generated.ps1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CompletionBindingIdentity {
    pub shell: String,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionCandidateIdentity {
    pub provider: String,
    pub installation: String,
    pub command_entry_point: String,
    pub exact_executable: PathBuf,
    pub launch_argv: Vec<String>,
    pub provider_native_identity: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionProviderInventoryStatus {
    Complete,
    Partial,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionProviderInventoryRecord {
    pub provider: String,
    pub status: CompletionProviderInventoryStatus,
    pub candidates: usize,
    pub reason: Option<String>,
}

#[derive(Clone)]
pub struct CompletionSyncArgs {
    pub providers_csv: String,
    pub discover: bool,
    pub report: String,
    pub catalog_path: PathBuf,
    pub config_path: Option<PathBuf>,
    /// Explicit one-release compatibility output root. `None` selects the
    /// public immutable managed-root pipeline and never writes shell rc state.
    pub rc_root: Option<PathBuf>,
    pub managed_root: PathBuf,
    pub shells: Vec<CompletionShell>,
    pub progress_cb: Option<Arc<dyn Fn(String) + Send + Sync>>,
}

#[derive(Debug)]
pub struct CompletionSyncResult {
    pub generated: usize,
    pub unchanged: usize,
    pub skipped: usize,
    pub inventories: Vec<CompletionProviderInventoryRecord>,
    pub events: Vec<String>,
    pub records: Vec<CompletionSyncRecord>,
    pub catalog_used: PathBuf,
    pub effective_catalog: Registry,
    pub outcome: CompletionSyncOutcome,
    pub shells: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionSyncOutcome {
    Reused,
    ProbedUnchanged,
    Published,
    RetainedPrevious,
    Unsupported,
    Removed,
    Failed,
}

impl CompletionSyncOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Reused => "reused",
            Self::ProbedUnchanged => "probed_unchanged",
            Self::Published => "published",
            Self::RetainedPrevious => "retained_previous",
            Self::Unsupported => "unsupported",
            Self::Removed => "removed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionArtifactClassification {
    Static,
    Dynamic,
}

impl CompletionArtifactClassification {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Dynamic => "dynamic",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionSyncRecord {
    pub provider: String,
    pub tool: String,
    pub shell: Option<String>,
    pub status: CompletionSyncRecordStatus,
    pub artifact: Option<String>,
    pub reason: Option<String>,
    pub classification: Option<CompletionArtifactClassification>,
    pub recipe: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionSyncRecordStatus {
    Generated,
    Unchanged,
    ProbedUnchanged,
    Reused,
    Retained,
    Shadowed,
    Retired,
    Skipped,
    Failed,
}

impl CompletionSyncRecord {
    fn with_status(
        provider: &str,
        tool: &str,
        status: CompletionSyncRecordStatus,
        artifact: Option<&Path>,
        reason: Option<String>,
    ) -> Self {
        Self {
            provider: provider.to_string(),
            tool: tool.to_string(),
            shell: None,
            status,
            artifact: artifact.map(|path| path.display().to_string()),
            reason,
            classification: None,
            recipe: None,
        }
    }

    fn with_artifact_details(
        provider: &str,
        tool: &str,
        status: CompletionSyncRecordStatus,
        artifact: Option<&Path>,
        reason: Option<String>,
        classification: Option<CompletionArtifactClassification>,
        recipe: Option<String>,
    ) -> Self {
        Self {
            provider: provider.to_string(),
            tool: tool.to_string(),
            shell: None,
            status,
            artifact: artifact.map(|path| path.display().to_string()),
            reason,
            classification,
            recipe,
        }
    }

    fn skipped(provider: &str, tool: &str, reason: impl Into<String>) -> Self {
        Self {
            provider: provider.to_string(),
            tool: tool.to_string(),
            shell: None,
            status: CompletionSyncRecordStatus::Skipped,
            artifact: None,
            reason: Some(reason.into()),
            classification: None,
            recipe: None,
        }
    }

    fn failed(provider: &str, tool: &str, reason: impl Into<String>) -> Self {
        Self {
            provider: provider.to_string(),
            tool: tool.to_string(),
            shell: None,
            status: CompletionSyncRecordStatus::Failed,
            artifact: None,
            reason: Some(reason.into()),
            classification: None,
            recipe: None,
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
    pub audit_command: Option<PathBuf>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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

    pub(crate) fn all() -> [Self; 5] {
        [
            Self::Bash,
            Self::Elvish,
            Self::Fish,
            Self::PowerShell,
            Self::Zsh,
        ]
    }
}

pub(crate) fn resolve_completion_shells(
    explicit: &[String],
    configured: &[String],
) -> Result<Vec<CompletionShell>> {
    let requested = if !explicit.is_empty() {
        explicit
    } else if !configured.is_empty() {
        configured
    } else {
        return Ok(detect_installed_completion_shells());
    };
    let normalized = requested
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let contains_all = normalized.iter().any(|value| value == "all");
    if contains_all && normalized.iter().any(|value| value != "all") {
        anyhow::bail!("completion shell 'all' is mutually exclusive with named shells");
    }
    let mut shells = if contains_all {
        CompletionShell::all().into_iter().collect::<BTreeSet<_>>()
    } else {
        normalized
            .iter()
            .map(|value| CompletionShell::parse(value))
            .collect::<Result<BTreeSet<_>>>()?
    };
    if shells.is_empty() {
        anyhow::bail!("completion sync requires at least one shell");
    }
    Ok(shells.iter().copied().collect())
}

fn detect_installed_completion_shells() -> Vec<CompletionShell> {
    let mut shells = BTreeSet::new();
    if let Some(current) = std::env::var_os("SHELL")
        .and_then(|path| PathBuf::from(path).file_name().map(|name| name.to_owned()))
        .and_then(|name| name.to_str().map(str::to_owned))
        .and_then(|name| CompletionShell::parse(&name).ok())
    {
        shells.insert(current);
    }
    for (shell, commands) in [
        (CompletionShell::Bash, &["bash"][..]),
        (CompletionShell::Elvish, &["elvish"][..]),
        (CompletionShell::Fish, &["fish"][..]),
        (
            CompletionShell::PowerShell,
            &["pwsh", "powershell.exe", "powershell"][..],
        ),
        (CompletionShell::Zsh, &["zsh"][..]),
    ] {
        if commands.iter().any(|command| which(command).is_some()) {
            shells.insert(shell);
        }
    }
    if shells.is_empty() {
        shells.insert(CompletionShell::Bash);
    }
    shells.into_iter().collect()
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
    engine::run_completion_sync(args)
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
    let mut slots = BTreeSet::new();
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
        if let Err(reason) = native::validate_catalog_native_tool(tool) {
            anyhow::bail!(reason);
        }
        if !slots.insert((provider.to_string(), name.to_string())) {
            anyhow::bail!(
                "completion tool '{name}' is configured more than once for provider '{provider}'"
            );
        }
    }
    Ok(())
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

    let Some(audit_command) = args.audit_command.as_deref() else {
        let msg = format!(
            "__UA_COMP_APPLY|{}|audit_skipped|audit_command_missing",
            shell.as_event_name()
        );
        if audit_mode == "strict" {
            anyhow::bail!("{msg}");
        }
        events.push(msg);
        return Ok(CompletionApplyResult { events });
    };
    validate_exact_audit_command(audit_command)?;

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
    let mut cmd = Command::new(audit_command);
    cmd.args([
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
    if shell == CompletionShell::PowerShell {
        let powershell_root = args
            .powershell_root
            .as_deref()
            .context("missing PowerShell root for powershell completion audit")?;
        cmd.args([
            "--powershell-root",
            powershell_root.to_string_lossy().as_ref(),
        ]);
    }
    cmd.env("UPDATE_ALL_COMPLETION_AUDIT_SHELL", shell.as_event_name());

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
            "__UA_COMP_APPLY|{}|audit_failed|exit={}",
            shell.as_event_name(),
            out.status.code().unwrap_or(1)
        ));
        return Err(CompletionApplyFailure { events }.into());
    }
    events.push(format!(
        "__UA_COMP_APPLY|{}|audit_ok",
        shell.as_event_name()
    ));

    Ok(CompletionApplyResult { events })
}

pub(crate) fn validate_exact_audit_command(path: &Path) -> Result<()> {
    if !path.is_absolute() || !path.is_file() {
        anyhow::bail!(
            "--audit-command must name an existing absolute executable file: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .with_context(|| format!("inspect audit executable {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            anyhow::bail!("--audit-command is not executable: {}", path.display());
        }
    }
    Ok(())
}

fn managed_completion_dir(rc_root: &Path) -> PathBuf {
    rc_root.join("shell/completions")
}

fn managed_overlay_dir(rc_root: &Path) -> PathBuf {
    rc_root.join("shell/completions-managed")
}

fn publish_public_completion_snapshot(
    managed_root: &Path,
    shells: &[CompletionShell],
    bindings: &[crate::completions::state::CompletionBindingMemo],
    candidates: &BTreeMap<
        crate::completions::state::CompletionCandidateSlot,
        crate::completions::state::CompletionCandidateMemo,
    >,
    events: &mut Vec<String>,
) -> Result<CompletionSnapshotPublishOutcome> {
    let root = ManagedCompletionRoot::new(managed_root.to_path_buf())?;
    let mut payloads = BTreeMap::new();
    let mut active_bindings = Vec::new();
    for shell in shells.iter().copied() {
        let mut payload = generate_update_all_completion(shell.as_event_name())?;
        for binding in bindings
            .iter()
            .filter(|binding| binding.binding.shell == shell.as_event_name())
        {
            let candidate = candidates.get(&binding.active_candidate).with_context(|| {
                format!(
                    "active completion candidate is missing: {:?}",
                    binding.active_candidate
                )
            })?;
            let bytes = fs::read(&candidate.artifact_path).with_context(|| {
                format!(
                    "read active completion artifact {}",
                    candidate.artifact_path.display()
                )
            })?;
            let text = String::from_utf8(bytes).with_context(|| {
                format!(
                    "active completion artifact is not UTF-8: {}",
                    candidate.artifact_path.display()
                )
            })?;
            active_bindings.push(ManagedCompletionBindingStatus {
                shell: binding.binding.shell.clone(),
                command: binding.binding.command.clone(),
                provider: candidate.slot.provider.clone(),
                executable: candidate.identity.exact_executable.clone(),
                classification: candidate
                    .artifact_classification
                    .map(|classification| classification.as_str().to_string()),
            });
            if !payload.ends_with('\n') {
                payload.push('\n');
            }
            payload.push_str(&format!(
                "\n# update-all managed binding: {}@{}\n",
                binding.binding.command, candidate.slot.provider
            ));
            payload.push_str(&text);
            if !payload.ends_with('\n') {
                payload.push('\n');
            }
            if shell == CompletionShell::Zsh {
                payload.push_str(&format!(
                    "if (( $+functions[compdef] )) && (( $+functions[_{}] )); then compdef _{} {}; fi\n",
                    binding.binding.command, binding.binding.command, binding.binding.command
                ));
            }
        }
        if shell == CompletionShell::Zsh {
            payload.push_str(
                "if (( $+functions[compdef] )) && (( $+functions[_update-all] )); then compdef _update-all update-all; fi\n",
            );
        }
        payloads.insert(shell, payload);
    }

    let outcome = root.publish_activation_assuming_lock(&payloads, active_bindings)?;
    match &outcome {
        CompletionSnapshotPublishOutcome::Published { snapshot } => {
            events.push(format!("__UA_COMP_PUBLIC|published|{}", snapshot.display()));
        }
        CompletionSnapshotPublishOutcome::Repaired { snapshot } => {
            events.push(format!("__UA_COMP_PUBLIC|repaired|{}", snapshot.display()));
        }
        CompletionSnapshotPublishOutcome::Unchanged { snapshot } => {
            events.push(format!("__UA_COMP_PUBLIC|unchanged|{}", snapshot.display()));
        }
    }

    Ok(outcome)
}

fn managed_payload_basename(provider: &str, tool: &str) -> String {
    format!("_managed_{provider}_{tool}")
}

fn candidate_payload_basename(shell: CompletionShell, provider: &str, tool: &str) -> String {
    if shell == CompletionShell::Zsh {
        managed_payload_basename(provider, tool)
    } else {
        format!("_managed_{}_{}_{}", shell.as_event_name(), provider, tool)
    }
}

fn managed_overlay_basename(tool: &str) -> String {
    format!("_{tool}")
}

struct ManagedOverlayWrite {
    pub(super) changed: bool,
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

fn remove_managed_overlay_shim(rc_root: &Path, tool: &str) -> Result<bool> {
    let overlay_path = managed_overlay_dir(rc_root).join(managed_overlay_basename(tool));
    let payload = match fs::read_to_string(&overlay_path) {
        Ok(payload) => payload,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("read {}", overlay_path.display()));
        }
    };
    if !payload
        .lines()
        .any(|line| line.trim() == MANAGED_OVERLAY_MARKER)
    {
        return Ok(false);
    }
    fs::remove_file(&overlay_path)
        .with_context(|| format!("remove managed overlay {}", overlay_path.display()))?;
    Ok(true)
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

    #[cfg(unix)]
    #[test]
    fn legacy_audit_requires_an_exact_absolute_executable() {
        let error = completion_apply(CompletionApplyArgs {
            shell: "zsh".to_string(),
            rc_root: PathBuf::from("/tmp/legacy-root"),
            powershell_root: None,
            registry_path: PathBuf::from("/tmp/registry.json"),
            managed_catalog_path: None,
            discover: false,
            audit_mode: "strict".to_string(),
            audit_command: Some(PathBuf::from("relative-audit")),
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("existing absolute executable file"));
    }

    #[cfg(unix)]
    #[test]
    fn legacy_powershell_audit_invokes_only_the_exact_executable_with_direct_argv() {
        let temp = TempDir::new().unwrap();
        let audit = temp.path().join("audit");
        crate::test_support::write_executable(
            &audit,
            "#!/bin/sh\nset -eu\nprintf 'shell=%s\\n' \"${UPDATE_ALL_COMPLETION_AUDIT_SHELL:-}\"\nfor arg in \"$@\"; do printf 'arg=%s\\n' \"$arg\"; done\n",
        )
        .unwrap();
        let result = completion_apply(CompletionApplyArgs {
            shell: "powershell".to_string(),
            rc_root: temp.path().join("legacy-root"),
            powershell_root: Some(temp.path().join("powershell-root")),
            registry_path: temp.path().join("registry.json"),
            managed_catalog_path: None,
            discover: false,
            audit_mode: "strict".to_string(),
            audit_command: Some(audit),
        })
        .unwrap();
        assert!(result
            .events
            .iter()
            .any(|event| event == "__UA_COMP_AUDIT|shell=powershell"));
        assert!(result
            .events
            .iter()
            .any(|event| event == "__UA_COMP_AUDIT|arg=--powershell-root"));
        assert!(result
            .events
            .iter()
            .any(|event| event == "__UA_COMP_APPLY|powershell|audit_ok"));
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
            rc_root: Some(rc_root),
            managed_root: temp.path().join("managed-root"),
            shells: vec![CompletionShell::Zsh],
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

// Conservative help-derived fallback. Native completion remains authoritative;
// these modules are entered only through the generator's existing fallback seam.
pub(crate) mod completion_query;
pub(crate) mod help_adapters;
pub(crate) mod help_evidence;
pub(crate) mod help_ir;
pub(crate) mod help_planner;

#[cfg(test)]
mod help_tests;
