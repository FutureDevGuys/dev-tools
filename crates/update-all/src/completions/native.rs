use super::generator::CompletionCommandSpec;
use super::registry::{RegistryBundledCompletion, RegistryCompletionRecipe, RegistryTool};
use super::{CompletionArtifactClassification, CompletionShell};
use crate::util::cancel;
use crate::util::process::{command_for_executable, terminate_process_group, which};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use wait_timeout::ChildExt;

pub(super) const NATIVE_PROTOCOL_REGISTRY_VERSION: u64 = 1;
pub(super) const NATIVE_TRUST_CLASSIFICATION_VERSION: u64 = 1;
pub(super) const MAX_BUNDLED_ARTIFACT_IDENTITY_BYTES: u64 = 4 * 1024 * 1024;

const BUNDLED_ARTIFACT_IDENTITY_VERSION: u64 = 1;

const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_TOTAL_TIMEOUT: Duration = Duration::from_secs(45);
const DEFAULT_ATTEMPT_LIMIT: usize = 96;
const DEFAULT_STDOUT_LIMIT: usize = 4 * 1024 * 1024;
const DEFAULT_STDERR_LIMIT: usize = 256 * 1024;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(20);
const PIPE_CLOSE_GRACE: Duration = Duration::from_millis(100);
const PIPE_TERMINATION_GRACE: Duration = Duration::from_secs(2);
#[cfg(windows)]
const WINDOWS_CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

const CONTROLLED_ENV_ALLOWLIST: &[&str] = &[
    "APPDATA",
    "COMSPEC",
    "HOME",
    "LANG",
    "LC_ALL",
    "LOCALAPPDATA",
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "TEMP",
    "TMP",
    "TMPDIR",
    "TZ",
    "USERPROFILE",
    "WINDIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum NativeRecipeSource {
    ProviderBundledStatic,
    Catalog,
    StdoutProtocol,
    HelpEvidenced,
    FrameworkEnvironment,
}

impl NativeRecipeSource {
    fn grants_dynamic_trust(self) -> bool {
        matches!(self, Self::ProviderBundledStatic | Self::Catalog)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::ProviderBundledStatic => "provider_bundled_static",
            Self::Catalog => "catalog",
            Self::StdoutProtocol => "stdout_protocol",
            Self::HelpEvidenced => "help_evidenced",
            Self::FrameworkEnvironment => "framework_environment",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum NativeRecipeInvocation {
    Process {
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
    StaticFile {
        path: PathBuf,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct NativeRecipeMemo {
    pub protocol_registry_version: u64,
    pub id: String,
    pub source: NativeRecipeSource,
    pub shell: String,
    pub command: String,
    pub invocation: NativeRecipeInvocation,
}

impl NativeRecipeMemo {
    pub(super) fn report_name(&self) -> String {
        format!("{}:{}", self.source.as_str(), self.id)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeCandidateOrigin {
    Managed,
    Ambient,
}

pub(super) struct NativeCompletionRequest<'a> {
    pub shell: CompletionShell,
    pub command_name: &'a str,
    pub command: &'a CompletionCommandSpec,
    pub provider_bin_dir: &'a Path,
    pub bundled_completions: &'a [RegistryBundledCompletion],
    pub catalog_recipes: &'a [RegistryCompletionRecipe],
    pub previous_recipe: Option<&'a NativeRecipeMemo>,
    pub origin: NativeCandidateOrigin,
    pub trust_dynamic: bool,
}

#[derive(Clone, Debug)]
pub(super) struct NativeCompletion {
    pub bytes: Vec<u8>,
    pub classification: CompletionArtifactClassification,
    pub recipe: NativeRecipeMemo,
}

#[derive(Clone, Debug, Default)]
pub(super) struct NativePlannerDiagnostics {
    pub rejections: Vec<String>,
}

impl NativePlannerDiagnostics {
    fn reject(&mut self, recipe: &NativeRecipeMemo, reason: impl Into<String>) {
        self.rejections.push(format!(
            "{}:{}:{}",
            recipe.source.as_str(),
            recipe.id,
            reason.into()
        ));
    }

    pub(super) fn is_empty(&self) -> bool {
        self.rejections.is_empty()
    }

    pub(super) fn summary(&self) -> String {
        self.rejections.join(";")
    }
}

#[derive(Clone, Debug)]
pub(super) enum NativePlannerOutcome {
    Completion(NativeCompletion),
    NotFound {
        root_help: Option<String>,
        diagnostics: NativePlannerDiagnostics,
    },
}

#[derive(Clone, Debug)]
enum RecipeAttempt {
    Completion(NativeCompletion),
    Rejected(String),
    NoOutput,
}

#[derive(Clone, Debug)]
pub(super) struct NativeProbeOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct NativeProbeLimits {
    per_probe_timeout: Duration,
    total_timeout: Duration,
    attempt_limit: usize,
    stdout_limit: usize,
    stderr_limit: usize,
}

impl NativeProbeLimits {
    fn from_env() -> Self {
        let per_probe_timeout = duration_from_env(
            "UPDATE_ALL_COMPLETION_PROBE_TIMEOUT_MS",
            "UPDATE_ALL_COMPLETION_PROBE_HARD_TIMEOUT",
            DEFAULT_PROBE_TIMEOUT,
        );
        let total_timeout = duration_from_env(
            "UPDATE_ALL_COMPLETION_TOTAL_TIMEOUT_MS",
            "UPDATE_ALL_COMPLETION_TOTAL_TIMEOUT",
            DEFAULT_TOTAL_TIMEOUT,
        );
        Self {
            per_probe_timeout,
            total_timeout,
            attempt_limit: usize_from_env(
                "UPDATE_ALL_COMPLETION_ATTEMPT_LIMIT",
                DEFAULT_ATTEMPT_LIMIT,
            )
            .max(1),
            stdout_limit: usize_from_env(
                "UPDATE_ALL_COMPLETION_STDOUT_LIMIT",
                DEFAULT_STDOUT_LIMIT,
            )
            .max(1),
            stderr_limit: usize_from_env(
                "UPDATE_ALL_COMPLETION_STDERR_LIMIT",
                DEFAULT_STDERR_LIMIT,
            )
            .max(1),
        }
    }
}

pub(super) struct NativeProbeSession {
    limits: NativeProbeLimits,
    started: Instant,
    remaining_attempts: usize,
}

impl NativeProbeSession {
    pub(super) fn from_env() -> Self {
        let limits = NativeProbeLimits::from_env();
        Self {
            limits,
            started: Instant::now(),
            remaining_attempts: limits.attempt_limit,
        }
    }

    pub(super) fn run_process(
        &mut self,
        command_spec: &CompletionCommandSpec,
        args: &[String],
        recipe_env: &BTreeMap<String, String>,
        label: &str,
    ) -> std::result::Result<NativeProbeOutput, String> {
        let invocation_args = command_spec
            .args
            .iter()
            .chain(args.iter())
            .cloned()
            .collect::<Vec<_>>();
        validate_non_mutating_args(&invocation_args)?;
        let remaining_total = self.reserve_attempt()?;
        let timeout = self.limits.per_probe_timeout.min(remaining_total);
        let total_limited = remaining_total <= self.limits.per_probe_timeout;
        match run_bounded_process(
            command_spec,
            args,
            recipe_env,
            timeout,
            self.limits.stdout_limit,
            self.limits.stderr_limit,
        ) {
            Ok(output) => Ok(output),
            Err(BoundedProcessError::TimedOut) if total_limited => {
                Err("native_total_deadline_exhausted".to_string())
            }
            Err(BoundedProcessError::TimedOut) => Err(format!("native_probe_timeout:{label}")),
            Err(BoundedProcessError::StdoutLimit) => {
                Err(format!("native_stdout_limit_exceeded:{label}"))
            }
            Err(BoundedProcessError::StderrLimit) => {
                Err(format!("native_stderr_limit_exceeded:{label}"))
            }
            Err(BoundedProcessError::Cancelled) => Err("native_probe_cancelled".to_string()),
            Err(BoundedProcessError::Spawn(error)) => {
                Err(format!("native_spawn_failed:{label}:{error}"))
            }
            Err(BoundedProcessError::Wait(error)) => {
                Err(format!("native_wait_failed:{label}:{error}"))
            }
            Err(BoundedProcessError::Pipe(error)) => {
                Err(format!("native_capture_failed:{label}:{error}"))
            }
        }
    }

    fn reserve_attempt(&mut self) -> std::result::Result<Duration, String> {
        if cancel::is_cancel_requested() {
            return Err("native_probe_cancelled".to_string());
        }
        if self.remaining_attempts == 0 {
            return Err("native_attempt_budget_exhausted".to_string());
        }
        let remaining = self.remaining_total()?;
        self.remaining_attempts -= 1;
        Ok(remaining)
    }

    fn remaining_total(&self) -> std::result::Result<Duration, String> {
        self.limits
            .total_timeout
            .checked_sub(self.started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| "native_total_deadline_exhausted".to_string())
    }

    fn read_static_file(
        &mut self,
        path: &Path,
        label: &str,
    ) -> std::result::Result<Option<Vec<u8>>, String> {
        self.reserve_attempt()?;
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(format!(
                    "native_bundled_artifact_read_failed:{label}:{error}"
                ));
            }
        };
        if !metadata.is_file() {
            return Err(format!("native_bundled_artifact_not_regular:{label}"));
        }
        if metadata.len() > self.limits.stdout_limit as u64 {
            return Err(format!("native_stdout_limit_exceeded:{label}"));
        }
        let mut file = File::open(path)
            .map_err(|error| format!("native_bundled_artifact_read_failed:{label}:{error}"))?;
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take((self.limits.stdout_limit + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("native_bundled_artifact_read_failed:{label}:{error}"))?;
        if bytes.len() > self.limits.stdout_limit {
            return Err(format!("native_stdout_limit_exceeded:{label}"));
        }
        self.remaining_total()?;
        Ok(Some(bytes))
    }

    #[cfg(test)]
    fn with_limits(limits: NativeProbeLimits) -> Self {
        Self {
            limits,
            started: Instant::now(),
            remaining_attempts: limits.attempt_limit,
        }
    }

    #[cfg(test)]
    fn attempts_used(&self) -> usize {
        self.limits
            .attempt_limit
            .saturating_sub(self.remaining_attempts)
    }
}

pub(super) fn validate_catalog_native_tool(tool: &RegistryTool) -> std::result::Result<(), String> {
    for (index, candidate) in tool.command_candidates.iter().enumerate() {
        validate_non_mutating_args(&candidate.args).map_err(|reason| {
            format!(
                "completion tool '{}': command_candidates[{index}].args {reason}",
                tool.name
            )
        })?;
        validate_non_mutating_args(&candidate.probe_args).map_err(|reason| {
            format!(
                "completion tool '{}': command_candidates[{index}].probe_args {reason}",
                tool.name
            )
        })?;
    }

    let mut bundled_ids = BTreeSet::new();
    for (index, artifact) in tool.bundled_completions.iter().enumerate() {
        CompletionShell::parse(&artifact.shell).map_err(|_| {
            format!(
                "completion tool '{}': bundled_completions[{index}] has unsupported shell '{}'",
                tool.name, artifact.shell
            )
        })?;
        if artifact.path.trim().is_empty() {
            return Err(format!(
                "completion tool '{}': bundled_completions[{index}].path is empty",
                tool.name
            ));
        }
        if Path::new(artifact.path.trim()).is_absolute()
            || Path::new(artifact.path.trim())
                .components()
                .any(|component| {
                    matches!(
                        component,
                        Component::ParentDir | Component::RootDir | Component::Prefix(_)
                    )
                })
            || ["{executable}", "{executable_dir}", "{provider_bin_dir}"]
                .iter()
                .any(|token| artifact.path.contains(token))
        {
            return Err(format!(
                "completion tool '{}': bundled_completions[{index}].path must stay relative to the provider bin directory",
                tool.name
            ));
        }
        if let Some(id) = artifact.id.as_deref() {
            let id = id.trim();
            if id.is_empty() || !bundled_ids.insert(id.to_string()) {
                return Err(format!(
                    "completion tool '{}': bundled completion id '{}' is empty or duplicated",
                    tool.name, id
                ));
            }
        }
    }

    let mut recipe_ids = BTreeSet::new();
    for (index, recipe) in tool.completion_recipes.iter().enumerate() {
        if recipe.args.is_empty() && recipe.env.is_empty() {
            return Err(format!(
                "completion tool '{}': completion_recipes[{index}] must provide args or env",
                tool.name
            ));
        }
        if let Some(id) = recipe.id.as_deref() {
            let id = id.trim();
            if id.is_empty() || !recipe_ids.insert(id.to_string()) {
                return Err(format!(
                    "completion tool '{}': completion recipe id '{}' is empty or duplicated",
                    tool.name, id
                ));
            }
        }
        for shell in &recipe.shells {
            CompletionShell::parse(shell).map_err(|_| {
                format!(
                    "completion tool '{}': completion_recipes[{index}] has unsupported shell '{}'",
                    tool.name, shell
                )
            })?;
        }
        validate_environment(&recipe.env).map_err(|reason| {
            format!(
                "completion tool '{}': completion_recipes[{index}] {reason}",
                tool.name
            )
        })?;
        let memo = NativeRecipeMemo {
            protocol_registry_version: NATIVE_PROTOCOL_REGISTRY_VERSION,
            id: recipe
                .id
                .clone()
                .unwrap_or_else(|| format!("catalog-{index}")),
            source: NativeRecipeSource::Catalog,
            shell: "validation".to_string(),
            command: tool.name.clone(),
            invocation: NativeRecipeInvocation::Process {
                args: recipe.args.clone(),
                env: recipe.env.clone(),
            },
        };
        validate_non_mutating_recipe(&memo).map_err(|reason| {
            format!(
                "completion tool '{}': completion_recipes[{index}] {reason}",
                tool.name
            )
        })?;
    }
    Ok(())
}

#[derive(Serialize)]
struct ProviderBundledArtifactIdentity {
    version: u64,
    max_bytes: u64,
    artifacts: Vec<BundledArtifactIdentityRecord>,
}

#[derive(Serialize)]
struct BundledArtifactIdentityRecord {
    shell: String,
    configured_path: String,
    id: Option<String>,
    resolved_path: PathBuf,
    file: BundledArtifactFileIdentity,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum BundledArtifactFileIdentity {
    Missing,
    Present { bytes: u64, sha256: String },
}

pub(super) fn provider_bundled_artifact_identity(
    shell: CompletionShell,
    command_name: &str,
    command: &CompletionCommandSpec,
    provider_bin_dir: &Path,
    bundled_completions: &[RegistryBundledCompletion],
) -> std::result::Result<String, String> {
    let request = NativeCompletionRequest {
        shell,
        command_name,
        command,
        provider_bin_dir,
        bundled_completions,
        catalog_recipes: &[],
        previous_recipe: None,
        origin: NativeCandidateOrigin::Managed,
        trust_dynamic: false,
    };
    let mut records = Vec::new();
    for resolved in resolved_provider_bundled_artifacts(&request)? {
        let label = bundled_artifact_identity_label(&resolved.declaration);
        let file = bundled_artifact_file_identity(&label, &resolved.path)?;
        records.push(BundledArtifactIdentityRecord {
            shell: resolved.declaration.shell,
            configured_path: resolved.declaration.path,
            id: resolved.declaration.id,
            resolved_path: resolved.path,
            file,
        });
    }
    let identity = ProviderBundledArtifactIdentity {
        version: BUNDLED_ARTIFACT_IDENTITY_VERSION,
        max_bytes: MAX_BUNDLED_ARTIFACT_IDENTITY_BYTES,
        artifacts: records,
    };
    let bytes = serde_json::to_vec(&identity)
        .map_err(|error| format!("bundled_artifact_identity_failed:{error}"))?;
    Ok(full_sha256_hex(&bytes))
}

fn bundled_artifact_identity_label(artifact: &RegistryBundledCompletion) -> String {
    artifact
        .id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .unwrap_or(artifact.path.as_str())
        .to_string()
}

fn bundled_artifact_file_identity(
    label: &str,
    path: &Path,
) -> std::result::Result<BundledArtifactFileIdentity, String> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BundledArtifactFileIdentity::Missing);
        }
        Err(error) => {
            return Err(format!(
                "native_bundled_artifact_identity_read_failed:{label}:{}:{error}",
                path.display()
            ));
        }
    };
    if !metadata.is_file() {
        return Err(format!(
            "native_bundled_artifact_identity_not_regular:{label}:{}",
            path.display()
        ));
    }
    if metadata.len() > MAX_BUNDLED_ARTIFACT_IDENTITY_BYTES {
        return Err(format!(
            "native_bundled_artifact_identity_limit_exceeded:{label}:{}",
            path.display()
        ));
    }

    let file = File::open(path).map_err(|error| {
        format!(
            "native_bundled_artifact_identity_read_failed:{label}:{}:{error}",
            path.display()
        )
    })?;
    let mut reader = file.take(MAX_BUNDLED_ARTIFACT_IDENTITY_BYTES + 1);
    let mut hasher = Sha256::new();
    let mut bytes_read = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let read = reader.read(&mut buffer).map_err(|error| {
            format!(
                "native_bundled_artifact_identity_read_failed:{label}:{}:{error}",
                path.display()
            )
        })?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read.saturating_add(read as u64);
        if bytes_read > MAX_BUNDLED_ARTIFACT_IDENTITY_BYTES {
            return Err(format!(
                "native_bundled_artifact_identity_limit_exceeded:{label}:{}",
                path.display()
            ));
        }
        hasher.update(&buffer[..read]);
    }

    Ok(BundledArtifactFileIdentity::Present {
        bytes: bytes_read,
        sha256: format!("{:x}", hasher.finalize()),
    })
}

fn full_sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub(super) fn plan_native_completion(
    request: NativeCompletionRequest<'_>,
    session: &mut NativeProbeSession,
) -> std::result::Result<NativePlannerOutcome, String> {
    validate_command_name(request.command_name)?;
    validate_non_mutating_args(&request.command.args)?;
    let mut attempted = BTreeSet::new();
    let mut diagnostics = NativePlannerDiagnostics::default();

    let bundled = provider_bundled_recipes(&request)?;
    if let Some(completion) = attempt_recipe_sequence(
        &request,
        session,
        bundled.iter().cloned(),
        &mut attempted,
        &mut diagnostics,
    )? {
        return Ok(NativePlannerOutcome::Completion(completion));
    }

    let catalog = catalog_recipes(&request)?;
    if let Some(previous) = request
        .previous_recipe
        .filter(|previous| previous_recipe_is_current(&request, previous, &bundled, &catalog))
    {
        if let Some(completion) = attempt_recipe_sequence(
            &request,
            session,
            std::iter::once(previous.clone()),
            &mut attempted,
            &mut diagnostics,
        )? {
            return Ok(NativePlannerOutcome::Completion(completion));
        }
    }

    if let Some(completion) = attempt_recipe_sequence(
        &request,
        session,
        catalog.iter().cloned(),
        &mut attempted,
        &mut diagnostics,
    )? {
        return Ok(NativePlannerOutcome::Completion(completion));
    }

    let high_yield = stdout_protocol_recipes(
        request.shell,
        request.command_name,
        ProtocolTier::HighYield,
        NativeRecipeSource::StdoutProtocol,
    );
    if let Some(completion) = attempt_recipe_sequence(
        &request,
        session,
        high_yield,
        &mut attempted,
        &mut diagnostics,
    )? {
        return Ok(NativePlannerOutcome::Completion(completion));
    }

    let root_help = read_help_text(
        request.command,
        &["--help".to_string()],
        session,
        "native-help-evidence:root",
    )?;
    if let Some(help) = root_help.as_deref() {
        let evidenced = help_evidenced_recipes(&request, session, help)?;
        if let Some(completion) = attempt_recipe_sequence(
            &request,
            session,
            evidenced,
            &mut attempted,
            &mut diagnostics,
        )? {
            return Ok(NativePlannerOutcome::Completion(completion));
        }

        if help_indicates_click_or_typer(help) {
            if let Some(completion) = attempt_recipe_sequence(
                &request,
                session,
                framework_environment_recipes(request.shell, request.command_name),
                &mut attempted,
                &mut diagnostics,
            )? {
                return Ok(NativePlannerOutcome::Completion(completion));
            }
        }
    }

    Ok(NativePlannerOutcome::NotFound {
        root_help,
        diagnostics,
    })
}

fn attempt_recipe_sequence(
    request: &NativeCompletionRequest<'_>,
    session: &mut NativeProbeSession,
    recipes: impl IntoIterator<Item = NativeRecipeMemo>,
    attempted: &mut BTreeSet<String>,
    diagnostics: &mut NativePlannerDiagnostics,
) -> std::result::Result<Option<NativeCompletion>, String> {
    for recipe in recipes {
        match attempt_recipe(request, session, recipe.clone(), attempted)? {
            RecipeAttempt::Completion(completion) => return Ok(Some(completion)),
            RecipeAttempt::Rejected(reason) => diagnostics.reject(&recipe, reason),
            RecipeAttempt::NoOutput => {}
        }
    }
    Ok(None)
}

fn validate_command_name(command: &str) -> std::result::Result<(), String> {
    static COMMAND_RE: std::sync::OnceLock<std::result::Result<Regex, regex::Error>> =
        std::sync::OnceLock::new();
    let command_re = COMMAND_RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.+@-]*$"));
    let command_re = command_re
        .as_ref()
        .map_err(|_| "internal_error:native_command_validator".to_string())?;
    if !command_re.is_match(command) {
        return Err("invalid_identifier".to_string());
    }
    Ok(())
}

fn validate_recipe_scope(
    request: &NativeCompletionRequest<'_>,
    recipe: &NativeRecipeMemo,
) -> std::result::Result<(), String> {
    match recipe.source {
        NativeRecipeSource::ProviderBundledStatic => {
            let NativeRecipeInvocation::StaticFile { path } = &recipe.invocation else {
                return Err(
                    "native_recipe_source_invocation_mismatch:provider_bundled_static".to_string(),
                );
            };
            let root = provider_artifact_root(request);
            let canonical_root = fs::canonicalize(&root).unwrap_or(root);
            let candidate = if path.is_absolute() {
                path.clone()
            } else {
                canonical_root.join(path)
            };
            let resolved = match fs::canonicalize(&candidate) {
                Ok(path) => path,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => candidate,
                Err(error) => {
                    return Err(format!(
                        "native_bundled_artifact_resolution_failed:{}:{error}",
                        path.display()
                    ));
                }
            };
            if !resolved.starts_with(&canonical_root) {
                return Err(format!(
                    "native_bundled_artifact_outside_provider:{}",
                    path.display()
                ));
            }
        }
        NativeRecipeSource::Catalog => {
            if !matches!(&recipe.invocation, NativeRecipeInvocation::Process { .. }) {
                return Err("native_recipe_source_invocation_mismatch:catalog".to_string());
            }
        }
        NativeRecipeSource::StdoutProtocol => {
            validate_registry_recipe(
                request,
                recipe,
                stdout_protocol_recipes(
                    request.shell,
                    request.command_name,
                    ProtocolTier::HighYield,
                    NativeRecipeSource::StdoutProtocol,
                ),
            )?;
        }
        NativeRecipeSource::HelpEvidenced => {
            validate_registry_recipe(
                request,
                recipe,
                stdout_protocol_recipes(
                    request.shell,
                    request.command_name,
                    ProtocolTier::EvidenceOnly,
                    NativeRecipeSource::HelpEvidenced,
                ),
            )?;
        }
        NativeRecipeSource::FrameworkEnvironment => {
            validate_registry_recipe(
                request,
                recipe,
                framework_environment_recipes(request.shell, request.command_name),
            )?;
        }
    }
    Ok(())
}

fn validate_registry_recipe(
    request: &NativeCompletionRequest<'_>,
    recipe: &NativeRecipeMemo,
    current: Vec<NativeRecipeMemo>,
) -> std::result::Result<(), String> {
    if !matches!(&recipe.invocation, NativeRecipeInvocation::Process { .. }) {
        return Err(format!(
            "native_recipe_source_invocation_mismatch:{}",
            recipe.source.as_str()
        ));
    }
    let key = recipe_key(recipe);
    if !current.iter().any(|candidate| recipe_key(candidate) == key) {
        return Err(format!(
            "native_recipe_not_in_registry:{}:{}:{}",
            request.shell.as_event_name(),
            request.command_name,
            recipe.source.as_str()
        ));
    }
    Ok(())
}

fn attempt_recipe(
    request: &NativeCompletionRequest<'_>,
    session: &mut NativeProbeSession,
    recipe: NativeRecipeMemo,
    attempted: &mut BTreeSet<String>,
) -> std::result::Result<RecipeAttempt, String> {
    if recipe.shell != request.shell.as_event_name() || recipe.command != request.command_name {
        return Err("native_recipe_identity_mismatch".to_string());
    }
    validate_non_mutating_recipe(&recipe)?;
    validate_recipe_scope(request, &recipe)?;
    let key = recipe_key(&recipe);
    if !attempted.insert(key) {
        return Ok(RecipeAttempt::NoOutput);
    }

    let raw = match &recipe.invocation {
        NativeRecipeInvocation::StaticFile { path } => {
            let Some(bytes) = session.read_static_file(path, &recipe.id)? else {
                return Ok(RecipeAttempt::NoOutput);
            };
            bytes
        }
        NativeRecipeInvocation::Process { args, env } => {
            validate_environment(env)?;
            let output = session.run_process(request.command, args, env, &recipe.id)?;
            if !output.success {
                return Ok(RecipeAttempt::NoOutput);
            }
            output.stdout
        }
    };
    let bytes = match normalize_native_output(&raw) {
        Ok(bytes) => bytes,
        Err(reason) => return Ok(RecipeAttempt::Rejected(reason)),
    };
    if bytes.is_empty() {
        return Ok(RecipeAttempt::NoOutput);
    }

    if let Err(reason) = validate_no_leading_banner(request.shell, &bytes) {
        return Ok(RecipeAttempt::Rejected(reason));
    }
    match registration_status(request.shell, request.command_name, &bytes) {
        Ok(RegistrationStatus::Absent) => {
            return Ok(RecipeAttempt::Rejected(
                "native_registration_absent".to_string(),
            ));
        }
        Ok(RegistrationStatus::WrongCommand(commands)) => {
            let names = if commands.is_empty() {
                "unknown".to_string()
            } else {
                commands.into_iter().collect::<Vec<_>>().join(",")
            };
            return Ok(RecipeAttempt::Rejected(format!(
                "native_registration_wrong_command:expected={}:found={names}",
                request.command_name
            )));
        }
        Ok(RegistrationStatus::Matches) => {}
        Err(reason) => return Ok(RecipeAttempt::Rejected(reason)),
    }

    if let Err(reason) = validate_shell_syntax(request.shell, &bytes, session) {
        if reason.starts_with("native_syntax_validation_failed:") {
            return Ok(RecipeAttempt::Rejected(reason));
        }
        return Err(reason);
    }
    let classification = match classify_native_output(request.shell, request.command_name, &bytes) {
        Ok(classification) => classification,
        Err(reason) => return Ok(RecipeAttempt::Rejected(reason)),
    };
    enforce_dynamic_policy(
        classification,
        request.origin,
        request.trust_dynamic,
        recipe.source,
    )?;

    Ok(RecipeAttempt::Completion(NativeCompletion {
        bytes,
        classification,
        recipe,
    }))
}

pub(super) fn stored_artifact_is_healthy(shell: &str, command: &str, bytes: &[u8]) -> bool {
    let Ok(shell) = CompletionShell::parse(shell) else {
        return false;
    };
    let Ok(normalized) = normalize_native_output(bytes) else {
        return false;
    };
    !normalized.is_empty()
        && validate_no_leading_banner(shell, &normalized).is_ok()
        && matches!(
            registration_status(shell, command, &normalized),
            Ok(RegistrationStatus::Matches)
        )
}

fn normalize_native_output(raw: &[u8]) -> std::result::Result<Vec<u8>, String> {
    if raw.starts_with(&[0xff, 0xfe]) || raw.starts_with(&[0xfe, 0xff]) {
        return Err("native_output_unsupported_bom".to_string());
    }
    let raw = raw.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(raw);
    if raw.contains(&0) {
        return Err("native_output_contains_nul".to_string());
    }
    std::str::from_utf8(raw).map_err(|_| "native_output_invalid_utf8".to_string())?;

    let mut normalized = Vec::with_capacity(raw.len().saturating_add(1));
    let mut index = 0usize;
    while index < raw.len() {
        if raw[index] == b'\r' {
            if raw.get(index + 1) == Some(&b'\n') {
                index += 1;
            }
            normalized.push(b'\n');
        } else {
            normalized.push(raw[index]);
        }
        index += 1;
    }
    while normalized.last() == Some(&b'\n') {
        normalized.pop();
    }
    if !normalized.is_empty() {
        normalized.push(b'\n');
    }
    Ok(normalized)
}

#[derive(Debug)]
enum RegistrationStatus {
    Matches,
    WrongCommand(BTreeSet<String>),
    Absent,
}

fn registration_status(
    shell: CompletionShell,
    command: &str,
    bytes: &[u8],
) -> std::result::Result<RegistrationStatus, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "native_output_invalid_utf8".to_string())?;
    let commands = registered_commands(shell, text)?;
    if commands.contains(command) {
        Ok(RegistrationStatus::Matches)
    } else if commands.is_empty() {
        Ok(RegistrationStatus::Absent)
    } else {
        Ok(RegistrationStatus::WrongCommand(commands))
    }
}

fn registered_commands(
    shell: CompletionShell,
    text: &str,
) -> std::result::Result<BTreeSet<String>, String> {
    match shell {
        CompletionShell::Bash => Ok(registered_bash_commands(text)),
        CompletionShell::Zsh => Ok(registered_zsh_commands(text)),
        CompletionShell::Fish => Ok(registered_fish_commands(text)),
        CompletionShell::Elvish => registered_elvish_commands(text),
        CompletionShell::PowerShell => registered_powershell_commands(text),
    }
}

fn registered_bash_commands(text: &str) -> BTreeSet<String> {
    let mut commands = BTreeSet::new();
    for line in logical_lines(text) {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("complete ") && trimmed != "complete" {
            continue;
        }
        let tokens = shellish_tokens(trimmed);
        let mut skip_value = false;
        for (index, token) in tokens.iter().enumerate().skip(1) {
            if skip_value {
                skip_value = false;
                continue;
            }
            if matches!(
                token.as_str(),
                "-A" | "-G" | "-W" | "-F" | "-C" | "-X" | "-P" | "-S" | "-o"
            ) {
                skip_value = true;
                continue;
            }
            if token == "--" {
                for command in tokens.iter().skip(index + 1) {
                    if is_command_token(command) {
                        commands.insert(command.clone());
                    }
                }
                break;
            }
            if !token.starts_with('-') && is_command_token(token) {
                commands.insert(token.clone());
            }
        }
    }
    commands
}

fn registered_zsh_commands(text: &str) -> BTreeSet<String> {
    let mut commands = BTreeSet::new();
    for line in logical_lines(text) {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("#compdef") {
            for token in shellish_tokens(rest) {
                let command = token.split('=').next().unwrap_or("");
                if !command.starts_with('-') && is_command_token(command) {
                    commands.insert(command.to_string());
                }
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("compdef ") {
            let tokens = shellish_tokens(rest);
            for token in tokens.into_iter().skip(1) {
                let command = token.split('=').next().unwrap_or("");
                if !command.starts_with('-') && is_command_token(command) {
                    commands.insert(command.to_string());
                }
            }
        }
    }
    commands
}

fn registered_fish_commands(text: &str) -> BTreeSet<String> {
    let mut commands = BTreeSet::new();
    for line in logical_lines(text) {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("complete ") && trimmed != "complete" {
            continue;
        }
        let tokens = shellish_tokens(trimmed);
        let mut index = 1usize;
        while index < tokens.len() {
            let token = &tokens[index];
            if token == "-c" || token == "--command" {
                if let Some(command) = tokens.get(index + 1) {
                    if is_command_token(command) {
                        commands.insert(command.clone());
                    }
                }
                index += 2;
                continue;
            }
            if let Some(command) = token.strip_prefix("--command=") {
                if is_command_token(command) {
                    commands.insert(command.to_string());
                }
            }
            index += 1;
        }
    }
    commands
}

fn registered_elvish_commands(text: &str) -> std::result::Result<BTreeSet<String>, String> {
    let pattern =
        Regex::new(r#"(?m)edit:completion:arg-completer\[\s*['\"]?([A-Za-z0-9_.+@-]+)['\"]?\s*\]"#)
            .map_err(|_| "internal_error:elvish_registration_validator".to_string())?;
    Ok(pattern
        .captures_iter(text)
        .filter_map(|capture| capture.get(1).map(|value| value.as_str().to_string()))
        .collect())
}

fn registered_powershell_commands(text: &str) -> std::result::Result<BTreeSet<String>, String> {
    let pattern = Regex::new(
        r#"(?is)Register-ArgumentCompleter\b.{0,2048}?-CommandName(?:\s+|:)\s*['\"]?([A-Za-z0-9_.+@-]+)['\"]?"#,
    )
    .map_err(|_| "internal_error:powershell_registration_validator".to_string())?;
    Ok(pattern
        .captures_iter(text)
        .filter_map(|capture| capture.get(1).map(|value| value.as_str().to_string()))
        .collect())
}

fn logical_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        let trimmed_end = line.trim_end();
        if trimmed_end.ends_with('\\') || trimmed_end.ends_with('`') {
            let without_continuation = &trimmed_end[..trimmed_end.len().saturating_sub(1)];
            current.push_str(without_continuation);
            current.push(' ');
            continue;
        }
        current.push_str(line);
        lines.push(std::mem::take(&mut current));
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn shellish_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if character == active {
                quote = None;
            } else {
                current.push(character);
            }
            continue;
        }
        if character == '\'' || character == '"' {
            quote = Some(character);
        } else if character.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn is_command_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.+@-".contains(&byte))
}

fn validate_no_leading_banner(
    shell: CompletionShell,
    bytes: &[u8],
) -> std::result::Result<(), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "native_output_invalid_utf8".to_string())?;
    let mut in_powershell_block_comment = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if shell == CompletionShell::PowerShell && in_powershell_block_comment {
            if trimmed.contains("#>") {
                in_powershell_block_comment = false;
            }
            continue;
        }
        if shell == CompletionShell::PowerShell && trimmed.starts_with("<#") {
            in_powershell_block_comment = !trimmed.contains("#>");
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with("#!") {
            continue;
        }
        if shell == CompletionShell::Zsh && trimmed.starts_with("#compdef") {
            return Ok(());
        }
        if trimmed.starts_with('#') {
            continue;
        }
        if looks_like_shell_start(shell, trimmed) {
            return Ok(());
        }
        return Err("native_output_leading_banner".to_string());
    }
    Ok(())
}

fn looks_like_shell_start(shell: CompletionShell, line: &str) -> bool {
    match shell {
        CompletionShell::Bash | CompletionShell::Zsh => {
            line.starts_with("function ")
                || line.starts_with("complete ")
                || line.starts_with("compdef ")
                || line.starts_with("autoload ")
                || line.starts_with("typeset ")
                || line.starts_with("declare ")
                || line.starts_with("local ")
                || line.starts_with("emulate ")
                || line.starts_with("setopt ")
                || line.starts_with("if ")
                || line.starts_with("case ")
                || line.starts_with('_')
                || is_function_declaration(line)
                || is_assignment(line)
        }
        CompletionShell::Fish => {
            line.starts_with("function ")
                || line.starts_with("complete ")
                || line.starts_with("set ")
                || line.starts_with("if ")
        }
        CompletionShell::Elvish => {
            line.starts_with("use ")
                || line.starts_with("fn ")
                || line.starts_with("var ")
                || line.starts_with("set ")
                || line.starts_with("edit:")
        }
        CompletionShell::PowerShell => {
            line.starts_with("using ")
                || line.starts_with("function ")
                || line.starts_with("Register-ArgumentCompleter")
                || line.starts_with("Set-StrictMode")
                || line.starts_with("param")
                || line.starts_with('$')
                || line.starts_with('[')
        }
    }
}

fn is_function_declaration(line: &str) -> bool {
    let Some(prefix) = line.split_once('(').map(|(prefix, _)| prefix.trim()) else {
        return false;
    };
    is_command_token(prefix) && line.contains(')')
}

fn is_assignment(line: &str) -> bool {
    let Some((name, _)) = line.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn classify_native_output(
    shell: CompletionShell,
    _command: &str,
    bytes: &[u8],
) -> std::result::Result<CompletionArtifactClassification, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "native_output_invalid_utf8".to_string())?;
    let declarative = match shell {
        CompletionShell::Bash => narrowly_declarative_bash_payload(text),
        CompletionShell::Fish => narrowly_declarative_fish_payload(text),
        CompletionShell::Zsh | CompletionShell::Elvish | CompletionShell::PowerShell => false,
    };
    Ok(if declarative {
        CompletionArtifactClassification::Static
    } else {
        CompletionArtifactClassification::Dynamic
    })
}

fn narrowly_declarative_bash_payload(text: &str) -> bool {
    let mut saw_declaration = false;
    for line in logical_lines(text) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if declarative_line_has_executable_syntax(trimmed)
            || !bash_complete_line_is_declarative(trimmed)
        {
            return false;
        }
        saw_declaration = true;
    }
    saw_declaration
}

fn bash_complete_line_is_declarative(line: &str) -> bool {
    let tokens = shellish_tokens(line);
    if tokens.first().map(String::as_str) != Some("complete") {
        return false;
    }

    let mut index = 1usize;
    let mut parsing_options = true;
    let mut saw_completion_spec = false;
    let mut saw_command = false;
    while index < tokens.len() {
        let token = &tokens[index];
        if parsing_options {
            match token.as_str() {
                "--" => {
                    parsing_options = false;
                    index += 1;
                    continue;
                }
                "-A" | "-G" | "-W" | "-X" | "-P" | "-S" | "-o" => {
                    let Some(value) = tokens.get(index + 1) else {
                        return false;
                    };
                    if value.is_empty() {
                        return false;
                    }
                    saw_completion_spec = true;
                    index += 2;
                    continue;
                }
                "-a" | "-b" | "-c" | "-d" | "-e" | "-f" | "-g" | "-j" | "-k" | "-s" | "-u"
                | "-v" => {
                    saw_completion_spec = true;
                    index += 1;
                    continue;
                }
                "-F" | "-C" | "-D" | "-E" | "-I" | "-p" | "-r" => {
                    return false;
                }
                _ if token.starts_with('-') => return false,
                _ => parsing_options = false,
            }
        }
        if !is_command_token(token) {
            return false;
        }
        saw_command = true;
        index += 1;
    }

    saw_completion_spec && saw_command
}

fn narrowly_declarative_fish_payload(text: &str) -> bool {
    let mut saw_declaration = false;
    for line in logical_lines(text) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if declarative_line_has_executable_syntax(trimmed)
            || !fish_complete_line_is_declarative(trimmed)
        {
            return false;
        }
        saw_declaration = true;
    }
    saw_declaration
}

fn fish_complete_line_is_declarative(line: &str) -> bool {
    let tokens = shellish_tokens(line);
    if tokens.first().map(String::as_str) != Some("complete") {
        return false;
    }

    let mut index = 1usize;
    let mut saw_command = false;
    let mut saw_completion_spec = false;
    while index < tokens.len() {
        let token = &tokens[index];
        match token.as_str() {
            "-c" | "--command" => {
                let Some(command) = tokens.get(index + 1) else {
                    return false;
                };
                if !is_command_token(command) {
                    return false;
                }
                saw_command = true;
                index += 2;
            }
            "-s" | "--short-option" | "-l" | "--long-option" | "-o" | "--old-option" | "-a"
            | "--arguments" | "-d" | "--description" => {
                let Some(value) = tokens.get(index + 1) else {
                    return false;
                };
                if value.is_empty() {
                    return false;
                }
                saw_completion_spec = true;
                index += 2;
            }
            "-f"
            | "--no-files"
            | "-F"
            | "--force-files"
            | "-r"
            | "--require-parameter"
            | "-x"
            | "--exclusive"
            | "-k"
            | "--keep-order" => {
                saw_completion_spec = true;
                index += 1;
            }
            _ => {
                if let Some(command) = token.strip_prefix("--command=") {
                    if !is_command_token(command) {
                        return false;
                    }
                    saw_command = true;
                    index += 1;
                    continue;
                }
                if [
                    "--short-option=",
                    "--long-option=",
                    "--old-option=",
                    "--arguments=",
                    "--description=",
                ]
                .iter()
                .any(|prefix| {
                    token
                        .strip_prefix(prefix)
                        .is_some_and(|value| !value.is_empty())
                }) {
                    saw_completion_spec = true;
                    index += 1;
                    continue;
                }
                return false;
            }
        }
    }

    saw_command && saw_completion_spec
}

fn declarative_line_has_executable_syntax(line: &str) -> bool {
    line.bytes().any(|byte| {
        matches!(
            byte,
            b'$' | b'`'
                | b';'
                | b'|'
                | b'&'
                | b'<'
                | b'>'
                | b'('
                | b')'
                | b'{'
                | b'}'
                | b'\\'
                | b'#'
        )
    })
}

fn enforce_dynamic_policy(
    classification: CompletionArtifactClassification,
    origin: NativeCandidateOrigin,
    trust_dynamic: bool,
    source: NativeRecipeSource,
) -> std::result::Result<(), String> {
    if classification == CompletionArtifactClassification::Dynamic
        && origin == NativeCandidateOrigin::Ambient
        && !trust_dynamic
        && !source.grants_dynamic_trust()
    {
        return Err("native_policy_rejected:ambient_dynamic_requires_explicit_trust".to_string());
    }
    Ok(())
}

fn validate_shell_syntax(
    shell: CompletionShell,
    bytes: &[u8],
    session: &mut NativeProbeSession,
) -> std::result::Result<(), String> {
    let Some(validator) = shell_validator(shell) else {
        return Ok(());
    };
    validate_shell_syntax_with_validator(shell, bytes, &validator, session)
}

fn validate_shell_syntax_with_validator(
    shell: CompletionShell,
    bytes: &[u8],
    validator: &Path,
    session: &mut NativeProbeSession,
) -> std::result::Result<(), String> {
    let temp = ValidationFile::create(shell, bytes)?;
    let path = temp.path().display().to_string();
    let (args, label) = match shell {
        CompletionShell::Bash | CompletionShell::Zsh => (
            vec!["-n".to_string(), path],
            format!("syntax:{}", shell.as_event_name()),
        ),
        CompletionShell::Fish => (
            vec!["--no-execute".to_string(), path],
            "syntax:fish".to_string(),
        ),
        CompletionShell::Elvish => (
            vec!["-compileonly".to_string(), path],
            "syntax:elvish".to_string(),
        ),
        CompletionShell::PowerShell => (
            vec![
                "-NoLogo".to_string(),
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                "$tokens = $null; $parseErrors = $null; [System.Management.Automation.Language.Parser]::ParseFile($args[0], [ref]$tokens, [ref]$parseErrors) > $null; if ($parseErrors.Count -ne 0) { $parseErrors | ForEach-Object { [Console]::Error.WriteLine($_.Message) }; exit 1 }".to_string(),
                path,
            ],
            "syntax:powershell".to_string(),
        ),
    };
    let command = CompletionCommandSpec {
        program: validator.to_path_buf(),
        args: Vec::new(),
    };
    let output = session.run_process(&command, &args, &BTreeMap::new(), &label)?;
    if output.success {
        Ok(())
    } else {
        Err(format!(
            "native_syntax_validation_failed:{}",
            shell.as_event_name()
        ))
    }
}

fn shell_validator(shell: CompletionShell) -> Option<PathBuf> {
    let candidates: &[&str] = match shell {
        CompletionShell::Bash => &["bash"],
        CompletionShell::Zsh => &["zsh"],
        CompletionShell::Fish => &["fish"],
        CompletionShell::Elvish => &["elvish"],
        CompletionShell::PowerShell => &["pwsh", "powershell.exe", "powershell"],
    };
    candidates.iter().find_map(|candidate| which(candidate))
}

struct ValidationFile {
    path: PathBuf,
}

impl ValidationFile {
    fn create(shell: CompletionShell, bytes: &[u8]) -> std::result::Result<Self, String> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let extension = match shell {
            CompletionShell::Bash => "bash",
            CompletionShell::Zsh => "zsh",
            CompletionShell::Fish => "fish",
            CompletionShell::Elvish => "elv",
            CompletionShell::PowerShell => "ps1",
        };
        for _ in 0..32 {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "update-all-native-completion-{}-{}-{id}.{extension}",
                std::process::id(),
                shell.as_event_name()
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    if let Err(error) = file.write_all(bytes) {
                        drop(file);
                        let _ = fs::remove_file(&path);
                        return Err(format!("native_validation_file_write_failed:{error}"));
                    }
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!("native_validation_file_create_failed:{error}"));
                }
            }
        }
        Err("native_validation_file_create_failed:name_exhausted".to_string())
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ValidationFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProtocolTier {
    HighYield,
    EvidenceOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProtocolHead {
    Subcommand(&'static str),
    TopLevelFlag(&'static str),
}

impl ProtocolHead {
    fn value(self) -> &'static str {
        match self {
            Self::Subcommand(value) | Self::TopLevelFlag(value) => value,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShellArgumentStyle {
    Positional,
    ShellFlagSeparated,
    ShellFlagJoined,
    HeadJoined,
}

#[derive(Clone, Copy, Debug)]
struct ProtocolForm {
    id: &'static str,
    head: ProtocolHead,
    style: ShellArgumentStyle,
    tier: ProtocolTier,
}

const PROTOCOL_FORMS: &[ProtocolForm] = &[
    ProtocolForm {
        id: "completion-positional",
        head: ProtocolHead::Subcommand("completion"),
        style: ShellArgumentStyle::Positional,
        tier: ProtocolTier::HighYield,
    },
    ProtocolForm {
        id: "completion-shell-separated",
        head: ProtocolHead::Subcommand("completion"),
        style: ShellArgumentStyle::ShellFlagSeparated,
        tier: ProtocolTier::EvidenceOnly,
    },
    ProtocolForm {
        id: "completion-shell-joined",
        head: ProtocolHead::Subcommand("completion"),
        style: ShellArgumentStyle::ShellFlagJoined,
        tier: ProtocolTier::EvidenceOnly,
    },
    ProtocolForm {
        id: "completions-positional",
        head: ProtocolHead::Subcommand("completions"),
        style: ShellArgumentStyle::Positional,
        tier: ProtocolTier::HighYield,
    },
    ProtocolForm {
        id: "completions-shell-separated",
        head: ProtocolHead::Subcommand("completions"),
        style: ShellArgumentStyle::ShellFlagSeparated,
        tier: ProtocolTier::EvidenceOnly,
    },
    ProtocolForm {
        id: "completions-shell-joined",
        head: ProtocolHead::Subcommand("completions"),
        style: ShellArgumentStyle::ShellFlagJoined,
        tier: ProtocolTier::EvidenceOnly,
    },
    ProtocolForm {
        id: "generate-completion-positional",
        head: ProtocolHead::Subcommand("generate-completion"),
        style: ShellArgumentStyle::Positional,
        tier: ProtocolTier::HighYield,
    },
    ProtocolForm {
        id: "generate-completion-shell-separated",
        head: ProtocolHead::Subcommand("generate-completion"),
        style: ShellArgumentStyle::ShellFlagSeparated,
        tier: ProtocolTier::EvidenceOnly,
    },
    ProtocolForm {
        id: "generate-completion-shell-joined",
        head: ProtocolHead::Subcommand("generate-completion"),
        style: ShellArgumentStyle::ShellFlagJoined,
        tier: ProtocolTier::EvidenceOnly,
    },
    ProtocolForm {
        id: "generate-completions-positional",
        head: ProtocolHead::Subcommand("generate-completions"),
        style: ShellArgumentStyle::Positional,
        tier: ProtocolTier::HighYield,
    },
    ProtocolForm {
        id: "generate-completions-shell-separated",
        head: ProtocolHead::Subcommand("generate-completions"),
        style: ShellArgumentStyle::ShellFlagSeparated,
        tier: ProtocolTier::EvidenceOnly,
    },
    ProtocolForm {
        id: "generate-completions-shell-joined",
        head: ProtocolHead::Subcommand("generate-completions"),
        style: ShellArgumentStyle::ShellFlagJoined,
        tier: ProtocolTier::EvidenceOnly,
    },
    ProtocolForm {
        id: "gen-completion-positional",
        head: ProtocolHead::Subcommand("gen-completion"),
        style: ShellArgumentStyle::Positional,
        tier: ProtocolTier::HighYield,
    },
    ProtocolForm {
        id: "gen-completion-shell-separated",
        head: ProtocolHead::Subcommand("gen-completion"),
        style: ShellArgumentStyle::ShellFlagSeparated,
        tier: ProtocolTier::EvidenceOnly,
    },
    ProtocolForm {
        id: "gen-completion-shell-joined",
        head: ProtocolHead::Subcommand("gen-completion"),
        style: ShellArgumentStyle::ShellFlagJoined,
        tier: ProtocolTier::EvidenceOnly,
    },
    ProtocolForm {
        id: "top-completion-positional",
        head: ProtocolHead::TopLevelFlag("--completion"),
        style: ShellArgumentStyle::Positional,
        tier: ProtocolTier::HighYield,
    },
    ProtocolForm {
        id: "top-completion-head-joined",
        head: ProtocolHead::TopLevelFlag("--completion"),
        style: ShellArgumentStyle::HeadJoined,
        tier: ProtocolTier::HighYield,
    },
    ProtocolForm {
        id: "top-completion-shell-separated",
        head: ProtocolHead::TopLevelFlag("--completion"),
        style: ShellArgumentStyle::ShellFlagSeparated,
        tier: ProtocolTier::EvidenceOnly,
    },
    ProtocolForm {
        id: "top-completion-shell-joined",
        head: ProtocolHead::TopLevelFlag("--completion"),
        style: ShellArgumentStyle::ShellFlagJoined,
        tier: ProtocolTier::EvidenceOnly,
    },
    ProtocolForm {
        id: "top-completions-positional",
        head: ProtocolHead::TopLevelFlag("--completions"),
        style: ShellArgumentStyle::Positional,
        tier: ProtocolTier::HighYield,
    },
    ProtocolForm {
        id: "top-completions-head-joined",
        head: ProtocolHead::TopLevelFlag("--completions"),
        style: ShellArgumentStyle::HeadJoined,
        tier: ProtocolTier::HighYield,
    },
    ProtocolForm {
        id: "top-completions-shell-separated",
        head: ProtocolHead::TopLevelFlag("--completions"),
        style: ShellArgumentStyle::ShellFlagSeparated,
        tier: ProtocolTier::EvidenceOnly,
    },
    ProtocolForm {
        id: "top-completions-shell-joined",
        head: ProtocolHead::TopLevelFlag("--completions"),
        style: ShellArgumentStyle::ShellFlagJoined,
        tier: ProtocolTier::EvidenceOnly,
    },
    ProtocolForm {
        id: "top-show-completion-positional",
        head: ProtocolHead::TopLevelFlag("--show-completion"),
        style: ShellArgumentStyle::Positional,
        tier: ProtocolTier::HighYield,
    },
    ProtocolForm {
        id: "top-show-completion-head-joined",
        head: ProtocolHead::TopLevelFlag("--show-completion"),
        style: ShellArgumentStyle::HeadJoined,
        tier: ProtocolTier::HighYield,
    },
    ProtocolForm {
        id: "top-show-completion-shell-separated",
        head: ProtocolHead::TopLevelFlag("--show-completion"),
        style: ShellArgumentStyle::ShellFlagSeparated,
        tier: ProtocolTier::EvidenceOnly,
    },
    ProtocolForm {
        id: "top-show-completion-shell-joined",
        head: ProtocolHead::TopLevelFlag("--show-completion"),
        style: ShellArgumentStyle::ShellFlagJoined,
        tier: ProtocolTier::EvidenceOnly,
    },
];

fn stdout_protocol_recipes(
    shell: CompletionShell,
    command: &str,
    tier: ProtocolTier,
    source: NativeRecipeSource,
) -> Vec<NativeRecipeMemo> {
    let mut recipes = Vec::new();
    let mut seen = BTreeSet::new();
    for form in PROTOCOL_FORMS.iter().filter(|form| form.tier == tier) {
        for shell_name in protocol_shell_names(shell) {
            let args = render_protocol_args(*form, shell_name);
            let key = args.join("\u{1f}");
            if !seen.insert(key) {
                continue;
            }
            recipes.push(NativeRecipeMemo {
                protocol_registry_version: NATIVE_PROTOCOL_REGISTRY_VERSION,
                id: format!(
                    "v{}:{}:{shell_name}",
                    NATIVE_PROTOCOL_REGISTRY_VERSION, form.id
                ),
                source,
                shell: shell.as_event_name().to_string(),
                command: command.to_string(),
                invocation: NativeRecipeInvocation::Process {
                    args,
                    env: BTreeMap::new(),
                },
            });
        }
    }
    recipes
}

fn render_protocol_args(form: ProtocolForm, shell_name: &str) -> Vec<String> {
    let head = form.head.value();
    match form.style {
        ShellArgumentStyle::Positional => vec![head.to_string(), shell_name.to_string()],
        ShellArgumentStyle::ShellFlagSeparated => vec![
            head.to_string(),
            "--shell".to_string(),
            shell_name.to_string(),
        ],
        ShellArgumentStyle::ShellFlagJoined => {
            vec![head.to_string(), format!("--shell={shell_name}")]
        }
        ShellArgumentStyle::HeadJoined => vec![format!("{head}={shell_name}")],
    }
}

fn protocol_shell_names(shell: CompletionShell) -> &'static [&'static str] {
    match shell {
        CompletionShell::Bash => &["bash"],
        CompletionShell::Zsh => &["zsh"],
        CompletionShell::Fish => &["fish"],
        CompletionShell::Elvish => &["elvish"],
        CompletionShell::PowerShell => &["powershell", "pwsh"],
    }
}

fn help_evidenced_recipes(
    request: &NativeCompletionRequest<'_>,
    session: &mut NativeProbeSession,
    root_help: &str,
) -> std::result::Result<Vec<NativeRecipeMemo>, String> {
    let mut nested_help = BTreeMap::<String, String>::new();
    let subcommands = PROTOCOL_FORMS
        .iter()
        .filter(|form| form.tier == ProtocolTier::EvidenceOnly)
        .filter_map(|form| match form.head {
            ProtocolHead::Subcommand(head) if help_mentions_protocol_head(root_help, head) => {
                Some(head)
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    for head in subcommands {
        let args = vec![head.to_string(), "--help".to_string()];
        if let Some(help) = read_help_text(
            request.command,
            &args,
            session,
            &format!("native-help-evidence:{head}"),
        )? {
            nested_help.insert(head.to_string(), help);
        }
    }

    let mut recipes = Vec::new();
    let mut seen = BTreeSet::new();
    for form in PROTOCOL_FORMS
        .iter()
        .copied()
        .filter(|form| form.tier == ProtocolTier::EvidenceOnly)
    {
        let head = form.head.value();
        if !help_mentions_protocol_head(root_help, head) {
            continue;
        }
        let shell_flag_evidenced = match form.head {
            ProtocolHead::Subcommand(head) => {
                nested_help
                    .get(head)
                    .map(String::as_str)
                    .is_some_and(help_mentions_shell_flag)
                    || help_mentions_shell_flag(root_help)
            }
            ProtocolHead::TopLevelFlag(_) => help_mentions_shell_flag(root_help),
        };
        if matches!(
            form.style,
            ShellArgumentStyle::ShellFlagSeparated | ShellArgumentStyle::ShellFlagJoined
        ) && !shell_flag_evidenced
        {
            continue;
        }
        for shell_name in protocol_shell_names(request.shell) {
            let args = render_protocol_args(form, shell_name);
            if !seen.insert(args.join("\u{1f}")) {
                continue;
            }
            recipes.push(NativeRecipeMemo {
                protocol_registry_version: NATIVE_PROTOCOL_REGISTRY_VERSION,
                id: format!(
                    "v{}:{}:{shell_name}",
                    NATIVE_PROTOCOL_REGISTRY_VERSION, form.id
                ),
                source: NativeRecipeSource::HelpEvidenced,
                shell: request.shell.as_event_name().to_string(),
                command: request.command_name.to_string(),
                invocation: NativeRecipeInvocation::Process {
                    args,
                    env: BTreeMap::new(),
                },
            });
        }
    }
    Ok(recipes)
}

fn help_mentions_protocol_head(help: &str, head: &str) -> bool {
    if head.starts_with('-') {
        return help.split_whitespace().any(|token| {
            token
                .trim_matches(|character: char| {
                    matches!(
                        character,
                        ',' | ';' | ':' | '[' | ']' | '(' | ')' | '<' | '>'
                    )
                })
                .split('=')
                .next()
                == Some(head)
        });
    }
    help.split(|character: char| !(character.is_ascii_alphanumeric() || character == '-'))
        .any(|token| token == head)
}

fn help_mentions_shell_flag(help: &str) -> bool {
    help.split_whitespace().any(|token| {
        token
            .trim_matches(|character: char| {
                matches!(
                    character,
                    ',' | ';' | ':' | '[' | ']' | '(' | ')' | '<' | '>'
                )
            })
            .split('=')
            .next()
            == Some("--shell")
    })
}

fn read_help_text(
    command: &CompletionCommandSpec,
    args: &[String],
    session: &mut NativeProbeSession,
    label: &str,
) -> std::result::Result<Option<String>, String> {
    let output = session.run_process(command, args, &BTreeMap::new(), label)?;
    if !output.success {
        return Ok(None);
    }
    let mut merged = output.stdout;
    if !output.stderr.is_empty() {
        if !merged.is_empty() && !merged.ends_with(b"\n") {
            merged.push(b'\n');
        }
        merged.extend_from_slice(&output.stderr);
    }
    if merged.is_empty() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&merged).into_owned()))
}

fn help_indicates_click_or_typer(help: &str) -> bool {
    let lower = help.to_ascii_lowercase();
    lower.contains("show this message and exit")
        && (lower.contains("options:") || lower.contains("commands:"))
}

fn framework_environment_recipes(shell: CompletionShell, command: &str) -> Vec<NativeRecipeMemo> {
    let source_name = match shell {
        CompletionShell::Bash => "bash_source",
        CompletionShell::Zsh => "zsh_source",
        CompletionShell::Fish => "fish_source",
        CompletionShell::Elvish | CompletionShell::PowerShell => return Vec::new(),
    };
    let mut recipe_env = BTreeMap::new();
    recipe_env.insert(click_completion_env_name(command), source_name.to_string());
    vec![NativeRecipeMemo {
        protocol_registry_version: NATIVE_PROTOCOL_REGISTRY_VERSION,
        id: format!(
            "v{}:click-typer:{source_name}",
            NATIVE_PROTOCOL_REGISTRY_VERSION
        ),
        source: NativeRecipeSource::FrameworkEnvironment,
        shell: shell.as_event_name().to_string(),
        command: command.to_string(),
        invocation: NativeRecipeInvocation::Process {
            args: Vec::new(),
            env: recipe_env,
        },
    }]
}

fn click_completion_env_name(command: &str) -> String {
    let normalized = command
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("_{normalized}_COMPLETE")
}

#[derive(Clone)]
struct ResolvedProviderBundledArtifact {
    declaration: RegistryBundledCompletion,
    path: PathBuf,
}

fn resolved_provider_bundled_artifacts(
    request: &NativeCompletionRequest<'_>,
) -> std::result::Result<Vec<ResolvedProviderBundledArtifact>, String> {
    let root = provider_artifact_root(request);
    let canonical_root = fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
    let mut resolved_artifacts = Vec::new();
    let mut seen_paths = BTreeSet::new();
    for artifact in request.bundled_completions {
        let shell = CompletionShell::parse(&artifact.shell)
            .map_err(|_| format!("catalog_bundled_invalid_shell:{}", artifact.shell))?;
        if shell != request.shell {
            continue;
        }
        let expanded = expand_template(artifact.path.trim(), request);
        let relative = Path::new(&expanded);
        if expanded.is_empty()
            || relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(format!("catalog_bundled_path_outside_provider:{expanded}"));
        }
        let joined = root.join(relative);
        let resolved = match fs::canonicalize(&joined) {
            Ok(path) => {
                if !path.starts_with(&canonical_root) {
                    return Err(format!(
                        "catalog_bundled_path_outside_provider:{}",
                        joined.display()
                    ));
                }
                path
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                canonical_root.join(relative)
            }
            Err(error) => {
                return Err(format!(
                    "catalog_bundled_path_resolution_failed:{}:{error}",
                    joined.display()
                ));
            }
        };
        if !seen_paths.insert(resolved.clone()) {
            continue;
        }
        resolved_artifacts.push(ResolvedProviderBundledArtifact {
            declaration: artifact.clone(),
            path: resolved,
        });
    }
    Ok(resolved_artifacts)
}

fn provider_bundled_recipes(
    request: &NativeCompletionRequest<'_>,
) -> std::result::Result<Vec<NativeRecipeMemo>, String> {
    let mut recipes = Vec::new();
    for resolved in resolved_provider_bundled_artifacts(request)? {
        let artifact = resolved.declaration;
        let fallback_id = stable_recipe_id(
            "bundled",
            format!("{}:{}", artifact.shell, artifact.path).as_bytes(),
        );
        recipes.push(NativeRecipeMemo {
            protocol_registry_version: NATIVE_PROTOCOL_REGISTRY_VERSION,
            id: artifact
                .id
                .filter(|id| !id.trim().is_empty())
                .unwrap_or(fallback_id),
            source: NativeRecipeSource::ProviderBundledStatic,
            shell: request.shell.as_event_name().to_string(),
            command: request.command_name.to_string(),
            invocation: NativeRecipeInvocation::StaticFile {
                path: resolved.path,
            },
        });
    }
    Ok(recipes)
}

fn provider_artifact_root(request: &NativeCompletionRequest<'_>) -> PathBuf {
    if !request.provider_bin_dir.as_os_str().is_empty() && request.provider_bin_dir.is_dir() {
        return request.provider_bin_dir.to_path_buf();
    }
    request
        .command
        .program
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| request.provider_bin_dir.to_path_buf())
}

fn catalog_recipes(
    request: &NativeCompletionRequest<'_>,
) -> std::result::Result<Vec<NativeRecipeMemo>, String> {
    let mut recipes = Vec::new();
    for recipe in request.catalog_recipes {
        if !catalog_recipe_matches_shell(recipe, request.shell)? {
            continue;
        }
        let args = recipe
            .args
            .iter()
            .map(|value| expand_template(value, request))
            .collect::<Vec<_>>();
        let recipe_env = recipe
            .env
            .iter()
            .map(|(key, value)| (key.clone(), expand_template(value, request)))
            .collect::<BTreeMap<_, _>>();
        validate_environment(&recipe_env)?;
        let fallback_bytes = serde_json::to_vec(&(recipe.shells.clone(), &args, &recipe_env))
            .map_err(|error| format!("catalog_recipe_identity_failed:{error}"))?;
        let memo = NativeRecipeMemo {
            protocol_registry_version: NATIVE_PROTOCOL_REGISTRY_VERSION,
            id: recipe
                .id
                .clone()
                .filter(|id| !id.trim().is_empty())
                .unwrap_or_else(|| stable_recipe_id("catalog", &fallback_bytes)),
            source: NativeRecipeSource::Catalog,
            shell: request.shell.as_event_name().to_string(),
            command: request.command_name.to_string(),
            invocation: NativeRecipeInvocation::Process {
                args,
                env: recipe_env,
            },
        };
        validate_non_mutating_recipe(&memo)?;
        recipes.push(memo);
    }
    Ok(recipes)
}

fn catalog_recipe_matches_shell(
    recipe: &RegistryCompletionRecipe,
    shell: CompletionShell,
) -> std::result::Result<bool, String> {
    if recipe.shells.is_empty() {
        return Ok(true);
    }
    for raw in &recipe.shells {
        let parsed = CompletionShell::parse(raw)
            .map_err(|_| format!("catalog_recipe_invalid_shell:{raw}"))?;
        if parsed == shell {
            return Ok(true);
        }
    }
    Ok(false)
}

fn expand_template(value: &str, request: &NativeCompletionRequest<'_>) -> String {
    let executable = request.command.program.display().to_string();
    let executable_name = request
        .command
        .program
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(request.command_name);
    let executable_dir = request
        .command
        .program
        .parent()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    value
        .replace("{shell}", request.shell.as_event_name())
        .replace("{command}", request.command_name)
        .replace("{executable}", &executable)
        .replace("{executable_name}", executable_name)
        .replace("{executable_dir}", &executable_dir)
        .replace(
            "{provider_bin_dir}",
            &request.provider_bin_dir.display().to_string(),
        )
}

fn previous_recipe_is_current(
    request: &NativeCompletionRequest<'_>,
    previous: &NativeRecipeMemo,
    bundled: &[NativeRecipeMemo],
    catalog: &[NativeRecipeMemo],
) -> bool {
    if previous.protocol_registry_version != NATIVE_PROTOCOL_REGISTRY_VERSION
        || previous.shell != request.shell.as_event_name()
        || previous.command != request.command_name
    {
        return false;
    }
    let current = match previous.source {
        NativeRecipeSource::ProviderBundledStatic => bundled.to_vec(),
        NativeRecipeSource::Catalog => catalog.to_vec(),
        NativeRecipeSource::StdoutProtocol => stdout_protocol_recipes(
            request.shell,
            request.command_name,
            ProtocolTier::HighYield,
            NativeRecipeSource::StdoutProtocol,
        ),
        NativeRecipeSource::HelpEvidenced => stdout_protocol_recipes(
            request.shell,
            request.command_name,
            ProtocolTier::EvidenceOnly,
            NativeRecipeSource::HelpEvidenced,
        ),
        NativeRecipeSource::FrameworkEnvironment => {
            framework_environment_recipes(request.shell, request.command_name)
        }
    };
    let previous_key = recipe_key(previous);
    current
        .iter()
        .any(|recipe| recipe_key(recipe) == previous_key)
}

fn recipe_key(recipe: &NativeRecipeMemo) -> String {
    match serde_json::to_vec(recipe) {
        Ok(bytes) => stable_recipe_id("recipe", &bytes),
        Err(_) => format!(
            "recipe:{}:{}:{}:{:?}",
            recipe.protocol_registry_version,
            recipe.source.as_str(),
            recipe.id,
            recipe.invocation
        ),
    }
}

fn stable_recipe_id(prefix: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = format!("{:x}", hasher.finalize());
    format!("{prefix}-{}", &digest[..16])
}

fn validate_environment(recipe_env: &BTreeMap<String, String>) -> std::result::Result<(), String> {
    for (key, value) in recipe_env {
        if key.is_empty()
            || key.contains('=')
            || key.contains('\0')
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(format!("native_recipe_invalid_environment_key:{key}"));
        }
        if value.contains('\0') {
            return Err(format!("native_recipe_invalid_environment_value:{key}"));
        }
    }
    Ok(())
}

fn validate_non_mutating_recipe(recipe: &NativeRecipeMemo) -> std::result::Result<(), String> {
    let NativeRecipeInvocation::Process { args, .. } = &recipe.invocation else {
        return Ok(());
    };
    validate_non_mutating_args(args)
}

fn validate_non_mutating_args(args: &[String]) -> std::result::Result<(), String> {
    if args.iter().any(|arg| arg.contains('\0')) {
        return Err("native_recipe_argument_contains_nul".to_string());
    }
    let normalized = args
        .iter()
        .map(|arg| normalize_recipe_arg(arg))
        .collect::<Vec<_>>();
    if normalized
        .iter()
        .any(|arg| is_mutating_completion_form(arg))
        || normalized.windows(2).any(|pair| {
            matches!(
                (pair[0].as_str(), pair[1].as_str()),
                ("install", "completion")
                    | ("install", "completions")
                    | ("completion", "install")
                    | ("completions", "install")
            )
        })
    {
        return Err("native_mutating_recipe_rejected:install_completion".to_string());
    }
    Ok(())
}

fn normalize_recipe_arg(arg: &str) -> String {
    arg.trim()
        .trim_start_matches('-')
        .replace('_', "-")
        .to_ascii_lowercase()
}

fn is_mutating_completion_form(normalized: &str) -> bool {
    let head = normalized.split('=').next().unwrap_or(normalized);
    matches!(
        head,
        "install-completion" | "install-completions" | "completion-install" | "completions-install"
    )
}

fn duration_from_env(milliseconds: &str, seconds: &str, fallback: Duration) -> Duration {
    if let Some(value) = env::var(milliseconds)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    {
        return Duration::from_millis(value.max(1));
    }
    env::var(seconds)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| Duration::from_secs(value.max(1)))
        .unwrap_or(fallback)
}

fn usize_from_env(key: &str, fallback: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(fallback)
}

#[derive(Debug)]
enum BoundedProcessError {
    TimedOut,
    Cancelled,
    StdoutLimit,
    StderrLimit,
    Spawn(String),
    Wait(String),
    Pipe(String),
}

fn run_bounded_process(
    command_spec: &CompletionCommandSpec,
    args: &[String],
    recipe_env: &BTreeMap<String, String>,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> std::result::Result<NativeProbeOutput, BoundedProcessError> {
    let mut command = command_for_executable(&command_spec.program);
    command.args(&command_spec.args);
    command.args(args);
    command.current_dir(env::temp_dir());
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    configure_controlled_environment(&mut command, recipe_env);
    #[cfg(unix)]
    {
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        command.creation_flags(WINDOWS_CREATE_NEW_PROCESS_GROUP);
    }

    let mut child = command
        .spawn()
        .map_err(|error| BoundedProcessError::Spawn(error.to_string()))?;
    let pid = child.id();
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            terminate_process_tree(&mut child, pid);
            return Err(BoundedProcessError::Pipe(
                "stdout_pipe_unavailable".to_string(),
            ));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            terminate_process_tree(&mut child, pid);
            return Err(BoundedProcessError::Pipe(
                "stderr_pipe_unavailable".to_string(),
            ));
        }
    };
    let stdout_overflow = Arc::new(AtomicBool::new(false));
    let stderr_overflow = Arc::new(AtomicBool::new(false));
    let stdout_rx = read_pipe_bounded(stdout, stdout_limit, Arc::clone(&stdout_overflow));
    let stderr_rx = read_pipe_bounded(stderr, stderr_limit, Arc::clone(&stderr_overflow));

    let started = Instant::now();
    let status = loop {
        if stdout_overflow.load(Ordering::SeqCst) {
            terminate_process_tree(&mut child, pid);
            drain_pipe_receivers(stdout_rx, stderr_rx);
            return Err(BoundedProcessError::StdoutLimit);
        }
        if stderr_overflow.load(Ordering::SeqCst) {
            terminate_process_tree(&mut child, pid);
            drain_pipe_receivers(stdout_rx, stderr_rx);
            return Err(BoundedProcessError::StderrLimit);
        }
        if cancel::is_cancel_requested() {
            terminate_process_tree(&mut child, pid);
            drain_pipe_receivers(stdout_rx, stderr_rx);
            return Err(BoundedProcessError::Cancelled);
        }
        if started.elapsed() >= timeout {
            terminate_process_tree(&mut child, pid);
            drain_pipe_receivers(stdout_rx, stderr_rx);
            return Err(BoundedProcessError::TimedOut);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => std::thread::sleep(PROCESS_POLL_INTERVAL),
            Err(error) => {
                terminate_process_tree(&mut child, pid);
                drain_pipe_receivers(stdout_rx, stderr_rx);
                return Err(BoundedProcessError::Wait(error.to_string()));
            }
        }
    };

    let (stdout, stderr) = collect_pipe_receivers(stdout_rx, stderr_rx, &mut child, pid)?;
    if stdout_overflow.load(Ordering::SeqCst) {
        return Err(BoundedProcessError::StdoutLimit);
    }
    if stderr_overflow.load(Ordering::SeqCst) {
        return Err(BoundedProcessError::StderrLimit);
    }
    Ok(NativeProbeOutput {
        success: status.success(),
        stdout,
        stderr,
    })
}

fn configure_controlled_environment(command: &mut Command, recipe_env: &BTreeMap<String, String>) {
    command.env_clear();
    for key in CONTROLLED_ENV_ALLOWLIST {
        if let Some(value) = env::var_os(key) {
            command.env(key, value);
        }
    }
    command.env("NO_COLOR", "1");
    command.env("TERM", "dumb");
    command.env("PAGER", "cat");
    command.env("GIT_PAGER", "cat");
    command.env("MANPAGER", "cat");
    for (key, value) in recipe_env {
        command.env(key, value);
    }
}

fn read_pipe_bounded<R: Read + Send + 'static>(
    mut reader: R,
    limit: usize,
    overflow: Arc<AtomicBool>,
) -> mpsc::Receiver<std::result::Result<Vec<u8>, String>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::with_capacity(limit.min(8192));
        let mut buffer = [0u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    let available = limit.saturating_sub(bytes.len());
                    let keep = read.min(available);
                    bytes.extend_from_slice(&buffer[..keep]);
                    if keep < read {
                        overflow.store(true, Ordering::SeqCst);
                    }
                }
                Err(error) => {
                    let _ = tx.send(Err(error.to_string()));
                    return;
                }
            }
        }
        let _ = tx.send(Ok(bytes));
    });
    rx
}

fn collect_pipe_receivers(
    stdout_rx: mpsc::Receiver<std::result::Result<Vec<u8>, String>>,
    stderr_rx: mpsc::Receiver<std::result::Result<Vec<u8>, String>>,
    child: &mut Child,
    pid: u32,
) -> std::result::Result<(Vec<u8>, Vec<u8>), BoundedProcessError> {
    let close_deadline = Instant::now() + PIPE_CLOSE_GRACE;
    let stdout = recv_pipe_until(&stdout_rx, close_deadline);
    let stderr = recv_pipe_until(&stderr_rx, close_deadline);
    if stdout.is_some() && stderr.is_some() {
        return combine_pipe_results(stdout, stderr);
    }

    terminate_process_tree(child, pid);
    let termination_deadline = Instant::now() + PIPE_TERMINATION_GRACE;
    let stdout = stdout.or_else(|| recv_pipe_until(&stdout_rx, termination_deadline));
    let stderr = stderr.or_else(|| recv_pipe_until(&stderr_rx, termination_deadline));
    combine_pipe_results(stdout, stderr)
}

fn combine_pipe_results(
    stdout: Option<std::result::Result<Vec<u8>, String>>,
    stderr: Option<std::result::Result<Vec<u8>, String>>,
) -> std::result::Result<(Vec<u8>, Vec<u8>), BoundedProcessError> {
    let stdout = stdout
        .ok_or_else(|| BoundedProcessError::Pipe("stdout_pipe_did_not_close".to_string()))?
        .map_err(BoundedProcessError::Pipe)?;
    let stderr = stderr
        .ok_or_else(|| BoundedProcessError::Pipe("stderr_pipe_did_not_close".to_string()))?
        .map_err(BoundedProcessError::Pipe)?;
    Ok((stdout, stderr))
}

fn recv_pipe_until(
    receiver: &mpsc::Receiver<std::result::Result<Vec<u8>, String>>,
    deadline: Instant,
) -> Option<std::result::Result<Vec<u8>, String>> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return receiver.try_recv().ok();
    }
    receiver.recv_timeout(remaining).ok()
}

fn drain_pipe_receivers(
    stdout_rx: mpsc::Receiver<std::result::Result<Vec<u8>, String>>,
    stderr_rx: mpsc::Receiver<std::result::Result<Vec<u8>, String>>,
) {
    let deadline = Instant::now() + PIPE_TERMINATION_GRACE;
    let _ = recv_pipe_until(&stdout_rx, deadline);
    let _ = recv_pipe_until(&stderr_rx, deadline);
}

fn terminate_process_tree(child: &mut Child, pid: u32) {
    #[cfg(unix)]
    {
        terminate_process_group(pid);
    }
    #[cfg(windows)]
    {
        let taskkill = env::var_os("SystemRoot")
            .map(PathBuf::from)
            .map(|root| root.join("System32").join("taskkill.exe"))
            .unwrap_or_else(|| PathBuf::from("taskkill.exe"));
        let pid_text = pid.to_string();
        if let Ok(mut killer) = Command::new(taskkill)
            .args(["/PID", pid_text.as_str(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            match killer.wait_timeout(PIPE_TERMINATION_GRACE) {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => {
                    let _ = killer.kill();
                    let _ = killer.wait_timeout(PIPE_TERMINATION_GRACE);
                }
            }
        }
    }
    let _ = child.kill();
    match child.wait_timeout(PIPE_TERMINATION_GRACE) {
        Ok(Some(_)) => {}
        Ok(None) | Err(_) => {
            let _ = child.kill();
            let _ = child.wait_timeout(PIPE_TERMINATION_GRACE);
        }
    }
}

#[cfg(all(test, unix))]
#[path = "../tests/completions_native.rs"]
mod tests;
