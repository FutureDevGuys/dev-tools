use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

const BINDING_RECEIPT_SCHEMA: &str = "dev-auth-workload-binding-receipt-v1";
const MAX_BINDING_TARGET_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BindingMode {
    Strong,
    UserOnly,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BindingAuthority {
    RootOwned,
    UserOwned,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BindingChange {
    Unchanged,
    Refresh,
    Rebind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BindingPlanChange {
    Install,
    Unchanged,
    Refresh,
    Rebind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BindingPlanActionKind {
    ValidateTarget,
    DeactivateProxy,
    PublishBinding,
    ActivateProxy,
    VerifyBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BindingPlanAction {
    pub order: u16,
    pub action: BindingPlanActionKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutableIdentity {
    pub canonical_path: PathBuf,
    pub length: u64,
    pub sha256: String,
    pub authority: BindingAuthority,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inode: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolvedContinuation {
    pub visible_path: PathBuf,
    pub canonical_path: PathBuf,
    pub continuation_path: OsString,
    pub search_index: usize,
    pub identity: ExecutableIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BindingTargetIntent {
    Continuation,
    Structured {
        executable: PathBuf,
        argv_prefix: Vec<OsString>,
        caller_argument_index: usize,
    },
    PinnedShell {
        shell: PathBuf,
        source_sha256: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BindingIntent {
    pub command_name: String,
    pub workload: String,
    pub target: BindingTargetIntent,
}

impl BindingIntent {
    pub fn continuation(
        command_name: impl Into<String>,
        workload: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            command_name.into(),
            workload.into(),
            BindingTargetIntent::Continuation,
        )
    }

    pub fn structured<I, S>(
        command_name: impl Into<String>,
        workload: impl Into<String>,
        executable: impl Into<PathBuf>,
        argv_prefix: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let executable = executable.into();
        require_absolute_normal_path(&executable, "structured binding executable")?;
        let argv_prefix = argv_prefix.into_iter().map(Into::into).collect::<Vec<_>>();
        let caller_argument_index = argv_prefix.len();
        Self::new(
            command_name.into(),
            workload.into(),
            BindingTargetIntent::Structured {
                executable,
                argv_prefix,
                caller_argument_index,
            },
        )
    }

    fn new(command_name: String, workload: String, target: BindingTargetIntent) -> Result<Self> {
        require_simple_name(&command_name, "binding command")?;
        require_simple_name(&workload, "binding workload")?;
        Ok(Self {
            command_name,
            workload,
            target,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BindingGeneration {
    pub generation: u64,
    pub intent: BindingIntent,
    pub resolved: ResolvedContinuation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BindingReceipt {
    pub schema: String,
    pub platform: String,
    pub active: BindingGeneration,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<BindingGeneration>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BindingPlan {
    pub schema: String,
    pub platform: String,
    pub name: String,
    pub intent: BindingIntent,
    pub resolved: ResolvedContinuation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_receipt: Option<BindingReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_receipt_sha256: Option<String>,
    pub change: BindingPlanChange,
    pub actions: Vec<BindingPlanAction>,
}

impl BindingReceipt {
    pub fn new(intent: BindingIntent, resolved: ResolvedContinuation) -> Result<Self> {
        validate_intent_resolution(&intent, &resolved)?;
        Ok(Self {
            schema: BINDING_RECEIPT_SCHEMA.to_owned(),
            platform: current_platform(),
            active: BindingGeneration {
                generation: 1,
                intent,
                resolved,
            },
            previous: None,
        })
    }
}

pub fn build_binding_plan(
    name: impl Into<String>,
    intent: BindingIntent,
    resolved: ResolvedContinuation,
    current: Option<&BindingReceipt>,
) -> Result<BindingPlan> {
    let name = name.into();
    require_simple_name(&name, "binding name")?;
    validate_intent_resolution(&intent, &resolved)?;
    let (current_generation, current_receipt_sha256, change) = match current {
        Some(receipt) => {
            validate_binding_receipt_structure(receipt)?;
            let change = match classify_binding_change(receipt, &intent, &resolved) {
                BindingChange::Unchanged => BindingPlanChange::Unchanged,
                BindingChange::Refresh => BindingPlanChange::Refresh,
                BindingChange::Rebind => BindingPlanChange::Rebind,
            };
            (
                Some(receipt.active.generation),
                Some(binding_receipt_sha256(receipt)?),
                change,
            )
        }
        None => (None, None, BindingPlanChange::Install),
    };
    let action_kinds: &[BindingPlanActionKind] = match change {
        BindingPlanChange::Install => &[
            BindingPlanActionKind::ValidateTarget,
            BindingPlanActionKind::PublishBinding,
            BindingPlanActionKind::ActivateProxy,
        ],
        BindingPlanChange::Unchanged => &[BindingPlanActionKind::VerifyBinding],
        BindingPlanChange::Refresh | BindingPlanChange::Rebind => &[
            BindingPlanActionKind::DeactivateProxy,
            BindingPlanActionKind::ValidateTarget,
            BindingPlanActionKind::PublishBinding,
            BindingPlanActionKind::ActivateProxy,
        ],
    };
    let actions = action_kinds
        .iter()
        .enumerate()
        .map(|(index, action)| {
            Ok(BindingPlanAction {
                order: u16::try_from(index + 1).context("binding action graph is too large")?,
                action: *action,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(BindingPlan {
        schema: "dev-auth-workload-binding-plan-v1".to_owned(),
        platform: current_platform(),
        name,
        intent,
        resolved,
        current_receipt: current.cloned(),
        current_generation,
        current_receipt_sha256,
        change,
        actions,
    })
}

pub fn canonical_binding_plan(plan: &BindingPlan) -> Result<Vec<u8>> {
    validate_binding_plan(plan)?;
    serde_jcs::to_vec(plan).context("canonicalize workload binding plan")
}

pub fn binding_plan_sha256(plan: &BindingPlan) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(canonical_binding_plan(plan)?)
    ))
}

pub fn write_binding_plan(path: &Path, plan: &BindingPlan) -> Result<String> {
    require_absolute_normal_path(path, "binding plan output")?;
    let bytes = canonical_binding_plan(plan)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(nix::libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .with_context(|| format!("create workload binding plan {}", path.display()))?;
    file.write_all(&bytes)
        .context("write workload binding plan")?;
    file.sync_all().context("sync workload binding plan")?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

fn validate_binding_plan(plan: &BindingPlan) -> Result<()> {
    if plan.schema != "dev-auth-workload-binding-plan-v1" {
        bail!("workload binding plan schema is not supported");
    }
    if plan.platform != current_platform() {
        bail!("workload binding plan belongs to a different native platform");
    }
    require_simple_name(&plan.name, "binding name")?;
    validate_intent_resolution(&plan.intent, &plan.resolved)?;
    let expected = build_binding_plan(
        plan.name.clone(),
        plan.intent.clone(),
        plan.resolved.clone(),
        plan.current_receipt.as_ref(),
    )?;
    if &expected != plan {
        bail!("workload binding plan is not canonical for its current-state snapshot");
    }
    Ok(())
}

fn binding_receipt_sha256(receipt: &BindingReceipt) -> Result<String> {
    validate_binding_receipt_structure(receipt)?;
    let bytes = serde_jcs::to_vec(receipt).context("canonicalize workload binding receipt")?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn resolve_continuation(
    command_name: &str,
    search_path: &OsStr,
    excluded_directories: &[PathBuf],
) -> Result<ResolvedContinuation> {
    require_simple_name(command_name, "binding command")?;
    let excluded = excluded_directories
        .iter()
        .map(|directory| {
            require_absolute_normal_path(directory, "excluded proxy directory")?;
            match fs::canonicalize(directory) {
                Ok(canonical) => Ok(canonical),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(directory.clone()),
                Err(error) => Err(error).with_context(|| {
                    format!("resolve excluded proxy directory {}", directory.display())
                }),
            }
        })
        .collect::<Result<Vec<_>>>()?;

    let mut continuation_entries = Vec::new();
    for entry in std::env::split_paths(search_path) {
        require_absolute_normal_path(&entry, "binding search path entry")?;
        let canonical_entry = fs::canonicalize(&entry)
            .with_context(|| format!("resolve binding search path entry {}", entry.display()))?;
        if excluded
            .iter()
            .any(|directory| canonical_entry.starts_with(directory))
        {
            continue;
        }
        if entry.to_str().is_none() {
            bail!("binding search path entries must be UTF-8");
        }
        continuation_entries.push(entry);
    }
    if continuation_entries.is_empty() {
        bail!("binding search path contains no non-proxy entries");
    }
    let continuation_path = std::env::join_paths(&continuation_entries)
        .context("construct continuation search path")?;

    for (search_index, directory) in continuation_entries.iter().enumerate() {
        let visible_path = directory.join(command_name);
        let link_metadata = match fs::symlink_metadata(&visible_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect binding candidate {}", visible_path.display())
                })
            }
        };
        if !(link_metadata.file_type().is_file() || link_metadata.file_type().is_symlink()) {
            continue;
        }
        let canonical_path = fs::canonicalize(&visible_path)
            .with_context(|| format!("resolve binding candidate {}", visible_path.display()))?;
        if excluded
            .iter()
            .any(|directory| canonical_path.starts_with(directory))
        {
            continue;
        }
        let identity = inspect_executable_identity(&canonical_path)?;
        return Ok(ResolvedContinuation {
            visible_path,
            canonical_path,
            continuation_path,
            search_index,
            identity,
        });
    }
    bail!("binding command {command_name} has no safe continuation target")
}

pub fn classify_binding_change(
    current: &BindingReceipt,
    desired_intent: &BindingIntent,
    desired_resolution: &ResolvedContinuation,
) -> BindingChange {
    if current.active.intent != *desired_intent {
        BindingChange::Rebind
    } else if current.active.resolved != *desired_resolution {
        BindingChange::Refresh
    } else {
        BindingChange::Unchanged
    }
}

pub fn advance_binding(
    current: &BindingReceipt,
    desired_intent: BindingIntent,
    desired_resolution: ResolvedContinuation,
) -> Result<BindingReceipt> {
    validate_binding_receipt_structure(current)?;
    validate_intent_resolution(&desired_intent, &desired_resolution)?;
    if classify_binding_change(current, &desired_intent, &desired_resolution)
        == BindingChange::Unchanged
    {
        return Ok(current.clone());
    }
    let generation = current
        .active
        .generation
        .checked_add(1)
        .context("binding generation overflow")?;
    Ok(BindingReceipt {
        schema: BINDING_RECEIPT_SCHEMA.to_owned(),
        platform: current_platform(),
        active: BindingGeneration {
            generation,
            intent: desired_intent,
            resolved: desired_resolution,
        },
        previous: Some(current.active.clone()),
    })
}

pub fn require_automatic_refresh(
    mode: BindingMode,
    resolved: &ResolvedContinuation,
    allow_degraded_user_owned: bool,
) -> Result<()> {
    verify_resolution_identity(resolved)?;
    match (mode, resolved.identity.authority) {
        (BindingMode::Strong, BindingAuthority::RootOwned) => Ok(()),
        (BindingMode::Strong, BindingAuthority::UserOwned) => {
            bail!("strong automatic binding refresh requires independent target authority")
        }
        (BindingMode::UserOnly, BindingAuthority::UserOwned) if allow_degraded_user_owned => Ok(()),
        (BindingMode::UserOnly, BindingAuthority::UserOwned) => {
            bail!("user-owned automatic binding refresh requires explicit degraded approval")
        }
        (BindingMode::UserOnly, _) => Ok(()),
    }
}

/// Validates the portable structure and lineage of a receipt.
///
/// This deliberately does not establish receipt custody or re-inspect historical
/// generations. Setup must nofollow-open the receipt from its receipt-owned
/// location before calling this function. New and refreshed active identities
/// are independently re-inspected by [`BindingReceipt::new`] and
/// [`advance_binding`].
pub fn validate_binding_receipt_structure(receipt: &BindingReceipt) -> Result<()> {
    if receipt.schema != BINDING_RECEIPT_SCHEMA {
        bail!("binding receipt schema is not supported");
    }
    if receipt.platform != current_platform() {
        bail!("binding receipt belongs to a different native platform");
    }
    validate_binding_generation(&receipt.active)?;
    if let Some(previous) = &receipt.previous {
        validate_binding_generation(previous)?;
        if previous.generation.checked_add(1) != Some(receipt.active.generation) {
            bail!("binding receipt does not contain one exact prior generation");
        }
    } else if receipt.active.generation != 1 {
        bail!("binding receipt is missing its prior generation");
    }
    Ok(())
}

fn validate_binding_generation(generation: &BindingGeneration) -> Result<()> {
    if generation.generation == 0 {
        bail!("binding generation must be positive");
    }
    validate_intent_resolution_structure(&generation.intent, &generation.resolved)
}

fn validate_intent_resolution(
    intent: &BindingIntent,
    resolved: &ResolvedContinuation,
) -> Result<()> {
    validate_intent_resolution_structure(intent, resolved)?;
    verify_resolution_identity(resolved)
}

fn validate_intent_resolution_structure(
    intent: &BindingIntent,
    resolved: &ResolvedContinuation,
) -> Result<()> {
    require_simple_name(&intent.command_name, "binding command")?;
    require_simple_name(&intent.workload, "binding workload")?;
    require_absolute_normal_path(&resolved.visible_path, "resolved visible command")?;
    require_absolute_normal_path(&resolved.canonical_path, "resolved canonical command")?;
    if resolved.identity.canonical_path != resolved.canonical_path {
        bail!("resolved command identity does not match its canonical path");
    }
    let continuation_entries = std::env::split_paths(&resolved.continuation_path)
        .map(|entry| {
            require_absolute_normal_path(&entry, "continuation search path entry")?;
            if entry.to_str().is_none() {
                bail!("continuation search path entries must be UTF-8");
            }
            Ok(entry)
        })
        .collect::<Result<Vec<_>>>()?;
    let selected = continuation_entries
        .get(resolved.search_index)
        .context("continuation search cursor is outside the search path")?;
    if selected.join(&intent.command_name) != resolved.visible_path {
        bail!("continuation search cursor does not identify the visible command");
    }
    Ok(())
}

fn verify_resolution_identity(resolved: &ResolvedContinuation) -> Result<()> {
    let observed = inspect_executable_identity(&resolved.canonical_path)?;
    if observed != resolved.identity {
        bail!("binding executable identity no longer matches the approved target");
    }
    Ok(())
}

fn inspect_executable_identity(path: &Path) -> Result<ExecutableIdentity> {
    require_absolute_normal_path(path, "binding executable")?;
    let canonical_path = fs::canonicalize(path)
        .with_context(|| format!("canonicalize binding executable {}", path.display()))?;
    if canonical_path != path {
        bail!("binding executable path is not canonical");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc_no_follow());
    let mut file = options
        .open(path)
        .with_context(|| format!("open binding executable {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect binding executable {}", path.display()))?;
    if !metadata.is_file() {
        bail!("binding target is not a regular file");
    }
    if metadata.len() > MAX_BINDING_TARGET_BYTES {
        bail!("binding target exceeds the size limit");
    }
    #[cfg(unix)]
    {
        if metadata.permissions().mode() & 0o111 == 0 {
            bail!("binding target is not executable");
        }
        if metadata.nlink() != 1 {
            bail!("binding target must have exactly one link");
        }
    }

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read binding executable {}", path.display()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .context("binding target size overflow")?;
        if total > MAX_BINDING_TARGET_BYTES {
            bail!("binding target exceeds the size limit");
        }
        hasher.update(&buffer[..read]);
    }
    if total != metadata.len() {
        bail!("binding target changed while it was inspected");
    }
    file.seek(SeekFrom::Start(0))
        .context("rewind binding executable after inspection")?;
    let after = file
        .metadata()
        .context("reinspect binding executable after hashing")?;
    if !same_open_file(&metadata, &after) {
        bail!("binding target changed while it was inspected");
    }
    let path_after = fs::metadata(path)
        .with_context(|| format!("reinspect binding executable path {}", path.display()))?;
    if !same_open_file(&metadata, &path_after) {
        bail!("binding target path changed while it was inspected");
    }
    let authority = binding_authority(&canonical_path, &metadata)?;
    Ok(ExecutableIdentity {
        canonical_path,
        length: total,
        sha256: format!("{:x}", hasher.finalize()),
        authority,
        #[cfg(unix)]
        device: Some(metadata.dev()),
        #[cfg(not(unix))]
        device: None,
        #[cfg(unix)]
        inode: Some(metadata.ino()),
        #[cfg(not(unix))]
        inode: None,
        #[cfg(unix)]
        mode: Some(metadata.mode()),
        #[cfg(not(unix))]
        mode: None,
        #[cfg(unix)]
        owner: Some(metadata.uid()),
        #[cfg(not(unix))]
        owner: None,
        #[cfg(unix)]
        group: Some(metadata.gid()),
        #[cfg(not(unix))]
        group: None,
    })
}

#[cfg(unix)]
fn same_open_file(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.nlink() == after.nlink()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
}

#[cfg(not(unix))]
fn same_open_file(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.len() == after.len() && before.permissions().readonly() == after.permissions().readonly()
}

#[cfg(unix)]
fn binding_authority(path: &Path, metadata: &fs::Metadata) -> Result<BindingAuthority> {
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Ok(BindingAuthority::UserOwned);
    }
    let mut ancestor = path.parent();
    while let Some(directory) = ancestor {
        let directory_metadata = fs::symlink_metadata(directory)
            .with_context(|| format!("inspect binding target ancestor {}", directory.display()))?;
        if !directory_metadata.is_dir()
            || directory_metadata.uid() != 0
            || directory_metadata.mode() & 0o022 != 0
        {
            return Ok(BindingAuthority::UserOwned);
        }
        ancestor = directory.parent();
    }
    Ok(BindingAuthority::RootOwned)
}

#[cfg(not(unix))]
fn binding_authority(_path: &Path, _metadata: &fs::Metadata) -> Result<BindingAuthority> {
    Ok(BindingAuthority::UserOwned)
}

fn require_simple_name(value: &str, description: &str) -> Result<()> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        bail!("{description} must be one safe command name");
    }
    Ok(())
}

fn require_absolute_normal_path(path: &Path, description: &str) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        bail!("{description} must be an absolute normalized path");
    }
    Ok(())
}

fn current_platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

pub fn default_proxy_directories() -> Result<Vec<PathBuf>> {
    let base = directories::BaseDirs::new().context("resolve native user directories")?;
    let mut directories = vec![base.data_local_dir().join("dev-auth/workload-bindings/bin")];
    #[cfg(target_os = "linux")]
    directories.insert(
        0,
        PathBuf::from("/usr/local/lib/dev-auth/workload-bindings/bin"),
    );
    Ok(directories)
}

#[cfg(unix)]
fn libc_no_follow() -> i32 {
    nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC
}
