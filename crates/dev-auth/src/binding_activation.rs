//! Receipt-owned Linux binding generations. This module does not publish a
//! proxy or admit a workload; the full setup transaction owns those effects.

use crate::setup::InstallReceipt;
use crate::smart_binding::{
    advance_binding, canonical_binding_plan, validate_binding_receipt_structure, BindingAuthority,
    BindingCodeTrust, BindingGeneration, BindingPlan, BindingPlanChange, BindingReceipt,
};
use anyhow::{bail, Context, Result};
use dev_tools_installation::{
    apply_versioned_installation_if_unchanged, observe_versioned_installation,
    read_atomic_document, recover_versioned_installation_transition,
    remove_atomic_document_if_unchanged, write_atomic_document, ArtifactIdentity,
    DocumentAuthority, VersionedInstallRequest, VersionedLayout, VersionedReceipt,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

const SCHEMA: &str = "dev-auth-binding-set-v1";
const LIMIT: u64 = 1024 * 1024;

pub(crate) mod launch_shell;
mod retirement;
mod shell_payload;
pub(crate) use shell_payload::{
    garbage_collect_shell_sources, observe_shell_payload, observe_shell_payload_for_restoration,
    publish_shell_payload, resume_shell_retirement_for_restoration, retire_shell_payload,
    sealed_source_for_binding, shell_store_accounts, verify_shell_payload,
    ShellRestorationObservation,
};

fn current_binding_runtime_installation() -> Result<(crate::setup::SetupPaths, InstallReceipt)> {
    let running = std::env::current_exe().context("locate binding runtime executable")?;
    if uses_privileged_launcher_installation(&running, nix::unistd::Uid::effective().as_raw()) {
        return crate::setup::validated_privileged_launcher_installation();
    }
    crate::setup::current_runtime_installation()
}

fn uses_privileged_launcher_installation(running: &Path, effective_uid: u32) -> bool {
    effective_uid == 0 && running == crate::setup::privileged_launcher_path()
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BindingSetReceipt {
    pub schema: String,
    pub platform: String,
    pub account_uid: u32,
    pub product_executable: PathBuf,
    pub product_sha256: String,
    pub bindings: BTreeMap<String, BindingReceipt>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pinned_artifacts: BTreeMap<String, ArtifactIdentity>,
}

/// The installed receipt compares exact source digest/length and complete
/// executable/generation context while keeping source text privately retained.
pub(crate) fn normalized_binding_receipt(receipt: &BindingReceipt) -> Result<BindingReceipt> {
    validate_binding_receipt_structure(receipt)?;
    let mut result = receipt.clone();
    result.active.resolved =
        crate::smart_binding::normalized_binding_resolution(&result.active.resolved)?;
    if let Some(previous) = &mut result.previous {
        previous.resolved =
            crate::smart_binding::normalized_binding_resolution(&previous.resolved)?;
    }
    validate_binding_receipt_structure(&result)?;
    Ok(result)
}

pub(crate) fn binding_receipt_matches(
    left: &BindingReceipt,
    right: &BindingReceipt,
) -> Result<bool> {
    Ok(normalized_binding_receipt(left)? == normalized_binding_receipt(right)?)
}

pub(crate) fn normalized_binding_set(receipt: &BindingSetReceipt) -> Result<BindingSetReceipt> {
    let mut result = receipt.clone();
    for binding in result.bindings.values_mut() {
        *binding = normalized_binding_receipt(binding)?;
    }
    Ok(result)
}

pub struct ResolvedBindingLaunch {
    pub workload: String,
    pub arguments: Vec<OsString>,
    pub code_trust: BindingCodeTrust,
    pub desktop_entry: bool,
    pub generation: u64,
    pub target: PathBuf,
}

pub struct BindingPlanningState {
    pub current: Option<BindingReceipt>,
    pub installed_executable: Option<PathBuf>,
    pub account_home: PathBuf,
}

pub fn planning_state(native_user: &str, alias: &str) -> Result<BindingPlanningState> {
    crate::setup::validate_workload_alias_names(&[alias.to_owned()])?;
    let user = nix::unistd::User::from_name(native_user)?
        .context("binding planning native account is absent")?;
    if user.uid.is_root() {
        bail!("binding planning requires a non-root native account");
    }
    if !crate::setup::running_executable_has_version_layout()? {
        return Ok(BindingPlanningState {
            current: None,
            installed_executable: None,
            account_home: user.dir,
        });
    }
    let (_, installation) = crate::setup::current_installation()?;
    if installation.mode == crate::setup::InstallMode::UserOnly
        && user.uid != nix::unistd::Uid::effective()
    {
        bail!("user-only binding planning requires the exact native account");
    }
    let receipt_path = native_receipt_path(installation.mode, &user.dir, user.uid.as_raw())?;
    let current = read_at(
        &receipt_path,
        installation.mode,
        user.uid.as_raw(),
        &installation,
    )?
    .and_then(|(set, _)| set.bindings.get(alias).cloned());
    Ok(BindingPlanningState {
        current,
        installed_executable: Some(PathBuf::from(installation.executable)),
        account_home: user.dir,
    })
}

pub fn resolve_current_alias(
    alias: &str,
    caller_arguments: &[OsString],
) -> Result<Option<ResolvedBindingLaunch>> {
    let uid = nix::unistd::Uid::effective().as_raw();
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
        .context("binding caller has no native account")?;
    if uid == 0 {
        bail!("binding alias requires a native non-root user");
    }
    let (_, installation) = current_binding_runtime_installation()?;
    let receipt_path = native_receipt_path(installation.mode, &user.dir, uid)?;
    let Some((set, _)) = read_at(&receipt_path, installation.mode, uid, &installation)? else {
        return Ok(None);
    };
    let Some(binding) = set.bindings.get(alias) else {
        return Ok(None);
    };
    crate::setup::verify_current_workload_alias_link(
        alias,
        &user.dir,
        uid,
        Path::new(&installation.executable),
    )?;
    let workload = &binding.active.intent.workload;
    let resolved = crate::setup::resolve_current_workload_alias(workload)?;
    let target = binding.active.resolved.identity().canonical_path.as_path();
    if Path::new(&resolved.launcher_path) != target
        || target == Path::new(&installation.executable)
        || matches!(
            &binding.active.resolved,
            crate::smart_binding::BindingResolution::Continuation { resolution }
                if resolution.visible_path != target
        )
    {
        bail!("binding target no longer matches its configured workload launcher");
    }
    Ok(Some(ResolvedBindingLaunch {
        workload: workload.clone(),
        arguments: if crate::smart_binding::is_pinned_shell_resolution(&binding.active.resolved) {
            caller_arguments.to_vec()
        } else {
            binding
                .active
                .intent
                .target
                .forward_arguments(caller_arguments)?
        },
        code_trust: binding.active.intent.code_trust,
        desktop_entry: binding.active.intent.desktop_entry,
        generation: binding.active.generation,
        target: target.to_path_buf(),
    }))
}

/// Expose only aliases belonging to the already admitted workload in its
/// private PATH plane. An alias for a different workload cannot turn a nested
/// shell into a new admission or borrow this session's credential authority.
pub fn active_aliases_for_workload(
    owner_uid: u32,
    workload: &str,
    launcher: &Path,
) -> Result<Vec<String>> {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(owner_uid))?
        .context("binding tool-plane account is absent")?;
    let (_, installation) = current_binding_runtime_installation()?;
    require_tool_plane_owner(nix::unistd::Uid::effective().as_raw(), owner_uid)?;
    let path = native_receipt_path(installation.mode, &user.dir, owner_uid)?;
    let Some((set, _)) = read_at(&path, installation.mode, owner_uid, &installation)? else {
        return Ok(Vec::new());
    };
    let mut aliases = Vec::new();
    for (alias, binding) in set.bindings {
        if binding.active.intent.workload != workload {
            continue;
        }
        let target = binding.active.resolved.identity().canonical_path.as_path();
        if target != launcher
            || matches!(
                &binding.active.resolved,
                crate::smart_binding::BindingResolution::Continuation { resolution }
                    if resolution.visible_path != launcher
            )
        {
            bail!("binding alias target changed during tool-plane preparation");
        }
        crate::setup::verify_current_workload_alias_link(
            &alias,
            &user.dir,
            owner_uid,
            Path::new(&installation.executable),
        )?;
        aliases.push(alias);
    }
    Ok(aliases)
}

/// A strong workload may execute user-owned mutable code only while an exact,
/// root-custodied binding generation for this owner/workload/launcher remains
/// active. The root dispatcher and the admitted non-root supervisor both use
/// this check; a copied alias name or a policy path alone is insufficient.
pub(crate) fn approves_strong_mutable_launcher(
    owner_uid: u32,
    workload: &str,
    launcher: &Path,
) -> Result<bool> {
    let caller_uid = nix::unistd::Uid::effective().as_raw();
    if owner_uid == 0 || (caller_uid != 0 && caller_uid != owner_uid) {
        bail!("strong mutable launcher inspection has the wrong native account");
    }
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(owner_uid))?
        .context("strong binding native account is absent")?;
    let (_, installation) = current_binding_runtime_installation()?;
    if installation.mode != crate::setup::InstallMode::Strong {
        bail!("strong mutable launcher requires a strong installation");
    }
    let receipt_path = native_receipt_path(installation.mode, &user.dir, owner_uid)?;
    let Some((set, _)) = read_at(&receipt_path, installation.mode, owner_uid, &installation)?
    else {
        return Ok(false);
    };
    let mut selected = false;
    for (alias, binding) in set.bindings {
        if binding.active.intent.workload != workload {
            continue;
        }
        let target = binding.active.resolved.identity().canonical_path.as_path();
        if binding.active.intent.code_trust != BindingCodeTrust::Mutable
            || target != launcher
            || matches!(
                &binding.active.resolved,
                crate::smart_binding::BindingResolution::Continuation { resolution }
                    if resolution.visible_path != launcher
            )
        {
            bail!("strong mutable binding differs from its approved workload launcher");
        }
        crate::setup::verify_current_workload_alias_link(
            &alias,
            &user.dir,
            owner_uid,
            Path::new(&installation.executable),
        )?;
        selected = true;
    }
    Ok(selected)
}

fn strong_pinned_bindings_for_workload(
    owner_uid: u32,
    workload: &str,
    launcher: &Path,
) -> Result<Vec<(String, BindingReceipt)>> {
    let caller_uid = nix::unistd::Uid::effective().as_raw();
    if owner_uid == 0 || (caller_uid != 0 && caller_uid != owner_uid) {
        bail!("strong pinned binding inspection has the wrong native account");
    }
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(owner_uid))?
        .context("pinned binding native account is absent")?;
    let (_, installation) = current_binding_runtime_installation()?;
    if installation.mode != crate::setup::InstallMode::Strong {
        bail!("strong pinned binding requires a strong installation");
    }
    let path = native_receipt_path(installation.mode, &user.dir, owner_uid)?;
    let Some((set, _)) = read_at(&path, installation.mode, owner_uid, &installation)? else {
        return Ok(Vec::new());
    };
    let mut selected = Vec::new();
    for (alias, binding) in set.bindings {
        if binding.active.intent.workload != workload
            || binding.active.intent.code_trust != BindingCodeTrust::Pinned
        {
            continue;
        }
        let target = binding.active.resolved.identity().canonical_path.as_path();
        if target != launcher
            || matches!(
                &binding.active.resolved,
                crate::smart_binding::BindingResolution::Continuation { resolution }
                    if resolution.visible_path != launcher
            )
        {
            bail!("strong pinned binding differs from its configured workload launcher");
        }
        crate::setup::verify_current_workload_alias_link(
            &alias,
            &user.dir,
            owner_uid,
            Path::new(&installation.executable),
        )?;
        if selected
            .first()
            .is_some_and(|(_, first): &(String, BindingReceipt)| {
                pinned_identity(first) != pinned_identity(&binding)
            })
        {
            bail!("one workload selects conflicting pinned executable bytes");
        }
        selected.push((alias, binding));
    }
    Ok(selected)
}

/// Root dispatch may bind the copied artifact over the configured root-owned
/// launcher in one native transient service. No caller path or environment hint
/// selects this source; it comes from the active root-custodied binding set.
pub(crate) fn strong_pinned_mount_source(
    owner_uid: u32,
    workload: &str,
    launcher: &Path,
) -> Result<Option<PathBuf>> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("pinned mount source requires the native root dispatcher");
    }
    let mut source = None;
    for (alias, binding) in strong_pinned_bindings_for_workload(owner_uid, workload, launcher)? {
        let path = verify_pinned_artifact(owner_uid, &alias, &binding)?;
        source.get_or_insert(path);
    }
    Ok(source)
}

/// The non-root workload verifies the manager projected the approved artifact
/// inode at the original pathname, then checks its exact bytes before launch.
pub(crate) fn verify_strong_pinned_projection(
    owner_uid: u32,
    workload: &str,
    launcher: &Path,
) -> Result<()> {
    if nix::unistd::Uid::effective().as_raw() != owner_uid {
        bail!("pinned projection requires the admitted native owner");
    }
    let selected = strong_pinned_bindings_for_workload(owner_uid, workload, launcher)?;
    let Some((alias, binding)) = selected.first() else {
        return Ok(());
    };
    // The root dispatcher verifies every selected store and projects the first
    // alias in canonical map order. Additional aliases may retain independent
    // copies of the same approved bytes, so their inodes must not be compared
    // with the single projected inode.
    let artifact = pinned_artifact_path(owner_uid, alias, binding)?;
    let pinned = fs::symlink_metadata(&artifact).context("inspect pinned artifact source")?;
    let projected = fs::symlink_metadata(launcher).context("inspect projected launcher")?;
    use std::os::unix::fs::MetadataExt;
    if !pinned.file_type().is_file()
        || !projected.file_type().is_file()
        || pinned.uid() != 0
        || projected.uid() != 0
        || pinned.dev() != projected.dev()
        || pinned.ino() != projected.ino()
    {
        bail!("pinned bytes are not projected at the approved launcher path");
    }
    let expected = pinned_identity(binding);
    if ArtifactIdentity::from_file(launcher, expected.length)? != expected {
        bail!("projected launcher bytes differ from the approved pin");
    }
    Ok(())
}

fn require_tool_plane_owner(caller: u32, owner: u32) -> Result<()> {
    if owner == 0 {
        bail!("binding tool plane requires a native non-root owner");
    }
    if caller != owner {
        bail!("binding tool plane requires the exact admitted native account");
    }
    Ok(())
}

pub fn native_receipt_path(
    mode: crate::setup::InstallMode,
    home: &Path,
    uid: u32,
) -> Result<PathBuf> {
    if !home.is_absolute() || uid == 0 {
        bail!("binding account authority is invalid");
    }
    Ok(match mode {
        crate::setup::InstallMode::Strong => {
            PathBuf::from(format!("/var/lib/dev-auth/binding-{uid}-v1.json"))
        }
        crate::setup::InstallMode::UserOnly => {
            home.join(".local/share/dev-auth/binding-set-v1.json")
        }
    })
}

pub fn require_explicit_selection_if_retained(
    mode: crate::setup::InstallMode,
    accounts: &[crate::setup_v3::NativeAccountIdentity],
    selected: bool,
) -> Result<()> {
    for account in accounts {
        let path = native_receipt_path(mode, &account.home, account.uid)?;
        match fs::symlink_metadata(&path) {
            Ok(_) if !selected => {
                bail!("retained binding generation requires explicit v3 deployment selection")
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect retained binding generation"),
        }
    }
    Ok(())
}

pub(crate) fn authority(mode: crate::setup::InstallMode, account_uid: u32) -> DocumentAuthority {
    DocumentAuthority {
        owner_uid: if mode == crate::setup::InstallMode::Strong {
            0
        } else {
            account_uid
        },
        mode: if mode == crate::setup::InstallMode::Strong {
            0o644
        } else {
            0o600
        },
        limit: LIMIT,
    }
}

/// Full Pending setup owns this public store parent. Private shell suffixes
/// remain separate; existing incompatible directory modes are never changed.
pub(crate) fn prepare_public_binding_parent() -> Result<bool> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("public binding store preparation requires native root");
    }
    let root = rustix::fs::open(
        "/",
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let root_stat = rustix::fs::fstat(&root)?;
    if root_stat.st_uid != 0 || root_stat.st_mode & 0o7022 != 0 || root_stat.st_mode & 0o001 == 0 {
        bail!("public binding store root is not safely traversable by its native account");
    }
    let verify_root = || -> Result<()> {
        let after = rustix::fs::fstat(&root)?;
        if (
            root_stat.st_dev,
            root_stat.st_ino,
            root_stat.st_uid,
            root_stat.st_mode,
        ) != (after.st_dev, after.st_ino, after.st_uid, after.st_mode)
        {
            bail!("public binding store root changed during preparation");
        }
        Ok(())
    };
    let changed = prepare_public_binding_parent_paths(
        &[
            Path::new("/var"),
            Path::new("/var/lib"),
            Path::new("/var/lib/dev-auth"),
        ],
        0,
        |preparation| {
            verify_root()?;
            Ok(preparation.prepare()?.1)
        },
    )?;
    verify_root()?;
    Ok(changed)
}

/// The product supplies the complete chain below its separately held root.
/// The callback is the single mutation/synchronization boundary; admission and
/// retained ancestor verification must finish before entering it.
fn prepare_public_binding_parent_paths(
    paths: &[&Path],
    owner_uid: u32,
    prepare: impl FnOnce(dev_tools_installation::DocumentDirectoryPreparation) -> Result<bool>,
) -> Result<bool> {
    let path = paths
        .last()
        .context("public binding store has no selected parent")?;
    if paths.len() > 64
        || paths
            .windows(2)
            .any(|pair| pair[1].parent() != Some(pair[0]))
    {
        bail!("public binding store ancestor chain is invalid");
    }
    let retained = preflight_public_binding_parent(paths, owner_uid, true)?;
    let preparation =
        dev_tools_installation::DocumentDirectoryPreparation::observe(path, owner_uid, 0o755)?;
    // A suffix that appeared while the shared observation was acquired is not
    // adopted, even if it has compatible custody. The shared observer then
    // retains its own absent-name guard through the mutation boundary.
    let observed = preflight_public_binding_parent(paths, owner_uid, true)?;
    if observed.len() != retained.len() {
        bail!("public binding store ancestor presence changed during admission");
    }
    for held in &retained {
        held.verify()?;
    }
    let changed = prepare(preparation)?;
    for held in &retained {
        held.verify()?;
    }
    preflight_public_binding_parent(paths, owner_uid, false)?;
    Ok(changed)
}

fn preflight_public_binding_parent(
    paths: &[&Path],
    owner_uid: u32,
    allow_missing_suffix: bool,
) -> Result<Vec<crate::privilege::custody::HeldResource>> {
    let mut retained = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        let held = match crate::privilege::custody::HeldResource::open(path, owner_uid) {
            Ok(held) => held,
            Err(error)
                if allow_missing_suffix
                    && error.downcast_ref::<rustix::io::Errno>()
                        == Some(&rustix::io::Errno::NOENT) =>
            {
                break
            }
            Err(error) => return Err(error).context("preflight public binding store ancestor"),
        };
        let stat = rustix::fs::fstat(&held.descriptor)?;
        if !held.is_directory()?
            || stat.st_uid != owner_uid
            || stat.st_mode & 0o7022 != 0
            || stat.st_mode & 0o001 == 0
            || (index + 1 == paths.len() && stat.st_mode & 0o7777 != 0o755)
        {
            bail!("public binding store directory is not safely traversable by its native account");
        }
        held.verify()?;
        retained.push(held);
    }
    Ok(retained)
}

pub fn read_at(
    path: &Path,
    mode: crate::setup::InstallMode,
    account_uid: u32,
    installation: &InstallReceipt,
) -> Result<Option<(BindingSetReceipt, ArtifactIdentity)>> {
    let Some(document) = read_atomic_document(path, &authority(mode, account_uid))? else {
        return Ok(None);
    };
    let receipt: BindingSetReceipt =
        serde_json::from_slice(&document.bytes).context("decode binding set receipt")?;
    if serde_jcs::to_vec(&receipt)? != document.bytes {
        bail!("binding set receipt differs from its exact canonical encoding");
    }
    validate(&receipt, account_uid, installation)?;
    Ok(Some((receipt, document.identity)))
}

pub(crate) fn write_at(
    path: &Path,
    mode: crate::setup::InstallMode,
    account_uid: u32,
    installation: &InstallReceipt,
    receipt: &BindingSetReceipt,
    expected: Option<&ArtifactIdentity>,
) -> Result<bool> {
    let receipt = normalized_binding_set(receipt)?;
    validate(&receipt, account_uid, installation)?;
    crate::setup_v3::require_pending_binding_set_selection(
        mode,
        account_uid,
        path,
        installation,
        Some(&receipt),
    )?;
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(account_uid))?
        .context("binding native account is absent")?;
    for (alias, binding) in &receipt.bindings {
        if crate::smart_binding::is_pinned_shell_resolution(&binding.active.resolved) {
            verify_shell_payload(mode, &user.dir, account_uid, alias, binding)?;
        }
    }
    let bytes = serde_jcs::to_vec(&receipt).context("canonicalize binding set receipt")?;
    write_atomic_document(path, &bytes, &authority(mode, account_uid), expected)
}

pub(crate) fn retire_at(
    path: &Path,
    mode: crate::setup::InstallMode,
    account_uid: u32,
    installation: &InstallReceipt,
    expected: &ArtifactIdentity,
) -> Result<bool> {
    crate::setup_v3::require_pending_binding_set_selection(
        mode,
        account_uid,
        path,
        installation,
        None,
    )?;
    remove_atomic_document_if_unchanged(path, &authority(mode, account_uid), expected)
}

pub fn build_desired(
    account_uid: u32,
    next_installation: &InstallReceipt,
    current: Option<(&BindingSetReceipt, &InstallReceipt)>,
    plans: &[BindingPlan],
) -> Result<BindingSetReceipt> {
    if account_uid == 0 || plans.len() > 128 {
        bail!("binding account or plan count is invalid");
    }
    if let Some((receipt, installation)) = current {
        validate(receipt, account_uid, installation)?;
    }
    let mut bindings = BTreeMap::new();
    let mut pinned_artifacts = BTreeMap::new();
    for plan in plans {
        let plan_current = plan
            .current_receipt
            .as_ref()
            .map(normalized_binding_receipt)
            .transpose()?;
        match (
            plan.intent.code_trust,
            plan.change,
            plan_current.as_ref(),
            current.and_then(|(receipt, _)| receipt.bindings.get(&plan.intent.command_name)),
        ) {
            (
                BindingCodeTrust::Pinned,
                BindingPlanChange::Unchanged,
                Some(retained),
                Some(active),
            ) if retained == active => {
                crate::smart_binding::canonical_retained_binding_plan(plan)?;
                if next_installation.mode == crate::setup::InstallMode::Strong {
                    verify_pinned_artifact(account_uid, &plan.intent.command_name, retained)?;
                }
                if crate::smart_binding::is_pinned_shell_resolution(&retained.active.resolved) {
                    let user =
                        nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(account_uid))?
                            .context("shell binding native account is absent")?;
                    verify_shell_payload(
                        next_installation.mode,
                        &user.dir,
                        account_uid,
                        &plan.intent.command_name,
                        retained,
                    )?;
                }
            }
            _ => {
                canonical_binding_plan(plan)?;
            }
        }
        if plan.intent.code_trust == BindingCodeTrust::Pinned
            && ((next_installation.mode != crate::setup::InstallMode::Strong
                && !crate::smart_binding::is_pinned_shell_resolution(&plan.resolved))
                || plan.resolved.identity().authority != BindingAuthority::RootOwned)
        {
            bail!("pinned binding requires a strong root-custodied executable and retained-byte launch");
        }
        let alias = &plan.intent.command_name;
        let prior = current.and_then(|(receipt, _)| receipt.bindings.get(alias));
        if plan_current.as_ref() != prior {
            bail!("binding plan does not match the current receipt generation");
        }
        let receipt = match prior {
            Some(prior)
                if plan.intent.code_trust == BindingCodeTrust::Pinned
                    && plan.change == BindingPlanChange::Unchanged
                    && prior.active.intent == plan.intent
                    && crate::smart_binding::normalized_binding_resolution(
                        &prior.active.resolved,
                    )? == crate::smart_binding::normalized_binding_resolution(
                        &plan.resolved,
                    )? =>
            {
                prior.clone()
            }
            Some(prior) => advance_binding(prior, plan.intent.clone(), plan.resolved.clone())?,
            None => BindingReceipt::new(plan.intent.clone(), plan.resolved.clone())?,
        };
        let receipt = normalized_binding_receipt(&receipt)?;
        if receipt.active.intent.code_trust == BindingCodeTrust::Pinned
            && next_installation.mode == crate::setup::InstallMode::Strong
        {
            pinned_artifacts.insert(alias.clone(), pinned_identity(&receipt));
        }
        if bindings.insert(alias.clone(), receipt).is_some() {
            bail!("binding desired state repeats one command alias");
        }
    }
    crate::setup::validate_workload_alias_names(&bindings.keys().cloned().collect::<Vec<_>>())?;
    Ok(BindingSetReceipt {
        schema: SCHEMA.into(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        account_uid,
        product_executable: PathBuf::from(&next_installation.executable),
        product_sha256: next_installation.executable_sha256.clone(),
        bindings,
        pinned_artifacts,
    })
}

/// Reconstruct the exact approved candidate without reopening mutable target
/// bytes. Only a previously captured full setup generation may use this for
/// postcondition or restoration; initial activation uses `build_desired`.
pub fn expected_desired_from_approved_plans(
    account_uid: u32,
    next_installation: &InstallReceipt,
    current: Option<(&BindingSetReceipt, &InstallReceipt)>,
    plans: &[BindingPlan],
) -> Result<BindingSetReceipt> {
    let mut expected = expected_desired_with_identity(
        account_uid,
        Path::new(&next_installation.executable),
        &next_installation.executable_sha256,
        current,
        plans,
    )?;
    if next_installation.mode == crate::setup::InstallMode::UserOnly {
        expected.pinned_artifacts.retain(|alias, _| {
            !crate::smart_binding::is_pinned_shell_resolution(
                &expected.bindings[alias].active.resolved,
            )
        });
    }
    Ok(expected)
}

pub fn expected_desired_with_identity(
    account_uid: u32,
    next_executable: &Path,
    next_sha256: &str,
    current: Option<(&BindingSetReceipt, &InstallReceipt)>,
    plans: &[BindingPlan],
) -> Result<BindingSetReceipt> {
    if account_uid == 0 || plans.len() > 128 {
        bail!("approved binding account or plan count is invalid");
    }
    if !next_executable.is_absolute()
        || next_sha256.len() != 64
        || !next_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("candidate binding product identity is invalid");
    }
    if let Some((receipt, installation)) = current {
        validate(receipt, account_uid, installation)?;
    }
    let mut bindings = BTreeMap::new();
    let mut pinned_artifacts = BTreeMap::new();
    for plan in plans {
        crate::smart_binding::canonical_retained_binding_plan(plan)?;
        if plan.schema != "dev-auth-workload-binding-plan-v3"
            || plan.platform != format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
            || (plan.intent.code_trust == BindingCodeTrust::Pinned
                && plan.resolved.identity().authority != BindingAuthority::RootOwned)
        {
            bail!("approved binding plan has unsupported execution authority");
        }
        let alias = &plan.intent.command_name;
        let prior = current.and_then(|(receipt, _)| receipt.bindings.get(alias));
        if plan
            .current_receipt
            .as_ref()
            .map(normalized_binding_receipt)
            .transpose()?
            .as_ref()
            != prior
        {
            bail!("approved binding plan differs from retained prior receipt");
        }
        let receipt = match (prior, plan.change) {
            (None, BindingPlanChange::Install) => BindingReceipt {
                schema: "dev-auth-workload-binding-receipt-v3".into(),
                platform: plan.platform.clone(),
                active: BindingGeneration {
                    generation: 1,
                    intent: plan.intent.clone(),
                    resolved: plan.resolved.clone(),
                },
                previous: None,
            },
            (Some(prior), BindingPlanChange::Unchanged) => {
                if prior.active.intent != plan.intent
                    || crate::smart_binding::normalized_binding_resolution(&prior.active.resolved)?
                        != crate::smart_binding::normalized_binding_resolution(&plan.resolved)?
                {
                    bail!("unchanged binding plan differs from retained bytes");
                }
                prior.clone()
            }
            (Some(prior), BindingPlanChange::Refresh | BindingPlanChange::Rebind) => {
                BindingReceipt {
                    schema: "dev-auth-workload-binding-receipt-v3".into(),
                    platform: plan.platform.clone(),
                    active: BindingGeneration {
                        generation: prior
                            .active
                            .generation
                            .checked_add(1)
                            .context("binding generation overflow")?,
                        intent: plan.intent.clone(),
                        resolved: plan.resolved.clone(),
                    },
                    previous: Some(prior.active.clone()),
                }
            }
            _ => bail!("approved binding plan has an invalid generation transition"),
        };
        let receipt = normalized_binding_receipt(&receipt)?;
        validate_binding_receipt_structure(&receipt)?;
        if receipt.active.intent.code_trust == BindingCodeTrust::Pinned {
            pinned_artifacts.insert(alias.clone(), pinned_identity(&receipt));
        }
        if bindings.insert(alias.clone(), receipt).is_some() {
            bail!("approved binding set contains a duplicate alias");
        }
    }
    crate::setup::validate_workload_alias_names(&bindings.keys().cloned().collect::<Vec<_>>())?;
    Ok(BindingSetReceipt {
        schema: SCHEMA.into(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        account_uid,
        product_executable: next_executable.to_path_buf(),
        product_sha256: next_sha256.into(),
        bindings,
        pinned_artifacts,
    })
}

pub(crate) fn expected_desired_with_mode_and_identity(
    account_uid: u32,
    mode: crate::setup::InstallMode,
    next_executable: &Path,
    next_sha256: &str,
    current: Option<(&BindingSetReceipt, &InstallReceipt)>,
    plans: &[BindingPlan],
) -> Result<BindingSetReceipt> {
    let mut result =
        expected_desired_with_identity(account_uid, next_executable, next_sha256, current, plans)?;
    if mode == crate::setup::InstallMode::UserOnly {
        result.pinned_artifacts.retain(|alias, _| {
            !crate::smart_binding::is_pinned_shell_resolution(
                &result.bindings[alias].active.resolved,
            )
        });
    }
    Ok(result)
}

pub fn validate(
    receipt: &BindingSetReceipt,
    account_uid: u32,
    installation: &InstallReceipt,
) -> Result<()> {
    if receipt.schema != SCHEMA
        || receipt.platform != format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
        || receipt.account_uid != account_uid
        || account_uid == 0
        || receipt.product_executable != Path::new(&installation.executable)
        || receipt.product_sha256 != installation.executable_sha256
        || receipt.bindings.len() > 128
    {
        bail!("binding set receipt does not match its installation authority");
    }
    crate::setup::validate_workload_alias_names(
        &receipt.bindings.keys().cloned().collect::<Vec<_>>(),
    )?;
    let mut expected_pins = BTreeMap::new();
    for (alias, binding) in &receipt.bindings {
        validate_binding_receipt_structure(binding)?;
        if matches!(
            binding.active.resolved,
            crate::smart_binding::BindingResolution::PinnedShell { .. }
        ) || binding.previous.as_ref().is_some_and(|previous| {
            matches!(
                previous.resolved,
                crate::smart_binding::BindingResolution::PinnedShell { .. }
            )
        }) {
            bail!("installed binding manifest must contain source-free shell references");
        }
        if alias != &binding.active.intent.command_name {
            bail!("binding alias or code trust differs from its receipt");
        }
        if binding.active.intent.code_trust == BindingCodeTrust::Pinned {
            if (installation.mode != crate::setup::InstallMode::Strong
                && !crate::smart_binding::is_pinned_shell_resolution(&binding.active.resolved))
                || binding.active.resolved.identity().authority != BindingAuthority::RootOwned
            {
                bail!("pinned binding lacks strong root-owned target authority");
            }
            if installation.mode == crate::setup::InstallMode::Strong {
                pinned_artifact_path(account_uid, alias, binding)?;
                expected_pins.insert(alias.clone(), pinned_identity(binding));
            }
        }
    }
    if receipt.pinned_artifacts != expected_pins {
        bail!("binding pinned artifact identities differ from active generations");
    }
    Ok(())
}

fn pinned_identity(binding: &BindingReceipt) -> ArtifactIdentity {
    pinned_generation_identity(&binding.active)
}

fn pinned_generation_identity(generation: &BindingGeneration) -> ArtifactIdentity {
    let identity = generation.resolved.identity();
    ArtifactIdentity {
        length: identity.length,
        sha256: identity.sha256.clone(),
    }
}

/// Each approved generation receives an immutable, separate nested artifact
/// store. A successor never changes or deletes the retained prior store.
pub fn pinned_layout(
    account_uid: u32,
    alias: &str,
    binding: &BindingReceipt,
) -> Result<VersionedLayout> {
    crate::smart_binding::validate_binding_receipt_structure(binding)?;
    pinned_generation_layout(account_uid, alias, &binding.active)
}

fn pinned_generation_layout(
    account_uid: u32,
    alias: &str,
    generation: &BindingGeneration,
) -> Result<VersionedLayout> {
    if account_uid == 0
        || generation.intent.code_trust != BindingCodeTrust::Pinned
        || generation.intent.command_name != alias
        || generation.resolved.identity().authority != BindingAuthority::RootOwned
    {
        bail!("pinned binding layout has incompatible native authority");
    }
    crate::smart_binding::validate_binding_generation(generation)?;
    crate::setup::validate_workload_alias_names(&[alias.to_owned()])?;
    let generation = format!(
        "g{}-{}",
        generation.generation,
        generation.resolved.identity().sha256
    );
    Ok(VersionedLayout {
        product: "dev-auth-binding".into(),
        data_root: PathBuf::from(format!(
            "/var/lib/dev-auth/pinned-bindings/{account_uid}/{alias}/{generation}"
        )),
        bin_dir: PathBuf::from(format!(
            "/var/lib/dev-auth/pinned-binding-links/{account_uid}/{alias}/{generation}"
        )),
        artifact_name: "payload".into(),
        owner_uid: 0,
        directory_mode: 0o755,
        bin_directory_mode: None,
    })
}

pub fn pinned_artifact_path(
    account_uid: u32,
    alias: &str,
    binding: &BindingReceipt,
) -> Result<PathBuf> {
    pinned_artifact_path_at(&pinned_layout(account_uid, alias, binding)?, alias, binding)
}

fn pinned_artifact_path_at(
    layout: &VersionedLayout,
    alias: &str,
    binding: &BindingReceipt,
) -> Result<PathBuf> {
    layout.validate_candidate("v1", &pinned_identity(binding), &[alias.to_owned()])?;
    Ok(layout.data_root.join("versions/v1/payload"))
}

fn pinned_ledger_receipt_at(
    layout: &VersionedLayout,
    alias: &str,
    binding: &BindingReceipt,
) -> Result<VersionedReceipt> {
    pinned_artifact_path_at(layout, alias, binding)?;
    Ok(VersionedReceipt {
        schema: "dev-tools-versioned-installation-v1".into(),
        product: layout.product.clone(),
        data_root: layout.data_root.clone(),
        bin_dir: layout.bin_dir.clone(),
        artifact_name: layout.artifact_name.clone(),
        active_version: "v1".into(),
        active_identity: pinned_identity(binding),
        previous_version: None,
        previous_identity: None,
        aliases: vec![alias.to_owned()],
    })
}

pub(crate) fn pinned_ledger_receipt_for_binding(
    account_uid: u32,
    alias: &str,
    binding: &BindingReceipt,
) -> Result<VersionedReceipt> {
    pinned_ledger_receipt_at(&pinned_layout(account_uid, alias, binding)?, alias, binding)
}

/// Observe the exact retained bytes without recovery or publication.
pub fn verify_pinned_artifact(
    account_uid: u32,
    alias: &str,
    binding: &BindingReceipt,
) -> Result<PathBuf> {
    verify_pinned_artifact_at(&pinned_layout(account_uid, alias, binding)?, alias, binding)
}

fn verify_pinned_artifact_at(
    layout: &VersionedLayout,
    alias: &str,
    binding: &BindingReceipt,
) -> Result<PathBuf> {
    let expected_path = pinned_artifact_path_at(layout, alias, binding)?;
    let expected_receipt = pinned_ledger_receipt_at(layout, alias, binding)?;
    let observed = observe_versioned_installation(layout, 512 * 1024 * 1024)?
        .context("pinned binding has no retained artifact installation")?;
    if observed != expected_receipt {
        bail!("pinned artifact store differs from its approved generation");
    }
    Ok(expected_path)
}

/// Publish only this approved generation; an older generation remains intact
/// for the outer setup transaction to restore without swapping history.
pub(crate) fn publish_pinned_artifact(
    account_uid: u32,
    alias: &str,
    binding: &BindingReceipt,
) -> Result<bool> {
    publish_pinned_artifact_at(&pinned_layout(account_uid, alias, binding)?, alias, binding)
}

fn publish_pinned_artifact_at(
    layout: &VersionedLayout,
    alias: &str,
    binding: &BindingReceipt,
) -> Result<bool> {
    let expected = pinned_ledger_receipt_at(layout, alias, binding)?;
    let has_root = match fs::symlink_metadata(&layout.data_root) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).context("inspect pinned artifact store"),
    };
    let has_transition = has_root
        && [
            "installation-receipt-v1.json",
            "installation-transition-v1.json",
        ]
        .iter()
        .any(|name| fs::symlink_metadata(layout.data_root.join(name)).is_ok());
    let (recovered, observed) = if has_transition {
        recover_versioned_installation_transition(
            layout,
            None,
            &expected,
            512 * 1024 * 1024,
            |_| Ok(()),
        )?
    } else {
        (false, None)
    };
    if observed.as_ref() == Some(&expected) {
        verify_pinned_artifact_at(layout, alias, binding)?;
        return Ok(recovered);
    }
    if observed.is_some() {
        bail!("pinned artifact store contains an unrelated generation");
    }
    let source = binding.active.resolved.identity();
    crate::smart_binding::retain_binding_executable(source)?;
    let report = apply_versioned_installation_if_unchanged(
        &VersionedInstallRequest {
            layout: layout.clone(),
            version: "v1".into(),
            source: source.canonical_path.clone(),
            identity: pinned_identity(binding),
            aliases: vec![alias.to_owned()],
        },
        None,
        |_| Ok(()),
    )?;
    if report.receipt != expected {
        bail!("pinned artifact publication did not match its approved generation");
    }
    verify_pinned_artifact_at(layout, alias, binding)?;
    Ok(recovered || report.changed)
}

/// Remove only completed, receipt-owned stores outside the accepted active and
/// prior binding generations. The caller must hold the full setup exclusion
/// after accepting its candidate; this never discovers authority from a
/// caller-supplied filesystem path.
pub(crate) fn garbage_collect_superseded_pins(
    account_uid: u32,
    retained_sets: &[BindingSetReceipt],
) -> Result<usize> {
    if !nix::unistd::Uid::effective().is_root() || account_uid == 0 {
        bail!("pinned store collection requires the native root setup owner");
    }
    let mut keep = BTreeSet::new();
    for set in retained_sets {
        if set.schema != SCHEMA
            || set.platform != format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
            || set.account_uid != account_uid
            || set.bindings.len() > 128
        {
            bail!("pinned store collection has incompatible binding authority");
        }
        for (alias, binding) in &set.bindings {
            validate_binding_receipt_structure(binding)?;
            if binding.active.intent.command_name != *alias {
                bail!("pinned store collection has a mismatched binding alias");
            }
            for generation in std::iter::once(&binding.active).chain(binding.previous.iter()) {
                if generation.intent.code_trust == BindingCodeTrust::Pinned {
                    keep.insert(
                        pinned_generation_layout(account_uid, alias, generation)?.data_root,
                    );
                }
            }
        }
    }
    let data_base = Path::new("/var/lib/dev-auth/pinned-bindings");
    let link_base = Path::new("/var/lib/dev-auth/pinned-binding-links");
    require_root_owned_ancestor_chain(data_base)?;
    require_root_owned_ancestor_chain(link_base)?;
    collect_pinned_stores_at(account_uid, data_base, link_base, 0, 0o755, &keep)
}

pub(crate) fn pinned_store_accounts() -> Result<BTreeSet<u32>> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("pinned store inventory requires the native root setup owner");
    }
    let data_base = Path::new("/var/lib/dev-auth/pinned-bindings");
    let link_base = Path::new("/var/lib/dev-auth/pinned-binding-links");
    require_root_owned_ancestor_chain(data_base)?;
    require_root_owned_ancestor_chain(link_base)?;
    let mut accounts = BTreeSet::new();
    for base in [data_base, link_base] {
        for name in owned_store_entries(base, 0, 0o755)?.unwrap_or_default() {
            let uid = name
                .parse::<u32>()
                .ok()
                .filter(|uid| *uid > 0 && uid.to_string() == name)
                .context("pinned store account directory is invalid")?;
            accounts.insert(uid);
        }
    }
    Ok(accounts)
}

pub(crate) fn require_no_pending_pinned_retirements() -> Result<()> {
    for uid in pinned_store_accounts()? {
        let data_account = PathBuf::from(format!("/var/lib/dev-auth/pinned-bindings/{uid}"));
        owned_store_entries(&data_account, 0, 0o755)?;
        if retirement::pending_at(&data_account, 0)? {
            bail!("a prior pinned store retirement requires accepted setup recovery");
        }
    }
    Ok(())
}

fn require_root_owned_ancestor_chain(path: &Path) -> Result<()> {
    let mut current = PathBuf::from("/");
    for part in path.components().skip(1) {
        current.push(part.as_os_str());
        match fs::symlink_metadata(&current) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("inspect pinned store ancestor"),
            Ok(metadata)
                if metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && std::os::unix::fs::MetadataExt::uid(&metadata) == 0
                    && std::os::unix::fs::MetadataExt::mode(&metadata) & 0o022 == 0 => {}
            Ok(_) => bail!("pinned store ancestor has unsafe native custody"),
        }
    }
    Ok(())
}

fn collect_pinned_stores_at(
    account_uid: u32,
    data_base: &Path,
    link_base: &Path,
    owner_uid: u32,
    directory_mode: u32,
    keep: &BTreeSet<PathBuf>,
) -> Result<usize> {
    let data_account = data_base.join(account_uid.to_string());
    let link_account = link_base.join(account_uid.to_string());
    // Inspect both native account directories before opening a marker beneath
    // either path. A forged parent must never select a retirement target.
    owned_store_entries(&data_account, owner_uid, directory_mode)?;
    owned_store_entries(&link_account, owner_uid, directory_mode)?;
    let mut removed = usize::from(retirement::resume_at(
        &data_account,
        &link_account,
        owner_uid,
        directory_mode,
        keep,
    )?);
    let Some(aliases) = owned_store_entries(&data_account, owner_uid, directory_mode)? else {
        if fs::symlink_metadata(&link_account).is_ok() || !keep.is_empty() {
            bail!("pinned store roots differ from retained binding authority");
        }
        return Ok(0);
    };
    if owned_store_entries(&link_account, owner_uid, directory_mode)?.unwrap_or_default() != aliases
    {
        bail!("pinned artifact and link accounts have different aliases");
    }
    let mut seen = BTreeSet::new();
    let mut stale = Vec::new();
    for alias in aliases {
        crate::setup::validate_workload_alias_names(std::slice::from_ref(&alias))?;
        let alias_root = data_account.join(&alias);
        let generations = owned_store_entries(&alias_root, owner_uid, directory_mode)?
            .context("pinned alias directory disappeared")?;
        if owned_store_entries(&link_account.join(&alias), owner_uid, directory_mode)?
            .context("pinned link alias directory disappeared")?
            != generations
        {
            bail!("pinned artifact and link aliases have different generations");
        }
        for generation in generations {
            let (number, digest) = generation
                .strip_prefix('g')
                .and_then(|value| value.split_once('-'))
                .context("pinned store generation name is invalid")?;
            if number
                .parse::<u64>()
                .ok()
                .filter(|number| *number > 0)
                .map(|value| value.to_string())
                != Some(number.to_owned())
                || digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                bail!("pinned store generation name is invalid");
            }
            let layout = VersionedLayout {
                product: "dev-auth-binding".into(),
                data_root: alias_root.join(&generation),
                bin_dir: link_account.join(&alias).join(&generation),
                artifact_name: "payload".into(),
                owner_uid,
                directory_mode,
                bin_directory_mode: None,
            };
            let observed = observe_versioned_installation(&layout, 512 * 1024 * 1024)?
                .context("pinned store has no completed receipt")?;
            if observed.active_version != "v1"
                || observed.previous_version.is_some()
                || observed.aliases != [alias.clone()]
                || observed.active_identity.sha256 != digest
            {
                bail!("pinned store does not match its generation directory");
            }
            seen.insert(layout.data_root.clone());
            if keep.contains(&layout.data_root) {
                continue;
            }
            require_store_entries(
                &layout.data_root,
                owner_uid,
                directory_mode,
                &[
                    "versions",
                    "active",
                    "installation-receipt-v1.json",
                    "installation.lock",
                ],
            )?;
            require_store_entries(
                &layout.data_root.join("versions"),
                owner_uid,
                directory_mode,
                &["v1"],
            )?;
            require_store_entries(
                &layout.data_root.join("versions/v1"),
                owner_uid,
                directory_mode,
                &["payload"],
            )?;
            require_store_entries(&layout.bin_dir, owner_uid, directory_mode, &[&alias])?;
            stale.push((layout, observed));
        }
    }
    if !keep.is_subset(&seen) {
        bail!("retained pinned generation has no completed artifact store");
    }
    for (layout, receipt) in stale {
        retirement::retire_at(
            &layout,
            &receipt,
            &data_account,
            &link_account,
            owner_uid,
            directory_mode,
            keep,
        )?;
        removed += 1;
    }
    Ok(removed)
}

fn owned_store_entries(path: &Path, owner_uid: u32, mode: u32) -> Result<Option<Vec<String>>> {
    use std::os::unix::fs::MetadataExt;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect pinned store directory"),
    };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != mode
    {
        bail!("pinned store directory has incompatible native custody");
    }
    let mut names = fs::read_dir(path)?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("pinned store contains a non-UTF-8 entry"))
        })
        .collect::<Result<Vec<_>>>()?;
    names.sort();
    Ok(Some(names))
}

fn require_store_entries(path: &Path, owner_uid: u32, mode: u32, expected: &[&str]) -> Result<()> {
    let entries = owned_store_entries(path, owner_uid, mode)?
        .context("pinned store directory disappeared")?;
    if entries
        != expected
            .iter()
            .map(|entry| (*entry).to_owned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    {
        bail!("pinned store contains an unowned entry");
    }
    Ok(())
}

#[cfg(test)]
mod public_parent_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn unsafe_earlier_ancestor_rejects_before_publication_or_storage_sync() {
        for mode in [0o700, 0o777, 0o1755] {
            let anchor = tempfile::tempdir().unwrap();
            fs::set_permissions(anchor.path(), fs::Permissions::from_mode(0o755)).unwrap();
            let earlier = anchor.path().join("earlier");
            let closest = earlier.join("closest");
            fs::create_dir(&earlier).unwrap();
            fs::create_dir(&closest).unwrap();
            fs::set_permissions(&earlier, fs::Permissions::from_mode(mode)).unwrap();
            fs::set_permissions(&closest, fs::Permissions::from_mode(0o755)).unwrap();
            let selected = closest.join("selected");
            let mut entered_preparation = false;
            let result = prepare_public_binding_parent_paths(
                &[anchor.path(), &earlier, &closest, &selected],
                nix::unistd::Uid::effective().as_raw(),
                |preparation| {
                    entered_preparation = true;
                    Ok(preparation.prepare()?.1)
                },
            );
            assert!(result.is_err());
            assert!(!entered_preparation);
            assert!(!selected.exists());
            assert_eq!(
                fs::symlink_metadata(&earlier).unwrap().mode() & 0o7777,
                mode
            );
            assert_eq!(fs::read_dir(&closest).unwrap().count(), 0);
        }
    }

    #[test]
    fn incompatible_existing_leaf_rejects_before_storage_sync_without_chmod() {
        let anchor = tempfile::tempdir().unwrap();
        fs::set_permissions(anchor.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let selected = anchor.path().join("selected");
        fs::create_dir(&selected).unwrap();
        fs::set_permissions(&selected, fs::Permissions::from_mode(0o700)).unwrap();
        let mut entered_preparation = false;
        let result = prepare_public_binding_parent_paths(
            &[anchor.path(), &selected],
            nix::unistd::Uid::effective().as_raw(),
            |preparation| {
                entered_preparation = true;
                Ok(preparation.prepare()?.1)
            },
        );
        assert!(result.is_err());
        assert!(!entered_preparation);
        assert_eq!(
            fs::symlink_metadata(&selected).unwrap().mode() & 0o7777,
            0o700
        );
        assert_eq!(fs::read_dir(&selected).unwrap().count(), 0);
    }
}
