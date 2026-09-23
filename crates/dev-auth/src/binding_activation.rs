//! Receipt-owned Linux binding generations. This module does not publish a
//! proxy or admit a workload; the full setup transaction owns those effects.

use crate::setup::InstallReceipt;
use crate::smart_binding::{
    advance_binding, canonical_binding_plan, validate_binding_receipt_structure, BindingCodeTrust,
    BindingGeneration, BindingPlan, BindingPlanChange, BindingReceipt,
};
use anyhow::{bail, Context, Result};
use dev_tools_installation::{
    read_atomic_document, remove_atomic_document_if_unchanged, write_atomic_document,
    ArtifactIdentity, DocumentAuthority,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

const SCHEMA: &str = "dev-auth-binding-set-v1";
const LIMIT: u64 = 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BindingSetReceipt {
    pub schema: String,
    pub platform: String,
    pub account_uid: u32,
    pub product_executable: PathBuf,
    pub product_sha256: String,
    pub bindings: BTreeMap<String, BindingReceipt>,
}

pub struct ResolvedBindingLaunch {
    pub workload: String,
    pub arguments: Vec<OsString>,
    pub code_trust: BindingCodeTrust,
    pub generation: u64,
    pub target: PathBuf,
}

pub struct BindingPlanningState {
    pub current: Option<BindingReceipt>,
    pub installed_executable: Option<PathBuf>,
    pub account_home: PathBuf,
}

pub fn planning_state(native_user: &str, alias: &str) -> Result<BindingPlanningState> {
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
    let (_, installation) = crate::setup::current_runtime_installation()?;
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
        arguments: binding
            .active
            .intent
            .target
            .forward_arguments(caller_arguments)?,
        code_trust: binding.active.intent.code_trust,
        generation: binding.active.generation,
        target: target.to_path_buf(),
    }))
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
    validate(&receipt, account_uid, installation)?;
    Ok(Some((receipt, document.identity)))
}

pub fn write_at(
    path: &Path,
    mode: crate::setup::InstallMode,
    account_uid: u32,
    installation: &InstallReceipt,
    receipt: &BindingSetReceipt,
    expected: Option<&ArtifactIdentity>,
) -> Result<bool> {
    validate(receipt, account_uid, installation)?;
    let bytes = serde_jcs::to_vec(receipt).context("canonicalize binding set receipt")?;
    write_atomic_document(path, &bytes, &authority(mode, account_uid), expected)
}

pub fn retire_at(
    path: &Path,
    mode: crate::setup::InstallMode,
    account_uid: u32,
    expected: &ArtifactIdentity,
) -> Result<bool> {
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
    for plan in plans {
        canonical_binding_plan(plan)?;
        if plan.intent.code_trust != BindingCodeTrust::Mutable {
            bail!("pinned binding activation requires retained-byte native launch support");
        }
        let alias = &plan.intent.command_name;
        let prior = current.and_then(|(receipt, _)| receipt.bindings.get(alias));
        if plan.current_receipt.as_ref() != prior {
            bail!("binding plan does not match the current receipt generation");
        }
        let receipt = match prior {
            Some(prior) => advance_binding(prior, plan.intent.clone(), plan.resolved.clone())?,
            None => BindingReceipt::new(plan.intent.clone(), plan.resolved.clone())?,
        };
        if bindings.insert(alias.clone(), receipt).is_some() {
            bail!("binding desired state repeats one command alias");
        }
    }
    Ok(BindingSetReceipt {
        schema: SCHEMA.into(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        account_uid,
        product_executable: PathBuf::from(&next_installation.executable),
        product_sha256: next_installation.executable_sha256.clone(),
        bindings,
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
    expected_desired_with_identity(
        account_uid,
        Path::new(&next_installation.executable),
        &next_installation.executable_sha256,
        current,
        plans,
    )
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
    for plan in plans {
        if plan.schema != "dev-auth-workload-binding-plan-v3"
            || plan.platform != format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
            || plan.intent.code_trust != BindingCodeTrust::Mutable
        {
            bail!("approved binding plan has unsupported execution authority");
        }
        let alias = &plan.intent.command_name;
        let prior = current.and_then(|(receipt, _)| receipt.bindings.get(alias));
        if plan.current_receipt.as_ref() != prior {
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
                if prior.active.intent != plan.intent || prior.active.resolved != plan.resolved {
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
        validate_binding_receipt_structure(&receipt)?;
        if bindings.insert(alias.clone(), receipt).is_some() {
            bail!("approved binding set contains a duplicate alias");
        }
    }
    Ok(BindingSetReceipt {
        schema: SCHEMA.into(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        account_uid,
        product_executable: next_executable.to_path_buf(),
        product_sha256: next_sha256.into(),
        bindings,
    })
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
    for (alias, binding) in &receipt.bindings {
        validate_binding_receipt_structure(binding)?;
        if alias != &binding.active.intent.command_name
            || binding.active.intent.code_trust != BindingCodeTrust::Mutable
        {
            bail!("binding alias or code trust differs from its receipt");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smart_binding::{build_binding_plan, resolve_structured_target, BindingIntent};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn installation(executable: &str, digest: &str) -> InstallReceipt {
        InstallReceipt {
            purpose: Default::default(),
            schema: "dev-auth-install-v2".into(),
            mode: crate::setup::InstallMode::UserOnly,
            version: "0.5.0".into(),
            executable: executable.into(),
            bin_dir: "/tmp/bin".into(),
            executable_length: 10,
            executable_sha256: digest.into(),
            source_commit: None,
            root_generation: None,
            manifest_generation: None,
            native_git: "/usr/bin/git".into(),
            native_gh: "/usr/bin/gh".into(),
            product_aliases: vec![],
            transparent_aliases: vec![],
            privileged_launcher: None,
            system_assets: BTreeMap::new(),
            previous_release: None,
        }
    }

    #[test]
    fn mutable_binding_set_is_receipted_and_rebound_to_an_upgrade() {
        let uid = nix::unistd::Uid::effective().as_raw();
        if uid == 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("agent");
        fs::write(&target, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let resolved = resolve_structured_target(&target).unwrap();
        let intent =
            BindingIntent::structured("agent", "automation", &target, Vec::<String>::new())
                .unwrap()
                .with_code_trust(BindingCodeTrust::Mutable);
        let plan =
            build_binding_plan("agent-binding", intent.clone(), resolved.clone(), None).unwrap();
        let prior_installation = installation("/tmp/dev-auth-v1", &"a".repeat(64));
        let initial = build_desired(uid, &prior_installation, None, &[plan]).unwrap();
        let path = root.path().join("binding-set.json");
        assert!(write_at(
            &path,
            crate::setup::InstallMode::UserOnly,
            uid,
            &prior_installation,
            &initial,
            None,
        )
        .unwrap());
        let (read, identity) = read_at(
            &path,
            crate::setup::InstallMode::UserOnly,
            uid,
            &prior_installation,
        )
        .unwrap()
        .unwrap();
        assert_eq!(read, initial);
        let next_installation = installation("/tmp/dev-auth-v2", &"b".repeat(64));
        let unchanged = build_binding_plan(
            "agent-binding",
            intent,
            resolved,
            read.bindings.get("agent"),
        )
        .unwrap();
        let next = build_desired(
            uid,
            &next_installation,
            Some((&read, &prior_installation)),
            &[unchanged],
        )
        .unwrap();
        assert_eq!(
            next.bindings["agent"].active.generation,
            initial.bindings["agent"].active.generation
        );
        assert!(write_at(
            &path,
            crate::setup::InstallMode::UserOnly,
            uid,
            &next_installation,
            &next,
            Some(&identity),
        )
        .unwrap());
        assert!(read_at(
            &path,
            crate::setup::InstallMode::UserOnly,
            uid,
            &prior_installation,
        )
        .is_err());
        assert!(read_at(
            &path,
            crate::setup::InstallMode::UserOnly,
            uid,
            &next_installation,
        )
        .unwrap()
        .is_some());
        let removed = build_desired(
            uid,
            &next_installation,
            Some((&next, &next_installation)),
            &[],
        )
        .unwrap();
        assert!(removed.bindings.is_empty());
    }

    #[test]
    fn pinned_binding_cannot_enter_mutable_proxy_activation() {
        let uid = nix::unistd::Uid::effective().as_raw();
        if uid == 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("agent");
        fs::write(&target, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let resolved = resolve_structured_target(&target).unwrap();
        let intent =
            BindingIntent::structured("agent", "automation", &target, Vec::<String>::new())
                .unwrap();
        let plan = build_binding_plan("agent-binding", intent, resolved, None).unwrap();
        assert!(build_desired(
            uid,
            &installation("/tmp/dev-auth", &"a".repeat(64)),
            None,
            &[plan]
        )
        .is_err());
    }
}
