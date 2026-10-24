//! Accepted setup source capture for authenticated candidate-owned updates.
use super::*;
use std::fs::File;
use std::os::unix::fs::PermissionsExt;

/// Keep the exact accepted configuration bytes available only while an update
/// plan is built and entered. Once setup publishes its retained generation,
/// recovery no longer depends on these ephemeral source paths.
pub struct PreparedUpdateIntent {
    pub intent: DeploymentIntent,
    _sources: tempfile::TempDir,
    staging_lock: File,
    staging_directory: File,
    pub accepted_plan_sha256: String,
    pub installation_receipt_sha256: String,
}

impl PreparedUpdateIntent {
    pub fn source_directory(&self) -> &Path {
        self._sources.path()
    }
    pub fn staging_lock(&self) -> &File {
        &self.staging_lock
    }
    pub fn staging_directory(&self) -> &File {
        &self.staging_directory
    }
}

pub fn prepare_update_intent_from_accepted() -> Result<PreparedUpdateIntent> {
    let (paths, receipt) = crate::setup::current_installation()?;
    prepare_update_intent_from_accepted_at(&paths, &receipt)
}

#[cfg(target_os = "linux")]
fn refreshed_binding_source(
    document: &RetainedCandidateDocument,
    installation: &crate::setup::InstallReceipt,
    accounts: &[NativeAccountIdentity],
) -> Result<Vec<u8>> {
    let prior: crate::smart_binding::BindingPlan =
        serde_json::from_slice(&document.bytes).context("decode accepted binding source")?;
    let (user_name, binding_name) = document
        .identity
        .subject
        .split_once('/')
        .context("accepted binding source has no native account selector")?;
    if prior.name != binding_name {
        bail!("accepted binding source name differs from its retained identity");
    }
    let account = accounts
        .iter()
        .find(|account| account.name == user_name)
        .context("accepted binding native account is absent")?;
    let receipt_path = crate::binding_activation::native_receipt_path(
        installation.mode,
        &account.home,
        account.uid,
    )?;
    let (set, _) = crate::binding_activation::read_at(
        &receipt_path,
        installation.mode,
        account.uid,
        installation,
    )?
    .context("accepted binding receipt is absent")?;
    let current = set
        .bindings
        .get(&prior.intent.command_name)
        .context("accepted binding alias is absent")?;
    if current.active.intent != prior.intent {
        bail!("accepted binding intent changed outside setup authority");
    }
    if prior.intent.code_trust == crate::smart_binding::BindingCodeTrust::Pinned {
        if installation.mode == crate::setup::InstallMode::Strong {
            crate::binding_activation::verify_pinned_artifact(
                account.uid,
                &prior.intent.command_name,
                current,
            )?;
        }
        if crate::smart_binding::is_pinned_shell_resolution(&prior.resolved) {
            crate::binding_activation::verify_shell_payload(
                installation.mode,
                &account.home,
                account.uid,
                &prior.intent.command_name,
                current,
            )?;
        }
        let rebased = crate::smart_binding::rebase_retained_pinned_plan(&prior, current)?;
        return crate::smart_binding::canonical_retained_binding_plan(&rebased);
    }
    let excluded = vec![
        PathBuf::from(&installation.executable),
        account
            .home
            .join(".local/share/dev-auth/workload-bindings/bin"),
        PathBuf::from("/usr/local/lib/dev-auth/workload-bindings/bin"),
    ];
    let resolved = match (&prior.intent.target, &prior.resolved) {
        (
            crate::smart_binding::BindingTargetIntent::Structured { executable, .. },
            crate::smart_binding::BindingResolution::Structured { .. },
        ) => crate::smart_binding::resolve_structured_target_excluding(executable, &excluded)?,
        (
            crate::smart_binding::BindingTargetIntent::Continuation,
            crate::smart_binding::BindingResolution::Continuation { resolution },
        ) => {
            let next = crate::smart_binding::resolve_continuation(
                &prior.intent.command_name,
                &resolution.continuation_path,
                &excluded,
            )?;
            if next.visible_path != resolution.visible_path
                || next.canonical_path != resolution.canonical_path
            {
                bail!("mutable binding location changed outside its approved source");
            }
            next.into()
        }
        _ => bail!("accepted mutable binding target kind is invalid"),
    };
    require_same_mutable_location(&prior.resolved, &resolved)?;
    let refreshed = crate::smart_binding::build_binding_plan(
        prior.name,
        prior.intent,
        resolved,
        Some(current),
    )?;
    crate::smart_binding::canonical_binding_plan(&refreshed)
}

pub fn prepare_update_intent_from_accepted_at(
    paths: &crate::setup::SetupPaths,
    receipt: &crate::setup::InstallReceipt,
) -> Result<PreparedUpdateIntent> {
    let owner_uid = match receipt.mode {
        crate::setup::InstallMode::Strong => 0,
        crate::setup::InstallMode::UserOnly => nix::unistd::Uid::effective().as_raw(),
    };
    let transition = crate::setup_transition::retained_transition(paths, owner_uid)?
        .context("an accepted full setup generation is required for update")?;
    if transition.phase != crate::setup_transition::Phase::Accepted {
        bail!("the current setup generation requires recovery or restoration before update");
    }
    let generation: RetainedSetupGeneration = serde_json::from_slice(&transition.bytes)
        .context("decode accepted full setup generation")?;
    if generation.schema != "dev-auth-retained-setup-generation-v1"
        || generation.plan_sha256 != transition.plan_sha256
        || sha256_hex(&serde_jcs::to_vec(&generation.plan)?) != transition.plan_sha256
        || generation.plan.installation.paths != *paths
        || generation.plan.installation.request.version != receipt.version
        || generation.plan.installation.request.mode != receipt.mode
        || generation.plan.installation.request.purpose != receipt.purpose
        || generation.plan.installation.source_length != receipt.executable_length
        || generation.plan.installation.source_sha256 != receipt.executable_sha256
    {
        bail!("accepted setup generation does not match the running installation");
    }
    validate_candidate_inventory(&generation.plan, &generation.candidate_documents)?;
    verify_postcondition(
        &generation.plan,
        &transition.plan_sha256,
        &generation.candidate_documents,
    )
    .context("current accepted setup postcondition changed before update")?;
    reclaim_abandoned_update_staging_at(&paths.data_root, owner_uid)?;
    let sources = tempfile::Builder::new()
        .prefix("dev-auth-update-sources-")
        .tempdir_in(&paths.data_root)
        .context("create private update source snapshot")?;
    fs::set_permissions(sources.path(), fs::Permissions::from_mode(0o700))
        .context("protect private update source snapshot")?;
    let staging_directory = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(sources.path())?;
    let staging_lock = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(sources.path().join("update.lock"))
        .context("create private update staging lock")?;
    fs2::FileExt::lock_exclusive(&staging_lock).context("lock private update staging")?;
    let mut intent = generation.plan.intent.clone();
    let mut seen = BTreeSet::new();
    for (index, document) in generation.candidate_documents.iter().enumerate() {
        let key = (
            document.identity.kind.as_str(),
            document.identity.subject.as_str(),
        );
        if !seen.insert(key) {
            bail!("accepted setup source inventory contains a duplicate declaration");
        }
        #[cfg(target_os = "linux")]
        let source_bytes = if key.0 == "binding_plan" {
            refreshed_binding_source(document, receipt, &generation.plan.accounts)?
        } else {
            document.bytes.clone()
        };
        #[cfg(not(target_os = "linux"))]
        let source_bytes = document.bytes.clone();
        let path = sources.path().join(format!("source-{index}"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .context("create private update source document")?;
        file.write_all(&source_bytes)
            .context("write private update source document")?;
        file.sync_all()
            .context("sync private update source document")?;
        replace_source_path(&mut intent, document, path, &source_bytes)?;
    }

    let expected = 1
        + usize::from(intent.grant_policy.is_some())
        + intent.bindings.len()
        + intent
            .users
            .iter()
            .map(|user| 1 + usize::from(user.policy.is_some()))
            .sum::<usize>();
    if seen.len() != expected {
        bail!("accepted update source inventory is incomplete");
    }
    canonical_deployment_intent(&intent)?;
    Ok(PreparedUpdateIntent {
        intent,
        _sources: sources,
        staging_lock,
        staging_directory,
        accepted_plan_sha256: transition.plan_sha256,
        installation_receipt_sha256: sha256_hex(&serde_jcs::to_vec(receipt)?),
    })
}

pub(crate) fn reclaim_abandoned_update_staging_at(data_root: &Path, owner_uid: u32) -> Result<()> {
    let metadata =
        fs::symlink_metadata(data_root).context("inspect accepted update staging root")?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o022 != 0
    {
        bail!("accepted update staging root has unsafe native authority");
    }
    reclaim_abandoned_update_staging(data_root, owner_uid)
}

/// Remove only complete, abandoned source snapshots made by this protocol.
/// The lock is inherited by the private worker, so parent death cannot make a
/// still-running setup transaction look abandoned. Older unmarked snapshots
/// are deliberately left for explicit inspection.
fn reclaim_abandoned_update_staging(data_root: &Path, owner_uid: u32) -> Result<()> {
    for entry in fs::read_dir(data_root).context("inspect update staging root")? {
        let entry = entry.context("inspect update staging entry")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("dev-auth-update-sources-") {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != owner_uid
            || metadata.mode() & 0o777 != 0o700
        {
            continue;
        }
        let lock_path = path.join("update.lock");
        let lock_metadata = match fs::symlink_metadata(&lock_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("inspect update staging lock"),
        };
        if !lock_metadata.file_type().is_file()
            || lock_metadata.file_type().is_symlink()
            || lock_metadata.uid() != owner_uid
            || lock_metadata.mode() & 0o777 != 0o600
            || lock_metadata.nlink() != 1
        {
            continue;
        }
        let lock = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&lock_path)
            .context("open update staging lock")?;
        let opened = lock.metadata()?;
        if opened.dev() != lock_metadata.dev() || opened.ino() != lock_metadata.ino() {
            continue;
        }
        match fs2::FileExt::try_lock_exclusive(&lock) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error).context("inspect update staging activity"),
        }
        if !staging_identity_unchanged(&path, &metadata, &lock_path, &opened)? {
            continue;
        }
        let mut files = Vec::new();
        let mut recognized = true;
        for child in fs::read_dir(&path).context("inspect abandoned update staging")? {
            let child = child?;
            let child_name = child.file_name();
            let Some(child_name) = child_name.to_str() else {
                recognized = false;
                break;
            };
            if child_name != "update.lock"
                && child_name != "update-request.json"
                && child_name != "update-result.json"
                && !child_name.strip_prefix("source-").is_some_and(|index| {
                    !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
                })
            {
                recognized = false;
                break;
            }
            let child_metadata = fs::symlink_metadata(child.path())?;
            if !child_metadata.file_type().is_file()
                || child_metadata.uid() != owner_uid
                || child_metadata.mode() & 0o777 != 0o600
                || child_metadata.nlink() != 1
            {
                recognized = false;
                break;
            }
            files.push((child.path(), child_metadata));
        }
        if !recognized {
            continue;
        }
        if !staging_identity_unchanged(&path, &metadata, &lock_path, &opened)? {
            continue;
        }
        if files.iter().any(|(file, expected)| {
            !fs::symlink_metadata(file).is_ok_and(|current| {
                current.file_type().is_file()
                    && current.dev() == expected.dev()
                    && current.ino() == expected.ino()
                    && current.uid() == owner_uid
                    && current.mode() & 0o777 == 0o600
                    && current.nlink() == 1
            })
        }) {
            continue;
        }
        for (file, _) in files {
            fs::remove_file(&file).context("remove abandoned update source")?;
        }
        fs::remove_dir(&path).context("remove abandoned update staging")?;
    }
    Ok(())
}

fn staging_identity_unchanged(
    directory: &Path,
    expected_directory: &fs::Metadata,
    lock: &Path,
    expected_lock: &fs::Metadata,
) -> Result<bool> {
    let current_directory = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("reinspect update staging directory"),
    };
    let current_lock = match fs::symlink_metadata(lock) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("reinspect update staging lock"),
    };
    Ok(current_directory.file_type().is_dir()
        && !current_directory.file_type().is_symlink()
        && current_directory.dev() == expected_directory.dev()
        && current_directory.ino() == expected_directory.ino()
        && current_directory.uid() == expected_directory.uid()
        && current_directory.mode() & 0o777 == 0o700
        && current_lock.file_type().is_file()
        && !current_lock.file_type().is_symlink()
        && current_lock.dev() == expected_lock.dev()
        && current_lock.ino() == expected_lock.ino()
        && current_lock.uid() == expected_lock.uid()
        && current_lock.mode() & 0o777 == 0o600
        && current_lock.nlink() == 1)
}

fn replace_source_path(
    intent: &mut DeploymentIntent,
    document: &RetainedCandidateDocument,
    path: PathBuf,
    source_bytes: &[u8],
) -> Result<()> {
    match (
        document.identity.kind.as_str(),
        document.identity.subject.as_str(),
    ) {
        ("administrator_policy", "system")
            if intent.administrator_policy == document.identity.path =>
        {
            intent.administrator_policy = path;
        }
        ("grant_policy", "system")
            if intent.grant_policy.as_ref() == Some(&document.identity.path) =>
        {
            intent.grant_policy = Some(path);
        }
        ("grant_policy", "system")
            if intent.purpose == crate::deployment::SetupPurpose::PrivilegeOnly
                && intent.administrator_policy == document.identity.path =>
        {
            intent.administrator_policy = path;
        }
        ("user_configuration", user) => {
            let target = intent
                .users
                .iter_mut()
                .find(|entry| entry.name == user && entry.config == document.identity.path)
                .context("accepted update user configuration source is unbound")?;
            target.config = path;
        }
        ("user_policy", user) => {
            let target = intent
                .users
                .iter_mut()
                .find(|entry| {
                    entry.name == user && entry.policy.as_ref() == Some(&document.identity.path)
                })
                .context("accepted update user policy source is unbound")?;
            target.policy = Some(path);
        }
        ("binding_plan", subject) => {
            let target = intent
                .bindings
                .iter_mut()
                .find(|binding| {
                    format!("{}/{}", binding.user, binding.name) == subject
                        && binding.plan == document.identity.path
                })
                .context("accepted update binding plan source is unbound")?;
            target.plan = path;
            target.sha256 = sha256_hex(source_bytes);
        }
        _ => bail!("accepted update source has no deployment-intent binding"),
    }
    Ok(())
}

/// Recheck the exact accepted source authority in the candidate process. Its
/// own embedded grant payload must not reinterpret the prior release's assets.
pub(crate) fn validate_update_intent_from_accepted_at(
    paths: &crate::setup::SetupPaths,
    receipt: &crate::setup::InstallReceipt,
    intent: &DeploymentIntent,
    accepted_digest: &str,
    receipt_digest: &str,
    staging: &Path,
) -> Result<CredentialPreservationV1> {
    let owner = if receipt.mode == crate::setup::InstallMode::Strong {
        0
    } else {
        nix::unistd::Uid::effective().as_raw()
    };
    let transition = crate::setup_transition::retained_transition(paths, owner)?
        .context("accepted setup is absent")?;
    let generation: RetainedSetupGeneration = serde_json::from_slice(&transition.bytes)?;
    if transition.phase != crate::setup_transition::Phase::Accepted
        || transition.plan_sha256 != accepted_digest
        || generation.schema != "dev-auth-retained-setup-generation-v1"
        || generation.plan_sha256 != accepted_digest
        || sha256_hex(&serde_jcs::to_vec(&generation.plan)?) != accepted_digest
        || sha256_hex(&serde_jcs::to_vec(receipt)?) != receipt_digest
        || generation.plan.installation.paths != *paths
        || generation.plan.installation.request.mode != receipt.mode
        || generation.plan.installation.request.purpose != receipt.purpose
        || generation.plan.installation.request.version != receipt.version
        || generation.plan.installation.source_length != receipt.executable_length
        || generation.plan.installation.source_sha256 != receipt.executable_sha256
    {
        bail!("accepted update authority changed before candidate entry");
    }
    validate_candidate_inventory(&generation.plan, &generation.candidate_documents)?;
    restoration::require_retained_native_accounts(
        generation
            .plan
            .accounts
            .iter()
            .chain(&generation.plan.retiring_accounts),
    )?;
    verify_credential_postcondition(&generation.plan, accepted_digest)?;
    let mut expected = generation.plan.intent.clone();
    expected.offline = intent.offline;
    for (index, document) in generation.candidate_documents.iter().enumerate() {
        let path = staging.join(format!("source-{index}"));
        let expected_bytes = if document.identity.kind == "binding_plan" {
            refreshed_binding_source(document, receipt, &generation.plan.accounts)?
        } else {
            document.bytes.clone()
        };
        let actual = read_atomic_document(
            &path,
            &DocumentAuthority {
                owner_uid: owner,
                mode: 0o600,
                limit: DOCUMENT_LIMIT,
            },
        )?
        .context("private update source is absent")?;
        if actual.bytes != expected_bytes {
            bail!("private update source changed after capture");
        }
        replace_source_path(&mut expected, document, path, &expected_bytes)?;
    }
    if expected != *intent {
        bail!("update attempted to replace accepted product policy");
    }
    observe_credential_preservation(
        &generation.plan,
        accepted_digest.into(),
        receipt_digest.into(),
    )
}

pub(crate) fn build_preserving_update_plan(
    intent: DeploymentIntent,
    release: crate::release_manifest::VerifiedDevAuthRelease,
    preservation: CredentialPreservationV1,
) -> Result<SetupPlanV3> {
    let mut plan = build_setup_plan_v3_for_verified_release(intent, release)?;
    if plan.intent.purpose.is_credentials() {
        plan.credential_preservation = Some(preservation);
        plan.schema = "dev-auth-setup-plan-v6".into();
        require_preserved_credential_state(&plan)?;
    }
    validate_setup_plan_v3(&plan)?;
    Ok(plan)
}

fn require_same_mutable_location(
    prior: &crate::smart_binding::BindingResolution,
    next: &crate::smart_binding::BindingResolution,
) -> Result<()> {
    use crate::smart_binding::BindingResolution;
    let same = match (prior, next) {
        (
            BindingResolution::Structured { identity: before },
            BindingResolution::Structured { identity: after },
        ) => before.canonical_path == after.canonical_path,
        (
            BindingResolution::Continuation { resolution: before },
            BindingResolution::Continuation { resolution: after },
        ) => {
            before.visible_path == after.visible_path
                && before.canonical_path == after.canonical_path
        }
        _ => false,
    };
    if !same {
        bail!("mutable binding location changed outside its accepted intent");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smart_binding::{BindingAuthority, BindingResolution, ExecutableIdentity};

    #[test]
    fn update_refresh_accepts_changed_mutable_bytes_only_at_the_same_target() {
        let identity = ExecutableIdentity {
            canonical_path: "/usr/local/bin/worker".into(),
            length: 4,
            sha256: "1".repeat(64),
            authority: BindingAuthority::UserOwned,
            device: None,
            inode: None,
            mode: None,
            owner: None,
            group: None,
        };
        let prior = BindingResolution::Structured {
            identity: identity.clone(),
        };
        let mut next = identity;
        next.sha256 = "2".repeat(64);
        next.inode = Some(9007199254740993);
        assert!(require_same_mutable_location(
            &prior,
            &BindingResolution::Structured {
                identity: next.clone()
            }
        )
        .is_ok());
        next.canonical_path = "/usr/local/bin/other-worker".into();
        assert!(require_same_mutable_location(
            &prior,
            &BindingResolution::Structured { identity: next }
        )
        .is_err());
    }

    #[test]
    fn staging_collection_keeps_live_and_foreign_documents() {
        if crate::test_isolation::run_isolated(concat!(
            module_path!(),
            "::staging_collection_keeps_live_and_foreign_documents"
        )) {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        let staging = root.path().join("dev-auth-update-sources-test");
        fs::create_dir(&staging).unwrap();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).unwrap();
        let lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(staging.join("update.lock"))
            .unwrap();
        fs2::FileExt::lock_exclusive(&lock).unwrap();
        reclaim_abandoned_update_staging(root.path(), uid).unwrap();
        assert!(staging.exists());
        drop(lock);
        fs::write(staging.join("foreign"), b"keep").unwrap();
        reclaim_abandoned_update_staging(root.path(), uid).unwrap();
        assert!(staging.exists());
        fs::remove_file(staging.join("foreign")).unwrap();
        reclaim_abandoned_update_staging(root.path(), uid).unwrap();
        assert!(!staging.exists());
    }
}
