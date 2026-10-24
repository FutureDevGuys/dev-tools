//! Native admission exclusion for full setup. The runtime lock survives
//! installation-directory replacement; the durable marker survives a crash.
use crate::deployment::DeploymentMode;
use crate::setup::{InstallMode, SetupPaths};
use anyhow::{bail, Context, Result};
use dev_tools_installation::{
    read_atomic_document, write_atomic_document, ArtifactIdentity, DocumentAuthority,
    InstallationLock,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Pending,
    Accepted,
    Restoring,
    RestoredInactive,
    Repairing,
    Uninstalling,
    UninstalledInactive,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Transition {
    schema: String,
    plan_sha256: String,
    phase: Phase,
    retained_generation: ArtifactIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    maintenance_generation: Option<ArtifactIdentity>,
}

pub(crate) struct RetainedTransition {
    pub plan_sha256: String,
    pub bytes: Vec<u8>,
    pub phase: Phase,
    pub maintenance_bytes: Option<Vec<u8>>,
}

pub(crate) fn retained_transition(
    paths: &SetupPaths,
    owner_uid: u32,
) -> Result<Option<RetainedTransition>> {
    let Some(document) = read_atomic_document(&state_path(paths), &authority(owner_uid))? else {
        return Ok(None);
    };
    let state = parse(&document.bytes)?;
    let bytes = read_generation(paths, owner_uid, &state)?;
    let maintenance_bytes = read_maintenance_generation(paths, owner_uid, &state)?;
    Ok(Some(RetainedTransition {
        plan_sha256: state.plan_sha256,
        bytes,
        phase: state.phase,
        maintenance_bytes,
    }))
}

pub(crate) fn lock_path(mode: DeploymentMode, owner_uid: Option<u32>) -> Result<PathBuf> {
    match (mode, owner_uid) {
        (DeploymentMode::Strong, None) => Ok("/run/lock/dev-auth-setup-v3.lock".into()),
        (DeploymentMode::UserOnly, Some(uid)) if uid != 0 => {
            Ok(format!("/run/user/{uid}/dev-auth-setup-v3.lock").into())
        }
        _ => bail!("setup admission lock has an invalid native owner"),
    }
}

pub(crate) fn state_path(paths: &SetupPaths) -> PathBuf {
    paths.data_root.join("setup-transition-v1.json")
}

fn authority(owner_uid: u32) -> DocumentAuthority {
    DocumentAuthority {
        owner_uid,
        mode: 0o600,
        limit: 4096,
    }
}

fn parse(bytes: &[u8]) -> Result<Transition> {
    let state: Transition = serde_json::from_slice(bytes).context("parse setup admission state")?;
    if state.schema != "dev-auth-setup-transition-v1"
        || state.plan_sha256.len() != 64
        || !state
            .plan_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || state.retained_generation.length == 0
        || state.retained_generation.length > 32 * 1024 * 1024
        || state.retained_generation.sha256.len() != 64
        || !state
            .retained_generation
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("setup admission state has invalid authority");
    }
    if state
        .maintenance_generation
        .as_ref()
        .is_some_and(|identity| {
            identity.length == 0
                || identity.length > 32 * 1024 * 1024
                || identity.sha256.len() != 64
                || !identity
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    {
        bail!("setup maintenance state has invalid retention authority");
    }
    Ok(state)
}

/// Called only while the full setup writer owns the native exclusive lock.
pub(crate) fn begin(
    paths: &SetupPaths,
    owner_uid: u32,
    digest: &str,
    capture: impl FnOnce() -> Result<Vec<u8>>,
) -> Result<bool> {
    #[cfg(target_os = "linux")]
    let data_root = {
        use std::os::unix::fs::MetadataExt;

        let prepared = dev_tools_installation::DocumentDirectoryPreparation::observe(
            &paths.data_root,
            owner_uid,
            crate::setup::INSTALLATION_DIRECTORY_MODE,
        )?;
        match std::fs::symlink_metadata(&paths.data_root) {
            Ok(metadata)
                if metadata.mode() & 0o777 != crate::setup::INSTALLATION_DIRECTORY_MODE =>
            {
                bail!("setup transition root differs from the installation directory mode");
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect setup transition root"),
        }
        prepared
    };
    let path = state_path(paths);
    let authority = authority(owner_uid);
    let current = read_atomic_document(&path, &authority)?;
    if let Some(document) = &current {
        let state = parse(&document.bytes)?;
        if matches!(
            state.phase,
            Phase::Restoring | Phase::Repairing | Phase::Uninstalling
        ) || (matches!(
            state.phase,
            Phase::RestoredInactive | Phase::UninstalledInactive
        ) && state.plan_sha256 == digest)
        {
            bail!(
                "restored setup cannot resume forward; finish restoration and approve a new plan"
            );
        }
        if state.phase == Phase::Pending {
            if state.plan_sha256 != digest {
                bail!("another setup transition requires recovery before replacement");
            }
            read_generation(paths, owner_uid, &state)?;
            return write_atomic_document(
                &path,
                &document.bytes,
                &authority,
                Some(&document.identity),
            );
        }
    }
    let generation = capture()?;
    let identity = ArtifactIdentity {
        length: generation.len() as u64,
        sha256: format!("{:x}", Sha256::digest(&generation)),
    };
    let state = Transition {
        schema: "dev-auth-setup-transition-v1".into(),
        plan_sha256: digest.into(),
        phase: Phase::Pending,
        retained_generation: identity,
        maintenance_generation: None,
    };
    let bytes = serde_jcs::to_vec(&state)?;
    parse(&bytes)?;
    #[cfg(target_os = "linux")]
    {
        // Retention precedes installation, so its parent must already satisfy
        // the binary layout. Publish new final metadata before exposing the
        // root; never chmod an existing path or let umask select its mode.
        data_root.prepare()?;
        dev_tools_installation::ensure_owned_directory(
            &paths.data_root,
            owner_uid,
            crate::setup::INSTALLATION_DIRECTORY_MODE,
        )?;
    }
    // Immutable, digest-addressed-by-plan retention precedes the admission
    // marker and every candidate mutation. Retry cannot replace old bytes.
    write_atomic_document(
        &generation_path(paths, &state.plan_sha256),
        &generation,
        &generation_authority(owner_uid),
        None,
    )?;
    write_atomic_document(
        &path,
        &bytes,
        &authority,
        current.as_ref().map(|doc| &doc.identity),
    )
}

fn generation_path(paths: &SetupPaths, digest: &str) -> PathBuf {
    paths
        .data_root
        .join("setup-generations")
        .join(format!("{digest}.json"))
}

fn generation_authority(owner_uid: u32) -> DocumentAuthority {
    DocumentAuthority {
        owner_uid,
        mode: 0o600,
        limit: 32 * 1024 * 1024,
    }
}

fn read_generation(paths: &SetupPaths, owner_uid: u32, state: &Transition) -> Result<Vec<u8>> {
    let generation = read_atomic_document(
        &generation_path(paths, &state.plan_sha256),
        &generation_authority(owner_uid),
    )?
    .context("retained setup generation is absent")?;
    if generation.identity != state.retained_generation {
        bail!("retained setup generation does not match its transition");
    }
    Ok(generation.bytes)
}

pub(crate) fn resumable(paths: &SetupPaths, owner_uid: u32, digest: &str) -> Result<bool> {
    Ok(pending_generation(paths, owner_uid, digest)?.is_some())
}

pub(crate) fn pending_generation(
    paths: &SetupPaths,
    owner_uid: u32,
    digest: &str,
) -> Result<Option<Vec<u8>>> {
    let Some(document) = read_atomic_document(&state_path(paths), &authority(owner_uid))? else {
        return Ok(None);
    };
    let state = parse(&document.bytes)?;
    if matches!(
        state.phase,
        Phase::Restoring | Phase::Repairing | Phase::Uninstalling
    ) || (matches!(
        state.phase,
        Phase::RestoredInactive | Phase::UninstalledInactive
    ) && state.plan_sha256 == digest)
    {
        bail!("setup restoration cannot resume forward");
    }
    if matches!(
        state.phase,
        Phase::Accepted | Phase::RestoredInactive | Phase::UninstalledInactive
    ) {
        return Ok(None);
    }
    if state.plan_sha256 != digest {
        bail!("another setup transition requires recovery before replacement");
    }
    read_generation(paths, owner_uid, &state).map(Some)
}

/// Acceptance is published only after the complete product postcondition.
/// An absent record preserves the already-installed legacy no-op path.
pub(crate) fn accept(paths: &SetupPaths, owner_uid: u32, digest: &str) -> Result<bool> {
    advance(paths, owner_uid, digest, Phase::Accepted)
}

/// The exclusive setup owner publishes restoration intent before restoring
/// bytes, and RestoredInactive only after verifying the complete inactive
/// postcondition. Direction cannot reverse within one retained generation.
pub(crate) fn advance(
    paths: &SetupPaths,
    owner_uid: u32,
    digest: &str,
    phase: Phase,
) -> Result<bool> {
    let path = state_path(paths);
    let authority = authority(owner_uid);
    let Some(document) = read_atomic_document(&path, &authority)? else {
        if phase == Phase::Accepted {
            return Ok(false);
        }
        bail!("setup restoration requires a retained transition");
    };
    let mut state = parse(&document.bytes)?;
    read_generation(paths, owner_uid, &state)?;
    read_maintenance_generation(paths, owner_uid, &state)?;
    if state.plan_sha256 != digest {
        bail!("setup acceptance does not match the retained transition");
    }
    if !matches!(
        (state.phase, phase),
        (
            Phase::Pending | Phase::Accepted,
            Phase::Accepted | Phase::Restoring
        ) | (Phase::Restoring, Phase::Restoring | Phase::RestoredInactive)
            | (Phase::RestoredInactive, Phase::RestoredInactive)
            | (Phase::Repairing, Phase::Repairing | Phase::Accepted)
            | (
                Phase::Uninstalling,
                Phase::Uninstalling | Phase::UninstalledInactive
            )
            | (Phase::UninstalledInactive, Phase::UninstalledInactive)
    ) {
        bail!("setup transition cannot change to the requested phase");
    }
    if state.phase == phase {
        return write_atomic_document(&path, &document.bytes, &authority, Some(&document.identity));
    }
    state.phase = phase;
    if phase == Phase::Accepted {
        state.maintenance_generation = None;
    }
    write_atomic_document(
        &path,
        &serde_jcs::to_vec(&state)?,
        &authority,
        Some(&document.identity),
    )
}

fn maintenance_generation_path(paths: &SetupPaths, identity: &ArtifactIdentity) -> PathBuf {
    paths
        .data_root
        .join("setup-maintenance")
        .join(format!("{}.json", identity.sha256))
}

fn read_maintenance_generation(
    paths: &SetupPaths,
    owner_uid: u32,
    state: &Transition,
) -> Result<Option<Vec<u8>>> {
    let Some(identity) = &state.maintenance_generation else {
        if matches!(
            state.phase,
            Phase::Repairing | Phase::Uninstalling | Phase::UninstalledInactive
        ) {
            bail!("setup maintenance has no retained authority");
        }
        return Ok(None);
    };
    let document = read_atomic_document(
        &maintenance_generation_path(paths, identity),
        &generation_authority(owner_uid),
    )?
    .context("retained setup maintenance generation is absent")?;
    if &document.identity != identity {
        bail!("retained setup maintenance generation changed");
    }
    Ok(Some(document.bytes))
}

/// The native exclusive owner retains a separate immutable maintenance snapshot
/// before closing admission. The original setup generation is never recaptured.
pub(crate) fn begin_maintenance(
    paths: &SetupPaths,
    owner_uid: u32,
    digest: &str,
    phase: Phase,
    capture: impl FnOnce() -> Result<Vec<u8>>,
) -> Result<bool> {
    if !matches!(phase, Phase::Repairing | Phase::Uninstalling) {
        bail!("unsupported setup maintenance direction");
    }
    let path = state_path(paths);
    let authority = authority(owner_uid);
    let document = read_atomic_document(&path, &authority)?
        .context("setup maintenance requires retained setup")?;
    let mut state = parse(&document.bytes)?;
    read_generation(paths, owner_uid, &state)?;
    if state.plan_sha256 != digest {
        bail!("setup maintenance does not match the retained generation");
    }
    if state.phase == phase {
        read_maintenance_generation(paths, owner_uid, &state)?;
        return write_atomic_document(&path, &document.bytes, &authority, Some(&document.identity));
    }
    if state.phase != Phase::Accepted {
        bail!("finish the existing setup direction before maintenance");
    }
    let bytes = capture()?;
    let identity = ArtifactIdentity {
        length: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(&bytes)),
    };
    if identity.length == 0 || identity.length > 32 * 1024 * 1024 {
        bail!("setup maintenance retention exceeds its bound");
    }
    write_atomic_document(
        &maintenance_generation_path(paths, &identity),
        &bytes,
        &generation_authority(owner_uid),
        None,
    )?;
    state.phase = phase;
    state.maintenance_generation = Some(identity);
    write_atomic_document(
        &path,
        &serde_jcs::to_vec(&state)?,
        &authority,
        Some(&document.identity),
    )
}

/// A freshly rendered equivalent plan can verify an accepted installation
/// without accepting a different transaction or replacing its rollback input.
/// The caller owns the exclusive setup lease and has verified its postcondition.
pub(crate) fn settle_verified(paths: &SetupPaths, owner_uid: u32, digest: &str) -> Result<bool> {
    if let Some(transition) = retained_transition(paths, owner_uid)? {
        if transition.phase != Phase::Pending && transition.plan_sha256 != digest {
            require_accepted(paths, owner_uid)?;
            return Ok(false);
        }
    }
    accept(paths, owner_uid, digest)
}

fn admit_at(lock: &Path, state: &Path, owner_uid: u32) -> Result<InstallationLock> {
    let lease = InstallationLock::try_acquire_shared(lock)?
        .context("workload admission is closed during setup")?;
    require_accepted_at(state, owner_uid)?;
    Ok(lease)
}

pub(crate) fn require_accepted(paths: &SetupPaths, owner_uid: u32) -> Result<()> {
    require_accepted_at(&state_path(paths), owner_uid)
}

fn require_accepted_at(state: &Path, owner_uid: u32) -> Result<()> {
    if let Some(document) = read_atomic_document(state, &authority(owner_uid))? {
        if parse(&document.bytes)?.phase != Phase::Accepted {
            bail!("workload admission requires completion or recovery of setup");
        }
    }
    Ok(())
}

/// Keep the lease through broker and workload cleanup, not only policy lookup.
pub(crate) fn admit(mode: InstallMode) -> Result<InstallationLock> {
    let (paths, uid, lock) = match mode {
        InstallMode::Strong => {
            if !nix::unistd::Uid::effective().is_root() {
                bail!("strong admission lease requires the privileged dispatcher");
            }
            (
                SetupPaths::strong(),
                0,
                lock_path(DeploymentMode::Strong, None)?,
            )
        }
        InstallMode::UserOnly => {
            let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
                .context("workload admission native account is absent")?;
            let uid = user.uid.as_raw();
            (
                SetupPaths::user_only(&user.dir),
                uid,
                lock_path(DeploymentMode::UserOnly, Some(uid))?,
            )
        }
    };
    admit_at(&lock, &state_path(&paths), uid)
}

#[cfg(target_os = "linux")]
pub(crate) fn try_grant_admission() -> Result<Option<InstallationLock>> {
    if !nix::unistd::geteuid().is_root() {
        bail!("privilege admission requires its native coordinator");
    }
    try_admit_at(
        &lock_path(DeploymentMode::Strong, None)?,
        &SetupPaths::strong(),
        0,
    )
}

#[cfg(target_os = "linux")]
fn try_admit_at(
    lock: &Path,
    paths: &SetupPaths,
    owner_uid: u32,
) -> Result<Option<InstallationLock>> {
    let Some(lease) = InstallationLock::try_acquire_shared(lock)? else {
        return Ok(None);
    };
    let Some(document) = read_atomic_document(&state_path(paths), &authority(owner_uid))? else {
        return Ok(None);
    };
    let transition = parse(&document.bytes)?;
    if transition.phase != Phase::Accepted {
        return Ok(None);
    }
    read_generation(paths, owner_uid, &transition)?;
    Ok(Some(lease))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    #[cfg(target_os = "linux")]
    #[test]
    fn transition_root_rejects_existing_wrong_modes_without_changing_custody() {
        for mode in [0o700, 0o775] {
            let root = tempfile::tempdir().unwrap();
            let paths = SetupPaths {
                data_root: root.path().join("data"),
                bin_dir: root.path().join("bin"),
            };
            std::fs::create_dir(&paths.data_root).unwrap();
            std::fs::set_permissions(&paths.data_root, std::fs::Permissions::from_mode(mode))
                .unwrap();
            let before = std::fs::symlink_metadata(&paths.data_root).unwrap();
            assert!(begin(
                &paths,
                nix::unistd::geteuid().as_raw(),
                &"a".repeat(64),
                || { panic!("invalid existing root must reject before capture") }
            )
            .is_err());
            let after = std::fs::symlink_metadata(&paths.data_root).unwrap();
            assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
            assert_eq!(after.mode() & 0o7777, mode);
            assert_eq!(std::fs::read_dir(&paths.data_root).unwrap().count(), 0);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn transition_root_rejects_symlinks_and_failed_capture_keeps_absence() {
        let root = tempfile::tempdir().unwrap();
        let paths = SetupPaths {
            data_root: root.path().join("data"),
            bin_dir: root.path().join("bin"),
        };
        let owner = nix::unistd::geteuid().as_raw();
        let digest = "a".repeat(64);
        assert!(begin(&paths, owner, &digest, || anyhow::bail!("capture failed")).is_err());
        assert!(!paths.data_root.exists());
        let other = root.path().join("other");
        std::fs::create_dir(&other).unwrap();
        std::os::unix::fs::symlink(&other, &paths.data_root).unwrap();
        assert!(begin(&paths, owner, &digest, || {
            panic!("symlink root must reject before capture")
        })
        .is_err());
        assert_eq!(std::fs::read_link(&paths.data_root).unwrap(), other);
        assert_eq!(std::fs::read_dir(other).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn transition_root_does_not_adopt_a_directory_created_after_observation() {
        let root = tempfile::tempdir().unwrap();
        let paths = SetupPaths {
            data_root: root.path().join("data"),
            bin_dir: root.path().join("bin"),
        };
        assert!(begin(
            &paths,
            nix::unistd::geteuid().as_raw(),
            &"a".repeat(64),
            || {
                std::fs::create_dir(&paths.data_root)?;
                std::fs::set_permissions(&paths.data_root, std::fs::Permissions::from_mode(0o755))?;
                std::fs::write(paths.data_root.join("other-writer"), b"keep")?;
                Ok(b"retained initial installation".to_vec())
            }
        )
        .is_err());
        assert_eq!(
            std::fs::read(paths.data_root.join("other-writer")).unwrap(),
            b"keep"
        );
        assert_eq!(std::fs::read_dir(&paths.data_root).unwrap().count(), 1);
        assert!(!state_path(&paths).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn transition_root_mode_drift_preserves_pending_authority() {
        let root = tempfile::tempdir().unwrap();
        let paths = SetupPaths {
            data_root: root.path().join("data"),
            bin_dir: root.path().join("bin"),
        };
        let owner = nix::unistd::geteuid().as_raw();
        let digest = "a".repeat(64);
        begin(&paths, owner, &digest, || Ok(b"retained".to_vec())).unwrap();
        let state = std::fs::read(state_path(&paths)).unwrap();
        let generation = std::fs::read(generation_path(&paths, &digest)).unwrap();
        std::fs::set_permissions(&paths.data_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(begin(&paths, owner, &digest, || {
            panic!("pending generation must not be recaptured")
        })
        .is_err());
        assert_eq!(std::fs::read(state_path(&paths)).unwrap(), state);
        assert_eq!(
            std::fs::read(generation_path(&paths, &digest)).unwrap(),
            generation
        );
        assert_eq!(
            std::fs::symlink_metadata(&paths.data_root).unwrap().mode() & 0o7777,
            0o700
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn transition_retention_preserves_installation_root_mode_under_restrictive_umask() {
        for umask in ["0022", "0077"] {
            let root = tempfile::tempdir().unwrap();
            let executable = std::env::current_exe().unwrap();
            let output =
                dev_tools_command::run_bounded_command(&dev_tools_command::BoundedCommand {
                    executable: &executable,
                    arguments: &[
                        "--ignored".into(),
                        "--exact".into(),
                        "setup_transition::tests::transition_root_mode_child".into(),
                        "--test-threads=1".into(),
                        "--nocapture".into(),
                    ],
                    environment: &std::collections::BTreeMap::from([
                        ("DEV_AUTH_TEST_TRANSITION_ROOT".into(), root.path().into()),
                        ("DEV_AUTH_TEST_TRANSITION_UMASK".into(), umask.into()),
                    ]),
                    cwd: Some(Path::new("/")),
                    timeout: std::time::Duration::from_secs(15),
                    output_limit: 64 * 1024,
                })
                .unwrap();
            assert!(
                output.status.success(),
                "umask {umask}: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated umask child invoked only by transition_retention_preserves_installation_root_mode_under_restrictive_umask"]
    fn transition_root_mode_child() {
        let root = PathBuf::from(std::env::var_os("DEV_AUTH_TEST_TRANSITION_ROOT").unwrap());
        let mask =
            u32::from_str_radix(&std::env::var("DEV_AUTH_TEST_TRANSITION_UMASK").unwrap(), 8)
                .unwrap();
        nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(mask));
        let paths = SetupPaths {
            data_root: root.join("data"),
            bin_dir: root.join("bin"),
        };
        let owner = nix::unistd::geteuid().as_raw();
        let digest = "e".repeat(64);
        assert!(begin(&paths, owner, &digest, || {
            Ok(b"retained initial installation".to_vec())
        })
        .unwrap());
        let directory = std::fs::symlink_metadata(&paths.data_root).unwrap();
        assert_eq!(directory.mode() & 0o7777, 0o755);
        assert_eq!(directory.uid(), owner);
        for path in [state_path(&paths), generation_path(&paths, &digest)] {
            let metadata = std::fs::symlink_metadata(path).unwrap();
            assert_eq!(metadata.mode() & 0o7777, 0o600);
            assert_eq!(metadata.uid(), owner);
        }
        dev_tools_installation::ensure_owned_directory(&paths.data_root, owner, 0o755).unwrap();
        assert!(!begin(&paths, owner, &digest, || {
            panic!("unchanged retry must not capture a new generation")
        })
        .unwrap());
        let retried = std::fs::symlink_metadata(&paths.data_root).unwrap();
        assert_eq!(
            (directory.dev(), directory.ino()),
            (retried.dev(), retried.ino())
        );
        assert_eq!(retried.mode() & 0o7777, 0o755);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn grant_admission_requires_accepted_retention_and_a_short_shared_lease() {
        if crate::test_isolation::run_isolated(concat!(
            module_path!(),
            "::grant_admission_requires_accepted_retention_and_a_short_shared_lease"
        )) {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let paths = SetupPaths {
            data_root: root.path().join("data"),
            bin_dir: root.path().join("bin"),
        };
        let lock = root.path().join("setup.lock");
        let owner = nix::unistd::geteuid().as_raw();
        let digest = "d".repeat(64);
        assert!(try_admit_at(&lock, &paths, owner).unwrap().is_none());
        begin(&paths, owner, &digest, || {
            Ok(b"fixed retained grant setup".to_vec())
        })
        .unwrap();
        assert!(try_admit_at(&lock, &paths, owner).unwrap().is_none());
        accept(&paths, owner, &digest).unwrap();
        let generation = generation_path(&paths, &digest);
        let retained = std::fs::read(&generation).unwrap();
        std::fs::remove_file(&generation).unwrap();
        assert!(try_admit_at(&lock, &paths, owner).is_err());
        std::fs::write(&generation, retained).unwrap();
        // Recreating the retained document must restore its explicit private
        // mode, independent of the test runner's inherited umask.
        std::fs::set_permissions(&generation, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(try_admit_at(&lock, &paths, owner).is_err());
        std::fs::set_permissions(&generation, std::fs::Permissions::from_mode(0o600)).unwrap();
        let state_document = state_path(&paths);
        let hidden = root.path().join("withheld-transition");
        std::fs::rename(&state_document, &hidden).unwrap();
        assert!(try_admit_at(&lock, &paths, owner).unwrap().is_none());
        std::fs::rename(&hidden, &state_document).unwrap();
        let lease = try_admit_at(&lock, &paths, owner).unwrap().unwrap();
        assert!(InstallationLock::try_acquire(&lock).unwrap().is_none());
        drop(lease);
        let writer = InstallationLock::try_acquire(&lock).unwrap().unwrap();
        assert!(try_admit_at(&lock, &paths, owner).unwrap().is_none());
        drop(writer);
        advance(&paths, owner, &digest, Phase::Restoring).unwrap();
        assert!(try_admit_at(&lock, &paths, owner).unwrap().is_none());
        advance(&paths, owner, &digest, Phase::RestoredInactive).unwrap();
        assert!(try_admit_at(&lock, &paths, owner).unwrap().is_none());
    }

    #[test]
    #[ignore = "child fixture invoked only by admission_owner_process_death_releases_setup_exclusion"]
    fn admission_shared_lease_child() {
        let lock = PathBuf::from(std::env::var_os("DEV_AUTH_TEST_SETUP_LOCK").unwrap());
        let state = PathBuf::from(std::env::var_os("DEV_AUTH_TEST_SETUP_STATE").unwrap());
        let ready = PathBuf::from(std::env::var_os("DEV_AUTH_TEST_SETUP_READY").unwrap());
        let owner_uid = std::env::var("DEV_AUTH_TEST_SETUP_UID")
            .unwrap()
            .parse::<u32>()
            .unwrap();
        let _lease = admit_at(&lock, &state, owner_uid).unwrap();
        std::fs::write(ready, b"admitted").unwrap();
        loop {
            std::thread::park_timeout(std::time::Duration::from_secs(1));
        }
    }

    #[test]
    fn admission_owner_process_death_releases_setup_exclusion() {
        let temp = tempfile::tempdir().unwrap();
        let paths = SetupPaths {
            data_root: temp.path().join("data"),
            bin_dir: temp.path().join("bin"),
        };
        let lock = temp.path().join("setup.lock");
        let state = state_path(&paths);
        let ready = temp.path().join("admitted");
        let uid = nix::unistd::Uid::effective().as_raw();
        let prior_digest = "c".repeat(64);
        begin(&paths, uid, &prior_digest, || {
            Ok(b"accepted prior generation".to_vec())
        })
        .unwrap();
        accept(&paths, uid, &prior_digest).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "setup_transition::tests::admission_shared_lease_child",
                "--test-threads=1",
            ])
            .env("DEV_AUTH_TEST_SETUP_LOCK", &lock)
            .env("DEV_AUTH_TEST_SETUP_STATE", &state)
            .env("DEV_AUTH_TEST_SETUP_READY", &ready)
            .env("DEV_AUTH_TEST_SETUP_UID", uid.to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let admitted = loop {
            if ready.is_file() {
                break true;
            }
            if child.try_wait().unwrap().is_some() || std::time::Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let writer_blocked = if admitted {
            InstallationLock::try_acquire(&lock).map(|lease| lease.is_none())
        } else {
            Ok(false)
        };
        let _ = child.kill();
        child.wait().unwrap();
        assert!(admitted, "admission owner child did not retain its lease");
        assert!(writer_blocked.unwrap());
        let writer = InstallationLock::try_acquire(&lock).unwrap().unwrap();
        let digest = "d".repeat(64);
        begin(&paths, uid, &digest, || {
            Ok(b"retained after coordinator death".to_vec())
        })
        .unwrap();
        assert!(admit_at(&lock, &state, uid).is_err());
        drop(writer);
        assert!(admit_at(&lock, &state, uid).is_err());
        accept(&paths, uid, &digest).unwrap();
        assert!(admit_at(&lock, &state, uid).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "child fixture invoked only by coordinator_process_death_releases_setup_exclusion"]
    fn coordinator_shared_lease_child() {
        let lock = PathBuf::from(std::env::var_os("DEV_AUTH_TEST_SETUP_LOCK").unwrap());
        let paths = SetupPaths {
            data_root: PathBuf::from(std::env::var_os("DEV_AUTH_TEST_SETUP_DATA_ROOT").unwrap()),
            bin_dir: PathBuf::from(std::env::var_os("DEV_AUTH_TEST_SETUP_BIN_DIR").unwrap()),
        };
        let ready = PathBuf::from(std::env::var_os("DEV_AUTH_TEST_SETUP_READY").unwrap());
        let owner_uid = std::env::var("DEV_AUTH_TEST_SETUP_UID")
            .unwrap()
            .parse::<u32>()
            .unwrap();
        let _lease = try_admit_at(&lock, &paths, owner_uid).unwrap().unwrap();
        std::fs::write(ready, b"admitted").unwrap();
        loop {
            std::thread::park_timeout(std::time::Duration::from_secs(1));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn coordinator_process_death_releases_setup_exclusion() {
        let temp = tempfile::tempdir().unwrap();
        let paths = SetupPaths {
            data_root: temp.path().join("data"),
            bin_dir: temp.path().join("bin"),
        };
        let lock = temp.path().join("setup.lock");
        let ready = temp.path().join("admitted");
        let uid = nix::unistd::Uid::effective().as_raw();
        let prior_digest = "c".repeat(64);
        begin(&paths, uid, &prior_digest, || {
            Ok(b"accepted prior generation".to_vec())
        })
        .unwrap();
        accept(&paths, uid, &prior_digest).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "setup_transition::tests::coordinator_shared_lease_child",
                "--test-threads=1",
            ])
            .env("DEV_AUTH_TEST_SETUP_LOCK", &lock)
            .env("DEV_AUTH_TEST_SETUP_DATA_ROOT", &paths.data_root)
            .env("DEV_AUTH_TEST_SETUP_BIN_DIR", &paths.bin_dir)
            .env("DEV_AUTH_TEST_SETUP_READY", &ready)
            .env("DEV_AUTH_TEST_SETUP_UID", uid.to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let admitted = loop {
            if ready.is_file() {
                break true;
            }
            if child.try_wait().unwrap().is_some() || std::time::Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let writer_blocked = if admitted {
            InstallationLock::try_acquire(&lock).map(|lease| lease.is_none())
        } else {
            Ok(false)
        };
        let _ = child.kill();
        child.wait().unwrap();
        assert!(
            admitted,
            "coordinator child did not retain its admission lease"
        );
        assert!(writer_blocked.unwrap());
        let writer = InstallationLock::try_acquire(&lock).unwrap().unwrap();
        let digest = "d".repeat(64);
        begin(&paths, uid, &digest, || {
            Ok(b"retained after coordinator death".to_vec())
        })
        .unwrap();
        assert!(try_admit_at(&lock, &paths, uid).unwrap().is_none());
        drop(writer);
        assert!(try_admit_at(&lock, &paths, uid).unwrap().is_none());
        accept(&paths, uid, &digest).unwrap();
        assert!(try_admit_at(&lock, &paths, uid).unwrap().is_some());
    }

    #[test]
    fn phase_publication_is_digest_bound_idempotent_and_one_way() {
        for initially_accepted in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let paths = SetupPaths {
                data_root: temp.path().join("data"),
                bin_dir: temp.path().join("bin"),
            };
            let uid = nix::unistd::Uid::effective().as_raw();
            let digest = "a".repeat(64);
            assert!(advance(&paths, uid, &digest, Phase::Restoring).is_err());
            begin(&paths, uid, &digest, || Ok(b"retained generation".to_vec())).unwrap();
            if initially_accepted {
                accept(&paths, uid, &digest).unwrap();
            }
            let original = std::fs::read(state_path(&paths)).unwrap();
            assert!(advance(&paths, uid, &digest, Phase::RestoredInactive).is_err());
            assert!(advance(&paths, uid, &"b".repeat(64), Phase::Restoring).is_err());
            assert_eq!(std::fs::read(state_path(&paths)).unwrap(), original);
            assert!(advance(&paths, uid, &digest, Phase::Restoring).unwrap());
            assert!(!advance(&paths, uid, &digest, Phase::Restoring).unwrap());
            assert!(accept(&paths, uid, &digest).is_err());
            assert!(advance(&paths, uid, &digest, Phase::Pending).is_err());
            assert!(advance(&paths, uid, &digest, Phase::RestoredInactive).unwrap());
            assert!(!advance(&paths, uid, &digest, Phase::RestoredInactive).unwrap());
            assert!(advance(&paths, uid, &digest, Phase::Restoring).is_err());
            assert!(accept(&paths, uid, &digest).is_err());
            assert!(require_accepted(&paths, uid).is_err());
            assert_eq!(
                retained_transition(&paths, uid).unwrap().unwrap().bytes,
                b"retained generation"
            );
        }
    }

    #[test]
    fn preserving_maintenance_retains_original_bytes_and_requires_its_exact_snapshot() {
        for phase in [Phase::Repairing, Phase::Uninstalling] {
            let temp = tempfile::tempdir().unwrap();
            let paths = SetupPaths {
                data_root: temp.path().join("data"),
                bin_dir: temp.path().join("bin"),
            };
            let uid = nix::unistd::Uid::effective().as_raw();
            let digest = "a".repeat(64);
            begin(&paths, uid, &digest, || {
                Ok(b"original immutable setup".to_vec())
            })
            .unwrap();
            accept(&paths, uid, &digest).unwrap();
            assert!(
                begin_maintenance(&paths, uid, &"b".repeat(64), phase, || panic!(
                    "wrong digest must not capture"
                ))
                .is_err()
            );
            assert!(begin_maintenance(&paths, uid, &digest, phase, || Ok(
                b"exact maintenance snapshot".to_vec()
            ))
            .unwrap());
            assert!(!begin_maintenance(&paths, uid, &digest, phase, || panic!(
                "retry must never recapture"
            ))
            .unwrap());
            let retained = retained_transition(&paths, uid).unwrap().unwrap();
            assert_eq!(retained.bytes, b"original immutable setup");
            assert_eq!(
                retained.maintenance_bytes.unwrap(),
                b"exact maintenance snapshot"
            );
            assert!(require_accepted(&paths, uid).is_err());
            assert!(begin(&paths, uid, &digest, || panic!(
                "maintenance cannot become ordinary setup"
            ))
            .is_err());
            assert!(advance(&paths, uid, &digest, Phase::Restoring).is_err());
            if phase == Phase::Repairing {
                assert!(advance(&paths, uid, &digest, Phase::UninstalledInactive).is_err());
                assert!(accept(&paths, uid, &digest).unwrap());
                assert!(retained_transition(&paths, uid)
                    .unwrap()
                    .unwrap()
                    .maintenance_bytes
                    .is_none());
            } else {
                assert!(accept(&paths, uid, &digest).is_err());
                assert!(advance(&paths, uid, &digest, Phase::UninstalledInactive).unwrap());
                assert!(!advance(&paths, uid, &digest, Phase::UninstalledInactive).unwrap());
                assert!(begin(&paths, uid, &digest, || panic!(
                    "uninstalled generation cannot replay"
                ))
                .is_err());
                assert!(begin(&paths, uid, &"b".repeat(64), || Ok(
                    b"new approved setup".to_vec()
                ))
                .unwrap());
            }
        }
    }

    #[test]
    fn maintenance_snapshot_drift_prevents_terminal_publication() {
        let temp = tempfile::tempdir().unwrap();
        let paths = SetupPaths {
            data_root: temp.path().join("data"),
            bin_dir: temp.path().join("bin"),
        };
        let uid = nix::unistd::Uid::effective().as_raw();
        let digest = "c".repeat(64);
        begin(&paths, uid, &digest, || Ok(b"original setup".to_vec())).unwrap();
        accept(&paths, uid, &digest).unwrap();
        begin_maintenance(&paths, uid, &digest, Phase::Uninstalling, || {
            Ok(b"retained maintenance".to_vec())
        })
        .unwrap();
        let document = read_atomic_document(&state_path(&paths), &authority(uid))
            .unwrap()
            .unwrap();
        let state = parse(&document.bytes).unwrap();
        std::fs::write(
            maintenance_generation_path(&paths, state.maintenance_generation.as_ref().unwrap()),
            b"foreign replacement",
        )
        .unwrap();
        assert!(retained_transition(&paths, uid).is_err());
        assert!(advance(&paths, uid, &digest, Phase::UninstalledInactive).is_err());
        assert_eq!(std::fs::read(state_path(&paths)).unwrap(), document.bytes);
        assert_eq!(
            std::fs::read(generation_path(&paths, &digest)).unwrap(),
            b"original setup"
        );
    }

    #[test]
    fn restoration_state_keeps_forward_recovery_and_admission_closed() {
        let temp = tempfile::tempdir().unwrap();
        let paths = SetupPaths {
            data_root: temp.path().join("data"),
            bin_dir: temp.path().join("bin"),
        };
        let uid = nix::unistd::Uid::effective().as_raw();
        let digest = "e".repeat(64);
        let replacement = "f".repeat(64);
        begin(&paths, uid, &digest, || Ok(b"prior generation".to_vec())).unwrap();
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(state_path(&paths)).unwrap()).unwrap();
        for phase in ["restoring", "restored_inactive"] {
            document["phase"] = phase.into();
            std::fs::write(state_path(&paths), serde_json::to_vec(&document).unwrap()).unwrap();
            let retained = retained_transition(&paths, uid).unwrap().unwrap();
            assert_eq!(retained.bytes, b"prior generation");
            assert!(require_accepted(&paths, uid).is_err());
            assert!(accept(&paths, uid, &digest).is_err());
            assert!(settle_verified(&paths, uid, &replacement).is_err());
            assert!(pending_generation(&paths, uid, &digest).is_err());
            assert!(begin(&paths, uid, &digest, || panic!(
                "must not replay restored plan"
            ))
            .is_err());
            if phase == "restoring" {
                assert!(pending_generation(&paths, uid, &replacement).is_err());
                assert!(begin(&paths, uid, &replacement, || panic!(
                    "must not abandon restoration"
                ))
                .is_err());
            } else {
                assert!(pending_generation(&paths, uid, &replacement)
                    .unwrap()
                    .is_none());
                assert!(begin(
                    &paths,
                    uid,
                    &replacement,
                    || Ok(b"next generation".to_vec())
                )
                .unwrap());
                assert_eq!(
                    std::fs::read(generation_path(&paths, &digest)).unwrap(),
                    b"prior generation"
                );
            }
        }
    }

    #[test]
    fn missing_or_changed_retention_blocks_resume_and_acceptance() {
        let temp = tempfile::tempdir().unwrap();
        let paths = SetupPaths {
            data_root: temp.path().join("data"),
            bin_dir: temp.path().join("bin"),
        };
        let uid = nix::unistd::Uid::effective().as_raw();
        let digest = "c".repeat(64);
        begin(&paths, uid, &digest, || Ok(b"original generation".to_vec())).unwrap();
        let generation = generation_path(&paths, &digest);
        std::fs::write(&generation, b"replacement generation").unwrap();
        assert!(begin(&paths, uid, &digest, || panic!(
            "must not replace missing retention"
        ))
        .is_err());
        assert!(accept(&paths, uid, &digest).is_err());
        assert!(require_accepted(&paths, uid).is_err());
        std::fs::remove_file(&generation).unwrap();
        assert!(accept(&paths, uid, &digest).is_err());
    }

    #[test]
    fn orphan_retention_is_not_replaced_with_later_state() {
        let temp = tempfile::tempdir().unwrap();
        let paths = SetupPaths {
            data_root: temp.path().join("data"),
            bin_dir: temp.path().join("bin"),
        };
        let uid = nix::unistd::Uid::effective().as_raw();
        let digest = "d".repeat(64);
        begin(&paths, uid, &digest, || Ok(b"original generation".to_vec())).unwrap();
        std::fs::remove_file(state_path(&paths)).unwrap();
        assert!(begin(&paths, uid, &digest, || Ok(b"later generation".to_vec())).is_err());
        assert!(!state_path(&paths).exists());
        assert_eq!(
            std::fs::read(generation_path(&paths, &digest)).unwrap(),
            b"original generation"
        );
        assert!(begin(&paths, uid, &digest, || Ok(b"original generation".to_vec())).unwrap());
    }

    #[test]
    fn pending_survives_writer_exit_and_only_matching_acceptance_reopens() {
        if crate::test_isolation::run_isolated(concat!(
            module_path!(),
            "::pending_survives_writer_exit_and_only_matching_acceptance_reopens"
        )) {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let paths = SetupPaths {
            data_root: temp.path().join("data"),
            bin_dir: temp.path().join("bin"),
        };
        let lock = temp.path().join("admission.lock");
        let uid = nix::unistd::Uid::effective().as_raw();
        let digest = "a".repeat(64);
        let first = admit_at(&lock, &state_path(&paths), uid).unwrap();
        let second = admit_at(&lock, &state_path(&paths), uid).unwrap();
        assert!(InstallationLock::try_acquire(&lock).unwrap().is_none());
        drop((first, second));
        let writer = InstallationLock::try_acquire(&lock).unwrap().unwrap();
        assert!(admit_at(&lock, &state_path(&paths), uid).is_err());
        assert!(begin(&paths, uid, &digest, || Ok(
            b"retained fixture generation".to_vec()
        ))
        .unwrap());
        drop(writer);
        assert!(admit_at(&lock, &state_path(&paths), uid).is_err());
        let _writer = InstallationLock::try_acquire(&lock).unwrap().unwrap();
        assert!(!begin(&paths, uid, &digest, || panic!(
            "resume must not recapture changed state"
        ))
        .unwrap());
        assert!(begin(&paths, uid, &"b".repeat(64), || panic!(
            "another plan must not capture state"
        ))
        .is_err());
        assert!(accept(&paths, uid, &"b".repeat(64)).is_err());
        assert!(accept(&paths, uid, &digest).unwrap());
        assert!(!accept(&paths, uid, &digest).unwrap());
        let accepted = std::fs::read(state_path(&paths)).unwrap();
        assert!(accept(&paths, uid, &"b".repeat(64)).is_err());
        assert_eq!(std::fs::read(state_path(&paths)).unwrap(), accepted);
        assert!(!settle_verified(&paths, uid, &"b".repeat(64)).unwrap());
        assert_eq!(std::fs::read(state_path(&paths)).unwrap(), accepted);
        drop(_writer);
        assert!(admit_at(&lock, &state_path(&paths), uid).is_ok());
    }
}
