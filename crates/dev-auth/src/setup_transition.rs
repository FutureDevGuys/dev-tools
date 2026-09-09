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
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Transition {
    schema: String,
    plan_sha256: String,
    phase: Phase,
    retained_generation: ArtifactIdentity,
}

pub(crate) struct RetainedTransition {
    pub plan_sha256: String,
    pub bytes: Vec<u8>,
    pub phase: Phase,
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
    Ok(Some(RetainedTransition {
        plan_sha256: state.plan_sha256,
        bytes,
        phase: state.phase,
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
    Ok(state)
}

/// Called only while the full setup writer owns the native exclusive lock.
pub(crate) fn begin(
    paths: &SetupPaths,
    owner_uid: u32,
    digest: &str,
    capture: impl FnOnce() -> Result<Vec<u8>>,
) -> Result<bool> {
    let path = state_path(paths);
    let authority = authority(owner_uid);
    let current = read_atomic_document(&path, &authority)?;
    if let Some(document) = &current {
        let state = parse(&document.bytes)?;
        if state.phase == Phase::Restoring
            || (state.phase == Phase::RestoredInactive && state.plan_sha256 == digest)
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
    };
    let bytes = serde_jcs::to_vec(&state)?;
    parse(&bytes)?;
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
    if state.phase == Phase::Restoring
        || (state.phase == Phase::RestoredInactive && state.plan_sha256 == digest)
    {
        bail!("setup restoration cannot resume forward");
    }
    if matches!(state.phase, Phase::Accepted | Phase::RestoredInactive) {
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
    ) {
        bail!("setup transition cannot change to the requested phase");
    }
    if state.phase == phase {
        return write_atomic_document(&path, &document.bytes, &authority, Some(&document.identity));
    }
    state.phase = phase;
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

#[cfg(test)]
mod tests {
    use super::*;

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
