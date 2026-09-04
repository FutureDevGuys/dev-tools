use anyhow::{bail, Context, Result};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::socket::{getsockopt, sockopt};
use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, PublicKey};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::sync::RwLock;

use crate::broker_protocol::LocalSessionClaim;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const PROC_CGROUP_LIMIT: u64 = 64 * 1024;
const SESSION_LIMIT: usize = 1024;
pub const WORKLOAD_CGROUP_ROOT: &str = "/sys/fs/cgroup/system.slice";

#[derive(Debug)]
pub struct LinuxPeerEvidence {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub unified_cgroup: PathBuf,
    peer_pidfd: OwnedFd,
}

impl LinuxPeerEvidence {
    pub fn peer_pidfd(&self) -> impl AsFd + '_ {
        self.peer_pidfd.as_fd()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionRegistration {
    pub session_id: String,
    /// Native account whose policy and resources authorize the workload.
    pub owner_uid: u32,
    /// Kernel UID that must originate broker requests for this workload.
    pub execution_uid: u32,
    /// Kernel primary GID that must originate broker requests for this workload.
    pub execution_gid: u32,
    pub workload: String,
    pub profile: String,
    pub authority: SessionAuthorityGrant,
    pub cgroup: PathBuf,
    pub expires_at_unix: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PendingSessionRegistration {
    pub session_id: String,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub execution_pid: u32,
    pub workload: String,
    pub profile: String,
    pub authority: SessionAuthorityGrant,
    pub cgroup: PathBuf,
    pub expires_at_unix: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionAuthorityGrant {
    pub github: Option<SessionGitHubGrant>,
    pub signing: Option<SessionOperationKeyGrant>,
    pub release_signing: Option<SessionReleaseSigningGrant>,
    pub ssh: Vec<SessionOperationKeyGrant>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionReleaseSigningGrant {
    pub credential_slot: String,
    pub private_key_ref: String,
    pub public_key: String,
    pub products: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionOperationKeyGrant {
    pub credential_slot: String,
    pub private_key_ref: String,
    pub public_key: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionGitHubGrant {
    pub credential_slot: String,
    pub app_id: u64,
    pub repository_selection: crate::RepositorySelection,
    pub private_key_ref: String,
    pub owners: Vec<String>,
    pub repositories: Vec<String>,
    pub permissions: BTreeMap<String, crate::policy_v2::Permission>,
    pub installation_ids: Vec<u64>,
}

struct RegisteredSession {
    registration: SessionRegistration,
    supervisor_pidfd: OwnedFd,
    cgroup_handle: File,
    cgroup_device: u64,
    cgroup_inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLinuxSession {
    pub session_id: String,
    pub owner_uid: u32,
    pub execution_uid: u32,
    pub workload: String,
    pub profile: String,
    pub authority: SessionAuthorityGrant,
    pub cgroup: PathBuf,
    pub expires_at_unix: i64,
}

#[derive(Default)]
pub struct LinuxSessionRegistry {
    sessions: RwLock<BTreeMap<String, RegisteredSession>>,
    pending: RwLock<BTreeMap<String, PendingSessionRegistration>>,
}

pub fn session_authority_from_resolved(
    profile: &crate::policy_v2::ResolvedAuthorityProfile,
) -> SessionAuthorityGrant {
    SessionAuthorityGrant {
        github: profile.github.as_ref().map(|github| SessionGitHubGrant {
            credential_slot: profile.credential_slot.clone(),
            app_id: github.app_id,
            repository_selection: github.repository_selection,
            private_key_ref: github.private_key_ref.clone(),
            owners: github.owners.iter().cloned().collect(),
            repositories: github.repositories.iter().cloned().collect(),
            permissions: github.permissions.clone(),
            installation_ids: github.installation_ids.iter().copied().collect(),
        }),
        signing: profile
            .signing_key
            .as_ref()
            .map(|key| operation_key_grant(&profile.credential_slot, key)),
        release_signing: profile.release_signing_key.as_ref().map(|key| {
            SessionReleaseSigningGrant {
                credential_slot: profile.credential_slot.clone(),
                private_key_ref: key.private_key_ref.clone(),
                public_key: key.public_key.clone(),
                products: profile.release_signing_products.iter().cloned().collect(),
            }
        }),
        ssh: profile
            .ssh_keys
            .iter()
            .map(|key| operation_key_grant(&profile.credential_slot, key))
            .collect(),
    }
}

fn operation_key_grant(
    credential_slot: &str,
    key: &crate::policy_v2::OperationKeyConfig,
) -> SessionOperationKeyGrant {
    SessionOperationKeyGrant {
        credential_slot: credential_slot.to_owned(),
        private_key_ref: key.private_key_ref.clone(),
        public_key: key.public_key.clone(),
        fingerprint: key.fingerprint.clone(),
    }
}

impl LinuxSessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_root_owned(
        &self,
        registration: SessionRegistration,
        supervisor_pidfd: OwnedFd,
    ) -> Result<()> {
        self.register_with_owner(registration, 0, supervisor_pidfd)
    }

    pub fn prepare_root_owned(&self, registration: PendingSessionRegistration) -> Result<()> {
        validate_pending_session_registration(&registration)?;
        let sessions = self
            .sessions
            .read()
            .map_err(|_| anyhow::anyhow!("session registry lock is poisoned"))?;
        if sessions.contains_key(&registration.session_id) {
            bail!("session identifier is already active");
        }
        let mut pending = self
            .pending
            .write()
            .map_err(|_| anyhow::anyhow!("pending session registry lock is poisoned"))?;
        if pending.len() >= SESSION_LIMIT {
            bail!("pending session registry is full");
        }
        if pending.contains_key(&registration.session_id) {
            bail!("session identifier is already pending");
        }
        pending.insert(registration.session_id.clone(), registration);
        drop(pending);
        drop(sessions);
        Ok(())
    }

    pub fn activate_pending(
        &self,
        peer: LinuxPeerEvidence,
        session_id: &str,
    ) -> Result<VerifiedLinuxSession> {
        let mut pending = self
            .pending
            .write()
            .map_err(|_| anyhow::anyhow!("pending session registry lock is poisoned"))?;
        let prepared = pending
            .remove(session_id)
            .context("session activation references no pending admission")?;
        drop(pending);
        if prepared.expires_at_unix <= time::OffsetDateTime::now_utc().unix_timestamp() {
            bail!("pending session admission has expired");
        }
        validate_pending_activation(&prepared, &peer)?;
        let registration = SessionRegistration {
            session_id: prepared.session_id,
            owner_uid: prepared.owner_uid,
            execution_uid: peer.uid,
            execution_gid: peer.gid,
            workload: prepared.workload,
            profile: prepared.profile,
            authority: prepared.authority,
            cgroup: prepared.cgroup,
            expires_at_unix: lease_expiry(),
        };
        self.register_with_owner(registration.clone(), 0, peer.peer_pidfd)?;
        Ok(VerifiedLinuxSession {
            session_id: registration.session_id,
            owner_uid: registration.owner_uid,
            execution_uid: registration.execution_uid,
            workload: registration.workload,
            profile: registration.profile,
            authority: registration.authority,
            cgroup: registration.cgroup,
            expires_at_unix: registration.expires_at_unix,
        })
    }

    fn register_with_owner(
        &self,
        registration: SessionRegistration,
        required_owner_uid: u32,
        supervisor_pidfd: OwnedFd,
    ) -> Result<()> {
        validate_session_registration(&registration)?;
        if !pidfd_process_is_alive(&supervisor_pidfd)? {
            bail!("session supervisor exited before registration");
        }
        let metadata = fs::symlink_metadata(&registration.cgroup).with_context(|| {
            format!(
                "inspect registered cgroup {}",
                registration.cgroup.display()
            )
        })?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != required_owner_uid
            || metadata.permissions().mode() & 0o022 != 0
        {
            bail!("registered workload cgroup is not immutable supervisor authority");
        }
        let cgroup_procs = registration.cgroup.join("cgroup.procs");
        let procs_metadata =
            fs::symlink_metadata(&cgroup_procs).context("inspect registered cgroup.procs")?;
        if !procs_metadata.file_type().is_file()
            || procs_metadata.file_type().is_symlink()
            || procs_metadata.uid() != required_owner_uid
            || procs_metadata.permissions().mode() & 0o022 != 0
        {
            bail!("registered cgroup membership is writable outside the supervisor");
        }
        let cgroup_handle = File::open(&registration.cgroup).context("hold registered cgroup")?;
        let held_metadata = cgroup_handle
            .metadata()
            .context("inspect held registered cgroup")?;
        if held_metadata.dev() != metadata.dev() || held_metadata.ino() != metadata.ino() {
            bail!("registered cgroup changed while it was being held");
        }

        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| anyhow::anyhow!("session registry lock is poisoned"))?;
        if sessions.len() >= SESSION_LIMIT {
            bail!("session registry is full");
        }
        if sessions.values().any(|session| {
            session.registration.cgroup == registration.cgroup
                || cgroup_contains(&session.registration.cgroup, &registration.cgroup)
                || cgroup_contains(&registration.cgroup, &session.registration.cgroup)
        }) {
            bail!("registered workload cgroup overlaps an active session");
        }
        if sessions.contains_key(&registration.session_id) {
            bail!("session identifier is already active");
        }
        sessions.insert(
            registration.session_id.clone(),
            RegisteredSession {
                registration,
                supervisor_pidfd,
                cgroup_handle,
                cgroup_device: held_metadata.dev(),
                cgroup_inode: held_metadata.ino(),
            },
        );
        Ok(())
    }

    pub fn revoke(&self, session_id: &str) -> Result<bool> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| anyhow::anyhow!("session registry lock is poisoned"))?;
        let active = sessions.remove(session_id).is_some();
        drop(sessions);
        let mut pending = self
            .pending
            .write()
            .map_err(|_| anyhow::anyhow!("pending session registry lock is poisoned"))?;
        Ok(active | pending.remove(session_id).is_some())
    }

    pub fn prune_stale(&self) -> Result<Vec<String>> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut pending = self
            .pending
            .write()
            .map_err(|_| anyhow::anyhow!("pending session registry lock is poisoned"))?;
        pending.retain(|_, session| session.expires_at_unix > now);
        drop(pending);
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| anyhow::anyhow!("session registry lock is poisoned"))?;
        let stale = sessions
            .iter()
            .filter(|(_, session)| {
                session.registration.expires_at_unix <= now
                    || !pidfd_process_is_alive(&session.supervisor_pidfd).unwrap_or(false)
            })
            .map(|(session_id, _)| session_id.clone())
            .collect::<Vec<_>>();
        for session_id in &stale {
            sessions.remove(session_id);
        }
        Ok(stale)
    }

    pub fn renew(&self, session_id: &str, expires_at_unix: i64) -> Result<()> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| anyhow::anyhow!("session registry lock is poisoned"))?;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        if expires_at_unix <= now || expires_at_unix > now + 15 * 60 {
            bail!("session renewal is outside the 15-minute lease window");
        }
        let session = sessions
            .get_mut(session_id)
            .context("session renewal references an inactive session")?;
        if session.registration.expires_at_unix <= now {
            bail!("session renewal cannot revive an expired lease");
        }
        if !pidfd_process_is_alive(&session.supervisor_pidfd)? {
            bail!("session supervisor exited before renewal");
        }
        let live_metadata = fs::symlink_metadata(&session.registration.cgroup)
            .context("revalidate registered cgroup path before renewal")?;
        let held_metadata = session
            .cgroup_handle
            .metadata()
            .context("revalidate held cgroup before renewal")?;
        if live_metadata.dev() != session.cgroup_device
            || live_metadata.ino() != session.cgroup_inode
            || held_metadata.dev() != session.cgroup_device
            || held_metadata.ino() != session.cgroup_inode
        {
            bail!("registered cgroup identity changed before renewal");
        }
        session.registration.expires_at_unix = expires_at_unix;
        Ok(())
    }

    pub fn verify_peer(&self, peer: &LinuxPeerEvidence) -> Result<VerifiedLinuxSession> {
        self.probe_peer(peer)?
            .context("peer is not in a registered workload session")
    }

    pub fn probe_peer(&self, peer: &LinuxPeerEvidence) -> Result<Option<VerifiedLinuxSession>> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| anyhow::anyhow!("session registry lock is poisoned"))?;
        let mut matching = sessions.values().filter(|session| {
            session.registration.execution_uid == peer.uid
                && session.registration.execution_gid == peer.gid
                && cgroup_contains(&session.registration.cgroup, &peer.unified_cgroup)
        });
        let Some(session) = matching.next() else {
            return Ok(None);
        };
        if matching.next().is_some() {
            bail!("peer matches more than one workload session");
        }
        if session.registration.expires_at_unix <= time::OffsetDateTime::now_utc().unix_timestamp()
        {
            bail!("workload session lease has expired");
        }
        if !pidfd_process_is_alive(&session.supervisor_pidfd)? {
            bail!("workload session supervisor is no longer alive");
        }
        let live_metadata = fs::symlink_metadata(&session.registration.cgroup)
            .context("revalidate registered cgroup path")?;
        let held_metadata = session
            .cgroup_handle
            .metadata()
            .context("revalidate held registered cgroup")?;
        if live_metadata.dev() != session.cgroup_device
            || live_metadata.ino() != session.cgroup_inode
            || held_metadata.dev() != session.cgroup_device
            || held_metadata.ino() != session.cgroup_inode
        {
            bail!("registered cgroup identity changed");
        }
        Ok(Some(VerifiedLinuxSession {
            session_id: session.registration.session_id.clone(),
            owner_uid: session.registration.owner_uid,
            execution_uid: session.registration.execution_uid,
            workload: session.registration.workload.clone(),
            profile: session.registration.profile.clone(),
            authority: session.registration.authority.clone(),
            cgroup: session.registration.cgroup.clone(),
            expires_at_unix: session.registration.expires_at_unix,
        }))
    }
}

fn validate_pending_activation(
    prepared: &PendingSessionRegistration,
    peer: &LinuxPeerEvidence,
) -> Result<()> {
    if peer.uid != prepared.owner_uid {
        bail!("strong workload execution identity does not match its native owner");
    }
    if peer.gid != prepared.owner_gid {
        bail!("strong workload primary group does not match its native owner");
    }
    if peer.pid != prepared.execution_pid {
        bail!("strong workload activation does not match the retained supervisor process");
    }
    if peer.unified_cgroup != prepared.cgroup {
        bail!("strong workload peer is outside the prepared cgroup");
    }
    Ok(())
}

fn lease_expiry() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp() + 15 * 60
}

fn pidfd_process_is_alive(pidfd: &OwnedFd) -> Result<bool> {
    let mut descriptors = [PollFd::new(pidfd.as_fd(), PollFlags::POLLIN)];
    let ready =
        poll(&mut descriptors, PollTimeout::ZERO).context("poll session supervisor pidfd")?;
    Ok(ready == 0)
}

pub fn peer_evidence(stream: &UnixStream) -> Result<LinuxPeerEvidence> {
    let credentials =
        getsockopt(stream, sockopt::PeerCredentials).context("read broker peer credentials")?;
    let peer_pidfd =
        getsockopt(stream, sockopt::PeerPidfd).context("read race-free broker peer pidfd")?;
    let pid = u32::try_from(credentials.pid()).context("broker peer PID is invalid")?;
    let unified_cgroup = read_unified_cgroup(pid)?;
    Ok(LinuxPeerEvidence {
        pid,
        uid: credentials.uid(),
        gid: credentials.gid(),
        unified_cgroup,
        peer_pidfd,
    })
}

pub fn local_session_claim() -> Result<LocalSessionClaim> {
    let cgroup = read_unified_cgroup(std::process::id())?;
    if workload_session_id(&cgroup).is_some() {
        Ok(LocalSessionClaim::Present {
            marker: format!("strong:{}", cgroup.display()),
        })
    } else {
        Ok(LocalSessionClaim::Absent)
    }
}

pub fn current_workload_cgroup(session_id: &str) -> Result<PathBuf> {
    validate_current_workload_session(session_id)?;
    let cgroup = read_unified_cgroup(std::process::id())?;
    let observed = workload_session_id(&cgroup)
        .context("supervisor is outside a product-owned transient workload service")?;
    if observed != session_id {
        bail!("supervisor transient service does not match its session identifier");
    }
    Ok(cgroup)
}

fn validate_current_workload_session(session_id: &str) -> Result<()> {
    validate_session_identifier(session_id)
}

fn workload_session_id(cgroup: &Path) -> Option<&str> {
    if cgroup.parent()? != Path::new(WORKLOAD_CGROUP_ROOT) {
        return None;
    }
    cgroup
        .file_name()?
        .to_str()?
        .strip_prefix("dev-auth-workload-")?
        .strip_suffix(".service")
        .filter(|session_id| {
            session_id.len() == 32 && session_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

fn read_unified_cgroup(pid: u32) -> Result<PathBuf> {
    let path = PathBuf::from(format!("/proc/{pid}/cgroup"));
    let metadata = fs::symlink_metadata(&path).context("inspect broker peer cgroup record")?;
    if !metadata.file_type().is_file() || metadata.len() > PROC_CGROUP_LIMIT {
        bail!("broker peer cgroup record is unsafe");
    }
    let mut input = String::with_capacity(metadata.len() as usize);
    File::open(&path)
        .context("open broker peer cgroup record")?
        .take(PROC_CGROUP_LIMIT + 1)
        .read_to_string(&mut input)
        .context("read broker peer cgroup record")?;
    let mut unified = input.lines().filter_map(|line| line.strip_prefix("0::"));
    let value = unified
        .next()
        .context("broker peer has no unified cgroup membership")?;
    if unified.next().is_some() {
        bail!("broker peer has ambiguous unified cgroup membership");
    }
    let relative = validate_relative_cgroup(Path::new(value))?;
    Ok(Path::new(CGROUP_ROOT).join(relative))
}

fn validate_session_registration(registration: &SessionRegistration) -> Result<()> {
    if registration.session_id.len() != 32
        || !registration
            .session_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("session identifier must contain exactly 32 hexadecimal characters");
    }
    validate_public_identifier(&registration.workload, "workload")?;
    validate_public_identifier(&registration.profile, "authority profile")?;
    validate_session_authority(&registration.authority)?;
    if registration.owner_uid == 0
        || registration.execution_uid == 0
        || registration.execution_gid == 0
    {
        bail!("session native and execution identities must be non-root");
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if registration.expires_at_unix <= now || registration.expires_at_unix > now + 24 * 60 * 60 {
        bail!("session lease expiry is outside the admitted range");
    }
    if workload_session_id(&registration.cgroup) != Some(registration.session_id.as_str()) {
        bail!("registered cgroup does not match its transient workload session");
    }
    let relative = registration
        .cgroup
        .strip_prefix(CGROUP_ROOT)
        .context("registered cgroup is outside the unified cgroup root")?;
    validate_relative_cgroup(relative)?;
    Ok(())
}

fn validate_pending_session_registration(registration: &PendingSessionRegistration) -> Result<()> {
    validate_session_identifier(&registration.session_id)?;
    validate_public_identifier(&registration.workload, "workload")?;
    validate_public_identifier(&registration.profile, "authority profile")?;
    validate_session_authority(&registration.authority)?;
    if registration.owner_uid == 0 || registration.owner_gid == 0 || registration.execution_pid == 0
    {
        bail!("pending session owner must be non-root");
    }
    let expected = PathBuf::from(format!(
        "{WORKLOAD_CGROUP_ROOT}/dev-auth-workload-{}.service",
        registration.session_id
    ));
    if registration.cgroup != expected {
        bail!("pending session cgroup is not the exact product transient unit");
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if registration.expires_at_unix <= now || registration.expires_at_unix > now + 60 {
        bail!("pending admission must expire within 60 seconds");
    }
    Ok(())
}

fn validate_session_identifier(session_id: &str) -> Result<()> {
    if session_id.len() != 32 || !session_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("session identifier must contain exactly 32 hexadecimal characters");
    }
    Ok(())
}

fn validate_session_authority(authority: &SessionAuthorityGrant) -> Result<()> {
    if let Some(github) = &authority.github {
        validate_public_identifier(&github.credential_slot, "credential slot")?;
        if github.app_id == 0 {
            bail!("session GitHub App ID is invalid");
        }
        crate::validate_op_reference(&github.private_key_ref)?;
        if github.owners.is_empty() {
            bail!("session GitHub authority has no owner");
        }
        let mut owners = BTreeMap::new();
        for owner in &github.owners {
            if !crate::is_github_component(owner)
                || owners.insert(owner.to_ascii_lowercase(), ()).is_some()
            {
                bail!("session GitHub owner authority is invalid");
            }
        }
        let mut repositories = BTreeMap::new();
        for repository in &github.repositories {
            if !crate::is_github_component(repository)
                || repositories
                    .insert(repository.to_ascii_lowercase(), ())
                    .is_some()
            {
                bail!("session GitHub repository authority is invalid");
            }
        }
        if github.permissions.is_empty()
            || github.permissions.keys().any(|permission| {
                permission.is_empty()
                    || !permission
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            })
        {
            bail!("session GitHub permission authority is invalid");
        }
        if github.installation_ids.contains(&0)
            || github
                .installation_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            bail!("session GitHub installation authority is invalid");
        }
    }
    if let Some(signing) = &authority.signing {
        validate_operation_key_grant(signing)?;
    }
    let mut ssh_fingerprints = BTreeMap::new();
    for key in &authority.ssh {
        validate_operation_key_grant(key)?;
        if ssh_fingerprints
            .insert(key.fingerprint.clone(), ())
            .is_some()
        {
            bail!("session SSH authority contains a duplicate identity");
        }
    }
    Ok(())
}

fn validate_operation_key_grant(key: &SessionOperationKeyGrant) -> Result<()> {
    validate_public_identifier(&key.credential_slot, "credential slot")?;
    crate::validate_op_reference(&key.private_key_ref)?;
    let public_key = PublicKey::from_openssh(&key.public_key)
        .context("session operation public key is not valid OpenSSH data")?;
    if public_key.fingerprint(HashAlg::Sha256).to_string() != key.fingerprint {
        bail!("session operation key fingerprint does not match its public key");
    }
    Ok(())
}

fn validate_relative_cgroup(path: &Path) -> Result<PathBuf> {
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) if !value.is_empty() => output.push(value),
            _ => bail!("cgroup path contains an unsafe component"),
        }
    }
    Ok(output)
}

fn validate_public_identifier(value: &str, description: &str) -> Result<()> {
    let mut bytes = value.bytes();
    if value.len() > 64
        || !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("{description} contains unsupported characters");
    }
    Ok(())
}

fn cgroup_contains(root: &Path, candidate: &Path) -> bool {
    candidate == root
        || candidate
            .strip_prefix(root)
            .is_ok_and(|suffix| !suffix.as_os_str().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixListener;

    #[test]
    fn peer_evidence_uses_kernel_credentials_pidfd_and_unified_cgroup() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let client = UnixStream::connect(&socket).unwrap();
        let (server, _) = listener.accept().unwrap();
        let evidence = peer_evidence(&server).unwrap();
        assert_eq!(evidence.pid, std::process::id());
        assert_eq!(evidence.uid, nix::unistd::Uid::effective().as_raw());
        assert!(evidence.unified_cgroup.starts_with(CGROUP_ROOT));
        assert!(evidence.peer_pidfd.as_raw_fd() >= 0);
        drop(client);
    }

    #[test]
    fn pending_activation_is_bound_to_exact_supervisor_pid_uid_gid_and_cgroup() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let client = UnixStream::connect(&socket).unwrap();
        let (server, _) = listener.accept().unwrap();
        let evidence = peer_evidence(&server).unwrap();
        let mut pending = PendingSessionRegistration {
            session_id: "0123456789abcdef0123456789abcdef".into(),
            owner_uid: evidence.uid,
            owner_gid: evidence.gid,
            execution_pid: evidence.pid,
            workload: "codex".into(),
            profile: "automation".into(),
            authority: SessionAuthorityGrant {
                github: None,
                signing: None,
                release_signing: None,
                ssh: Vec::new(),
            },
            cgroup: evidence.unified_cgroup.clone(),
            expires_at_unix: time::OffsetDateTime::now_utc().unix_timestamp() + 30,
        };
        assert!(validate_pending_activation(&pending, &evidence).is_ok());
        pending.execution_pid = pending.execution_pid.saturating_add(1);
        assert!(validate_pending_activation(&pending, &evidence).is_err());
        pending.execution_pid = evidence.pid;
        pending.owner_gid = pending.owner_gid.saturating_add(1);
        assert!(validate_pending_activation(&pending, &evidence).is_err());
        drop(client);
    }

    #[test]
    fn registration_rejects_the_root_and_user_writable_cgroups() {
        let registry = LinuxSessionRegistry::new();
        let root_registration = SessionRegistration {
            session_id: "0123456789abcdef0123456789abcdef".into(),
            owner_uid: nix::unistd::Uid::effective().as_raw(),
            execution_uid: nix::unistd::Uid::effective().as_raw(),
            execution_gid: nix::unistd::getegid().as_raw(),
            workload: "codex".into(),
            profile: "automation".into(),
            authority: SessionAuthorityGrant {
                github: None,
                signing: None,
                release_signing: None,
                ssh: Vec::new(),
            },
            cgroup: PathBuf::from(CGROUP_ROOT),
            expires_at_unix: time::OffsetDateTime::now_utc().unix_timestamp() + 900,
        };
        let supervisor_pidfd = rustix::process::pidfd_open(
            rustix::process::getpid(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap();
        assert!(registry
            .register_root_owned(root_registration, supervisor_pidfd)
            .is_err());
    }

    #[test]
    fn cgroup_membership_is_component_bounded() {
        assert!(cgroup_contains(
            Path::new("/sys/fs/cgroup/dev-auth/session-a"),
            Path::new("/sys/fs/cgroup/dev-auth/session-a/child")
        ));
        assert!(!cgroup_contains(
            Path::new("/sys/fs/cgroup/dev-auth/session-a"),
            Path::new("/sys/fs/cgroup/dev-auth/session-ab")
        ));
    }

    #[test]
    fn only_exact_transient_workload_services_are_session_claims() {
        let session = "0123456789abcdef0123456789abcdef";
        let cgroup = PathBuf::from(format!(
            "/sys/fs/cgroup/system.slice/dev-auth-workload-{session}.service"
        ));
        assert_eq!(workload_session_id(&cgroup), Some(session));
        for rejected in [
            "/sys/fs/cgroup/system.slice/ssh.service",
            "/sys/fs/cgroup/user.slice/dev-auth-workload-0123456789abcdef0123456789abcdef.service",
            "/sys/fs/cgroup/system.slice/dev-auth-workload-short.service",
            "/sys/fs/cgroup/system.slice/dev-auth-workload-0123456789abcdef0123456789abcdef.scope",
        ] {
            assert_eq!(workload_session_id(Path::new(rejected)), None);
        }
    }

    #[test]
    fn current_workload_accepts_numeric_prefix_session_identifiers() {
        validate_current_workload_session("4c5461c2953de137653360f284ee797d").unwrap();
        assert!(validate_current_workload_session("g0000000000000000000000000000000").is_err());
    }

    #[test]
    fn retained_supervisor_pidfd_distinguishes_live_and_exited_processes() {
        let mut child = std::process::Command::new("/usr/bin/sleep")
            .arg("1")
            .spawn()
            .unwrap();
        let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
        let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap();
        assert!(pidfd_process_is_alive(&pidfd).unwrap());
        child.wait().unwrap();
        assert!(!pidfd_process_is_alive(&pidfd).unwrap());
    }

    #[test]
    fn ordinary_test_process_has_no_workload_claim() {
        assert_eq!(local_session_claim().unwrap(), LocalSessionClaim::Absent);
    }

    #[test]
    fn pending_admission_is_short_lived_and_bound_to_the_retained_execution_identity() {
        let registry = LinuxSessionRegistry::new();
        let session_id = "0123456789abcdef0123456789abcdef";
        let pending = PendingSessionRegistration {
            session_id: session_id.into(),
            owner_uid: 1000,
            owner_gid: 1000,
            execution_pid: 4242,
            workload: "codex".into(),
            profile: "automation".into(),
            authority: SessionAuthorityGrant {
                github: None,
                signing: None,
                release_signing: None,
                ssh: Vec::new(),
            },
            cgroup: PathBuf::from(format!(
                "{WORKLOAD_CGROUP_ROOT}/dev-auth-workload-{session_id}.service"
            )),
            expires_at_unix: time::OffsetDateTime::now_utc().unix_timestamp() + 30,
        };
        registry.prepare_root_owned(pending.clone()).unwrap();
        assert!(registry.prepare_root_owned(pending.clone()).is_err());
        assert!(registry.revoke(session_id).unwrap());

        let mut wrong_cgroup = pending;
        wrong_cgroup.cgroup = PathBuf::from("/sys/fs/cgroup/system.slice/other.service");
        assert!(registry.prepare_root_owned(wrong_cgroup).is_err());
    }

    #[test]
    fn renew_rejects_an_expired_registered_session_before_the_reaper_prunes_it() {
        let registry = LinuxSessionRegistry::new();
        let cgroup = tempfile::tempdir().unwrap();
        let cgroup_handle = File::open(cgroup.path()).unwrap();
        let cgroup_metadata = cgroup_handle.metadata().unwrap();
        let supervisor_pidfd = rustix::process::pidfd_open(
            rustix::process::getpid(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let expired_at = now - 1;
        let session_id = "0123456789abcdef0123456789abcdef";
        registry.sessions.write().unwrap().insert(
            session_id.into(),
            RegisteredSession {
                registration: SessionRegistration {
                    session_id: session_id.into(),
                    owner_uid: nix::unistd::Uid::effective().as_raw(),
                    execution_uid: nix::unistd::Uid::effective().as_raw(),
                    execution_gid: nix::unistd::getegid().as_raw(),
                    workload: "codex".into(),
                    profile: "automation".into(),
                    authority: SessionAuthorityGrant {
                        github: None,
                        signing: None,
                        release_signing: None,
                        ssh: Vec::new(),
                    },
                    cgroup: cgroup.path().to_path_buf(),
                    expires_at_unix: expired_at,
                },
                supervisor_pidfd,
                cgroup_handle,
                cgroup_device: cgroup_metadata.dev(),
                cgroup_inode: cgroup_metadata.ino(),
            },
        );

        let error = registry.renew(session_id, now + 10 * 60).unwrap_err();

        assert!(format!("{error:#}").contains("session renewal cannot revive an expired lease"));
        assert_eq!(
            registry
                .sessions
                .read()
                .unwrap()
                .get(session_id)
                .unwrap()
                .registration
                .expires_at_unix,
            expired_at
        );
    }
}
