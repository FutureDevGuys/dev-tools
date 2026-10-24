use super::policy::{Account, NativeScope};
use super::Failure;
use crate::linux_admission::LinuxPeerEvidence;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// What one look at native state found.
pub(super) type Look<T> = Result<T, Unobserved>;

/// A look at native state that could not be taken. It is never evidence that
/// a process, a workload or a trust input changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Unobserved(pub io::ErrorKind);

pub(super) struct Caller {
    pub peer: LinuxPeerEvidence,
    pub scope: NativeScope,
    pub workload: Option<File>,
    pub mount_namespace: File,
    pub directory: File,
    pub user_namespace: File,
    pub start_time: u64,
}

impl Caller {
    pub fn groups(&self) -> Result<Vec<u32>, Failure> {
        let status = read_bounded(
            Path::new(&format!("/proc/{}/status", self.peer.pid)),
            1024 * 1024,
        )?;
        let groups = status
            .split(|byte| *byte == b'\n')
            .find_map(|line| line.strip_prefix(b"Groups:"))
            .ok_or(Failure::AuthorityDenied)?;
        let groups = std::str::from_utf8(groups)
            .map_err(|_| Failure::AuthorityDenied)?
            .split_whitespace()
            .map(|group| group.parse().map_err(|_| Failure::AuthorityDenied))
            .collect::<Result<Vec<_>, Failure>>()?;
        if groups.len() > 65_536 || !self.still_present() {
            return Err(Failure::AuthorityDenied);
        }
        Ok(groups)
    }

    pub fn verify_directory(&self, submitted: &std::ffi::OsStr) -> Result<(), Failure> {
        let relative = Path::new(submitted)
            .strip_prefix("/")
            .map_err(|_| Failure::AuthorityDenied)?;
        if relative.components().any(|component| {
            !matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        }) {
            return Err(Failure::AuthorityDenied);
        }
        // Resolve the path in the caller's retained namespace, then compare
        // native identity with the cwd descriptor that execution actually uses.
        let observed =
            File::open(Path::new(&format!("/proc/{}/root", self.peer.pid)).join(relative))
                .map_err(|_| Failure::AuthorityDenied)?;
        if !same_file(&observed, &self.directory)? || !self.still_present() {
            return Err(Failure::AuthorityDenied);
        }
        Ok(())
    }

    pub fn capture(socket: &impl AsFd) -> Result<Self, Failure> {
        Self::capture_as(socket, None)
    }

    /// The product verifies the peer's retained native sudo executable before
    /// accepting its root-owned plugin's original-user observation.
    pub fn capture_sudo(socket: &impl AsFd, original_uid: u32) -> Result<Self, Failure> {
        if original_uid == 0 {
            return Err(Failure::AuthorityDenied);
        }
        Self::capture_as(socket, Some(original_uid))
    }

    fn capture_as(socket: &impl AsFd, original_uid: Option<u32>) -> Result<Self, Failure> {
        let peer = crate::linux_admission::peer_evidence_fd(socket)
            .map_err(|_| Failure::AuthorityDenied)?;
        if (peer.uid == 0) != original_uid.is_some() {
            return Err(Failure::AuthorityDenied);
        }
        let user_namespace = File::open(format!("/proc/{}/ns/user", peer.pid))
            .map_err(|_| Failure::AuthorityDenied)?;
        let host_namespace =
            File::open("/proc/self/ns/user").map_err(|_| Failure::NativeUnavailable)?;
        let same_namespace = same_file(&user_namespace, &host_namespace)?;
        let workload = if crate::linux_admission::workload_session_id(&peer.unified_cgroup)
            .is_some()
        {
            let directory = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
                .open(&peer.unified_cgroup)
                .map_err(|_| Failure::AuthorityDenied)?;
            let metadata = directory.metadata().map_err(|_| Failure::AuthorityDenied)?;
            if metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
                || rustix::fs::fstatfs(&directory)
                    .map_err(|_| Failure::AuthorityDenied)?
                    .f_type as u64
                    != 0x6367_7270
            {
                return Err(Failure::AuthorityDenied);
            }
            if !same_namespace {
                let uid_map =
                    read_bounded(Path::new(&format!("/proc/{}/uid_map", peer.pid)), 4096)?;
                let gid_map =
                    read_bounded(Path::new(&format!("/proc/{}/gid_map", peer.pid)), 4096)?;
                crate::linux_platform::IdentityUserNamespace::parse_maps(&uid_map, &gid_map)
                    .map_err(|_| Failure::AuthorityDenied)?;
            }
            Some(directory)
        } else {
            if !same_namespace {
                return Err(Failure::AuthorityDenied);
            }
            None
        };
        let key = workload
            .as_ref()
            .map(|directory| {
                directory
                    .metadata()
                    .map(|metadata| ((metadata.dev() as u128) << 64) | metadata.ino() as u128)
            })
            .transpose()
            .map_err(|_| Failure::AuthorityDenied)?;
        let stat = read_bounded(Path::new(&format!("/proc/{}/stat", peer.pid)), 8192)?;
        let end_name = stat
            .iter()
            .rposition(|byte| *byte == b')')
            .ok_or(Failure::AuthorityDenied)?;
        let stat =
            std::str::from_utf8(&stat[end_name + 1..]).map_err(|_| Failure::AuthorityDenied)?;
        let start_time = Some(stat)
            .and_then(|rest| rest.split_whitespace().nth(19))
            .and_then(|value| value.parse().ok())
            .ok_or(Failure::AuthorityDenied)?;
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_PATH | nix::libc::O_DIRECTORY | nix::libc::O_CLOEXEC)
            .open(format!("/proc/{}/cwd", peer.pid))
            .map_err(|_| Failure::AuthorityDenied)?;
        let mount_namespace = File::open(format!("/proc/{}/ns/mnt", peer.pid))
            .map_err(|_| Failure::AuthorityDenied)?;
        if !alive(peer.peer_pidfd()) {
            return Err(Failure::AuthorityDenied);
        }
        Ok(Self {
            scope: NativeScope {
                account: Account::Unix {
                    uid: original_uid.unwrap_or(peer.uid),
                },
                workload: key,
            },
            peer,
            workload,
            mount_namespace,
            directory,
            user_namespace,
            start_time,
        })
    }

    pub fn still_present(&self) -> bool {
        if !alive(self.peer.peer_pidfd()) {
            return false;
        }
        let Ok(namespace) = File::open(format!("/proc/{}/ns/user", self.peer.pid)) else {
            return false;
        };
        if !same_file(&namespace, &self.user_namespace).unwrap_or(false) {
            return false;
        }
        for (name, retained) in [("ns/mnt", &self.mount_namespace), ("cwd", &self.directory)] {
            let Ok(observed) = File::open(format!("/proc/{}/{name}", self.peer.pid)) else {
                return false;
            };
            if !same_file(&observed, retained).unwrap_or(false) {
                return false;
            }
        }
        let Ok(status) = read_bounded(
            Path::new(&format!("/proc/{}/status", self.peer.pid)),
            64 * 1024,
        ) else {
            return false;
        };
        let effective = |name: &[u8]| {
            status.split(|byte| *byte == b'\n').find_map(|line| {
                let line = line.strip_prefix(name)?;
                std::str::from_utf8(line)
                    .ok()?
                    .split_whitespace()
                    .nth(1)?
                    .parse::<u32>()
                    .ok()
            })
        };
        effective(b"Uid:") == Some(self.peer.uid)
            && effective(b"Gid:") == Some(self.peer.gid)
            && crate::linux_admission::read_unified_cgroup(self.peer.pid)
                .ok()
                .as_ref()
                == Some(&self.peer.unified_cgroup)
            && alive(self.peer.peer_pidfd())
    }
}

pub(super) fn alive(fd: impl AsFd) -> bool {
    let mut descriptors = [nix::poll::PollFd::new(
        fd.as_fd(),
        nix::poll::PollFlags::POLLIN,
    )];
    matches!(
        nix::poll::poll(&mut descriptors, nix::poll::PollTimeout::ZERO),
        Ok(0)
    )
}

pub(super) fn clone_fd(fd: impl AsFd) -> Result<OwnedFd, Failure> {
    fd.as_fd()
        .try_clone_to_owned()
        .map_err(|_| Failure::RuntimeFailure)
}

pub(super) fn same_file(left: &File, right: &File) -> Result<bool, Failure> {
    let left = left.metadata().map_err(|_| Failure::AuthorityDenied)?;
    let right = right.metadata().map_err(|_| Failure::AuthorityDenied)?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

pub(super) fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::NativeUnavailable)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::NativeUnavailable)?;
    if bytes.len() > limit {
        return Err(Failure::ProtocolViolation);
    }
    Ok(bytes)
}
