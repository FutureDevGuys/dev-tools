use super::policy::{Account, NativeScope};
use super::Failure;
use crate::linux_admission::LinuxPeerEvidence;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// What one look at native state found. Supervision ends a grant or stops a
/// job only on an observed answer (ADR 0138).
pub(super) type Look<T> = Result<T, Unobserved>;

/// A look at native state that could not be taken. It is never evidence that
/// a process, a workload or a trust input changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Unobserved(pub io::ErrorKind);

/// A read of a process's `/proc` entry: `None` when the process has exited,
/// which Linux reports as ENOENT or ESRCH.
pub(super) fn process_look<T>(read: io::Result<T>) -> Look<Option<T>> {
    read.map_or_else(|error| exited(&error), |value| Ok(Some(value)))
}

/// A process's unified cgroup, or `None` when the process has exited.
pub(super) fn cgroup_look(pid: u32) -> Look<Option<std::path::PathBuf>> {
    crate::linux_admission::read_unified_cgroup(pid).map_or_else(
        |error| {
            error
                .root_cause()
                .downcast_ref::<io::Error>()
                .map_or(Err(Unobserved(io::ErrorKind::InvalidData)), exited)
        },
        |path| Ok(Some(path)),
    )
}

fn exited<T>(error: &io::Error) -> Look<Option<T>> {
    match error.raw_os_error() {
        Some(nix::libc::ENOENT | nix::libc::ESRCH) => Ok(None),
        _ => Err(Unobserved(error.kind())),
    }
}

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
    /// The caller's file-creation mask, from its `/proc` status.
    pub fn umask(&self) -> Result<u32, Failure> {
        let status = read_bounded(
            Path::new(&format!("/proc/{}/status", self.peer.pid)),
            1024 * 1024,
        )?;
        let mask = parse_umask(&status).ok_or(Failure::AuthorityDenied)?;
        if !self.still_present() {
            return Err(Failure::AuthorityDenied);
        }
        Ok(mask)
    }

    /// Whether the caller runs under a confinement that a process started for
    /// it in the host namespaces would leave: no-new-privileges, a seccomp
    /// filter, or a namespace other than the coordinator's, except the mount
    /// namespace, which that process joins.
    pub fn confined(&self) -> Result<bool, Failure> {
        let status = read_bounded(
            Path::new(&format!("/proc/{}/status", self.peer.pid)),
            1024 * 1024,
        )?;
        let mut confined = parse_confinement(&status).ok_or(Failure::AuthorityDenied)?;
        for namespace in ["user", "net", "pid", "ipc", "uts", "cgroup", "time"] {
            let theirs = File::open(format!("/proc/{}/ns/{namespace}", self.peer.pid))
                .map_err(|_| Failure::AuthorityDenied)?;
            let ours = File::open(format!("/proc/self/ns/{namespace}"))
                .map_err(|_| Failure::NativeUnavailable)?;
            confined |= !same_file(&theirs, &ours)?;
        }
        if !self.still_present() {
            return Err(Failure::AuthorityDenied);
        }
        Ok(confined)
    }

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
        self.presence() == Ok(true)
    }

    /// One look at whether the caller is still the process that connected:
    /// the same live process, namespaces, directory, identity and cgroup.
    pub fn presence(&self) -> Look<bool> {
        if readable(self.peer.peer_pidfd())? {
            return Ok(false);
        }
        let pid = self.peer.pid;
        for (name, retained) in [
            ("ns/user", &self.user_namespace),
            ("ns/mnt", &self.mount_namespace),
            ("cwd", &self.directory),
        ] {
            let Some(observed) = process_look(File::open(format!("/proc/{pid}/{name}")))? else {
                return Ok(false);
            };
            if !identical(&observed, retained)? {
                return Ok(false);
            }
        }
        let Some(status) = process_look(read_limited(
            Path::new(&format!("/proc/{pid}/status")),
            64 * 1024,
        ))?
        else {
            return Ok(false);
        };
        let Some(cgroup) = cgroup_look(pid)? else {
            return Ok(false);
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
        Ok(effective(b"Uid:") == Some(self.peer.uid)
            && effective(b"Gid:") == Some(self.peer.gid)
            && cgroup == self.peer.unified_cgroup
            && !readable(self.peer.peer_pidfd())?)
    }
}

/// `NoNewPrivs` and `Seccomp` from a `/proc` status: `Some(true)` when either
/// confines the process, `None` when either is missing or repeated.
fn parse_confinement(status: &[u8]) -> Option<bool> {
    let field = |name: &[u8]| {
        let mut values = status
            .split(|byte| *byte == b'\n')
            .filter_map(|line| line.strip_prefix(name));
        let value = std::str::from_utf8(values.next()?)
            .ok()?
            .trim()
            .parse::<u32>()
            .ok()?;
        values.next().is_none().then_some(value)
    };
    Some(field(b"NoNewPrivs:")? != 0 || field(b"Seccomp:")? != 0)
}

fn parse_umask(status: &[u8]) -> Option<u32> {
    let mut masks = status
        .split(|byte| *byte == b'\n')
        .filter_map(|line| line.strip_prefix(b"Umask:"));
    let mask = std::str::from_utf8(masks.next()?).ok()?.trim();
    if masks.next().is_some()
        || mask.is_empty()
        || !mask.bytes().all(|byte| (b'0'..=b'7').contains(&byte))
    {
        return None;
    }
    u32::from_str_radix(mask, 8)
        .ok()
        .filter(|mask| *mask <= 0o777)
}

/// Admission needs a positive look that the process is alive.
pub(super) fn alive(fd: impl AsFd) -> bool {
    readable(fd) == Ok(false)
}

/// Whether a held descriptor is readable now: a pidfd whose process exited,
/// or a connection whose peer hung up or sent data.
pub(super) fn readable(fd: impl AsFd) -> Look<bool> {
    let mut descriptors = [nix::poll::PollFd::new(
        fd.as_fd(),
        nix::poll::PollFlags::POLLIN,
    )];
    nix::poll::poll(&mut descriptors, nix::poll::PollTimeout::ZERO)
        .map(|ready| ready > 0)
        .map_err(|error| Unobserved(io::Error::from(error).kind()))
}

pub(super) fn clone_fd(fd: impl AsFd) -> Result<OwnedFd, Failure> {
    fd.as_fd()
        .try_clone_to_owned()
        .map_err(|_| Failure::RuntimeFailure)
}

pub(super) fn same_file(left: &File, right: &File) -> Result<bool, Failure> {
    identical(left, right).map_err(|_| Failure::AuthorityDenied)
}

pub(super) fn identical(left: &File, right: &File) -> Look<bool> {
    let left = left.metadata().map_err(|error| Unobserved(error.kind()))?;
    let right = right.metadata().map_err(|error| Unobserved(error.kind()))?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

pub(super) fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Failure> {
    read_limited(path, limit).map_err(|error| {
        if error.kind() == io::ErrorKind::InvalidData {
            Failure::ProtocolViolation
        } else {
            Failure::NativeUnavailable
        }
    })
}

fn read_limited(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_new_privileges_or_a_seccomp_filter_confines_a_caller() {
        let status = |no_new_privs: &str, seccomp: &str| {
            format!(
                "Name:\tshell\nUmask:\t0022\nNoNewPrivs:\t{no_new_privs}\nSeccomp:\t{seccomp}\n"
            )
        };
        assert_eq!(parse_confinement(status("0", "0").as_bytes()), Some(false));
        assert_eq!(parse_confinement(status("1", "0").as_bytes()), Some(true));
        assert_eq!(parse_confinement(status("0", "2").as_bytes()), Some(true));
        assert_eq!(parse_confinement(b"Name:\tshell\nSeccomp:\t0\n"), None);
        assert_eq!(
            parse_confinement(b"NoNewPrivs:\t0\nNoNewPrivs:\t1\nSeccomp:\t0\n"),
            None
        );
        assert_eq!(parse_umask(status("0", "0").as_bytes()), Some(0o022));
    }

    #[test]
    fn only_an_exited_process_is_gone_from_proc() {
        for exited in [nix::libc::ENOENT, nix::libc::ESRCH] {
            assert_eq!(
                process_look::<()>(Err(io::Error::from_raw_os_error(exited))),
                Ok(None)
            );
        }
        for unobserved in [nix::libc::EMFILE, nix::libc::ENOMEM, nix::libc::EACCES] {
            assert!(
                process_look::<()>(Err(io::Error::from_raw_os_error(unobserved))).is_err(),
                "errno {unobserved}"
            );
        }
        assert_eq!(process_look(Ok(7)), Ok(Some(7)));
    }

    #[test]
    fn a_held_connection_is_readable_only_once_its_peer_hangs_up() {
        use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
        let (held, peer) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        assert_eq!(readable(&held), Ok(false));
        assert!(alive(&held));
        drop(peer);
        assert_eq!(readable(&held), Ok(true));
        assert!(!alive(&held));
    }
}
