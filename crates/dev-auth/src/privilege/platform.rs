//! Kernel-owned prerequisites that namespaces alone cannot enforce.
//! Host root remains trusted not to mutate the platform behind an active grant.
use anyhow::{bail, Context, Result};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const CORE_PATTERN: &str = "/proc/sys/kernel/core_pattern";
const LIMIT: u64 = 4096;

/// Linux pipe/socket collectors act in host namespaces. Pipe profiles require
/// the separately enforced immutable RLIMIT_CORE=1 recursion guard. Socket
/// profiles have no equivalent guard and remain unsupported. File paths stay
/// in the dying task's private filesystem namespace.
pub struct CoreDumpProfile {
    pattern: Vec<u8>,
}
impl CoreDumpProfile {
    pub fn capture() -> Result<Self> {
        let pattern = read_pattern()?;
        validate_pattern(&pattern)?;
        Ok(Self { pattern })
    }
    pub fn verify(&self) -> Result<()> {
        let current = read_pattern()?;
        validate_pattern(&current)?;
        if current != self.pattern {
            bail!("administrative kernel core profile changed");
        }
        Ok(())
    }
}
fn validate_pattern(bytes: &[u8]) -> Result<()> {
    let pattern = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if bytes.len() > LIMIT as usize
        || (pattern.starts_with(b"|") && !pattern.starts_with(b"|/"))
        || pattern.starts_with(b"@")
        || pattern.iter().any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
    {
        bail!("administrative containment requires a file or absolute-pipe kernel core profile");
    }
    Ok(())
}
fn read_pattern() -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
        .open(CORE_PATTERN)
        .context("observe administrative kernel core profile")?;
    let stat = file.metadata()?;
    if !stat.is_file()
        || stat.uid() != 0
        || stat.mode() & 0o022 != 0
        || rustix::fs::fstatfs(&file)?.f_type as u64 != 0x9fa0
    {
        bail!("administrative core profile is not kernel-owned proc authority");
    }
    let mut bytes = Vec::new();
    (&mut file).take(LIMIT + 1).read_to_end(&mut bytes)?;
    validate_pattern(&bytes)?;
    Ok(bytes)
}
/// Read-only readiness check before opening native administrator approval.
pub fn require_caller_core_floor() -> Result<()> {
    let mut limit = nix::libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { nix::libc::getrlimit(nix::libc::RLIMIT_CORE, &mut limit) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read caller core limit");
    }
    if limit.rlim_max < 1 {
        bail!("native caller hard CORE limit must permit the exact one-byte guard");
    }
    Ok(())
}

/// Async-signal-safe native calls only: also used by the pkexec child's
/// pre-exec hook, so the trusted bootstrap inherits suppression from ELF entry.
/// Linux's exact limit1 recursion guard aborts before a pipe helper is invoked.
pub fn constrain_core_limit() -> std::io::Result<()> {
    let wanted = nix::libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    let mut actual = nix::libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { nix::libc::setrlimit(nix::libc::RLIMIT_CORE, &wanted) } != 0
        || unsafe { nix::libc::getrlimit(nix::libc::RLIMIT_CORE, &mut actual) } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    if actual.rlim_cur != 1 || actual.rlim_max != 1 {
        return Err(std::io::Error::from_raw_os_error(nix::libc::EPERM));
    }
    Ok(())
}
/// Apply only to the dedicated root maintenance entry, never credential
/// broker/workload paths. The manager also sets LimitCORE=1 before ELF startup.
pub fn protect_infrastructure() -> Result<()> {
    if !nix::unistd::geteuid().is_root() || nix::unistd::getuid() != nix::unistd::geteuid() {
        bail!("maintenance infrastructure requires native root");
    }
    if unsafe { nix::libc::prctl(nix::libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("suppress trusted maintenance core");
    }
    constrain_core_limit().context("fix maintenance core recursion guard")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn external_collectors_and_ambiguous_profile_bytes_reject() {
        for pattern in [
            b"|helper".as_slice(),
            b"|",
            b"| /unknown",
            b"@/run/systemd/coredump.socket",
            b"@@/run/systemd/coredump.socket\n",
            b"core\nextra",
            b"core\0",
            b"core\r\n",
        ] {
            assert!(validate_pattern(pattern).is_err());
        }
        assert!(validate_pattern(&vec![b'a'; LIMIT as usize + 1]).is_err());
    }
    #[test]
    fn ordinary_file_patterns_do_not_require_host_core_mutation() {
        for pattern in [
            b"core\n".as_slice(),
            b"/cores/core.%p\n",
            b"\n",
            b"|/usr/lib/systemd/systemd-coredump %P\n",
        ] {
            validate_pattern(pattern).unwrap();
        }
    }
}
