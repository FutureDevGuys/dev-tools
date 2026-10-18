//! Product-owned descriptor slots for a declared native sandbox adapter.
//! The caller proves each descriptor's authority before forming this set.
use anyhow::{bail, Context, Result};
use std::ffi::OsString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

pub(crate) const MAX_ADAPTER_DESCRIPTORS: usize = 3;
const FIRST_SLOT: RawFd = 3;
const FIRST_HELD: RawFd = FIRST_SLOT + MAX_ADAPTER_DESCRIPTORS as RawFd;
pub(crate) const MIN_EXECUTABLE_DESCRIPTOR: i32 = FIRST_HELD;

pub(crate) struct AdapterDescriptors {
    held: Vec<OwnedFd>,
    slots: Vec<RawFd>,
}

/// Own successful compact duplications if native exec reports an error.
pub(crate) struct ExecDescriptorGuard {
    mapped: Arc<AtomicU8>,
    slots: Vec<RawFd>,
    previous: Vec<Option<(OwnedFd, i32)>>,
}

impl Drop for ExecDescriptorGuard {
    fn drop(&mut self) {
        let mapped = self.mapped.load(Ordering::Acquire);
        for (index, slot) in self.slots.iter().enumerate() {
            if mapped & (1 << index) != 0 {
                // SAFETY: the exec-only callback records each successful dup2
                // immediately, transferring that new slot to this guard. No
                // successful exec returns, and failed exec must close it once.
                if let Some((descriptor, flags)) = &self.previous[index] {
                    // SAFETY: the backup owns the original OFD above all target
                    // slots. Restore both that identity and its descriptor flags
                    // before any pre-existing Rust owner can drop after error.
                    unsafe {
                        loop {
                            if nix::libc::dup2(descriptor.as_raw_fd(), *slot) >= 0 {
                                break;
                            }
                            if std::io::Error::last_os_error().raw_os_error()
                                != Some(nix::libc::EINTR)
                            {
                                std::process::abort();
                            }
                        }
                        if nix::libc::fcntl(*slot, nix::libc::F_SETFD, *flags) < 0 {
                            std::process::abort();
                        }
                    }
                } else {
                    unsafe {
                        nix::libc::close(*slot);
                    }
                }
            }
        }
    }
}

impl AdapterDescriptors {
    pub(crate) fn new(descriptors: Vec<OwnedFd>) -> Result<Self> {
        if descriptors.len() > MAX_ADAPTER_DESCRIPTORS {
            bail!("native sandbox descriptor count exceeds its product bound");
        }
        let held = descriptors
            .iter()
            .map(|descriptor| {
                rustix::io::fcntl_dupfd_cloexec(descriptor, FIRST_HELD)
                    .context("retain native sandbox descriptor outside compact slots")
            })
            .collect::<Result<Vec<_>>>()?;
        // All original owners, including any reserved stdio allocations, close
        // here. Owned high descriptors keep mapping independent of input order.
        drop(descriptors);
        Ok(Self {
            slots: (0..held.len())
                .map(|index| FIRST_SLOT + index as RawFd)
                .collect(),
            held,
        })
    }

    pub(crate) fn slots(&self) -> &[RawFd] {
        &self.slots
    }

    pub(crate) fn expanded_arguments(&self, template: &[String]) -> Result<Vec<OsString>> {
        validate_template(template)?;
        if self.held.is_empty() {
            return Ok(Vec::new());
        }
        if template.is_empty() {
            bail!("sandbox adapter does not declare native descriptor preservation");
        }
        Ok(template
            .iter()
            .map(|argument| {
                OsString::from(argument.replace("{count}", &self.held.len().to_string()))
            })
            .collect())
    }

    /// Prepare only a native replacement performed with CommandExt::exec.
    /// Spawn allocates a private error pipe that must never be overwritten by
    /// compact slot mapping; callers spawn an installed native intermediate.
    pub(crate) fn prepare_exec_command(self, command: &mut Command) -> Result<ExecDescriptorGuard> {
        let mapped = Arc::new(AtomicU8::new(0));
        // Private native intermediates are single-threaded while preparing exec.
        // Retain every currently occupied destination, including unrelated live
        // owners, so failure restores their original open-file descriptions.
        let previous = self
            .slots
            .iter()
            .map(|slot| duplicate_existing_slot(*slot))
            .collect::<Result<Vec<_>>>()?;
        let guard = ExecDescriptorGuard {
            mapped: mapped.clone(),
            slots: self.slots.clone(),
            previous,
        };
        if self.held.is_empty() {
            return Ok(guard);
        }
        // SAFETY: the callback owns every high source descriptor; each compact
        // destination is distinct and below every source. dup2/fcntl are async-
        // signal-safe, with no allocation, environment access or foreign Rust
        // reference in the child. Exec performs this replacement in the current
        // native intermediate and allocates no spawn error pipe. The configured
        // adapter and the final probe therefore inherit only compact owned slots.
        unsafe {
            command.pre_exec(move || {
                for (index, (descriptor, slot)) in self.held.iter().zip(&self.slots).enumerate() {
                    if nix::libc::dup2(descriptor.as_raw_fd(), *slot) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    mapped.fetch_or(1 << index, Ordering::Release);
                    if nix::libc::fcntl(*slot, nix::libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        Ok(guard)
    }
}

fn duplicate_existing_slot(slot: RawFd) -> Result<Option<(OwnedFd, i32)>> {
    // SAFETY: fcntl accepts any integer, including a closed slot. Success creates
    // a new exclusively owned descriptor without borrowing a foreign lifetime.
    let descriptor = unsafe { nix::libc::fcntl(slot, nix::libc::F_DUPFD_CLOEXEC, FIRST_HELD) };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(nix::libc::EBADF) {
            return Ok(None);
        }
        return Err(error).context("retain existing native adapter compact slot");
    }
    // SAFETY: that successful duplication allocated this distinct owned FD.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    // SAFETY: the single-threaded exec intermediate still owns the original slot.
    let flags = unsafe { nix::libc::fcntl(slot, nix::libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error())
            .context("inspect existing native adapter slot flags");
    }
    Ok(Some((descriptor, flags)))
}

pub(crate) fn validate_template(template: &[String]) -> Result<()> {
    crate::policy_v2::validate_inherited_descriptor_arguments(template)
}

pub(crate) fn normalize_source_descriptor(file: std::fs::File) -> Result<std::fs::File> {
    if file.as_raw_fd() >= FIRST_SLOT {
        return Ok(file);
    }
    let retained = rustix::io::fcntl_dupfd_cloexec(&file, FIRST_SLOT)
        .context("retain private source outside reserved standard stream slots")?;
    drop(file);
    Ok(retained.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptors(count: usize) -> Vec<OwnedFd> {
        (0..count)
            .map(|_| std::fs::File::open("/dev/null").unwrap().into())
            .collect()
    }

    #[test]
    fn declared_adapter_arguments_expand_only_the_bounded_compact_count() {
        let template = vec!["--preserve-fds".into(), "{count}".into()];
        let mapped = AdapterDescriptors::new(descriptors(3)).unwrap();
        assert_eq!(mapped.slots(), &[3, 4, 5]);
        assert_eq!(
            mapped.expanded_arguments(&template).unwrap(),
            vec![OsString::from("--preserve-fds"), OsString::from("3")]
        );
        assert!(mapped
            .held
            .iter()
            .all(|descriptor| descriptor.as_raw_fd() >= 6));
        assert!(AdapterDescriptors::new(descriptors(4)).is_err());
        assert!(mapped.expanded_arguments(&[]).is_err());
        let empty = AdapterDescriptors::new(Vec::new()).unwrap();
        assert!(empty.expanded_arguments(&[]).unwrap().is_empty());
        assert!(empty.expanded_arguments(&template).unwrap().is_empty());
    }

    #[test]
    fn adapter_template_rejects_unknown_unbounded_and_ambiguous_tokens() {
        for template in [
            vec!["--preserve-fds".into()],
            vec!["{count}{count}".into()],
            vec!["{fd}".into(), "{count}".into()],
            vec!["{count}".into(), "\0".into()],
            vec!["{count}".into(); 9],
        ] {
            assert!(validate_template(&template).is_err());
        }
    }

    #[test]
    fn source_descriptor_floor_survives_closed_stdin() {
        const FIXTURE: &str = "DEV_AUTH_TEST_CLOSED_STDIN_SOURCE_DESCRIPTOR";
        if std::env::var_os(FIXTURE).is_none() {
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "supervisor_descriptors::tests::source_descriptor_floor_survives_closed_stdin",
                ])
                .env(FIXTURE, "1")
                .stdin(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        // SAFETY: this branch runs only in the isolated one-test child above;
        // its parent and other tests retain their independent standard streams.
        assert_eq!(unsafe { nix::libc::close(0) }, 0);
        let file = std::fs::File::from(
            rustix::fs::memfd_create(
                "closed-stdin-source-fixture",
                rustix::fs::MemfdFlags::CLOEXEC,
            )
            .unwrap(),
        );
        assert_eq!(file.as_raw_fd(), 0);
        let retained = normalize_source_descriptor(file).unwrap();
        assert!(retained.as_raw_fd() >= 3);
        // SAFETY: fcntl accepts a closed integer descriptor and performs no
        // memory access; failure proves the original closed stream stays closed.
        assert_eq!(unsafe { nix::libc::fcntl(0, nix::libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(nix::libc::EBADF)
        );
    }

    #[test]
    fn failed_adapter_exec_restores_preexisting_compact_owner_and_flags() {
        const FIXTURE: &str = "DEV_AUTH_TEST_FAILED_ADAPTER_EXEC_DESCRIPTOR";
        if std::env::var_os(FIXTURE).is_none() {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command.args(["--exact", "supervisor_descriptors::tests::failed_adapter_exec_restores_preexisting_compact_owner_and_flags"])
                .env(FIXTURE, "1");
            // SAFETY: this one-test subprocess drops only inherited non-CLOEXEC
            // compact descriptors before exec. The parent's owners are separate;
            // std::process's CLOEXEC error pipe is retained for diagnostics and
            // closes normally on successful test-binary exec.
            unsafe {
                command.pre_exec(|| {
                    for slot in 3..=5 {
                        let flags = nix::libc::fcntl(slot, nix::libc::F_GETFD);
                        if flags >= 0 && flags & nix::libc::FD_CLOEXEC == 0 {
                            nix::libc::close(slot);
                        }
                    }
                    Ok(())
                });
            }
            let status = command.status().unwrap();
            assert!(status.success());
            return;
        }
        use std::os::unix::fs::MetadataExt;
        let original = std::fs::File::open("/dev/zero").unwrap();
        assert_eq!(
            original.as_raw_fd(),
            3,
            "isolated exec fixture requires its first free compact slot"
        );
        let before = original.metadata().unwrap();
        // SAFETY: this live descriptor remains owned by original throughout.
        let flags = unsafe { nix::libc::fcntl(original.as_raw_fd(), nix::libc::F_GETFD) };
        let descriptors = AdapterDescriptors::new(descriptors(1)).unwrap();
        let mut command = Command::new("/dev-auth-test-missing-adapter-fixture");
        let guard = descriptors.prepare_exec_command(&mut command).unwrap();
        assert_eq!(command.exec().kind(), std::io::ErrorKind::NotFound);
        drop(guard);
        let after = original.metadata().unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        // SAFETY: failed exec restored the slot before the original owner drops.
        assert_eq!(
            unsafe { nix::libc::fcntl(original.as_raw_fd(), nix::libc::F_GETFD) },
            flags
        );
    }
}
