//! Installed shell selection and sealed descriptor transport. Neither the
//! numeric inherited descriptor hint nor source bytes grant native admission.
use super::*;
use crate::policy_v2::ResolvedWorkload;
use crate::smart_binding::{BindingResolution, BindingTargetIntent};
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
use sha2::Digest;
use std::io::{IoSlice, Read};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::os::unix::net::UnixStream;

pub(crate) const SOURCE_FD_ENV: &str = "DEV_AUTH_PRIVATE_SHELL_SOURCE_FD";
const SOURCE_FRAME: &[u8; 5] = b"DASF1";

struct Selection {
    mode: crate::setup::InstallMode,
    home: PathBuf,
    alias: String,
    binding: BindingReceipt,
}

fn selection(
    owner_uid: u32,
    workload_name: &str,
    workload: &ResolvedWorkload,
) -> Result<Option<Selection>> {
    let caller = nix::unistd::Uid::effective().as_raw();
    if owner_uid == 0 || (caller != 0 && caller != owner_uid) {
        bail!("shell source has the wrong native owner");
    }
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(owner_uid))?
        .context("shell native account is absent")?;
    let (_, installation) = current_binding_runtime_installation()?;
    let path = native_receipt_path(installation.mode, &user.dir, owner_uid)?;
    let Some((set, _)) = read_at(&path, installation.mode, owner_uid, &installation)? else {
        return Ok(None);
    };
    let selected = set
        .bindings
        .iter()
        .filter(|(_, binding)| binding.active.intent.workload == workload_name)
        .collect::<Vec<_>>();
    if !selected.iter().any(|(_, binding)| {
        crate::smart_binding::is_pinned_shell_resolution(&binding.active.resolved)
    }) {
        return Ok(None);
    }
    if !workload.allow_pinned_shell {
        bail!("administrator workload authority no longer permits the shell definition");
    }
    let mut first: Option<(&String, &BindingReceipt)> = None;
    for (alias, binding) in selected {
        if !crate::smart_binding::is_pinned_shell_resolution(&binding.active.resolved)
            || binding.active.resolved.identity().canonical_path
                != Path::new(&workload.launcher_path)
            || !matches!(
                binding.active.intent.target,
                BindingTargetIntent::PinnedShell { .. }
            )
        {
            bail!("workload shell aliases select conflicting execution authority");
        }
        crate::setup::verify_current_workload_alias_link(
            alias,
            &user.dir,
            owner_uid,
            Path::new(&installation.executable),
        )?;
        if let Some((_, prior)) = first {
            if prior.active.resolved != binding.active.resolved {
                bail!("workload aliases select different private shell definitions");
            }
        } else {
            first = Some((alias, binding));
        }
    }
    let (alias, binding) = first.context("shell source selection disappeared")?;
    Ok(Some(Selection {
        mode: installation.mode,
        home: user.dir,
        alias: alias.clone(),
        binding: binding.clone(),
    }))
}

pub(crate) fn outer_source(
    owner_uid: u32,
    workload_name: &str,
    workload: &ResolvedWorkload,
) -> Result<Option<fs::File>> {
    let Some(selected) = selection(owner_uid, workload_name, workload)? else {
        return Ok(None);
    };
    if selected.mode == crate::setup::InstallMode::Strong
        && !nix::unistd::Uid::effective().is_root()
    {
        bail!("strong private shell source requires the authenticated root dispatcher");
    }
    let source = sealed_source_for_binding(
        selected.mode,
        &selected.home,
        owner_uid,
        &selected.alias,
        &selected.binding,
    )?;
    verify_descriptor(&source, owner_uid, &selected.binding)?;
    Ok(Some(source))
}

/// Called on a fresh command before caller-owned environment, cwd and streams
/// are installed. The direct user-only branch supplies its owned shell command.
pub(crate) fn configure_outer(
    command: &mut std::process::Command,
    source: Option<fs::File>,
    owner_uid: u32,
    workload_name: &str,
    workload: &ResolvedWorkload,
    arguments: &[OsString],
    through_adapter: bool,
) -> Result<()> {
    match (selection(owner_uid, workload_name, workload)?, source) {
        (Some(selected), Some(source)) => {
            verify_descriptor(&source, owner_uid, &selected.binding)?;
            if through_adapter {
                crate::smart_binding::shell::retain_descriptor(command, source)?;
            } else if selected.mode == crate::setup::InstallMode::UserOnly {
                *command = crate::smart_binding::shell::retained_shell_command(
                    &selected.binding,
                    source,
                    arguments,
                )?;
            } else {
                crate::smart_binding::shell::attach_sealed_source(
                    command,
                    &selected.binding,
                    source,
                    arguments,
                )?;
            }
        }
        (None, None) if !through_adapter => {
            command.args(arguments).env_remove(SOURCE_FD_ENV);
        }
        (None, None) => {
            command.env_remove(SOURCE_FD_ENV);
        }
        _ => bail!("outer shell source differs from the installed generation"),
    }
    Ok(())
}

pub(crate) fn verify_handoff_source(
    source: Option<fs::File>,
    owner_uid: u32,
    workload_name: &str,
    workload: &ResolvedWorkload,
) -> Result<Option<fs::File>> {
    match (selection(owner_uid, workload_name, workload)?, source) {
        (None, None) => Ok(None),
        (Some(selected), Some(source)) => {
            verify_descriptor(&source, owner_uid, &selected.binding)?;
            Ok(Some(source))
        }
        _ => bail!("native shell source handoff differs from the installed binding generation"),
    }
}

fn require_native_session(
    owner_uid: u32,
    workload_name: &str,
    workload: &ResolvedWorkload,
) -> Result<()> {
    let (claim, probe) = crate::broker_client::active_claim_and_probe()?;
    if matches!(claim, crate::broker_protocol::LocalSessionClaim::Absent) {
        bail!("private shell source is outside native workload admission");
    }
    match probe {
        crate::broker_protocol::BrokerSessionProbe::Verified {
            owner_uid: owner,
            execution_uid,
            workload: name,
            profile,
            ..
        } if owner == owner_uid
            && execution_uid == nix::unistd::Uid::effective().as_raw()
            && name == workload_name
            && profile == workload.authority_profile =>
        {
            Ok(())
        }
        _ => bail!("private shell source differs from the broker-verified native workload"),
    }
}

fn inherited_source() -> Result<fs::File> {
    let descriptor = std::env::var(SOURCE_FD_ENV)
        .map_err(|_| anyhow::anyhow!("native shell source descriptor is absent"))?
        .parse::<RawFd>()
        .map_err(|_| anyhow::anyhow!("native shell source descriptor is invalid"))?;
    if descriptor < 3 {
        bail!("native shell source descriptor is reserved");
    }
    // SAFETY: fcntl accepts an integer even when the hint names a closed FD and
    // atomically duplicates only a currently open descriptor. A successful
    // result is a new exclusively owned FD; no borrowed raw-FD validity or
    // caller lifetime assumption enters Rust. It is close-on-exec until the
    // checked native command explicitly retains it.
    let duplicate = unsafe { nix::libc::fcntl(descriptor, nix::libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error())
            .context("retain inherited shell source descriptor");
    }
    // SAFETY: the preceding successful atomic duplication allocated this live
    // descriptor and this function transfers its unique ownership to File.
    Ok(unsafe { fs::File::from_raw_fd(duplicate) })
}

pub(crate) fn command(
    owner_uid: u32,
    workload_name: &str,
    workload: &ResolvedWorkload,
    arguments: &[OsString],
) -> Result<std::process::Command> {
    let mut command = std::process::Command::new(&workload.launcher_path);
    let Some(selected) = selection(owner_uid, workload_name, workload)? else {
        command.args(arguments).env_remove(SOURCE_FD_ENV);
        return Ok(command);
    };
    require_native_session(owner_uid, workload_name, workload)?;
    let source = match (selected.mode, std::env::var_os(SOURCE_FD_ENV)) {
        (crate::setup::InstallMode::Strong, _) => inherited_source()?,
        (_, Some(_)) => inherited_source()?,
        (_, None) => sealed_source_for_binding(
            selected.mode,
            &selected.home,
            owner_uid,
            &selected.alias,
            &selected.binding,
        )?,
    };
    verify_descriptor(&source, owner_uid, &selected.binding)?;
    if selected.mode == crate::setup::InstallMode::UserOnly {
        return crate::smart_binding::shell::retained_shell_command(
            &selected.binding,
            source,
            arguments,
        );
    }
    crate::smart_binding::shell::attach_sealed_source(
        &mut command,
        &selected.binding,
        source,
        arguments,
    )?;
    Ok(command)
}

/// A sandbox adapter gets the checked sealed descriptor while preserving its
/// own argv. The native probe after the adapter repeats installed/session proof.
pub(crate) fn source_for_adapter(
    owner_uid: u32,
    workload_name: &str,
    workload: &ResolvedWorkload,
) -> Result<Option<fs::File>> {
    let Some(selected) = selection(owner_uid, workload_name, workload)? else {
        return Ok(None);
    };
    require_native_session(owner_uid, workload_name, workload)?;
    let source = inherited_source()?;
    verify_descriptor(&source, owner_uid, &selected.binding)?;
    Ok(Some(source))
}

fn verify_descriptor(file: &fs::File, owner_uid: u32, binding: &BindingReceipt) -> Result<()> {
    let BindingResolution::PinnedShellSource {
        source_sha256,
        source_length,
        ..
    } = &binding.active.resolved
    else {
        bail!("installed shell source is not a private reference");
    };
    let metadata = file.metadata()?;
    let seals = rustix::fs::fcntl_get_seals(file)?;
    if !metadata.is_file()
        || metadata.nlink() != 0
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() != *source_length
        || *source_length == 0
        || *source_length > 64 * 1024
        || !seals.contains(
            rustix::fs::SealFlags::SEAL
                | rustix::fs::SealFlags::SHRINK
                | rustix::fs::SealFlags::GROW
                | rustix::fs::SealFlags::WRITE,
        )
    {
        bail!("inherited shell source lacks exact sealed native custody");
    }
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0_u8; 8192];
    let mut offset = 0;
    while offset < *source_length {
        let limit = ((*source_length - offset) as usize).min(buffer.len());
        let count = file.read_at(&mut buffer[..limit], offset)?;
        if count == 0 {
            bail!("inherited shell source ended before its approved length");
        }
        hasher.update(&buffer[..count]);
        offset += count as u64;
    }
    if format!("{:x}", hasher.finalize()) != *source_sha256 {
        bail!("inherited shell source differs from its exact approved digest");
    }
    Ok(())
}

/// Caller authenticates the receiving native peer/cgroup before sending.
pub(crate) fn send_source(stream: &UnixStream, source: Option<&fs::File>) -> Result<()> {
    let mut frame = [0_u8; 6];
    frame[..5].copy_from_slice(SOURCE_FRAME);
    frame[5] = u8::from(source.is_some());
    let descriptors = source
        .map(|file| vec![file.as_raw_fd()])
        .unwrap_or_default();
    let controls = if descriptors.is_empty() {
        Vec::new()
    } else {
        vec![ControlMessage::ScmRights(&descriptors)]
    };
    let sent = sendmsg::<()>(
        stream.as_raw_fd(),
        &[IoSlice::new(&frame)],
        &controls,
        MsgFlags::MSG_NOSIGNAL,
        None,
    )?;
    if sent != frame.len() {
        bail!("native shell descriptor handoff was incomplete");
    }
    Ok(())
}

/// Caller authenticates the root dispatcher before receiving. Every delivered
/// descriptor immediately gains an RAII owner, including rejected extra FDs.
pub(crate) fn receive_source(stream: &mut UnixStream) -> Result<Option<fs::File>> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut frame = [0_u8; 6];
    // Nix refuses cmsgs() on ancillary truncation before exposing installed
    // rights. This bounded raw receive must own every complete FD first, so a
    // malformed/oversized root frame cannot leak kernel-delivered descriptors.
    const _: () =
        assert!(std::mem::align_of::<usize>() >= std::mem::align_of::<nix::libc::cmsghdr>());
    let mut ancillary = [0_usize; 32];
    let mut vector = nix::libc::iovec {
        iov_base: frame.as_mut_ptr().cast(),
        iov_len: frame.len(),
    };
    let mut message = nix::libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut vector,
        msg_iovlen: 1,
        msg_control: ancillary.as_mut_ptr().cast(),
        msg_controllen: std::mem::size_of_val(&ancillary),
        msg_flags: 0,
    };
    // SAFETY: every pointer names an initialized uniquely writable buffer of
    // the supplied length, kept alive through this syscall. The kernel writes
    // within those bounds and delivers distinct close-on-exec owned rights.
    let received = unsafe {
        nix::libc::recvmsg(
            stream.as_raw_fd(),
            &mut message,
            nix::libc::MSG_CMSG_CLOEXEC,
        )
    };
    if received < 0 {
        return Err(std::io::Error::last_os_error()).context("receive native shell source frame");
    }
    let mut descriptors = Vec::new();
    let mut invalid = false;
    let control_length = message
        .msg_controllen
        .min(std::mem::size_of_val(&ancillary));
    let base = ancillary.as_ptr().cast::<u8>();
    let mut offset = 0;
    let header_size = std::mem::size_of::<nix::libc::cmsghdr>();
    while offset <= control_length && header_size <= control_length - offset {
        // SAFETY: a complete native header lies within initialized storage;
        // unaligned reading avoids creating a foreign-layout Rust reference.
        let header =
            unsafe { std::ptr::read_unaligned(base.add(offset).cast::<nix::libc::cmsghdr>()) };
        if header.cmsg_len < header_size || header.cmsg_len > control_length - offset {
            invalid = true;
            break;
        }
        let payload = header.cmsg_len - header_size;
        if header.cmsg_level == nix::libc::SOL_SOCKET && header.cmsg_type == nix::libc::SCM_RIGHTS {
            if !payload.is_multiple_of(std::mem::size_of::<RawFd>()) {
                invalid = true;
            }
            for index in 0..payload / std::mem::size_of::<RawFd>() {
                // SAFETY: each complete native FD integer fits inside the
                // already checked payload. recvmsg allocated a distinct owned
                // descriptor for each complete SCM_RIGHTS entry.
                let descriptor = unsafe {
                    std::ptr::read_unaligned(
                        base.add(offset + header_size + index * std::mem::size_of::<RawFd>())
                            .cast::<RawFd>(),
                    )
                };
                if descriptor < 0 {
                    invalid = true;
                    continue;
                }
                // SAFETY: ownership of that newly received live FD transfers
                // exactly once to File, which closes it on every error path.
                descriptors.push(unsafe { fs::File::from_raw_fd(descriptor) });
            }
        } else {
            invalid = true;
        }
        let word = std::mem::size_of::<usize>();
        let Some(aligned) = header
            .cmsg_len
            .checked_add(word - 1)
            .map(|size| size & !(word - 1))
        else {
            invalid = true;
            break;
        };
        let Some(next) = offset.checked_add(aligned) else {
            invalid = true;
            break;
        };
        offset = next;
    }
    if invalid
        || received == 0
        || received as usize > frame.len()
        || message.msg_flags & (nix::libc::MSG_TRUNC | nix::libc::MSG_CTRUNC) != 0
    {
        bail!("native shell handoff ancillary data is invalid or truncated");
    }
    stream.read_exact(&mut frame[received as usize..])?;
    if &frame[..5] != SOURCE_FRAME || frame[5] > 1 || descriptors.len() != frame[5] as usize {
        bail!("native shell handoff frame and descriptor count differ");
    }
    descriptors
        .pop()
        .map(crate::supervisor_descriptors::normalize_source_descriptor)
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smart_binding::BindingResolution;

    fn definition() -> BindingReceipt {
        let (intent, resolved) = crate::smart_binding::pinned_shell_binding(
            "private-script",
            "fixture",
            Path::new("/usr/bin/true"),
            "printf 'fixture-only\\n'\n".into(),
            true,
            &[],
        )
        .unwrap();
        BindingReceipt::new(intent, resolved).unwrap()
    }

    #[test]
    fn installed_shell_authority_serializes_only_exact_source_identity() {
        let receipt = definition();
        let normalized = normalized_binding_receipt(&receipt).unwrap();
        let bytes = serde_jcs::to_vec(&normalized).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("fixture-only"));
        assert!(!String::from_utf8_lossy(&bytes).contains("\"source\":"));
        assert!(binding_receipt_matches(&receipt, &normalized).unwrap());
        let BindingResolution::PinnedShellSource {
            source_length,
            source_sha256,
            ..
        } = &normalized.active.resolved
        else {
            panic!("installed source must be a reference");
        };
        assert_eq!(*source_length, "printf 'fixture-only\\n'\n".len() as u64);
        assert_eq!(source_sha256.len(), 64);
        let mut altered = normalized.clone();
        if let BindingResolution::PinnedShellSource { source_sha256, .. } =
            &mut altered.active.resolved
        {
            *source_sha256 = "0".repeat(64);
        }
        assert!(crate::smart_binding::validate_binding_receipt_structure(&altered).is_err());
    }

    #[test]
    fn native_source_frame_retains_exact_sealed_owned_descriptor() {
        let receipt = definition();
        let source = crate::smart_binding::sealed_shell_source(&receipt)
            .unwrap()
            .unwrap();
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        send_source(&sender, Some(&source)).unwrap();
        let received = receive_source(&mut receiver).unwrap().unwrap();
        let normalized = normalized_binding_receipt(&receipt).unwrap();
        verify_descriptor(
            &received,
            nix::unistd::Uid::effective().as_raw(),
            &normalized,
        )
        .unwrap();
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        send_source(&sender, None).unwrap();
        assert!(receive_source(&mut receiver).unwrap().is_none());
    }

    fn matching_open_descriptors(file: &fs::File) -> usize {
        let selected = file.metadata().unwrap();
        fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| fs::metadata(entry.path()).ok())
            .filter(|metadata| metadata.dev() == selected.dev() && metadata.ino() == selected.ino())
            .count()
    }

    fn rejected_rights_frame(descriptor_count: usize) {
        let source = crate::smart_binding::sealed_shell_source(&definition())
            .unwrap()
            .unwrap();
        let before = matching_open_descriptors(&source);
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        let mut frame = [0_u8; 6];
        frame[..5].copy_from_slice(SOURCE_FRAME);
        frame[5] = 1;
        let rights = vec![source.as_raw_fd(); descriptor_count];
        assert_eq!(
            sendmsg::<()>(
                sender.as_raw_fd(),
                &[IoSlice::new(&frame)],
                &[ControlMessage::ScmRights(&rights)],
                MsgFlags::MSG_NOSIGNAL,
                None,
            )
            .unwrap(),
            frame.len()
        );
        assert!(receive_source(&mut receiver).is_err());
        assert_eq!(matching_open_descriptors(&source), before);
    }

    #[test]
    fn extra_native_source_rights_are_rejected_and_closed() {
        rejected_rights_frame(2);
    }

    #[test]
    fn truncated_native_source_rights_are_rejected_and_closed() {
        rejected_rights_frame(128);
    }

    #[test]
    fn wrong_source_body_is_rejected_even_with_native_seals_and_owner() {
        let expected = normalized_binding_receipt(&definition()).unwrap();
        let (intent, resolved) = crate::smart_binding::pinned_shell_binding(
            "private-script",
            "fixture",
            Path::new("/usr/bin/true"),
            "wrong source\n".into(),
            true,
            &[],
        )
        .unwrap();
        let wrong = BindingReceipt::new(intent, resolved).unwrap();
        let source = crate::smart_binding::sealed_shell_source(&wrong)
            .unwrap()
            .unwrap();
        assert!(
            verify_descriptor(&source, nix::unistd::Uid::effective().as_raw(), &expected).is_err()
        );
    }

    #[test]
    fn user_only_shell_retains_the_exact_native_executable_identity() {
        let mut receipt = definition();
        if let BindingResolution::PinnedShell { identity, .. } = &mut receipt.active.resolved {
            identity.inode = Some(identity.inode.unwrap().checked_add(1).unwrap());
        }
        let source = crate::smart_binding::sealed_shell_source(&receipt)
            .unwrap()
            .unwrap();
        assert!(
            crate::smart_binding::shell::retained_shell_command(&receipt, source, &[]).is_err()
        );
    }
}
