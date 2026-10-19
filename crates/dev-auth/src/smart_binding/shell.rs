//! Private descriptor transport for an already approved public shell definition.
//! The caller owns installed receipt custody, exact shell execution identity,
//! native admission and its command's cwd/environment/streams/lifetime.
use super::*;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;

/// Attach source as sealed nonexecutable data. This supplies no admission or
/// permission and never turns mutable code into a pinned shell definition.
pub fn attach_source(
    command: &mut std::process::Command,
    receipt: &BindingReceipt,
    caller_arguments: &[OsString],
) -> Result<()> {
    validate_binding_receipt_structure(receipt)?;
    if command.get_program()
        != receipt
            .active
            .resolved
            .identity()
            .canonical_path
            .as_os_str()
    {
        bail!("public shell source requires the exact selected shell command");
    }
    let source = sealed_shell_source(receipt)?.context("binding has no public shell definition")?;
    attach_sealed_source(command, receipt, source, caller_arguments)
}

/// The native owner separately proves installed receipt custody, exact source
/// digest/length/seals and admission before entering this transport boundary.
pub(crate) fn attach_sealed_source(
    command: &mut std::process::Command,
    receipt: &BindingReceipt,
    source: fs::File,
    caller_arguments: &[OsString],
) -> Result<()> {
    validate_binding_receipt_structure(receipt)?;
    if !is_pinned_shell_resolution(&receipt.active.resolved)
        || command.get_program()
            != receipt
                .active
                .resolved
                .identity()
                .canonical_path
                .as_os_str()
    {
        bail!("private shell source requires the exact selected shell command");
    }
    append_source(command, source, caller_arguments)
}

/// User-only shell execution retains the exact administrator-selected shell
/// inode and bytes; package replacement cannot change a pinned definition.
pub(crate) fn retained_shell_command(
    receipt: &BindingReceipt,
    source: fs::File,
    caller_arguments: &[OsString],
) -> Result<std::process::Command> {
    validate_binding_receipt_structure(receipt)?;
    if !is_pinned_shell_resolution(&receipt.active.resolved) {
        bail!("retained shell command requires a pinned shell definition");
    }
    let identity = receipt.active.resolved.identity();
    let held = retain_binding_executable(identity)?;
    let mut command = held.into_command_above(
        identity.canonical_path.as_os_str(),
        crate::supervisor_descriptors::MIN_EXECUTABLE_DESCRIPTOR,
    )?;
    append_source(&mut command, source, caller_arguments)?;
    Ok(command)
}

fn append_source(
    command: &mut std::process::Command,
    source: fs::File,
    caller_arguments: &[OsString],
) -> Result<()> {
    let source = crate::supervisor_descriptors::normalize_source_descriptor(source)?;
    let descriptor = source.as_raw_fd();
    command
        .arg(format!("/proc/self/fd/{descriptor}"))
        .args(caller_arguments);
    for name in ["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "ZDOTDIR"] {
        command.env_remove(name);
    }
    retain_descriptor(command, source)?;
    Ok(())
}

pub(crate) fn retain_descriptor(
    command: &mut std::process::Command,
    source: fs::File,
) -> Result<()> {
    let source = crate::supervisor_descriptors::normalize_source_descriptor(source)?;
    let descriptor = source.as_raw_fd();
    command.env(
        crate::binding_activation::launch_shell::SOURCE_FD_ENV,
        descriptor.to_string(),
    );
    // SAFETY: the closure owns the sealed file for as long as Command stores
    // it and across fork until exec. fcntl is async-signal-safe, takes no Rust
    // pointers and clears close-on-exec only for this still-owned descriptor.
    // Child exec failure reaches std::process's established error reporting.
    // No source string, allocation or ambient environment read occurs here.
    unsafe {
        command.pre_exec(move || {
            let _keep_alive = &source;
            if nix::libc::fcntl(descriptor, nix::libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}
