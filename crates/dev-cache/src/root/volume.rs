//! Native volume evidence, independent of mount paths and transient Unix device
//! allocation. Unknown filesystem contracts retain the legacy fail-closed check.
use std::path::Path;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Context;
use anyhow::{bail, Result};

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Observation {
    pub device: String,
    pub stable: Option<String>,
}

pub(super) fn observe(path: &Path) -> Result<Observation> {
    let device = super::volume_identity(path)?;
    Ok(Observation {
        stable: stable_identity(path, &device)?,
        device,
    })
}

#[cfg(target_os = "linux")]
fn stable_identity(path: &Path, _: &str) -> Result<Option<String>> {
    use std::os::fd::AsRawFd;

    let directory = std::fs::File::open(path).context("open cache volume for observation")?;
    let mut native = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let mut portable = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: the retained file descriptor is live; each output points to an
    // aligned allocation of the exact libc target type. No output is read
    // unless its successful syscall initialized it.
    if unsafe { libc::fstatfs(directory.as_raw_fd(), native.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("observe cache filesystem type");
    }
    // SAFETY: same live descriptor and exact writable libc output contract.
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), portable.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("observe cache filesystem identity");
    }
    // SAFETY: both preceding calls succeeded and initialized their outputs.
    let (native, portable) = unsafe { (native.assume_init(), portable.assume_init()) };
    let kind = native.f_type as u32;
    // These Linux filesystems supply a filesystem/superblock ID rather than
    // st_dev. tmpfs/overlay IDs identify that instance, not recreated storage.
    // Other native filesystem contracts are not guessed into equivalence.
    if !matches!(
        kind,
        0xef53 | 0x58465342 | 0x9123683e | 0xf2f52010 | 0x2fc12fc1 | 0x01021994 | 0x794c7630
    ) || portable.f_fsid == 0
    {
        return Ok(None);
    }
    Ok(Some(format!(
        "linux-fsid:{kind:08x}:{:016x}",
        portable.f_fsid
    )))
}

#[cfg(target_os = "macos")]
fn stable_identity(path: &Path, _: &str) -> Result<Option<String>> {
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .context("cache volume path contains NUL")?;
    let mut attributes = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: 0,
        volattr: libc::ATTR_VOL_INFO | libc::ATTR_VOL_UUID,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    // The selected fixed attribute is a native u32 length followed by 16 UUID
    // bytes; byte decoding avoids an alignment or padding assumption.
    let mut output = [0_u8; 20];
    // SAFETY: the path is NUL-terminated, attrlist matches libc's ABI, and the
    // writable output remains live for its stated capacity. No pointers escape.
    let result = unsafe {
        libc::getattrlist(
            path.as_ptr(),
            (&mut attributes as *mut libc::attrlist).cast(),
            output.as_mut_ptr().cast(),
            output.len(),
            0,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ENOTSUP | libc::EINVAL)) {
            return Ok(None);
        }
        return Err(error).context("observe native volume UUID");
    }
    if u32::from_ne_bytes([output[0], output[1], output[2], output[3]]) != 20 {
        bail!("native volume UUID has an unexpected attribute length");
    }
    if output[4..].iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    Ok(Some(format!(
        "macos-volume-uuid:{}",
        output[4..]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )))
}

#[cfg(windows)]
fn stable_identity(_: &Path, device: &str) -> Result<Option<String>> {
    // The existing Win32 observation is already the filesystem volume serial,
    // not a drive letter or transient device enumeration number.
    Ok(Some(device.to_owned()))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn stable_identity(_: &Path, _: &str) -> Result<Option<String>> {
    Ok(None)
}

pub(super) fn validate(marker: &super::RootMarker, current: &Observation) -> Result<()> {
    if let Some(expected) = &marker.stable_volume_identity {
        if current.stable.as_ref() != Some(expected) {
            bail!("cache-root filesystem identity changed or is unavailable; refusing automatic adoption");
        }
    } else if marker.volume_identity != current.device {
        bail!(
            "cache-root volume changed; expected {}, found {}; the legacy marker has no stable filesystem evidence for automatic repair",
            marker.volume_identity,
            current.device
        );
    }
    Ok(())
}
