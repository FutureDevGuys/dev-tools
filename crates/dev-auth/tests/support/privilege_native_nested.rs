//! An ungranted nested mount, prepared only by the disposable root fault driver.
use super::*;
use std::ffi::CString;

const SENTINEL: &[u8] = b"ungranted-native-mount-sentinel\n";
#[repr(C)]
struct Attributes {
    set: u64,
    clear: u64,
    propagation: u64,
    userns: u64,
}
struct Mounted {
    tree: OwnedFd,
    attached: bool,
}
impl Mounted {
    fn detach(&mut self) -> Result<()> {
        if self.attached {
            let path = CString::new(format!("/proc/self/fd/{}", self.tree.as_raw_fd()))?;
            if unsafe { nix::libc::umount2(path.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            self.attached = false;
        }
        Ok(())
    }
}
impl Drop for Mounted {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}
pub(super) fn run(input: &Input, root: &File, owner: u32) -> Result<()> {
    let source = tempfile::Builder::new()
        .prefix("dev-auth-privilege-native-sentinel-")
        .tempdir_in("/var/tmp")?;
    let mut sentinel = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(source.path().join("sentinel"))?;
    sentinel.write_all(SENTINEL)?;
    sentinel.sync_all()?;
    let source_fd = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(source.path())?;
    let scope_fd = rustix::fs::openat(
        root,
        "scope",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let scope = File::from(scope_fd);
    if scope.metadata()?.uid() != owner || scope.metadata()?.mode() & 0o7777 != 0o700 {
        bail!("nested fixture scope custody differs");
    }
    rustix::fs::mkdirat(&scope, "nested", rustix::fs::Mode::from_raw_mode(0o700))?;
    let target = rustix::fs::openat(
        &scope,
        "nested",
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    // All mount authority comes from retained fds. There is no caller pathname
    // resolution at publication, including if the caller renames its scope.
    let fd = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_open_tree,
            source_fd.as_raw_fd(),
            c"".as_ptr(),
            1u32 | nix::libc::O_CLOEXEC as u32 | nix::libc::AT_EMPTY_PATH as u32,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut mounted = Mounted {
        tree: unsafe { OwnedFd::from_raw_fd(fd as i32) },
        attached: false,
    };
    let attributes = Attributes {
        set: 0x1 | 0x2 | 0x4,
        clear: 0,
        propagation: nix::libc::MS_PRIVATE,
        userns: 0,
    };
    if unsafe {
        nix::libc::syscall(
            nix::libc::SYS_mount_setattr,
            mounted.tree.as_raw_fd(),
            c"".as_ptr(),
            nix::libc::AT_EMPTY_PATH,
            &attributes,
            std::mem::size_of::<Attributes>(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe {
        nix::libc::syscall(
            nix::libc::SYS_move_mount,
            mounted.tree.as_raw_fd(),
            c"".as_ptr(),
            target.as_raw_fd(),
            c"".as_ptr(),
            0x4u32 | 0x40u32,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    mounted.attached = true;
    // Positive control: the service manager must see this very mounted inode.
    // A driver-private mount namespace would make even recursive buggy cloning
    // appear safe, so reject it before requesting a grant.
    let driver_ns = fs::metadata("/proc/self/ns/mnt")?;
    let manager_ns = fs::metadata("/proc/1/ns/mnt")?;
    if (driver_ns.dev(), driver_ns.ino()) != (manager_ns.dev(), manager_ns.ino()) {
        bail!("nested mount driver does not share the native service manager mount view");
    }
    let view_path = Path::new("/proc/1/root")
        .join(input.fixture_root.strip_prefix("/")?)
        .join("scope/nested/sentinel");
    let mut visible = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(view_path)?;
    let expected = sentinel.metadata()?;
    let observed = visible.metadata()?;
    if (observed.dev(), observed.ino()) != (expected.dev(), expected.ino()) {
        bail!("native service manager view does not contain the exact mounted sentinel");
    }
    let mut bytes = Vec::new();
    (&mut visible)
        .take(SENTINEL.len() as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes != SENTINEL {
        bail!("native nested mount positive control differs");
    }
    write_at(root, "fault-driver-ready", input.case.name().as_bytes())?;
    let until = Instant::now() + Duration::from_secs(130);
    let session = loop {
        if let Ok(bytes) = read_at(root, "session") {
            if let Ok(session) = String::from_utf8(bytes) {
                if protocol::token(&session).is_ok() {
                    break session;
                }
            }
        }
        ensure_before(until)?;
        pause();
    };
    write_at(root, "fault-applied", input.case.name().as_bytes())?;
    let terminal = Instant::now() + Duration::from_secs(85);
    while read_at(root, "observer-cleanup").ok().as_deref() != Some(session.as_bytes()) {
        ensure_before(terminal)?;
        pause();
    }
    if fs::read(source.path().join("sentinel"))? != SENTINEL {
        bail!("ungranted nested sentinel was modified");
    }
    mounted.detach()?;
    // Remove only the exact empty fixture mountpoint; never recursively clean a
    // caller resource or erase unexpected data after a failed negative probe.
    let named = rustix::fs::statat(&scope, "nested", rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
    let held = rustix::fs::fstat(&target)?;
    if (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino) {
        bail!("nested fixture mountpoint identity changed");
    }
    rustix::fs::unlinkat(&scope, "nested", rustix::fs::AtFlags::REMOVEDIR)?;
    write_at(root, "fault-driver-passed", input.case.name().as_bytes())?;
    Ok(())
}
