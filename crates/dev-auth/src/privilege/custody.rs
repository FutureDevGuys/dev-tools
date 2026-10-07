//! Product-owned file and executable custody. No caller path grants privilege.
use super::policy;
use anyhow::{bail, Context, Result};
use dev_tools_command::{HeldComponentKind, HeldExecutable};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

pub use crate::setup::maintenance::{HELPER_PATH, POLICY_PATH, POLKIT, POLKIT_PATH, RECEIPT_PATH};
pub const RUNTIME_PATH: &str = "/run/dev-auth-privilege";

pub fn read_document(path: &Path, owner: u32, mode: u32) -> Result<Vec<u8>> {
    validate_parents(path, owner, owner != 0)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != owner
        || before.nlink() != 1
        || before.mode() & 0o7777 != mode
        || before.len() == 0
        || before.len() as usize > policy::DOCUMENT_LIMIT
    {
        bail!("administrative document custody is invalid");
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(policy::DOCUMENT_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if bytes.len() > policy::DOCUMENT_LIMIT
        || identity(&before) != identity(&after)
        || identity(&after) != identity(&named)
        || after.mtime_nsec() != before.mtime_nsec()
        || after.mtime() != before.mtime()
        || after.ctime() != before.ctime()
        || after.ctime_nsec() != before.ctime_nsec()
    {
        bail!("administrative document changed while observed");
    }
    Ok(bytes)
}

pub fn write_new_document(path: &Path, bytes: &[u8], owner: u32) -> Result<()> {
    if owner != nix::unistd::geteuid().as_raw()
        || bytes.is_empty()
        || bytes.len() > policy::DOCUMENT_LIMIT
    {
        bail!("administrative output ownership or size is invalid");
    }
    validate_parents(path, owner, owner != 0)?;
    let parent = path
        .parent()
        .context("administrative output has no parent")?;
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700 {
        bail!("administrative output requires an existing private parent");
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn policy_bytes() -> Result<Vec<u8>> {
    read_document(Path::new(POLICY_PATH), 0, 0o644)
}

pub fn validate_parents(path: &Path, owner: u32, allow_sticky: bool) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        bail!("administrative path is not canonical");
    }
    let mut current = PathBuf::new();
    let mut parts = path.components().peekable();
    while let Some(part) = parts.next() {
        current.push(part.as_os_str());
        if parts.peek().is_none() {
            break;
        }
        let metadata = fs::symlink_metadata(&current)?;
        let sticky = allow_sticky && metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || ![0, owner].contains(&metadata.uid())
            || metadata.mode() & 0o022 != 0 && !sticky
        {
            bail!("administrative ancestor custody is invalid");
        }
    }
    Ok(())
}

pub fn held_root_executable(path: &Path, expected: &str) -> Result<HeldExecutable> {
    policy::hex_digest(expected)?;
    let held = HeldExecutable::open_with_validation(path, |fd, kind| {
        let stat = rustix::fs::fstat(fd)?;
        if stat.st_uid != 0
            || stat.st_mode & 0o022 != 0
            || stat.st_mode & 0o7000 != 0
            || kind == HeldComponentKind::Executable && stat.st_nlink != 1
        {
            bail!("administrative executable custody is invalid");
        }
        Ok(())
    })?;
    let mut source = held.open_read_handle()?;
    // Ambient capability preservation requires an ordinary ELF with no file
    // capability transition. Query the held readable inode, never its name.
    let attribute = std::ffi::CString::new("security.capability")?;
    let attribute_length = unsafe {
        nix::libc::fgetxattr(
            source.as_raw_fd(),
            attribute.as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if attribute_length >= 0
        || std::io::Error::last_os_error().raw_os_error() != Some(nix::libc::ENODATA)
    {
        bail!("administrative executable has unsupported file capabilities");
    }
    let before = source.metadata()?;
    if before.len() > 256 * 1024 * 1024 {
        bail!("administrative executable exceeds bounds");
    }
    let mut bytes = Vec::new();
    (&mut source)
        .take(256 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let after = source.metadata()?;
    if !bytes.starts_with(b"\x7fELF")
        || policy::digest(&bytes) != expected
        || identity(&before) != identity(&after)
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        bail!("administrative executable identity changed or is not native");
    }
    Ok(held)
}

pub fn installation_identity() -> Result<String> {
    crate::setup::maintenance_installation_identity()
}

pub fn random_id() -> Result<String> {
    let mut bytes = [0; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDescriptor {
    pub name: String,
    pub path: PathBuf,
    pub fd: i32,
    pub device: u64,
    pub inode: u64,
    pub owner: u32,
    pub mode: u32,
    pub links: u64,
}

pub struct HeldResource {
    pub path: PathBuf,
    pub descriptor: OwnedFd,
    identity: (u64, u64, u32, u32, u64),
}
impl HeldResource {
    pub fn open(path: &Path, owner: u32) -> Result<Self> {
        let fd = open_resource_path(path, owner)?;
        let stat = rustix::fs::fstat(&fd)?;
        let kind = rustix::fs::FileType::from_raw_mode(stat.st_mode);
        if !matches!(
            kind,
            rustix::fs::FileType::Directory | rustix::fs::FileType::RegularFile
        ) || ![0, owner].contains(&stat.st_uid)
            || stat.st_mode & 0o022 != 0
        {
            bail!("administrative resource custody is unsafe");
        }
        let this = Self {
            path: path.into(),
            descriptor: fd,
            identity: (
                stat.st_dev,
                stat.st_ino,
                stat.st_uid,
                stat.st_mode,
                if kind == rustix::fs::FileType::Directory {
                    0
                } else {
                    stat.st_nlink
                },
            ),
        };
        this.verify()?;
        Ok(this)
    }
    pub fn inherited(capsule: &ResourceDescriptor) -> Result<Self> {
        if capsule.fd < 3 {
            bail!("administrative resource descriptor is invalid");
        }
        let flags = unsafe { nix::libc::fcntl(capsule.fd, nix::libc::F_GETFL) };
        if flags < 0 || flags & nix::libc::O_PATH == 0 {
            bail!("administrative resource descriptor is not an identity handle");
        }
        // The dedicated helper owns inherited descriptors from its sealed capsule.
        let fd = unsafe { OwnedFd::from_raw_fd(capsule.fd) };
        rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
        let held = Self {
            path: capsule.path.clone(),
            descriptor: fd,
            identity: (
                capsule.device,
                capsule.inode,
                capsule.owner,
                capsule.mode,
                capsule.links,
            ),
        };
        held.verify()?;
        Ok(held)
    }
    pub fn transfer(&self, name: &str) -> Result<(ResourceDescriptor, OwnedFd)> {
        self.verify()?;
        let fd = rustix::io::fcntl_dupfd_cloexec(&self.descriptor, 3)?;
        let capsule = ResourceDescriptor {
            name: name.into(),
            path: self.path.clone(),
            fd: fd.as_raw_fd(),
            device: self.identity.0,
            inode: self.identity.1,
            owner: self.identity.2,
            mode: self.identity.3,
            links: self.identity.4,
        };
        Ok((capsule, fd))
    }
    pub fn verify(&self) -> Result<()> {
        let held = rustix::fs::fstat(&self.descriptor)?;
        let named = fs::symlink_metadata(&self.path)?;
        if self.identity
            != (
                held.st_dev,
                held.st_ino,
                held.st_uid,
                held.st_mode,
                if rustix::fs::FileType::from_raw_mode(held.st_mode)
                    == rustix::fs::FileType::Directory
                {
                    0
                } else {
                    held.st_nlink
                },
            )
            || self.identity
                != (
                    named.dev(),
                    named.ino(),
                    named.uid(),
                    named.mode(),
                    if named.is_dir() { 0 } else { named.nlink() },
                )
        {
            bail!("administrative resource identity changed");
        }
        Ok(())
    }
    pub fn is_directory(&self) -> Result<bool> {
        Ok(
            rustix::fs::FileType::from_raw_mode(
                rustix::fs::fstat(self.descriptor.as_fd())?.st_mode,
            ) == rustix::fs::FileType::Directory,
        )
    }
}

fn identity(m: &fs::Metadata) -> (u64, u64, u32, u32, u64, u64) {
    (m.dev(), m.ino(), m.uid(), m.mode(), m.nlink(), m.len())
}

/// Lightweight observation after complete receipt/content validation. It never
/// treats metadata alone as initial executable authority.
pub struct IdentityWatch {
    path: PathBuf,
    snapshot: (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64),
    link: Option<PathBuf>,
}
impl IdentityWatch {
    pub fn root(path: &Path, allow_symlink: bool) -> Result<Self> {
        validate_parents(path, 0, false)?;
        let metadata = fs::symlink_metadata(path)?;
        if metadata.uid() != 0
            || !metadata.file_type().is_symlink() && metadata.mode() & 0o022 != 0
            || metadata.file_type().is_symlink() && !allow_symlink
        {
            bail!("administrative authority watch has unsafe custody");
        }
        let link = if metadata.file_type().is_symlink() {
            Some(fs::read_link(path)?)
        } else {
            None
        };
        Ok(Self {
            path: path.into(),
            snapshot: watch_identity(&metadata),
            link,
        })
    }
    pub fn verify(&self) -> Result<()> {
        let metadata = fs::symlink_metadata(&self.path)?;
        let link = if metadata.file_type().is_symlink() {
            Some(fs::read_link(&self.path)?)
        } else {
            None
        };
        if watch_identity(&metadata) != self.snapshot || link != self.link {
            bail!("retained administrative authority changed");
        }
        Ok(())
    }
}
fn watch_identity(m: &fs::Metadata) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

// Every component is opened relative to the already-held parent. An lstat pass
// followed by one absolute open would permit a same-user ancestor-symlink race.
fn open_resource_path(path: &Path, owner: u32) -> Result<OwnedFd> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        bail!("administrative resource path is invalid");
    }
    let mut current = rustix::fs::open(
        "/",
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let components = path
        .components()
        .filter_map(|c| {
            if let Component::Normal(name) = c {
                Some(name)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if components.is_empty() || components.len() > 64 {
        bail!("administrative resource path exceeds bounds");
    }
    for (index, name) in components.iter().enumerate() {
        let final_component = index + 1 == components.len();
        let flags = rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | if final_component {
                rustix::fs::OFlags::empty()
            } else {
                rustix::fs::OFlags::DIRECTORY
            };
        let next = rustix::fs::openat(&current, *name, flags, rustix::fs::Mode::empty())?;
        let metadata = rustix::fs::fstat(&next)?;
        let kind = rustix::fs::FileType::from_raw_mode(metadata.st_mode);
        let sticky = !final_component && metadata.st_uid == 0 && metadata.st_mode & 0o1000 != 0;
        if ![0, owner].contains(&metadata.st_uid)
            || metadata.st_mode & 0o022 != 0 && !sticky
            || !matches!(
                kind,
                rustix::fs::FileType::Directory | rustix::fs::FileType::RegularFile
            )
        {
            bail!("administrative resource ancestor custody is invalid");
        }
        current = next;
    }
    Ok(current)
}
