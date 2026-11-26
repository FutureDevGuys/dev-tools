//! Windows custody primitives for overlay transactions.
//!
//! No directory handle is retained: a held directory handle would have to deny
//! write sharing to be meaningful, and Windows opens the directory for writing
//! during a rename. The selected directory is instead identified by volume
//! serial and file index and revalidated by pathname around every operation.
//! Reparse points are never followed. Publication writes a private temporary
//! beside the leaf, flushes it, and replaces the leaf with a write-through
//! `MoveFileExW`. Ownership and ACLs are not audited; leaves inherit the
//! parent's ACL, and the journal's mode/group fields carry fixed values.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use dev_tools_installation::{
    ArtifactIdentity, AtomicDocument, DocumentAuthority, FileAuthority, InstallationLock,
};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorControl, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileIdInfo, FindClose, FindFirstFileW, GetFileInformationByHandle,
    GetFileInformationByHandleEx, MoveFileExW, BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE, FILE_ID_INFO, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    READ_CONTROL, WIN32_FIND_DATAW, WRITE_DAC, WRITE_OWNER,
};

use super::{ParentIdentity, FILE_LIMIT, PREFIX};
use dev_tools_command::windows_path::is_reserved_device_stem;

pub(super) const MAX_NATIVE_PATH: usize = 32768;
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

pub(super) fn uid() -> u32 {
    0
}

pub(super) fn gid() -> u32 {
    0
}

/// Volume serial plus the 128-bit file id; the 64-bit file index is not unique
/// on ReFS.
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileId {
    volume: u64,
    id: [u8; 16],
}

impl FileId {
    /// The journal's 64-bit fingerprint. Live checks compare the full id; for
    /// NTFS (high half zero) this is the file index itself.
    fn fingerprint(self) -> ParentIdentity {
        let (mut low, mut high) = ([0; 8], [0; 8]);
        low.copy_from_slice(&self.id[..8]);
        high.copy_from_slice(&self.id[8..]);
        ParentIdentity {
            device: self.volume,
            inode: u64::from_le_bytes(low) ^ u64::from_le_bytes(high),
        }
    }
}

struct Observed {
    id: FileId,
    attributes: u32,
    links: u32,
    size: u64,
    written: u64,
}

fn observe_handle(file: &File) -> io::Result<Observed> {
    // SAFETY: the handle is live for the call and the all-zero struct is a
    // valid out-parameter for this plain-data Win32 type.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above; FILE_ID_INFO is plain data and its exact size is passed.
    let mut id: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileIdInfo,
            std::ptr::addr_of_mut!(id).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(Observed {
        id: FileId {
            volume: id.VolumeSerialNumber,
            id: id.FileId.Identifier,
        },
        attributes: info.dwFileAttributes,
        links: info.nNumberOfLinks,
        size: u64::from(info.nFileSizeHigh) << 32 | u64::from(info.nFileSizeLow),
        written: u64::from(info.ftLastWriteTime.dwHighDateTime) << 32
            | u64::from(info.ftLastWriteTime.dwLowDateTime),
    })
}

fn open_no_follow(path: &Path, directory: bool, write: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).share_mode(SHARE_ALL);
    options.custom_flags(
        FILE_FLAG_OPEN_REPARSE_POINT
            | if directory {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                0
            },
    );
    if write {
        options.write(true);
    }
    options.open(path)
}

fn is_reparse(metadata: &Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn directory_identity(path: &Path) -> Result<FileId> {
    let observed = observe_handle(&open_no_follow(path, true, false)?)?;
    if observed.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || observed.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        bail!("selected document directory is not a real directory");
    }
    Ok(observed.id)
}

pub(super) fn prepare(parent_path: &Path) -> Result<(Directory, ParentIdentity)> {
    fs::create_dir_all(parent_path).context("prepare overlay directory")?;
    let id = directory_identity(parent_path)?;
    Ok((
        Directory {
            path: parent_path.to_path_buf(),
            id,
        },
        id.fingerprint(),
    ))
}

fn validate_name(name: &OsStr) -> Result<()> {
    let text = name.to_string_lossy();
    let stem = text
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ')
        .to_uppercase();
    if text.is_empty()
        || text == "."
        || text == ".."
        || text.ends_with(['.', ' '])
        || text.chars().any(|c| c < ' ' || "\\/:*?\"<>|".contains(c))
        || is_reserved_device_stem(&stem)
    {
        bail!("overlay leaf name is not a plain Windows file name");
    }
    Ok(())
}

fn identity_of(bytes: &[u8]) -> ArtifactIdentity {
    ArtifactIdentity {
        length: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// Retry a bounded number of times on the transient denials that antivirus and
/// indexers cause, returning the last error.
fn retry<T>(mut operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let mut delay = 10;
    for _ in 0..4 {
        match operation() {
            Err(error)
                if matches!(
                    error.raw_os_error().map(|code| code as u32),
                    Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION)
                ) =>
            {
                std::thread::sleep(std::time::Duration::from_millis(delay));
                delay *= 2;
            }
            other => return other,
        }
    }
    operation()
}

/// Give the staged file the replaced file's owner and DACL, so a narrowed
/// target never becomes readable by more principals.
fn copy_security(from: &File, to: &File) -> io::Result<()> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the handle is live and every out-pointer is valid for the call.
    let status = unsafe {
        GetSecurityInfo(
            from.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: `descriptor` was returned by GetSecurityInfo and is freed once.
    let result =
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            let protection = if control & SE_DACL_PROTECTED != 0 {
                PROTECTED_DACL_SECURITY_INFORMATION
            } else {
                UNPROTECTED_DACL_SECURITY_INFORMATION
            };
            // SAFETY: owner and dacl point into `descriptor`, which is still live.
            let status = unsafe {
                SetSecurityInfo(
                    to.as_raw_handle() as HANDLE,
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | protection,
                    owner,
                    std::ptr::null_mut(),
                    dacl,
                    std::ptr::null_mut(),
                )
            };
            if status == 0 {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(status as i32))
            }
        };
    // SAFETY: allocated by GetSecurityInfo with LocalAlloc.
    unsafe { LocalFree(descriptor) };
    result
}

/// Refuse a spelling that is not the leaf's real long name (8.3 short name or
/// another case): lock and journal identity are keyed on the exact name.
/// `FindFirstFileW` reports the stored name without following the leaf.
fn require_exact_name(path: &Path, name: &OsStr) -> Result<()> {
    // SAFETY: all-zero is a valid out-parameter for this plain-data type.
    let mut found: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    // SAFETY: the path is NUL-terminated and `found` is valid for the call.
    let handle = unsafe { FindFirstFileW(wide(path).as_ptr(), &mut found) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error()).context("resolve the leaf's real name");
    }
    // SAFETY: the handle came from FindFirstFileW and is closed once.
    unsafe { FindClose(handle) };
    let length = found
        .cFileName
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(found.cFileName.len());
    if found.cFileName[..length] != name.encode_wide().collect::<Vec<_>>()[..] {
        bail!("overlay leaf is not spelled as its real file name");
    }
    Ok(())
}

/// A selected existing directory, identified by volume serial and file id.
pub(super) struct Directory {
    path: PathBuf,
    id: FileId,
}

impl Directory {
    fn validate(&self) -> Result<()> {
        if directory_identity(&self.path)? != self.id {
            bail!("selected document directory changed or has unsafe custody");
        }
        Ok(())
    }

    fn sync(&self) -> Result<()> {
        open_no_follow(&self.path, true, true)
            .and_then(|directory| directory.sync_all())
            .context("sync overlay directory")
    }

    pub(super) fn metadata(&self, name: &OsStr) -> Result<Option<Metadata>> {
        validate_name(name)?;
        self.validate()?;
        let metadata = match fs::symlink_metadata(self.path.join(name)) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("inspect selected entry"),
        };
        if metadata.is_some() {
            require_exact_name(&self.path.join(name), name)?;
        }
        self.validate()?;
        Ok(metadata)
    }

    fn read_regular(
        &self,
        name: &OsStr,
        limit: u64,
        allow_empty: bool,
    ) -> Result<Option<AtomicDocument>> {
        validate_name(name)?;
        self.validate()?;
        let path = self.path.join(name);
        let mut file = match open_no_follow(&path, false, false) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("open held document"),
        };
        require_exact_name(&path, name)?;
        let before = observe_handle(&file)?;
        if before.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || before.links != 1
            || before.size > limit
            || (!allow_empty && before.size == 0)
        {
            bail!("held document has unsafe custody or content bounds");
        }
        let mut bytes = Vec::new();
        (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
        let after = observe_handle(&file)?;
        let named = observe_handle(&open_no_follow(&path, false, false)?)?;
        if bytes.len() as u64 != before.size
            || before.id != after.id
            || before.size != after.size
            || before.written != after.written
            || named.id != before.id
        {
            bail!("held document changed while being read");
        }
        self.validate()?;
        let identity = identity_of(&bytes);
        Ok(Some(AtomicDocument { bytes, identity }))
    }

    fn publish(
        &self,
        name: &OsStr,
        bytes: &[u8],
        limit: u64,
        allow_empty: bool,
        expected: Option<&ArtifactIdentity>,
    ) -> Result<bool> {
        validate_name(name)?;
        if bytes.len() as u64 > limit || (!allow_empty && bytes.is_empty()) {
            bail!("held document exceeds its content bounds");
        }
        let current = self.read_regular(name, limit, true)?;
        match (
            current.as_ref().map(|document| &document.identity),
            expected,
        ) {
            (Some(current), Some(expected)) if current == expected => {}
            (None, None) => {}
            _ => bail!("held document differs from its expected identity"),
        }
        let destination = self.path.join(name);
        let temporary = self
            .path
            .join(format!("{PREFIX}tmp-{}", uuid::Uuid::new_v4().simple()));
        let mut file = OpenOptions::new()
            .access_mode(FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC | WRITE_OWNER)
            .create_new(true)
            .share_mode(0)
            .open(&temporary)
            .context("create overlay staging file")?;
        let staged = (|| {
            if expected.is_some() {
                copy_security(&open_no_follow(&destination, false, false)?, &file)?;
            }
            file.write_all(bytes)?;
            file.sync_all()
        })();
        drop(file);
        let published = staged.and_then(|()| {
            let mut flags = MOVEFILE_WRITE_THROUGH;
            if expected.is_some() {
                flags |= MOVEFILE_REPLACE_EXISTING;
            }
            retry(|| {
                // SAFETY: both arguments are NUL-terminated and outlive the call.
                let moved = unsafe {
                    MoveFileExW(
                        wide(&temporary).as_ptr(),
                        wide(&destination).as_ptr(),
                        flags,
                    )
                };
                if moved == 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            })
        });
        if let Err(error) = published {
            let _ = fs::remove_file(&temporary);
            return Err(error).context("publish overlay file");
        }
        // WRITE_THROUGH does not flush a same-volume rename's directory entry.
        self.sync()?;
        self.validate()?;
        Ok(true)
    }

    fn remove_regular(
        &self,
        name: &OsStr,
        limit: u64,
        allow_empty: bool,
        expected: &ArtifactIdentity,
    ) -> Result<bool> {
        if (!allow_empty && expected.length == 0) || expected.length > limit {
            bail!("held document removal identity is invalid");
        }
        let current = self.read_regular(name, limit, allow_empty)?;
        if let Some(current) = &current {
            if current.identity != *expected {
                bail!("held document removal does not match expected content");
            }
            retry(|| fs::remove_file(self.path.join(name)))
                .context("remove exact held document")?;
        }
        self.sync()?;
        self.validate()?;
        if fs::symlink_metadata(self.path.join(name)).is_ok() {
            bail!("held document reappeared after removal");
        }
        Ok(current.is_some())
    }

    pub(super) fn read_file_with_group(
        &self,
        name: &OsStr,
        authority: &FileAuthority,
    ) -> Result<Option<AtomicDocument>> {
        self.read_regular(name, authority.limit, true)
    }

    pub(super) fn write_file_with_group(
        &self,
        name: &OsStr,
        bytes: &[u8],
        authority: &FileAuthority,
        expected_current: Option<&ArtifactIdentity>,
    ) -> Result<bool> {
        self.publish(name, bytes, authority.limit, true, expected_current)
    }

    pub(super) fn remove_file_with_group(
        &self,
        name: &OsStr,
        authority: &FileAuthority,
        expected: &ArtifactIdentity,
    ) -> Result<bool> {
        self.remove_regular(name, authority.limit, true, expected)
    }

    pub(super) fn read(
        &self,
        name: &OsStr,
        authority: &DocumentAuthority,
    ) -> Result<Option<AtomicDocument>> {
        self.read_regular(name, authority.limit, false)
    }

    pub(super) fn write(
        &self,
        name: &OsStr,
        bytes: &[u8],
        authority: &DocumentAuthority,
        expected_current: Option<&ArtifactIdentity>,
    ) -> Result<bool> {
        self.publish(name, bytes, authority.limit, false, expected_current)
    }

    pub(super) fn remove(
        &self,
        name: &OsStr,
        authority: &DocumentAuthority,
        expected: &ArtifactIdentity,
    ) -> Result<bool> {
        self.remove_regular(name, authority.limit, false, expected)
    }

    pub(super) fn read_symbolic_link(&self, name: &OsStr) -> Result<Option<PathBuf>> {
        let Some(metadata) = self.metadata(name)? else {
            return Ok(None);
        };
        if !metadata.file_type().is_symlink() {
            bail!("selected entry is not a symbolic link");
        }
        let target = fs::read_link(self.path.join(name)).context("read selected link")?;
        if target.as_os_str().is_empty() || target.as_os_str().len() > MAX_NATIVE_PATH {
            bail!("selected link target exceeds transaction bounds");
        }
        Ok(Some(target))
    }

    pub(super) fn remove_symbolic_link(
        &self,
        name: &OsStr,
        expected_target: &Path,
    ) -> Result<bool> {
        let removed = match self.read_symbolic_link(name)? {
            Some(target) => {
                if target.as_os_str() != expected_target.as_os_str() {
                    bail!("held symbolic link differs from its expected raw target");
                }
                let path = self.path.join(name);
                if fs::symlink_metadata(&path)?.file_type().is_symlink_dir() {
                    fs::remove_dir(path)
                } else {
                    fs::remove_file(path)
                }
                .context("remove exact held symbolic link")?;
                true
            }
            None => false,
        };
        self.sync()?;
        if self.metadata(name)?.is_some() {
            bail!("held symbolic link reappeared after removal");
        }
        Ok(removed)
    }

    pub(super) fn try_lock(&self, name: &OsStr) -> Result<Option<InstallationLock>> {
        validate_name(name)?;
        self.validate()?;
        let path = self.path.join(name);
        let ordinary = |metadata: &Metadata| metadata.is_file() && !is_reparse(metadata);
        if fs::symlink_metadata(&path).is_ok_and(|metadata| !ordinary(&metadata)) {
            bail!("held resource lock has unsafe custody");
        }
        let lock = InstallationLock::try_acquire(&path)?;
        if lock.is_some() {
            let metadata = fs::symlink_metadata(&path)?;
            if !ordinary(&metadata) || metadata.len() != 0 {
                bail!("held resource lock has unsafe custody");
            }
            self.validate()?;
        }
        Ok(lock)
    }
}

/// Ordinary-file custody of an observed leaf, or `None` for a reparse point or
/// non-file. Owner and mode are not audited on Windows.
pub(super) fn file_authority_of(metadata: &Metadata, limit: u64) -> Option<FileAuthority> {
    (metadata.is_file() && !is_reparse(metadata)).then_some(FileAuthority {
        owner_uid: uid(),
        group_gid: gid(),
        mode: 0o600,
        limit,
    })
}

pub(super) fn read_text(path: &Path) -> Result<String> {
    let open = || {
        OpenOptions::new()
            .read(true)
            .share_mode(SHARE_ALL)
            .open(path)
            .context("open overlay text input")
    };
    let mut file = open()?;
    let before = observe_handle(&file)?;
    if before.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 || before.size > FILE_LIMIT {
        bail!("overlay input must be a bounded regular file");
    }
    let mut text = String::new();
    (&mut file)
        .take(FILE_LIMIT + 1)
        .read_to_string(&mut text)
        .map_err(|_| anyhow!("overlay input is not bounded UTF-8 text"))?;
    let after = observe_handle(&file)?;
    let named = observe_handle(&open()?)?;
    if text.len() as u64 != before.size
        || before.id != after.id
        || before.size != after.size
        || before.written != after.written
        || named.id != after.id
    {
        bail!("overlay text input changed while being read");
    }
    Ok(text)
}

/// Simple uppercase of one UTF-16 unit, as Windows folds leaf names.
fn fold_unit(unit: u16) -> u16 {
    let mut upper = char::from_u32(u32::from(unit))
        .map(char::to_uppercase)
        .into_iter()
        .flatten();
    match (upper.next(), upper.next()) {
        (Some(single), None) if single as u32 <= 0xFFFF => single as u16,
        _ => unit,
    }
}

fn folded(name: &OsStr) -> Vec<u16> {
    name.encode_wide().map(fold_unit).collect()
}

/// Lock/journal key for a leaf that does not exist yet: the name folded per
/// UTF-16 unit. An existing leaf must already carry its exact real spelling.
pub(super) fn name_key(name: &OsStr) -> Vec<u8> {
    folded(name)
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect()
}

pub(super) fn has_reserved_prefix(name: &OsStr, prefix: &str) -> bool {
    folded(name).starts_with(&folded(OsStr::new(prefix)))
}

pub(super) fn native_len(path: &OsStr) -> usize {
    path.encode_wide().count()
}

// Authority paths retain their exact UTF-16 units; lossy conversion would make
// distinct selected targets or raw link destinations share journal identity.
pub(super) mod native_path {
    use super::*;
    use serde::{Deserialize, Serialize};

    pub fn serialize<S: serde::Serializer>(
        path: &Path,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let units: Vec<u16> = path.as_os_str().encode_wide().collect();
        if units.is_empty() || units.len() > MAX_NATIVE_PATH || units.contains(&0) {
            return Err(<S::Error as serde::ser::Error>::custom(
                "native path exceeds transaction bounds",
            ));
        }
        units.serialize(serializer)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<PathBuf, D::Error> {
        let units = Vec::<u16>::deserialize(deserializer)?;
        if units.is_empty() || units.len() > MAX_NATIVE_PATH || units.contains(&0) {
            return Err(<D::Error as serde::de::Error>::custom(
                "native path exceeds transaction bounds",
            ));
        }
        Ok(PathBuf::from(OsString::from_wide(&units)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_authority() -> FileAuthority {
        FileAuthority {
            owner_uid: 0,
            group_gid: 0,
            mode: 0o600,
            limit: 1024,
        }
    }

    #[test]
    fn publication_replaces_only_the_exact_expected_content_and_leaves_no_staging() {
        let temp = tempfile::tempdir().unwrap();
        let (directory, _) = prepare(temp.path()).unwrap();
        let name = OsStr::new("leaf.txt");
        let authority = file_authority();

        directory
            .write_file_with_group(name, b"one", &authority, None)
            .unwrap();
        // A second no-replace publication must not clobber the first.
        assert!(directory
            .write_file_with_group(name, b"two", &authority, None)
            .is_err());
        let one = identity_of(b"one");
        assert!(directory
            .write_file_with_group(name, b"two", &authority, Some(&identity_of(b"other")))
            .is_err());
        directory
            .write_file_with_group(name, b"two", &authority, Some(&one))
            .unwrap();

        assert_eq!(fs::read(temp.path().join("leaf.txt")).unwrap(), b"two");
        let names: Vec<_> = fs::read_dir(temp.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, [OsString::from("leaf.txt")]);
    }

    #[test]
    fn removal_requires_the_exact_content_and_absence_is_a_no_op() {
        let temp = tempfile::tempdir().unwrap();
        let (directory, _) = prepare(temp.path()).unwrap();
        let name = OsStr::new("leaf.txt");
        let authority = file_authority();
        fs::write(temp.path().join("leaf.txt"), b"data").unwrap();

        assert!(directory
            .remove_file_with_group(name, &authority, &identity_of(b"different"))
            .is_err());
        assert!(directory
            .remove_file_with_group(name, &authority, &identity_of(b"data"))
            .unwrap());
        assert!(!directory
            .remove_file_with_group(name, &authority, &identity_of(b""))
            .unwrap());
        assert!(!temp.path().join("leaf.txt").exists());
    }

    #[test]
    fn a_replaced_directory_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let selected = temp.path().join("selected");
        let (directory, _) = prepare(&selected).unwrap();
        fs::rename(&selected, temp.path().join("moved")).unwrap();
        fs::create_dir(&selected).unwrap();

        assert!(directory.metadata(OsStr::new("leaf.txt")).is_err());
    }

    #[test]
    fn only_plain_leaf_names_are_admitted() {
        for rejected in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "stream:name",
            "NUL",
            "con.txt",
            "COM1",
            "lpt9.log",
            "trailing.",
            "trailing ",
            "COM\u{b9}",
            "lpt\u{b3}.txt",
            "COM0",
            "conout$",
        ] {
            assert!(validate_name(OsStr::new(rejected)).is_err(), "{rejected}");
        }
        for accepted in ["config.json", "COM10", "console.log", ".hidden"] {
            assert!(validate_name(OsStr::new(accepted)).is_ok(), "{accepted}");
        }
    }

    #[test]
    fn only_the_real_spelling_of_an_existing_leaf_is_admitted() {
        let temp = tempfile::tempdir().unwrap();
        let (directory, _) = prepare(temp.path()).unwrap();
        fs::write(temp.path().join("Leaf.txt"), b"x").unwrap();

        assert!(directory
            .metadata(OsStr::new("Leaf.txt"))
            .unwrap()
            .is_some());
        // Another case is refused on a case-folding volume; Wine's host
        // filesystem does not fold case and reports the entry absent. Either
        // way the other spelling never selects the existing leaf.
        assert!(!matches!(
            directory.metadata(OsStr::new("leaf.txt")),
            Ok(Some(_))
        ));
    }

    #[test]
    fn lock_keys_fold_case_and_keep_unpaired_surrogates_distinct() {
        assert_eq!(
            name_key(OsStr::new("Config.JSON")),
            name_key(OsStr::new("config.json"))
        );
        let lone = |unit: u16| OsString::from_wide(&[0x61, unit]);
        assert_ne!(name_key(&lone(0xD800)), name_key(&lone(0xD801)));
    }
}
