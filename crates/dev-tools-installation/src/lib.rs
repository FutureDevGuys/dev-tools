use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentAuthority {
    pub owner_uid: u32,
    pub mode: u32,
    pub limit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicDocument {
    pub bytes: Vec<u8>,
    pub identity: ArtifactIdentity,
}

#[derive(Debug)]
pub struct InstallationLock {
    file: File,
}

impl InstallationLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        Self::open(path, false)?.context("installation lock unexpectedly unavailable")
    }

    pub fn try_acquire(path: &Path) -> Result<Option<Self>> {
        Self::open(path, true)
    }

    fn open(path: &Path, nonblocking: bool) -> Result<Option<Self>> {
        let parent = path.parent().context("installation lock has no parent")?;
        ensure_directory_chain(parent)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options
            .open(path)
            .with_context(|| format!("open installation lock {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("inspect installation lock {}", path.display()))?;
        if !metadata.file_type().is_file() {
            bail!("installation lock is not a regular file");
        }
        #[cfg(unix)]
        {
            let parent_metadata = fs::metadata(parent).with_context(|| {
                format!("inspect installation lock parent {}", parent.display())
            })?;
            if metadata.nlink() != 1
                || metadata.uid() != parent_metadata.uid()
                || metadata.mode() & 0o077 != 0
            {
                bail!("installation lock has unsafe filesystem authority");
            }
        }
        if nonblocking {
            match file.try_lock_exclusive() {
                Ok(()) => Ok(Some(Self { file })),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
                Err(error) => Err(error).context("acquire installation lock"),
            }
        } else {
            file.lock_exclusive().context("acquire installation lock")?;
            Ok(Some(Self { file }))
        }
    }
}

impl Drop for InstallationLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptArtifact {
    pub path: std::path::PathBuf,
    pub identity: ArtifactIdentity,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallationReceipt {
    pub schema: String,
    pub product: String,
    pub active_version: String,
    pub previous_version: Option<String>,
    pub artifacts: Vec<ReceiptArtifact>,
}

impl ArtifactIdentity {
    pub fn from_file(path: &Path, limit: u64) -> Result<Self> {
        let mut file = open_read_nofollow(path)?;
        let metadata = file
            .metadata()
            .with_context(|| format!("inspect opened artifact {}", path.display()))?;
        if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > limit {
            bail!("artifact has unsafe filesystem authority");
        }
        #[cfg(unix)]
        if metadata.nlink() != 1 {
            bail!("artifact must have exactly one filesystem link");
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut length = 0_u64;
        loop {
            let read = file
                .read(&mut buffer)
                .with_context(|| format!("read artifact {}", path.display()))?;
            if read == 0 {
                break;
            }
            length = length
                .checked_add(read as u64)
                .context("artifact length overflow")?;
            if length > limit {
                bail!("artifact exceeded its size bound while being read");
            }
            hasher.update(&buffer[..read]);
        }
        if length != metadata.len() {
            bail!("artifact changed while being read");
        }
        Ok(Self {
            length,
            sha256: format!("{:x}", hasher.finalize()),
        })
    }
}

pub fn read_atomic_document(
    path: &Path,
    authority: &DocumentAuthority,
) -> Result<Option<AtomicDocument>> {
    validate_document_authority(authority)?;
    let mut file = match open_read_nofollow(path) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let before = file
        .metadata()
        .with_context(|| format!("inspect atomic document {}", path.display()))?;
    #[cfg(unix)]
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != authority.owner_uid
        || before.mode() & 0o777 != authority.mode
        || before.len() == 0
        || before.len() > authority.limit
    {
        bail!("atomic document has unsafe filesystem authority");
    }
    #[cfg(not(unix))]
    if !before.file_type().is_file() || before.len() == 0 || before.len() > authority.limit {
        bail!("atomic document has unsafe filesystem authority");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(authority.limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read atomic document {}", path.display()))?;
    let after = file
        .metadata()
        .with_context(|| format!("reinspect atomic document {}", path.display()))?;
    #[cfg(unix)]
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        bail!("atomic document changed while being read");
    }
    #[cfg(not(unix))]
    if bytes.len() as u64 != before.len() || before.len() != after.len() {
        bail!("atomic document changed while being read");
    }
    Ok(Some(AtomicDocument {
        identity: ArtifactIdentity {
            length: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(&bytes)),
        },
        bytes,
    }))
}

pub fn write_atomic_document(
    path: &Path,
    bytes: &[u8],
    authority: &DocumentAuthority,
    expected_current: Option<&ArtifactIdentity>,
) -> Result<bool> {
    validate_document_authority(authority)?;
    if bytes.is_empty() || bytes.len() as u64 > authority.limit {
        bail!("atomic document content is empty or exceeds its size bound");
    }
    let parent = path.parent().context("atomic document has no parent")?;
    ensure_directory_chain(parent)?;
    let current = read_atomic_document(path, authority)?;
    if current
        .as_ref()
        .is_some_and(|current| current.bytes == bytes)
    {
        return Ok(false);
    }
    match (&current, expected_current) {
        (None, None) => {}
        (Some(current), Some(expected)) if current.identity == *expected => {}
        (None, Some(_)) => bail!("atomic document disappeared before replacement"),
        (Some(_), None) => bail!("atomic document already exists with different content"),
        (Some(_), Some(_)) => bail!("atomic document changed before replacement"),
    }

    let mut temporary = tempfile::Builder::new()
        .prefix(".dev-tools-document-")
        .tempfile_in(parent)
        .context("create atomic document temporary")?;
    temporary
        .as_file_mut()
        .write_all(bytes)
        .context("write atomic document temporary")?;
    temporary
        .as_file_mut()
        .flush()
        .context("flush atomic document temporary")?;
    temporary
        .as_file()
        .sync_all()
        .context("sync atomic document temporary")?;
    #[cfg(unix)]
    {
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(authority.mode))
            .context("protect atomic document temporary")?;
        if temporary.as_file().metadata()?.uid() != authority.owner_uid {
            std::os::unix::fs::chown(temporary.path(), Some(authority.owner_uid), None)
                .context("set atomic document owner")?;
        }
    }
    let staged = ArtifactIdentity::from_file(temporary.path(), authority.limit)?;
    let expected = ArtifactIdentity {
        length: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
    };
    if staged != expected {
        bail!("atomic document temporary changed before publication");
    }
    if current.is_some() {
        temporary
            .persist(path)
            .map_err(|error| error.error)
            .context("replace atomic document")?;
    } else {
        temporary
            .persist_noclobber(path)
            .map_err(|error| error.error)
            .context("publish atomic document")?;
    }
    sync_directory(parent)?;
    Ok(true)
}

fn validate_document_authority(authority: &DocumentAuthority) -> Result<()> {
    if authority.limit == 0
        || authority.limit > 256 * 1024 * 1024
        || authority.mode & !0o777 != 0
        || authority.mode & 0o022 != 0
    {
        bail!("atomic document authority is invalid");
    }
    Ok(())
}

pub fn publish_executable(
    source: &Path,
    destination: &Path,
    expected: &ArtifactIdentity,
) -> Result<bool> {
    let actual = ArtifactIdentity::from_file(source, expected.length)?;
    if &actual != expected {
        bail!("source artifact does not match its approved identity");
    }
    let parent = destination
        .parent()
        .context("installation destination has no parent")?;
    ensure_directory_chain(parent)?;
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                bail!("installation destination is not a regular file");
            }
            let existing = ArtifactIdentity::from_file(destination, expected.length)?;
            if existing == *expected {
                return Ok(false);
            }
            bail!("installation destination has unowned content drift");
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect installation destination"),
    }

    let mut input = open_read_nofollow(source)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".dev-tools-install-")
        .tempfile_in(parent)
        .context("create private installation temporary")?;
    std::io::copy(&mut input, temporary.as_file_mut()).context("copy installation artifact")?;
    temporary
        .as_file_mut()
        .flush()
        .context("flush installation artifact")?;
    temporary
        .as_file()
        .sync_all()
        .context("sync installation artifact")?;
    #[cfg(unix)]
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))
        .context("protect installation artifact")?;
    let staged = ArtifactIdentity::from_file(temporary.path(), expected.length)?;
    if staged != *expected {
        bail!("staged installation artifact changed before publication");
    }
    temporary
        .persist_noclobber(destination)
        .map_err(|error| error.error)
        .context("publish installation artifact")?;
    sync_directory(parent)?;
    Ok(true)
}

pub fn remove_owned_file(path: &Path, expected: &ArtifactIdentity) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                bail!("owned path is not a regular file");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("inspect owned path"),
    }
    if ArtifactIdentity::from_file(path, expected.length)? != *expected {
        bail!("owned path content no longer matches its receipt");
    }
    fs::remove_file(path).context("remove receipt-owned file")?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(true)
}

pub fn verify_owned_installation(receipt: &InstallationReceipt) -> Result<()> {
    validate_receipt(receipt)?;
    for artifact in &receipt.artifacts {
        let actual = ArtifactIdentity::from_file(&artifact.path, artifact.identity.length)?;
        if actual != artifact.identity {
            bail!(
                "receipt-owned artifact does not match: {}",
                artifact.path.display()
            );
        }
    }
    Ok(())
}

pub fn remove_owned_installation(receipt: &InstallationReceipt) -> Result<usize> {
    verify_owned_installation(receipt)?;
    for artifact in &receipt.artifacts {
        remove_owned_file(&artifact.path, &artifact.identity)?;
    }
    Ok(receipt.artifacts.len())
}

fn validate_receipt(receipt: &InstallationReceipt) -> Result<()> {
    if receipt.schema != "dev-tools-installation-receipt-v1"
        || receipt.product.is_empty()
        || receipt.active_version.is_empty()
        || receipt.artifacts.is_empty()
    {
        bail!("installation receipt has an unsupported contract");
    }
    let mut paths = BTreeSet::new();
    for artifact in &receipt.artifacts {
        if !artifact.path.is_absolute()
            || artifact.identity.length == 0
            || artifact.identity.sha256.len() != 64
            || !artifact
                .identity
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || !paths.insert(artifact.path.clone())
        {
            bail!("installation receipt contains an invalid artifact");
        }
    }
    Ok(())
}

fn ensure_directory_chain(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("installation directory must be absolute");
    }
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                current.push(component.as_os_str())
            }
            Component::CurDir => continue,
            Component::ParentDir => bail!("installation directory cannot contain parent traversal"),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if !metadata.file_type().is_dir() {
                    bail!("installation directory chain contains a non-directory");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).with_context(|| {
                    format!("create installation directory {}", current.display())
                })?;
                #[cfg(unix)]
                fs::set_permissions(&current, fs::Permissions::from_mode(0o755)).with_context(
                    || format!("protect installation directory {}", current.display()),
                )?;
            }
            Err(error) => return Err(error).context("inspect installation directory chain"),
        }
    }
    Ok(())
}

fn open_read_nofollow(path: &Path) -> Result<File> {
    let parent = path.parent().context("regular file has no parent")?;
    validate_existing_directory_chain(parent)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(path)
        .with_context(|| format!("open regular file {}", path.display()))
}

fn validate_existing_directory_chain(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("installation path must be absolute");
    }
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                current.push(component.as_os_str())
            }
            Component::CurDir => continue,
            Component::ParentDir => bail!("installation path cannot contain parent traversal"),
        }
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("inspect installation path {}", current.display()))?;
        if !metadata.file_type().is_dir() {
            bail!("installation path contains a non-directory component");
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("open directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("sync directory {}", path.display()))
}
