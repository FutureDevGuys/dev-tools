use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VersionedLayout {
    pub product: String,
    pub data_root: PathBuf,
    pub bin_dir: PathBuf,
    pub artifact_name: String,
    pub owner_uid: u32,
    pub directory_mode: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VersionedInstallRequest {
    pub layout: VersionedLayout,
    pub version: String,
    pub source: PathBuf,
    pub identity: ArtifactIdentity,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VersionedReceipt {
    pub schema: String,
    pub product: String,
    pub data_root: PathBuf,
    pub bin_dir: PathBuf,
    pub artifact_name: String,
    pub active_version: String,
    pub active_identity: ArtifactIdentity,
    pub previous_version: Option<String>,
    pub previous_identity: Option<ArtifactIdentity>,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VersionedApplyReport {
    pub changed: bool,
    pub receipt: VersionedReceipt,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VersionedUninstallReport {
    pub removed_versions: usize,
    pub removed_aliases: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct VersionedTransitionJournal {
    schema: String,
    prior: Option<VersionedReceipt>,
    next: VersionedReceipt,
}

const VERSIONED_RECEIPT_SCHEMA: &str = "dev-tools-versioned-installation-v1";
const VERSIONED_JOURNAL_SCHEMA: &str = "dev-tools-versioned-transition-v1";
const VERSIONED_DOCUMENT_LIMIT: u64 = 1024 * 1024;

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

impl VersionedLayout {
    fn versions_dir(&self) -> PathBuf {
        self.data_root.join("versions")
    }

    fn version_artifact(&self, version: &str) -> PathBuf {
        self.versions_dir().join(version).join(&self.artifact_name)
    }

    fn active_pointer(&self) -> PathBuf {
        self.data_root.join("active")
    }

    fn previous_pointer(&self) -> PathBuf {
        self.data_root.join("previous")
    }

    fn receipt_path(&self) -> PathBuf {
        self.data_root.join("installation-receipt-v1.json")
    }

    fn journal_path(&self) -> PathBuf {
        self.data_root.join("installation-transition-v1.json")
    }

    fn lock_path(&self) -> PathBuf {
        self.data_root.join("installation.lock")
    }
}

pub fn apply_versioned_installation<F>(
    request: &VersionedInstallRequest,
    post_install_verify: F,
) -> Result<VersionedApplyReport>
where
    F: FnOnce(&Path) -> Result<()>,
{
    validate_versioned_request(request)?;
    prepare_layout(&request.layout, Some(&request.version))?;
    let _lock = InstallationLock::acquire(&request.layout.lock_path())?;
    recover_versioned_installation_locked(&request.layout)?;

    let prior = read_versioned_receipt(&request.layout)?;
    if let Some(receipt) = &prior {
        verify_versioned_receipt(&request.layout, receipt)?;
        if receipt.active_version == request.version {
            if receipt.active_identity != request.identity {
                bail!("requested version is already occupied by different content");
            }
            if receipt.aliases != request.aliases {
                bail!("an installed version cannot change its owned alias set in place");
            }
            post_install_verify(&request.layout.version_artifact(&request.version))?;
            return Ok(VersionedApplyReport {
                changed: false,
                receipt: receipt.clone(),
            });
        }
    }

    preflight_alias_transition(&request.layout, prior.as_ref(), &request.aliases)?;
    let candidate = request.layout.version_artifact(&request.version);
    publish_executable(&request.source, &candidate, &request.identity)?;
    verify_versioned_artifact_authority(&candidate, request.layout.owner_uid, &request.identity)?;
    post_install_verify(&candidate).context("product post-install verification failed")?;

    let next = VersionedReceipt {
        schema: VERSIONED_RECEIPT_SCHEMA.into(),
        product: request.layout.product.clone(),
        data_root: request.layout.data_root.clone(),
        bin_dir: request.layout.bin_dir.clone(),
        artifact_name: request.layout.artifact_name.clone(),
        active_version: request.version.clone(),
        active_identity: request.identity.clone(),
        previous_version: prior.as_ref().map(|receipt| receipt.active_version.clone()),
        previous_identity: prior
            .as_ref()
            .map(|receipt| receipt.active_identity.clone()),
        aliases: request.aliases.clone(),
    };
    validate_versioned_receipt(&request.layout, &next)?;
    commit_versioned_transition(&request.layout, prior.as_ref(), &next)?;
    remove_superseded_version(&request.layout, prior.as_ref(), &next)?;
    Ok(VersionedApplyReport {
        changed: true,
        receipt: next,
    })
}

pub fn verify_versioned_installation(layout: &VersionedLayout) -> Result<VersionedReceipt> {
    validate_layout(layout)?;
    let _lock = InstallationLock::acquire(&layout.lock_path())?;
    recover_versioned_installation_locked(layout)?;
    let receipt = read_versioned_receipt(layout)?.context("installation receipt is absent")?;
    verify_versioned_receipt(layout, &receipt)?;
    Ok(receipt)
}

pub fn rollback_versioned_installation<F>(
    layout: &VersionedLayout,
    post_install_verify: F,
) -> Result<VersionedApplyReport>
where
    F: FnOnce(&Path) -> Result<()>,
{
    validate_layout(layout)?;
    let _lock = InstallationLock::acquire(&layout.lock_path())?;
    recover_versioned_installation_locked(layout)?;
    let prior = read_versioned_receipt(layout)?.context("installation receipt is absent")?;
    verify_versioned_receipt(layout, &prior)?;
    let previous_version = prior
        .previous_version
        .clone()
        .context("installation has no retained previous version")?;
    let previous_identity = prior
        .previous_identity
        .clone()
        .context("installation has no retained previous identity")?;
    let candidate = layout.version_artifact(&previous_version);
    post_install_verify(&candidate).context("product rollback verification failed")?;
    let next = VersionedReceipt {
        active_version: previous_version,
        active_identity: previous_identity,
        previous_version: Some(prior.active_version.clone()),
        previous_identity: Some(prior.active_identity.clone()),
        ..prior.clone()
    };
    commit_versioned_transition(layout, Some(&prior), &next)?;
    Ok(VersionedApplyReport {
        changed: true,
        receipt: next,
    })
}

pub fn uninstall_versioned_installation(
    layout: &VersionedLayout,
) -> Result<VersionedUninstallReport> {
    validate_layout(layout)?;
    let _lock = InstallationLock::acquire(&layout.lock_path())?;
    recover_versioned_installation_locked(layout)?;
    let receipt = read_versioned_receipt(layout)?.context("installation receipt is absent")?;
    verify_versioned_receipt(layout, &receipt)?;

    for alias in &receipt.aliases {
        remove_exact_symlink(&layout.bin_dir.join(alias), &layout.active_pointer())?;
    }
    remove_exact_symlink(
        &layout.active_pointer(),
        &layout.version_artifact(&receipt.active_version),
    )?;
    if let Some(previous) = &receipt.previous_version {
        remove_exact_symlink(
            &layout.previous_pointer(),
            &layout.version_artifact(previous),
        )?;
    }
    let receipt_document = read_versioned_receipt_document(layout)?
        .context("installation receipt disappeared before uninstall")?;
    let receipt_document_after = read_versioned_receipt_document(layout)?
        .context("installation receipt disappeared before uninstall")?;
    if receipt_document_after.identity != receipt_document.identity {
        bail!("installation receipt changed before uninstall");
    }
    fs::remove_file(layout.receipt_path()).context("remove versioned installation receipt")?;
    sync_directory(&layout.data_root)?;

    let mut removed_versions = 0;
    let mut versions = vec![(receipt.active_version, receipt.active_identity)];
    if let (Some(version), Some(identity)) = (receipt.previous_version, receipt.previous_identity) {
        versions.push((version, identity));
    }
    versions.sort_by(|left, right| left.0.cmp(&right.0));
    versions.dedup_by(|left, right| left.0 == right.0);
    for (version, identity) in versions {
        if remove_owned_file(&layout.version_artifact(&version), &identity)? {
            removed_versions += 1;
        }
        remove_directory_if_empty(&layout.versions_dir().join(version))?;
    }
    remove_directory_if_empty(&layout.versions_dir())?;
    Ok(VersionedUninstallReport {
        removed_versions,
        removed_aliases: receipt.aliases.len(),
    })
}

fn validate_versioned_request(request: &VersionedInstallRequest) -> Result<()> {
    validate_layout(&request.layout)?;
    validate_component(&request.version, "version")?;
    if !request.source.is_absolute()
        || request.identity.length == 0
        || request.identity.sha256.len() != 64
        || !request
            .identity
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("versioned installation request has an invalid source identity");
    }
    let actual = ArtifactIdentity::from_file(&request.source, request.identity.length)?;
    if actual != request.identity {
        bail!("versioned installation source does not match its approved identity");
    }
    if request.aliases.is_empty() {
        bail!("versioned installation requires at least one owned alias");
    }
    let mut prior: Option<&String> = None;
    for alias in &request.aliases {
        validate_component(alias, "alias")?;
        if prior.is_some_and(|prior| prior >= alias) {
            bail!("versioned installation aliases must be sorted and unique");
        }
        prior = Some(alias);
    }
    Ok(())
}

fn validate_layout(layout: &VersionedLayout) -> Result<()> {
    validate_component(&layout.product, "product")?;
    validate_component(&layout.artifact_name, "artifact name")?;
    if !layout.data_root.is_absolute()
        || !layout.bin_dir.is_absolute()
        || layout.data_root == layout.bin_dir
        || layout.data_root.starts_with(&layout.bin_dir)
        || layout.bin_dir.starts_with(&layout.data_root)
        || layout.directory_mode & !0o777 != 0
        || layout.directory_mode & 0o022 != 0
        || layout.directory_mode & 0o500 != 0o500
    {
        bail!("versioned installation layout is invalid");
    }
    Ok(())
}

fn validate_component(value: &str, description: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || value.starts_with(['.', '-'])
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("versioned installation {description} is invalid");
    }
    Ok(())
}

fn prepare_layout(layout: &VersionedLayout, version: Option<&str>) -> Result<()> {
    validate_layout(layout)?;
    ensure_owned_directory(&layout.data_root, layout.owner_uid, layout.directory_mode)?;
    ensure_owned_directory(&layout.bin_dir, layout.owner_uid, layout.directory_mode)?;
    ensure_owned_directory(
        &layout.versions_dir(),
        layout.owner_uid,
        layout.directory_mode,
    )?;
    if let Some(version) = version {
        validate_component(version, "version")?;
        ensure_owned_directory(
            &layout.versions_dir().join(version),
            layout.owner_uid,
            layout.directory_mode,
        )?;
    }
    Ok(())
}

fn ensure_owned_directory(path: &Path, owner_uid: u32, mode: u32) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let (directory, created) = open_directory_chain(path, true)?;
        if created {
            rustix::fs::fchmod(&directory, rustix::fs::Mode::from_raw_mode(mode))
                .context("protect installation directory")?;
        }
        let metadata = rustix::fs::fstat(&directory).context("inspect installation directory")?;
        if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::Directory
            || metadata.st_uid != owner_uid
            || metadata.st_mode & 0o777 != mode
        {
            bail!("installation directory has unsafe filesystem authority");
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let existed = fs::symlink_metadata(path).is_ok();
        ensure_directory_chain(path)?;
        #[cfg(unix)]
        if !existed {
            fs::set_permissions(path, fs::Permissions::from_mode(mode))
                .with_context(|| format!("protect installation directory {}", path.display()))?;
        }
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect installation directory {}", path.display()))?;
        #[cfg(unix)]
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != owner_uid
            || metadata.mode() & 0o777 != mode
        {
            bail!("installation directory has unsafe filesystem authority");
        }
        #[cfg(not(unix))]
        if !metadata.file_type().is_dir() {
            bail!("installation directory has unsafe filesystem authority");
        }
        Ok(())
    }
}

fn receipt_authority(layout: &VersionedLayout) -> DocumentAuthority {
    DocumentAuthority {
        owner_uid: layout.owner_uid,
        mode: 0o600,
        limit: VERSIONED_DOCUMENT_LIMIT,
    }
}

fn read_versioned_receipt_document(layout: &VersionedLayout) -> Result<Option<AtomicDocument>> {
    read_atomic_document(&layout.receipt_path(), &receipt_authority(layout))
}

fn read_versioned_receipt(layout: &VersionedLayout) -> Result<Option<VersionedReceipt>> {
    let Some(document) = read_versioned_receipt_document(layout)? else {
        return Ok(None);
    };
    let receipt =
        serde_json::from_slice(&document.bytes).context("parse versioned installation receipt")?;
    validate_versioned_receipt(layout, &receipt)?;
    Ok(Some(receipt))
}

fn write_versioned_receipt(layout: &VersionedLayout, receipt: &VersionedReceipt) -> Result<()> {
    validate_versioned_receipt(layout, receipt)?;
    let bytes = serde_jcs::to_vec(receipt).context("serialize versioned installation receipt")?;
    let current = read_versioned_receipt_document(layout)?;
    write_atomic_document(
        &layout.receipt_path(),
        &bytes,
        &receipt_authority(layout),
        current.as_ref().map(|document| &document.identity),
    )?;
    Ok(())
}

fn validate_versioned_receipt(layout: &VersionedLayout, receipt: &VersionedReceipt) -> Result<()> {
    if receipt.schema != VERSIONED_RECEIPT_SCHEMA
        || receipt.product != layout.product
        || receipt.data_root != layout.data_root
        || receipt.bin_dir != layout.bin_dir
        || receipt.artifact_name != layout.artifact_name
    {
        bail!("versioned installation receipt does not match its layout");
    }
    validate_component(&receipt.active_version, "active version")?;
    validate_identity(&receipt.active_identity)?;
    match (&receipt.previous_version, &receipt.previous_identity) {
        (Some(version), Some(identity)) => {
            validate_component(version, "previous version")?;
            validate_identity(identity)?;
            if version == &receipt.active_version {
                bail!("active and previous versions must be distinct");
            }
        }
        (None, None) => {}
        _ => bail!("previous version and identity must be present together"),
    }
    if receipt.aliases.is_empty() {
        bail!("versioned installation receipt has no owned aliases");
    }
    let mut prior: Option<&String> = None;
    for alias in &receipt.aliases {
        validate_component(alias, "receipt alias")?;
        if prior.is_some_and(|prior| prior >= alias) {
            bail!("versioned installation receipt aliases are not sorted and unique");
        }
        prior = Some(alias);
    }
    Ok(())
}

fn validate_identity(identity: &ArtifactIdentity) -> Result<()> {
    if identity.length == 0
        || identity.sha256.len() != 64
        || !identity.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("versioned installation receipt has an invalid artifact identity");
    }
    Ok(())
}

fn verify_versioned_receipt(layout: &VersionedLayout, receipt: &VersionedReceipt) -> Result<()> {
    validate_versioned_receipt(layout, receipt)?;
    let active = layout.version_artifact(&receipt.active_version);
    verify_versioned_artifact_authority(&active, layout.owner_uid, &receipt.active_identity)
        .context("active version does not match its receipt")?;
    verify_exact_symlink(&layout.active_pointer(), &active)?;
    match (&receipt.previous_version, &receipt.previous_identity) {
        (Some(version), Some(identity)) => {
            let previous = layout.version_artifact(version);
            verify_versioned_artifact_authority(&previous, layout.owner_uid, identity)
                .context("previous version does not match its receipt")?;
            verify_exact_symlink(&layout.previous_pointer(), &previous)?;
        }
        (None, None) => require_path_absent(&layout.previous_pointer())?,
        _ => bail!("previous version receipt is incomplete"),
    }
    for alias in &receipt.aliases {
        verify_exact_symlink(&layout.bin_dir.join(alias), &layout.active_pointer())?;
    }
    Ok(())
}

fn verify_versioned_artifact_authority(
    path: &Path,
    owner_uid: u32,
    identity: &ArtifactIdentity,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect versioned artifact {}", path.display()))?;
    #[cfg(unix)]
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != 0o755
    {
        bail!("versioned artifact has unsafe filesystem authority");
    }
    #[cfg(not(unix))]
    if !metadata.file_type().is_file() {
        bail!("versioned artifact has unsafe filesystem authority");
    }
    if ArtifactIdentity::from_file(path, identity.length)? != *identity {
        bail!("versioned artifact content does not match its receipt");
    }
    Ok(())
}

fn preflight_alias_transition(
    layout: &VersionedLayout,
    prior: Option<&VersionedReceipt>,
    next_aliases: &[String],
) -> Result<()> {
    let prior_aliases = prior
        .map(|receipt| receipt.aliases.iter().cloned().collect::<BTreeSet<_>>())
        .unwrap_or_default();
    for alias in next_aliases {
        let path = layout.bin_dir.join(alias);
        match fs::symlink_metadata(&path) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    && prior_aliases.contains(alias)
                    && fs::read_link(&path)? == layout.active_pointer() => {}
            Ok(_) => bail!("refusing to replace an unowned installation alias"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect installation alias"),
        }
    }
    if let Some(prior) = prior {
        for alias in &prior.aliases {
            if !next_aliases.contains(alias) {
                verify_exact_symlink(&layout.bin_dir.join(alias), &layout.active_pointer())?;
            }
        }
    }
    Ok(())
}

fn commit_versioned_transition(
    layout: &VersionedLayout,
    prior: Option<&VersionedReceipt>,
    next: &VersionedReceipt,
) -> Result<()> {
    validate_versioned_receipt(layout, next)?;
    if let Some(prior) = prior {
        verify_versioned_receipt(layout, prior)?;
    } else {
        require_path_absent(&layout.active_pointer())?;
        require_path_absent(&layout.previous_pointer())?;
    }
    preflight_alias_transition(layout, prior, &next.aliases)?;
    let journal = VersionedTransitionJournal {
        schema: VERSIONED_JOURNAL_SCHEMA.into(),
        prior: prior.cloned(),
        next: next.clone(),
    };
    write_transition_journal(layout, &journal)?;

    let result: Result<()> = (|| {
        let prior_active = prior.map(|receipt| layout.version_artifact(&receipt.active_version));
        let prior_previous = prior
            .and_then(|receipt| receipt.previous_version.as_deref())
            .map(|version| layout.version_artifact(version));
        let next_active = layout.version_artifact(&next.active_version);
        let next_previous = next
            .previous_version
            .as_deref()
            .map(|version| layout.version_artifact(version));
        replace_owned_symlink(
            &layout.previous_pointer(),
            next_previous.as_deref(),
            prior_previous.as_deref(),
        )?;
        replace_owned_symlink(
            &layout.active_pointer(),
            Some(&next_active),
            prior_active.as_deref(),
        )?;
        let prior_aliases = prior
            .map(|receipt| receipt.aliases.iter().cloned().collect::<BTreeSet<_>>())
            .unwrap_or_default();
        for alias in &next.aliases {
            replace_owned_symlink(
                &layout.bin_dir.join(alias),
                Some(&layout.active_pointer()),
                prior_aliases
                    .contains(alias)
                    .then(|| layout.active_pointer())
                    .as_deref(),
            )?;
        }
        if let Some(prior) = prior {
            for alias in &prior.aliases {
                if !next.aliases.contains(alias) {
                    remove_exact_symlink(&layout.bin_dir.join(alias), &layout.active_pointer())?;
                }
            }
        }
        write_versioned_receipt(layout, next)?;
        verify_versioned_receipt(layout, next)?;
        Ok(())
    })();
    if let Err(error) = result {
        return Err(error).context(
            "versioned installation transition was interrupted; the next operation will recover",
        );
    }
    remove_transition_journal(layout)?;
    Ok(())
}

fn write_transition_journal(
    layout: &VersionedLayout,
    journal: &VersionedTransitionJournal,
) -> Result<()> {
    if journal.schema != VERSIONED_JOURNAL_SCHEMA {
        bail!("versioned installation transition journal is unsupported");
    }
    let bytes = serde_jcs::to_vec(journal).context("serialize installation transition journal")?;
    write_atomic_document(
        &layout.journal_path(),
        &bytes,
        &receipt_authority(layout),
        None,
    )?;
    Ok(())
}

fn read_transition_journal(layout: &VersionedLayout) -> Result<Option<VersionedTransitionJournal>> {
    let Some(document) = read_atomic_document(&layout.journal_path(), &receipt_authority(layout))?
    else {
        return Ok(None);
    };
    let journal: VersionedTransitionJournal =
        serde_json::from_slice(&document.bytes).context("parse installation transition journal")?;
    if journal.schema != VERSIONED_JOURNAL_SCHEMA {
        bail!("versioned installation transition journal is unsupported");
    }
    if let Some(prior) = &journal.prior {
        validate_versioned_receipt(layout, prior)?;
    }
    validate_versioned_receipt(layout, &journal.next)?;
    Ok(Some(journal))
}

fn remove_transition_journal(layout: &VersionedLayout) -> Result<()> {
    match fs::remove_file(layout.journal_path()) {
        Ok(()) => sync_directory(&layout.data_root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("remove installation transition journal"),
    }
}

fn recover_versioned_installation_locked(layout: &VersionedLayout) -> Result<()> {
    let Some(journal) = read_transition_journal(layout)? else {
        return Ok(());
    };
    let installed = read_versioned_receipt(layout)?;
    if installed.as_ref() == Some(&journal.next) {
        verify_versioned_receipt(layout, &journal.next)?;
        return remove_transition_journal(layout);
    }
    if installed.as_ref() != journal.prior.as_ref() {
        bail!("installation receipt changed during interrupted transition");
    }
    restore_transition_prior(layout, &journal)?;
    remove_transition_journal(layout)
}

fn restore_transition_prior(
    layout: &VersionedLayout,
    journal: &VersionedTransitionJournal,
) -> Result<()> {
    let next_active = layout.version_artifact(&journal.next.active_version);
    let next_previous = journal
        .next
        .previous_version
        .as_deref()
        .map(|version| layout.version_artifact(version));
    match &journal.prior {
        Some(prior) => {
            let prior_active = layout.version_artifact(&prior.active_version);
            let prior_previous = prior
                .previous_version
                .as_deref()
                .map(|version| layout.version_artifact(version));
            restore_owned_symlink(&layout.active_pointer(), &prior_active, Some(&next_active))?;
            restore_optional_symlink(
                &layout.previous_pointer(),
                prior_previous.as_deref(),
                next_previous.as_deref(),
            )?;
            let prior_aliases = prior.aliases.iter().cloned().collect::<BTreeSet<_>>();
            for alias in &journal.next.aliases {
                let path = layout.bin_dir.join(alias);
                if prior_aliases.contains(alias) {
                    restore_owned_symlink(
                        &path,
                        &layout.active_pointer(),
                        Some(&layout.active_pointer()),
                    )?;
                } else {
                    remove_symlink_if_target(&path, &layout.active_pointer())?;
                }
            }
            for alias in &prior.aliases {
                restore_owned_symlink(
                    &layout.bin_dir.join(alias),
                    &layout.active_pointer(),
                    Some(&layout.active_pointer()),
                )?;
            }
            verify_versioned_receipt(layout, prior)
        }
        None => {
            remove_symlink_if_target(&layout.active_pointer(), &next_active)?;
            if let Some(next_previous) = next_previous.as_deref() {
                remove_symlink_if_target(&layout.previous_pointer(), next_previous)?;
            } else {
                require_path_absent(&layout.previous_pointer())?;
            }
            for alias in &journal.next.aliases {
                remove_symlink_if_target(&layout.bin_dir.join(alias), &layout.active_pointer())?;
            }
            Ok(())
        }
    }
}

fn restore_optional_symlink(
    path: &Path,
    desired: Option<&Path>,
    alternate: Option<&Path>,
) -> Result<()> {
    match desired {
        Some(desired) => restore_owned_symlink(path, desired, alternate),
        None => {
            if let Some(alternate) = alternate {
                remove_symlink_if_target(path, alternate)
            } else {
                require_path_absent(path)
            }
        }
    }
}

fn restore_owned_symlink(path: &Path, desired: &Path, alternate: Option<&Path>) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let current = fs::read_link(path)?;
            if current == desired {
                return Ok(());
            }
            if alternate != Some(current.as_path()) {
                bail!("interrupted installation contains unowned symlink drift");
            }
            replace_owned_symlink(path, Some(desired), Some(&current))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            replace_owned_symlink(path, Some(desired), None)
        }
        Ok(_) => bail!("interrupted installation path is not an owned symlink"),
        Err(error) => Err(error).context("inspect interrupted installation symlink"),
    }
}

fn remove_superseded_version(
    layout: &VersionedLayout,
    prior: Option<&VersionedReceipt>,
    next: &VersionedReceipt,
) -> Result<()> {
    let Some(prior) = prior else {
        return Ok(());
    };
    let Some(version) = prior.previous_version.as_deref() else {
        return Ok(());
    };
    if version == next.active_version || next.previous_version.as_deref() == Some(version) {
        return Ok(());
    }
    let identity = prior
        .previous_identity
        .as_ref()
        .context("prior receipt omitted its previous identity")?;
    remove_owned_file(&layout.version_artifact(version), identity)?;
    remove_directory_if_empty(&layout.versions_dir().join(version))
}

fn replace_owned_symlink(
    path: &Path,
    desired: Option<&Path>,
    expected_current: Option<&Path>,
) -> Result<()> {
    let current = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Some(fs::read_link(path)?),
        Ok(_) => bail!("installation pointer collides with a non-symlink path"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("inspect installation pointer"),
    };
    if current.as_deref() == desired {
        return Ok(());
    }
    if current.as_deref() != expected_current {
        bail!("installation pointer changed before publication");
    }
    let Some(desired) = desired else {
        fs::remove_file(path).context("remove installation pointer")?;
        if let Some(parent) = path.parent() {
            sync_directory(parent)?;
        }
        return Ok(());
    };
    let parent = path
        .parent()
        .context("installation pointer has no parent")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("installation pointer name is not UTF-8")?;
    let temporary = parent.join(format!(".{file_name}.new-{}", std::process::id()));
    require_path_absent(&temporary)?;
    create_symlink(desired, &temporary).context("stage installation pointer")?;
    let publish = if current.is_some() {
        fs::rename(&temporary, path)
    } else {
        rename_noreplace(&temporary, path)
    };
    if let Err(error) = publish {
        let _ = fs::remove_file(&temporary);
        return Err(error).context("publish installation pointer");
    }
    sync_directory(parent)
}

fn verify_exact_symlink(path: &Path, expected: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect installation pointer {}", path.display()))?;
    if !metadata.file_type().is_symlink() || fs::read_link(path)? != expected {
        bail!("installation pointer does not match its receipt");
    }
    Ok(())
}

fn remove_exact_symlink(path: &Path, expected: &Path) -> Result<()> {
    verify_exact_symlink(path, expected)?;
    fs::remove_file(path).context("remove receipt-owned installation pointer")?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn remove_symlink_if_target(path: &Path, expected: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() && fs::read_link(path)? == expected => {
            fs::remove_file(path).context("remove interrupted installation pointer")?;
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
            Ok(())
        }
        Ok(_) => bail!("interrupted installation pointer has unowned drift"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect interrupted installation pointer"),
    }
}

fn require_path_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => bail!("installation path is unexpectedly occupied"),
        Err(error) => Err(error).context("inspect installation path"),
    }
}

#[cfg(unix)]
fn create_symlink(target: &Path, path: &Path) -> std::io::Result<()> {
    symlink(target, path)
}

#[cfg(not(unix))]
fn create_symlink(_target: &Path, _path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "versioned symlink installation is unsupported on this platform",
    ))
}

#[cfg(target_os = "linux")]
fn rename_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)
}

#[cfg(not(target_os = "linux"))]
fn rename_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(destination) {
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "installation destination already exists",
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::rename(source, destination)
}

fn remove_directory_if_empty(path: &Path) -> Result<()> {
    match fs::remove_dir(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
            Ok(())
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error).context("remove empty installation directory"),
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

#[cfg(target_os = "linux")]
fn open_directory_chain(path: &Path, create: bool) -> Result<(std::os::fd::OwnedFd, bool)> {
    if !path.is_absolute() {
        bail!("installation directory must be absolute");
    }
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => names.push(name.to_os_string()),
            Component::Prefix(_) => bail!("installation directory has an unsupported prefix"),
            Component::ParentDir => bail!("installation directory cannot contain parent traversal"),
        }
    }
    let flags =
        rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    let mut directory = rustix::fs::open("/", flags, rustix::fs::Mode::empty())
        .context("open installation filesystem root")?;
    let mut final_created = false;
    for (index, name) in names.iter().enumerate() {
        let opened = match rustix::fs::openat(&directory, name, flags, rustix::fs::Mode::empty()) {
            Ok(opened) => opened,
            Err(error) if create && error == rustix::io::Errno::NOENT => {
                match rustix::fs::mkdirat(&directory, name, rustix::fs::Mode::from_raw_mode(0o755))
                {
                    Ok(()) => {}
                    Err(error) if error == rustix::io::Errno::EXIST => {}
                    Err(error) => {
                        return Err(error).context("create installation directory component")
                    }
                }
                if index + 1 == names.len() {
                    final_created = true;
                }
                rustix::fs::openat(&directory, name, flags, rustix::fs::Mode::empty())
                    .context("open created installation directory component")?
            }
            Err(error) => return Err(error).context("open installation directory component"),
        };
        if rustix::fs::FileType::from_raw_mode(
            rustix::fs::fstat(&opened)
                .context("inspect installation directory component")?
                .st_mode,
        ) != rustix::fs::FileType::Directory
        {
            bail!("installation directory chain contains a non-directory");
        }
        directory = opened;
    }
    Ok((directory, final_created))
}

#[cfg(target_os = "linux")]
fn ensure_directory_chain(path: &Path) -> Result<()> {
    open_directory_chain(path, true).map(|_| ())
}

#[cfg(not(target_os = "linux"))]
fn ensure_directory_chain(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("installation directory must be absolute");
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                current.push(component.as_os_str())
            }
            Component::CurDir => continue,
            Component::ParentDir => bail!("installation directory cannot contain parent traversal"),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => bail!("installation directory chain contains a non-directory"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).with_context(|| {
                    format!("create installation directory {}", current.display())
                })?;
            }
            Err(error) => return Err(error).context("inspect installation directory chain"),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_read_nofollow(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        bail!("regular file path must be absolute");
    }
    let parent = path.parent().context("regular file has no parent")?;
    let name = path.file_name().context("regular file has no name")?;
    let (directory, _) = open_directory_chain(parent, false)?;
    let file = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("open regular file {}", path.display()))?;
    Ok(File::from(file))
}

#[cfg(not(target_os = "linux"))]
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

#[cfg(not(target_os = "linux"))]
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

#[cfg(all(test, unix))]
mod versioned_tests {
    use super::*;

    fn request(root: &Path, version: &str, bytes: &[u8]) -> VersionedInstallRequest {
        let source = root.join(format!("source-{version}"));
        fs::write(&source, bytes).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        VersionedInstallRequest {
            layout: VersionedLayout {
                product: "fixture".into(),
                data_root: root.join("data"),
                bin_dir: root.join("bin"),
                artifact_name: "fixture".into(),
                owner_uid: fs::metadata(root).unwrap().uid(),
                directory_mode: 0o700,
            },
            version: version.into(),
            identity: ArtifactIdentity::from_file(&source, 4096).unwrap(),
            source,
            aliases: vec!["fixture".into()],
        }
    }

    #[test]
    fn interrupted_pointer_transition_restores_the_last_published_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let first = request(temp.path(), "1.0.0", b"first");
        let prior = apply_versioned_installation(&first, |_| Ok(()))
            .unwrap()
            .receipt;
        let second = request(temp.path(), "1.1.0", b"second");
        prepare_layout(&second.layout, Some(&second.version)).unwrap();
        let _lock = InstallationLock::acquire(&second.layout.lock_path()).unwrap();
        let candidate = second.layout.version_artifact(&second.version);
        publish_executable(&second.source, &candidate, &second.identity).unwrap();
        let next = VersionedReceipt {
            schema: VERSIONED_RECEIPT_SCHEMA.into(),
            product: second.layout.product.clone(),
            data_root: second.layout.data_root.clone(),
            bin_dir: second.layout.bin_dir.clone(),
            artifact_name: second.layout.artifact_name.clone(),
            active_version: second.version.clone(),
            active_identity: second.identity.clone(),
            previous_version: Some(prior.active_version.clone()),
            previous_identity: Some(prior.active_identity.clone()),
            aliases: second.aliases.clone(),
        };
        write_transition_journal(
            &second.layout,
            &VersionedTransitionJournal {
                schema: VERSIONED_JOURNAL_SCHEMA.into(),
                prior: Some(prior.clone()),
                next: next.clone(),
            },
        )
        .unwrap();
        replace_owned_symlink(
            &second.layout.previous_pointer(),
            Some(&second.layout.version_artifact(&prior.active_version)),
            None,
        )
        .unwrap();
        replace_owned_symlink(
            &second.layout.active_pointer(),
            Some(&candidate),
            Some(&second.layout.version_artifact(&prior.active_version)),
        )
        .unwrap();

        recover_versioned_installation_locked(&second.layout).unwrap();
        verify_versioned_receipt(&second.layout, &prior).unwrap();
        assert!(!second.layout.journal_path().exists());
    }
}
