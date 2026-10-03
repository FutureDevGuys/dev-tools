use super::*;
use std::ffi::{OsStr, OsString};
use std::io::Seek;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::sync::atomic::{AtomicU64, Ordering};

/// An existing, owner-controlled directory retained for document operations.
/// Every leaf operation is descriptor-relative, including staging, ownership,
/// publication, removal and synchronization. Replacing the directory's pathname
/// cannot redirect a write. No directories are created or removed.
///
/// Callers own ancestor trust, release/content authority, writer serialization
/// and higher-level recovery. This is not an atomic exclusion mechanism against
/// hostile same-owner leaf writers or a permanent legacy-writer fence. Errors
/// after publication/removal can have uncertain progress; retry the retained
/// transaction. Unmarked staging files after process death are never adopted.
pub struct ExistingDocumentDirectory {
    path: PathBuf,
    directory: OwnedFd,
    owner_uid: u32,
}

/// Read-only admission of an existing document parent or an absent suffix below
/// an existing owner-controlled directory. The caller owns ancestor trust,
/// destination selection and writer exclusion. Preparation never adopts a
/// directory that appeared after admission, or changes an existing one's mode.
pub struct DocumentDirectoryPreparation {
    ancestor: ExistingDocumentDirectory,
    missing: Vec<OsString>,
    mode: u32,
}

impl DocumentDirectoryPreparation {
    pub fn observe(path: &Path, owner_uid: u32, mode: u32) -> Result<Self> {
        if !path.is_absolute()
            || path.as_os_str().as_bytes().len() > 4096
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)))
            || mode & !0o777 != 0
            || mode & 0o022 != 0
            || mode & 0o700 != 0o700
        {
            bail!("document directory preparation has invalid authority");
        }
        let mut ancestor_path = path.to_path_buf();
        let mut missing = Vec::new();
        loop {
            match open_directory_chain(&ancestor_path, false) {
                Ok((directory, _)) => {
                    let ancestor = ExistingDocumentDirectory {
                        path: ancestor_path,
                        directory,
                        owner_uid,
                    };
                    ancestor.validate()?;
                    missing.reverse();
                    let result = Self {
                        ancestor,
                        missing,
                        mode,
                    };
                    result.verify_observed()?;
                    return Ok(result);
                }
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
                {
                    missing.push(
                        ancestor_path
                            .file_name()
                            .context("absent directory has no name")?
                            .to_os_string(),
                    );
                    ancestor_path.pop();
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub fn verify_observed(&self) -> Result<()> {
        self.ancestor.validate()?;
        if let Some(name) = self.missing.first() {
            self.ancestor.require_named_current(name, None)?;
        }
        Ok(())
    }

    /// Read a selected document, preserving an admitted absent parent without
    /// creating it. This is a read-only operation, including storage sync.
    pub fn read(
        &self,
        name: &OsStr,
        authority: &DocumentAuthority,
    ) -> Result<Option<AtomicDocument>> {
        validate_name(name)?;
        validate_document_authority(authority)?;
        self.verify_observed()?;
        if self.missing.is_empty() {
            self.ancestor.read(name, authority)
        } else {
            Ok(None)
        }
    }

    /// Publish the admitted missing suffix and return its descriptor-bound
    /// document directory. Errors after publication can have uncertain progress;
    /// reacquire admission for a retained transaction, never adopt staging names.
    pub fn prepare(&self) -> Result<(ExistingDocumentDirectory, bool)> {
        self.verify_observed()?;
        // Sync every existing ancestor link as well: a fresh observation may
        // follow a prior publication whose parent synchronization failed.
        open_directory_chain_with_durability(&self.ancestor.path, false, true, |directory| {
            rustix::fs::fsync(directory).context("sync admitted directory ancestor")
        })?;
        self.verify_observed()?;
        let mut current = ExistingDocumentDirectory {
            path: self.ancestor.path.clone(),
            directory: self.ancestor.directory.try_clone()?,
            owner_uid: self.ancestor.owner_uid,
        };
        for name in &self.missing {
            current.validate()?;
            current.require_named_current(name, None)?;
            let mut temporary = TemporaryDirectory::create(&current.directory)?;
            if temporary.file.metadata()?.uid() != current.owner_uid {
                rustix::fs::fchown(
                    &temporary.file,
                    Some(rustix::fs::Uid::from_raw(current.owner_uid)),
                    None,
                )?;
            }
            temporary
                .file
                .set_permissions(fs::Permissions::from_mode(self.mode))?;
            temporary
                .file
                .sync_all()
                .context("sync staged directory metadata")?;
            require_named_file(
                &current.directory,
                &temporary.name,
                &temporary.file.metadata()?,
            )?;
            current.validate()?;
            current.require_named_current(name, None)?;
            rustix::fs::renameat_with(
                &current.directory,
                &temporary.name,
                &current.directory,
                name,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .context("publish admitted directory without replacement")?;
            temporary.published = true;
            rustix::fs::fsync(&current.directory).context("sync published directory parent")?;
            current.validate()?;
            require_named_file(&current.directory, name, &temporary.file.metadata()?)?;
            let next = ExistingDocumentDirectory {
                path: current.path.join(name),
                directory: temporary.file.try_clone()?.into(),
                owner_uid: current.owner_uid,
            };
            next.validate()?;
            drop(temporary);
            current = next;
        }
        rustix::fs::fsync(&current.directory).context("sync prepared document directory")?;
        current.validate()?;
        Ok((current, !self.missing.is_empty()))
    }
}

struct TemporaryDirectory<'a> {
    parent: &'a OwnedFd,
    name: OsString,
    file: File,
    published: bool,
}

impl<'a> TemporaryDirectory<'a> {
    fn create(parent: &'a OwnedFd) -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..32 {
            let name = OsString::from(format!(
                ".dev-tools-directory-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match rustix::fs::mkdirat(parent, &name, rustix::fs::Mode::from_raw_mode(0o700)) {
                Ok(()) => {
                    // If opening fails, no descriptor establishes cleanup
                    // authority; leave the unmarked staging entry untouched.
                    let file = rustix::fs::openat(
                        parent,
                        &name,
                        rustix::fs::OFlags::DIRECTORY
                            | rustix::fs::OFlags::NOFOLLOW
                            | rustix::fs::OFlags::CLOEXEC,
                        rustix::fs::Mode::empty(),
                    )?;
                    return Ok(Self {
                        parent,
                        name,
                        file: File::from(file),
                        published: false,
                    });
                }
                Err(rustix::io::Errno::EXIST) => continue,
                Err(error) => return Err(error).context("stage admitted directory"),
            }
        }
        bail!("directory staging name collision bound exceeded")
    }
}

impl Drop for TemporaryDirectory<'_> {
    fn drop(&mut self) {
        if !self.published
            && self.file.metadata().ok().is_some_and(|metadata| {
                require_named_file(self.parent, &self.name, &metadata).is_ok()
            })
        {
            let _ = rustix::fs::unlinkat(self.parent, &self.name, rustix::fs::AtFlags::REMOVEDIR);
        }
    }
}

impl ExistingDocumentDirectory {
    /// Observe a leaf's native metadata without following it or reading its
    /// contents. This does not grant document or removal authority; callers
    /// must still select an exact supported object through the other APIs.
    pub fn metadata(&self, name: &OsStr) -> Result<Option<fs::Metadata>> {
        validate_name(name)?;
        self.validate()?;
        let file = match rustix::fs::openat(
            &self.directory,
            name,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(file) => Some(File::from(file)),
            Err(rustix::io::Errno::NOENT) => None,
            Err(error) => return Err(error).context("hold selected entry metadata"),
        };
        let metadata = match &file {
            Some(file) => {
                let metadata = file.metadata()?;
                require_named_file(&self.directory, name, &metadata)?;
                Some(metadata)
            }
            None => {
                self.require_named_current(name, None)?;
                None
            }
        };
        self.validate()?;
        Ok(metadata)
    }

    /// Read an owner-matching single-link symbolic link without following its
    /// target or synchronizing storage. Targets are bounded to 4096 bytes.
    pub fn read_symbolic_link(&self, name: &OsStr) -> Result<Option<PathBuf>> {
        self.read_symbolic_link_with_owner(name, self.owner_uid)
    }

    /// Read a link with an explicitly selected owner, independently of the
    /// retained directory owner. The caller supplies ownership authority;
    /// observing metadata alone does not authorize the selected UID.
    pub fn read_symbolic_link_with_owner(
        &self,
        name: &OsStr,
        owner_uid: u32,
    ) -> Result<Option<PathBuf>> {
        validate_name(name)?;
        self.validate()?;
        let current = self.open_symbolic_link(name, owner_uid)?;
        if let Some(link) = &current {
            require_named_file(&self.directory, name, &link.metadata)?;
        } else {
            self.require_named_current(name, None)?;
        }
        self.validate()?;
        Ok(current.map(|link| link.target))
    }

    /// Durably remove only a symbolic link with the exact raw expected target
    /// and this directory's owner. No target is followed or modified. An
    /// absent retry synchronizes the selected parent. Caller-owned writer
    /// exclusion remains required, as for ordinary document removal.
    pub fn remove_symbolic_link(&self, name: &OsStr, expected_target: &Path) -> Result<bool> {
        self.remove_symbolic_link_with_owner(name, expected_target, self.owner_uid)
    }

    /// Durably remove an exact target/owner pair without following the target
    /// or changing ownership. Directory custody, writer-exclusion requirements
    /// and uncertain-progress semantics are unchanged from the default API.
    pub fn remove_symbolic_link_with_owner(
        &self,
        name: &OsStr,
        expected_target: &Path,
        owner_uid: u32,
    ) -> Result<bool> {
        validate_name(name)?;
        validate_symbolic_target(expected_target)?;
        self.validate()?;
        let current = self.open_symbolic_link(name, owner_uid)?;
        if let Some(link) = &current {
            if link.target.as_os_str() != expected_target.as_os_str() {
                bail!("held symbolic link differs from its expected raw target");
            }
            require_named_file(&self.directory, name, &link.metadata)?;
            self.validate()?;
            rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::empty())
                .context("remove exact held symbolic link")?;
        }
        rustix::fs::fsync(&self.directory).context("sync held symbolic-link absence")?;
        self.validate()?;
        self.require_named_current(name, None)?;
        Ok(current.is_some())
    }

    pub fn open(path: &Path, owner_uid: u32) -> Result<Self> {
        let (directory, _) = open_directory_chain(path, false)?;
        let result = Self {
            path: path.to_path_buf(),
            directory,
            owner_uid,
        };
        result.validate()?;
        Ok(result)
    }

    /// Read a single bounded regular document without mutation or storage sync.
    pub fn read(
        &self,
        name: &OsStr,
        authority: &DocumentAuthority,
    ) -> Result<Option<AtomicDocument>> {
        validate_name(name)?;
        validate_document_authority(authority)?;
        self.validate()?;
        let current = self.open_document(name, authority)?;
        self.require_named_current(name, current.as_ref())?;
        self.validate()?;
        Ok(current.map(|current| current.document))
    }

    /// Replace an exact current document while selecting different ordinary
    /// permission bits. The owner does not change; both states are bounded.
    pub fn replace(
        &self,
        name: &OsStr,
        bytes: &[u8],
        authority: &DocumentAuthority,
        current_authority: &DocumentAuthority,
        expected_current: &ArtifactIdentity,
    ) -> Result<bool> {
        self.write_with_current_authority(
            name,
            bytes,
            authority,
            current_authority,
            Some(expected_current),
        )
    }

    /// Publish exact bytes within this existing parent. Matching bytes are a
    /// durable no-op; different current bytes require the supplied identity.
    /// Authority modes exclude special bits; this does not publish set-ID files.
    pub fn write(
        &self,
        name: &OsStr,
        bytes: &[u8],
        authority: &DocumentAuthority,
        expected_current: Option<&ArtifactIdentity>,
    ) -> Result<bool> {
        self.write_with_current_authority(name, bytes, authority, authority, expected_current)
    }

    fn write_with_current_authority(
        &self,
        name: &OsStr,
        bytes: &[u8],
        authority: &DocumentAuthority,
        current_authority: &DocumentAuthority,
        expected_current: Option<&ArtifactIdentity>,
    ) -> Result<bool> {
        validate_name(name)?;
        validate_document_authority(authority)?;
        validate_document_authority(current_authority)?;
        if authority.owner_uid != current_authority.owner_uid {
            bail!("document replacement cannot change its native owner");
        }
        if bytes.is_empty() || bytes.len() as u64 > authority.limit {
            bail!("document publication exceeds its content bounds");
        }
        self.validate()?;
        let current = self.open_document(name, current_authority)?;
        if let Some(current) = &current {
            if current.document.bytes == bytes && authority.mode == current_authority.mode {
                self.require_named_current(name, Some(current))?;
                current
                    .file
                    .sync_all()
                    .context("sync unchanged held document")?;
                rustix::fs::fsync(&self.directory).context("sync unchanged document parent")?;
                self.validate()?;
                return Ok(false);
            }
        }
        match (&current, expected_current) {
            (None, None) => {}
            (Some(current), Some(expected)) if current.document.identity == *expected => {}
            _ => bail!("document publication does not match expected current authority"),
        }
        let mut temporary = TemporaryDocument::create(&self.directory)?;
        temporary
            .file
            .write_all(bytes)
            .context("write held document staging file")?;
        temporary
            .file
            .flush()
            .context("flush held document staging file")?;
        if temporary.file.metadata()?.uid() != authority.owner_uid {
            rustix::fs::fchown(
                &temporary.file,
                Some(rustix::fs::Uid::from_raw(authority.owner_uid)),
                None,
            )
            .context("assign held document owner")?;
        }
        temporary
            .file
            .set_permissions(fs::Permissions::from_mode(authority.mode))
            .context("protect held document staging file")?;
        temporary
            .file
            .sync_all()
            .context("sync held document data and metadata")?;
        temporary.file.rewind()?;
        let staged = read_atomic_document_file(
            temporary.file.try_clone()?,
            &self.path.join(&temporary.name),
            authority,
        )?;
        if staged.bytes != bytes {
            bail!("held document staging bytes changed");
        }
        let staged_metadata = temporary.file.metadata()?;
        require_named_file(&self.directory, &temporary.name, &staged_metadata)?;
        self.require_named_current(name, current.as_ref())?;
        self.validate()?;
        if current.is_some() {
            rustix::fs::renameat(&self.directory, &temporary.name, &self.directory, name)
                .context("replace held document")?;
        } else {
            rustix::fs::renameat_with(
                &self.directory,
                &temporary.name,
                &self.directory,
                name,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .context("publish held document without replacement")?;
        }
        temporary.published = true;
        rustix::fs::fsync(&self.directory).context("sync published held document parent")?;
        self.validate()?;
        let published = self
            .open_document(name, authority)?
            .context("published document disappeared")?;
        if published.document.bytes != bytes {
            bail!("published held document changed before acknowledgement");
        }
        self.require_named_current(name, Some(&published))?;
        Ok(true)
    }

    /// Remove only this single exact document. Already-absent retries sync the
    /// held parent without recreating the leaf or its directory.
    pub fn remove(
        &self,
        name: &OsStr,
        authority: &DocumentAuthority,
        expected: &ArtifactIdentity,
    ) -> Result<bool> {
        validate_name(name)?;
        validate_document_authority(authority)?;
        if expected.length == 0
            || expected.length > authority.limit
            || expected.sha256.len() != 64
            || !expected
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            bail!("held document removal identity is invalid");
        }
        self.validate()?;
        let current = self.open_document(name, authority)?;
        if let Some(current) = &current {
            if current.document.identity != *expected {
                bail!("held document removal does not match expected content");
            }
            self.require_named_current(name, Some(current))?;
            self.validate()?;
            rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::empty())
                .context("remove exact held document")?;
        }
        rustix::fs::fsync(&self.directory).context("sync held document absence")?;
        self.validate()?;
        self.require_named_current(name, None)?;
        Ok(current.is_some())
    }

    fn validate(&self) -> Result<()> {
        let held = rustix::fs::fstat(&self.directory)?;
        let (named, _) = open_directory_chain(&self.path, false)?;
        let named = rustix::fs::fstat(&named)?;
        if rustix::fs::FileType::from_raw_mode(held.st_mode) != rustix::fs::FileType::Directory
            || held.st_uid != self.owner_uid
            || held.st_mode & 0o022 != 0
            || held.st_dev != named.st_dev
            || held.st_ino != named.st_ino
        {
            bail!("selected document directory changed or has unsafe custody");
        }
        Ok(())
    }

    fn open_document(
        &self,
        name: &OsStr,
        authority: &DocumentAuthority,
    ) -> Result<Option<OpenedDocument>> {
        let file = match rustix::fs::openat(
            &self.directory,
            name,
            rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        ) {
            Ok(file) => File::from(file),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(error).context("open held document"),
        };
        let metadata = file.metadata()?;
        if metadata.mode() & 0o7777 != authority.mode {
            bail!("held document has unexpected permission bits");
        }
        let document =
            read_atomic_document_file(file.try_clone()?, &self.path.join(name), authority)?;
        require_named_file(&self.directory, name, &metadata)?;
        Ok(Some(OpenedDocument {
            file,
            metadata,
            document,
        }))
    }

    fn open_symbolic_link(
        &self,
        name: &OsStr,
        owner_uid: u32,
    ) -> Result<Option<OpenedSymbolicLink>> {
        let file = match rustix::fs::openat(
            &self.directory,
            name,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(file) => File::from(file),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(error).context("hold selected symbolic link"),
        };
        let metadata = file.metadata()?;
        if !metadata.file_type().is_symlink()
            || metadata.uid() != owner_uid
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > 4096
        {
            bail!("held symbolic link has unsafe custody or exceeds target bounds");
        }
        // Empty-path readlinkat reads this O_PATH symlink descriptor itself,
        // not a re-resolved leaf or target. Fixed storage also bounds allocation
        // for virtual links whose generated contents exceed their stat length.
        let mut bytes = [0_u8; 4097];
        let length = rustix::fs::readlinkat_raw(&file, "", &mut bytes)?;
        if length == 0 || length > 4096 || length as u64 != metadata.len() {
            bail!("held symbolic-link target changed or exceeds its bound");
        }
        let target = PathBuf::from(OsString::from_vec(bytes[..length].to_vec()));
        validate_symbolic_target(&target)?;
        require_named_file(&self.directory, name, &metadata)?;
        Ok(Some(OpenedSymbolicLink {
            _file: file,
            metadata,
            target,
        }))
    }

    fn require_named_current(&self, name: &OsStr, current: Option<&OpenedDocument>) -> Result<()> {
        if let Some(current) = current {
            return require_named_file(&self.directory, name, &current.metadata);
        }
        match rustix::fs::statat(&self.directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(error) => Err(error).context("inspect absent held document"),
            Ok(_) => bail!("held document appeared outside publication authority"),
        }
    }
}

struct OpenedDocument {
    file: File,
    metadata: fs::Metadata,
    document: AtomicDocument,
}

struct OpenedSymbolicLink {
    // Keep the selected symlink inode alive until observation/removal ends.
    _file: File,
    metadata: fs::Metadata,
    target: PathBuf,
}

fn validate_symbolic_target(target: &Path) -> Result<()> {
    let bytes = target.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() > 4096 || bytes.contains(&0) {
        bail!("symbolic-link target is outside content bounds");
    }
    Ok(())
}

fn validate_name(name: &OsStr) -> Result<()> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(component)) if component == name)
        || components.next().is_some()
    {
        bail!("held document requires a single ordinary leaf name");
    }
    Ok(())
}

fn require_named_file(directory: &OwnedFd, name: &OsStr, expected: &fs::Metadata) -> Result<()> {
    let actual = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
    if expected.dev() != actual.st_dev
        || expected.ino() != actual.st_ino
        || expected.uid() != actual.st_uid
        || expected.mode() != actual.st_mode
        || u128::from(expected.nlink()) != u128::from(actual.st_nlink)
        || expected.len() != u64::try_from(actual.st_size)?
        || expected.mtime() != actual.st_mtime
        || expected.mtime_nsec() != i64::try_from(actual.st_mtime_nsec)?
        || expected.ctime() != actual.st_ctime
        || expected.ctime_nsec() != i64::try_from(actual.st_ctime_nsec)?
    {
        bail!("held document name no longer matches its selected file");
    }
    Ok(())
}

struct TemporaryDocument<'a> {
    directory: &'a OwnedFd,
    name: OsString,
    file: File,
    published: bool,
}

impl<'a> TemporaryDocument<'a> {
    fn create(directory: &'a OwnedFd) -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..32 {
            // Names are collision-resistant within this process, not authority.
            // Exclusive descriptor-relative creation is the ownership boundary.
            let name = OsString::from(format!(
                ".dev-tools-document-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match rustix::fs::openat(
                directory,
                &name,
                rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::from_raw_mode(0o600),
            ) {
                Ok(file) => {
                    return Ok(Self {
                        directory,
                        name,
                        file: File::from(file),
                        published: false,
                    })
                }
                Err(rustix::io::Errno::EXIST) => continue,
                Err(error) => return Err(error).context("create held document staging file"),
            }
        }
        bail!("held document staging name collision bound exceeded")
    }
}

impl Drop for TemporaryDocument<'_> {
    fn drop(&mut self) {
        if !self.published
            && self.file.metadata().ok().is_some_and(|metadata| {
                metadata.nlink() == 1
                    && require_named_file(self.directory, &self.name, &metadata).is_ok()
            })
        {
            // Best-effort cleanup owns only the still-named file created here.
            // Process death or a failed cleanup can leave unmarked staging; no
            // later invocation adopts or removes entries by their name or age.
            let _ = rustix::fs::unlinkat(self.directory, &self.name, rustix::fs::AtFlags::empty());
        }
    }
}
