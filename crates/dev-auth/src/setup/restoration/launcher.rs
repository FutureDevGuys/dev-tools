//! Receipt-derived launcher restoration inside an already-closed setup
//! generation. This is not a general set-ID publisher or setup authority.
use super::*;
use std::os::fd::OwnedFd;

const NAME: &str = "dev-auth-workload-launcher";

#[derive(PartialEq, Eq)]
struct LauncherSelection {
    identity: ArtifactIdentity,
    mode: u32,
}

pub(crate) struct StrongLauncherCompletion {
    directory: OwnedFd,
    documents: dev_tools_installation::ExistingDocumentDirectory,
    source: dev_tools_installation::ExistingDocumentDirectory,
    source_name: std::ffi::OsString,
    candidate: InstallReceipt,
    prior: Option<InstallReceipt>,
    observed: Option<LauncherSelection>,
    target: LauncherSelection,
}

impl StrongLauncherCompletion {
    pub(crate) fn observe(
        paths: &SetupPaths,
        candidate: &InstallReceipt,
        prior: Option<&InstallReceipt>,
        candidate_source: &Path,
    ) -> Result<Self> {
        if !nix::unistd::Uid::effective().is_root()
            || paths != &SetupPaths::strong()
            || candidate.mode != InstallMode::Strong
            || candidate.privileged_launcher.as_deref() != Some(PRIVILEGED_LAUNCHER_PATH)
            || Path::new(&candidate.executable) != paths.versioned_binary(&candidate.version)
            || !candidate_source.is_absolute()
            || !candidate.transparent_aliases.is_empty()
            || prior.is_some_and(|prior| {
                prior.mode != InstallMode::Strong
                    || prior.privileged_launcher.as_deref() != Some(PRIVILEGED_LAUNCHER_PATH)
                    || Path::new(&prior.executable) != paths.versioned_binary(&prior.version)
            })
        {
            bail!("launcher completion requires retained native strong authority");
        }
        let documents =
            dev_tools_installation::ExistingDocumentDirectory::open(&paths.data_root, 0)?;
        let directory = rustix::fs::open(
            &paths.data_root,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        require_directory(&directory, &paths.data_root)?;
        let source = dev_tools_installation::ExistingDocumentDirectory::open(
            candidate_source
                .parent()
                .context("launcher source has no parent")?,
            0,
        )?;
        let mut proof = Self {
            directory,
            documents,
            source,
            source_name: candidate_source
                .file_name()
                .context("candidate launcher source has no name")?
                .to_os_string(),
            candidate: candidate.clone(),
            prior: prior.cloned(),
            observed: None,
            target: LauncherSelection {
                identity: receipt_identity(candidate),
                mode: privileged_launcher_mode_for_version(&candidate.version)?,
            },
        };
        proof.source_bytes()?;
        proof.observed = proof.current()?.map(|(_, selection)| selection);
        Ok(proof)
    }

    pub(crate) fn needs_publication(&self) -> bool {
        self.observed.as_ref() != Some(&self.target)
    }

    pub(crate) fn verify_observed(&self) -> Result<()> {
        if self.current()?.as_ref().map(|(_, selection)| selection) != self.observed.as_ref() {
            bail!("selected launcher changed after completion admission");
        }
        self.source_bytes()?;
        Ok(())
    }

    pub(crate) fn verify_complete(&self) -> Result<()> {
        self.require_target(privileged_launcher_mode_for_version(
            &self.candidate.version,
        )?)?;
        self.source_bytes()?;
        Ok(())
    }

    pub(crate) fn complete(
        &self,
        mut verify_generation: impl FnMut() -> Result<()>,
        mut record_change: impl FnMut(bool),
    ) -> Result<bool> {
        verify_generation()?;
        self.verify_observed()?;
        let target_mode = privileged_launcher_mode_for_version(&self.candidate.version)?;
        if !self.needs_publication() {
            let file = self.require_target(target_mode)?;
            file.sync_all()?;
            rustix::fs::fsync(&self.directory)?;
            self.verify_complete()?;
            verify_generation()?;
            return Ok(false);
        }
        let bytes = self.source_bytes()?;
        let mut changed = false;
        if let Some((file, selection)) = self.current()? {
            if selection.mode != 0o755 {
                // Privilege is removed from the held exact inode before an
                // ordinary document can replace it. Record the syscall before
                // synchronization or a later independent writer can fail.
                require_named_launcher(&self.directory, &file)?;
                file.set_permissions(fs::Permissions::from_mode(0o755))?;
                record_change(true);
                changed = true;
                file.sync_all()?;
                require_named_launcher(&self.directory, &file)?;
            }
        }
        verify_generation()?;
        let expected = self.observed.as_ref().map(|selection| LauncherSelection {
            identity: selection.identity.clone(),
            mode: 0o755,
        });
        if self.current()?.as_ref().map(|(_, selection)| selection) != expected.as_ref() {
            bail!("launcher ordinary intermediate changed before publication");
        }
        let published = self.documents.write(
            OsStr::new(NAME),
            &bytes,
            &ordinary_authority(),
            self.observed.as_ref().map(|selection| &selection.identity),
        )?;
        record_change(published);
        changed |= published;
        verify_generation()?;
        let file = self.require_target(0o755)?;
        // Only the exact candidate release selects this fixed permission.
        // A crash before it leaves recognized candidate bytes without set-ID.
        if target_mode != 0o755 {
            file.set_permissions(fs::Permissions::from_mode(target_mode))?;
            record_change(true);
            changed = true;
        }
        file.sync_all()?;
        require_named_launcher(&self.directory, &file)?;
        rustix::fs::fsync(&self.directory)?;
        self.verify_complete()?;
        verify_generation()?;
        Ok(changed)
    }

    fn source_bytes(&self) -> Result<Vec<u8>> {
        let source = self
            .source
            .read(&self.source_name, &ordinary_authority())?
            .context("candidate launcher source is absent")?;
        if source.identity != receipt_identity(&self.candidate) {
            bail!("candidate launcher source differs from retained release");
        }
        Ok(source.bytes)
    }

    fn current(&self) -> Result<Option<(File, LauncherSelection)>> {
        require_directory(&self.directory, &SetupPaths::strong().data_root)?;
        let result = if self.documents.metadata(OsStr::new(NAME))?.is_some() {
            let (file, identity, mode) = open_admitted_launcher(
                &self.directory,
                self.prior.as_ref().unwrap_or(&self.candidate),
                &self.candidate,
            )?;
            Some((file, LauncherSelection { identity, mode }))
        } else {
            // The shared observer revalidates the held parent and exact absence.
            None
        };
        require_directory(&self.directory, &SetupPaths::strong().data_root)?;
        Ok(result)
    }

    fn require_target(&self, mode: u32) -> Result<File> {
        let (file, selection) = self.current()?.context("candidate launcher disappeared")?;
        if selection.identity != receipt_identity(&self.candidate) || selection.mode != mode {
            bail!("launcher completion differs from the selected candidate pair");
        }
        Ok(file)
    }
}

fn ordinary_authority() -> DocumentAuthority {
    DocumentAuthority {
        owner_uid: 0,
        mode: 0o755,
        limit: BINARY_LIMIT,
    }
}

impl InitialInstallationRestoration {
    pub(super) fn observe_initial_privileged_launcher(&self) -> Result<()> {
        if self.directory.metadata(OsStr::new(NAME))?.is_none() {
            return Ok(());
        }
        let directory = rustix::fs::open(
            &self.paths.data_root,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        require_directory(&directory, &self.paths.data_root)?;
        open_admitted_launcher(&directory, &self.candidate, &self.candidate)?;
        require_directory(&directory, &self.paths.data_root)
    }

    pub(super) fn retire_initial_privileged_launcher(&self) -> Result<bool> {
        self.require_initial_native_authority()?;
        if self.directory.metadata(OsStr::new(NAME))?.is_some() {
            let directory = rustix::fs::open(
                &self.paths.data_root,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?;
            require_directory(&directory, &self.paths.data_root)?;
            let (file, _, mode) =
                open_admitted_launcher(&directory, &self.candidate, &self.candidate)?;
            if mode != 0o755 {
                // Clear privilege on the held exact candidate before unlink.
                // A crash leaves only an admitted ordinary-mode intermediate.
                file.set_permissions(fs::Permissions::from_mode(0o755))?;
                file.sync_all()?;
                require_named_launcher(&directory, &file)?;
            }
            require_directory(&directory, &self.paths.data_root)?;
        }
        self.directory.remove(
            OsStr::new(NAME),
            &DocumentAuthority {
                owner_uid: 0,
                mode: 0o755,
                limit: BINARY_LIMIT,
            },
            &self.shared.active_identity,
        )
    }
}

impl RetainedInstallationRestoration {
    pub(super) fn restore_privileged_launcher(&self) -> Result<bool> {
        if self.original.mode == InstallMode::UserOnly {
            return Ok(false);
        }
        if !nix::unistd::Uid::effective().is_root() {
            bail!("privileged launcher restoration requires native root");
        }
        if !self.admitted_receipt()?.transparent_aliases.is_empty() {
            bail!("privileged launcher restoration requires inactive transparent integrations");
        }
        self.verify_inactive_transparent()?;
        let directory = rustix::fs::open(
            &self.paths.data_root,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        require_directory(&directory, &self.paths.data_root)?;
        let source_path = Path::new(&self.original.executable);
        let source_directory = dev_tools_installation::ExistingDocumentDirectory::open(
            source_path
                .parent()
                .context("retained launcher source has no parent")?,
            0,
        )?;
        let source = source_directory
            .read(
                source_path
                    .file_name()
                    .context("retained launcher source has no leaf")?,
                &DocumentAuthority {
                    owner_uid: 0,
                    mode: 0o755,
                    limit: BINARY_LIMIT,
                },
            )?
            .context("retained privileged launcher source is absent")?;
        let original_identity = receipt_identity(&self.original);
        if source.identity != original_identity {
            bail!("retained privileged launcher source changed");
        }
        let target_mode = privileged_launcher_mode_for_version(&self.original.version)?;
        let (file, current_identity, current_mode) =
            open_admitted_launcher(&directory, &self.original, &self.candidate)?;
        self.current_document()?;
        require_directory(&directory, &self.paths.data_root)?;
        if current_identity == original_identity && current_mode == target_mode {
            file.sync_all()?;
            rustix::fs::fsync(&directory)?;
            require_named_launcher(&directory, &file)?;
            require_directory(&directory, &self.paths.data_root)?;
            return Ok(false);
        }
        // Clearing privilege on the held inode precedes ordinary publication.
        // A crash at either boundary is admitted only for the exact retained
        // original/candidate bytes at ordinary 0755, never unrelated bytes.
        if current_mode != 0o755 {
            require_named_launcher(&directory, &file)?;
            file.set_permissions(fs::Permissions::from_mode(0o755))?;
            file.sync_all()?;
            require_named_launcher(&directory, &file)?;
        }
        let authority = DocumentAuthority {
            owner_uid: 0,
            mode: 0o755,
            limit: BINARY_LIMIT,
        };
        self.receipt_directory.replace(
            OsStr::new(NAME),
            &source.bytes,
            &authority,
            &authority,
            &current_identity,
        )?;
        require_directory(&directory, &self.paths.data_root)?;
        let (published, identity, mode) =
            open_admitted_launcher(&directory, &self.original, &self.candidate)?;
        if identity != original_identity || mode != 0o755 {
            bail!("privileged launcher publication differs from the retained target");
        }
        // This permission comes from the prior release's product contract,
        // never from the retained candidate's mode or caller-supplied bits.
        published.set_permissions(fs::Permissions::from_mode(target_mode))?;
        published.sync_all()?;
        require_named_launcher(&directory, &published)?;
        rustix::fs::fsync(&directory)?;
        require_directory(&directory, &self.paths.data_root)?;
        let (_, identity, mode) =
            open_admitted_launcher(&directory, &self.original, &self.candidate)?;
        if identity != original_identity || mode != target_mode {
            bail!("privileged launcher restoration is incomplete");
        }
        Ok(true)
    }
}

fn receipt_identity(receipt: &InstallReceipt) -> ArtifactIdentity {
    ArtifactIdentity {
        length: receipt.executable_length,
        sha256: receipt.executable_sha256.clone(),
    }
}

fn require_directory(directory: &OwnedFd, path: &Path) -> Result<()> {
    let held = rustix::fs::fstat(directory)?;
    let named = fs::symlink_metadata(path)?;
    if !named.is_dir()
        || named.file_type().is_symlink()
        || named.uid() != 0
        || named.mode() & 0o022 != 0
        || held.st_dev != named.dev()
        || held.st_ino != named.ino()
        || held.st_uid != named.uid()
        || held.st_mode != named.mode()
    {
        bail!("privileged launcher directory changed or has unsafe custody");
    }
    Ok(())
}

fn require_named_launcher(directory: &OwnedFd, file: &File) -> Result<()> {
    let held = file.metadata()?;
    require_named_metadata(directory, &held)
}

fn require_named_metadata(directory: &OwnedFd, held: &fs::Metadata) -> Result<()> {
    let named = rustix::fs::statat(directory, NAME, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
    if held.dev() != named.st_dev
        || held.ino() != named.st_ino
        || held.uid() != named.st_uid
        || held.mode() != named.st_mode
        || u128::from(held.nlink()) != u128::from(named.st_nlink)
        || held.len() != u64::try_from(named.st_size)?
        || held.mtime() != named.st_mtime
        || held.mtime_nsec() != i64::try_from(named.st_mtime_nsec)?
        || held.ctime() != named.st_ctime
        || held.ctime_nsec() != i64::try_from(named.st_ctime_nsec)?
    {
        bail!("privileged launcher no longer names the held executable");
    }
    Ok(())
}

fn open_admitted_launcher(
    directory: &OwnedFd,
    original: &InstallReceipt,
    candidate: &InstallReceipt,
) -> Result<(File, ArtifactIdentity, u32)> {
    let file = File::from(rustix::fs::openat(
        directory,
        NAME,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > BINARY_LIMIT
    {
        bail!("privileged launcher has unsafe custody");
    }
    let mut bytes = Vec::new();
    (&file).take(BINARY_LIMIT + 1).read_to_end(&mut bytes)?;
    let identity = ArtifactIdentity {
        length: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(&bytes)),
    };
    let mode = metadata.mode() & 0o7777;
    let mut admitted = false;
    for receipt in [original, candidate] {
        admitted |= identity == receipt_identity(receipt)
            && (mode == privileged_launcher_mode_for_version(&receipt.version)? || mode == 0o755);
    }
    if identity.length > BINARY_LIMIT || identity.length != metadata.len() || !admitted {
        bail!("privileged launcher is outside the retained content/permission pair");
    }
    require_named_metadata(directory, &metadata)?;
    Ok((file, identity, mode))
}
