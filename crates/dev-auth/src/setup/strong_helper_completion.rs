//! Fixed ordinary helper publication within retained, inactive strong recovery.
use super::*;
use dev_tools_installation::{ArtifactIdentity, DocumentAuthority, ExistingDocumentDirectory};

const HELPER_NAME: &str = "dev-auth-setup-helper";

pub(super) struct StrongHelperCompletion {
    directory: ExistingDocumentDirectory,
    source_directory: ExistingDocumentDirectory,
    source_name: std::ffi::OsString,
    candidate: ArtifactIdentity,
    helper_observed: Option<ArtifactIdentity>,
    sidecar_observed: Option<ArtifactIdentity>,
    sidecar_bytes: Vec<u8>,
}

impl StrongHelperCompletion {
    // The caller supplies only its already-validated retained generation. This
    // proof is private and cannot grant release, root, or service authority.
    pub(super) fn observe(
        paths: &SetupPaths,
        candidate: &InstallReceipt,
        prior: Option<&InstallReceipt>,
        candidate_source: &Path,
    ) -> Result<Self> {
        if !nix::unistd::Uid::effective().is_root()
            || paths != &SetupPaths::strong()
            || candidate.mode != InstallMode::Strong
            || !candidate.transparent_aliases.is_empty()
            || !release_supports_setup_helper(candidate)
            || Path::new(&candidate.executable) != paths.versioned_binary(&candidate.version)
            || !candidate_source.is_absolute()
        {
            bail!("helper completion requires retained native strong authority");
        }
        let prior = prior.filter(|receipt| release_supports_setup_helper(receipt));
        if prior.is_some_and(|receipt| {
            receipt.mode != InstallMode::Strong
                || Path::new(&receipt.executable) != paths.versioned_binary(&receipt.version)
        }) {
            bail!("prior setup helper has inconsistent retained authority");
        }
        let directory = ExistingDocumentDirectory::open(&paths.data_root, 0)?;
        let source_directory = ExistingDocumentDirectory::open(
            candidate_source
                .parent()
                .context("candidate helper source has no parent")?,
            0,
        )?;
        let identity = receipt_identity(candidate);
        let source_name = candidate_source
            .file_name()
            .context("candidate helper source has no name")?
            .to_os_string();
        let source = source_directory
            .read(&source_name, &helper_authority())?
            .context("candidate helper source is absent")?;
        if source.identity != identity {
            bail!("candidate helper source differs from retained release");
        }
        let helper = directory.read(OsStr::new(HELPER_NAME), &helper_authority())?;
        if helper.as_ref().is_some_and(|observed| {
            observed.identity != identity
                && !prior.is_some_and(|receipt| observed.identity == receipt_identity(receipt))
        }) {
            bail!("setup helper is outside retained executable authority");
        }
        let sidecar =
            directory.read(OsStr::new(SETUP_HELPER_RECEIPT_NAME), &sidecar_authority())?;
        let target = crate::release_manifest::target_id()?;
        let expected =
            expected_setup_helper_receipt(Path::new(SETUP_HELPER_PATH), candidate, &target);
        let mut sidecar_bytes = serde_json::to_vec_pretty(&expected)?;
        if let Some(observed) = &sidecar {
            let parsed: SetupHelperReceipt = serde_json::from_slice(&observed.bytes)?;
            if parsed == expected {
                // Preserve already-correct serialization on a receipt-only retry.
                sidecar_bytes = observed.bytes.clone();
            } else if !prior.is_some_and(|receipt| {
                parsed
                    == expected_setup_helper_receipt(Path::new(SETUP_HELPER_PATH), receipt, &target)
            }) {
                bail!("setup helper sidecar is outside retained release authority");
            }
        }
        Ok(Self {
            directory,
            source_directory,
            source_name,
            candidate: identity,
            helper_observed: helper.map(|document| document.identity),
            sidecar_observed: sidecar.map(|document| document.identity),
            sidecar_bytes,
        })
    }

    pub(super) fn needs_publication(&self) -> bool {
        self.helper_observed.as_ref() != Some(&self.candidate)
            || self.sidecar_observed.as_ref() != Some(&bytes_identity(&self.sidecar_bytes))
    }

    pub(super) fn verify_observed(&self) -> Result<()> {
        self.require_leaf(
            HELPER_NAME,
            &helper_authority(),
            self.helper_observed.as_ref(),
        )?;
        self.require_leaf(
            SETUP_HELPER_RECEIPT_NAME,
            &sidecar_authority(),
            self.sidecar_observed.as_ref(),
        )?;
        self.source()?;
        Ok(())
    }

    pub(super) fn complete(
        &self,
        mut verify_generation: impl FnMut() -> Result<()>,
        mut record_change: impl FnMut(bool),
    ) -> Result<bool> {
        verify_generation()?;
        self.verify_observed()?;
        let source = self.source()?;
        let mut changed = self.directory.write(
            OsStr::new(HELPER_NAME),
            &source,
            &helper_authority(),
            self.helper_observed.as_ref(),
        )?;
        record_change(changed);
        // A later failure must preserve the known helper publication. A fresh
        // proof can admit this mixed pair, but a stale proof cannot adopt edits.
        verify_generation()?;
        self.require_leaf(HELPER_NAME, &helper_authority(), Some(&self.candidate))?;
        self.require_leaf(
            SETUP_HELPER_RECEIPT_NAME,
            &sidecar_authority(),
            self.sidecar_observed.as_ref(),
        )?;
        let published = self.directory.write(
            OsStr::new(SETUP_HELPER_RECEIPT_NAME),
            &self.sidecar_bytes,
            &sidecar_authority(),
            self.sidecar_observed.as_ref(),
        )?;
        record_change(published);
        changed |= published;
        verify_generation()?;
        self.require_leaf(HELPER_NAME, &helper_authority(), Some(&self.candidate))?;
        self.require_leaf(
            SETUP_HELPER_RECEIPT_NAME,
            &sidecar_authority(),
            Some(&bytes_identity(&self.sidecar_bytes)),
        )?;
        Ok(changed)
    }

    fn source(&self) -> Result<Vec<u8>> {
        let source = self
            .source_directory
            .read(&self.source_name, &helper_authority())?
            .context("candidate helper source disappeared")?;
        if source.identity != self.candidate {
            bail!("candidate helper source changed after admission");
        }
        Ok(source.bytes)
    }

    fn require_leaf(
        &self,
        name: &str,
        authority: &DocumentAuthority,
        expected: Option<&ArtifactIdentity>,
    ) -> Result<()> {
        let observed = self.directory.read(OsStr::new(name), authority)?;
        if observed.as_ref().map(|document| &document.identity) != expected {
            bail!("selected setup helper leaf changed after admission");
        }
        Ok(())
    }
}

fn receipt_identity(receipt: &InstallReceipt) -> ArtifactIdentity {
    ArtifactIdentity {
        length: receipt.executable_length,
        sha256: receipt.executable_sha256.clone(),
    }
}

fn bytes_identity(bytes: &[u8]) -> ArtifactIdentity {
    ArtifactIdentity {
        length: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
    }
}

fn helper_authority() -> DocumentAuthority {
    DocumentAuthority {
        owner_uid: 0,
        mode: 0o755,
        limit: BINARY_LIMIT,
    }
}

fn sidecar_authority() -> DocumentAuthority {
    DocumentAuthority {
        owner_uid: 0,
        mode: 0o644,
        limit: RECEIPT_LIMIT,
    }
}
