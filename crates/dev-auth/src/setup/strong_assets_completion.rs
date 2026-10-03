//! Exact fixed definitions for an already committed, inactive strong candidate.
use super::*;
use dev_tools_installation::{
    ArtifactIdentity, DocumentAuthority, DocumentDirectoryPreparation, ExistingDocumentDirectory,
};

struct Asset {
    directory: usize,
    path: &'static Path,
    bytes: &'static [u8],
    observed: Option<ArtifactIdentity>,
    candidate: ArtifactIdentity,
}

pub(super) struct StrongAssetsCompletion {
    directories: Vec<(&'static Path, DocumentDirectoryPreparation)>,
    assets: Vec<Asset>,
}

impl StrongAssetsCompletion {
    pub(super) fn observe(
        paths: &SetupPaths,
        candidate: &InstallReceipt,
        prior: Option<&InstallReceipt>,
    ) -> Result<Self> {
        if !nix::unistd::Uid::effective().is_root()
            || paths != &SetupPaths::strong()
            || candidate.mode != InstallMode::Strong
            || !candidate.transparent_aliases.is_empty()
            || candidate.system_assets != system_asset_digests()
        {
            bail!("system definition completion requires exact compiled strong authority");
        }
        if let Some(prior) = prior {
            if prior.mode != InstallMode::Strong {
                bail!("prior system definitions lack strong authority");
            }
            validate_system_asset_receipt_shape(&prior.system_assets)?;
        }
        let mut assets = Vec::new();
        let mut directories = Vec::<(&'static Path, DocumentDirectoryPreparation)>::new();
        for (path, content, mode) in linux_system_assets() {
            if mode != 0o644 {
                bail!("unsupported system definition publication mode");
            }
            let parent = path.parent().context("system definition has no parent")?;
            let directory = match directories.iter().position(|(path, _)| *path == parent) {
                Some(index) => index,
                None => {
                    directories.push((
                        parent,
                        DocumentDirectoryPreparation::observe(parent, 0, 0o755)?,
                    ));
                    directories.len() - 1
                }
            };
            let document = directories[directory].1.read(
                path.file_name().context("system definition has no name")?,
                &authority(),
            )?;
            let bytes = content.as_bytes();
            let identity = ArtifactIdentity {
                length: bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(bytes)),
            };
            if document.as_ref().is_some_and(|observed| {
                observed.identity != identity
                    && !prior.is_some_and(|prior| {
                        prior.system_assets.get(&path.display().to_string())
                            == Some(&observed.identity.sha256)
                    })
            }) {
                bail!("system definition is outside retained authority");
            }
            assets.push(Asset {
                directory,
                path,
                bytes,
                observed: document.map(|document| document.identity),
                candidate: identity,
            });
        }
        let selected = Self {
            directories,
            assets,
        };
        selected.verify_progress(0, &[])?;
        Ok(selected)
    }

    pub(super) fn needs_publication(&self) -> bool {
        self.assets
            .iter()
            .any(|asset| asset.observed.as_ref() != Some(&asset.candidate))
    }

    pub(super) fn verify_observed(&self) -> Result<()> {
        self.verify_progress(0, &[])
    }

    fn verify_progress(
        &self,
        published: usize,
        prepared: &[ExistingDocumentDirectory],
    ) -> Result<()> {
        let mut files = [false; 3];
        for (index, asset) in self.assets.iter().enumerate() {
            let expected = if index < published {
                Some(&asset.candidate)
            } else {
                asset.observed.as_ref()
            };
            let name = asset.path.file_name().unwrap();
            let observed = match prepared.get(asset.directory) {
                Some(directory) => directory.read(name, &authority())?,
                None => self.directories[asset.directory]
                    .1
                    .read(name, &authority())?,
            };
            if observed.as_ref().map(|document| &document.identity) != expected {
                bail!("selected system definition changed after admission");
            }
            for (unit_index, name) in [
                "dev-auth-broker.socket",
                "dev-auth-broker-control.socket",
                "dev-auth-broker.service",
            ]
            .into_iter()
            .enumerate()
            {
                if asset.path == Path::new("/etc/systemd/system").join(name) {
                    files[unit_index] = expected.is_some();
                }
            }
        }
        restoration::require_completion_services_stopped(&files)
    }

    pub(super) fn complete(
        &self,
        mut verify_generation: impl FnMut() -> Result<()>,
        mut record_change: impl FnMut(bool),
    ) -> Result<bool> {
        let mut changed = false;
        let mut prepared = Vec::new();
        for (_, directory) in &self.directories {
            verify_generation()?;
            self.verify_progress(0, &prepared)?;
            let (directory, published) = directory.prepare()?;
            record_change(published);
            changed |= published;
            prepared.push(directory);
        }
        for (index, asset) in self.assets.iter().enumerate() {
            verify_generation()?;
            self.verify_progress(index, &prepared)?;
            let published = prepared[asset.directory].write(
                asset.path.file_name().unwrap(),
                asset.bytes,
                &authority(),
                asset.observed.as_ref(),
            )?;
            record_change(published);
            changed |= published;
        }
        verify_generation()?;
        self.verify_progress(self.assets.len(), &prepared)?;
        changed |= restoration::synchronize_completion_services(&mut record_change)?;
        verify_generation()?;
        self.verify_progress(self.assets.len(), &prepared)?;
        Ok(changed)
    }
}

fn authority() -> DocumentAuthority {
    DocumentAuthority {
        owner_uid: 0,
        mode: 0o644,
        limit: RECEIPT_LIMIT,
    }
}
