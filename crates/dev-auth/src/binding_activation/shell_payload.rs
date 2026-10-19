//! Private immutable shell definitions owned by the full setup transaction.
//! Typed plans/receipts select exact bytes; this component grants no admission.

use super::BindingSetReceipt;
use crate::setup::InstallMode;
use crate::smart_binding::{
    canonical_retained_binding_plan, normalized_binding_resolution, validate_binding_generation,
    validate_binding_receipt_structure, BindingAuthority, BindingGeneration, BindingPlan,
    BindingPlanChange, BindingReceipt, BindingResolution,
};
use anyhow::{bail, Context, Result};
use dev_tools_installation::{
    ArtifactIdentity, AtomicDocument, DocumentAuthority, DocumentDirectoryPreparation,
    ExistingDocumentDirectory,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

const ROOT: &str = "/var/lib/dev-auth/private-shell-bindings";
const SOURCE: &str = "source";
const METADATA: &str = "metadata-v1.json";
const MARKER: &str = "retirement-v1.json";
const SCHEMA: &str = "dev-auth-private-shell-source-v1";
const RETIREMENT_SCHEMA: &str = "dev-auth-private-shell-retirement-v1";
const SOURCE_LIMIT: u64 = 64 * 1024;
const METADATA_LIMIT: u64 = 64 * 1024;
const INVENTORY_LIMIT: usize = 4096;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Metadata {
    schema: String,
    account_uid: u32,
    alias: String,
    generation: BindingGeneration,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Retirement {
    schema: String,
    metadata: Metadata,
}

struct Store {
    root: PathBuf,
    account: PathBuf,
    account_uid: u32,
    owner_uid: u32,
}

impl Store {
    fn new(mode: InstallMode, home: &Path, uid: u32) -> Result<Self> {
        if uid == 0
            || !home.is_absolute()
            || home
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            bail!("private shell account authority is invalid");
        }
        let caller = nix::unistd::Uid::effective().as_raw();
        let owner_uid = match mode {
            InstallMode::Strong if caller == 0 => 0,
            InstallMode::UserOnly if caller == 0 || caller == uid => uid,
            _ => bail!("private shell store requires its selected native owner"),
        };
        let root = match mode {
            InstallMode::Strong => PathBuf::from(ROOT),
            InstallMode::UserOnly => home.join(".local/share/dev-auth/private-shell-bindings"),
        };
        let account = match mode {
            InstallMode::Strong => root.join(uid.to_string()),
            InstallMode::UserOnly => root.clone(),
        };
        Ok(Self {
            root,
            account,
            account_uid: uid,
            owner_uid,
        })
    }

    fn authority(&self, limit: u64) -> DocumentAuthority {
        DocumentAuthority {
            owner_uid: self.owner_uid,
            mode: 0o600,
            limit,
        }
    }

    fn metadata(&self, alias: &str, generation: &BindingGeneration) -> Result<Metadata> {
        crate::setup::validate_workload_alias_names(&[alias.to_owned()])?;
        validate_binding_generation(generation)?;
        let generation = BindingGeneration {
            generation: generation.generation,
            intent: generation.intent.clone(),
            resolved: normalized_binding_resolution(&generation.resolved)?,
        };
        if generation.intent.command_name != alias
            || generation.resolved.identity().authority != BindingAuthority::RootOwned
            || !matches!(
                generation.resolved,
                BindingResolution::PinnedShellSource { .. }
            )
        {
            bail!("private shell source differs from its pinned binding authority");
        }
        Ok(Metadata {
            schema: SCHEMA.into(),
            account_uid: self.account_uid,
            alias: alias.into(),
            generation,
        })
    }

    fn validate_metadata(&self, metadata: &Metadata) -> Result<()> {
        if *metadata != self.metadata(&metadata.alias, &metadata.generation)? {
            bail!("private shell metadata differs from its native account or generation");
        }
        Ok(())
    }

    fn directory_name(metadata: &Metadata) -> Result<String> {
        let BindingResolution::PinnedShellSource { source_sha256, .. } =
            &metadata.generation.resolved
        else {
            bail!("private shell metadata must omit source text");
        };
        Ok(format!(
            "g{}-{source_sha256}",
            metadata.generation.generation
        ))
    }

    fn path(&self, metadata: &Metadata) -> Result<PathBuf> {
        self.validate_metadata(metadata)?;
        Ok(self
            .account
            .join(&metadata.alias)
            .join(Self::directory_name(metadata)?))
    }

    fn open_account(&self) -> Result<Option<PrivateDirectory>> {
        // Admission validates all existing ancestors without creating an absent
        // private suffix. Existing private components require exact 0700.
        DocumentDirectoryPreparation::observe(&self.root, self.owner_uid, 0o700)?
            .verify_observed()?;
        let Some(root) = PrivateDirectory::open(&self.root, self.owner_uid)? else {
            return Ok(None);
        };
        if self.account == self.root {
            Ok(Some(root))
        } else {
            root.child(OsStr::new(&self.account_uid.to_string()))
        }
    }

    fn prepare_account(&self) -> Result<(PrivateDirectory, bool)> {
        // Full setup owns the enclosing product directory and its public or
        // private mode. This component may create only its private suffix.
        let base = self
            .root
            .parent()
            .context("private shell root has no product parent")?;
        let base = crate::privilege::custody::HeldResource::open(base, self.owner_uid)
            .context("private shell publication requires its existing product directory")?;
        let stat = rustix::fs::fstat(&base.descriptor)?;
        if !base.is_directory()? || stat.st_uid != self.owner_uid || stat.st_mode & 0o7022 != 0 {
            bail!("private shell product parent has unsafe native custody");
        }
        let (_, mut changed) =
            DocumentDirectoryPreparation::observe(&self.root, self.owner_uid, 0o700)?.prepare()?;
        base.verify()?;
        let root = PrivateDirectory::open(&self.root, self.owner_uid)?
            .context("private shell root disappeared")?;
        if self.account == self.root {
            return Ok((root, changed));
        }
        let (_, account_changed) =
            DocumentDirectoryPreparation::observe(&self.account, self.owner_uid, 0o700)?
                .prepare()?;
        changed |= account_changed;
        root.verify()?;
        Ok((
            PrivateDirectory::open(&self.account, self.owner_uid)?
                .context("private shell account disappeared")?,
            changed,
        ))
    }

    fn open_generation(&self, metadata: &Metadata) -> Result<Option<PrivateDirectory>> {
        let Some(account) = self.open_account()? else {
            return Ok(None);
        };
        let Some(alias) = account.child(OsStr::new(&metadata.alias))? else {
            return Ok(None);
        };
        alias.child(OsStr::new(&Self::directory_name(metadata)?))
    }

    fn marker(&self, account: &PrivateDirectory) -> Result<Option<(Retirement, ArtifactIdentity)>> {
        let Some(document) = account
            .documents
            .read(OsStr::new(MARKER), &self.authority(METADATA_LIMIT))?
        else {
            return Ok(None);
        };
        let marker: Retirement = serde_json::from_slice(&document.bytes)
            .map_err(|_| anyhow::anyhow!("private shell retirement document is invalid"))?;
        if marker.schema != RETIREMENT_SCHEMA || serde_jcs::to_vec(&marker)? != document.bytes {
            bail!("private shell retirement is not exact canonical authority");
        }
        self.validate_metadata(&marker.metadata)?;
        Ok(Some((marker, document.identity)))
    }

    fn observe(&self, metadata: &Metadata, complete: bool) -> Result<bool> {
        self.validate_metadata(metadata)?;
        let Some(directory) = self.open_generation(metadata)? else {
            return Ok(false);
        };
        let entries = directory.entries()?;
        if entries
            .iter()
            .any(|entry| entry != SOURCE && entry != METADATA)
        {
            bail!("private shell generation contains an unowned entry");
        }
        let source = directory
            .documents
            .read(OsStr::new(SOURCE), &self.authority(SOURCE_LIMIT))?;
        if let Some(source) = &source {
            verify_source(source, metadata)?;
        }
        let recorded = directory
            .documents
            .read(OsStr::new(METADATA), &self.authority(METADATA_LIMIT))?;
        if let Some(recorded) = &recorded {
            if recorded.bytes != serde_jcs::to_vec(metadata)? {
                bail!("private shell generation has different metadata");
            }
        }
        if complete && (source.is_none() || recorded.is_none()) {
            bail!("private shell generation is incomplete");
        }
        directory.verify()?;
        Ok(true)
    }

    fn publish(&self, metadata: &Metadata, source: &[u8]) -> Result<bool> {
        verify_source_bytes(source, metadata)?;
        // Validate any existing partial before entering directory publication.
        self.observe(metadata, false)?;
        if let Some(account) = self.open_account()? {
            if self.marker(&account)?.is_some() {
                bail!("private shell retirement requires recovery")
            }
        }
        let (account, mut changed) = self.prepare_account()?;
        if self.marker(&account)?.is_some() {
            bail!("private shell retirement requires recovery")
        }
        let path = self.path(metadata)?;
        let (_, directories_changed) =
            DocumentDirectoryPreparation::observe(&path, self.owner_uid, 0o700)?.prepare()?;
        changed |= directories_changed;
        // Validate every private parent, including an existing alias's mode.
        let directory = self
            .open_generation(metadata)?
            .context("private shell generation disappeared")?;
        changed |= directory.documents.write(
            OsStr::new(SOURCE),
            source,
            &self.authority(SOURCE_LIMIT),
            None,
        )?;
        changed |= directory.documents.write(
            OsStr::new(METADATA),
            &serde_jcs::to_vec(metadata)?,
            &self.authority(METADATA_LIMIT),
            None,
        )?;
        if !self.observe(metadata, true)? {
            bail!("published private shell generation disappeared")
        }
        Ok(changed)
    }

    fn finish_retirement(&self, account: &PrivateDirectory, marker: &Retirement) -> Result<()> {
        self.validate_metadata(&marker.metadata)?;
        let metadata = &marker.metadata;
        if !self.observe(metadata, false)? {
            self.sync_generation_absence(account, metadata)?;
            return Ok(());
        }
        let alias = account
            .child(OsStr::new(&metadata.alias))?
            .context("retiring shell alias disappeared")?;
        let name = Self::directory_name(metadata)?;
        let directory = alias
            .child(OsStr::new(&name))?
            .context("retiring shell generation disappeared")?;
        let source_identity = source_identity(metadata)?;
        directory.documents.remove(
            OsStr::new(SOURCE),
            &self.authority(SOURCE_LIMIT),
            &source_identity,
        )?;
        let bytes = serde_jcs::to_vec(metadata)?;
        directory.documents.remove(
            OsStr::new(METADATA),
            &self.authority(METADATA_LIMIT),
            &bytes_identity(&bytes),
        )?;
        directory.verify()?;
        alias.remove_empty_child(OsStr::new(&name), &directory)?;
        account.sync()?;
        Ok(())
    }

    fn sync_generation_absence(
        &self,
        account: &PrivateDirectory,
        metadata: &Metadata,
    ) -> Result<()> {
        if let Some(alias) = account.child(OsStr::new(&metadata.alias))? {
            if alias
                .child(OsStr::new(&Self::directory_name(metadata)?))?
                .is_some()
            {
                bail!("retired private shell generation reappeared");
            }
            // A preceding attempt may have removed the directory and failed
            // its parent sync. The marker must outlive this acknowledgement.
            alias.sync()?;
        }
        account.sync()
    }

    fn resume_retirement(
        &self,
        account: &PrivateDirectory,
        keep: &BTreeSet<PathBuf>,
    ) -> Result<bool> {
        let Some((marker, identity)) = self.marker(account)? else {
            return Ok(false);
        };
        if keep.contains(&self.path(&marker.metadata)?) {
            bail!("retiring private shell source is still retained");
        }
        self.finish_retirement(account, &marker)?;
        if !account.documents.remove(
            OsStr::new(MARKER),
            &self.authority(METADATA_LIMIT),
            &identity,
        )? {
            bail!("private shell retirement marker disappeared before completion");
        }
        Ok(true)
    }

    fn retire(&self, metadata: &Metadata) -> Result<bool> {
        self.validate_metadata(metadata)?;
        let Some(account) = self.open_account()? else {
            return Ok(false);
        };
        if let Some((marker, _)) = self.marker(&account)? {
            if marker.metadata != *metadata {
                bail!("another private shell retirement requires recovery")
            }
            return self.resume_retirement(&account, &BTreeSet::new());
        }
        if !self.observe(metadata, false)? {
            self.sync_generation_absence(&account, metadata)?;
            return Ok(false);
        }
        let marker = Retirement {
            schema: RETIREMENT_SCHEMA.into(),
            metadata: metadata.clone(),
        };
        account.documents.write(
            OsStr::new(MARKER),
            &serde_jcs::to_vec(&marker)?,
            &self.authority(METADATA_LIMIT),
            None,
        )?;
        self.resume_retirement(&account, &BTreeSet::new())
    }

    fn collect(&self, retained: &[&BindingSetReceipt]) -> Result<bool> {
        if retained.len() > INVENTORY_LIMIT {
            bail!("retained private shell inventory exceeds its bound");
        }
        let mut keep = BTreeMap::new();
        for set in retained {
            if set.account_uid != self.account_uid
                || set.schema != super::SCHEMA
                || set.platform != format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
                || set.bindings.len() > 128
            {
                bail!("retained shell set has invalid native authority")
            }
            for (alias, binding) in &set.bindings {
                validate_binding_receipt_structure(binding)?;
                for generation in std::iter::once(&binding.active).chain(binding.previous.iter()) {
                    if crate::smart_binding::is_pinned_shell_resolution(&generation.resolved) {
                        let metadata = self.metadata(alias, generation)?;
                        let path = self.path(&metadata)?;
                        if keep.len() == INVENTORY_LIMIT && !keep.contains_key(&path) {
                            bail!("retained private shell inventory exceeds its bound");
                        }
                        if let Some(previous) = keep.insert(path, metadata.clone()) {
                            if previous != metadata {
                                bail!("retained shell generations conflict")
                            }
                        }
                    }
                }
            }
        }
        let Some(account) = self.open_account()? else {
            if !keep.is_empty() {
                bail!("retained private shell store is absent")
            }
            return Ok(false);
        };
        let pending = self.marker(&account)?;
        let pending_path = pending
            .as_ref()
            .map(|(marker, _)| self.path(&marker.metadata))
            .transpose()?;
        if pending_path
            .as_ref()
            .is_some_and(|path| keep.contains_key(path))
        {
            bail!("retiring private shell source is still retained");
        }
        let mut seen = BTreeSet::new();
        let mut stale = Vec::new();
        let mut visited = 0;
        for alias in account.entries()? {
            if alias == MARKER {
                continue;
            }
            crate::setup::validate_workload_alias_names(std::slice::from_ref(&alias))?;
            let directory = account
                .child(OsStr::new(&alias))?
                .context("private shell alias disappeared")?;
            for name in directory.entries()? {
                visited += 1;
                if visited > INVENTORY_LIMIT {
                    bail!("private shell generation inventory exceeds its bound");
                }
                let generation = directory
                    .child(OsStr::new(&name))?
                    .context("private shell generation disappeared")?;
                let path = generation.path.clone();
                if pending_path.as_ref() == Some(&path) {
                    self.observe(
                        &pending
                            .as_ref()
                            .context("shell retirement disappeared")?
                            .0
                            .metadata,
                        false,
                    )?;
                    continue;
                }
                let document = generation
                    .documents
                    .read(OsStr::new(METADATA), &self.authority(METADATA_LIMIT))?
                    .context("unretained shell generation has no ownership metadata")?;
                let metadata: Metadata = serde_json::from_slice(&document.bytes)
                    .map_err(|_| anyhow::anyhow!("private shell ownership metadata is invalid"))?;
                self.validate_metadata(&metadata)?;
                if serde_jcs::to_vec(&metadata)? != document.bytes
                    || self.path(&metadata)? != path
                    || metadata.alias != alias
                {
                    bail!("private shell ownership metadata differs from its exact path");
                }
                self.observe(&metadata, true)?;
                if let Some(expected) = keep.get(&path) {
                    if expected != &metadata {
                        bail!("retained private shell metadata changed")
                    }
                    seen.insert(path);
                } else {
                    stale.push(metadata);
                }
            }
        }
        if keep.keys().any(|path| !seen.contains(path)) {
            bail!("retained shell generation has no complete private store")
        }
        let keep_paths = keep.into_keys().collect();
        let mut changed = self.resume_retirement(&account, &keep_paths)?;
        for metadata in stale {
            changed |= self.retire(&metadata)?;
        }
        // Finish a prior marker-removal sync failure even when no marked
        // generation remains visible on an otherwise unchanged retry.
        account.sync()?;
        Ok(changed)
    }
}

/// Retained readable directory plus the shared descriptor-bound document
/// operations. Inventory uses our native descriptor instead of re-resolving
/// the directory pathname; the named/held identity is checked on every boundary.
struct PrivateDirectory {
    path: PathBuf,
    directory: File,
    documents: ExistingDocumentDirectory,
    owner_uid: u32,
}

impl PrivateDirectory {
    fn open(path: &Path, owner_uid: u32) -> Result<Option<Self>> {
        let held = match crate::privilege::custody::HeldResource::open(path, owner_uid) {
            Ok(held) => held,
            Err(error) if missing(&error) => return Ok(None),
            Err(error) => return Err(error).context("open private shell directory"),
        };
        let directory = File::from(rustix::fs::openat(
            &held.descriptor,
            ".",
            directory_flags(),
            rustix::fs::Mode::empty(),
        )?);
        Self::from_file(path.to_owned(), directory, owner_uid).map(Some)
    }

    fn from_file(path: PathBuf, directory: File, owner_uid: u32) -> Result<Self> {
        let documents = ExistingDocumentDirectory::open(&path, owner_uid)?;
        let result = Self {
            path,
            directory,
            documents,
            owner_uid,
        };
        result.verify()?;
        Ok(result)
    }

    fn verify(&self) -> Result<()> {
        let held = self.directory.metadata()?;
        let named = crate::privilege::custody::HeldResource::open(&self.path, self.owner_uid)?;
        let actual = rustix::fs::fstat(&named.descriptor)?;
        if !held.is_dir()
            || held.uid() != self.owner_uid
            || held.mode() & 0o7777 != 0o700
            || held.dev() != actual.st_dev
            || held.ino() != actual.st_ino
            || held.mode() != actual.st_mode
            || held.uid() != actual.st_uid
        {
            bail!("private shell directory changed or has unsafe custody");
        }
        Ok(())
    }

    fn child(&self, name: &OsStr) -> Result<Option<Self>> {
        self.verify()?;
        let directory = match rustix::fs::openat(
            &self.directory,
            name,
            directory_flags(),
            rustix::fs::Mode::empty(),
        ) {
            Ok(directory) => File::from(directory),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(error).context("open private shell child directory"),
        };
        let result = Self::from_file(self.path.join(name), directory, self.owner_uid)?;
        self.verify()?;
        Ok(Some(result))
    }

    fn entries(&self) -> Result<Vec<String>> {
        self.verify()?;
        let path = format!("/proc/self/fd/{}", self.directory.as_raw_fd());
        let mut names = Vec::new();
        for entry in fs::read_dir(path)? {
            if names.len() == INVENTORY_LIMIT {
                bail!("private shell inventory exceeds its bound")
            }
            names.push(
                entry?.file_name().into_string().map_err(|_| {
                    anyhow::anyhow!("private shell inventory has a non-UTF-8 entry")
                })?,
            );
        }
        names.sort();
        self.verify()?;
        Ok(names)
    }

    fn sync(&self) -> Result<()> {
        self.verify()?;
        self.directory
            .sync_all()
            .context("sync private shell directory")?;
        self.verify()
    }

    fn remove_empty_child(&self, name: &OsStr, child: &Self) -> Result<()> {
        self.verify()?;
        child.verify()?;
        let metadata = child.directory.metadata()?;
        let named =
            rustix::fs::statat(&self.directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        if metadata.dev() != named.st_dev
            || metadata.ino() != named.st_ino
            || metadata.mode() != named.st_mode
            || metadata.uid() != named.st_uid
        {
            bail!("retiring private shell directory changed");
        }
        rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::REMOVEDIR)?;
        self.sync()?;
        if self.child(name)?.is_some() {
            bail!("retired shell generation reappeared")
        }
        Ok(())
    }
}

fn directory_flags() -> rustix::fs::OFlags {
    rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC
}

fn missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        || error.downcast_ref::<rustix::io::Errno>() == Some(&rustix::io::Errno::NOENT)
}

fn source_identity(metadata: &Metadata) -> Result<ArtifactIdentity> {
    let BindingResolution::PinnedShellSource {
        source_sha256,
        source_length,
        ..
    } = &metadata.generation.resolved
    else {
        bail!("private shell metadata contains source text");
    };
    Ok(ArtifactIdentity {
        length: *source_length,
        sha256: source_sha256.clone(),
    })
}

fn bytes_identity(bytes: &[u8]) -> ArtifactIdentity {
    ArtifactIdentity {
        length: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
    }
}

fn verify_source(document: &AtomicDocument, metadata: &Metadata) -> Result<()> {
    if document.identity != source_identity(metadata)? {
        bail!("private shell source identity changed")
    }
    verify_source_bytes(&document.bytes, metadata)
}

fn verify_source_bytes(bytes: &[u8], metadata: &Metadata) -> Result<()> {
    if bytes.is_empty()
        || bytes.len() as u64 > SOURCE_LIMIT
        || bytes.contains(&0)
        || std::str::from_utf8(bytes).is_err()
        || bytes_identity(bytes) != source_identity(metadata)?
    {
        bail!("private shell source is not the exact bounded approved definition");
    }
    Ok(())
}

fn metadata_for_binding(store: &Store, alias: &str, binding: &BindingReceipt) -> Result<Metadata> {
    validate_binding_receipt_structure(binding)?;
    store.metadata(alias, &binding.active)
}

pub(crate) fn publish_shell_payload(
    mode: InstallMode,
    home: &Path,
    uid: u32,
    alias: &str,
    plan: &BindingPlan,
) -> Result<bool> {
    canonical_retained_binding_plan(plan)?;
    let BindingResolution::PinnedShell { source, .. } = &plan.resolved else {
        bail!("private shell publication requires retained exact source bytes");
    };
    let generation = match (&plan.current_receipt, plan.change) {
        (None, BindingPlanChange::Install) => 1,
        (Some(current), BindingPlanChange::Unchanged) => current.active.generation,
        (Some(current), BindingPlanChange::Refresh | BindingPlanChange::Rebind) => current
            .active
            .generation
            .checked_add(1)
            .context("private shell generation overflow")?,
        _ => bail!("private shell publication has an invalid generation transition"),
    };
    let store = Store::new(mode, home, uid)?;
    let metadata = store.metadata(
        alias,
        &BindingGeneration {
            generation,
            intent: plan.intent.clone(),
            resolved: plan.resolved.clone(),
        },
    )?;
    store.publish(&metadata, source.as_bytes())
}

pub(crate) fn verify_shell_payload(
    mode: InstallMode,
    home: &Path,
    uid: u32,
    alias: &str,
    binding: &BindingReceipt,
) -> Result<()> {
    let store = Store::new(mode, home, uid)?;
    let metadata = metadata_for_binding(&store, alias, binding)?;
    if let Some(account) = store.open_account()? {
        if store.marker(&account)?.is_some() {
            bail!("private shell retirement is incomplete")
        }
    }
    if !store.observe(&metadata, true)? {
        bail!("private shell source is absent")
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) enum ShellRestorationObservation {
    RetainedComplete,
    CandidatePartial,
}

fn selected_retirements(
    store: &Store,
    retiring: &[(String, BindingReceipt)],
) -> Result<Vec<Metadata>> {
    if retiring.len() > 128 {
        bail!("private shell restoration retirement inventory exceeds its bound");
    }
    retiring
        .iter()
        .map(|(alias, binding)| metadata_for_binding(store, alias, binding))
        .collect()
}

impl Store {
    fn observe_for_restoration(
        &self,
        metadata: &Metadata,
        observation: ShellRestorationObservation,
        retiring: &[Metadata],
    ) -> Result<bool> {
        self.validate_metadata(metadata)?;
        for candidate in retiring {
            self.validate_metadata(candidate)?;
        }
        if let Some(account) = self.open_account()? {
            if let Some((marker, _)) = self.marker(&account)? {
                if !retiring.contains(&marker.metadata)
                    || (matches!(observation, ShellRestorationObservation::RetainedComplete)
                        && marker.metadata == *metadata)
                {
                    bail!(
                        "private shell restoration marker is outside its exact candidate inventory"
                    );
                }
            }
        }
        self.observe(
            metadata,
            matches!(observation, ShellRestorationObservation::RetainedComplete),
        )
    }

    fn resume_for_restoration(&self, retiring: &[Metadata]) -> Result<bool> {
        for candidate in retiring {
            self.validate_metadata(candidate)?;
        }
        let Some(account) = self.open_account()? else {
            return Ok(false);
        };
        let Some((marker, _)) = self.marker(&account)? else {
            return Ok(false);
        };
        if !retiring.contains(&marker.metadata) {
            bail!("private shell restoration cannot replay an unrelated retirement marker");
        }
        self.resume_retirement(&account, &BTreeSet::new())
    }
}

pub(crate) fn observe_shell_payload_for_restoration(
    mode: InstallMode,
    home: &Path,
    uid: u32,
    alias: &str,
    binding: &BindingReceipt,
    observation: ShellRestorationObservation,
    retiring: &[(String, BindingReceipt)],
) -> Result<bool> {
    let store = Store::new(mode, home, uid)?;
    store.observe_for_restoration(
        &metadata_for_binding(&store, alias, binding)?,
        observation,
        &selected_retirements(&store, retiring)?,
    )
}

pub(crate) fn resume_shell_retirement_for_restoration(
    mode: InstallMode,
    home: &Path,
    uid: u32,
    retiring: &[(String, BindingReceipt)],
) -> Result<bool> {
    let store = Store::new(mode, home, uid)?;
    store.resume_for_restoration(&selected_retirements(&store, retiring)?)
}

pub(crate) fn observe_shell_payload(
    mode: InstallMode,
    home: &Path,
    uid: u32,
    alias: &str,
    binding: &BindingReceipt,
) -> Result<bool> {
    let store = Store::new(mode, home, uid)?;
    let metadata = metadata_for_binding(&store, alias, binding)?;
    if let Some(account) = store.open_account()? {
        if let Some((marker, _)) = store.marker(&account)? {
            if marker.metadata != metadata {
                bail!("another private shell retirement requires recovery")
            }
        }
    }
    store.observe(&metadata, false)
}

pub(crate) fn retire_shell_payload(
    mode: InstallMode,
    home: &Path,
    uid: u32,
    alias: &str,
    binding: &BindingReceipt,
) -> Result<bool> {
    let store = Store::new(mode, home, uid)?;
    store.retire(&metadata_for_binding(&store, alias, binding)?)
}

pub(crate) fn garbage_collect_shell_sources(
    mode: InstallMode,
    home: &Path,
    uid: u32,
    retained: &[&BindingSetReceipt],
) -> Result<bool> {
    Store::new(mode, home, uid)?.collect(retained)
}

pub(crate) fn shell_store_accounts() -> Result<BTreeSet<u32>> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("private shell account inventory requires native root")
    }
    DocumentDirectoryPreparation::observe(Path::new(ROOT), 0, 0o700)?.verify_observed()?;
    let Some(root) = PrivateDirectory::open(Path::new(ROOT), 0)? else {
        return Ok(BTreeSet::new());
    };
    let mut accounts = BTreeSet::new();
    for name in root.entries()? {
        let uid = name
            .parse::<u32>()
            .context("private shell store has an invalid native account")?;
        if uid == 0 || uid.to_string() != name {
            bail!("private shell native account is not canonical")
        }
        root.child(OsStr::new(&name))?
            .context("private shell account disappeared")?;
        accounts.insert(uid);
    }
    Ok(accounts)
}

pub(crate) fn sealed_source_for_binding(
    mode: InstallMode,
    home: &Path,
    uid: u32,
    alias: &str,
    binding: &BindingReceipt,
) -> Result<File> {
    verify_shell_payload(mode, home, uid, alias, binding)?;
    let store = Store::new(mode, home, uid)?;
    let metadata = metadata_for_binding(&store, alias, binding)?;
    let directory = store
        .open_generation(&metadata)?
        .context("private shell source disappeared before capture")?;
    let source = directory
        .documents
        .read(OsStr::new(SOURCE), &store.authority(SOURCE_LIMIT))?
        .context("private shell source disappeared before capture")?;
    verify_source(&source, &metadata)?;
    directory.verify()?;
    seal_source(&source.bytes, uid)
}

fn seal_source(bytes: &[u8], uid: u32) -> Result<File> {
    if uid == 0 {
        bail!("sealed shell source requires a native non-root owner")
    }
    let mut file = crate::supervisor_descriptors::normalize_source_descriptor(File::from(
        rustix::fs::memfd_create(
            "dev-auth-private-shell-source",
            rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
        )?,
    ))?;
    if file.metadata()?.uid() != uid {
        rustix::fs::fchown(&file, Some(rustix::fs::Uid::from_raw(uid)), None)?;
    }
    rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o600))?;
    file.write_all(bytes)?;
    file.rewind()?;
    let seals = rustix::fs::SealFlags::SEAL
        | rustix::fs::SealFlags::SHRINK
        | rustix::fs::SealFlags::GROW
        | rustix::fs::SealFlags::WRITE;
    rustix::fs::fcntl_add_seals(&file, seals)?;
    if rustix::fs::fcntl_get_seals(&file)? != seals
        || file.metadata()?.uid() != uid
        || file.metadata()?.mode() & 0o7777 != 0o600
    {
        bail!("sealed private shell source has incorrect native custody");
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smart_binding::{
        BindingCodeTrust, BindingIntent, BindingTargetIntent, ExecutableIdentity,
    };
    use std::io::Read;
    use std::os::unix::fs::{symlink, PermissionsExt};

    const ALIAS: &str = "shell-fixture";

    #[test]
    fn interrupted_candidate_retirement_keeps_prior_complete_and_replays_exact_marker() {
        let (_temporary, store) = fixture();
        let prior = store
            .metadata(ALIAS, &generation(1, "prior approved\n"))
            .unwrap();
        let candidate = store
            .metadata(ALIAS, &generation(2, "candidate approved\n"))
            .unwrap();
        store.publish(&prior, b"prior approved\n").unwrap();
        store.publish(&candidate, b"candidate approved\n").unwrap();
        let account = store.open_account().unwrap().unwrap();
        let marker = Retirement {
            schema: RETIREMENT_SCHEMA.into(),
            metadata: candidate.clone(),
        };
        account
            .documents
            .write(
                OsStr::new(MARKER),
                &serde_jcs::to_vec(&marker).unwrap(),
                &store.authority(METADATA_LIMIT),
                None,
            )
            .unwrap();
        let directory = store.open_generation(&candidate).unwrap().unwrap();
        directory
            .documents
            .remove(
                OsStr::new(SOURCE),
                &store.authority(SOURCE_LIMIT),
                &source_identity(&candidate).unwrap(),
            )
            .unwrap();
        let selected = vec![candidate.clone()];
        assert!(store
            .observe_for_restoration(
                &prior,
                ShellRestorationObservation::RetainedComplete,
                &selected
            )
            .unwrap());
        assert!(store
            .observe_for_restoration(
                &candidate,
                ShellRestorationObservation::CandidatePartial,
                &selected
            )
            .unwrap());
        assert!(store
            .observe_for_restoration(&prior, ShellRestorationObservation::RetainedComplete, &[])
            .is_err());
        assert!(store
            .resume_for_restoration(std::slice::from_ref(&prior))
            .is_err());
        assert!(store.resume_for_restoration(&selected).unwrap());
        assert!(store.observe(&prior, true).unwrap());
        assert!(!store.observe(&candidate, false).unwrap());
        assert!(store.marker(&account).unwrap().is_none());
    }

    fn fixture() -> (tempfile::TempDir, Store) {
        let temporary = tempfile::tempdir().unwrap();
        let owner_uid = temporary.path().metadata().unwrap().uid();
        let root = temporary.path().join("private-shell-bindings");
        let store = Store {
            account: root.join("1000"),
            root,
            owner_uid,
            account_uid: 1000,
        };
        (temporary, store)
    }

    fn generation(number: u64, source: &str) -> BindingGeneration {
        let shell = PathBuf::from("/usr/bin/fixture-shell");
        BindingGeneration {
            generation: number,
            intent: BindingIntent {
                command_name: ALIAS.into(),
                workload: "fixture".into(),
                code_trust: BindingCodeTrust::Pinned,
                desktop_entry: false,
                target: BindingTargetIntent::PinnedShell {
                    shell: shell.clone(),
                    source_sha256: bytes_identity(source.as_bytes()).sha256,
                },
            },
            resolved: BindingResolution::PinnedShell {
                identity: ExecutableIdentity {
                    canonical_path: shell,
                    length: 11,
                    sha256: "a".repeat(64),
                    authority: BindingAuthority::RootOwned,
                    device: Some(u64::MAX),
                    inode: Some(u64::MAX - 1),
                    mode: Some(0o755),
                    owner: Some(0),
                    group: Some(0),
                },
                source: source.into(),
                acknowledged_public_source: true,
            },
        }
    }

    fn binding(active: BindingGeneration, previous: Option<BindingGeneration>) -> BindingReceipt {
        BindingReceipt {
            schema: "dev-auth-workload-binding-receipt-v3".into(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            active,
            previous,
        }
    }

    fn set(active: BindingGeneration, previous: Option<BindingGeneration>) -> BindingSetReceipt {
        BindingSetReceipt {
            schema: "dev-auth-binding-set-v1".into(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            account_uid: 1000,
            product_executable: "/usr/bin/dev-auth".into(),
            product_sha256: "b".repeat(64),
            bindings: BTreeMap::from([(ALIAS.into(), binding(active, previous))]),
            pinned_artifacts: BTreeMap::new(),
        }
    }

    #[test]
    fn publication_is_private_exact_and_idempotent_without_source_in_metadata() {
        let (_temporary, store) = fixture();
        let text = "printf '%s\\n' public-definition-fixture\n";
        let metadata = store.metadata(ALIAS, &generation(1, text)).unwrap();
        assert!(!store.observe(&metadata, false).unwrap());
        assert!(!store.root.exists());
        assert!(store.publish(&metadata, text.as_bytes()).unwrap());
        assert!(!store.publish(&metadata, text.as_bytes()).unwrap());
        assert!(store.observe(&metadata, true).unwrap());
        let path = store.path(&metadata).unwrap();
        let alias = store.account.join(ALIAS);
        for directory in [&store.root, &store.account, &alias, &path] {
            let stat = directory.metadata().unwrap();
            assert_eq!(stat.uid(), store.owner_uid);
            assert_eq!(stat.mode() & 0o7777, 0o700);
        }
        for name in [SOURCE, METADATA] {
            let stat = path.join(name).metadata().unwrap();
            assert_eq!(stat.uid(), store.owner_uid);
            assert_eq!(stat.mode() & 0o7777, 0o600);
            assert_eq!(stat.nlink(), 1);
        }
        let recorded = fs::read(path.join(METADATA)).unwrap();
        assert!(!String::from_utf8_lossy(&recorded).contains("public-definition-fixture"));
        let decoded: Metadata = serde_json::from_slice(&recorded).unwrap();
        assert_eq!(decoded, metadata);
        assert_eq!(
            decoded.generation.resolved.identity().device,
            Some(u64::MAX)
        );
        assert_eq!(fs::read(path.join(SOURCE)).unwrap(), text.as_bytes());
    }

    #[test]
    fn publication_rejects_unacknowledged_unbounded_or_different_source_before_creation() {
        let (_temporary, store) = fixture();
        let metadata = store.metadata(ALIAS, &generation(1, "approved\n")).unwrap();
        for source in [b"".as_slice(), b"different\n", b"approved\0", b"\xff"] {
            assert!(store.publish(&metadata, source).is_err());
            assert!(!store.root.exists());
        }
        assert!(store
            .publish(&metadata, &vec![b'x'; SOURCE_LIMIT as usize + 1])
            .is_err());
        let mut unacknowledged = generation(1, "approved\n");
        if let BindingResolution::PinnedShell {
            acknowledged_public_source,
            ..
        } = &mut unacknowledged.resolved
        {
            *acknowledged_public_source = false;
        }
        assert!(store.metadata(ALIAS, &unacknowledged).is_err());
        assert!(store
            .metadata("../fixture", &generation(1, "approved\n"))
            .is_err());
        assert!(!store.root.exists());
    }

    #[test]
    fn exact_partial_candidates_and_marked_retirement_resume_without_adoption() {
        for stage in [
            "empty",
            "source",
            "metadata",
            "complete",
            "marked-source-removed",
            "marked-files-removed",
            "marked-directory-removed",
        ] {
            let (_temporary, store) = fixture();
            let text = "approved\n";
            let metadata = store.metadata(ALIAS, &generation(1, text)).unwrap();
            store.publish(&metadata, text.as_bytes()).unwrap();
            let account = store.open_account().unwrap().unwrap();
            let directory = store.open_generation(&metadata).unwrap().unwrap();
            if stage.starts_with("marked") {
                let marker = Retirement {
                    schema: RETIREMENT_SCHEMA.into(),
                    metadata: metadata.clone(),
                };
                account
                    .documents
                    .write(
                        OsStr::new(MARKER),
                        &serde_jcs::to_vec(&marker).unwrap(),
                        &store.authority(METADATA_LIMIT),
                        None,
                    )
                    .unwrap();
            }
            if [
                "empty",
                "metadata",
                "marked-source-removed",
                "marked-files-removed",
                "marked-directory-removed",
            ]
            .contains(&stage)
            {
                directory
                    .documents
                    .remove(
                        OsStr::new(SOURCE),
                        &store.authority(SOURCE_LIMIT),
                        &source_identity(&metadata).unwrap(),
                    )
                    .unwrap();
            }
            if [
                "empty",
                "source",
                "marked-files-removed",
                "marked-directory-removed",
            ]
            .contains(&stage)
            {
                let identity = bytes_identity(&serde_jcs::to_vec(&metadata).unwrap());
                directory
                    .documents
                    .remove(
                        OsStr::new(METADATA),
                        &store.authority(METADATA_LIMIT),
                        &identity,
                    )
                    .unwrap();
            }
            if stage == "marked-directory-removed" {
                let alias = account.child(OsStr::new(ALIAS)).unwrap().unwrap();
                alias
                    .remove_empty_child(
                        OsStr::new(&Store::directory_name(&metadata).unwrap()),
                        &directory,
                    )
                    .unwrap();
            } else {
                assert!(store.observe(&metadata, false).unwrap(), "{stage}");
            }
            assert!(store.retire(&metadata).unwrap(), "{stage}");
            assert!(!store.retire(&metadata).unwrap());
            assert!(!store.path(&metadata).unwrap().exists());
            assert!(store.marker(&account).unwrap().is_none());
        }
    }

    #[test]
    fn publication_completes_only_the_exact_admitted_partial_candidate() {
        for missing in [SOURCE, METADATA] {
            let (_temporary, store) = fixture();
            let metadata = store.metadata(ALIAS, &generation(1, "approved\n")).unwrap();
            store.publish(&metadata, b"approved\n").unwrap();
            let directory = store.open_generation(&metadata).unwrap().unwrap();
            let identity = if missing == SOURCE {
                source_identity(&metadata).unwrap()
            } else {
                bytes_identity(&serde_jcs::to_vec(&metadata).unwrap())
            };
            directory
                .documents
                .remove(
                    OsStr::new(missing),
                    &store.authority(METADATA_LIMIT),
                    &identity,
                )
                .unwrap();
            assert!(store.observe(&metadata, false).unwrap());
            assert!(store.observe(&metadata, true).is_err());
            assert!(store.publish(&metadata, b"approved\n").unwrap());
            assert!(store.observe(&metadata, true).unwrap());
            assert!(!store.publish(&metadata, b"approved\n").unwrap());
        }
    }

    #[test]
    fn retained_directory_replacement_cannot_redirect_inventory_or_documents() {
        let (temporary, store) = fixture();
        let metadata = store.metadata(ALIAS, &generation(1, "approved\n")).unwrap();
        store.publish(&metadata, b"approved\n").unwrap();
        let directory = store.open_generation(&metadata).unwrap().unwrap();
        let alias = store.account.join(ALIAS);
        let displaced = temporary.path().join("displaced");
        fs::rename(&alias, &displaced).unwrap();
        fs::create_dir(&alias).unwrap();
        fs::set_permissions(&alias, fs::Permissions::from_mode(0o700)).unwrap();
        let replacement = store.path(&metadata).unwrap();
        fs::create_dir(&replacement).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(replacement.join(SOURCE), b"foreign\n").unwrap();
        fs::set_permissions(replacement.join(SOURCE), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(directory.entries().is_err());
        assert!(directory
            .documents
            .write(
                OsStr::new(SOURCE),
                b"changed\n",
                &store.authority(SOURCE_LIMIT),
                None
            )
            .is_err());
        assert!(directory
            .documents
            .remove(
                OsStr::new(SOURCE),
                &store.authority(SOURCE_LIMIT),
                &source_identity(&metadata).unwrap()
            )
            .is_err());
        assert_eq!(
            fs::read(
                displaced
                    .join(Store::directory_name(&metadata).unwrap())
                    .join(SOURCE)
            )
            .unwrap(),
            b"approved\n"
        );
        assert_eq!(fs::read(replacement.join(SOURCE)).unwrap(), b"foreign\n");
    }

    #[test]
    fn collection_retains_active_and_previous_sources_from_every_retained_set() {
        let (_temporary, store) = fixture();
        let mut generations = Vec::new();
        for (number, text) in [(1, "one\n"), (2, "two\n"), (3, "three\n"), (4, "four\n")] {
            let metadata = store.metadata(ALIAS, &generation(number, text)).unwrap();
            store.publish(&metadata, text.as_bytes()).unwrap();
            generations.push(metadata.generation);
        }
        let current = set(generations[3].clone(), Some(generations[2].clone()));
        let prior = set(generations[1].clone(), Some(generations[0].clone()));
        assert!(!store.collect(&[&current, &prior]).unwrap());
        assert!(store.collect(&[&current]).unwrap());
        assert!(!store.collect(&[&current]).unwrap());
        for (index, generation) in generations.iter().enumerate() {
            let metadata = store.metadata(ALIAS, generation).unwrap();
            assert_eq!(store.observe(&metadata, true).unwrap(), index >= 2);
        }
        assert!(store
            .marker(&store.open_account().unwrap().unwrap())
            .unwrap()
            .is_none());
    }

    #[test]
    fn changed_custody_content_and_unknown_inventory_never_authorize_removal() {
        for change in [
            "mode",
            "special-mode",
            "source",
            "metadata",
            "symlink",
            "hard-link",
            "unknown",
            "alias-mode",
        ] {
            let (temporary, store) = fixture();
            let metadata = store.metadata(ALIAS, &generation(1, "approved\n")).unwrap();
            store.publish(&metadata, b"approved\n").unwrap();
            let path = store.path(&metadata).unwrap();
            let source = path.join(SOURCE);
            match change {
                "mode" => fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap(),
                "special-mode" => {
                    fs::set_permissions(&source, fs::Permissions::from_mode(0o4600)).unwrap()
                }
                "source" => fs::write(&source, b"foreign\n").unwrap(),
                "metadata" => fs::write(path.join(METADATA), b"{}\n").unwrap(),
                "symlink" => {
                    fs::remove_file(&source).unwrap();
                    symlink(temporary.path().join("foreign"), &source).unwrap();
                }
                "hard-link" => {
                    fs::hard_link(&source, temporary.path().join("foreign-link")).unwrap()
                }
                "unknown" => fs::write(path.join("unknown"), b"foreign").unwrap(),
                "alias-mode" => fs::set_permissions(
                    store.account.join(ALIAS),
                    fs::Permissions::from_mode(0o755),
                )
                .unwrap(),
                _ => unreachable!(),
            }
            assert!(store.observe(&metadata, false).is_err(), "{change}");
            assert!(store.retire(&metadata).is_err(), "{change}");
            assert!(fs::symlink_metadata(&source).is_ok(), "{change}");
            assert!(!store.account.join(MARKER).exists(), "{change}");
        }
    }

    #[test]
    fn retirement_markers_cannot_delete_retained_sources_or_foreign_late_entries() {
        let (_temporary, store) = fixture();
        let metadata = store.metadata(ALIAS, &generation(1, "approved\n")).unwrap();
        store.publish(&metadata, b"approved\n").unwrap();
        let account = store.open_account().unwrap().unwrap();
        let marker = Retirement {
            schema: RETIREMENT_SCHEMA.into(),
            metadata: metadata.clone(),
        };
        account
            .documents
            .write(
                OsStr::new(MARKER),
                &serde_jcs::to_vec(&marker).unwrap(),
                &store.authority(METADATA_LIMIT),
                None,
            )
            .unwrap();
        let retained = set(metadata.generation.clone(), None);
        assert!(store.collect(&[&retained]).is_err());
        assert!(store.path(&metadata).unwrap().join(SOURCE).exists());
        fs::write(store.path(&metadata).unwrap().join("foreign"), b"preserve").unwrap();
        assert!(store.retire(&metadata).is_err());
        assert!(store.account.join(MARKER).exists());
        assert_eq!(
            fs::read(store.path(&metadata).unwrap().join("foreign")).unwrap(),
            b"preserve"
        );
    }

    #[test]
    fn source_capture_has_selected_ownership_no_execute_bits_and_all_seals() {
        let current = nix::unistd::Uid::effective().as_raw();
        let owner = if current == 0 { 1000 } else { current };
        let mut sealed = seal_source(b"approved\n", owner).unwrap();
        assert_eq!(sealed.metadata().unwrap().uid(), owner);
        assert_eq!(sealed.metadata().unwrap().mode() & 0o7777, 0o600);
        let mut captured = Vec::new();
        sealed.read_to_end(&mut captured).unwrap();
        assert_eq!(captured, b"approved\n");
        assert!(sealed.write_all(b"changed").is_err());
        assert!(sealed.set_len(1).is_err());
        assert!(sealed.set_len(100).is_err());
        assert_eq!(
            rustix::fs::fcntl_get_seals(&sealed).unwrap(),
            rustix::fs::SealFlags::SEAL
                | rustix::fs::SealFlags::SHRINK
                | rustix::fs::SealFlags::GROW
                | rustix::fs::SealFlags::WRITE
        );
        assert!(seal_source(b"approved\n", 0).is_err());
    }
}
