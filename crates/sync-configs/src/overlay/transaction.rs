//! Product-owned forward recovery for one overlay target and optional receipt.
//!
//! Locks are permanent and selected by the native parent/leaf authority, never
//! by a managed ID or state root. The journal is local authority for this exact
//! request, not a general filesystem instruction format.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Take};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use dev_tools_installation::{
    ArtifactIdentity, DocumentAuthority, DocumentDirectoryPreparation, ExistingDocumentDirectory,
    FileAuthority, InstallationLock,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ownership::RECEIPT_LIMIT;
use super::{ownership, OverlayResult, PathKey};
use crate::paths::{lexical_normalize, PathPlatform};

const FILE_LIMIT: u64 = 16 * 1024 * 1024;
// JSON escaping of two admitted UTF-8 targets and receipts remains bounded.
const JOURNAL_LIMIT: u64 = 256 * 1024 * 1024;
const SCHEMA: &str = "sync-configs-overlay-transaction-v1";
const PREFIX: &str = ".sync-configs-overlay-";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Operation {
    JsonOverlay,
    TomlOverlay,
    TomlRemove,
}

impl Operation {
    fn target_label(self) -> &'static str {
        match self {
            Self::JsonOverlay => "JSON overlay target",
            Self::TomlOverlay => "TOML overlay target",
            Self::TomlRemove => "TOML removal target",
        }
    }
}

pub(crate) struct ReceiptSpec {
    pub id: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ParentIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
enum Leaf {
    Missing,
    SymbolicLink {
        #[serde(with = "native_path")]
        target: PathBuf,
    },
    Regular {
        text: String,
        mode: u32,
        group: u32,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReceiptTransition {
    id: String,
    #[serde(with = "native_path")]
    path: PathBuf,
    parent: ParentIdentity,
    before: Leaf,
    candidate: Leaf,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReceiptReservation {
    schema: String,
    id: String,
    #[serde(with = "native_path")]
    target: PathBuf,
    target_parent: ParentIdentity,
    #[serde(with = "native_path")]
    source: PathBuf,
    operation: Operation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: String,
    operation: Operation,
    #[serde(with = "native_path")]
    source: PathBuf,
    source_sha256: String,
    #[serde(with = "native_path")]
    target: PathBuf,
    parent: ParentIdentity,
    before: Leaf,
    candidate: Leaf,
    receipt: Option<ReceiptTransition>,
}

struct SelectedLeaf {
    path: PathBuf,
    directory: ExistingDocumentDirectory,
    parent: ParentIdentity,
    name: OsString,
}

impl SelectedLeaf {
    fn prepare(path: PathBuf, label: &str) -> Result<Self> {
        ownership::validate_real_parent_chain(&path, label)?;
        let parent_path = path.parent().context("overlay leaf has no parent")?;
        let preparation = DocumentDirectoryPreparation::observe(parent_path, uid(), 0o700)?;
        let (directory, _) = preparation.prepare()?;
        let metadata = fs::symlink_metadata(parent_path)?;
        let name = path
            .file_name()
            .context("overlay leaf has no name")?
            .to_os_string();
        // This descriptor-relative observation also revalidates the held parent.
        directory.metadata(&name)?;
        Ok(Self {
            parent: ParentIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            directory,
            name,
            path,
        })
    }

    fn observe(&self, limit: u64, allow_link: bool) -> Result<Leaf> {
        let Some(metadata) = self.directory.metadata(&self.name)? else {
            return Ok(Leaf::Missing);
        };
        if metadata.file_type().is_symlink() && allow_link {
            let target = self
                .directory
                .read_symbolic_link(&self.name)?
                .context("selected overlay link disappeared")?;
            return Ok(Leaf::SymbolicLink { target });
        }
        if !metadata.is_file() || metadata.uid() != uid() || metadata.mode() & 0o7022 != 0 {
            bail!("overlay leaf has unsafe ordinary-file custody");
        }
        let authority = FileAuthority {
            owner_uid: uid(),
            group_gid: metadata.gid(),
            mode: metadata.mode() & 0o777,
            limit,
        };
        let document = self
            .directory
            .read_file_with_group(&self.name, &authority)?
            .context("selected overlay file disappeared")?;
        let text =
            String::from_utf8(document.bytes).map_err(|_| anyhow!("overlay file is not UTF-8"))?;
        Ok(Leaf::Regular {
            text,
            mode: authority.mode,
            group: authority.group_gid,
        })
    }

    fn apply(&self, before: &Leaf, candidate: &Leaf, limit: u64) -> Result<()> {
        let current = self.observe(limit, true)?;
        // A missing link is the one admitted intermediate state: its exact
        // unlink is durable before the candidate regular file is published.
        let link_gap =
            matches!(before, Leaf::SymbolicLink { .. }) && matches!(current, Leaf::Missing);
        if &current != before && &current != candidate && !link_gap {
            bail!("overlay transaction leaf drifted outside its before/candidate authority");
        }
        match (&current, candidate) {
            (Leaf::SymbolicLink { target }, _) => {
                self.directory.remove_symbolic_link(&self.name, target)?;
            }
            (Leaf::Regular { text, mode, group }, Leaf::Missing) => {
                self.directory.remove_file_with_group(
                    &self.name,
                    &file_authority(*mode, *group, limit),
                    &identity(text.as_bytes()),
                )?;
                return Ok(());
            }
            _ => {}
        }
        match candidate {
            Leaf::Regular { text, mode, group } => {
                let expected = match &current {
                    Leaf::Regular { text, .. } => Some(identity(text.as_bytes())),
                    _ => None,
                };
                self.directory.write_file_with_group(
                    &self.name,
                    text.as_bytes(),
                    &file_authority(*mode, *group, limit),
                    expected.as_ref(),
                )?;
            }
            Leaf::Missing => {
                // Synchronize an admitted absence through the typed primitive.
                self.directory.remove_file_with_group(
                    &self.name,
                    &file_authority(0o600, gid(), limit),
                    &identity(&[]),
                )?;
            }
            Leaf::SymbolicLink { .. } => bail!("overlay recovery cannot publish a symbolic link"),
        }
        Ok(())
    }
}

pub(crate) struct Transaction {
    // Keep every acquired lease until publication/recovery has terminalized.
    _locks: Vec<InstallationLock>,
    target: SelectedLeaf,
    before: Leaf,
    receipt: Option<(ReceiptSpec, SelectedLeaf, Leaf)>,
    source: PathBuf,
    source_text: Option<String>,
    target_text: Option<String>,
    operation: Operation,
    journal_name: OsString,
    recovered: bool,
}

impl Transaction {
    pub(crate) fn begin(
        source: &Path,
        target: &Path,
        operation: Operation,
        receipt: Option<ReceiptSpec>,
    ) -> Result<Self> {
        let source = absolute(source)?;
        let target_path = absolute(target)?;
        if target_path
            .file_name()
            .is_some_and(|name| name.as_bytes().starts_with(PREFIX.as_bytes()))
        {
            bail!("overlay target uses the reserved transaction namespace");
        }
        let target = SelectedLeaf::prepare(target_path, operation.target_label())?;
        let journal_name = sibling_name(&target.name, ".json");
        let receipt = receipt
            .map(|mut spec| -> Result<_> {
                spec.path = absolute(&spec.path)?;
                if spec.path == target.path {
                    bail!("overlay target and receipt must differ");
                }
                ownership::validate_managed_id(&spec.id)?;
                if spec
                    .path
                    .file_name()
                    .is_some_and(|name| name.as_bytes().starts_with(PREFIX.as_bytes()))
                {
                    bail!("overlay receipt uses the reserved transaction namespace");
                }
                let leaf = SelectedLeaf::prepare(spec.path.clone(), "overlay ownership receipt")?;
                Ok((spec, leaf))
            })
            .transpose()?;
        let target_lock = sibling_name(&target.name, ".lock");
        let mut lock_paths = vec![(
            target.path.with_file_name(&target_lock),
            &target.directory,
            target_lock,
        )];
        if let Some((_, leaf)) = &receipt {
            let name = sibling_name(&leaf.name, ".lock");
            lock_paths.push((leaf.path.with_file_name(&name), &leaf.directory, name));
        }
        lock_paths.sort_by(|left, right| left.0.cmp(&right.0));
        lock_paths.dedup_by(|left, right| left.0 == right.0);
        let mut locks = Vec::new();
        for (_, directory, name) in lock_paths {
            locks.push(
                directory
                    .try_lock(&name)?
                    .context("overlay target or receipt is busy")?,
            );
        }
        // Revalidate held parents after acquiring all nonblocking leases.
        target.directory.metadata(&target.name)?;
        if let Some((_, leaf)) = &receipt {
            leaf.directory.metadata(&leaf.name)?;
        }
        let mut result = Self {
            _locks: locks,
            before: Leaf::Missing,
            target,
            receipt: None,
            source,
            source_text: None,
            target_text: None,
            operation,
            journal_name,
            recovered: false,
        };
        let reservation = if let Some((spec, leaf)) = &receipt {
            let document = leaf.directory.read(
                &sibling_name(&leaf.name, ".receipt"),
                &reservation_authority(),
            )?;
            if let Some(document) = &document {
                let reservation: ReceiptReservation = serde_json::from_slice(&document.bytes)
                    .map_err(|_| anyhow!("overlay receipt reservation has invalid fields"))?;
                if reservation != result.reservation(spec) {
                    bail!("overlay receipt belongs to a pending transaction; retry its original operation");
                }
            }
            document
        } else {
            None
        };
        if let Some(document) = result
            .target
            .directory
            .read(&result.journal_name, &journal_authority())?
        {
            let journal: Journal = serde_json::from_slice(&document.bytes)
                .map_err(|_| anyhow!("overlay recovery journal has invalid fields"))?;
            result.validate_journal(&journal, receipt.as_ref())?;
            if receipt.is_some() && reservation.is_none() {
                bail!("managed overlay journal is missing its receipt reservation");
            }
            // Validate both leaves before the first recovery effect.
            validate_pair(
                &result.target.observe(FILE_LIMIT, true)?,
                &journal.before,
                &journal.candidate,
            )?;
            if let (Some((_, leaf)), Some(transition)) = (&receipt, &journal.receipt) {
                validate_pair(
                    &leaf.observe(RECEIPT_LIMIT, false)?,
                    &transition.before,
                    &transition.candidate,
                )?;
            }
            result
                .target
                .apply(&journal.before, &journal.candidate, FILE_LIMIT)?;
            if let (Some((_, leaf)), Some(transition)) = (&receipt, &journal.receipt) {
                leaf.apply(&transition.before, &transition.candidate, RECEIPT_LIMIT)?;
            }
            require_exact(
                &result.target.observe(FILE_LIMIT, true)?,
                &journal.candidate,
            )?;
            if let (Some((_, leaf)), Some(transition)) = (&receipt, &journal.receipt) {
                require_exact(&leaf.observe(RECEIPT_LIMIT, false)?, &transition.candidate)?;
            }
            result.target.directory.remove(
                &result.journal_name,
                &journal_authority(),
                &document.identity,
            )?;
            result.recovered = true;
        }
        // A reservation without a journal precedes target mutation, or follows
        // the durable completion of both leaves. It authorizes only its own
        // exact cleanup; no target/receipt state is inferred from its presence.
        if let (Some((_, leaf)), Some(document)) = (&receipt, reservation) {
            leaf.directory.remove(
                &sibling_name(&leaf.name, ".receipt"),
                &reservation_authority(),
                &document.identity,
            )?;
            result.recovered = true;
        }
        result.before = result.target.observe(FILE_LIMIT, true)?;
        result.receipt = receipt
            .map(|(spec, leaf)| -> Result<_> {
                let before = leaf.observe(RECEIPT_LIMIT, false)?;
                validate_receipt_leaf(&before)?;
                Ok((spec, leaf, before))
            })
            .transpose()?;
        Ok(result)
    }

    pub(crate) fn source_text(&mut self) -> Result<&str> {
        if self.source_text.is_none() {
            self.source_text = Some(read_text(&self.source)?);
        }
        self.source_text
            .as_deref()
            .context("overlay source was not observed")
    }

    pub(crate) fn target_text(&mut self) -> Result<String> {
        let text = match &self.before {
            Leaf::Missing => Ok(String::new()),
            Leaf::Regular { text, .. } => Ok(text.clone()),
            Leaf::SymbolicLink { target } => {
                let referent = if target.is_absolute() {
                    target.clone()
                } else {
                    self.target
                        .path
                        .parent()
                        .context("overlay link has no parent")?
                        .join(target)
                };
                match read_text(&referent) {
                    Ok(text) => Ok(text),
                    Err(error)
                        if error
                            .downcast_ref::<std::io::Error>()
                            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
                    {
                        Ok(String::new())
                    }
                    Err(error) => Err(error),
                }
            }
        }?;
        self.target_text = Some(text.clone());
        Ok(text)
    }

    pub(crate) fn is_missing(&self) -> bool {
        matches!(self.before, Leaf::Missing)
    }
    pub(crate) fn is_symlink(&self) -> bool {
        matches!(self.before, Leaf::SymbolicLink { .. })
    }
    pub(crate) fn recovered(&self) -> bool {
        self.recovered
    }

    pub(crate) fn prior_paths(&self) -> Result<BTreeSet<PathKey>> {
        match &self.receipt {
            Some((spec, _, Leaf::Regular { text, .. })) => {
                ownership::decode_paths(text.as_bytes(), &spec.id)
            }
            _ => Ok(BTreeSet::new()),
        }
    }

    pub(crate) fn publish(
        self,
        result: &mut OverlayResult,
        remove_empty: bool,
        paths: Option<&BTreeSet<PathKey>>,
    ) -> Result<()> {
        let source_text = self
            .source_text
            .as_deref()
            .context("overlay publication has no admitted source")?;
        if read_text(&self.source)? != source_text {
            bail!("overlay source changed before publication");
        }
        if let Leaf::SymbolicLink { target } = &self.before {
            let referent = if target.is_absolute() {
                target.clone()
            } else {
                self.target
                    .path
                    .parent()
                    .context("overlay link has no parent")?
                    .join(target)
            };
            let latest = match read_text(&referent) {
                Ok(text) => text,
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
                {
                    String::new()
                }
                Err(error) => return Err(error),
            };
            if self.target_text.as_deref() != Some(latest.as_str()) {
                bail!("overlay link input changed before publication");
            }
        }
        if !result.changed {
            require_exact(&self.target.observe(FILE_LIMIT, true)?, &self.before)?;
            if let Some((_, leaf, before)) = &self.receipt {
                require_exact(&leaf.observe(RECEIPT_LIMIT, false)?, before)?;
            }
            result.changed = self.recovered;
            return Ok(());
        }
        let (mode, group) = match self.before {
            Leaf::Regular { mode, group, .. } => (mode, group),
            _ => (0o600, gid()),
        };
        let candidate = if remove_empty && result.text.is_empty() {
            Leaf::Missing
        } else {
            Leaf::Regular {
                text: result.text.clone(),
                mode,
                group,
            }
        };
        let receipt = match (&self.receipt, paths) {
            (Some((spec, leaf, before)), Some(paths)) => {
                let group = match before {
                    Leaf::Regular { group, .. } => *group,
                    _ => gid(),
                };
                Some(ReceiptTransition {
                    id: spec.id.clone(),
                    path: spec.path.clone(),
                    parent: leaf.parent.clone(),
                    before: before.clone(),
                    candidate: Leaf::Regular {
                        text: ownership::encode_paths(&spec.id, paths)?,
                        mode: 0o600,
                        group,
                    },
                })
            }
            (None, None) => None,
            _ => bail!("overlay receipt publication authority is incomplete"),
        };
        let journal = Journal {
            schema: SCHEMA.to_owned(),
            operation: self.operation,
            source: self.source.clone(),
            source_sha256: identity(source_text.as_bytes()).sha256,
            target: self.target.path.clone(),
            parent: self.target.parent.clone(),
            before: self.before.clone(),
            candidate,
            receipt,
        };
        validate_leaf(&journal.candidate, FILE_LIMIT, false)?;
        if let Some(transition) = &journal.receipt {
            validate_receipt_leaf(&transition.candidate)?;
        }
        require_exact(&self.target.observe(FILE_LIMIT, true)?, &journal.before)?;
        if let Some((_, leaf, before)) = &self.receipt {
            require_exact(&leaf.observe(RECEIPT_LIMIT, false)?, before)?;
        }
        let bytes = serde_json::to_vec(&journal).context("cannot encode overlay transaction")?;
        if read_text(&self.source)? != source_text {
            bail!("overlay source changed before journal publication");
        }
        let reservation = if let Some((spec, leaf, _)) = &self.receipt {
            let bytes = serde_json::to_vec(&self.reservation(spec))
                .context("cannot encode overlay receipt reservation")?;
            leaf.directory.write(
                &sibling_name(&leaf.name, ".receipt"),
                &bytes,
                &reservation_authority(),
                None,
            )?;
            Some(bytes)
        } else {
            None
        };
        self.target
            .directory
            .write(&self.journal_name, &bytes, &journal_authority(), None)?;
        // No rollback is attempted after journal publication. Every error leaves
        // forward recovery authority; do not overwrite an intervening edit.
        self.target
            .apply(&journal.before, &journal.candidate, FILE_LIMIT)?;
        if let (Some((_, leaf, _)), Some(transition)) = (&self.receipt, &journal.receipt) {
            leaf.apply(&transition.before, &transition.candidate, RECEIPT_LIMIT)?;
        }
        require_exact(&self.target.observe(FILE_LIMIT, true)?, &journal.candidate)?;
        if let (Some((_, leaf, _)), Some(transition)) = (&self.receipt, &journal.receipt) {
            require_exact(&leaf.observe(RECEIPT_LIMIT, false)?, &transition.candidate)?;
        }
        self.target.directory.remove(
            &self.journal_name,
            &journal_authority(),
            &identity(&bytes),
        )?;
        if let (Some((_, leaf, _)), Some(bytes)) = (&self.receipt, reservation) {
            leaf.directory.remove(
                &sibling_name(&leaf.name, ".receipt"),
                &reservation_authority(),
                &identity(&bytes),
            )?;
        }
        result.changed |= self.recovered;
        Ok(())
    }

    fn reservation(&self, spec: &ReceiptSpec) -> ReceiptReservation {
        ReceiptReservation {
            schema: "sync-configs-overlay-receipt-reservation-v1".to_owned(),
            id: spec.id.clone(),
            target: self.target.path.clone(),
            target_parent: self.target.parent.clone(),
            source: self.source.clone(),
            operation: self.operation,
        }
    }

    fn validate_journal(
        &self,
        journal: &Journal,
        receipt: Option<&(ReceiptSpec, SelectedLeaf)>,
    ) -> Result<()> {
        if journal.schema != SCHEMA
            || journal.operation != self.operation
            || journal.source != self.source
            || journal.target != self.target.path
            || journal.parent != self.target.parent
            || journal.source_sha256.len() != 64
            || !journal
                .source_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            bail!("overlay recovery journal does not match this request; retry the original operation");
        }
        validate_leaf(&journal.before, FILE_LIMIT, true)?;
        validate_leaf(&journal.candidate, FILE_LIMIT, false)?;
        if journal.operation != Operation::TomlRemove && matches!(journal.candidate, Leaf::Missing)
        {
            bail!("overlay journal cannot retire an overlay target");
        }
        match (receipt, &journal.receipt) {
            (None, None) => {}
            (Some((spec, leaf)), Some(transition))
                if spec.id == transition.id
                    && spec.path == transition.path
                    && leaf.parent == transition.parent =>
            {
                validate_receipt_leaf(&transition.before)?;
                validate_receipt_leaf(&transition.candidate)?;
                if !matches!(transition.candidate, Leaf::Regular { .. }) {
                    bail!("managed overlay journal must retain a candidate receipt");
                }
                if let Leaf::Regular { text, .. } = &transition.before {
                    ownership::decode_paths(text.as_bytes(), &spec.id)?;
                }
                if let Leaf::Regular { text, .. } = &transition.candidate {
                    ownership::decode_paths(text.as_bytes(), &spec.id)?;
                }
            }
            _ => bail!("overlay recovery receipt differs; retry the original operation"),
        }
        Ok(())
    }
}

pub(crate) fn ensure_no_pending(target: &Path) -> Result<()> {
    let target = absolute(target)?;
    ownership::validate_real_parent_chain(&target, "overlay target")?;
    let name = target.file_name().context("overlay target has no name")?;
    let path = target.with_file_name(sibling_name(name, ".json"));
    match fs::symlink_metadata(path) {
        Ok(_) => bail!(
            "overlay has a pending transaction; rerun the original mutating operation to recover"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect pending overlay transaction"),
    }
}

pub(crate) fn ensure_no_receipt_pending(receipt: &Path) -> Result<()> {
    let receipt = absolute(receipt)?;
    ownership::validate_real_parent_chain(&receipt, "overlay receipt")?;
    let name = receipt.file_name().context("overlay receipt has no name")?;
    match fs::symlink_metadata(receipt.with_file_name(sibling_name(name, ".receipt"))) {
        Ok(_) => bail!("overlay receipt has a pending transaction; rerun its original mutating operation to recover"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect pending overlay receipt reservation"),
    }
}

fn validate_pair(current: &Leaf, before: &Leaf, candidate: &Leaf) -> Result<()> {
    if current == before
        || current == candidate
        || (matches!(before, Leaf::SymbolicLink { .. }) && matches!(current, Leaf::Missing))
    {
        return Ok(());
    }
    bail!("overlay transaction leaf drifted outside its before/candidate authority")
}

fn require_exact(current: &Leaf, expected: &Leaf) -> Result<()> {
    if current != expected {
        bail!("overlay transaction leaf changed before acknowledgement");
    }
    Ok(())
}

fn validate_receipt_leaf(leaf: &Leaf) -> Result<()> {
    validate_leaf(leaf, RECEIPT_LIMIT, false)?;
    if let Leaf::Regular { mode, .. } = leaf {
        if *mode != 0o600 {
            bail!("overlay receipt must have mode 0600");
        }
    }
    Ok(())
}

fn validate_leaf(leaf: &Leaf, limit: u64, allow_link: bool) -> Result<()> {
    match leaf {
        Leaf::Missing => Ok(()),
        Leaf::Regular { text, mode, .. }
            if text.len() as u64 <= limit && mode & !0o777 == 0 && mode & 0o022 == 0 =>
        {
            Ok(())
        }
        Leaf::SymbolicLink { target }
            if allow_link
                && !target.as_os_str().is_empty()
                && target.as_os_str().as_bytes().len() <= 4096 =>
        {
            Ok(())
        }
        _ => bail!("overlay transaction leaf has invalid custody or content bounds"),
    }
}

fn read_text(path: &Path) -> Result<String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    let file = options.open(path).context("open overlay text input")?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > FILE_LIMIT {
        bail!("overlay input must be a bounded regular file");
    }
    let mut bounded: Take<File> = file.try_clone()?.take(FILE_LIMIT + 1);
    let mut text = String::new();
    bounded
        .read_to_string(&mut text)
        .map_err(|_| anyhow!("overlay input is not bounded UTF-8 text"))?;
    let after = file.metadata()?;
    let named = fs::metadata(path)?;
    if text.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || after.dev() != named.dev()
        || after.ino() != named.ino()
    {
        bail!("overlay text input changed while being read");
    }
    Ok(text)
}

fn sibling_name(name: &std::ffi::OsStr, suffix: &str) -> OsString {
    let mut digest = Sha256::new();
    digest.update(b"sync-configs-overlay-leaf-v1\0");
    digest.update(name.as_bytes());
    OsString::from(format!("{PREFIX}{:x}{suffix}", digest.finalize()))
}

fn absolute(path: &Path) -> Result<PathBuf> {
    Ok(lexical_normalize(
        &if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        },
        PathPlatform::current(),
    ))
}

fn identity(bytes: &[u8]) -> ArtifactIdentity {
    ArtifactIdentity {
        length: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
    }
}
fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}
fn gid() -> u32 {
    rustix::process::getegid().as_raw()
}
fn file_authority(mode: u32, group_gid: u32, limit: u64) -> FileAuthority {
    FileAuthority {
        owner_uid: uid(),
        group_gid,
        mode,
        limit,
    }
}
fn journal_authority() -> DocumentAuthority {
    DocumentAuthority {
        owner_uid: uid(),
        mode: 0o600,
        limit: JOURNAL_LIMIT,
    }
}
fn reservation_authority() -> DocumentAuthority {
    DocumentAuthority {
        owner_uid: uid(),
        mode: 0o600,
        limit: 64 * 1024,
    }
}

// Authority paths retain their native bytes; lossy UTF-8 conversion would make
// distinct selected targets or raw link destinations share journal identity.
mod native_path {
    use super::*;

    pub fn serialize<S: serde::Serializer>(
        path: &Path,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.len() > 4096 || bytes.contains(&0) {
            return Err(<S::Error as serde::ser::Error>::custom(
                "native path exceeds transaction bounds",
            ));
        }
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<PathBuf, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        if bytes.is_empty() || bytes.len() > 4096 || bytes.contains(&0) {
            return Err(<D::Error as serde::de::Error>::custom(
                "native path exceeds transaction bounds",
            ));
        }
        Ok(PathBuf::from(OsString::from_vec(bytes)))
    }
}
