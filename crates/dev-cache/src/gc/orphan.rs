//! Join a proven orphan's identity and exact Cargo intermediates before either
//! can be retired. Missing metadata never supplies orphan deletion authority.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;

use super::{GcAbstention, GcAction};
use crate::adapter::Adapter;
use crate::config::GcConfig;
use crate::repository::{classify_identity_record, IdentityDisposition, IdentityRecord};
use crate::resources::{self, CleanupStrategy, ResourceKind, ResourceRecord};
use crate::root::RootHandle;

pub(super) const ACTION_KIND: &str = "orphan-workspace-cargo";
const MAX_METADATA_BYTES: u64 = 64 * 1024;
// A future field may encode a reservation or stronger ownership requirement.
// Additions must be reviewed before this stronger deletion route accepts them.
const OWNER_FIELDS: &[&str] = &[
    "schema_version",
    "identity",
    "canonical_worktree",
    "filesystem_identity",
    "platform",
    "created_unix",
    "last_used_unix",
];
const RESOURCE_FIELDS: &[&str] = &[
    "schema_version",
    "resource_id",
    "root_id",
    "domain_id",
    "platform",
    "adapter",
    "kind",
    "relative_path",
    "generation",
    "created_unix",
    "last_started_unix",
    "last_completed_unix",
    "last_maintained_unix",
    "cleanup",
    "hazards",
    "native_program",
    "native_prefix",
    "native_environment",
];
const MAX_DEPTH: usize = 256;

pub(super) struct Admission<'a> {
    pub root: &'a RootHandle,
    pub policy: &'a GcConfig,
    pub now: u64,
    pub active_paths: &'a [PathBuf],
}

/// Current in-memory admission, never deserialized from a printed GC plan.
pub(super) struct Evidence {
    owner: IdentityRecord,
    resource: ResourceRecord,
    owner_path: PathBuf,
    cargo_path: PathBuf,
}

struct Catalog<'a> {
    paths: BTreeMap<PathBuf, Vec<&'a ResourceRecord>>,
    complete: bool,
}

impl<'a> Catalog<'a> {
    fn new(root: &RootHandle, records: &'a [ResourceRecord], complete: bool) -> Self {
        let mut paths = BTreeMap::<_, Vec<_>>::new();
        for record in records {
            paths
                .entry(root.platform_root.join(&record.relative_path))
                .or_default()
                .push(record);
        }
        Self { paths, complete }
    }

    fn exact(&self, path: &Path) -> Result<&'a ResourceRecord> {
        if !self.complete {
            bail!("orphan Cargo ownership is uncertain while catalog records are invalid");
        }
        match self.paths.get(path).map(Vec::as_slice) {
            Some([record]) => Ok(record),
            _ => bail!("orphan Cargo storage requires one exact valid catalog record"),
        }
    }

    fn no_other_overlap(&self, root: &Path, admitted_id: &str) -> Result<()> {
        // Component-ordered paths make each subtree contiguous. Ancestor
        // lookups separately catch a resource that contains the proposed root.
        let descendant = self
            .paths
            .range(root.to_path_buf()..)
            .take_while(|(path, _)| path.starts_with(root));
        for (_, records) in descendant {
            if records.iter().any(|r| r.resource_id != admitted_id) {
                bail!("another catalog resource overlaps the orphan transaction");
            }
        }
        for ancestor in root.ancestors().skip(1) {
            if self
                .paths
                .get(ancestor)
                .is_some_and(|records| records.iter().any(|r| r.resource_id != admitted_id))
            {
                bail!("another catalog resource contains the orphan transaction");
            }
        }
        Ok(())
    }
}

pub(super) fn link_actions(
    admission: &Admission<'_>,
    records: &[ResourceRecord],
    catalog_complete: bool,
    actions: &mut Vec<GcAction>,
    abstentions: &mut Vec<GcAbstention>,
) -> BTreeMap<PathBuf, Evidence> {
    let root = admission.root;
    let catalog = Catalog::new(root, records, catalog_complete);
    // Reconciliation may publish new overlapping catalog resources earlier in
    // this collection. Preserve the owner until a subsequent fresh plan instead
    // of performing a full catalog scan for every compound action at apply.
    let rehomes = actions
        .iter()
        .filter_map(|action| action.destination.as_ref())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut groups = BTreeMap::new();
    let mut retained = Vec::with_capacity(actions.len());
    for action in actions.drain(..) {
        if action.kind != "repository" || action.reason != "orphan" {
            retained.push(action);
            continue;
        }
        let Some(id) = action.path.file_name() else {
            retained.push(action);
            continue;
        };
        let cargo_path = root.shared().join("cargo/intermediate").join(id);
        let admitted = (|| {
            if !catalog.complete {
                bail!("orphan ownership is uncertain while catalog records are invalid");
            }
            if [&action.path, &cargo_path]
                .iter()
                .any(|path| overlaps_index(path, &rehomes))
            {
                bail!("workspace identity reconciliation overlaps the orphan transaction");
            }
            // Preserve old metadata-only behavior only with proven absent
            // Cargo storage, complete metadata, and no redirected ancestor.
            if storage_absent(&cargo_path)? {
                catalog.no_other_overlap(&cargo_path, "")?;
                return Ok(None);
            }
            let record = catalog.exact(&cargo_path)?;
            catalog.no_other_overlap(&action.path, &record.resource_id)?;
            catalog.no_other_overlap(&cargo_path, &record.resource_id)?;
            admit(admission, &action.path, &cargo_path, record).map(Some)
        })();
        match admitted {
            Ok(None) => retained.push(action),
            Ok(Some(evidence)) => {
                let last_used_unix =
                    last_use(&evidence.resource).max(evidence.owner.last_used_unix);
                retained.push(GcAction {
                    kind: ACTION_KIND.to_owned(),
                    path: action.path.clone(),
                    destination: None,
                    companion_paths: vec![action.path.clone(), cargo_path],
                    bytes: 0,
                    reason: "orphan".to_owned(),
                    strategy: "owneddirectory".to_owned(),
                    resource_id: Some(evidence.resource.resource_id.clone()),
                    last_used_unix,
                });
                groups.insert(action.path, evidence);
            }
            Err(error) => abstentions.push(GcAbstention {
                resource_id: None,
                path: action.path,
                reason: format!("orphan Cargo owner retained: {error:#}"),
            }),
        }
    }
    *actions = retained;
    groups
}

fn overlaps_index(path: &Path, paths: &BTreeSet<PathBuf>) -> bool {
    path.ancestors().any(|ancestor| paths.contains(ancestor))
        || paths
            .range(path.to_path_buf()..)
            .next()
            .is_some_and(|candidate| candidate.starts_with(path))
}

fn admit(
    admission: &Admission<'_>,
    owner_path: &Path,
    cargo_path: &Path,
    resource: &ResourceRecord,
) -> Result<Evidence> {
    let Admission {
        root,
        policy,
        now,
        active_paths,
    } = *admission;
    let owner = read_owner(root, owner_path)?;
    let expected_cargo = root
        .shared()
        .join("cargo/intermediate")
        .join(&owner.identity);
    if cargo_path != expected_cargo
        || resources::absolute_path(root, resource)? != expected_cargo
        || resource.adapter != Adapter::Cargo
        || resource.kind != ResourceKind::CargoIntermediate
        || resource.cleanup != CleanupStrategy::OwnedDirectory
        || !resource.hazards.is_empty()
        || !uuid::Uuid::parse_str(&resource.generation)
            .is_ok_and(|id| id.get_version_num() == 4 && id.get_variant() == uuid::Variant::RFC4122)
    {
        bail!("invalid or hazardous owner-linked Cargo resource");
    }
    if read_resource(root, &resource.resource_id)? != *resource {
        bail!("orphan Cargo catalog changed during admission");
    }
    if resource
        .last_completed_unix
        .is_none_or(|completed| completed < resource.last_started_unix)
    {
        bail!("orphan Cargo work has no matching completion evidence");
    }
    strict_directory(owner_path)?;
    strict_directory(cargo_path)?;
    if [owner_path, cargo_path]
        .iter()
        .any(|path| super::path_overlaps_any(path, active_paths))
    {
        bail!("orphan transaction overlaps an active routed command");
    }
    let newest = owner
        .created_unix
        .max(owner.last_used_unix)
        .max(last_use(resource));
    if newest > now || now - newest < policy.orphan_grace_days.saturating_mul(86_400) {
        bail!("owner or Cargo resource is newer than the orphan grace");
    }
    prove_worktree_absent(&owner)?;
    Ok(Evidence {
        owner,
        resource: resource.clone(),
        owner_path: owner_path.to_path_buf(),
        cargo_path: cargo_path.to_path_buf(),
    })
}

pub(super) fn apply(
    root: &RootHandle,
    policy: &GcConfig,
    action: &GcAction,
    evidence: &Evidence,
) -> Result<()> {
    if action.kind != ACTION_KIND
        || action.path != evidence.owner_path
        || action.destination.is_some()
        || action.resource_id.as_deref() != Some(evidence.resource.resource_id.as_str())
        || action.companion_paths != [evidence.owner_path.clone(), evidence.cargo_path.clone()]
    {
        bail!("orphan action differs from current admission");
    }
    // Exclusive root coordination excludes catalog/setup publication throughout
    // this collection. Reconciliation overlap was excluded during planning.
    // Re-read exact owner/resource evidence, live lease scope and source
    // disappearance immediately before mutation.
    let resource = read_resource(root, &evidence.resource.resource_id)?;
    if resource != evidence.resource {
        bail!("orphan Cargo generation or catalog record changed after admission");
    }
    let active = crate::lease::observe_active_resource_ids(root)?;
    let active_paths = super::active_resource_paths(root, &active)?;
    let fresh = admit(
        &Admission {
            root,
            policy,
            now: crate::util::now_unix(),
            active_paths: &active_paths,
        },
        &evidence.owner_path,
        &evidence.cargo_path,
        &resource,
    )?;
    if fresh.owner != evidence.owner {
        bail!("orphan workspace identity changed after admission");
    }
    // Both members enter the same existing journal. A failed pre-commit rename
    // restores both; committed recovery finishes only this admitted transaction.
    super::owned_transaction(root, action)?;
    resources::remove_record(root, &resource.resource_id)?;
    Ok(())
}

fn last_use(record: &ResourceRecord) -> u64 {
    record
        .created_unix
        .max(record.last_started_unix)
        .max(record.last_completed_unix.unwrap_or(0))
        .max(record.last_maintained_unix.unwrap_or(0))
}

fn read_owner(root: &RootHandle, path: &Path) -> Result<IdentityRecord> {
    strict_directory(path)?;
    let owner: IdentityRecord = read_metadata(&path.join("identity.json"), OWNER_FIELDS)?;
    if classify_identity_record(root, path, &owner)? != IdentityDisposition::Current {
        bail!("orphan workspace identity is not current-domain authority");
    }
    Ok(owner)
}

fn read_resource(root: &RootHandle, id: &str) -> Result<ResourceRecord> {
    let record: ResourceRecord =
        read_metadata(&resources::catalog_path(root, id), RESOURCE_FIELDS)?;
    resources::validate_record(root, &record)?;
    if record.resource_id != id {
        bail!("orphan catalog filename does not match resource identity");
    }
    Ok(record)
}

fn read_metadata<T: DeserializeOwned>(path: &Path, fields: &[&str]) -> Result<T> {
    strict_directory(path.parent().context("orphan metadata parent")?)?;
    let metadata = fs::symlink_metadata(path).context("observe orphan ownership metadata")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
        bail!("orphan ownership metadata is not an ordinary file");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .context("open orphan ownership metadata")?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || is_reparse(&metadata) || metadata.len() > MAX_METADATA_BYTES {
        bail!("orphan ownership metadata is unsafe or oversized");
    }
    let mut bytes = Vec::new();
    file.take(MAX_METADATA_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        bail!("orphan ownership metadata exceeded its read limit");
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("parse orphan ownership metadata")?;
    let object = value
        .as_object()
        .context("orphan ownership metadata is not an object")?;
    if object.keys().any(|name| !fields.contains(&name.as_str())) {
        bail!("orphan ownership metadata has unknown fields");
    }
    // Decode original bytes so duplicate known fields still fail typed Serde.
    serde_json::from_slice(&bytes).context("parse orphan ownership metadata")
}

fn strict_directory(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        bail!("orphan path is not normal and absolute");
    }
    for (depth, ancestor) in path.ancestors().enumerate() {
        if depth >= MAX_DEPTH {
            bail!("orphan path exceeds the metadata depth limit");
        }
        let metadata = fs::symlink_metadata(ancestor).context("observe orphan path ancestry")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
            bail!("orphan path ancestry is not a real directory");
        }
    }
    Ok(())
}

/// Prove an absent managed subtree without following a missing/redirected
/// ancestor. An unavailable parent is not silently treated as absent storage.
fn storage_absent(path: &Path) -> Result<bool> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        bail!("Cargo storage path is not normal and absolute");
    }
    let ancestors = path.ancestors().take(MAX_DEPTH + 1).collect::<Vec<_>>();
    if ancestors.len() > MAX_DEPTH {
        bail!("Cargo storage exceeds metadata depth limit");
    }
    for ancestor in ancestors.into_iter().rev() {
        match fs::symlink_metadata(ancestor) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(error) => return Err(error).context("Cargo storage absence is unproven"),
            Ok(metadata)
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || is_reparse(&metadata) =>
            {
                bail!("Cargo storage ancestry is not a real directory");
            }
            Ok(_) => {}
        }
    }
    Ok(false)
}

#[cfg(unix)]
fn prove_worktree_absent(owner: &IdentityRecord) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if !owner.canonical_worktree.is_absolute()
        || owner
            .canonical_worktree
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        bail!("orphan worktree path is not normal and absolute");
    }
    let (device, inode) = owner
        .filesystem_identity
        .split_once(':')
        .context("unknown workspace filesystem identity")?;
    let device = device
        .parse::<u64>()
        .context("invalid workspace device identity")?;
    let _inode = inode
        .parse::<u64>()
        .context("invalid workspace inode identity")?;
    let parent = owner
        .canonical_worktree
        .parent()
        .context("orphan worktree has no parent")?;
    strict_directory(parent)?;
    if fs::symlink_metadata(parent)?.dev() != device {
        bail!("orphan worktree filesystem continuity is unproven");
    }
    match fs::symlink_metadata(&owner.canonical_worktree) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("orphan worktree absence is unproven"),
        Ok(_) => bail!("orphan worktree is present or redirected"),
    }
}

#[cfg(not(unix))]
fn prove_worktree_absent(_owner: &IdentityRecord) -> Result<()> {
    bail!("orphan worktree filesystem evidence is unsupported on this platform")
}

#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(all(test, unix))]
#[path = "orphan_tests.rs"]
mod tests;
