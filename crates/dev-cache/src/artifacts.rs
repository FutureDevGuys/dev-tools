use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::lease::RootLease;
use crate::root::RootHandle;
use crate::util::{hash_file, now_unix, write_json_atomic};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ArtifactRecord {
    pub schema_version: u32,
    pub digest: String,
    pub size: u64,
    pub original_name: String,
    pub created_unix: u64,
    pub last_verified_unix: u64,
}

pub fn put(root: &RootHandle, source: &Path) -> Result<ArtifactRecord> {
    let _lease = RootLease::shared(root, "artifacts-put")?;
    let source = source
        .canonicalize()
        .with_context(|| format!("resolve artifact {}", source.display()))?;
    if source.starts_with(&root.root) {
        bail!("artifact source must be outside the disposable cache root");
    }
    if !source.is_file() {
        bail!("artifact source is not a file: {}", source.display());
    }
    let (digest, size) = hash_file(&source)?;
    let object = object_path(root, &digest)?;
    fs::create_dir_all(
        object
            .parent()
            .context("artifact object path has no parent")?,
    )?;
    if object.exists() {
        let (existing, existing_size) = hash_file(&object)?;
        if existing != digest || existing_size != size {
            bail!("artifact CAS collision or corruption for {digest}");
        }
    } else {
        let temporary = object.with_extension(format!("partial-{}", std::process::id()));
        fs::copy(&source, &temporary)
            .with_context(|| format!("copy artifact {}", source.display()))?;
        let (copied, copied_size) = hash_file(&temporary)?;
        if copied != digest || copied_size != size {
            let _ = fs::remove_file(&temporary);
            bail!("artifact changed while being copied: {}", source.display());
        }
        fs::rename(&temporary, &object)?;
    }
    let now = now_unix();
    let record = ArtifactRecord {
        schema_version: 1,
        digest: digest.clone(),
        size,
        original_name: source
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        created_unix: now,
        last_verified_unix: now,
    };
    write_json_atomic(&metadata_path(root, &digest)?, &record)?;
    Ok(record)
}

pub fn get(root: &RootHandle, digest: &str, destination: &Path) -> Result<ArtifactRecord> {
    let _lease = RootLease::shared(root, "artifacts-get")?;
    let mut record = read_record(root, digest)?;
    let object = object_path(root, digest)?;
    verify_object(&object, &record)?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = destination.with_extension(format!("dev-cache-partial-{}", std::process::id()));
    fs::copy(&object, &temporary)?;
    let (copied, size) = hash_file(&temporary)?;
    if copied != record.digest || size != record.size {
        let _ = fs::remove_file(&temporary);
        bail!("artifact verification failed while restoring {digest}");
    }
    fs::rename(&temporary, destination)?;
    record.last_verified_unix = now_unix();
    write_json_atomic(&metadata_path(root, digest)?, &record)?;
    Ok(record)
}

pub fn verify(root: &RootHandle, digest: Option<&str>) -> Result<Vec<ArtifactRecord>> {
    let _lease = RootLease::shared(root, "artifacts-verify")?;
    let mut records = if let Some(digest) = digest {
        vec![read_record(root, digest)?]
    } else {
        list_unlocked(root)?
    };
    for record in &mut records {
        verify_object(&object_path(root, &record.digest)?, record)?;
        record.last_verified_unix = now_unix();
        write_json_atomic(&metadata_path(root, &record.digest)?, record)?;
    }
    Ok(records)
}

pub fn list(root: &RootHandle) -> Result<Vec<ArtifactRecord>> {
    let _lease = RootLease::shared(root, "artifacts-list")?;
    list_unlocked(root)
}

pub fn remove(root: &RootHandle, digest: &str) -> Result<()> {
    let _lease = RootLease::exclusive(root)?;
    let record = read_record(root, digest)?;
    let object = object_path(root, &record.digest)?;
    let metadata = metadata_path(root, &record.digest)?;
    if object.exists() {
        fs::remove_file(object)?;
    }
    if metadata.exists() {
        fs::remove_file(metadata)?;
    }
    Ok(())
}

fn list_unlocked(root: &RootHandle) -> Result<Vec<ArtifactRecord>> {
    let metadata = root.platform_root.join("artifacts/metadata");
    if !metadata.is_dir() {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    for entry in fs::read_dir(metadata)? {
        let entry = entry?;
        if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        records.push(serde_json::from_slice(&fs::read(entry.path())?)?);
    }
    records.sort_by(|left: &ArtifactRecord, right: &ArtifactRecord| left.digest.cmp(&right.digest));
    Ok(records)
}

fn read_record(root: &RootHandle, digest: &str) -> Result<ArtifactRecord> {
    validate_digest(digest)?;
    let path = metadata_path(root, digest)?;
    serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("read artifact metadata {}", path.display()))?,
    )
    .context("parse artifact metadata")
}

fn verify_object(path: &Path, record: &ArtifactRecord) -> Result<()> {
    let (digest, size) = hash_file(path)?;
    if digest != record.digest || size != record.size {
        bail!("artifact CAS object is corrupt: {}", record.digest);
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("invalid BLAKE3 digest: {digest}");
    }
    Ok(())
}

fn object_path(root: &RootHandle, digest: &str) -> Result<PathBuf> {
    validate_digest(digest)?;
    Ok(root.artifacts().join(&digest[..2]).join(digest))
}

fn metadata_path(root: &RootHandle, digest: &str) -> Result<PathBuf> {
    validate_digest(digest)?;
    Ok(root
        .platform_root
        .join("artifacts/metadata")
        .join(format!("{digest}.json")))
}
