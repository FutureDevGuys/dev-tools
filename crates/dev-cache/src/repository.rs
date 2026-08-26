use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::root::RootHandle;
use crate::util::{now_unix, write_json_atomic};

#[derive(Clone, Debug)]
pub struct Repository {
    pub worktree: PathBuf,
    pub identity: String,
    pub cache_dir: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct IdentityRecord {
    pub schema_version: u32,
    pub identity: String,
    pub canonical_worktree: PathBuf,
    pub filesystem_identity: String,
    pub platform: String,
    pub created_unix: u64,
    pub last_used_unix: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentityIssue {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum IdentityDisposition {
    Current,
    RootScoped {
        legacy_path: PathBuf,
        destination: PathBuf,
    },
    UnknownSelfBound {
        destination: PathBuf,
    },
}

impl Repository {
    pub fn discover(cwd: &Path, root: &RootHandle) -> Result<Option<Self>> {
        let requested = cwd
            .canonicalize()
            .with_context(|| format!("resolve workspace start {}", cwd.display()))?;
        let output = Command::new("git")
            .args(["-C"])
            .arg(&requested)
            .args(["rev-parse", "--show-toplevel"])
            .output();
        let worktree = match output {
            Ok(output) if output.status.success() => {
                let raw = String::from_utf8(output.stdout)
                    .context("Git returned non-UTF-8 worktree path")?;
                PathBuf::from(raw.trim())
                    .canonicalize()
                    .context("resolve Git worktree")?
            }
            _ => native_workspace_root(&requested),
        };
        let filesystem_identity = filesystem_identity(&worktree)?;
        let seed = format!(
            "v2\0{}\0{}\0{}",
            root.domain_id,
            worktree.display(),
            filesystem_identity
        );
        let identity = blake3::hash(seed.as_bytes()).to_hex().to_string();
        let cache_dir = root.repos().join(&identity[..2]).join(&identity);
        let record_path = cache_dir.join("identity.json");
        if record_path.exists() {
            let record: IdentityRecord = serde_json::from_slice(&fs::read(&record_path)?)
                .context("parse repository identity")?;
            validate_identity_record(root, &cache_dir, &record)?;
            if record.canonical_worktree != worktree
                || record.filesystem_identity != filesystem_identity
            {
                bail!(
                    "repository cache identity mismatch at {}",
                    cache_dir.display()
                );
            }
        }
        Ok(Some(Self {
            worktree,
            identity,
            cache_dir,
        }))
    }

    pub fn touch(&self, root: &RootHandle) -> Result<()> {
        let record_path = self.cache_dir.join("identity.json");
        let filesystem_identity = filesystem_identity(&self.worktree)?;
        let now = now_unix();
        let mut record = if record_path.is_file() {
            let record: IdentityRecord = serde_json::from_slice(&fs::read(&record_path)?)
                .context("parse repository identity")?;
            validate_identity_record(root, &self.cache_dir, &record)?;
            if record.canonical_worktree != self.worktree
                || record.filesystem_identity != filesystem_identity
            {
                bail!(
                    "repository cache identity mismatch at {}",
                    self.cache_dir.display()
                );
            }
            record
        } else {
            fs::create_dir_all(&self.cache_dir)?;
            IdentityRecord {
                schema_version: 2,
                identity: self.identity.clone(),
                canonical_worktree: self.worktree.clone(),
                filesystem_identity,
                platform: root.platform.clone(),
                created_unix: now,
                last_used_unix: now,
            }
        };
        record.last_used_unix = now;
        write_json_atomic(&record_path, &record)
    }
}

pub fn validate_identity_record(
    root: &RootHandle,
    cache_dir: &Path,
    record: &IdentityRecord,
) -> Result<()> {
    if record.schema_version != 2
        || record.platform != root.platform
        || record.identity.len() < 2
        || record.canonical_worktree.as_os_str().is_empty()
        || record.filesystem_identity.is_empty()
    {
        bail!(
            "invalid repository cache identity at {}",
            cache_dir.display()
        );
    }
    let seed = format!(
        "v2\0{}\0{}\0{}",
        root.domain_id,
        record.canonical_worktree.display(),
        record.filesystem_identity
    );
    let expected = blake3::hash(seed.as_bytes()).to_hex().to_string();
    let expected_dir = root.repos().join(&expected[..2]).join(&expected);
    if record.identity != expected || cache_dir != expected_dir {
        bail!(
            "repository cache identity mismatch at {}",
            cache_dir.display()
        );
    }
    Ok(())
}

pub(crate) fn classify_identity_record(
    root: &RootHandle,
    cache_dir: &Path,
    record: &IdentityRecord,
) -> Result<IdentityDisposition> {
    validate_identity_shape(root, cache_dir, record)?;
    let current_identity = identity_for(
        &root.domain_id,
        &record.canonical_worktree,
        &record.filesystem_identity,
    );
    let destination = identity_path(root, &current_identity);
    if record.identity == current_identity {
        if cache_dir != destination {
            bail!(
                "repository cache identity mismatch at {}",
                cache_dir.display()
            );
        }
        return Ok(IdentityDisposition::Current);
    }
    let root_scoped_identity = identity_for(
        &root.marker.root_id,
        &record.canonical_worktree,
        &record.filesystem_identity,
    );
    let legacy_path = identity_path(root, &root_scoped_identity);
    if record.identity == root_scoped_identity
        && (cache_dir == legacy_path || cache_dir == destination)
    {
        return Ok(IdentityDisposition::RootScoped {
            legacy_path,
            destination,
        });
    }
    if cache_dir == identity_path(root, &record.identity) {
        return Ok(IdentityDisposition::UnknownSelfBound { destination });
    }
    bail!(
        "repository cache identity mismatch at {}",
        cache_dir.display()
    )
}

pub(crate) fn current_identity_record(
    root: &RootHandle,
    record: &IdentityRecord,
) -> IdentityRecord {
    let mut current = record.clone();
    current.identity = identity_for(
        &root.domain_id,
        &record.canonical_worktree,
        &record.filesystem_identity,
    );
    current
}

pub(crate) fn records_describe_same_workspace(
    left: &IdentityRecord,
    right: &IdentityRecord,
) -> bool {
    left.schema_version == right.schema_version
        && left.canonical_worktree == right.canonical_worktree
        && left.filesystem_identity == right.filesystem_identity
        && left.platform == right.platform
}

pub fn scan_identity_issues(root: &RootHandle) -> Result<Vec<IdentityIssue>> {
    if !root.repos().is_dir() {
        return Ok(Vec::new());
    }
    let mut issues = Vec::new();
    for prefix in fs::read_dir(root.repos())? {
        let prefix = prefix?;
        if !prefix.file_type()?.is_dir() {
            continue;
        }
        for entry in fs::read_dir(prefix.path())? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let identity_path = entry.path().join("identity.json");
            let result = fs::read(&identity_path)
                .context("read repository identity")
                .and_then(|bytes| {
                    serde_json::from_slice::<IdentityRecord>(&bytes)
                        .context("parse repository identity")
                })
                .and_then(|record| {
                    classify_identity_record(root, &entry.path(), &record).and_then(|disposition| {
                        match disposition {
                            IdentityDisposition::Current => Ok(()),
                            IdentityDisposition::RootScoped { .. } => bail!(
                                "repository cache identity reconciliation is pending at {}",
                                entry.path().display()
                            ),
                            IdentityDisposition::UnknownSelfBound { .. } => bail!(
                                "repository cache identity has unknown generation at {}",
                                entry.path().display()
                            ),
                        }
                    })
                });
            if let Err(error) = result {
                issues.push(IdentityIssue {
                    path: entry.path(),
                    reason: format!("{error:#}"),
                });
            }
        }
    }
    issues.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(issues)
}

fn validate_identity_shape(
    root: &RootHandle,
    cache_dir: &Path,
    record: &IdentityRecord,
) -> Result<()> {
    if record.schema_version != 2
        || record.platform != root.platform
        || record.identity.len() != 64
        || !record.identity.bytes().all(|byte| byte.is_ascii_hexdigit())
        || record.canonical_worktree.as_os_str().is_empty()
        || record.filesystem_identity.is_empty()
        || !record.canonical_worktree.is_absolute()
        || cache_dir.parent().and_then(Path::file_name) != Some(record.identity[..2].as_ref())
        || cache_dir.file_name() != Some(record.identity.as_ref())
        || !cache_dir.starts_with(root.repos())
    {
        bail!(
            "invalid repository cache identity at {}",
            cache_dir.display()
        );
    }
    Ok(())
}

fn identity_for(scope: &str, worktree: &Path, filesystem_identity: &str) -> String {
    let seed = format!(
        "v2\0{}\0{}\0{}",
        scope,
        worktree.display(),
        filesystem_identity
    );
    blake3::hash(seed.as_bytes()).to_hex().to_string()
}

fn identity_path(root: &RootHandle, identity: &str) -> PathBuf {
    root.repos().join(&identity[..2]).join(identity)
}

fn native_workspace_root(start: &Path) -> PathBuf {
    const MARKERS: &[&str] = &[
        "Cargo.toml",
        "go.mod",
        "package.json",
        "pnpm-workspace.yaml",
        "pyproject.toml",
        "uv.lock",
        "build.zig",
        "meson.build",
    ];
    for candidate in start.ancestors() {
        if MARKERS
            .iter()
            .any(|marker| candidate.join(marker).is_file())
        {
            return candidate.to_path_buf();
        }
    }
    start.to_path_buf()
}

#[cfg(unix)]
fn filesystem_identity(path: &Path) -> Result<String> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path)?;
    Ok(format!("{}:{}", meta.dev(), meta.ino()))
}

#[cfg(windows)]
fn filesystem_identity(path: &Path) -> Result<String> {
    Ok(path.to_string_lossy().to_lowercase())
}

#[cfg(not(any(unix, windows)))]
fn filesystem_identity(path: &Path) -> Result<String> {
    Ok(path.display().to_string())
}
