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
        let now = now_unix();
        if record_path.exists() {
            let mut record: IdentityRecord = serde_json::from_slice(&fs::read(&record_path)?)
                .context("parse repository identity")?;
            if record.identity != identity
                || record.canonical_worktree != worktree
                || record.filesystem_identity != filesystem_identity
                || record.platform != root.platform
            {
                bail!(
                    "repository cache identity mismatch at {}",
                    cache_dir.display()
                );
            }
            record.last_used_unix = now;
            write_json_atomic(&record_path, &record)?;
        } else {
            fs::create_dir_all(&cache_dir)?;
            let record = IdentityRecord {
                schema_version: 2,
                identity: identity.clone(),
                canonical_worktree: worktree.clone(),
                filesystem_identity,
                platform: root.platform.clone(),
                created_unix: now,
                last_used_unix: now,
            };
            write_json_atomic(&record_path, &record)?;
        }
        Ok(Some(Self {
            worktree,
            identity,
            cache_dir,
        }))
    }
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
