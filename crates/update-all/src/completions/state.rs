use super::native::NativeRecipeMemo;
use super::{
    CompletionArtifactClassification, CompletionBindingIdentity, CompletionCandidateIdentity,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

const IDENTITY_MEMO_SCHEMA_VERSION: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(super) struct CompletionCandidateSlot {
    pub shell: String,
    pub provider: String,
    pub source: String,
    pub command: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CompletionCandidateMemo {
    pub slot: CompletionCandidateSlot,
    pub binding: CompletionBindingIdentity,
    pub identity: CompletionCandidateIdentity,
    pub resolution_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_resolution_fingerprint: Option<String>,
    pub artifact_path: PathBuf,
    pub artifact_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_ir_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_ir_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_classification: Option<CompletionArtifactClassification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successful_recipe: Option<NativeRecipeMemo>,
    pub priority: Option<i64>,
    pub managed_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CompletionBindingMemo {
    pub binding: CompletionBindingIdentity,
    pub active_candidate: CompletionCandidateSlot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CompletionIdentityMemo {
    schema_version: u64,
    #[serde(default)]
    pub candidates: Vec<CompletionCandidateMemo>,
    #[serde(default)]
    pub bindings: Vec<CompletionBindingMemo>,
}

impl Default for CompletionIdentityMemo {
    fn default() -> Self {
        Self {
            schema_version: IDENTITY_MEMO_SCHEMA_VERSION,
            candidates: Vec::new(),
            bindings: Vec::new(),
        }
    }
}

impl CompletionIdentityMemo {
    pub(super) fn normalize(&mut self) {
        self.candidates
            .sort_by(|left, right| left.slot.cmp(&right.slot));
        self.bindings
            .sort_by(|left, right| left.binding.cmp(&right.binding));
    }

    fn validate(&self, path: &Path) -> Result<()> {
        if self.schema_version != IDENTITY_MEMO_SCHEMA_VERSION {
            anyhow::bail!(
                "unsupported completion identity memo schema {} at {}",
                self.schema_version,
                path.display()
            );
        }
        for pair in self.candidates.windows(2) {
            if pair[0].slot == pair[1].slot {
                anyhow::bail!(
                    "duplicate completion candidate slot in identity memo {}",
                    path.display()
                );
            }
        }
        for candidate in &self.candidates {
            if candidate.canonical_ir_path.is_some() != candidate.canonical_ir_digest.is_some() {
                anyhow::bail!(
                    "incomplete canonical completion IR identity for candidate {:?} in {}",
                    candidate.slot,
                    path.display()
                );
            }
        }
        for pair in self.bindings.windows(2) {
            if pair[0].binding == pair[1].binding {
                anyhow::bail!(
                    "duplicate completion binding in identity memo {}",
                    path.display()
                );
            }
        }
        Ok(())
    }
}

pub(super) struct CompletionIdentityStore {
    path: PathBuf,
}

impl CompletionIdentityStore {
    pub(super) fn new(managed_root: &Path) -> Result<Self> {
        if !managed_root.is_absolute() {
            anyhow::bail!(
                "managed completion root must be absolute: {}",
                managed_root.display()
            );
        }
        Ok(Self {
            path: managed_root.join("identity-memo.json"),
        })
    }

    pub(super) fn load(&self) -> Result<CompletionIdentityMemo> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(CompletionIdentityMemo::default());
            }
            Err(error) => {
                return Err(error).with_context(|| format!("read {}", self.path.display()));
            }
        };
        let mut memo: CompletionIdentityMemo = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse {}", self.path.display()))?;
        memo.normalize();
        memo.validate(&self.path)?;
        Ok(memo)
    }

    pub(super) fn save_if_changed(&self, memo: &CompletionIdentityMemo) -> Result<bool> {
        let mut normalized = memo.clone();
        normalized.normalize();
        normalized.validate(&self.path)?;
        let mut bytes =
            serde_json::to_vec_pretty(&normalized).context("serialize completion identity memo")?;
        bytes.push(b'\n');
        if fs::read(&self.path).is_ok_and(|existing| existing == bytes) {
            return Ok(false);
        }
        write_atomic_bytes(&self.path, &bytes)?;
        Ok(true)
    }

    #[cfg(test)]
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

fn write_atomic_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let Some(parent) = path.parent() else {
        anyhow::bail!(
            "completion identity memo path has no parent: {}",
            path.display()
        );
    };
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let tmp = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("identity-memo"),
        std::process::id()
    ));
    {
        let mut file = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", tmp.display()))?;
    }
    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(error)
            if path.exists()
                && matches!(
                    error.kind(),
                    std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::PermissionDenied
                ) =>
        {
            fs::remove_file(path).with_context(|| format!("replace {}", path.display()))?;
            fs::rename(&tmp, path)
                .with_context(|| format!("rename {} to {}", tmp.display(), path.display()))
        }
        Err(error) => {
            Err(error).with_context(|| format!("rename {} to {}", tmp.display(), path.display()))
        }
    }
}
