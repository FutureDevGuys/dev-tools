//! Transactional creation of a new sync-configs manifest skeleton.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;
use thiserror::Error;

pub const EXAMPLE_ROOT_CONFIG: &str = "# Root sync configuration (sync_targets.yaml)\n# - Keep defaults here\n# - Place most entries under `entries_dir` for maintainability\ndefault_mode: symlink\nentries_dir: ./sync_targets.d\n\nentries:\n  # Optional inline entries are still supported\n  - name: single_file\n    source: ../cli/codex/config.toml\n    target: ~/.codex/config.toml\n";

pub const EXAMPLE_ENTRY_CONFIG: &str = "# Example entry file (sync_targets.d/00-example.yaml)\nentries:\n  - name: codex_config\n    group: CLI\n    subgroup: Codex\n    source: ../cli/codex/config.toml\n    target: ~/.codex/config.toml\n    mode: toml_overlay\n\n  - name: example_commands\n    group: CLI\n    subgroup: Example\n    source: ../cli/example/commands\n    target: ~/.example/commands\n    mode: copy\n    directory_strategy: as_directory\n    permissions:\n      file: \"0644\"\n      dir: \"0755\"\n      recursive: true\n";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScaffoldPaths {
    pub manifest: PathBuf,
    pub entries_dir: PathBuf,
    pub example: PathBuf,
}

#[derive(Debug, Error)]
pub enum ScaffoldError {
    #[error("refusing to overwrite existing file (use --force-init): {0}")]
    Existing(PathBuf),
    #[error("entries path exists and is not a real directory: {0}")]
    UnsafeEntries(PathBuf),
    #[error("cannot create sync-configs scaffold: {0}")]
    Io(#[from] io::Error),
}

pub fn derive_paths(manifest: &Path) -> ScaffoldPaths {
    let entries_dir = if manifest
        .file_name()
        .is_some_and(|name| name == "sync_targets.yaml")
    {
        manifest.with_file_name("sync_targets.d")
    } else {
        let stem = manifest
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("sync_targets");
        manifest.with_file_name(format!("{stem}.d"))
    };
    let example = entries_dir.join("00-example.yaml");
    ScaffoldPaths {
        manifest: manifest.to_owned(),
        entries_dir,
        example,
    }
}

pub fn render_examples() -> String {
    format!(
        "# --- sync_targets.yaml ---\n{}\n# --- sync_targets.d/00-example.yaml ---\n{}\n",
        EXAMPLE_ROOT_CONFIG.trim_end(),
        EXAMPLE_ENTRY_CONFIG.trim_end()
    )
}

pub fn initialize(manifest: &Path, force: bool) -> Result<ScaffoldPaths, ScaffoldError> {
    let paths = derive_paths(manifest);
    validate_destination(&paths, force)?;
    let manifest_parent = paths.manifest.parent().ok_or_else(|| {
        ScaffoldError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "manifest has no parent directory",
        ))
    })?;
    fs::create_dir_all(manifest_parent)?;
    fs::create_dir_all(&paths.entries_dir)?;
    let root = format!(
        "# Root sync configuration.\n# Most entries should live under the entries directory tree.\ndefault_mode: symlink\nentries_dir: ./{}\n",
        paths
            .entries_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("sync_targets.d")
    );
    let staged_example = stage(
        &paths.entries_dir,
        ".sync-configs-example.",
        EXAMPLE_ENTRY_CONFIG,
    )?;
    let staged_root = stage(manifest_parent, ".sync-configs-root.", &root)?;
    let old_example = snapshot(&paths.example)?;
    let old_manifest = snapshot(&paths.manifest)?;
    if let Err(error) =
        persist(staged_example, &paths.example).and_then(|()| persist(staged_root, &paths.manifest))
    {
        let _ = restore(&paths.example, old_example.as_deref());
        let _ = restore(&paths.manifest, old_manifest.as_deref());
        return Err(ScaffoldError::Io(error));
    }
    Ok(paths)
}

fn validate_destination(paths: &ScaffoldPaths, force: bool) -> Result<(), ScaffoldError> {
    for path in [&paths.manifest, &paths.example] {
        if fs::symlink_metadata(path).is_ok() && !force {
            return Err(ScaffoldError::Existing(path.clone()));
        }
    }
    match fs::symlink_metadata(&paths.entries_dir) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(ScaffoldError::UnsafeEntries(paths.entries_dir.clone()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ScaffoldError::Io(error)),
    }
}

fn stage(parent: &Path, prefix: &str, content: &str) -> io::Result<NamedTempFile> {
    let mut file = tempfile::Builder::new()
        .prefix(prefix)
        .tempfile_in(parent)?;
    file.write_all(content.as_bytes())?;
    file.as_file_mut().sync_all()?;
    Ok(file)
}

fn persist(file: NamedTempFile, target: &Path) -> io::Result<()> {
    if fs::symlink_metadata(target).is_ok() {
        fs::remove_file(target)?;
    }
    file.persist(target).map_err(|error| error.error)?;
    OpenOptions::new().read(true).open(target)?.sync_all()
}

fn snapshot(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::read(path).map(Some)
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "scaffold destination is not a regular file",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn restore(path: &Path, content: Option<&[u8]>) -> io::Result<()> {
    match content {
        Some(content) => fs::write(path, content),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        },
    }
}
