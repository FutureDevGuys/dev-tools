use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::adapter::Adapter;
use crate::lease::RootLease;
use crate::repository::Repository;
use crate::root::RootHandle;
use crate::util::{hash_file, now_unix, write_json_atomic};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationReport {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub bytes: u64,
    pub destination_state: String,
    pub apply_supported: bool,
    pub abstention_reason: Option<String>,
    pub applied: bool,
    pub source_removed: bool,
}

pub fn migrate(
    root: &RootHandle,
    repository: Option<&Repository>,
    adapter: Adapter,
    source: &Path,
    apply: bool,
    remove_source: bool,
) -> Result<MigrationReport> {
    migrate_resource(
        root,
        repository,
        adapter,
        None,
        source,
        apply,
        remove_source,
    )
}

pub fn migrate_resource(
    root: &RootHandle,
    repository: Option<&Repository>,
    adapter: Adapter,
    resource: Option<&str>,
    source: &Path,
    apply: bool,
    remove_source: bool,
) -> Result<MigrationReport> {
    if fs::symlink_metadata(source)
        .with_context(|| format!("inspect migration source {}", source.display()))?
        .file_type()
        .is_symlink()
    {
        bail!(
            "migration refuses a symbolic-link source: {}",
            source.display()
        );
    }
    let source = source
        .canonicalize()
        .with_context(|| format!("resolve migration source {}", source.display()))?;
    let owned_v1 = root.root.join("v1").join(&root.platform);
    if source.starts_with(&root.root) && !source.starts_with(&owned_v1) {
        bail!(
            "migration source is already inside the dev-cache root and is not in the owned V1 namespace"
        );
    }
    if remove_source && !apply {
        bail!("--remove-source requires --apply");
    }
    let destination = destination(root, repository, adapter, resource)?;
    let source_fingerprint = fingerprint(&source)?;
    let bytes = source_fingerprint.bytes;
    let destination_state = if !destination.exists() {
        "absent"
    } else if destination.is_dir() && fs::read_dir(&destination)?.next().is_none() {
        "empty"
    } else {
        "nonempty"
    };
    let apply_supported = destination_state != "nonempty";
    let abstention_reason = (!apply_supported).then(|| {
        format!(
            "migration destination is not empty: {}",
            destination.display()
        )
    });
    if !apply {
        return Ok(MigrationReport {
            source,
            destination,
            bytes,
            destination_state: destination_state.to_owned(),
            apply_supported,
            abstention_reason,
            applied: false,
            source_removed: false,
        });
    }
    let _lease = RootLease::exclusive(root)?;
    if let Some(reason) = abstention_reason.as_deref() {
        bail!(reason.to_owned());
    }
    let stage = root.platform_root.join("migration").join(format!(
        "stage-{}-{}",
        now_unix(),
        std::process::id()
    ));
    let requires_link_rewrite = source.is_dir() && has_internal_absolute_links(&source)?;
    let source_moved = if source.is_dir() && remove_source && !requires_link_rewrite {
        fs::create_dir_all(
            stage
                .parent()
                .context("migration stage must have a parent directory")?,
        )?;
        match fs::rename(&source, &stage) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {
                copy_tree(&source, &stage, &destination)?;
                false
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "move migration source {} into owned staging",
                        source.display()
                    )
                });
            }
        }
    } else if source.is_dir() {
        copy_tree(&source, &stage, &destination)?;
        false
    } else {
        fs::create_dir_all(&stage)?;
        fs::copy(&source, stage.join(source.file_name().unwrap_or_default()))?;
        false
    };
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    if destination.exists() {
        fs::remove_dir_all(&destination)?;
    }
    fs::rename(&stage, &destination)?;
    let destination_fingerprint = fingerprint(&destination)?;
    if destination_fingerprint != source_fingerprint {
        if source_moved {
            if source.exists() {
                bail!(
                    "migration verification detected a concurrent writer that recreated {}; the published destination is preserved for adapter-specific review",
                    source.display()
                );
            } else {
                fs::rename(&destination, &source).with_context(|| {
                    format!(
                        "restore migration source {} after verification failure",
                        source.display()
                    )
                })?;
            }
        }
        bail!(
            "migration verification failed: {} ({destination_fingerprint:?}) does not match {} ({source_fingerprint:?})",
            destination.display(),
            source.display()
        );
    }
    let receipt_name = blake3::hash(destination.to_string_lossy().as_bytes())
        .to_hex()
        .to_string();
    write_json_atomic(
        &root
            .platform_root
            .join("migration")
            .join(format!("{receipt_name}.json")),
        &serde_json::json!({"schema_version":1,"source":source,"destination":destination,"adapter":format!("{adapter:?}"),"resource":resource,"verified":true,"migrated_unix":now_unix()}),
    )?;
    if remove_source && !source_moved {
        if source.is_dir() {
            remove_tree(&source)?;
        } else {
            fs::remove_file(&source)?;
        }
    }
    let source_removed = remove_source && !source.exists();
    Ok(MigrationReport {
        source,
        destination,
        bytes,
        destination_state: destination_state.to_owned(),
        apply_supported,
        abstention_reason,
        applied: true,
        source_removed,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct Fingerprint {
    digest: String,
    bytes: u64,
}

fn fingerprint(path: &Path) -> Result<Fingerprint> {
    let mut entries = Vec::new();
    let mut total_bytes = 0_u64;
    if path.is_file() {
        let (digest, bytes) = hash_file(path)?;
        total_bytes = bytes;
        entries.push(format!("file\0{bytes}\0{digest}"));
    } else {
        for entry in walkdir::WalkDir::new(path).follow_links(false) {
            let entry = entry?;
            let relative = entry.path().strip_prefix(path)?;
            if relative.as_os_str().is_empty() {
                continue;
            }
            if entry.file_type().is_symlink() {
                let link = fs::read_link(entry.path()).with_context(|| {
                    format!("read migration symlink {}", entry.path().display())
                })?;
                let link_fingerprint = if link.is_absolute() && link.starts_with(path) {
                    format!("internal:{}", link.strip_prefix(path)?.to_string_lossy())
                } else {
                    format!("literal:{}", link.to_string_lossy())
                };
                entries.push(format!(
                    "link\0{}\0{}",
                    relative.to_string_lossy(),
                    link_fingerprint
                ));
                continue;
            }
            let relative = relative.to_string_lossy();
            if entry.file_type().is_dir() {
                entries.push(format!("dir\0{relative}"));
            } else if entry.file_type().is_file() {
                let (digest, bytes) = hash_file(entry.path())?;
                total_bytes = total_bytes.saturating_add(bytes);
                entries.push(format!("file\0{relative}\0{bytes}\0{digest}"));
            }
        }
    }
    entries.sort();
    let mut hasher = blake3::Hasher::new();
    for entry in entries {
        hasher.update(entry.as_bytes());
        hasher.update(b"\n");
    }
    Ok(Fingerprint {
        digest: hasher.finalize().to_hex().to_string(),
        bytes: total_bytes,
    })
}

fn remove_tree(path: &Path) -> Result<()> {
    make_directories_writable(path)?;
    fs::remove_dir_all(path)
        .with_context(|| format!("remove migrated source tree {}", path.display()))
}

#[cfg(unix)]
fn make_directories_writable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    for entry in walkdir::WalkDir::new(path).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_dir() {
            let metadata = entry.metadata()?;
            let mode = metadata.permissions().mode();
            if mode & 0o300 != 0o300 {
                fs::set_permissions(entry.path(), fs::Permissions::from_mode(mode | 0o300))
                    .with_context(|| {
                        format!(
                            "make migrated source directory removable {}",
                            entry.path().display()
                        )
                    })?;
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn make_directories_writable(path: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(path).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_dir() {
            let mut permissions = entry.metadata()?.permissions();
            if permissions.readonly() {
                permissions.set_readonly(false);
                fs::set_permissions(entry.path(), permissions).with_context(|| {
                    format!(
                        "make migrated source directory removable {}",
                        entry.path().display()
                    )
                })?;
            }
        }
    }
    Ok(())
}

fn destination(
    root: &RootHandle,
    repository: Option<&Repository>,
    adapter: Adapter,
    resource: Option<&str>,
) -> Result<PathBuf> {
    let resource = resource.unwrap_or("default");
    Ok(match adapter {
        Adapter::Cargo => anyhow::bail!(
            "Cargo target directories mix final outputs with intermediates; rebuild with Cargo 1.91+ build-dir routing instead of migrating them"
        ),
        Adapter::Temp => repository
            .context("temp migration requires repository context")?
            .cache_dir
            .join("temp/generic"),
        Adapter::Sccache if resource == "default" || resource == "cache" => {
            root.shared().join("sccache")
        }
        Adapter::Go if resource == "default" || resource == "build" => {
            root.shared().join("go-build")
        }
        Adapter::Go if resource == "modules" => root.shared().join("go-mod"),
        Adapter::Npm if resource == "default" || resource == "cache" => {
            root.shared().join("npm")
        }
        Adapter::Pnpm if resource == "default" || resource == "store" => {
            root.shared().join("pnpm-store")
        }
        Adapter::Pnpm if resource == "cache" => root.shared().join("pnpm-cache"),
        Adapter::Uv if resource == "default" || resource == "cache" => {
            root.shared().join("uv")
        }
        Adapter::Uv if resource == "python" => root.shared().join("uv-python"),
        Adapter::Pip if resource == "default" || resource == "cache" => {
            root.shared().join("pip")
        }
        Adapter::Ccache if resource == "default" || resource == "cache" => {
            root.shared().join("ccache")
        }
        Adapter::Zig if resource == "default" || resource == "global" => {
            root.shared().join("zig/global")
        }
        Adapter::Meson if resource == "default" || resource == "packages" => {
            root.shared().join("meson/packages")
        }
        Adapter::Bun if resource == "default" || resource == "install" => {
            root.shared().join("bun/install")
        }
        Adapter::Bun if resource == "transpiler" => root.shared().join("bun/transpiler"),
        Adapter::Yarn if resource == "default" || resource == "classic" => {
            root.shared().join("yarn/classic")
        }
        _ => bail!("unsupported migration resource '{resource}' for {adapter:?}"),
    })
}

fn copy_tree(source: &Path, destination: &Path, published_destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    let mut hard_links = HashMap::new();
    for entry in walkdir::WalkDir::new(source).follow_links(false) {
        let entry = entry?;
        let relative = entry.path().strip_prefix(source)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let target = destination.join(relative);
        let file_type = entry.file_type();
        if file_type.is_symlink() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            copy_symlink(source, published_destination, entry.path(), &target)?;
        }
        if file_type.is_dir() {
            fs::create_dir_all(target)?;
        } else if file_type.is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            if let Some(key) = hard_link_key(entry.path())? {
                if let Some(existing) = hard_links.get(&key) {
                    fs::hard_link(existing, &target).with_context(|| {
                        format!("preserve hard link {}", entry.path().display())
                    })?;
                    continue;
                }
                fs::copy(entry.path(), &target)?;
                hard_links.insert(key, target);
            } else {
                fs::copy(entry.path(), target)?;
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn hard_link_key(path: &Path) -> Result<Option<(u64, u64)>> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(path)?;
    Ok((metadata.nlink() > 1).then_some((metadata.dev(), metadata.ino())))
}

#[cfg(not(unix))]
fn hard_link_key(_path: &Path) -> Result<Option<(u64, u64)>> {
    Ok(None)
}

#[cfg(unix)]
fn copy_symlink(
    source_root: &Path,
    destination_root: &Path,
    source: &Path,
    target: &Path,
) -> Result<()> {
    let link = migrated_link_target(source_root, destination_root, &fs::read_link(source)?)?;
    std::os::unix::fs::symlink(link, target)
        .with_context(|| format!("copy symbolic link {}", source.display()))
}

#[cfg(windows)]
fn copy_symlink(
    source_root: &Path,
    destination_root: &Path,
    source: &Path,
    target: &Path,
) -> Result<()> {
    let link = migrated_link_target(source_root, destination_root, &fs::read_link(source)?)?;
    if fs::metadata(source).is_ok_and(|metadata| metadata.is_dir()) {
        std::os::windows::fs::symlink_dir(link, target)
            .with_context(|| format!("copy directory symbolic link {}", source.display()))
    } else {
        std::os::windows::fs::symlink_file(link, target)
            .with_context(|| format!("copy file symbolic link {}", source.display()))
    }
}

#[cfg(not(any(unix, windows)))]
fn copy_symlink(
    _source_root: &Path,
    _destination_root: &Path,
    source: &Path,
    _target: &Path,
) -> Result<()> {
    bail!(
        "symbolic-link migration is unsupported on this platform: {}",
        source.display()
    )
}

fn migrated_link_target(
    source_root: &Path,
    destination_root: &Path,
    link: &Path,
) -> Result<PathBuf> {
    if link.is_absolute() && link.starts_with(source_root) {
        return Ok(destination_root.join(link.strip_prefix(source_root)?));
    }
    Ok(link.to_path_buf())
}

fn has_internal_absolute_links(source_root: &Path) -> Result<bool> {
    for entry in walkdir::WalkDir::new(source_root).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_symlink() {
            continue;
        }
        let link = fs::read_link(entry.path())
            .with_context(|| format!("read migration symlink {}", entry.path().display()))?;
        if link.is_absolute() && link.starts_with(source_root) {
            return Ok(true);
        }
    }
    Ok(false)
}
