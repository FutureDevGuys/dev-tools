use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::adapter::Adapter;
use crate::root::RootHandle;
use crate::util::{now_unix, write_json_atomic};

const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    CargoIntermediate,
    SccacheLocal,
    GoBuild,
    GoModule,
    GoTemp,
    NpmCache,
    PnpmStore,
    PnpmMetadata,
    UvCache,
    UvPythonArchive,
    PipCache,
    CcacheLocal,
    CcacheTemp,
    ZigGlobal,
    ZigLocal,
    MesonPackage,
    BunInstall,
    BunTranspiler,
    YarnClassic,
    GenericTemp,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CleanupStrategy {
    OwnedDirectory,
    SccacheServerAware,
    GoBuild,
    GoModule,
    Npm,
    PnpmStore,
    Uv,
    Pip,
    Ccache,
    BunInstall,
    YarnClassic,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ResourceRecord {
    pub schema_version: u32,
    pub resource_id: String,
    pub root_id: String,
    pub domain_id: String,
    pub platform: String,
    pub adapter: Adapter,
    pub kind: ResourceKind,
    pub relative_path: PathBuf,
    pub generation: String,
    pub created_unix: u64,
    pub last_started_unix: u64,
    pub last_completed_unix: Option<u64>,
    pub last_maintained_unix: Option<u64>,
    pub cleanup: CleanupStrategy,
    #[serde(default)]
    pub hazards: BTreeSet<String>,
    #[serde(default)]
    pub native_program: Option<PathBuf>,
    #[serde(default)]
    pub native_prefix: Vec<String>,
    #[serde(default)]
    pub native_environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default)]
pub struct NativeTool {
    pub program: Option<PathBuf>,
    pub prefix: Vec<String>,
    pub environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CatalogIssue {
    pub path: PathBuf,
    pub reason: String,
}

pub fn register_routed(
    root: &RootHandle,
    adapter: Adapter,
    values: &HashMap<String, String>,
    native: &NativeTool,
    hazards: &BTreeSet<String>,
) -> Result<Vec<String>> {
    let directory = catalog_dir(root);
    fs::create_dir_all(&directory)?;
    let now = now_unix();
    let mut registered = BTreeSet::new();
    for (variable, value) in values {
        let Some(kind) = resource_kind(variable) else {
            continue;
        };
        let mut absolute = PathBuf::from(value);
        if kind == ResourceKind::CargoIntermediate
            && absolute
                .file_name()
                .is_some_and(|name| name == "{workspace-path-hash}")
        {
            absolute.pop();
        }
        if !absolute.is_absolute() || !absolute.starts_with(&root.platform_root) {
            continue;
        }
        let relative = checked_relative(root, &absolute)?;
        let resource_id = resource_id(kind, &relative);
        if !registered.insert(resource_id.clone()) {
            continue;
        }
        let record_path = catalog_path(root, &resource_id);
        let mut record = if record_path.is_file() {
            let record: ResourceRecord = serde_json::from_slice(&fs::read(&record_path)?)
                .with_context(|| format!("parse resource record {}", record_path.display()))?;
            validate_record(root, &record)?;
            if record.kind != kind || record.adapter != adapter || record.relative_path != relative
            {
                bail!("resource catalog identity mismatch for {resource_id}");
            }
            record
        } else {
            let mut initial_hazards = BTreeSet::new();
            if linked_state_sensitive(kind) && directory_nonempty(&absolute)? {
                initial_hazards.insert("existing-linked-state-unknown".to_owned());
            }
            ResourceRecord {
                schema_version: SCHEMA_VERSION,
                resource_id: resource_id.clone(),
                root_id: root.marker.root_id.clone(),
                domain_id: root.domain_id.clone(),
                platform: root.platform.clone(),
                adapter,
                kind,
                relative_path: relative,
                generation: uuid::Uuid::new_v4().simple().to_string(),
                created_unix: now,
                last_started_unix: now,
                last_completed_unix: None,
                last_maintained_unix: None,
                cleanup: cleanup_strategy(kind),
                hazards: initial_hazards,
                native_program: native.program.clone(),
                native_prefix: native.prefix.clone(),
                native_environment: native.environment.clone(),
            }
        };
        record.last_started_unix = now;
        record.hazards.extend(
            hazards
                .iter()
                .filter(|hazard| hazard_applies(kind, hazard))
                .cloned(),
        );
        if native.program.is_some() {
            record.native_program = native.program.clone();
            record.native_prefix = native.prefix.clone();
            record.native_environment = native.environment.clone();
        }
        write_json_atomic(&record_path, &record)?;
    }
    Ok(registered.into_iter().collect())
}

pub fn register_migrated(
    root: &RootHandle,
    adapter: Adapter,
    resource: Option<&str>,
    destination: &Path,
) -> Result<String> {
    let kind = migrated_resource_kind(adapter, resource.unwrap_or("default"))?;
    if !destination.is_absolute() || !destination.starts_with(&root.platform_root) {
        bail!(
            "migrated resource is outside the runtime domain: {}",
            destination.display()
        );
    }
    let relative = checked_relative(root, destination)?;
    let resource_id = resource_id(kind, &relative);
    let now = now_unix();
    let record = ResourceRecord {
        schema_version: SCHEMA_VERSION,
        resource_id: resource_id.clone(),
        root_id: root.marker.root_id.clone(),
        domain_id: root.domain_id.clone(),
        platform: root.platform.clone(),
        adapter,
        kind,
        relative_path: relative,
        generation: uuid::Uuid::new_v4().simple().to_string(),
        created_unix: now,
        last_started_unix: now,
        last_completed_unix: Some(now),
        last_maintained_unix: None,
        cleanup: cleanup_strategy(kind),
        hazards: BTreeSet::new(),
        native_program: None,
        native_prefix: Vec::new(),
        native_environment: BTreeMap::new(),
    };
    validate_record(root, &record)?;
    fs::create_dir_all(catalog_dir(root))?;
    write_json_atomic(&catalog_path(root, &resource_id), &record)?;
    Ok(resource_id)
}

pub fn complete(root: &RootHandle, resource_ids: &[String]) -> Result<()> {
    let now = now_unix();
    for resource_id in resource_ids {
        let path = catalog_path(root, resource_id);
        if !path.is_file() {
            continue;
        }
        let mut record: ResourceRecord = serde_json::from_slice(&fs::read(&path)?)?;
        validate_record(root, &record)?;
        record.last_completed_unix = Some(now);
        write_json_atomic(&path, &record)?;
    }
    Ok(())
}

pub fn mark_maintained(root: &RootHandle, resource_id: &str) -> Result<()> {
    let path = catalog_path(root, resource_id);
    let mut record: ResourceRecord = serde_json::from_slice(&fs::read(&path)?)?;
    validate_record(root, &record)?;
    record.last_maintained_unix = Some(now_unix());
    write_json_atomic(&path, &record)
}

pub fn get(root: &RootHandle, resource_id: &str) -> Result<Option<ResourceRecord>> {
    let path = catalog_path(root, resource_id);
    if !path.is_file() {
        return Ok(None);
    }
    let record: ResourceRecord = serde_json::from_slice(&fs::read(&path)?)?;
    validate_record(root, &record)?;
    if catalog_path(root, &record.resource_id) != path {
        bail!("catalog filename does not match resource identifier");
    }
    Ok(Some(record))
}

pub fn remove_record(root: &RootHandle, resource_id: &str) -> Result<()> {
    let path = catalog_path(root, resource_id);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub fn resource_ids_under(root: &RootHandle, parent: &Path) -> Result<Vec<String>> {
    let (records, issues) = scan(root)?;
    if let Some(issue) = issues.first() {
        bail!(
            "cannot reconcile resources below {} while catalog entry {} is invalid: {}",
            parent.display(),
            issue.path.display(),
            issue.reason
        );
    }
    records
        .into_iter()
        .filter_map(|record| match absolute_path(root, &record) {
            Ok(path) if path.starts_with(parent) => Some(Ok(record.resource_id)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

pub fn list(root: &RootHandle) -> Result<Vec<ResourceRecord>> {
    let (records, issues) = scan(root)?;
    if let Some(issue) = issues.first() {
        bail!(
            "invalid resource catalog entry {}: {}",
            issue.path.display(),
            issue.reason
        );
    }
    Ok(records)
}

pub fn scan(root: &RootHandle) -> Result<(Vec<ResourceRecord>, Vec<CatalogIssue>)> {
    let directory = catalog_dir(root);
    if !directory.is_dir() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut records = Vec::new();
    let mut issues = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let result = fs::read(entry.path())
            .context("read resource record")
            .and_then(|bytes| {
                serde_json::from_slice::<ResourceRecord>(&bytes).context("parse resource record")
            })
            .and_then(|record| {
                validate_record(root, &record)?;
                if catalog_path(root, &record.resource_id) != entry.path() {
                    bail!("catalog filename does not match resource identifier");
                }
                Ok(record)
            });
        match result {
            Ok(record) => records.push(record),
            Err(error) => issues.push(CatalogIssue {
                path: entry.path(),
                reason: format!("{error:#}"),
            }),
        }
    }
    records.sort_by(|left, right| left.resource_id.cmp(&right.resource_id));
    Ok((records, issues))
}

pub fn absolute_path(root: &RootHandle, record: &ResourceRecord) -> Result<PathBuf> {
    validate_record(root, record)?;
    let absolute = root.platform_root.join(&record.relative_path);
    checked_relative(root, &absolute)?;
    Ok(absolute)
}

pub fn validate_record(root: &RootHandle, record: &ResourceRecord) -> Result<()> {
    if record.schema_version != SCHEMA_VERSION {
        bail!(
            "unsupported resource record schema {}",
            record.schema_version
        );
    }
    if record.root_id != root.marker.root_id
        || record.domain_id != root.domain_id
        || record.platform != root.platform
    {
        bail!("resource record belongs to another root or runtime domain");
    }
    if resource_id(record.kind, &record.relative_path) != record.resource_id {
        bail!("resource record identifier does not match its kind and path");
    }
    let absolute = root.platform_root.join(&record.relative_path);
    checked_relative(root, &absolute)?;
    Ok(())
}

pub fn catalog_path(root: &RootHandle, resource_id: &str) -> PathBuf {
    catalog_dir(root).join(format!("{resource_id}.json"))
}

fn catalog_dir(root: &RootHandle) -> PathBuf {
    root.control().join("resources")
}

fn resource_id(kind: ResourceKind, relative: &Path) -> String {
    let payload = format!("v1\0{kind:?}\0{}", relative.to_string_lossy());
    blake3::hash(payload.as_bytes()).to_hex().to_string()
}

fn checked_relative(root: &RootHandle, absolute: &Path) -> Result<PathBuf> {
    let relative = absolute
        .strip_prefix(&root.platform_root)
        .with_context(|| {
            format!(
                "resource path is outside runtime domain: {}",
                absolute.display()
            )
        })?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("resource path is not a normal domain-relative path");
    }
    let mut current = root.platform_root.clone();
    for component in relative.components() {
        current.push(component.as_os_str());
        let Ok(metadata) = fs::symlink_metadata(&current) else {
            continue;
        };
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            bail!(
                "resource path contains a link or reparse point: {}",
                current.display()
            );
        }
    }
    Ok(relative.to_path_buf())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn cleanup_strategy(kind: ResourceKind) -> CleanupStrategy {
    match kind {
        ResourceKind::SccacheLocal => CleanupStrategy::SccacheServerAware,
        ResourceKind::GoBuild => CleanupStrategy::GoBuild,
        ResourceKind::GoModule => CleanupStrategy::GoModule,
        ResourceKind::NpmCache => CleanupStrategy::Npm,
        ResourceKind::PnpmStore => CleanupStrategy::PnpmStore,
        ResourceKind::UvCache => CleanupStrategy::Uv,
        ResourceKind::PipCache => CleanupStrategy::Pip,
        ResourceKind::CcacheLocal => CleanupStrategy::Ccache,
        ResourceKind::BunInstall => CleanupStrategy::BunInstall,
        ResourceKind::YarnClassic => CleanupStrategy::YarnClassic,
        _ => CleanupStrategy::OwnedDirectory,
    }
}

fn linked_state_sensitive(kind: ResourceKind) -> bool {
    matches!(
        kind,
        ResourceKind::SccacheLocal
            | ResourceKind::PnpmStore
            | ResourceKind::UvCache
            | ResourceKind::BunInstall
    )
}

fn directory_nonempty(path: &Path) -> Result<bool> {
    if !path.is_dir() {
        return Ok(false);
    }
    Ok(fs::read_dir(path)?.next().transpose()?.is_some())
}

fn hazard_applies(kind: ResourceKind, hazard: &str) -> bool {
    match hazard {
        "uv-symlink-mode" | "uv-link-mode-unknown" => kind == ResourceKind::UvCache,
        "bun-global-store" | "bun-global-store-unknown" => kind == ResourceKind::BunInstall,
        "sccache-remote-or-foreign-server" => kind == ResourceKind::SccacheLocal,
        "pnpm-external-store-server" => kind == ResourceKind::PnpmStore,
        _ => true,
    }
}

fn resource_kind(variable: &str) -> Option<ResourceKind> {
    Some(match variable {
        "CARGO_BUILD_BUILD_DIR" => ResourceKind::CargoIntermediate,
        "SCCACHE_DIR" => ResourceKind::SccacheLocal,
        "GOCACHE" => ResourceKind::GoBuild,
        "GOMODCACHE" => ResourceKind::GoModule,
        "GOTMPDIR" => ResourceKind::GoTemp,
        "npm_config_cache" => ResourceKind::NpmCache,
        "pnpm_config_store_dir" => ResourceKind::PnpmStore,
        "pnpm_config_cache_dir" => ResourceKind::PnpmMetadata,
        "UV_CACHE_DIR" => ResourceKind::UvCache,
        "UV_PYTHON_CACHE_DIR" => ResourceKind::UvPythonArchive,
        "PIP_CACHE_DIR" => ResourceKind::PipCache,
        "CCACHE_DIR" => ResourceKind::CcacheLocal,
        "CCACHE_TEMPDIR" => ResourceKind::CcacheTemp,
        "ZIG_GLOBAL_CACHE_DIR" => ResourceKind::ZigGlobal,
        "ZIG_LOCAL_CACHE_DIR" => ResourceKind::ZigLocal,
        "MESON_PACKAGE_CACHE_DIR" => ResourceKind::MesonPackage,
        "BUN_INSTALL_CACHE_DIR" => ResourceKind::BunInstall,
        "BUN_RUNTIME_TRANSPILER_CACHE_PATH" => ResourceKind::BunTranspiler,
        "YARN_CACHE_FOLDER" => ResourceKind::YarnClassic,
        "TMPDIR" | "TEMP" | "TMP" => ResourceKind::GenericTemp,
        _ => return None,
    })
}

fn migrated_resource_kind(adapter: Adapter, resource: &str) -> Result<ResourceKind> {
    Ok(match (adapter, resource) {
        (Adapter::Temp, "default") => ResourceKind::GenericTemp,
        (Adapter::Sccache, "default" | "cache") => ResourceKind::SccacheLocal,
        (Adapter::Go, "default" | "build") => ResourceKind::GoBuild,
        (Adapter::Go, "modules") => ResourceKind::GoModule,
        (Adapter::Npm, "default" | "cache") => ResourceKind::NpmCache,
        (Adapter::Pnpm, "default" | "store") => ResourceKind::PnpmStore,
        (Adapter::Pnpm, "cache") => ResourceKind::PnpmMetadata,
        (Adapter::Uv, "default" | "cache") => ResourceKind::UvCache,
        (Adapter::Uv, "python") => ResourceKind::UvPythonArchive,
        (Adapter::Pip, "default" | "cache") => ResourceKind::PipCache,
        (Adapter::Ccache, "default" | "cache") => ResourceKind::CcacheLocal,
        (Adapter::Zig, "default" | "global") => ResourceKind::ZigGlobal,
        (Adapter::Meson, "default" | "packages") => ResourceKind::MesonPackage,
        (Adapter::Bun, "default" | "install") => ResourceKind::BunInstall,
        (Adapter::Bun, "transpiler") => ResourceKind::BunTranspiler,
        (Adapter::Yarn, "default" | "classic") => ResourceKind::YarnClassic,
        _ => bail!("unsupported migrated resource '{resource}' for {adapter:?}"),
    })
}

pub fn hazard_map(records: &[ResourceRecord]) -> BTreeMap<String, Vec<String>> {
    records
        .iter()
        .filter(|record| !record.hazards.is_empty())
        .map(|record| {
            (
                record.resource_id.clone(),
                record.hazards.iter().cloned().collect(),
            )
        })
        .collect()
}
