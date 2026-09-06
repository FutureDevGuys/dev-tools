use dev_tools_product::{BuildInfo, ProductId};
use dev_tools_update::artifact::ArtifactCatalog;
use dev_tools_update::discovery::{DiscoveryError, ObservedRelease};
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const CONFIG_LIMIT: u64 = 1024 * 1024;
mod completion;
mod config_edit;
mod doctor;

enum CheckedRelease {
    Observed(ObservedRelease),
    #[cfg(target_os = "linux")]
    Authenticated {
        version: String,
        url: String,
        generation: u64,
        changed: bool,
    },
}

#[cfg(target_os = "linux")]
mod artifact_cache;
#[cfg(target_os = "linux")]
mod cache;
#[cfg(target_os = "linux")]
mod installed_state;
#[cfg(target_os = "linux")]
mod installer;
#[cfg(target_os = "linux")]
mod ledger_store;
#[cfg(target_os = "linux")]
mod private_directory;
#[cfg(target_os = "linux")]
mod recovery;
#[cfg(target_os = "linux")]
mod retained_evidence;
#[cfg(target_os = "linux")]
mod rollback;
#[cfg(target_os = "linux")]
mod signed_cache;
#[cfg(all(target_os = "linux", test))]
#[path = "../tests/support/signed_check.rs"]
mod signed_check_tests;

pub fn main_entry(arguments: impl Iterator<Item = OsString>) -> i32 {
    match run(arguments) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("artifact-update: {error}");
            2
        }
    }
}

fn run(arguments: impl Iterator<Item = OsString>) -> Result<i32, String> {
    let arguments = arguments
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| "arguments must be UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let Some(command) = arguments.first().map(String::as_str) else {
        return Err(usage().to_owned());
    };
    match command {
        "--help" | "-h" if arguments.len() == 1 => {
            println!("{}", usage());
            Ok(0)
        }
        "--version" | "-V" if arguments.len() == 1 => {
            println!("artifact-update {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        "build-info" => build_info(&arguments[1..]),
        "completion" => completion::run(&arguments[1..]),
        "list" => catalog_command("list", &arguments[1..]),
        "status" => catalog_command("status", &arguments[1..]),
        "doctor" => doctor::run(&arguments[1..]),
        "check" => check_command(&arguments[1..]),
        "install" => install_command(&arguments[1..]),
        "rollback" | "recover" => local_installation_command(&arguments[0], &arguments[1..]),
        "trust" => trust_command(&arguments[1..]),
        "config" => config_edit::run(&arguments[1..]),
        _ => Err(usage().to_owned()),
    }
}

fn local_installation_command(operation: &str, arguments: &[String]) -> Result<i32, String> {
    let id = arguments
        .first()
        .filter(|id| !id.starts_with('-'))
        .ok_or_else(|| format!("{operation} requires ID [--config PATH] [--json]"))?;
    let (config, json) = parse_catalog_options(&arguments[1..])?;
    let bytes = read_bounded_config(&config)?;
    let catalog = ArtifactCatalog::parse(
        std::str::from_utf8(&bytes).map_err(|_| "configuration is not UTF-8")?,
    )
    .map_err(|error| error.to_string())?;
    let record = catalog
        .get(id)
        .ok_or("selected artifact is not configured")?;
    let mut row = serde_json::json!({
        "schema": format!("artifact-update-{operation}-v1"), "id": id, "operation": operation,
        "outcome": "unsupported-platform", "changed": false, "network_accessed": false,
    });
    let code = if record.release_authority().is_none() {
        row["outcome"] = serde_json::json!("check-only");
        3
    } else {
        #[cfg(target_os = "linux")]
        {
            let mut changed = Some(false);
            let result = ledger_store::LedgerStore::for_record(record)
                .map_err(|_| ("authority-unavailable", 4))
                .and_then(|store| {
                    if operation == "recover" {
                        recovery::execute_with_store(record, &store, &mut changed)
                    } else {
                        rollback::execute_with_store(record, &store, &mut changed)
                            .map(|report| (report.changed, Some(report.receipt)))
                    }
                });
            row["changed"] = serde_json::json!(changed);
            match result {
                Ok((changed, receipt)) => {
                    row["outcome"] = serde_json::json!(if operation == "rollback" {
                        "rolled-back"
                    } else if changed {
                        "recovered"
                    } else {
                        "unchanged"
                    });
                    if let Some(receipt) = receipt {
                        row["installed_version"] = serde_json::json!(receipt.active_version);
                        row["installation_state"] = serde_json::json!("managed");
                        row["verification"] =
                            serde_json::json!("signed-manifest-and-receipt-content");
                    } else {
                        row["installation_state"] = serde_json::json!("unknown");
                    }
                    0
                }
                Err((outcome, code)) => {
                    row["outcome"] = serde_json::json!(outcome);
                    row["error_kind"] = serde_json::json!(if code == 4 {
                        "authority-violation"
                    } else {
                        "blocked"
                    });
                    code
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            3
        }
    };
    if json {
        write_json(&row)?;
    } else {
        println!("{id}\t{}", row["outcome"].as_str().unwrap_or("unknown"));
    }
    Ok(code)
}

fn install_command(arguments: &[String]) -> Result<i32, String> {
    let id = arguments
        .first()
        .filter(|id| !id.starts_with('-'))
        .ok_or("install requires ID [--config PATH] [--json] [--offline]")?;
    let mut offline = false;
    let mut options = Vec::new();
    let mut arguments = arguments[1..].iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--offline" if !offline => offline = true,
            "--config" => {
                options.push(argument.clone());
                options.push(arguments.next().ok_or("--config requires a path")?.clone());
            }
            "--json" => options.push(argument.clone()),
            _ => return Err("install contains an unknown or duplicate option".into()),
        }
    }
    let (config, json) = parse_catalog_options(&options)?;
    let bytes = read_bounded_config(&config)?;
    let catalog = ArtifactCatalog::parse(
        std::str::from_utf8(&bytes).map_err(|_| "configuration is not UTF-8")?,
    )
    .map_err(|error| error.to_string())?;
    let record = catalog
        .get(id)
        .ok_or("selected artifact is not configured")?;
    let mut row = serde_json::json!({
        "schema": "artifact-update-install-v1", "id": id, "operation": "install",
        "outcome": "unsupported-platform", "changed": false, "network_accessed": false,
        "metadata_cache_changed": false,
        "artifact_cache_changed": false,
    });
    let code = if record.release_authority().is_none() {
        row["outcome"] = serde_json::json!("check-only");
        3
    } else {
        #[cfg(target_os = "linux")]
        {
            let mut progress = installer::Progress::default();
            let result = installer::execute(record, &bytes, offline, &mut progress);
            row["network_accessed"] = serde_json::json!(progress.network_accessed);
            row["changed"] = serde_json::json!(progress.changed);
            row["metadata_cache_changed"] = serde_json::json!(progress.metadata_cache_changed);
            row["artifact_cache_changed"] = serde_json::json!(progress.artifact_cache_changed);
            match result {
                Ok(report) => {
                    row["outcome"] = serde_json::json!(if progress.changed == Some(true) {
                        "installed"
                    } else {
                        "unchanged"
                    });
                    row["installed_version"] = serde_json::json!(report.receipt.active_version);
                    row["installation_state"] = serde_json::json!("managed");
                    row["verification"] = serde_json::json!("signed-manifest-and-receipt-content");
                    0
                }
                Err((outcome, code)) => {
                    row["outcome"] = serde_json::json!(outcome);
                    row["error_kind"] = serde_json::json!(match code {
                        4 => "authority-violation",
                        3 => "blocked",
                        _ => "operation-failed",
                    });
                    code
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            3
        }
    };
    if json {
        write_json(&row)?;
    } else {
        println!("{id}\t{}", row["outcome"].as_str().unwrap_or("unknown"));
    }
    Ok(code)
}

fn trust_command(arguments: &[String]) -> Result<i32, String> {
    if !matches!(
        arguments.first().map(String::as_str),
        Some("initialize" | "status" | "recover")
    ) || arguments.get(1).is_none_or(|id| id.starts_with('-'))
    {
        return Err("trust requires initialize|status|recover ID [--config PATH] [--json]".into());
    }
    let operation = arguments[0].as_str();
    let id = &arguments[1];
    let (config, json) = parse_catalog_options(&arguments[2..])?;
    let bytes = read_bounded_config(&config)?;
    let catalog = ArtifactCatalog::parse(
        std::str::from_utf8(&bytes).map_err(|_| "configuration is not UTF-8")?,
    )
    .map_err(|error| error.to_string())?;
    let record = catalog
        .get(id)
        .ok_or("selected artifact is not configured")?;
    if record.release_authority().is_none() {
        return Err("trust initialization requires signed-manifest authority".into());
    }
    #[cfg(target_os = "linux")]
    let (outcome, code, changed) = {
        let initialize = || -> Result<(&str, i32, Option<bool>), String> {
            let store = ledger_store::LedgerStore::for_record(record)?;
            if operation == "recover" {
                let changed = store.recover_initial_publication()?;
                return Ok((
                    if changed { "recovered" } else { "unchanged" },
                    0,
                    Some(changed),
                ));
            }
            let present = store.load(record)?.is_some();
            if operation == "status" {
                return Ok((if present { "present" } else { "absent" }, 0, Some(false)));
            }
            if present {
                return Ok(("already-initialized", 3, Some(false)));
            }
            store.transaction(
                record,
                ledger_store::LedgerExpectation::FirstUse,
                |_| Ok(()),
            )?;
            Ok(("initialized", 0, Some(true)))
        };
        initialize().unwrap_or((
            "authority-unavailable",
            4,
            (operation == "status").then_some(false),
        ))
    };
    #[cfg(not(target_os = "linux"))]
    let (outcome, code, changed) = ("unsupported-platform", 3, Some(false));
    if json {
        write_json(&serde_json::json!({
            "schema": "artifact-update-trust-v1", "id": id, "operation": operation,
            "outcome": outcome, "changed": changed, "network_accessed": false,
            "installation_authorized": false,
        }))?;
    } else {
        println!("{id}\t{outcome}");
    }
    Ok(code)
}

fn check_command(arguments: &[String]) -> Result<i32, String> {
    let mut selected = None;
    let mut all = false;
    let mut os = None;
    let mut architecture = None;
    let mut catalog_arguments = Vec::new();
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--all" if !all && selected.is_none() => all = true,
            "--os" if os.is_none() => {
                os = Some(arguments.next().ok_or("--os requires a value")?.as_str())
            }
            "--architecture" if architecture.is_none() => {
                architecture = Some(
                    arguments
                        .next()
                        .ok_or("--architecture requires a value")?
                        .as_str(),
                )
            }
            "--config" => {
                catalog_arguments.push(argument.clone());
                catalog_arguments.push(arguments.next().ok_or("--config requires a path")?.clone());
            }
            "--json" => catalog_arguments.push(argument.clone()),
            id if !id.starts_with('-') && selected.is_none() && !all => selected = Some(id),
            _ => return Err("check contains an unknown or duplicate option".into()),
        }
    }
    let (config, json) = parse_catalog_options(&catalog_arguments)?;
    let bytes = read_bounded_config(&config)?;
    let catalog = ArtifactCatalog::parse(
        std::str::from_utf8(&bytes).map_err(|_| "configuration is not UTF-8")?,
    )
    .map_err(|error| error.to_string())?;
    if selected.is_some_and(|id| catalog.get(id).is_none()) {
        return Err("selected artifact is not configured".into());
    }
    let target_override = os.is_some() || architecture.is_some();
    let os = os.unwrap_or(std::env::consts::OS);
    let architecture = architecture.unwrap_or(std::env::consts::ARCH);
    for target in [os, architecture] {
        if target.is_empty()
            || target.len() > 128
            || !target
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err("target operating system or architecture is invalid".into());
        }
    }
    let mut rows = Vec::new();
    let mut network_accessed = false;
    let mut exit = 0;
    for (id, artifact) in catalog
        .iter()
        .filter(|(id, _)| selected.is_none_or(|selected| selected == *id))
    {
        let result = check_one(
            artifact,
            &bytes,
            id,
            os,
            architecture,
            target_override,
            &mut network_accessed,
        );
        let row = match result {
            Ok(Some(CheckedRelease::Observed(observed))) => serde_json::json!({
                "id": id, "outcome": "available", "available_version": observed.version(),
                "tag": observed.tag(), "asset_name": observed.asset().name(), "asset_url": observed.asset().url(),
                "verification": "not-performed", "installation_authorized": false,
            }),
            #[cfg(target_os = "linux")]
            Ok(Some(CheckedRelease::Authenticated {
                version,
                url,
                generation,
                changed,
            })) => serde_json::json!({
                "id": id, "outcome": "available", "available_version": version,
                "asset_url": url, "manifest_generation": generation, "ledger_changed": changed,
                "verification": "signed-metadata", "installation_authorized": false,
            }),
            Ok(None) => {
                serde_json::json!({"id": id, "outcome": "no-match", "installation_authorized": false})
            }
            Err((diagnostic, code)) => {
                exit = match (exit, code) {
                    (4, _) | (_, 4) => 4,
                    (1, _) | (_, 1) => 1,
                    _ => 3,
                };
                serde_json::json!({"id": id, "outcome": "unknown", "diagnostic": diagnostic, "installation_authorized": false})
            }
        };
        if !json {
            let outcome = row["outcome"].as_str().unwrap_or("unknown");
            let detail = row
                .get("available_version")
                .or_else(|| row.get("diagnostic"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            println!("{id}\t{outcome}\t{}", detail.escape_default());
        }
        rows.push(row);
    }
    if json {
        write_json(
            &serde_json::json!({"schema": "artifact-update-check-v1", "network_accessed": network_accessed, "artifacts": rows}),
        )?;
    }
    Ok(exit)
}

fn check_one(
    artifact: &dev_tools_update::artifact::ArtifactRecord,
    config: &[u8],
    id: &str,
    os: &str,
    architecture: &str,
    target_override: bool,
    network_accessed: &mut bool,
) -> Result<Option<CheckedRelease>, (String, i32)> {
    if matches!(
        artifact.source(),
        dev_tools_update::artifact::ArtifactSource::StaticManifest { .. }
    ) {
        if target_override {
            return Err((
                "signed checks use the configured target and do not accept target overrides".into(),
                3,
            ));
        }
        #[cfg(target_os = "linux")]
        return check_signed(artifact, config, id, network_accessed).map(Some);
        #[cfg(not(target_os = "linux"))]
        return Err((
            "signed release state is unsupported on this platform".into(),
            3,
        ));
    }
    let uses_network = matches!(
        artifact.source(),
        dev_tools_update::artifact::ArtifactSource::Github { .. }
            | dev_tools_update::artifact::ArtifactSource::Gitlab { .. }
            | dev_tools_update::artifact::ArtifactSource::Forgejo { .. }
            | dev_tools_update::artifact::ArtifactSource::Gitea { .. }
            | dev_tools_update::artifact::ArtifactSource::GenericJson { .. }
            | dev_tools_update::artifact::ArtifactSource::Npm { .. }
            | dev_tools_update::artifact::ArtifactSource::CratesIo { .. }
            | dev_tools_update::artifact::ArtifactSource::Maven { .. }
            | dev_tools_update::artifact::ArtifactSource::Sparkle { .. }
            | dev_tools_update::artifact::ArtifactSource::GenericXml { .. }
            | dev_tools_update::artifact::ArtifactSource::Zsync { .. }
            | dev_tools_update::artifact::ArtifactSource::Html { .. }
            | dev_tools_update::artifact::ArtifactSource::Url { .. }
    );
    let discovery_error = |error: DiscoveryError| {
        (
            error.to_string(),
            if error == DiscoveryError::UnsupportedSource {
                3
            } else {
                1
            },
        )
    };
    #[cfg(target_os = "linux")]
    {
        let store = metadata_store().map_err(|error| (error, 1))?;
        let key = cache::cache_key(config, id, os, architecture);
        let mut metadata = store
            .load(&key, artifact, os, architecture)
            .map_err(|error| (error, 1))?
            .map(|snapshot| snapshot.metadata)
            .unwrap_or(cache::Metadata::empty(artifact).map_err(discovery_error)?);
        *network_accessed |= uses_network;
        let result = metadata
            .check(artifact, os, architecture)
            .map_err(discovery_error)?;
        store
            .save(&key, &metadata, unix_now().map_err(|error| (error, 1))?)
            .map_err(|error| (error, 1))?;
        Ok(result.map(CheckedRelease::Observed))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config, id);
        *network_accessed |= uses_network;
        match artifact.source() {
            dev_tools_update::artifact::ArtifactSource::Url { .. } => {
                dev_tools_update::discovery::check_url_release(artifact, os, architecture)
            }
            dev_tools_update::artifact::ArtifactSource::Html { .. } => {
                dev_tools_update::discovery::check_html_release(artifact, os, architecture)
            }
            dev_tools_update::artifact::ArtifactSource::Zsync { .. } => {
                dev_tools_update::discovery::check_zsync_release(artifact, os, architecture)
            }
            dev_tools_update::artifact::ArtifactSource::GenericXml { .. } => {
                dev_tools_update::discovery::check_generic_xml_release(artifact, os, architecture)
            }
            dev_tools_update::artifact::ArtifactSource::Sparkle { .. } => {
                dev_tools_update::discovery::check_sparkle_release(artifact, os, architecture)
            }
            dev_tools_update::artifact::ArtifactSource::Maven { .. } => {
                dev_tools_update::discovery::check_maven_release(artifact, os, architecture)
            }
            dev_tools_update::artifact::ArtifactSource::CratesIo { .. } => {
                dev_tools_update::discovery::check_crates_io_release(artifact, os, architecture)
            }
            dev_tools_update::artifact::ArtifactSource::Npm { .. } => {
                dev_tools_update::discovery::check_npm_release(artifact, os, architecture)
            }
            dev_tools_update::artifact::ArtifactSource::Gitlab { .. } => {
                dev_tools_update::discovery::check_gitlab_release(artifact, os, architecture)
            }
            dev_tools_update::artifact::ArtifactSource::Forgejo { .. } => {
                dev_tools_update::discovery::check_forgejo_release(artifact, os, architecture)
            }
            dev_tools_update::artifact::ArtifactSource::Gitea { .. } => {
                dev_tools_update::discovery::check_gitea_release(artifact, os, architecture)
            }
            dev_tools_update::artifact::ArtifactSource::GenericJson { .. } => {
                dev_tools_update::discovery::check_generic_json_release(artifact, os, architecture)
            }
            _ => dev_tools_update::discovery::check_github_release(artifact, os, architecture),
        }
        .map(|result| result.map(CheckedRelease::Observed))
        .map_err(discovery_error)
    }
}

#[cfg(target_os = "linux")]
fn check_signed(
    record: &dev_tools_update::artifact::ArtifactRecord,
    config: &[u8],
    id: &str,
    network_accessed: &mut bool,
) -> Result<CheckedRelease, (String, i32)> {
    let store = ledger_store::LedgerStore::for_record(record).map_err(|error| (error, 4))?;
    let cache = signed_metadata_store().map_err(|error| (error, 1))?;
    let key = signed_metadata_key(config, id);
    check_signed_with_fetch(
        record,
        &store,
        network_accessed,
        || dev_tools_update::discovery::check_static_manifest(record).map(|(metadata, _)| metadata),
        |metadata| cache.save_cache(&key, metadata, unix_now()?),
    )
}

#[cfg(target_os = "linux")]
fn check_signed_with_fetch(
    record: &dev_tools_update::artifact::ArtifactRecord,
    store: &ledger_store::LedgerStore,
    network_accessed: &mut bool,
    fetch: impl FnOnce() -> Result<dev_tools_release::ReleaseMetadata, DiscoveryError>,
    publish: impl FnOnce(&dev_tools_release::ReleaseMetadata) -> Result<bool, String>,
) -> Result<CheckedRelease, (String, i32)> {
    let (_, identity) = store
        .load(record)
        .map_err(|error| (error, 4))?
        .ok_or_else(|| ("release trust requires explicit initialization".into(), 3))?;
    *network_accessed = true;
    let metadata = fetch().map_err(|error| {
        (
            error.to_string(),
            if matches!(
                error,
                DiscoveryError::Authentication | DiscoveryError::Acceptance
            ) {
                4
            } else {
                1
            },
        )
    })?;
    let (verified, changed) = store
        .transaction(
            record,
            ledger_store::LedgerExpectation::Current(identity),
            |ledger| {
                ledger
                    .accept(record, &metadata)
                    .map(|(verified, _)| verified)
                    .map_err(|error| error.to_string())
            },
        )
        .map_err(|error| (error, 4))?;
    // Cache failure cannot roll back accepted authority. A later check can
    // repopulate disposable metadata, but must honor the committed ledger.
    publish(&metadata).map_err(|error| (error, 1))?;
    Ok(CheckedRelease::Authenticated {
        version: verified.version.to_string(),
        url: verified.artifact_url,
        generation: verified.manifest_generation,
        changed,
    })
}

#[cfg(target_os = "linux")]
fn metadata_store() -> Result<cache::CacheStore, String> {
    cache::CacheStore::new(
        native_metadata_root("metadata-v1")?,
        rustix::process::geteuid().as_raw(),
    )
}

#[cfg(target_os = "linux")]
fn signed_metadata_store() -> Result<signed_cache::Store, String> {
    signed_cache::Store::new(
        native_metadata_root("signed-metadata-v1")?,
        rustix::process::geteuid().as_raw(),
    )
}

#[cfg(target_os = "linux")]
fn signed_metadata_key(config: &[u8], id: &str) -> String {
    cache::cache_key(config, id, "signed-metadata-v1", "configured-target")
}

#[cfg(target_os = "linux")]
fn native_metadata_root(namespace: &str) -> Result<PathBuf, String> {
    if std::env::var_os("XDG_CACHE_HOME")
        .filter(|value| !value.is_empty())
        .is_some_and(|value| !Path::new(&value).is_absolute())
    {
        return Err("native cache root must be absolute".into());
    }
    Ok(
        directories::ProjectDirs::from("dev", "FutureDevGuys", "artifact-update")
            .ok_or("native cache directory is unavailable")?
            .cache_dir()
            .join(namespace),
    )
}

#[cfg(target_os = "linux")]
fn signed_status_row(
    id: &str,
    record: &dev_tools_update::artifact::ArtifactRecord,
    ledger: &ledger_store::LedgerStore,
    cache: &signed_cache::Store,
    key: &str,
    now: u64,
) -> Result<serde_json::Value, String> {
    let mut row = serde_json::json!({"id": id, "outcome": "unknown", "cache_freshness": "absent", "installation_authorized": false});
    let Some((mut accepted, _)) = ledger.load(record)? else {
        row["trust"] = serde_json::json!("requires-initialization");
        return Ok(row);
    };
    let Some(snapshot) = cache.load(key)? else {
        return Ok(row);
    };
    let (verified, changed) = accepted
        .accept(record, &snapshot.metadata)
        .map_err(|_| "cached signed metadata does not match accepted authority")?;
    if changed {
        return Err("cached signed metadata has not been durably accepted".into());
    }
    let fresh = snapshot.is_fresh(now);
    row["cache_freshness"] = serde_json::json!(if fresh { "fresh" } else { "stale" });
    if fresh {
        row["verification"] = serde_json::json!("signed-metadata");
        row["available_version"] = serde_json::json!(verified.version.to_string());
        row["manifest_generation"] = serde_json::json!(verified.manifest_generation);
    }
    Ok(row)
}

#[cfg(target_os = "linux")]
fn unix_now() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "native clock is unavailable".into())
}

fn status_rows(catalog: &ArtifactCatalog, config: &[u8]) -> Result<Vec<serde_json::Value>, String> {
    #[cfg(target_os = "linux")]
    let (store, now) = (metadata_store()?, unix_now()?);
    #[cfg(not(target_os = "linux"))]
    let _ = config;
    let mut rows = Vec::new();
    for (id, artifact) in catalog.iter() {
        #[cfg(target_os = "linux")]
        if matches!(
            artifact.source(),
            dev_tools_update::artifact::ArtifactSource::StaticManifest { .. }
        ) {
            let result = (|| {
                signed_status_row(
                    id,
                    artifact,
                    &ledger_store::LedgerStore::for_record(artifact)?,
                    &signed_metadata_store()?,
                    &signed_metadata_key(config, id),
                    now,
                )
            })();
            let mut row = result.unwrap_or_else(|_| {
                serde_json::json!({
                    "id": id, "outcome": "authority-unavailable", "cache_freshness": "unknown",
                    "installation_authorized": false, "error_kind": "authority-violation"
                })
            });
            installed_state::attach(&mut row, artifact);
            rows.push(row);
            continue;
        }
        let row = serde_json::json!({"id": id, "outcome": "unknown", "cache_freshness": "absent", "installation_authorized": false});
        #[cfg(target_os = "linux")]
        let row = {
            let mut row = row;
            let os = std::env::consts::OS;
            let architecture = std::env::consts::ARCH;
            let key = cache::cache_key(config, id, os, architecture);
            if let Some(snapshot) = store.load(&key, artifact, os, architecture)? {
                row["cache_freshness"] = serde_json::json!(if snapshot.is_fresh(now) {
                    "fresh"
                } else {
                    "stale"
                });
                if snapshot.is_fresh(now) {
                    row["verification"] = serde_json::json!("not-performed");
                    if let Some(observed) = snapshot
                        .metadata
                        .observe(artifact, os, architecture)
                        .map_err(|error| error.to_string())?
                    {
                        row["available_version"] = serde_json::json!(observed.version());
                    }
                }
            }
            row
        };
        #[cfg(not(target_os = "linux"))]
        let _ = artifact;
        #[cfg(target_os = "linux")]
        let row = {
            let mut row = row;
            installed_state::attach(&mut row, artifact);
            row
        };
        rows.push(row);
    }
    Ok(rows)
}

fn build_info(arguments: &[String]) -> Result<i32, String> {
    if arguments != ["--json"] {
        return Err("build-info requires --json".to_owned());
    }
    let product = ProductId::parse("artifact-update").map_err(|error| error.to_string())?;
    let info = BuildInfo::from_build_values(
        product,
        env!("CARGO_PKG_VERSION"),
        option_env!("DEV_TOOLS_GIT_COMMIT"),
        option_env!("DEV_TOOLS_GIT_DIRTY"),
        option_env!("DEV_TOOLS_BUILD_TARGET"),
        option_env!("DEV_TOOLS_BUILD_PROFILE"),
        option_env!("DEV_TOOLS_BUILD_UNIX"),
    )
    .map_err(|error| error.to_string())?;
    write_json(&info)?;
    Ok(0)
}

fn catalog_command(command: &str, arguments: &[String]) -> Result<i32, String> {
    let (config, json) = parse_catalog_options(arguments)?;
    let bytes = read_bounded_config(&config)?;
    let source = std::str::from_utf8(&bytes).map_err(|_| "configuration is not UTF-8")?;
    let catalog = ArtifactCatalog::parse(source).map_err(|error| error.to_string())?;
    match (command, json) {
        ("list", true) => write_json(&serde_json::json!({
            "schema": "artifact-update-list-v1",
            "artifacts": catalog.iter().map(|(id, artifact)| serde_json::json!({
                "id": id,
                "kind": artifact.kind().as_str(),
                "source": artifact.source().provider_name(),
                "verification": verification_name(artifact.verification()),
            })).collect::<Vec<_>>(),
        }))?,
        ("list", false) => {
            for (id, artifact) in catalog.iter() {
                println!("{id}\t{}", artifact.source().provider_name());
            }
        }
        ("status", json) => {
            let rows = status_rows(&catalog, &bytes)?;
            let exit = if rows
                .iter()
                .any(|row| row["outcome"] == "authority-unavailable")
            {
                4
            } else {
                0
            };
            if json {
                write_json(&serde_json::json!({
                    "schema": "artifact-update-status-v1",
                    "network_accessed": false,
                    "artifacts": rows,
                }))?;
            } else {
                for row in rows {
                    println!(
                        "{}\t{}\tcache={}",
                        row["id"].as_str().unwrap_or(""),
                        row["outcome"].as_str().unwrap_or("unknown"),
                        row["cache_freshness"].as_str().unwrap_or("unknown")
                    );
                }
            }
            return Ok(exit);
        }
        _ => return Err("catalog operation is unsupported".to_owned()),
    }
    Ok(0)
}

fn parse_catalog_options(arguments: &[String]) -> Result<(PathBuf, bool), String> {
    let mut config = None;
    let mut json = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--config" if config.is_none() => {
                index += 1;
                config =
                    Some(PathBuf::from(arguments.get(index).ok_or_else(|| {
                        "--config requires an absolute path".to_owned()
                    })?));
            }
            "--json" if !json => json = true,
            _ => return Err("catalog operation contains an unknown or duplicate option".to_owned()),
        }
        index += 1;
    }
    let config = match config {
        Some(config) => config,
        None => default_config_path()?,
    };
    require_absolute_normal_path(&config)?;
    Ok((config, json))
}

fn default_config_path() -> Result<PathBuf, String> {
    directories::ProjectDirs::from("dev", "FutureDevGuys", "artifact-update")
        .map(|directories| directories.config_dir().join("config.toml"))
        .ok_or_else(|| "native configuration directory is unavailable".to_owned())
}

fn require_absolute_normal_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err("configuration path must be absolute and normalized".to_owned());
    }
    Ok(())
}

fn read_bounded_config(path: &Path) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix_no_follow());
    let mut file = options
        .open(path)
        .map_err(|_| "configuration is unavailable")?;
    let metadata = file
        .metadata()
        .map_err(|_| "configuration is unavailable")?;
    if !metadata.is_file() || metadata.len() > CONFIG_LIMIT {
        return Err("configuration is not a bounded regular file".to_owned());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(CONFIG_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "configuration could not be read".to_owned())?;
    if bytes.len() as u64 > CONFIG_LIMIT {
        return Err("configuration is not a bounded regular file".to_owned());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn nix_no_follow() -> i32 {
    libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
}

fn verification_name(policy: dev_tools_update::artifact::VerificationPolicy) -> &'static str {
    use dev_tools_update::artifact::VerificationPolicy;
    match policy {
        VerificationPolicy::CheckOnly => "check-only",
        VerificationPolicy::Sha256Sidecar { .. } => "sha256-sidecar",
        VerificationPolicy::SignedManifest { .. } => "signed-manifest",
    }
}

fn write_json(value: &impl serde::Serialize) -> Result<(), String> {
    serde_json::to_writer(std::io::stdout().lock(), value)
        .map_err(|_| "JSON output could not be written".to_owned())?;
    println!();
    Ok(())
}

fn usage() -> &'static str {
    "usage: artifact-update --version\n       artifact-update build-info --json\n       artifact-update completion bash|zsh|fish|elvish|powershell\n       artifact-update list [--config PATH] [--json]\n       artifact-update status [--config PATH] [--json]\n       artifact-update doctor [--config PATH] [--json]\n       artifact-update check [ID|--all] [--config PATH] [--os OS] [--architecture ARCH] [--json]\n       artifact-update install ID [--config PATH] [--json] [--offline]\n       artifact-update rollback ID [--config PATH] [--json]\n       artifact-update recover ID [--config PATH] [--json]\n       artifact-update trust initialize|status|recover ID [--config PATH] [--json]\n       artifact-update config inspect|recover [--config PATH] [--json]\n       artifact-update config apply --from PATH --expect absent|SHA256 [--config PATH] [--json]"
}
