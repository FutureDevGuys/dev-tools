//! Explicit whole-document editing, separate from provider and install authority.
use std::path::PathBuf;

enum Expected {
    Absent,
    Digest(String),
}

struct Options {
    operation: String,
    config: PathBuf,
    source: Option<PathBuf>,
    expected: Option<Expected>,
    json: bool,
}

pub(super) fn run(arguments: &[String]) -> Result<i32, String> {
    let options = parse_options(arguments)?;
    let row = serde_json::json!({
        "schema": "artifact-update-config-operation-v1",
        "operation": options.operation,
        "outcome": "unsupported-platform",
        "changed": false,
        "network_accessed": false,
        "sha256": null,
    });
    #[cfg(target_os = "linux")]
    let (row, code) = {
        let mut row = row;
        let code = match execute(&options, &mut row) {
            Ok(code) => code,
            Err((outcome, code)) => {
                row["outcome"] = serde_json::json!(outcome);
                code
            }
        };
        (row, code)
    };
    #[cfg(not(target_os = "linux"))]
    let code = {
        let _ = (&options.config, &options.source);
        if let Some(Expected::Digest(digest)) = &options.expected {
            let _ = digest;
        }
        3
    };
    if options.json {
        super::write_json(&row)?;
    } else {
        println!(
            "{}\t{}",
            options.operation,
            row["outcome"].as_str().unwrap_or("unknown")
        );
    }
    Ok(code)
}

fn parse_options(arguments: &[String]) -> Result<Options, String> {
    let operation = arguments
        .first()
        .filter(|operation| matches!(operation.as_str(), "inspect" | "apply" | "recover"))
        .ok_or("config requires inspect|apply|recover [--config PATH] [--json]")?;
    let mut source = None;
    let mut expected = None;
    let mut catalog_options = Vec::new();
    let mut arguments = arguments[1..].iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--from" if operation == "apply" && source.is_none() => {
                let path =
                    PathBuf::from(arguments.next().ok_or("--from requires an absolute path")?);
                super::require_absolute_normal_path(&path)?;
                source = Some(path);
            }
            "--expect" if operation == "apply" && expected.is_none() => {
                let value = arguments
                    .next()
                    .ok_or("--expect requires absent or a SHA-256 digest")?;
                expected = Some(if value == "absent" {
                    Expected::Absent
                } else if value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    Expected::Digest(value.clone())
                } else {
                    return Err("--expect requires absent or a lowercase SHA-256 digest".into());
                });
            }
            "--config" => {
                catalog_options.push(argument.clone());
                catalog_options.push(
                    arguments
                        .next()
                        .ok_or("--config requires an absolute path")?
                        .clone(),
                );
            }
            "--json" => catalog_options.push(argument.clone()),
            _ => {
                return Err(
                    "configuration operation contains an unknown or duplicate option".into(),
                )
            }
        }
    }
    if operation == "apply" && (source.is_none() || expected.is_none()) {
        return Err("config apply requires --from PATH and --expect absent|SHA256".into());
    }
    let (config, json) = super::parse_catalog_options(&catalog_options)?;
    Ok(Options {
        operation: operation.clone(),
        config,
        source,
        expected,
        json,
    })
}

#[cfg(target_os = "linux")]
fn artifact_count(bytes: &[u8]) -> Result<usize, (&'static str, i32)> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| super::ArtifactCatalog::parse(text).ok())
        .map(|catalog| catalog.iter().len())
        .ok_or(("invalid-configuration", 2))
}

#[cfg(target_os = "linux")]
fn execute(options: &Options, row: &mut serde_json::Value) -> Result<i32, (&'static str, i32)> {
    use super::private_directory::PrivateDirectory;
    use dev_tools_installation::{
        read_atomic_document, write_atomic_document, DocumentAuthority, InstallationLock,
    };
    const CUSTODY: (&str, i32) = ("authority-unavailable", 4);
    const LOCK_NAME: &str = ".artifact-update-config.lock";

    // Capture and validate all proposed bytes before creating directories,
    // locks or publication state. Preserve comments and formatting verbatim.
    let proposal = if let Some(source) = &options.source {
        let bytes = super::read_bounded_config(source).map_err(|_| ("source-unavailable", 1))?;
        let count = artifact_count(&bytes)?;
        Some((bytes, count))
    } else {
        None
    };
    let name = options
        .config
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && name.len() <= 128 && *name != LOCK_NAME)
        .ok_or(CUSTODY)?;
    let owner = rustix::process::geteuid().as_raw();
    let directory =
        PrivateDirectory::new(options.config.parent().ok_or(CUSTODY)?.to_owned(), owner)
            .map_err(|_| CUSTODY)?;
    let authority = DocumentAuthority {
        owner_uid: owner,
        mode: 0o600,
        limit: super::CONFIG_LIMIT,
    };
    let present = directory.inspect().map_err(|_| CUSTODY)?;
    if options.operation == "recover" {
        row["changed"] = serde_json::Value::Null;
        let changed = directory
            .recover_publication(name, &authority)
            .map_err(|_| ("recovery-failed", 4))?;
        row["changed"] = serde_json::json!(changed);
        row["outcome"] = serde_json::json!(if changed { "recovered" } else { "unchanged" });
        return Ok(0);
    }
    if options.operation == "inspect" {
        let current = if present {
            read_atomic_document(&options.config, &authority).map_err(|_| CUSTODY)?
        } else {
            None
        };
        let Some(current) = current else {
            row["outcome"] = serde_json::json!("absent");
            return Ok(0);
        };
        row["sha256"] = serde_json::json!(current.identity.sha256);
        row["artifact_count"] = serde_json::json!(artifact_count(&current.bytes)?);
        row["outcome"] = serde_json::json!("valid");
        return Ok(0);
    }
    let (bytes, count) = proposal.ok_or(("invalid-configuration", 2))?;
    let expected = options
        .expected
        .as_ref()
        .ok_or(("invalid-configuration", 2))?;
    if !present {
        if !matches!(expected, Expected::Absent) {
            return Err(("conflict", 3));
        }
        row["changed"] = serde_json::Value::Null;
        directory
            .publish_document(name, &bytes, &authority)
            .map_err(|_| ("publication-failed", 1))?;
        row["changed"] = serde_json::json!(true);
        row["outcome"] = serde_json::json!("initialized");
    } else {
        // One nonblocking lock serializes cooperating config writers in this
        // directory. No network, external command or nested lock runs here.
        let _lock = InstallationLock::try_acquire(&directory.path.join(LOCK_NAME))
            .map_err(|_| CUSTODY)?
            .ok_or(("busy", 3))?;
        if !directory.inspect().map_err(|_| CUSTODY)? {
            return Err(CUSTODY);
        }
        let current = read_atomic_document(&options.config, &authority).map_err(|_| CUSTODY)?;
        let matches = match (expected, &current) {
            (Expected::Absent, None) => true,
            (Expected::Digest(expected), Some(current)) => *expected == current.identity.sha256,
            _ => false,
        };
        if !matches {
            return Err(("conflict", 3));
        }
        row["changed"] = serde_json::Value::Null;
        let changed = write_atomic_document(
            &options.config,
            &bytes,
            &authority,
            current.as_ref().map(|current| &current.identity),
        )
        .map_err(|_| ("publication-failed", 1))?;
        row["changed"] = serde_json::json!(changed);
        row["outcome"] = serde_json::json!(if !changed {
            "unchanged"
        } else if current.is_none() {
            "initialized"
        } else {
            "replaced"
        });
    }
    use sha2::{Digest, Sha256};
    row["sha256"] = serde_json::json!(format!("{:x}", Sha256::digest(&bytes)));
    row["artifact_count"] = serde_json::json!(count);
    Ok(0)
}
