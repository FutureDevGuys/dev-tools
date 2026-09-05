use dev_tools_product::{BuildInfo, ProductId};
use dev_tools_update::artifact::ArtifactCatalog;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const CONFIG_LIMIT: u64 = 1024 * 1024;

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
        "list" => catalog_command("list", &arguments[1..]),
        "status" => catalog_command("status", &arguments[1..]),
        "doctor" => catalog_command("doctor", &arguments[1..]),
        _ => Err(usage().to_owned()),
    }
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
        ("status", true) => write_json(&serde_json::json!({
            "schema": "artifact-update-status-v1",
            "network_accessed": false,
            "artifacts": catalog.iter().map(|(id, _)| serde_json::json!({
                "id": id,
                "outcome": "unknown",
                "cache_freshness": "absent",
            })).collect::<Vec<_>>(),
        }))?,
        ("status", false) => {
            for (id, _) in catalog.iter() {
                println!("{id}\tunknown\tcache=absent");
            }
        }
        ("doctor", true) => write_json(&serde_json::json!({
            "schema": "artifact-update-doctor-v1",
            "healthy": true,
            "network_accessed": false,
            "artifact_count": catalog.iter().len(),
        }))?,
        ("doctor", false) => println!("configuration=valid artifacts={}", catalog.iter().len()),
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
    "usage: artifact-update --version\n       artifact-update build-info --json\n       artifact-update list [--config PATH] [--json]\n       artifact-update status [--config PATH] [--json]\n       artifact-update doctor [--config PATH] [--json]"
}
