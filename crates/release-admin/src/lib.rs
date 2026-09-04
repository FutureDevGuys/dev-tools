use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use clap::{Args, Parser, Subcommand};
use dev_tools_command::{run_prepared_bounded_command_with_public_input, HeldExecutable};
use dev_tools_installation::{write_atomic_document, ArtifactIdentity, DocumentAuthority};
use dev_tools_product::{BuildInfo, ProductId};
use dev_tools_release::{
    authorized_release_public_key, build_signed_envelope, build_unsigned_product_manifest,
    build_unsigned_root_document, root_key_id, verify_artifact_bytes, verify_release_metadata,
    verify_release_set_metadata, verify_root_bytes, ArtifactUrlPolicy, EnvelopeSignature,
    ManifestArtifact, ProductManifestSpec, ReleaseAuthority, ReleaseMetadata, RootDocumentSpec,
    RootReleaseKey,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
#[cfg(unix)]
use zeroize::Zeroizing;

const METADATA_LIMIT: u64 = 512 * 1024;
const ARTIFACT_LIMIT: u64 = 256 * 1024 * 1024;
const SIGNER_OUTPUT_LIMIT: usize = 256;

#[derive(Debug, Parser)]
#[command(
    name = "release-admin",
    version,
    about = "Native Dev Tools release administration"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print checkout-independent build identity.
    BuildInfo {
        #[arg(long)]
        json: bool,
    },
    /// Construct and rotate offline release roots.
    Root(RootArgs),
    /// Construct source-bound product manifests.
    Manifest(ManifestArgs),
    /// Build, verify, and publish complete release sets.
    Set(SetArgs),
}

#[derive(Debug, Args)]
struct RootArgs {
    #[command(subcommand)]
    command: RootCommand,
}

#[derive(Debug, Subcommand)]
enum RootCommand {
    /// Build one signed root document.
    Build(RootBuildArgs),
}

#[derive(Debug, Args)]
struct RootBuildArgs {
    #[arg(long = "root-private-key", required = true)]
    root_private_keys: Vec<PathBuf>,
    #[arg(long = "release-public-key", required = true)]
    release_public_keys: Vec<PathBuf>,
    #[arg(long = "revoked-release-public-key")]
    revoked_release_public_keys: Vec<PathBuf>,
    #[arg(long)]
    trusted_root_public_key: PathBuf,
    #[arg(long)]
    generation: u64,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct ManifestArgs {
    #[command(subcommand)]
    command: ManifestCommand,
}

#[derive(Debug, Subcommand)]
enum ManifestCommand {
    /// Build one source-bound, multi-target product manifest.
    Build(ManifestBuildArgs),
}

#[derive(Debug, Args)]
struct ManifestBuildArgs {
    #[arg(long)]
    product: String,
    #[arg(long)]
    version: String,
    #[arg(long)]
    source_commit: String,
    #[arg(long)]
    generation: u64,
    #[arg(long = "artifact", required = true)]
    artifacts: Vec<String>,
    #[arg(long)]
    root_document: PathBuf,
    #[arg(long)]
    trusted_root_public_key: PathBuf,
    #[arg(long)]
    release_key_id: String,
    #[arg(long)]
    signer: PathBuf,
    #[arg(long)]
    signer_profile: String,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct SetArgs {
    #[command(subcommand)]
    command: SetCommand,
}

#[derive(Debug, Subcommand)]
enum SetCommand {
    /// Build a deterministic release set from explicit source identity.
    Build,
    /// Verify a complete release set without network access.
    Verify(SetVerifyArgs),
    /// Publish and anonymously verify one authenticated release set.
    Publish,
}

#[derive(Debug, Args)]
struct SetVerifyArgs {
    #[arg(long)]
    product: String,
    #[arg(long)]
    source_commit: String,
    #[arg(long = "artifact", required = true)]
    artifacts: Vec<String>,
    #[arg(long)]
    root_document: PathBuf,
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    trusted_root_public_key: PathBuf,
}

pub fn main_entry<I>(arguments: I) -> i32
where
    I: IntoIterator<Item = OsString>,
{
    let mut argv = vec![OsString::from("release-admin")];
    argv.extend(arguments);
    match Cli::try_parse_from(argv) {
        Ok(Cli {
            command: Command::BuildInfo { json },
        }) => print_build_info(json),
        Ok(Cli {
            command:
                Command::Root(RootArgs {
                    command: RootCommand::Build(arguments),
                }),
        }) => run_result(build_root(arguments)),
        Ok(Cli {
            command:
                Command::Manifest(ManifestArgs {
                    command: ManifestCommand::Build(arguments),
                }),
        }) => run_result(build_manifest(arguments)),
        Ok(Cli {
            command:
                Command::Set(SetArgs {
                    command: SetCommand::Verify(arguments),
                }),
        }) => run_result(verify_release_set(arguments)),
        Ok(_) => {
            eprintln!("release-admin: requested operation is not implemented");
            2
        }
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            code
        }
    }
}

fn run_result(result: Result<()>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("release-admin: {error:#}");
            2
        }
    }
}

fn print_build_info(json: bool) -> i32 {
    let product = match ProductId::parse("release-admin") {
        Ok(product) => product,
        Err(error) => {
            eprintln!("release-admin: {error}");
            return 1;
        }
    };
    let info = match BuildInfo::from_build_values(
        product,
        env!("CARGO_PKG_VERSION"),
        option_env!("DEV_TOOLS_GIT_COMMIT"),
        option_env!("DEV_TOOLS_GIT_DIRTY"),
        option_env!("DEV_TOOLS_BUILD_TARGET"),
        option_env!("DEV_TOOLS_BUILD_PROFILE"),
        option_env!("DEV_TOOLS_BUILD_UNIX"),
    ) {
        Ok(info) => info,
        Err(error) => {
            eprintln!("release-admin: {error}");
            return 1;
        }
    };
    if json {
        if serde_json::to_writer_pretty(std::io::stdout().lock(), &info).is_err() {
            eprintln!("release-admin: build information could not be written");
            return 1;
        }
        println!();
    } else {
        println!("{} {}", info.product, info.version);
        println!("source_commit={}", info.source_commit);
        println!("source_state={:?}", info.source_state);
        println!("target={}", info.target);
        println!("profile={:?}", info.profile);
        println!("built_unix={}", info.built_unix);
    }
    0
}

fn build_root(arguments: RootBuildArgs) -> Result<()> {
    if !arguments.output.is_absolute() {
        bail!("root output must be an absolute path");
    }
    if arguments.output.exists() {
        bail!("root output already exists");
    }
    let trusted_root = read_public_key_text(&arguments.trusted_root_public_key)
        .context("read trusted root public key")?;
    let root_keys = arguments
        .root_private_keys
        .iter()
        .map(|path| read_root_private_key(path))
        .collect::<Result<Vec<_>>>()?;
    if !root_keys
        .iter()
        .any(|key| hex(key.verifying_key().as_bytes()) == trusted_root)
    {
        bail!("no root private key matches the trusted root public key");
    }
    let mut release_keys = Vec::new();
    for (paths, revoked) in [
        (&arguments.release_public_keys, false),
        (&arguments.revoked_release_public_keys, true),
    ] {
        for path in paths {
            release_keys.push(RootReleaseKey {
                public_key: read_public_key_text(path)
                    .context("read root-authorized release public key")?,
                revoked,
            });
        }
    }
    let unsigned = build_unsigned_root_document(&RootDocumentSpec {
        generation: arguments.generation,
        release_keys,
    })?;
    let signatures = root_keys
        .iter()
        .map(|key| {
            Ok(EnvelopeSignature {
                key_id: root_key_id(&hex(key.verifying_key().as_bytes()))?,
                signature: key.sign(&unsigned).to_bytes().to_vec(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let document = build_signed_envelope(&unsigned, &signatures)?;
    verify_root_bytes(&document, &trusted_root).context("verify constructed root document")?;
    write_new_private_file(&arguments.output, &document)?;
    let result = json!({
        "schema": "release-admin-root-build-v1",
        "generation": arguments.generation,
        "active_release_keys": arguments.release_public_keys.len(),
        "revoked_release_keys": arguments.revoked_release_public_keys.len(),
        "root_signatures": root_keys.len(),
        "output": arguments.output,
    });
    serde_json::to_writer(std::io::stdout().lock(), &result).context("write root build result")?;
    println!();
    Ok(())
}

fn build_manifest(arguments: ManifestBuildArgs) -> Result<()> {
    if !valid_public_id(&arguments.release_key_id) || !valid_public_id(&arguments.signer_profile) {
        bail!("signer identity is invalid");
    }
    if !arguments.output.is_absolute() {
        bail!("manifest output must be an absolute path");
    }
    if arguments.output.exists() {
        bail!("manifest output already exists");
    }
    let artifacts =
        manifest_artifacts(&arguments.product, &arguments.version, &arguments.artifacts)?;
    let trusted_root = read_bounded_file(&arguments.trusted_root_public_key, 256)
        .context("read trusted root public key")?;
    let trusted_root = std::str::from_utf8(&trusted_root)
        .context("trusted root public key is not UTF-8")?
        .trim()
        .to_owned();
    dev_tools_release::parse_release_public_key(&trusted_root)
        .context("parse trusted root public key")?;
    let root = read_bounded_file(&arguments.root_document, METADATA_LIMIT)
        .context("read root document")?;
    authorized_release_public_key(&root, &trusted_root, &arguments.release_key_id)
        .context("authenticate routine release-signing key")?;
    let unsigned = build_unsigned_product_manifest(&ProductManifestSpec {
        product: arguments.product.clone(),
        generation: arguments.generation,
        version: arguments.version.clone(),
        source_commit: arguments.source_commit.clone(),
        artifacts,
    })?;
    let signature = invoke_signer(&arguments.signer, &arguments.signer_profile, &unsigned)?;
    let manifest = build_signed_envelope(
        &unsigned,
        &[EnvelopeSignature {
            key_id: arguments.release_key_id,
            signature: signature.to_vec(),
        }],
    )
    .context("build signed product manifest")?;
    let selected_target = parse_artifact_argument(&arguments.artifacts[0])?.0;
    verify_release_metadata(
        &ReleaseMetadata {
            root,
            manifest: manifest.clone(),
        },
        &ReleaseAuthority {
            trusted_root_key: trusted_root,
            product: arguments.product.clone(),
            accepted_manifest_schemas: vec!["dev-tools-product-v2".into()],
            target: selected_target,
            artifact_url: ArtifactUrlPolicy::GitHubRelease {
                owner: "FutureDevGuys".into(),
                repository: "dev-tools".into(),
            },
            require_source_commit: true,
            engine_protocol: 1,
        },
    )
    .context("verify signed product manifest")?;
    write_new_private_file(&arguments.output, &manifest)?;
    let summary = json!({
        "schema": "release-admin-manifest-build-v1",
        "product": arguments.product,
        "version": arguments.version,
        "source_commit": arguments.source_commit,
        "targets": arguments.artifacts.len(),
        "output": arguments.output,
    });
    serde_json::to_writer(std::io::stdout().lock(), &summary)
        .context("write manifest build result")?;
    println!();
    Ok(())
}

fn verify_release_set(arguments: SetVerifyArgs) -> Result<()> {
    let trusted_root = read_bounded_file(&arguments.trusted_root_public_key, 256)
        .context("read trusted root public key")?;
    let trusted_root = std::str::from_utf8(&trusted_root)
        .context("trusted root public key is not UTF-8")?
        .trim()
        .to_owned();
    dev_tools_release::parse_release_public_key(&trusted_root)
        .context("parse trusted root public key")?;
    let root = read_bounded_file(&arguments.root_document, METADATA_LIMIT)
        .context("read root document")?;
    let manifest =
        read_bounded_file(&arguments.manifest, METADATA_LIMIT).context("read product manifest")?;
    let mut paths = BTreeMap::new();
    for value in &arguments.artifacts {
        let (target, path) = parse_artifact_argument(value)?;
        require_accepted_target(&arguments.product, &target)?;
        if !path.is_absolute() || paths.insert(target, path).is_some() {
            bail!("release artifact paths are invalid or duplicated");
        }
    }
    let selected_target = paths
        .keys()
        .next()
        .context("release set has no artifacts")?;
    let releases = verify_release_set_metadata(
        &ReleaseMetadata { root, manifest },
        &ReleaseAuthority {
            trusted_root_key: trusted_root,
            product: arguments.product.clone(),
            accepted_manifest_schemas: vec!["dev-tools-product-v2".into()],
            target: selected_target.clone(),
            artifact_url: ArtifactUrlPolicy::GitHubRelease {
                owner: "FutureDevGuys".into(),
                repository: "dev-tools".into(),
            },
            require_source_commit: true,
            engine_protocol: 1,
        },
    )
    .context("verify release-set metadata")?;
    if releases.len() != paths.len()
        || releases
            .iter()
            .any(|release| !paths.contains_key(&release.target))
    {
        bail!("release artifact inputs do not exactly match the signed target set");
    }
    for release in &releases {
        if release.source_commit.as_deref() != Some(arguments.source_commit.as_str()) {
            bail!("release manifest source commit does not match the expected source");
        }
        let path = paths
            .get(&release.target)
            .context("release artifact target is absent")?;
        let bytes = read_bounded_file(path, ARTIFACT_LIMIT).context("read release artifact")?;
        verify_artifact_bytes(release, &bytes)?;
    }
    let version = releases
        .first()
        .context("release set has no authenticated targets")?
        .version
        .to_string();
    let result = json!({
        "schema": "release-admin-set-verify-v1",
        "product": arguments.product,
        "version": version,
        "source_commit": arguments.source_commit,
        "targets": releases.len(),
        "verified": true,
    });
    serde_json::to_writer(std::io::stdout().lock(), &result)
        .context("write release-set verification result")?;
    println!();
    Ok(())
}

fn manifest_artifacts(
    product: &str,
    version: &str,
    values: &[String],
) -> Result<Vec<ManifestArtifact>> {
    let mut targets = BTreeMap::new();
    for value in values {
        let (target, path) = parse_artifact_argument(value)?;
        require_accepted_target(product, &target)?;
        if !path.is_absolute() {
            bail!("release artifact path must be absolute");
        }
        let identity = ArtifactIdentity::from_file(&path, ARTIFACT_LIMIT)
            .context("inspect release artifact")?;
        let executable_suffix = if target.starts_with("windows-") {
            ".exe"
        } else {
            ""
        };
        let artifact = ManifestArtifact {
            target: target.clone(),
            url: format!(
                "https://github.com/FutureDevGuys/dev-tools/releases/download/{product}%2Fv{version}/{product}-{version}-{target}{executable_suffix}"
            ),
            length: identity.length,
            sha256: identity.sha256,
        };
        if targets.insert(target, artifact).is_some() {
            bail!("release artifact target is duplicated");
        }
    }
    Ok(targets.into_values().collect())
}

fn parse_artifact_argument(value: &str) -> Result<(String, PathBuf)> {
    let (target, path) = value
        .split_once('=')
        .context("release artifact must use TARGET=PATH")?;
    if target.is_empty() || path.is_empty() || path.contains('\0') {
        bail!("release artifact must use TARGET=PATH");
    }
    Ok((target.to_owned(), PathBuf::from(path)))
}

fn require_accepted_target(product: &str, target: &str) -> Result<()> {
    if !matches!(
        (product, target),
        (
            "update-all" | "dev-auth" | "dev-cache" | "sync-configs" | "skills-sync",
            "linux-x86_64"
        )
    ) {
        bail!("{product} release target is not accepted: {target}");
    }
    Ok(())
}

fn invoke_signer(executable: &Path, profile: &str, payload: &[u8]) -> Result<[u8; 64]> {
    if !executable.is_absolute() {
        bail!("release signer must be an absolute executable path");
    }
    let held = HeldExecutable::open(executable).context("hold exact release signer identity")?;
    let mut command = held
        .command(executable.as_os_str())
        .context("prepare exact release signer identity")?;
    command
        .args(["sign-release-manifest", "--profile", profile])
        .env_clear();
    let output = run_prepared_bounded_command_with_public_input(
        &mut command,
        payload,
        Duration::from_secs(125),
        SIGNER_OUTPUT_LIMIT,
    )
    .map_err(|_| anyhow::anyhow!("release signer denied or failed"))?;
    if !output.status.success() || !output.stderr.is_empty() {
        bail!("release signer denied or failed");
    }
    let encoded = std::str::from_utf8(&output.stdout)
        .context("release signer response is not UTF-8")?
        .strip_suffix('\n')
        .context("release signer response is not one line")?;
    if encoded.is_empty() || encoded.contains(['\r', '\n']) {
        bail!("release signer response is not one line");
    }
    let decoded = BASE64
        .decode(encoded)
        .context("release signer response is not base64")?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("release signer response is not an Ed25519 signature"))
}

fn read_public_key_text(path: &Path) -> Result<String> {
    let bytes = read_bounded_file(path, 256)?;
    let value = std::str::from_utf8(&bytes)
        .context("public key is not UTF-8")?
        .trim();
    dev_tools_release::parse_release_public_key(value)?;
    Ok(value.to_owned())
}

#[cfg(unix)]
fn read_root_private_key(path: &Path) -> Result<SigningKey> {
    let document = dev_tools_installation::read_atomic_document(
        path,
        &DocumentAuthority {
            owner_uid: current_owner_uid(),
            mode: 0o600,
            limit: 256,
        },
    )
    .map_err(|_| {
        anyhow::anyhow!("root private key must be an owner-owned, owner-only regular file")
    })?
    .context("root private key does not exist")?;
    let bytes = Zeroizing::new(document.bytes);
    let value = std::str::from_utf8(&bytes)
        .context("root private key is not UTF-8")?
        .trim();
    let decoded = decode_32_byte_hex(value).context("root private key is invalid")?;
    Ok(SigningKey::from_bytes(&decoded))
}

#[cfg(not(unix))]
fn read_root_private_key(_path: &Path) -> Result<SigningKey> {
    bail!("offline root signing is not accepted on this platform")
}

#[cfg(unix)]
fn decode_32_byte_hex(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("key is not 32-byte lowercase hexadecimal");
    }
    let mut decoded = [0_u8; 32];
    for (index, output) in decoded.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).context("decode key")?;
    }
    Ok(decoded)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    if !path.is_absolute() || limit == 0 {
        bail!("release input path or bound is invalid");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .with_context(|| format!("open release input {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect release input {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > limit {
        bail!("release input has unsafe filesystem authority");
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        bail!("release input must have exactly one filesystem link");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read release input {}", path.display()))?;
    if bytes.len() as u64 != metadata.len() {
        bail!("release input changed while being read");
    }
    Ok(bytes)
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("release output has no parent")?;
    let parent_metadata = fs::symlink_metadata(parent).context("inspect release output parent")?;
    if !parent_metadata.file_type().is_dir() {
        bail!("release output parent is not a directory");
    }
    let written = write_atomic_document(
        path,
        bytes,
        &DocumentAuthority {
            owner_uid: current_owner_uid(),
            mode: 0o600,
            limit: METADATA_LIMIT,
        },
        None,
    )
    .with_context(|| format!("publish release output {}", path.display()))?;
    if !written {
        bail!("release output unexpectedly already exists");
    }
    Ok(())
}

#[cfg(unix)]
fn current_owner_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(not(unix))]
fn current_owner_uid() -> u32 {
    0
}

fn valid_public_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}
