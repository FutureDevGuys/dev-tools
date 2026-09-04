use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use clap::{Args, Parser, Subcommand};
use dev_tools_command::{
    run_prepared_bounded_command, run_prepared_bounded_command_with_public_input, HeldExecutable,
};
use dev_tools_installation::{write_atomic_document, ArtifactIdentity, DocumentAuthority};
use dev_tools_product::{BuildInfo, ProductId};
use dev_tools_release::{
    authorized_release_public_key, build_signed_envelope, build_unsigned_crate_set,
    build_unsigned_product_manifest, build_unsigned_root_document, root_key_id,
    verify_artifact_bytes, verify_crate_package_bytes, verify_crate_set_metadata,
    verify_release_metadata, verify_release_set_metadata, verify_root_bytes, ArtifactUrlPolicy,
    CratePackageSpec, CrateSetAuthority, CrateSetMetadata, CrateSetSpec, EnvelopeSignature,
    ManifestArtifact, ProductManifestSpec, ReleaseAuthority, ReleaseMetadata, RootDocumentSpec,
    RootReleaseKey, CRATE_SET_AUTHORITY,
};
use ed25519_dalek::{Signer, SigningKey};
use flate2::read::GzDecoder;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;
#[cfg(unix)]
use zeroize::Zeroizing;

const METADATA_LIMIT: u64 = 512 * 1024;
const ARTIFACT_LIMIT: u64 = 256 * 1024 * 1024;
const SIGNER_OUTPUT_LIMIT: usize = 256;
const CRATE_PACKAGE_LIMIT: u64 = 10 * 1024 * 1024;
const CRATE_ARCHIVE_EXPANDED_LIMIT: u64 = 64 * 1024 * 1024;
const CRATE_ARCHIVE_ENTRY_LIMIT: usize = 4096;
const CRATE_METADATA_LIMIT: u64 = 512 * 1024;
const BUILD_OUTPUT_LIMIT: usize = 1024 * 1024;
const BUILD_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

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
    /// Construct and verify authenticated registry crate inventories.
    CrateSet(CrateSetArgs),
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
struct CrateSetArgs {
    #[command(subcommand)]
    command: CrateSetCommand,
}

#[derive(Debug, Subcommand)]
enum CrateSetCommand {
    /// Reproduce registry packages twice from one clean exact source commit.
    Package(CrateSetPackageArgs),
    /// Build one signed source-bound crate inventory.
    Build(CrateSetBuildArgs),
    /// Verify one signed crate inventory and every exact package byte stream.
    Verify(CrateSetVerifyArgs),
}

#[derive(Debug, Args)]
struct CrateSetPackageArgs {
    #[arg(long)]
    source_root: PathBuf,
    #[arg(long)]
    source_commit: String,
    #[arg(long)]
    git: PathBuf,
    #[arg(long)]
    cargo: PathBuf,
    #[arg(long)]
    cargo_home: PathBuf,
    #[arg(long = "package", required = true)]
    packages: Vec<String>,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct CrateSetBuildArgs {
    #[arg(long)]
    source_commit: String,
    #[arg(long)]
    generation: u64,
    #[arg(long = "package", required = true)]
    packages: Vec<String>,
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
struct CrateSetVerifyArgs {
    #[arg(long)]
    source_commit: String,
    #[arg(long = "package", required = true)]
    packages: Vec<String>,
    #[arg(long)]
    root_document: PathBuf,
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    trusted_root_public_key: PathBuf,
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
                Command::CrateSet(CrateSetArgs {
                    command: CrateSetCommand::Package(arguments),
                }),
        }) => run_result(package_crate_set(arguments)),
        Ok(Cli {
            command:
                Command::CrateSet(CrateSetArgs {
                    command: CrateSetCommand::Build(arguments),
                }),
        }) => run_result(build_crate_set(arguments)),
        Ok(Cli {
            command:
                Command::CrateSet(CrateSetArgs {
                    command: CrateSetCommand::Verify(arguments),
                }),
        }) => run_result(verify_crate_set(arguments)),
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct CratePackageRequest {
    name: String,
    version: String,
}

fn package_crate_set(arguments: CrateSetPackageArgs) -> Result<()> {
    if !valid_lower_hex(&arguments.source_commit, 40)
        || !arguments.source_root.is_absolute()
        || !arguments.git.is_absolute()
        || !arguments.cargo.is_absolute()
        || !arguments.cargo_home.is_absolute()
        || !arguments.output.is_absolute()
        || arguments.output.exists()
    {
        bail!("crate package construction input is invalid");
    }
    let source_root = require_canonical_directory(&arguments.source_root, false)
        .context("validate source checkout")?;
    let cargo_home =
        require_canonical_directory(&arguments.cargo_home, false).context("validate Cargo home")?;
    let output_parent = arguments
        .output
        .parent()
        .context("crate package output has no parent")?;
    require_canonical_directory(output_parent, true)
        .context("validate private crate package output parent")?;
    let packages = parse_crate_package_requests(&arguments.packages)?;
    let git = HeldExecutable::open(&arguments.git).context("hold exact Git identity")?;
    let cargo = HeldExecutable::open(&arguments.cargo).context("hold exact Cargo identity")?;
    inspect_clean_checkout(&git, &arguments.git, &source_root, &arguments.source_commit)?;

    let work = tempfile::Builder::new()
        .prefix(".release-admin-crates-")
        .tempdir_in(output_parent)
        .context("create private crate package work directory")?;
    let first = build_crate_package_pass(
        &git,
        &arguments.git,
        &cargo,
        &arguments.cargo,
        &cargo_home,
        &source_root,
        &arguments.source_commit,
        &packages,
        work.path(),
        "first",
    )?;
    inspect_clean_checkout(&git, &arguments.git, &source_root, &arguments.source_commit)?;
    let second = build_crate_package_pass(
        &git,
        &arguments.git,
        &cargo,
        &arguments.cargo,
        &cargo_home,
        &source_root,
        &arguments.source_commit,
        &packages,
        work.path(),
        "second",
    )?;
    inspect_clean_checkout(&git, &arguments.git, &source_root, &arguments.source_commit)?;
    if first != second {
        bail!("independent crate package builds are not byte-identical");
    }

    let staged_output = work.path().join("packages");
    fs::create_dir(&staged_output).context("create staged crate package output")?;
    #[cfg(unix)]
    fs::set_permissions(&staged_output, fs::Permissions::from_mode(0o700))
        .context("protect staged crate package output")?;
    let mut reported = Vec::with_capacity(packages.len());
    for package in &packages {
        let bytes = first
            .get(&package.name)
            .context("reproduced crate package is missing")?;
        let filename = crate_package_filename(package);
        write_new_private_file_with_limit(
            &staged_output.join(&filename),
            bytes,
            CRATE_PACKAGE_LIMIT,
        )?;
        reported.push(json!({
            "name": package.name,
            "version": package.version,
            "path": arguments.output.join(filename),
            "length": bytes.len(),
            "sha256": format!("{:x}", Sha256::digest(bytes)),
        }));
    }
    fs::rename(&staged_output, &arguments.output)
        .context("publish reproduced crate package directory")?;
    sync_directory(output_parent).context("persist reproduced crate package directory")?;
    let result = json!({
        "schema": "release-admin-crate-package-v1",
        "source_commit": arguments.source_commit,
        "registry": "crates-io",
        "packages": reported,
        "output": arguments.output,
        "reproduced": true,
    });
    serde_json::to_writer(std::io::stdout().lock(), &result)
        .context("write crate package result")?;
    println!();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_crate_package_pass(
    git: &HeldExecutable,
    git_path: &Path,
    cargo: &HeldExecutable,
    cargo_path: &Path,
    cargo_home: &Path,
    source_root: &Path,
    source_commit: &str,
    packages: &[CratePackageRequest],
    work_root: &Path,
    label: &str,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let checkout = work_root.join(format!("checkout-{label}"));
    run_git(
        git,
        git_path,
        &[
            OsString::from("clone"),
            OsString::from("--quiet"),
            OsString::from("--no-local"),
            OsString::from("--no-checkout"),
            OsString::from("--"),
            source_root.as_os_str().to_owned(),
            checkout.as_os_str().to_owned(),
        ],
        work_root,
    )
    .context("clone exact source repository")?;
    run_git(
        git,
        git_path,
        &[
            OsString::from("-C"),
            checkout.as_os_str().to_owned(),
            OsString::from("checkout"),
            OsString::from("--detach"),
            OsString::from("--quiet"),
            OsString::from(source_commit),
        ],
        work_root,
    )
    .context("check out exact source commit")?;
    inspect_clean_checkout(git, git_path, &checkout, source_commit)?;
    if checkout.join(".gitmodules").exists() {
        bail!("crate package construction does not admit submodules");
    }
    let target = work_root.join(format!("target-{label}"));
    let mut built = BTreeMap::new();
    for package in packages {
        let mut command = cargo
            .command(cargo_path.as_os_str())
            .context("prepare exact Cargo identity")?;
        let cargo_bin = cargo_path
            .parent()
            .context("exact Cargo executable has no parent")?;
        command
            .env_clear()
            .env("CARGO_HOME", cargo_home)
            .env("CARGO_NET_OFFLINE", "true")
            .env("CARGO_TERM_COLOR", "never")
            .env("LC_ALL", "C")
            .env("PATH", fixed_build_path(cargo_bin))
            .current_dir(&checkout)
            .args([
                OsString::from("package"),
                OsString::from("--manifest-path"),
                checkout.join("Cargo.toml").into_os_string(),
                OsString::from("--package"),
                OsString::from(&package.name),
                OsString::from("--frozen"),
                OsString::from("--no-verify"),
                OsString::from("--quiet"),
                OsString::from("--color"),
                OsString::from("never"),
                OsString::from("--target-dir"),
                target.as_os_str().to_owned(),
            ]);
        let output =
            run_prepared_bounded_command(&mut command, BUILD_COMMAND_TIMEOUT, BUILD_OUTPUT_LIMIT)
                .map_err(|_| anyhow::anyhow!("bounded Cargo package execution failed"))?;
        require_success(output.status, "Cargo package execution failed")?;
        let archive_path = target.join("package").join(crate_package_filename(package));
        let bytes = read_bounded_file(&archive_path, CRATE_PACKAGE_LIMIT)
            .context("read constructed crate package")?;
        validate_crate_archive_bytes(&bytes, &package.name, &package.version, source_commit)
            .context("constructed crate package identity is invalid")?;
        built.insert(package.name.clone(), bytes);
    }
    inspect_clean_checkout(git, git_path, &checkout, source_commit)?;
    Ok(built)
}

fn inspect_clean_checkout(
    git: &HeldExecutable,
    git_path: &Path,
    source_root: &Path,
    source_commit: &str,
) -> Result<()> {
    let top_level = run_git(
        git,
        git_path,
        &[
            OsString::from("-C"),
            source_root.as_os_str().to_owned(),
            OsString::from("rev-parse"),
            OsString::from("--show-toplevel"),
        ],
        source_root,
    )?;
    let top_level = one_utf8_line(&top_level, "Git source root")?;
    if Path::new(top_level) != source_root {
        bail!("source checkout root does not match the selected source");
    }
    let head = run_git(
        git,
        git_path,
        &[
            OsString::from("-C"),
            source_root.as_os_str().to_owned(),
            OsString::from("rev-parse"),
            OsString::from("--verify"),
            OsString::from("HEAD"),
        ],
        source_root,
    )?;
    if one_utf8_line(&head, "Git source commit")? != source_commit {
        bail!("source checkout does not match the selected commit");
    }
    let status = run_git(
        git,
        git_path,
        &[
            OsString::from("-C"),
            source_root.as_os_str().to_owned(),
            OsString::from("status"),
            OsString::from("--porcelain=v1"),
            OsString::from("--untracked-files=all"),
        ],
        source_root,
    )?;
    if !status.is_empty() {
        bail!("source checkout is not clean");
    }
    let tracked = run_git(
        git,
        git_path,
        &[
            OsString::from("-C"),
            source_root.as_os_str().to_owned(),
            OsString::from("ls-files"),
            OsString::from("--stage"),
            OsString::from("-z"),
        ],
        source_root,
    )?;
    validate_regular_tracked_entries(&tracked)?;
    Ok(())
}

fn validate_regular_tracked_entries(input: &[u8]) -> Result<()> {
    for record in input
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        if !(record.starts_with(b"100644 ") || record.starts_with(b"100755 ")) {
            bail!("source checkout contains a non-regular tracked entry");
        }
    }
    Ok(())
}

fn run_git(
    git: &HeldExecutable,
    git_path: &Path,
    arguments: &[OsString],
    cwd: &Path,
) -> Result<Vec<u8>> {
    let mut command = git
        .command(git_path.as_os_str())
        .context("prepare exact Git identity")?;
    command
        .env_clear()
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .current_dir(cwd)
        .args(arguments);
    let output =
        run_prepared_bounded_command(&mut command, BUILD_COMMAND_TIMEOUT, BUILD_OUTPUT_LIMIT)
            .map_err(|_| anyhow::anyhow!("bounded Git execution failed"))?;
    require_success(output.status, "Git execution failed")?;
    Ok(output.stdout)
}

fn require_success(status: ExitStatus, diagnostic: &str) -> Result<()> {
    if !status.success() {
        bail!("{diagnostic}");
    }
    Ok(())
}

fn one_utf8_line<'a>(bytes: &'a [u8], label: &str) -> Result<&'a str> {
    let value = std::str::from_utf8(bytes).with_context(|| format!("{label} is not UTF-8"))?;
    let value = value
        .strip_suffix('\n')
        .with_context(|| format!("{label} is not one line"))?;
    if value.is_empty() || value.contains(['\r', '\n']) {
        bail!("{label} is not one line");
    }
    Ok(value)
}

fn parse_crate_package_requests(values: &[String]) -> Result<Vec<CratePackageRequest>> {
    let mut packages = BTreeMap::new();
    for value in values {
        let (name, version) = value
            .split_once('@')
            .context("crate package must use NAME@VERSION")?;
        if !valid_crate_name(name)
            || version.is_empty()
            || version.contains('@')
            || semver::Version::parse(version).is_err()
        {
            bail!("crate package must use a valid NAME@VERSION");
        }
        let parsed = semver::Version::parse(version).context("parse crate package version")?;
        if !parsed.pre.is_empty() || parsed.to_string() != version {
            bail!("crate package version is not a canonical stable semantic version");
        }
        if packages
            .insert(
                name.to_owned(),
                CratePackageRequest {
                    name: name.to_owned(),
                    version: version.to_owned(),
                },
            )
            .is_some()
        {
            bail!("crate package request is duplicated");
        }
    }
    Ok(packages.into_values().collect())
}

fn valid_crate_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn crate_package_filename(package: &CratePackageRequest) -> String {
    format!("{}-{}.crate", package.name, package.version)
}

fn fixed_build_path(cargo_bin: &Path) -> OsString {
    let mut value = cargo_bin.as_os_str().to_owned();
    value.push(":/usr/bin:/bin");
    value
}

fn require_canonical_directory(path: &Path, private: bool) -> Result<PathBuf> {
    #[cfg(not(unix))]
    let _ = private;
    let metadata = fs::symlink_metadata(path).context("inspect directory")?;
    if !metadata.file_type().is_dir()
        || fs::canonicalize(path).context("canonicalize directory")? != path
    {
        bail!("directory is not an exact canonical directory");
    }
    #[cfg(unix)]
    if metadata.uid() != current_owner_uid() || (private && metadata.mode() & 0o077 != 0) {
        bail!("directory has unsafe filesystem authority");
    }
    Ok(path.to_owned())
}

fn sync_directory(path: &Path) -> Result<()> {
    let directory = fs::File::open(path).context("open release output parent")?;
    directory.sync_all().context("sync release output parent")
}

fn build_crate_set(arguments: CrateSetBuildArgs) -> Result<()> {
    if !valid_public_id(&arguments.release_key_id)
        || !valid_public_id(&arguments.signer_profile)
        || !arguments.output.is_absolute()
    {
        bail!("crate-set output or signer identity is invalid");
    }
    if arguments.output.exists() {
        bail!("crate-set output already exists");
    }
    let trusted_root = read_public_key_text(&arguments.trusted_root_public_key)
        .context("read trusted root public key")?;
    let root = read_bounded_file(&arguments.root_document, METADATA_LIMIT)
        .context("read root document")?;
    authorized_release_public_key(&root, &trusted_root, &arguments.release_key_id)
        .context("authenticate routine release-signing key")?;
    let packages = crate_package_specs(&arguments.packages, &arguments.source_commit)?;
    let unsigned = build_unsigned_crate_set(&CrateSetSpec {
        generation: arguments.generation,
        source_commit: arguments.source_commit.clone(),
        registry: "crates-io".into(),
        packages,
    })?;
    let signature = invoke_signer(&arguments.signer, &arguments.signer_profile, &unsigned)?;
    let manifest = build_signed_envelope(
        &unsigned,
        &[EnvelopeSignature {
            key_id: arguments.release_key_id,
            signature: signature.to_vec(),
        }],
    )?;
    let verified = verify_crate_set_metadata(
        &CrateSetMetadata {
            root,
            manifest: manifest.clone(),
        },
        &CrateSetAuthority {
            trusted_root_key: trusted_root,
            registry: "crates-io".into(),
            source_commit: arguments.source_commit.clone(),
        },
    )?;
    verify_crate_package_inputs(&verified, &arguments.packages)?;
    write_new_private_file(&arguments.output, &manifest)?;
    let result = json!({
        "schema": "release-admin-crate-set-build-v1",
        "authority": CRATE_SET_AUTHORITY,
        "source_commit": arguments.source_commit,
        "registry": "crates-io",
        "packages": verified.packages.len(),
        "output": arguments.output,
    });
    serde_json::to_writer(std::io::stdout().lock(), &result)
        .context("write crate-set build result")?;
    println!();
    Ok(())
}

fn verify_crate_set(arguments: CrateSetVerifyArgs) -> Result<()> {
    let trusted_root = read_public_key_text(&arguments.trusted_root_public_key)
        .context("read trusted root public key")?;
    let metadata = CrateSetMetadata {
        root: read_bounded_file(&arguments.root_document, METADATA_LIMIT)
            .context("read root document")?,
        manifest: read_bounded_file(&arguments.manifest, METADATA_LIMIT)
            .context("read crate-set manifest")?,
    };
    let verified = verify_crate_set_metadata(
        &metadata,
        &CrateSetAuthority {
            trusted_root_key: trusted_root,
            registry: "crates-io".into(),
            source_commit: arguments.source_commit.clone(),
        },
    )?;
    verify_crate_package_inputs(&verified, &arguments.packages)?;
    let result = json!({
        "schema": "release-admin-crate-set-verify-v1",
        "authority": CRATE_SET_AUTHORITY,
        "source_commit": arguments.source_commit,
        "registry": "crates-io",
        "packages": verified.packages.len(),
        "verified": true,
    });
    serde_json::to_writer(std::io::stdout().lock(), &result)
        .context("write crate-set verification result")?;
    println!();
    Ok(())
}

fn crate_package_specs(values: &[String], source_commit: &str) -> Result<Vec<CratePackageSpec>> {
    values
        .iter()
        .map(|value| {
            let (name, version, path) = parse_crate_package_argument(value)?;
            let bytes =
                read_bounded_file(&path, CRATE_PACKAGE_LIMIT).context("read crate package")?;
            validate_crate_archive_bytes(&bytes, &name, &version, source_commit)
                .context("crate archive package identity is invalid")?;
            Ok(CratePackageSpec {
                name,
                version,
                length: bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(&bytes)),
            })
        })
        .collect()
}

fn verify_crate_package_inputs(
    verified: &dev_tools_release::VerifiedCrateSet,
    values: &[String],
) -> Result<()> {
    let mut supplied = BTreeMap::new();
    for value in values {
        let (name, version, path) = parse_crate_package_argument(value)?;
        if supplied.insert(name.clone(), ()).is_some() {
            bail!("crate package input is duplicated");
        }
        let bytes = read_bounded_file(&path, CRATE_PACKAGE_LIMIT).context("read crate package")?;
        validate_crate_archive_bytes(&bytes, &name, &version, &verified.source_commit)
            .context("crate archive package identity is invalid")?;
        verify_crate_package_bytes(verified, &name, &version, &bytes)?;
    }
    if supplied.len() != verified.packages.len()
        || verified
            .packages
            .keys()
            .any(|name| !supplied.contains_key(name))
    {
        bail!("crate package inputs do not exactly match the authenticated set");
    }
    Ok(())
}

fn parse_crate_package_argument(value: &str) -> Result<(String, String, PathBuf)> {
    let (identity, path) = value
        .split_once('=')
        .context("crate package must use NAME@VERSION=PATH")?;
    let (name, version) = identity
        .split_once('@')
        .context("crate package must use NAME@VERSION=PATH")?;
    let path = PathBuf::from(path);
    if name.is_empty()
        || version.is_empty()
        || !path.is_absolute()
        || path.extension().and_then(|part| part.to_str()) != Some("crate")
    {
        bail!("crate package must use NAME@VERSION=/absolute/PACKAGE.crate");
    }
    Ok((name.into(), version.into(), path))
}

fn validate_crate_archive_bytes(
    bytes: &[u8],
    expected_name: &str,
    expected_version: &str,
    expected_source_commit: &str,
) -> Result<()> {
    let root = format!("{expected_name}-{expected_version}");
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let bounded_decoder = decoder.take(CRATE_ARCHIVE_EXPANDED_LIMIT + 1);
    let mut archive = tar::Archive::new(bounded_decoder);
    let mut cargo_manifest = None;
    let mut vcs_info = None;
    let mut entry_count = 0_usize;
    let mut declared_size = 0_u64;
    for entry in archive.entries().context("read crate archive entries")? {
        let mut entry = entry.context("read crate archive entry")?;
        entry_count = entry_count
            .checked_add(1)
            .context("crate archive entry count overflow")?;
        if entry_count > CRATE_ARCHIVE_ENTRY_LIMIT || !entry.header().entry_type().is_file() {
            bail!("crate archive contains an unsupported entry");
        }
        declared_size = declared_size
            .checked_add(entry.size())
            .context("crate archive expanded size overflow")?;
        if declared_size > CRATE_ARCHIVE_EXPANDED_LIMIT {
            bail!("crate archive exceeds its expanded size limit");
        }
        let path = entry.path().context("read crate archive entry path")?;
        let mut components = path.components();
        if !matches!(components.next(), Some(Component::Normal(part)) if part == root.as_str())
            || !components
                .clone()
                .all(|part| matches!(part, Component::Normal(_)))
        {
            bail!("crate archive entry escapes its package root");
        }
        let destination = match components.as_path().to_str() {
            Some("Cargo.toml") => &mut cargo_manifest,
            Some(".cargo_vcs_info.json") => &mut vcs_info,
            _ => continue,
        };
        if destination.is_some() {
            bail!("crate archive metadata entry is duplicated");
        }
        let mut value = Vec::new();
        Read::by_ref(&mut entry)
            .take(CRATE_METADATA_LIMIT + 1)
            .read_to_end(&mut value)
            .context("read crate archive metadata")?;
        if value.len() as u64 > CRATE_METADATA_LIMIT {
            bail!("crate archive metadata exceeds its size limit");
        }
        *destination = Some(value);
    }
    let mut bounded_decoder = archive.into_inner();
    std::io::copy(&mut bounded_decoder, &mut std::io::sink())
        .context("finish crate archive stream")?;
    if bounded_decoder.limit() == 0
        || bounded_decoder.into_inner().into_inner().position() != bytes.len() as u64
    {
        bail!("crate archive has trailing or excessive compressed data");
    }
    let manifest = cargo_manifest.context("crate archive has no normalized Cargo.toml")?;
    let manifest = std::str::from_utf8(&manifest).context("crate Cargo.toml is not UTF-8")?;
    let manifest: toml::Value = toml::from_str(manifest).context("parse crate Cargo.toml")?;
    let package = manifest
        .get("package")
        .and_then(toml::Value::as_table)
        .context("crate Cargo.toml has no package table")?;
    if package.get("name").and_then(toml::Value::as_str) != Some(expected_name)
        || package.get("version").and_then(toml::Value::as_str) != Some(expected_version)
    {
        bail!("crate archive package identity does not match its signed label");
    }
    let vcs: serde_json::Value =
        serde_json::from_slice(&vcs_info.context("crate archive has no Cargo VCS identity")?)
            .context("parse crate Cargo VCS identity")?;
    let git = vcs
        .get("git")
        .and_then(serde_json::Value::as_object)
        .context("crate Cargo VCS identity has no Git record")?;
    if git.get("sha1").and_then(serde_json::Value::as_str) != Some(expected_source_commit)
        || git
            .get("dirty")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    {
        bail!("crate archive source commit does not match its signed source");
    }
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
    write_new_private_file_with_limit(path, bytes, METADATA_LIMIT)
}

fn write_new_private_file_with_limit(path: &Path, bytes: &[u8], limit: u64) -> Result<()> {
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
            limit,
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
