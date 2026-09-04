use super::{
    construct_product_manifest, fixed_build_path, inspect_clean_checkout, one_utf8_line,
    read_bounded_file, require_accepted_target, require_canonical_directory, require_success,
    run_git, sync_directory, valid_lower_hex, valid_public_id, write_new_private_file,
    write_new_private_file_with_limit, ManifestBuildArgs, ARTIFACT_LIMIT, BUILD_OUTPUT_LIMIT,
    METADATA_LIMIT,
};
use anyhow::{bail, Context, Result};
use clap::Args;
use dev_tools_command::{run_prepared_bounded_command, HeldExecutable};
use dev_tools_release::{
    authorized_release_public_key, verify_artifact_bytes, verify_release_set_metadata,
    ArtifactUrlPolicy, ReleaseAuthority, ReleaseMetadata,
};
use semver::Version;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const PRODUCTS: [&str; 5] = [
    "update-all",
    "dev-auth",
    "dev-cache",
    "sync-configs",
    "skills-sync",
];
const BINARY_BUILD_TIMEOUT: Duration = Duration::from_secs(1_800);

#[derive(Debug, Args)]
pub(crate) struct SetBuildArgs {
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
    #[arg(long)]
    target: String,
    #[arg(long = "product")]
    products: Vec<String>,
    #[arg(long = "manifest-generation", required = true)]
    manifest_generations: Vec<String>,
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

pub(crate) fn build_release_set(arguments: SetBuildArgs) -> Result<()> {
    validate_public_inputs(&arguments)?;
    let products = selected_products(&arguments.products)?;
    for product in &products {
        require_accepted_target(product, &arguments.target)?;
    }
    require_native_target(&arguments.target)?;
    let generations = parse_manifest_generations(&arguments.manifest_generations, &products)?;
    let source_root = require_canonical_directory(&arguments.source_root, false)
        .context("validate source checkout")?;
    let cargo_home =
        require_canonical_directory(&arguments.cargo_home, true).context("validate Cargo home")?;
    let output_parent = arguments
        .output
        .parent()
        .context("release output has no parent")?;
    require_canonical_directory(output_parent, true)
        .context("validate private release output parent")?;

    let trusted_root = read_bounded_file(&arguments.trusted_root_public_key, 256)
        .context("read trusted root public key")?;
    let trusted_root_text = std::str::from_utf8(&trusted_root)
        .context("trusted root public key is not UTF-8")?
        .trim();
    dev_tools_release::parse_release_public_key(trusted_root_text)
        .context("parse trusted root public key")?;
    let root_document = read_bounded_file(&arguments.root_document, METADATA_LIMIT)
        .context("read root document")?;
    authorized_release_public_key(&root_document, trusted_root_text, &arguments.release_key_id)
        .context("authenticate routine release-signing key")?;

    let git = HeldExecutable::open(&arguments.git).context("hold exact Git identity")?;
    let cargo = HeldExecutable::open(&arguments.cargo).context("hold exact Cargo identity")?;
    inspect_clean_checkout(&git, &arguments.git, &source_root, &arguments.source_commit)?;

    let work = tempfile::Builder::new()
        .prefix(".release-admin-set-")
        .tempdir_in(output_parent)
        .context("create private release work directory")?;
    let checkout = work.path().join("source");
    clone_exact_source(
        &git,
        &arguments.git,
        &source_root,
        &arguments.source_commit,
        &checkout,
        work.path(),
    )?;
    let source_timestamp =
        source_timestamp(&git, &arguments.git, &checkout, &arguments.source_commit)?;
    let versions = product_versions(&checkout, &products)?;
    let cargo_target = work.path().join("cargo-target");
    build_products(
        &cargo,
        &arguments.cargo,
        &cargo_home,
        &checkout,
        work.path(),
        &cargo_target,
        &arguments.source_commit,
        source_timestamp,
        trusted_root_text,
        &products,
    )?;
    inspect_clean_checkout(&git, &arguments.git, &checkout, &arguments.source_commit)?;
    inspect_clean_checkout(&git, &arguments.git, &source_root, &arguments.source_commit)?;

    let staged = work.path().join("release-set");
    fs::create_dir(&staged).context("create staged release set")?;
    set_private_directory(&staged)?;
    let releases = staged.join("releases");
    fs::create_dir(&releases).context("create staged releases directory")?;
    set_private_directory(&releases)?;
    let staged_root = staged.join("dev-tools-root.json");
    let staged_trusted_root = staged.join("root-public-key.txt");
    write_new_private_file(&staged_root, &root_document)?;
    write_new_private_file(&staged_trusted_root, &trusted_root)?;

    let mut summaries = Vec::with_capacity(products.len());
    for product in &products {
        let version = versions
            .get(*product)
            .context("product version is absent")?;
        let product_dir = releases.join(product);
        fs::create_dir(&product_dir).context("create product release directory")?;
        set_private_directory(&product_dir)?;
        let artifact_source = cargo_target
            .join("release")
            .join(native_binary_name(product, &arguments.target));
        let artifact_bytes = super::read_bounded_file_with_origin(
            &artifact_source,
            ARTIFACT_LIMIT,
            super::InputOrigin::ControlledBuild,
        )
        .context("read constructed release artifact")?;
        let artifact_name = public_artifact_name(product, version, &arguments.target);
        let artifact_output = product_dir.join(&artifact_name);
        write_new_private_file_with_limit(&artifact_output, &artifact_bytes, ARTIFACT_LIMIT)?;
        set_executable_file(&artifact_output)?;
        let product_root = product_dir.join("dev-tools-root.json");
        write_new_private_file(&product_root, &root_document)?;
        let manifest_output = product_dir.join(format!("{product}-stable.json"));
        let manifest_arguments = ManifestBuildArgs {
            product: (*product).to_owned(),
            version: version.clone(),
            source_commit: arguments.source_commit.clone(),
            generation: *generations
                .get(*product)
                .context("manifest generation is absent")?,
            artifacts: vec![format!(
                "{}={}",
                arguments.target,
                artifact_output.display()
            )],
            root_document: staged_root.clone(),
            trusted_root_public_key: staged_trusted_root.clone(),
            release_key_id: arguments.release_key_id.clone(),
            signer: arguments.signer.clone(),
            signer_profile: arguments.signer_profile.clone(),
            output: manifest_output.clone(),
        };
        let manifest = construct_product_manifest(&manifest_arguments)?;
        write_new_private_file(&manifest_output, &manifest)?;
        verify_constructed_product(
            product,
            &arguments.target,
            &arguments.source_commit,
            trusted_root_text,
            &root_document,
            &manifest,
            &artifact_bytes,
        )?;
        summaries.push(json!({
            "product": product,
            "version": version,
            "generation": generations.get(*product),
            "artifact": artifact_name,
            "length": artifact_bytes.len(),
            "sha256": format!("{:x}", Sha256::digest(&artifact_bytes)),
        }));
    }

    fs::remove_file(&staged_root).context("remove private staged root copy")?;
    fs::remove_file(&staged_trusted_root).context("remove private staged trust copy")?;
    publish_new_directory(&staged, &arguments.output)?;
    sync_directory(output_parent).context("persist constructed release set")?;
    let result = json!({
        "schema": "release-admin-set-build-v1",
        "source_commit": arguments.source_commit,
        "source_date_epoch": source_timestamp,
        "target": arguments.target,
        "products": summaries,
        "output": arguments.output,
        "controlled_build": true,
    });
    serde_json::to_writer(std::io::stdout().lock(), &result)
        .context("write release-set build result")?;
    println!();
    Ok(())
}

fn validate_public_inputs(arguments: &SetBuildArgs) -> Result<()> {
    let paths = [
        &arguments.source_root,
        &arguments.git,
        &arguments.cargo,
        &arguments.cargo_home,
        &arguments.root_document,
        &arguments.trusted_root_public_key,
        &arguments.signer,
        &arguments.output,
    ];
    if !valid_lower_hex(&arguments.source_commit, 40)
        || !valid_public_id(&arguments.release_key_id)
        || !valid_public_id(&arguments.signer_profile)
        || !arguments.source_root.is_absolute()
        || !arguments.git.is_absolute()
        || !arguments.cargo.is_absolute()
        || !arguments.cargo_home.is_absolute()
        || !arguments.root_document.is_absolute()
        || !arguments.trusted_root_public_key.is_absolute()
        || !arguments.signer.is_absolute()
        || !arguments.output.is_absolute()
        || paths.iter().any(|path| path.to_str().is_none())
        || arguments.output.exists()
    {
        bail!("release-set construction input is invalid");
    }
    Ok(())
}

fn selected_products(values: &[String]) -> Result<Vec<&str>> {
    if values.is_empty() {
        return Ok(PRODUCTS.to_vec());
    }
    let mut selected = Vec::with_capacity(values.len());
    for value in values {
        let product = PRODUCTS
            .iter()
            .copied()
            .find(|candidate| *candidate == value)
            .context("release product is not accepted")?;
        if selected.contains(&product) {
            bail!("release product is duplicated");
        }
        selected.push(product);
    }
    Ok(selected)
}

fn parse_manifest_generations(
    values: &[String],
    products: &[&str],
) -> Result<BTreeMap<String, u64>> {
    if values.len() == 1 && !values[0].contains('=') {
        let generation = positive_generation(&values[0])?;
        return Ok(products
            .iter()
            .map(|product| ((*product).to_owned(), generation))
            .collect());
    }
    let mut generations = BTreeMap::new();
    for value in values {
        let (product, raw) = value
            .split_once('=')
            .context("manifest generations must name each selected product exactly once")?;
        if !products.contains(&product)
            || generations
                .insert(product.to_owned(), positive_generation(raw)?)
                .is_some()
        {
            bail!("manifest generations must name each selected product exactly once");
        }
    }
    if generations.len() != products.len() {
        bail!("manifest generations must name each selected product exactly once");
    }
    Ok(generations)
}

fn positive_generation(value: &str) -> Result<u64> {
    let generation = value
        .parse::<u64>()
        .context("manifest generation must be a positive integer")?;
    if generation == 0 {
        bail!("manifest generation must be a positive integer");
    }
    Ok(generation)
}

fn require_native_target(target: &str) -> Result<()> {
    let native = native_target().context("native release construction is not accepted here")?;
    if target != native {
        bail!("release target does not match the native accepted builder");
    }
    Ok(())
}

fn native_target() -> Option<&'static str> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Some("linux-x86_64")
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        None
    }
}

fn clone_exact_source(
    git: &HeldExecutable,
    git_path: &Path,
    source_root: &Path,
    source_commit: &str,
    checkout: &Path,
    work_root: &Path,
) -> Result<()> {
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
    inspect_clean_checkout(git, git_path, checkout, source_commit)?;
    if checkout.join(".gitmodules").exists() {
        bail!("binary release construction does not admit submodules");
    }
    Ok(())
}

fn source_timestamp(
    git: &HeldExecutable,
    git_path: &Path,
    checkout: &Path,
    source_commit: &str,
) -> Result<u64> {
    let output = run_git(
        git,
        git_path,
        &[
            OsString::from("-C"),
            checkout.as_os_str().to_owned(),
            OsString::from("show"),
            OsString::from("-s"),
            OsString::from("--format=%ct"),
            OsString::from(source_commit),
        ],
        checkout,
    )?;
    one_utf8_line(&output, "Git source timestamp")?
        .parse::<u64>()
        .context("Git source timestamp is invalid")
}

fn product_versions(checkout: &Path, products: &[&str]) -> Result<BTreeMap<String, String>> {
    let mut versions = BTreeMap::new();
    for product in products {
        let manifest = checkout.join("crates").join(product).join("Cargo.toml");
        let bytes = read_bounded_file(&manifest, METADATA_LIMIT)
            .context("read product package manifest")?;
        let text = std::str::from_utf8(&bytes).context("product package manifest is not UTF-8")?;
        let parsed = text
            .parse::<toml::Table>()
            .context("parse product package manifest")?;
        let package = parsed
            .get("package")
            .and_then(toml::Value::as_table)
            .context("product package manifest has no package table")?;
        if package.get("name").and_then(toml::Value::as_str) != Some(*product) {
            bail!("product package manifest name does not match the selected product");
        }
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .context("product package manifest has no version")?;
        let parsed_version = Version::parse(version).context("parse product version")?;
        if !parsed_version.pre.is_empty() || parsed_version.to_string() != version {
            bail!("product version is not a canonical stable semantic version");
        }
        versions.insert((*product).to_owned(), version.to_owned());
    }
    Ok(versions)
}

#[allow(clippy::too_many_arguments)]
fn build_products(
    cargo: &HeldExecutable,
    cargo_path: &Path,
    cargo_home: &Path,
    checkout: &Path,
    work_root: &Path,
    cargo_target: &Path,
    source_commit: &str,
    source_timestamp: u64,
    trusted_root: &str,
    products: &[&str],
) -> Result<()> {
    let cargo_bin = cargo_path
        .parent()
        .context("exact Cargo executable has no parent")?;
    let mut command = cargo
        .command(cargo_path.as_os_str())
        .context("prepare exact Cargo identity")?;
    command
        .env_clear()
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TERM_COLOR", "never")
        .env("CARGO_TARGET_DIR", cargo_target)
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            encoded_remap_flags(checkout, work_root, cargo_home),
        )
        .env("DEV_TOOLS_GIT_COMMIT", source_commit)
        .env("DEV_AUTH_SOURCE_COMMIT", source_commit)
        .env("DEV_TOOLS_GIT_DIRTY", "0")
        .env("DEV_TOOLS_TRUST_ROOT_PUBLIC_KEY", trusted_root)
        .env("SOURCE_DATE_EPOCH", source_timestamp.to_string())
        .env("LC_ALL", "C")
        .env("PATH", fixed_build_path(cargo_bin))
        .current_dir(checkout)
        .args([
            "build",
            "--release",
            "--locked",
            "--offline",
            "--color",
            "never",
        ]);
    for product in products {
        command.args([OsStr::new("--bin"), OsStr::new(product)]);
    }
    let output =
        run_prepared_bounded_command(&mut command, BINARY_BUILD_TIMEOUT, BUILD_OUTPUT_LIMIT)
            .map_err(|_| anyhow::anyhow!("bounded Cargo release execution failed"))?;
    require_success(output.status, "Cargo release execution failed")
}

fn encoded_remap_flags(source: &Path, work_root: &Path, cargo_home: &Path) -> OsString {
    [
        format!("--remap-path-prefix={}=/dev-tools/source", source.display()),
        format!(
            "--remap-path-prefix={}=/dev-tools/output",
            work_root.display()
        ),
        format!(
            "--remap-path-prefix={}=/dev-tools/cargo-home",
            cargo_home.display()
        ),
    ]
    .join("\u{1f}")
    .into()
}

#[cfg(target_os = "linux")]
fn publish_new_directory(staged: &Path, output: &Path) -> Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        staged,
        rustix::fs::CWD,
        output,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .context("publish constructed release set without replacement")
}

#[cfg(not(target_os = "linux"))]
fn publish_new_directory(_staged: &Path, _output: &Path) -> Result<()> {
    bail!("native release construction is not accepted here")
}

fn native_binary_name(product: &str, target: &str) -> String {
    if target.starts_with("windows-") {
        format!("{product}.exe")
    } else {
        product.to_owned()
    }
}

fn public_artifact_name(product: &str, version: &str, target: &str) -> String {
    let suffix = if target.starts_with("windows-") {
        ".exe"
    } else {
        ""
    };
    format!("{product}-{version}-{target}{suffix}")
}

fn verify_constructed_product(
    product: &str,
    target: &str,
    source_commit: &str,
    trusted_root: &str,
    root: &[u8],
    manifest: &[u8],
    artifact: &[u8],
) -> Result<()> {
    let releases = verify_release_set_metadata(
        &ReleaseMetadata {
            root: root.to_vec(),
            manifest: manifest.to_vec(),
        },
        &ReleaseAuthority {
            trusted_root_key: trusted_root.to_owned(),
            product: product.to_owned(),
            accepted_manifest_schemas: vec!["dev-tools-product-v2".into()],
            target: target.to_owned(),
            artifact_url: ArtifactUrlPolicy::GitHubRelease {
                owner: "FutureDevGuys".into(),
                repository: "dev-tools".into(),
            },
            require_source_commit: true,
            engine_protocol: 1,
        },
    )
    .context("verify constructed release metadata")?;
    if releases.len() != 1 || releases[0].source_commit.as_deref() != Some(source_commit) {
        bail!("constructed release metadata does not bind the exact source");
    }
    verify_artifact_bytes(&releases[0], artifact).context("verify constructed release artifact")
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .context("protect release directory")
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_executable_file(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .context("make release artifact executable")
}

#[cfg(not(unix))]
fn set_executable_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        encoded_remap_flags, native_binary_name, parse_manifest_generations, public_artifact_name,
        selected_products,
    };
    use std::path::Path;

    #[test]
    fn frozen_product_and_generation_grammar_is_canonical() {
        assert_eq!(
            selected_products(&[]).unwrap(),
            [
                "update-all",
                "dev-auth",
                "dev-cache",
                "sync-configs",
                "skills-sync"
            ]
        );
        let selected = ["update-all".into(), "dev-cache".into()];
        let products = selected_products(&selected).unwrap();
        assert_eq!(
            parse_manifest_generations(&["7".into()], &products).unwrap(),
            [("dev-cache".into(), 7), ("update-all".into(), 7)].into()
        );
        assert_eq!(
            parse_manifest_generations(&["update-all=7".into(), "dev-cache=11".into()], &products)
                .unwrap(),
            [("dev-cache".into(), 11), ("update-all".into(), 7)].into()
        );
        assert!(selected_products(&["update-all".into(), "update-all".into()]).is_err());
        assert!(parse_manifest_generations(&["update-all=7".into()], &products).is_err());
    }

    #[test]
    fn frozen_artifact_names_cover_native_and_windows_shapes() {
        assert_eq!(
            native_binary_name("sync-configs", "linux-x86_64"),
            "sync-configs"
        );
        assert_eq!(
            native_binary_name("sync-configs", "windows-x86_64"),
            "sync-configs.exe"
        );
        assert_eq!(
            public_artifact_name("sync-configs", "1.2.3", "linux-x86_64"),
            "sync-configs-1.2.3-linux-x86_64"
        );
        assert_eq!(
            public_artifact_name("sync-configs", "1.2.3", "windows-x86_64"),
            "sync-configs-1.2.3-windows-x86_64.exe"
        );
    }

    #[test]
    fn deterministic_environment_remaps_every_host_specific_root() {
        let flags = encoded_remap_flags(
            Path::new("/private/source"),
            Path::new("/private/output"),
            Path::new("/private/cargo"),
        );
        let flags = flags
            .to_string_lossy()
            .split('\u{1f}')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert_eq!(
            flags,
            [
                "--remap-path-prefix=/private/source=/dev-tools/source",
                "--remap-path-prefix=/private/output=/dev-tools/output",
                "--remap-path-prefix=/private/cargo=/dev-tools/cargo-home",
            ]
        );
    }
}
