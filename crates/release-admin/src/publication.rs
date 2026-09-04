#[cfg(target_os = "linux")]
use super::{
    read_bounded_file, require_accepted_target, valid_lower_hex, ARTIFACT_LIMIT,
    BUILD_OUTPUT_LIMIT, METADATA_LIMIT,
};
#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{bail, Result};
#[cfg(target_os = "linux")]
use base64::engine::general_purpose::STANDARD as BASE64;
#[cfg(target_os = "linux")]
use base64::Engine as _;
use clap::{Args, ValueEnum};
#[cfg(target_os = "linux")]
use dev_tools_command::{run_prepared_bounded_command, HeldExecutable};
#[cfg(target_os = "linux")]
use dev_tools_release::{
    fetch_https, verify_artifact_bytes, verify_release_set_metadata, ArtifactUrlPolicy,
    HttpsPolicy, ReleaseAuthority, ReleaseMetadata,
};
#[cfg(target_os = "linux")]
use serde::Deserialize;
#[cfg(target_os = "linux")]
use serde_json::{json, Value};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "linux")]
use std::ffi::{OsStr, OsString};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
const COMMAND_TIMEOUT: Duration = Duration::from_secs(125);
#[cfg(target_os = "linux")]
const MAX_PRODUCTS: usize = 16;
const REPOSITORY: &str = "FutureDevGuys/dev-tools";

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PublishFormat {
    Human,
    Json,
}

#[derive(Debug, Args)]
pub(crate) struct SetPublishArgs {
    #[arg(long)]
    source_root: PathBuf,
    #[arg(long)]
    release_root: PathBuf,
    #[arg(long)]
    trusted_root_public_key: PathBuf,
    #[arg(long)]
    source_commit: String,
    #[arg(long, default_value = REPOSITORY)]
    repository: String,
    #[arg(long)]
    git_command: PathBuf,
    #[arg(long)]
    gh_command: PathBuf,
    #[arg(long)]
    dev_auth_command: PathBuf,
    #[arg(long)]
    git_signing_public_key: String,
    #[arg(long, default_value = "origin")]
    remote: String,
    #[arg(long, value_enum, default_value_t = PublishFormat::Human)]
    format: PublishFormat,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct Asset {
    path: PathBuf,
    url: String,
    length: u64,
    sha256: String,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ProductRelease {
    product: String,
    version: String,
    tag: String,
    title: String,
    assets: Vec<Asset>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize)]
struct ManifestEnvelopeHint {
    signed: ManifestHint,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize)]
struct ManifestHint {
    schema: String,
    product: String,
    artifacts: BTreeMap<String, Value>,
}

#[cfg(target_os = "linux")]
struct CommandOutput {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[cfg(target_os = "linux")]
trait PublicationCommands {
    fn admission(&mut self, arguments: &[OsString]) -> Result<CommandOutput>;
    fn git(&mut self, arguments: &[OsString]) -> Result<CommandOutput>;
    fn gh(&mut self, arguments: &[OsString]) -> Result<CommandOutput>;
    fn anonymous_get(&mut self, url: &str, limit: u64) -> Result<Vec<u8>>;
}

#[cfg(target_os = "linux")]
struct ExactCommand {
    launcher: PathBuf,
    held: HeldExecutable,
}

#[cfg(target_os = "linux")]
struct ExactPublicationCommands {
    source_root: PathBuf,
    admission: ExactCommand,
    git: ExactCommand,
    gh: ExactCommand,
}

pub(crate) fn publish_release_set(arguments: SetPublishArgs) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = arguments;
        bail!("release publication is not accepted on this platform")
    }
    #[cfg(target_os = "linux")]
    {
        if arguments.repository != REPOSITORY
            || arguments.remote != "origin"
            || !valid_lower_hex(&arguments.source_commit, 40)
        {
            bail!("release publication authority is invalid");
        }
        let source_root = canonical_directory(&arguments.source_root, "source checkout")?;
        let release_root = canonical_directory(&arguments.release_root, "release root")?;
        let signing_key = ssh_key_identity(&arguments.git_signing_public_key)
            .context("validate expected Git signing identity")?;
        let trusted_root = super::read_public_key_text(&arguments.trusted_root_public_key)
            .context("read trusted root public key")?;
        let releases = load_release_set(&release_root, &trusted_root, &arguments.source_commit)?;
        let mut commands = ExactPublicationCommands {
            source_root: source_root.clone(),
            admission: ExactCommand::open(&arguments.dev_auth_command, "dev-auth")?,
            git: ExactCommand::open(&arguments.git_command, "git")?,
            gh: ExactCommand::open(&arguments.gh_command, "gh")?,
        };
        ensure_admitted(&mut commands)?;
        ensure_source(
            &mut commands,
            &arguments.source_commit,
            &arguments.remote,
            &arguments.repository,
        )?;
        let mut changed = false;
        let mut reports = Vec::with_capacity(releases.len());
        for release in &releases {
            changed |= publish_one(
                &mut commands,
                &arguments.remote,
                &arguments.repository,
                release,
                &arguments.source_commit,
                &signing_key,
            )?;
            reports.push(json!({
                "product": release.product,
                "version": release.version,
                "tag": release.tag,
                "source_bound": true,
            }));
        }
        write_result(
            arguments.format,
            &arguments.source_commit,
            &arguments.repository,
            changed,
            &reports,
        )
    }
}

#[cfg(target_os = "linux")]
impl ExactCommand {
    fn open(path: &Path, expected_name: &str) -> Result<Self> {
        if !path.is_absolute() || path.file_name() != Some(OsStr::new(expected_name)) {
            bail!("{expected_name} command must be an absolute same-name launcher");
        }
        let launcher = fs::symlink_metadata(path)
            .with_context(|| format!("inspect {expected_name} command launcher"))?;
        if (!launcher.file_type().is_file() && !launcher.file_type().is_symlink())
            || launcher.uid() != 0
        {
            bail!("{expected_name} command launcher has unsafe authority");
        }
        require_root_owned_ancestors(path, expected_name)?;
        let executable = fs::canonicalize(path)
            .with_context(|| format!("resolve {expected_name} command target"))?;
        let target = fs::metadata(&executable)
            .with_context(|| format!("inspect {expected_name} command target"))?;
        if !target.file_type().is_file()
            || target.uid() != 0
            || target.mode() & 0o022 != 0
            || target.mode() & 0o111 == 0
        {
            bail!("{expected_name} command target has unsafe authority");
        }
        require_root_owned_ancestors(&executable, expected_name)?;
        let held = HeldExecutable::open(&executable)
            .with_context(|| format!("hold exact {expected_name} command identity"))?;
        Ok(Self {
            launcher: path.to_owned(),
            held,
        })
    }

    fn run(&self, cwd: &Path, arguments: &[OsString]) -> Result<CommandOutput> {
        let mut command = self
            .held
            .command(self.launcher.as_os_str())
            .context("prepare exact release command identity")?;
        apply_publication_environment(&mut command);
        command.current_dir(cwd).args(arguments);
        let output =
            run_prepared_bounded_command(&mut command, COMMAND_TIMEOUT, BUILD_OUTPUT_LIMIT)
                .map_err(|_| anyhow::anyhow!("bounded release command failed"))?;
        Ok(CommandOutput {
            code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

#[cfg(target_os = "linux")]
fn apply_publication_environment(command: &mut std::process::Command) {
    command.env_clear();
    // Strong admission is authenticated from the retained kernel boundary.
    // Dev Auth reconstructs every scoped child value, including Git/GitHub
    // credentials, signing helpers, PATH, HOME, and temporary state.
}

#[cfg(target_os = "linux")]
impl PublicationCommands for ExactPublicationCommands {
    fn admission(&mut self, arguments: &[OsString]) -> Result<CommandOutput> {
        self.admission.run(&self.source_root, arguments)
    }

    fn git(&mut self, arguments: &[OsString]) -> Result<CommandOutput> {
        self.git.run(&self.source_root, arguments)
    }

    fn gh(&mut self, arguments: &[OsString]) -> Result<CommandOutput> {
        self.gh.run(&self.source_root, arguments)
    }

    fn anonymous_get(&mut self, url: &str, limit: u64) -> Result<Vec<u8>> {
        let policy = HttpsPolicy {
            allowed_hosts: BTreeSet::from([
                "github.com".into(),
                "objects.githubusercontent.com".into(),
                "github-releases.githubusercontent.com".into(),
                "release-assets.githubusercontent.com".into(),
            ]),
            max_redirects: 3,
            timeout: Duration::from_secs(30),
            user_agent: "release-admin/0.1".into(),
        };
        Ok(fetch_https(url, &policy, limit, None)?.bytes)
    }
}

#[cfg(target_os = "linux")]
fn require_root_owned_ancestors(path: &Path, label: &str) -> Result<()> {
    for ancestor in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(ancestor)
            .with_context(|| format!("inspect {label} command path authority"))?;
        if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!("{label} command path has unsafe authority");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_absolute()
        || !fs::symlink_metadata(path)
            .with_context(|| format!("inspect {label}"))?
            .file_type()
            .is_dir()
        || fs::canonicalize(path).with_context(|| format!("canonicalize {label}"))? != path
    {
        bail!("{label} must be an exact canonical directory");
    }
    Ok(path.to_owned())
}

#[cfg(target_os = "linux")]
fn load_release_set(
    release_root: &Path,
    trusted_root: &str,
    source_commit: &str,
) -> Result<Vec<ProductRelease>> {
    let mut directories = fs::read_dir(release_root)
        .context("read release root")?
        .collect::<std::io::Result<Vec<_>>>()?;
    directories.sort_by_key(fs::DirEntry::file_name);
    if directories.is_empty() || directories.len() > MAX_PRODUCTS {
        bail!("release root must contain between one and sixteen products");
    }
    if directories
        .iter()
        .any(|entry| !entry.file_type().is_ok_and(|kind| kind.is_dir()))
    {
        bail!("release root contains an unexpected non-directory entry");
    }
    let mut releases = Vec::with_capacity(directories.len());
    let mut tags = BTreeSet::new();
    for entry in directories {
        let release = load_product_release(&entry.path(), trusted_root, source_commit)?;
        if !tags.insert(release.tag.clone()) {
            bail!("release set contains a duplicate tag");
        }
        releases.push(release);
    }
    Ok(releases)
}

#[cfg(target_os = "linux")]
fn load_product_release(
    directory: &Path,
    trusted_root: &str,
    source_commit: &str,
) -> Result<ProductRelease> {
    let product = directory
        .file_name()
        .and_then(OsStr::to_str)
        .context("release product directory name is invalid")?;
    if !valid_product(product) {
        bail!("release product directory name is invalid");
    }
    let root_path = directory.join("dev-tools-root.json");
    let manifest_path = directory.join(format!("{product}-stable.json"));
    let root = read_bounded_file(&root_path, METADATA_LIMIT).context("read root document")?;
    let manifest =
        read_bounded_file(&manifest_path, METADATA_LIMIT).context("read product manifest")?;
    let hint: ManifestEnvelopeHint =
        serde_json::from_slice(&manifest).context("inspect product manifest routing")?;
    if hint.signed.schema != "dev-tools-product-v2"
        || hint.signed.product != product
        || hint.signed.artifacts.len() != 1
    {
        bail!("product manifest has an unsupported publication contract");
    }
    let target = hint
        .signed
        .artifacts
        .keys()
        .next()
        .context("product manifest has no target")?;
    require_accepted_target(product, target)?;
    let verified = verify_release_set_metadata(
        &ReleaseMetadata {
            root: root.clone(),
            manifest: manifest.clone(),
        },
        &ReleaseAuthority {
            trusted_root_key: trusted_root.to_owned(),
            product: product.to_owned(),
            accepted_manifest_schemas: vec!["dev-tools-product-v2".into()],
            target: target.clone(),
            artifact_url: ArtifactUrlPolicy::GitHubRelease {
                owner: "FutureDevGuys".into(),
                repository: "dev-tools".into(),
            },
            require_source_commit: true,
            engine_protocol: 1,
        },
    )
    .context("authenticate product release")?;
    if verified.len() != 1 {
        bail!("product manifest must contain exactly one target artifact");
    }
    let verified = &verified[0];
    if verified.source_commit.as_deref() != Some(source_commit) {
        bail!("product manifest source commit does not match publication source");
    }
    let executable_suffix = if verified.target.starts_with("windows-") {
        ".exe"
    } else {
        ""
    };
    let artifact_path = directory.join(format!(
        "{}-{}-{}{}",
        verified.product, verified.version, verified.target, executable_suffix
    ));
    let artifact =
        read_bounded_file(&artifact_path, ARTIFACT_LIMIT).context("read release artifact")?;
    verify_artifact_bytes(verified, &artifact).context("authenticate release artifact")?;
    let artifact_name = artifact_path
        .file_name()
        .and_then(OsStr::to_str)
        .context("release artifact name is invalid")?;
    let (release_url, published_artifact_name) = verified
        .artifact_url
        .rsplit_once('/')
        .context("release artifact URL is invalid")?;
    if published_artifact_name != artifact_name {
        bail!("release artifact URL does not match its authenticated file name");
    }
    let expected = BTreeSet::from([
        root_path
            .file_name()
            .context("root document has no file name")?
            .to_os_string(),
        manifest_path
            .file_name()
            .context("manifest has no file name")?
            .to_os_string(),
        artifact_path
            .file_name()
            .context("artifact has no file name")?
            .to_os_string(),
    ]);
    let actual = fs::read_dir(directory)
        .context("read product release directory")?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<BTreeSet<_>>>()?;
    if actual != expected {
        bail!("release product directory contains unexpected files");
    }
    let assets = [
        (artifact_path, verified.artifact_url.clone(), artifact),
        (
            manifest_path,
            format!("{release_url}/{product}-stable.json"),
            manifest,
        ),
        (
            root_path,
            format!("{release_url}/dev-tools-root.json"),
            root,
        ),
    ]
    .into_iter()
    .map(|(path, url, bytes)| Asset {
        path,
        url,
        length: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
    })
    .collect();
    let version = verified.version.to_string();
    Ok(ProductRelease {
        product: product.to_owned(),
        tag: format!("{product}/v{version}"),
        title: format!("{product} v{version}"),
        version,
        assets,
    })
}

#[cfg(target_os = "linux")]
fn ensure_admitted(commands: &mut impl PublicationCommands) -> Result<()> {
    let output = require_success(
        commands.admission(&os_args(["status", "--broker"]))?,
        "verify release workload admission",
    )?;
    let report: Value =
        serde_json::from_slice(&output.stdout).context("parse release workload admission")?;
    if report.get("schema") != Some(&Value::String("dev-auth-broker-status-v2".into()))
        || report.get("mode") != Some(&Value::String("strong".into()))
        || report.get("authenticated_release") != Some(&Value::Bool(true))
        || report.get("session_state") != Some(&Value::String("present".into()))
        || report.get("broker_state") != Some(&Value::String("verified".into()))
        || report.get("degraded_same_user_boundary") != Some(&Value::Bool(false))
    {
        bail!("release publication requires a verified strong workload admission");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_source(
    commands: &mut impl PublicationCommands,
    source_commit: &str,
    remote: &str,
    repository: &str,
) -> Result<()> {
    require_success(
        commands.git(&os_args([
            "status",
            "--porcelain",
            "--untracked-files=normal",
        ]))?,
        "inspect publication source",
    )
    .and_then(|output| {
        if output.stdout.is_empty() {
            Ok(())
        } else {
            bail!("release publication requires a clean checkout")
        }
    })?;
    require_success(
        commands.git(&os_args([
            "cat-file",
            "-e",
            &format!("{source_commit}^{{commit}}"),
        ]))?,
        "verify publication source commit",
    )?;
    for arguments in [
        os_args(["remote", "get-url", remote]),
        os_args(["remote", "get-url", "--push", remote]),
    ] {
        let output = require_success(commands.git(&arguments)?, "verify publication Git remote")?;
        let url = one_line(&output.stdout, "publication Git remote")?;
        if !valid_repository_url(url, repository) {
            bail!("publication Git remote does not match the GitHub repository");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn publish_one(
    commands: &mut impl PublicationCommands,
    remote: &str,
    repository: &str,
    release: &ProductRelease,
    source_commit: &str,
    signing_key: &(String, String),
) -> Result<bool> {
    let mut changed = ensure_signed_tag(commands, remote, release, source_commit, signing_key)?;
    if release_view(commands, repository, &release.tag)?.is_none() {
        for asset in &release.assets {
            if file_identity(&asset.path, ARTIFACT_LIMIT)? != (asset.length, asset.sha256.clone()) {
                bail!("release asset changed before publication");
            }
        }
        let notes = format!(
            "Authenticated {} release from source `{source_commit}`.",
            release.title
        );
        let mut create = os_args([
            "release",
            "create",
            &release.tag,
            "--repo",
            repository,
            "--verify-tag",
            "--title",
            &release.title,
            "--notes",
            &notes,
        ]);
        create.extend(
            release
                .assets
                .iter()
                .map(|asset| asset.path.clone().into_os_string()),
        );
        let _ = commands.gh(&create)?;
        changed = true;
    }
    verify_published_release(commands, repository, release)?;
    Ok(changed)
}

#[cfg(target_os = "linux")]
fn ensure_signed_tag(
    commands: &mut impl PublicationCommands,
    remote: &str,
    release: &ProductRelease,
    source_commit: &str,
    signing_key: &(String, String),
) -> Result<bool> {
    let remote_ref = format!("refs/tags/{}", release.tag);
    let peeled_ref = format!("{remote_ref}^{{}}");
    let remote_rows = remote_tag_rows(commands, remote, &release.tag)?;
    if !remote_rows.is_empty() {
        if remote_rows.get(&peeled_ref).map(String::as_str) != Some(source_commit)
            || !remote_rows.contains_key(&remote_ref)
        {
            bail!("remote release tag is not the expected signed source");
        }
        ensure_local_tag(
            commands,
            remote,
            release,
            source_commit,
            &remote_ref,
            remote_rows.get(&remote_ref).map(String::as_str),
            signing_key,
        )?;
        return Ok(false);
    }
    let local_output = require_success(
        commands.git(&os_args(["tag", "--list", &release.tag]))?,
        "inspect local release tag",
    )?;
    let local = utf8_lines(&local_output.stdout, "local release tag")?;
    if local.is_empty() {
        require_success(
            commands.git(&os_args([
                "tag",
                "-s",
                &release.tag,
                source_commit,
                "-m",
                &release.title,
            ]))?,
            "create signed release tag",
        )?;
    } else if local != [release.tag.as_str()] {
        bail!("local release tag is ambiguous");
    }
    verify_local_tag(commands, release, source_commit, None, signing_key)?;
    let _ = commands.git(&os_args([
        "push",
        remote,
        &format!("{remote_ref}:{remote_ref}"),
    ]))?;
    let published = remote_tag_rows(commands, remote, &release.tag)?;
    if published.get(&peeled_ref).map(String::as_str) != Some(source_commit)
        || !published.contains_key(&remote_ref)
    {
        bail!("remote release tag did not verify after push");
    }
    verify_local_tag(
        commands,
        release,
        source_commit,
        published.get(&remote_ref).map(String::as_str),
        signing_key,
    )?;
    Ok(true)
}

#[cfg(target_os = "linux")]
fn ensure_local_tag(
    commands: &mut impl PublicationCommands,
    remote: &str,
    release: &ProductRelease,
    source_commit: &str,
    remote_ref: &str,
    remote_object: Option<&str>,
    signing_key: &(String, String),
) -> Result<()> {
    let local_output = require_success(
        commands.git(&os_args(["tag", "--list", &release.tag]))?,
        "inspect local release tag",
    )?;
    let local = utf8_lines(&local_output.stdout, "local release tag")?;
    if local.is_empty() {
        require_success(
            commands.git(&os_args([
                "fetch",
                "--no-tags",
                remote,
                &format!("{remote_ref}:{remote_ref}"),
            ]))?,
            "fetch signed release tag",
        )?;
    } else if local != [release.tag.as_str()] {
        bail!("local release tag is ambiguous");
    }
    verify_local_tag(commands, release, source_commit, remote_object, signing_key)
}

#[cfg(target_os = "linux")]
fn remote_tag_rows(
    commands: &mut impl PublicationCommands,
    remote: &str,
    tag: &str,
) -> Result<BTreeMap<String, String>> {
    let output = require_success(
        commands.git(&os_args([
            "ls-remote",
            "--tags",
            remote,
            &format!("refs/tags/{tag}"),
            &format!("refs/tags/{tag}^{{}}"),
        ]))?,
        "inspect remote release tag",
    )?;
    let text = std::str::from_utf8(&output.stdout).context("remote tag metadata is not UTF-8")?;
    let mut rows = BTreeMap::new();
    let remote_ref = format!("refs/tags/{tag}");
    let peeled_ref = format!("{remote_ref}^{{}}");
    for line in text.lines() {
        let (commit, reference) = line
            .split_once('\t')
            .context("remote tag metadata is malformed")?;
        if !valid_lower_hex(commit, 40)
            || (reference != remote_ref && reference != peeled_ref)
            || rows.insert(reference.into(), commit.into()).is_some()
        {
            bail!("remote tag metadata is malformed");
        }
    }
    Ok(rows)
}

#[cfg(target_os = "linux")]
fn verify_local_tag(
    commands: &mut impl PublicationCommands,
    release: &ProductRelease,
    source_commit: &str,
    remote_object: Option<&str>,
    signing_key: &(String, String),
) -> Result<()> {
    let object_output = require_success(
        commands.git(&os_args([
            "rev-parse",
            &format!("refs/tags/{}", release.tag),
        ]))?,
        "inspect local release tag object",
    )?;
    let object = one_line(&object_output.stdout, "local release tag object")?;
    if !valid_lower_hex(object, 40) || remote_object.is_some_and(|remote| remote != object) {
        bail!("local signed tag is not the exact remote tag object");
    }
    let source_output = require_success(
        commands.git(&os_args(["rev-list", "-n", "1", &release.tag]))?,
        "inspect local release tag source",
    )?;
    let source = one_line(&source_output.stdout, "local release tag source")?;
    if source != source_commit {
        bail!("local release tag points at a different source");
    }
    let signing_output = require_success(
        commands.git(&os_args(["config", "--get", "user.signingKey"]))?,
        "inspect Git signing identity",
    )?;
    let configured_signing_key = one_line(&signing_output.stdout, "Git signing identity")?;
    let inline = configured_signing_key
        .strip_prefix("key::")
        .context("Git signing identity is not one inline SSH public key")?;
    let observed = ssh_key_identity(inline).context("validate admitted Git signing identity")?;
    if &observed != signing_key {
        bail!("admitted Git signing identity does not match the expected public key");
    }
    let directory = tempfile::Builder::new()
        .prefix("release-admin-signers-")
        .tempdir()
        .context("create allowed-signers directory")?;
    let allowed = directory.path().join("allowed-signers");
    fs::write(
        &allowed,
        format!("* namespaces=\"git\" {} {}\n", signing_key.0, signing_key.1),
    )
    .context("write allowed Git signer")?;
    fs::set_permissions(&allowed, fs::Permissions::from_mode(0o600))
        .context("protect allowed Git signer")?;
    require_success(
        commands.git(&[
            OsString::from("-c"),
            OsString::from(format!("gpg.ssh.allowedSignersFile={}", allowed.display())),
            OsString::from("verify-tag"),
            OsString::from(&release.tag),
        ])?,
        "verify signed release tag",
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn release_view(
    commands: &mut impl PublicationCommands,
    repository: &str,
    tag: &str,
) -> Result<Option<Value>> {
    let output = commands.gh(&os_args([
        "release",
        "view",
        tag,
        "--repo",
        repository,
        "--json",
        "tagName,isDraft,isPrerelease,assets",
    ]))?;
    if output.code == Some(1) && trim_ascii(&output.stderr) == b"release not found" {
        return Ok(None);
    }
    let output = require_success(output, "inspect GitHub release")?;
    serde_json::from_slice(&output.stdout)
        .context("parse GitHub release metadata")
        .map(Some)
}

#[cfg(target_os = "linux")]
fn verify_published_release(
    commands: &mut impl PublicationCommands,
    repository: &str,
    release: &ProductRelease,
) -> Result<()> {
    let view = release_view(commands, repository, &release.tag)?
        .context("published release is absent after creation")?;
    if view.get("tagName") != Some(&Value::String(release.tag.clone()))
        || view.get("isDraft") != Some(&Value::Bool(false))
        || view.get("isPrerelease") != Some(&Value::Bool(false))
    {
        bail!("published release metadata is unexpected");
    }
    let assets = view
        .get("assets")
        .and_then(Value::as_array)
        .context("published release asset metadata is invalid")?;
    let mut observed = BTreeMap::new();
    for asset in assets {
        let name = asset
            .get("name")
            .and_then(Value::as_str)
            .context("published release asset name is invalid")?;
        let size = asset
            .get("size")
            .and_then(Value::as_u64)
            .context("published release asset size is invalid")?;
        if observed.insert(name, size).is_some() {
            bail!("published release contains a duplicate asset");
        }
    }
    let expected = release
        .assets
        .iter()
        .map(|asset| {
            Ok((
                asset
                    .path
                    .file_name()
                    .and_then(OsStr::to_str)
                    .context("release asset name is invalid")?,
                asset.length,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    if observed != expected {
        bail!("published release assets do not match the signed set");
    }
    for asset in &release.assets {
        let bytes = commands
            .anonymous_get(&asset.url, asset.length.saturating_add(1))
            .context("anonymously download published release asset")?;
        if (bytes.len() as u64, format!("{:x}", Sha256::digest(&bytes)))
            != (asset.length, asset.sha256.clone())
        {
            bail!("downloaded release asset does not match the signed set");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn file_identity(path: &Path, limit: u64) -> Result<(u64, String)> {
    let bytes = read_bounded_file(path, limit)?;
    Ok((bytes.len() as u64, format!("{:x}", Sha256::digest(bytes))))
}

#[cfg(target_os = "linux")]
fn require_success(output: CommandOutput, action: &str) -> Result<CommandOutput> {
    if output.code != Some(0) {
        bail!("{action} failed");
    }
    Ok(output)
}

#[cfg(target_os = "linux")]
fn one_line<'a>(bytes: &'a [u8], label: &str) -> Result<&'a str> {
    let value = std::str::from_utf8(bytes).with_context(|| format!("{label} is not UTF-8"))?;
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.is_empty() || value.contains(['\r', '\n']) {
        bail!("{label} is not one line");
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn utf8_lines<'a>(bytes: &'a [u8], label: &str) -> Result<Vec<&'a str>> {
    let value = std::str::from_utf8(bytes).with_context(|| format!("{label} is not UTF-8"))?;
    if value.contains('\r') {
        bail!("{label} is malformed");
    }
    Ok(value.lines().collect())
}

#[cfg(target_os = "linux")]
fn os_args<const N: usize>(values: [&str; N]) -> Vec<OsString> {
    values.into_iter().map(OsString::from).collect()
}

#[cfg(target_os = "linux")]
fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

#[cfg(target_os = "linux")]
fn valid_repository_url(url: &str, repository: &str) -> bool {
    [
        format!("git@github.com:{repository}.git"),
        format!("ssh://git@github.com/{repository}.git"),
        format!("https://github.com/{repository}.git"),
    ]
    .iter()
    .any(|accepted| accepted == url)
}

#[cfg(target_os = "linux")]
fn valid_product(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(target_os = "linux")]
fn valid_ssh_key_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'.' | b'_' | b'+' | b'-')
        })
}

#[cfg(target_os = "linux")]
fn ssh_key_identity(value: &str) -> Result<(String, String)> {
    let fields = value.split_ascii_whitespace().collect::<Vec<_>>();
    if !(2..=3).contains(&fields.len())
        || !valid_ssh_key_type(fields[0])
        || BASE64
            .decode(fields[1])
            .ok()
            .is_none_or(|bytes| !(32..=16 * 1024).contains(&bytes.len()))
    {
        bail!("Git signing identity is not one SSH public key");
    }
    Ok((fields[0].into(), fields[1].into()))
}

#[cfg(target_os = "linux")]
fn write_result(
    format: PublishFormat,
    source_commit: &str,
    repository: &str,
    changed: bool,
    releases: &[Value],
) -> Result<()> {
    match format {
        PublishFormat::Json => {
            serde_json::to_writer(
                std::io::stdout().lock(),
                &json!({
                    "schema": "release-admin-set-publish-v1",
                    "tag_source_commit": source_commit,
                    "repository": repository,
                    "changed": changed,
                    "verified": true,
                    "releases": releases,
                }),
            )?;
            println!();
        }
        PublishFormat::Human => {
            println!("changed={changed}");
            println!("verified=true");
            for release in releases {
                println!(
                    "release={}",
                    release
                        .get("tag")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                );
            }
        }
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use dev_tools_release::{
        build_signed_envelope, build_unsigned_product_manifest, build_unsigned_root_document,
        release_key_id, root_key_id, EnvelopeSignature, ManifestArtifact, ProductManifestSpec,
        RootDocumentSpec, RootReleaseKey,
    };
    use ed25519_dalek::{Signer, SigningKey};

    const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SIGNING_KEY: &str = "key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGFx1w/enBxQRy/DEl59qE3az25LG9DbYUue2Bj5IghY fixture";

    struct Fixture {
        _directory: tempfile::TempDir,
        release_root: PathBuf,
        trusted_root: String,
    }

    struct FakeCommands {
        local_tags: BTreeSet<String>,
        remote_tags: BTreeSet<String>,
        releases: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
        calls: Vec<(String, Vec<String>)>,
        release_view_error: bool,
        fail_create_after_publication: bool,
        corrupt_anonymous_download: bool,
        admitted: bool,
        remote_url: String,
    }

    impl Default for FakeCommands {
        fn default() -> Self {
            Self {
                local_tags: BTreeSet::new(),
                remote_tags: BTreeSet::new(),
                releases: BTreeMap::new(),
                calls: Vec::new(),
                release_view_error: false,
                fail_create_after_publication: false,
                corrupt_anonymous_download: false,
                admitted: true,
                remote_url: "git@github.com:FutureDevGuys/dev-tools.git".into(),
            }
        }
    }

    impl PublicationCommands for FakeCommands {
        fn admission(&mut self, arguments: &[OsString]) -> Result<CommandOutput> {
            let arguments = strings(arguments);
            self.calls.push(("dev-auth".into(), arguments));
            Ok(success(serde_json::to_vec(&json!({
                "schema": "dev-auth-broker-status-v2",
                "mode": "strong",
                "authenticated_release": true,
                "session_state": if self.admitted { "present" } else { "absent" },
                "broker_state": if self.admitted { "verified" } else { "no_session" },
                "degraded_same_user_boundary": false,
            }))?))
        }

        fn git(&mut self, arguments: &[OsString]) -> Result<CommandOutput> {
            let arguments = strings(arguments);
            self.calls.push(("git".into(), arguments.clone()));
            let output = match arguments.as_slice() {
                [status, porcelain, untracked]
                    if status == "status"
                        && porcelain == "--porcelain"
                        && untracked == "--untracked-files=normal" =>
                {
                    success(Vec::new())
                }
                [cat_file, exists, _] if cat_file == "cat-file" && exists == "-e" => {
                    success(Vec::new())
                }
                [remote, get_url, name]
                    if remote == "remote" && get_url == "get-url" && name == "origin" =>
                {
                    success(format!("{}\n", self.remote_url).into_bytes())
                }
                [remote, get_url, push, name]
                    if remote == "remote"
                        && get_url == "get-url"
                        && push == "--push"
                        && name == "origin" =>
                {
                    success(format!("{}\n", self.remote_url).into_bytes())
                }
                [tag, list, name] if tag == "tag" && list == "--list" => {
                    if self.local_tags.contains(name) {
                        success(format!("{name}\n").into_bytes())
                    } else {
                        success(Vec::new())
                    }
                }
                [tag, sign, name, source, message, _]
                    if tag == "tag" && sign == "-s" && source == SOURCE && message == "-m" =>
                {
                    self.local_tags.insert(name.clone());
                    success(Vec::new())
                }
                [rev_list, count, one, name]
                    if rev_list == "rev-list"
                        && count == "-n"
                        && one == "1"
                        && self.local_tags.contains(name) =>
                {
                    success(format!("{SOURCE}\n").into_bytes())
                }
                [rev_parse, reference]
                    if rev_parse == "rev-parse"
                        && self
                            .local_tags
                            .contains(reference.trim_start_matches("refs/tags/")) =>
                {
                    success(format!("{}\n", "b".repeat(40)).into_bytes())
                }
                [config, get, key]
                    if config == "config" && get == "--get" && key == "user.signingKey" =>
                {
                    success(format!("{SIGNING_KEY}\n").into_bytes())
                }
                [configuration, _, verify, name]
                    if configuration == "-c"
                        && verify == "verify-tag"
                        && self.local_tags.contains(name) =>
                {
                    success(Vec::new())
                }
                [remote, tags, _, reference, _] if remote == "ls-remote" && tags == "--tags" => {
                    let name = reference.trim_start_matches("refs/tags/");
                    if self.remote_tags.contains(name) {
                        success(
                            format!(
                                "{}\trefs/tags/{name}\n{SOURCE}\trefs/tags/{name}^{{}}\n",
                                "b".repeat(40)
                            )
                            .into_bytes(),
                        )
                    } else {
                        success(Vec::new())
                    }
                }
                [push, _, specification] if push == "push" => {
                    let reference = specification
                        .split_once(':')
                        .map(|(source, _)| source)
                        .unwrap_or(specification);
                    self.remote_tags
                        .insert(reference.trim_start_matches("refs/tags/").into());
                    success(Vec::new())
                }
                [fetch, no_tags, _, specification]
                    if fetch == "fetch" && no_tags == "--no-tags" =>
                {
                    let reference = specification
                        .split_once(':')
                        .map(|(_, destination)| destination)
                        .unwrap_or(specification);
                    self.local_tags
                        .insert(reference.trim_start_matches("refs/tags/").into());
                    success(Vec::new())
                }
                _ => failure(91, b"unexpected git command"),
            };
            Ok(output)
        }

        fn gh(&mut self, arguments: &[OsString]) -> Result<CommandOutput> {
            let arguments = strings(arguments);
            self.calls.push(("gh".into(), arguments.clone()));
            if arguments.first().map(String::as_str) != Some("release") {
                return Ok(failure(92, b"unexpected gh command"));
            }
            match arguments.get(1).map(String::as_str) {
                Some("view") => {
                    if self.release_view_error {
                        return Ok(failure(2, b"provider unavailable"));
                    }
                    let tag = arguments.get(2).context("missing fake release tag")?;
                    let Some(assets) = self.releases.get(tag) else {
                        return Ok(failure(1, b"release not found"));
                    };
                    let assets = assets
                        .iter()
                        .map(|(name, bytes)| json!({"name": name, "size": bytes.len()}))
                        .collect::<Vec<_>>();
                    Ok(success(serde_json::to_vec(&json!({
                        "tagName": tag,
                        "isDraft": false,
                        "isPrerelease": false,
                        "assets": assets,
                    }))?))
                }
                Some("create") => {
                    let tag = arguments
                        .get(2)
                        .context("missing fake release tag")?
                        .clone();
                    let notes = arguments
                        .iter()
                        .position(|value| value == "--notes")
                        .context("missing fake release notes")?;
                    let mut assets = BTreeMap::new();
                    for path in &arguments[notes + 2..] {
                        let path = Path::new(path);
                        let name = path
                            .file_name()
                            .and_then(OsStr::to_str)
                            .context("invalid fake release asset")?;
                        assets.insert(name.into(), fs::read(path)?);
                    }
                    self.releases.insert(tag, assets);
                    if self.fail_create_after_publication {
                        Ok(failure(2, b"connection lost"))
                    } else {
                        Ok(success(Vec::new()))
                    }
                }
                _ => Ok(failure(92, b"unexpected gh command")),
            }
        }

        fn anonymous_get(&mut self, url: &str, _limit: u64) -> Result<Vec<u8>> {
            self.calls.push(("https".into(), vec![url.into()]));
            let remainder = url
                .strip_prefix("https://github.com/FutureDevGuys/dev-tools/releases/download/")
                .context("unexpected anonymous release URL")?;
            let (encoded_tag, name) = remainder
                .split_once('/')
                .context("invalid anonymous release URL")?;
            let tag = encoded_tag.replace("%2F", "/");
            let mut bytes = self
                .releases
                .get(&tag)
                .and_then(|assets| assets.get(name))
                .cloned()
                .context("anonymous release asset is absent")?;
            if self.corrupt_anonymous_download {
                bytes.push(0);
            }
            Ok(bytes)
        }
    }

    #[test]
    fn authenticated_release_publication_is_idempotent_and_anonymously_verified() {
        let fixture = fixture("update-all", "linux-x86_64", "dev-tools-product-v2");
        let releases =
            load_release_set(&fixture.release_root, &fixture.trusted_root, SOURCE).unwrap();
        let mut commands = FakeCommands::default();
        let signing_key = expected_signing_key();
        ensure_admitted(&mut commands).unwrap();
        ensure_source(&mut commands, SOURCE, "origin", REPOSITORY).unwrap();

        assert!(publish_one(
            &mut commands,
            "origin",
            REPOSITORY,
            &releases[0],
            SOURCE,
            &signing_key,
        )
        .unwrap());
        assert!(!publish_one(
            &mut commands,
            "origin",
            REPOSITORY,
            &releases[0],
            SOURCE,
            &signing_key,
        )
        .unwrap());
        assert!(commands.calls.iter().any(|(command, _)| command == "https"));
        assert!(!commands.calls.iter().any(|(command, arguments)| {
            command == "gh" && arguments.get(1).map(String::as_str) == Some("download")
        }));
    }

    #[test]
    fn ambiguous_release_creation_is_resolved_from_exact_final_state() {
        let fixture = fixture("update-all", "linux-x86_64", "dev-tools-product-v2");
        let release = load_release_set(&fixture.release_root, &fixture.trusted_root, SOURCE)
            .unwrap()
            .remove(0);
        let mut commands = FakeCommands {
            fail_create_after_publication: true,
            ..FakeCommands::default()
        };
        assert!(publish_one(
            &mut commands,
            "origin",
            REPOSITORY,
            &release,
            SOURCE,
            &expected_signing_key(),
        )
        .unwrap());
    }

    #[test]
    fn provider_error_is_not_treated_as_an_absent_release() {
        let fixture = fixture("update-all", "linux-x86_64", "dev-tools-product-v2");
        let release = load_release_set(&fixture.release_root, &fixture.trusted_root, SOURCE)
            .unwrap()
            .remove(0);
        let mut commands = FakeCommands {
            release_view_error: true,
            ..FakeCommands::default()
        };
        assert!(publish_one(
            &mut commands,
            "origin",
            REPOSITORY,
            &release,
            SOURCE,
            &expected_signing_key(),
        )
        .unwrap_err()
        .to_string()
        .contains("inspect GitHub release failed"));
        assert!(!commands.calls.iter().any(|(command, arguments)| {
            command == "gh" && arguments.get(1).map(String::as_str) == Some("create")
        }));
    }

    #[test]
    fn publication_refuses_native_human_passthrough_without_workload_admission() {
        let mut commands = FakeCommands {
            admitted: false,
            ..FakeCommands::default()
        };
        assert!(ensure_admitted(&mut commands)
            .unwrap_err()
            .to_string()
            .contains("requires a verified strong workload admission"));
        assert_eq!(commands.calls.len(), 1);
    }

    #[test]
    fn publication_refuses_a_git_remote_for_a_different_repository() {
        let mut commands = FakeCommands {
            remote_url: "git@github.com:FutureDevGuys/other.git".into(),
            ..FakeCommands::default()
        };
        assert!(ensure_source(&mut commands, SOURCE, "origin", REPOSITORY)
            .unwrap_err()
            .to_string()
            .contains("does not match the GitHub repository"));
        assert!(!commands.calls.iter().any(|(_, arguments)| {
            arguments.first().map(String::as_str) == Some("ls-remote")
                || arguments.first().map(String::as_str) == Some("push")
        }));
    }

    #[test]
    fn publication_child_environment_removes_ambient_credentials_and_git_configuration() {
        let mut command = std::process::Command::new("/usr/bin/env");
        command
            .env("GH_TOKEN", "not-authorized")
            .env("GITHUB_TOKEN", "not-authorized")
            .env("GIT_CONFIG_GLOBAL", "/tmp/not-authorized")
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "gpg.ssh.program")
            .env("GIT_CONFIG_VALUE_0", "/tmp/not-authorized");
        apply_publication_environment(&mut command);
        let output = command.output().unwrap();
        assert!(output.status.success());
        let environment = String::from_utf8(output.stdout).unwrap();
        for denied in [
            "GH_TOKEN=",
            "GITHUB_TOKEN=",
            "GIT_CONFIG_GLOBAL=",
            "GIT_CONFIG_COUNT=",
            "GIT_CONFIG_KEY_0=",
            "GIT_CONFIG_VALUE_0=",
        ] {
            assert!(!environment.contains(denied));
        }
    }

    #[test]
    fn repository_git_configuration_cannot_self_authorize_a_signing_key() {
        let fixture = fixture("update-all", "linux-x86_64", "dev-tools-product-v2");
        let release = load_release_set(&fixture.release_root, &fixture.trusted_root, SOURCE)
            .unwrap()
            .remove(0);
        let mut commands = FakeCommands::default();
        let independently_expected = ("ssh-ed25519".into(), BASE64.encode([0_u8; 32]));
        assert!(publish_one(
            &mut commands,
            "origin",
            REPOSITORY,
            &release,
            SOURCE,
            &independently_expected,
        )
        .unwrap_err()
        .to_string()
        .contains("does not match the expected public key"));
        assert!(!commands.calls.iter().any(|(command, _)| command == "gh"));
    }

    #[test]
    fn authenticated_provider_metadata_cannot_substitute_for_public_asset_bytes() {
        let fixture = fixture("update-all", "linux-x86_64", "dev-tools-product-v2");
        let release = load_release_set(&fixture.release_root, &fixture.trusted_root, SOURCE)
            .unwrap()
            .remove(0);
        let mut commands = FakeCommands {
            corrupt_anonymous_download: true,
            ..FakeCommands::default()
        };
        assert!(publish_one(
            &mut commands,
            "origin",
            REPOSITORY,
            &release,
            SOURCE,
            &expected_signing_key(),
        )
        .unwrap_err()
        .to_string()
        .contains("downloaded release asset does not match"));
    }

    #[test]
    fn tampered_artifact_is_rejected_before_provider_access() {
        let fixture = fixture("update-all", "linux-x86_64", "dev-tools-product-v2");
        let artifact = fs::read_dir(fixture.release_root.join("update-all"))
            .unwrap()
            .map(Result::unwrap)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .ends_with("linux-x86_64")
            })
            .unwrap()
            .path();
        fs::write(artifact, b"tampered").unwrap();
        assert!(
            load_release_set(&fixture.release_root, &fixture.trusted_root, SOURCE,)
                .unwrap_err()
                .to_string()
                .contains("authenticate release artifact")
        );
    }

    #[test]
    fn unsupported_contract_and_target_fail_before_provider_access() {
        let legacy = fixture("update-all", "linux-x86_64", "dev-tools-product-v1");
        assert!(
            load_release_set(&legacy.release_root, &legacy.trusted_root, SOURCE)
                .unwrap_err()
                .to_string()
                .contains("unsupported publication contract")
        );

        let unsupported = fixture("sync-configs", "windows-x86_64", "dev-tools-product-v2");
        assert!(
            load_release_set(&unsupported.release_root, &unsupported.trusted_root, SOURCE,)
                .unwrap_err()
                .to_string()
                .contains("release target is not accepted")
        );
    }

    fn fixture(product: &str, target: &str, schema: &str) -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let release_root = directory.path().join("releases");
        let product_root = release_root.join(product);
        fs::create_dir_all(&product_root).unwrap();
        let version = "1.2.3";
        let suffix = if target.starts_with("windows-") {
            ".exe"
        } else {
            ""
        };
        let artifact_name = format!("{product}-{version}-{target}{suffix}");
        let artifact_path = product_root.join(&artifact_name);
        let artifact = format!("{product} fixture\n").into_bytes();
        fs::write(&artifact_path, &artifact).unwrap();
        let root_key = SigningKey::from_bytes(&[3; 32]);
        let release_key = SigningKey::from_bytes(&[7; 32]);
        let release_public = hex(&release_key.verifying_key().to_bytes());
        let unsigned_root = build_unsigned_root_document(&RootDocumentSpec {
            generation: 1,
            release_keys: vec![RootReleaseKey {
                public_key: release_public.clone(),
                revoked: false,
            }],
        })
        .unwrap();
        let root = build_signed_envelope(
            &unsigned_root,
            &[EnvelopeSignature {
                key_id: root_key_id(&hex(&root_key.verifying_key().to_bytes())).unwrap(),
                signature: root_key.sign(&unsigned_root).to_bytes().to_vec(),
            }],
        )
        .unwrap();
        fs::write(product_root.join("dev-tools-root.json"), root).unwrap();
        let artifact_url = format!(
            "https://github.com/FutureDevGuys/dev-tools/releases/download/{product}%2Fv{version}/{artifact_name}"
        );
        let unsigned_manifest = if schema == "dev-tools-product-v2" {
            build_unsigned_product_manifest(&ProductManifestSpec {
                product: product.into(),
                generation: 1,
                version: version.into(),
                source_commit: SOURCE.into(),
                artifacts: vec![ManifestArtifact {
                    target: target.into(),
                    url: artifact_url,
                    length: artifact.len() as u64,
                    sha256: format!("{:x}", Sha256::digest(&artifact)),
                }],
            })
            .unwrap()
        } else {
            serde_jcs::to_vec(&json!({
                "schema": schema,
                "product": product,
                "generation": 1,
                "version": version,
                "engine_protocol": 1,
                "artifacts": {
                    target: {
                        "url": artifact_url,
                        "length": artifact.len(),
                        "sha256": format!("{:x}", Sha256::digest(&artifact)),
                    }
                }
            }))
            .unwrap()
        };
        let manifest = build_signed_envelope(
            &unsigned_manifest,
            &[EnvelopeSignature {
                key_id: release_key_id(&release_public).unwrap(),
                signature: release_key.sign(&unsigned_manifest).to_bytes().to_vec(),
            }],
        )
        .unwrap();
        fs::write(
            product_root.join(format!("{product}-stable.json")),
            manifest,
        )
        .unwrap();
        Fixture {
            _directory: directory,
            release_root,
            trusted_root: hex(&root_key.verifying_key().to_bytes()),
        }
    }

    fn strings(arguments: &[OsString]) -> Vec<String> {
        arguments
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect()
    }

    fn expected_signing_key() -> (String, String) {
        ssh_key_identity(SIGNING_KEY.strip_prefix("key::").unwrap()).unwrap()
    }

    fn success(stdout: Vec<u8>) -> CommandOutput {
        CommandOutput {
            code: Some(0),
            stdout,
            stderr: Vec::new(),
        }
    }

    fn failure(code: i32, stderr: &[u8]) -> CommandOutput {
        CommandOutput {
            code: Some(code),
            stdout: Vec::new(),
            stderr: stderr.to_vec(),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
