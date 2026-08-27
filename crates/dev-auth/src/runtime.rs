use crate::{
    parse_config, render_git_credential, sanitize_environment, CacheEntry, Config,
    CredentialRequest, ExecProfile, SecretString, SshKeyPurpose, SshProfile,
};
use anyhow::{bail, Context, Result};
use fs2::FileExt;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const CONFIG_LIMIT: u64 = 1024 * 1024;
const RESPONSE_LIMIT: u64 = 64 * 1024;
const SECRET_TOOL: &str = "/usr/bin/secret-tool";
const OP: &str = "/usr/bin/op";
const SSH_ADD: &str = "/usr/bin/ssh-add";
const GH: &str = "/usr/bin/gh";
const GIT: &str = "/usr/bin/git";
const SSH_KEYGEN: &str = "/usr/bin/ssh-keygen";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStatus {
    pub config_ready: bool,
    pub service_token_enrolled: bool,
    pub runtime_ready: bool,
    pub cached_installation_tokens: usize,
}

#[derive(Debug)]
struct RuntimePaths {
    config: PathBuf,
    runtime: PathBuf,
}

impl RuntimePaths {
    fn discover() -> Result<Self> {
        let home = absolute_environment_path("HOME")?;
        let config_root = match env::var_os("XDG_CONFIG_HOME") {
            Some(value) => absolute_path(value, "XDG_CONFIG_HOME")?,
            None => home.join(".config"),
        };
        let runtime_root = absolute_environment_path("XDG_RUNTIME_DIR")?;
        Ok(Self {
            config: config_root.join("dev-auth/config.toml"),
            runtime: runtime_root.join("dev-auth"),
        })
    }

    fn cache_dir(&self) -> PathBuf {
        self.runtime.join("github-installation-tokens")
    }
}

fn absolute_environment_path(name: &str) -> Result<PathBuf> {
    let value = env::var_os(name).with_context(|| format!("{name} is not set"))?;
    absolute_path(value, name)
}

fn absolute_path(value: std::ffi::OsString, name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        bail!("{name} must be an absolute path");
    }
    Ok(path)
}

fn load_config(paths: &RuntimePaths) -> Result<Config> {
    let parent = paths
        .config
        .parent()
        .context("dev-auth configuration has no parent directory")?;
    validate_private_directory(parent, "dev-auth configuration directory")?;
    let file = private_read(&paths.config, "dev-auth configuration")?;
    let mut bytes = Vec::new();
    file.take(CONFIG_LIMIT + 1)
        .read_to_end(&mut bytes)
        .context("read configuration")?;
    if bytes.len() as u64 > CONFIG_LIMIT {
        bail!("configuration exceeds the size limit");
    }
    parse_config(&bytes)
}

fn validate_private_directory(path: &Path, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {description} at {}", path.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!("{description} must be a directory");
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        bail!("{description} is not owned by the current user");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("{description} permissions must not grant group or other access");
    }
    Ok(())
}

fn private_read(path: &Path, description: &str) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .with_context(|| format!("open {description} at {}", path.display()))?;
    validate_open_private_file(&file, description)?;
    Ok(file)
}

fn validate_open_private_file(file: &File, description: &str) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {description}"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!("{description} has unsafe type, ownership, links, or permissions");
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(false).mode(0o700);
        builder
            .create(path)
            .with_context(|| format!("create private runtime directory {}", path.display()))?;
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect private runtime directory {}", path.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!("private runtime path is not a directory");
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        bail!("private runtime directory is not owned by the current user");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("private runtime directory grants group or other access");
    }
    Ok(())
}

fn ensure_runtime(paths: &RuntimePaths) -> Result<()> {
    let parent = paths
        .runtime
        .parent()
        .context("private runtime path has no parent")?;
    let parent_metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("inspect runtime root {}", parent.display()))?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != rustix::process::geteuid().as_raw()
        || parent_metadata.permissions().mode() & 0o077 != 0
    {
        bail!("XDG runtime root is not a private current-user directory");
    }
    ensure_private_directory(&paths.runtime)?;
    ensure_private_directory(&paths.cache_dir())?;
    Ok(())
}

fn strip_one_line_ending(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.ends_with(b"\r\n") {
        bytes.truncate(bytes.len() - 2);
    } else if bytes.ends_with(b"\n") {
        bytes.truncate(bytes.len() - 1);
    }
    bytes
}

fn secret_service_environment(
    source: impl IntoIterator<Item = (OsString, OsString)>,
) -> BTreeMap<OsString, OsString> {
    source
        .into_iter()
        .filter(|(name, _)| {
            matches!(
                name.to_str(),
                Some("DBUS_SESSION_BUS_ADDRESS" | "XDG_RUNTIME_DIR")
            )
        })
        .collect()
}

fn service_account_token() -> Result<SecretString> {
    let mut command = Command::new(SECRET_TOOL);
    command
        .args(["lookup", "service", "dev-auth", "account", "automation"])
        .env_clear()
        .env("PATH", "/usr/bin")
        .envs(secret_service_environment(env::vars_os()))
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    let output = command.output().context("run OS credential-store lookup")?;
    if !output.status.success() {
        bail!("the dev-auth service credential is not enrolled or the keyring is locked");
    }
    let bytes = strip_one_line_ending(output.stdout);
    let value = String::from_utf8(bytes).context("credential-store value is not UTF-8")?;
    if value.is_empty() || value.contains(['\n', '\r', '\0']) {
        bail!("credential-store value is malformed");
    }
    Ok(SecretString::new(value))
}

fn read_automation_secret(reference: &str) -> Result<SecretString> {
    crate::validate_op_reference(reference)?;
    let service_token = service_account_token()?;
    let output = Command::new(OP)
        .args(["read", "--no-newline", reference])
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("OP_SERVICE_ACCOUNT_TOKEN", service_token.expose())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("run bounded 1Password item read")?;
    if !output.status.success() {
        bail!("1Password denied the declared Automation-vault item read");
    }
    let value = String::from_utf8(output.stdout).context("1Password item value is not UTF-8")?;
    if value.is_empty() || value.contains('\0') {
        bail!("1Password item value is empty or malformed");
    }
    Ok(SecretString::new(value))
}

#[derive(Debug, Serialize)]
struct AppJwtClaims {
    iat: i64,
    exp: i64,
    iss: String,
}

#[derive(Debug, Serialize)]
struct InstallationTokenRequest<'a> {
    repository_ids: [u64; 1],
    permissions: &'a BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct InstallationTokenResponse {
    token: String,
    expires_at: String,
}

fn mint_installation_token(
    config: &Config,
    installation_id: u64,
    repository_id: u64,
    now: i64,
) -> Result<CacheEntry> {
    let private_key = read_automation_secret(&config.github.private_key_ref)?;
    let key = EncodingKey::from_rsa_pem(private_key.expose().as_bytes())
        .context("GitHub App private key is not a valid RSA PEM key")?;
    let jwt = encode(
        &Header::new(Algorithm::RS256),
        &AppJwtClaims {
            iat: now - 60,
            exp: now + 540,
            iss: config.github.app_id.to_string(),
        },
        &key,
    )
    .context("sign GitHub App JWT")?;

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(format!("dev-auth/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let url = format!("https://api.github.com/app/installations/{installation_id}/access_tokens");
    let mut response = agent
        .post(&url)
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("X-GitHub-Api-Version", "2026-03-10")
        .send_json(&InstallationTokenRequest {
            repository_ids: [repository_id],
            permissions: &config.github.permissions,
        })
        .context("request narrowed GitHub App installation token")?;
    if !response.status().is_success() {
        bail!(
            "GitHub App installation token request returned HTTP {}",
            response.status()
        );
    }
    let bytes = response
        .body_mut()
        .with_config()
        .limit(RESPONSE_LIMIT)
        .read_to_vec()
        .context("read bounded GitHub App response")?;
    let response: InstallationTokenResponse =
        serde_json::from_slice(&bytes).context("parse GitHub App token response")?;
    let expires_at = OffsetDateTime::parse(&response.expires_at, &Rfc3339)
        .context("parse GitHub App token expiry")?
        .unix_timestamp();
    if response.token.is_empty()
        || response.token.contains(['\n', '\r', '\0'])
        || expires_at <= now + 300
        || expires_at > now + 3700
    {
        bail!("GitHub returned an invalid installation token contract");
    }
    Ok(CacheEntry::new(
        SecretString::new(response.token),
        expires_at,
        installation_id,
        repository_id,
        config.github.permissions.clone(),
    ))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheFile {
    token: String,
    expires_at: i64,
    installation_id: u64,
    repository_id: u64,
    permissions: BTreeMap<String, String>,
}

impl From<&CacheEntry> for CacheFile {
    fn from(entry: &CacheEntry) -> Self {
        Self {
            token: entry.token().expose().to_owned(),
            expires_at: entry.expires_at(),
            installation_id: entry.installation_id(),
            repository_id: entry.repository_id(),
            permissions: entry.permissions.clone(),
        }
    }
}

impl From<CacheFile> for CacheEntry {
    fn from(value: CacheFile) -> Self {
        CacheEntry::new(
            SecretString::new(value.token),
            value.expires_at,
            value.installation_id,
            value.repository_id,
            value.permissions,
        )
    }
}

fn cache_key(
    installation_id: u64,
    repository_id: u64,
    permissions: &BTreeMap<String, String>,
) -> Result<String> {
    let public_scope = serde_json::to_vec(&(installation_id, repository_id, permissions))
        .context("serialize installation-token cache scope")?;
    Ok(format!("{:x}", Sha256::digest(public_scope)))
}

fn locked_cache_entry<F>(
    paths: &RuntimePaths,
    installation_id: u64,
    repository_id: u64,
    permissions: &BTreeMap<String, String>,
    create: F,
) -> Result<CacheEntry>
where
    F: FnOnce() -> Result<CacheEntry>,
{
    ensure_runtime(paths)?;
    let key = cache_key(installation_id, repository_id, permissions)?;
    let cache_path = paths.cache_dir().join(format!("{key}.json"));
    let lock_path = paths.cache_dir().join(format!("{key}.lock"));
    let lock = private_open(&lock_path)?;
    lock.lock_exclusive()
        .context("lock installation-token cache")?;
    let now = OffsetDateTime::now_utc().unix_timestamp();

    if let Ok(entry) = read_cache(&cache_path) {
        if entry.is_usable_at(now, installation_id, repository_id, permissions) {
            return Ok(entry);
        }
    }
    let entry = create()?;
    if !entry.is_usable_at(now, installation_id, repository_id, permissions) {
        bail!("new installation token is not usable for the requested scope");
    }
    write_cache(&cache_path, &entry)?;
    Ok(entry)
}

fn private_open(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open private runtime file {}", path.display()))?;
    validate_open_private_file(&file, "private runtime file")?;
    Ok(file)
}

fn read_cache(path: &Path) -> Result<CacheEntry> {
    let file = private_read(path, "installation-token cache")?;
    let value: CacheFile =
        serde_json::from_reader(file).context("parse installation-token cache")?;
    if value.token.is_empty() || value.token.contains(['\n', '\r', '\0']) {
        bail!("installation-token cache is malformed");
    }
    Ok(value.into())
}

fn write_cache(path: &Path, entry: &CacheEntry) -> Result<()> {
    let parent = path.parent().context("cache path has no parent")?;
    let temp = parent.join(format!(
        ".cache-{}-{}.tmp",
        std::process::id(),
        entry.repository_id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(&temp)
        .with_context(|| format!("create private cache temporary file {}", temp.display()))?;
    let result = (|| -> Result<()> {
        serde_json::to_writer(&mut file, &CacheFile::from(entry))
            .context("serialize installation-token cache")?;
        file.write_all(b"\n")
            .context("terminate installation-token cache")?;
        file.sync_all().context("sync installation-token cache")?;
        fs::rename(&temp, path).context("publish installation-token cache")?;
        File::open(parent)
            .context("open installation-token cache directory")?
            .sync_all()
            .context("sync installation-token cache directory")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn selected_token(
    paths: &RuntimePaths,
    config: &Config,
    request: &CredentialRequest,
) -> Result<CacheEntry> {
    let (owner, repository) = request.repository()?;
    let selected = config.github.select_repository(owner, repository)?;
    locked_cache_entry(
        paths,
        selected.installation_id,
        selected.repository_id,
        &config.github.permissions,
        || {
            mint_installation_token(
                config,
                selected.installation_id,
                selected.repository_id,
                OffsetDateTime::now_utc().unix_timestamp(),
            )
        },
    )
}

pub fn credential_get(input: &[u8]) -> Result<String> {
    let paths = RuntimePaths::discover()?;
    let config = load_config(&paths)?;
    let request = CredentialRequest::parse(input)?;
    let entry = selected_token(&paths, &config, &request)?;
    render_git_credential(entry.token().expose(), entry.expires_at())
}

pub fn github_token_for_repository(owner: &str, repository: &str) -> Result<SecretString> {
    let paths = RuntimePaths::discover()?;
    let config = load_config(&paths)?;
    let selected = config.github.select_repository(owner, repository)?;
    let entry = locked_cache_entry(
        &paths,
        selected.installation_id,
        selected.repository_id,
        &config.github.permissions,
        || {
            mint_installation_token(
                &config,
                selected.installation_id,
                selected.repository_id,
                OffsetDateTime::now_utc().unix_timestamp(),
            )
        },
    )?;
    Ok(entry.token().clone())
}

fn explicit_gh_repository(arguments: &[String]) -> Result<Option<String>> {
    let mut selected: Option<String> = None;
    let mut index = 0;
    while index < arguments.len() {
        let value = if matches!(arguments[index].as_str(), "-R" | "--repo") {
            index += 1;
            Some(
                arguments
                    .get(index)
                    .context("gh repository flag has no value")?
                    .clone(),
            )
        } else {
            arguments[index].strip_prefix("--repo=").map(str::to_owned)
        };
        if let Some(value) = value {
            if selected.as_ref().is_some_and(|current| current != &value) {
                bail!("gh command contains conflicting repository selectors");
            }
            selected = Some(value);
        }
        index += 1;
    }
    Ok(selected)
}

fn origin_repository() -> Result<String> {
    let output = Command::new(GIT)
        .args(["remote", "get-url", "origin"])
        .env_clear()
        .env("PATH", "/usr/bin")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("read current Git origin")?;
    if !output.status.success() {
        bail!("no explicit repository and no readable Git origin");
    }
    let value = String::from_utf8(output.stdout).context("Git origin is not UTF-8")?;
    Ok(value.trim_end_matches(['\n', '\r']).to_owned())
}

fn resolve_gh_repository(arguments: &[String]) -> Result<(String, String)> {
    let selected = match explicit_gh_repository(arguments)? {
        Some(value) => value,
        None => match env::var("GH_REPO") {
            Ok(value) => value,
            Err(_) => origin_repository()?,
        },
    };
    crate::parse_github_repository(&selected)
}

pub fn run_gh(arguments: &[String]) -> Result<ExitStatus> {
    crate::admit_gh_arguments(arguments)?;
    let (owner, repository) = resolve_gh_repository(arguments)?;
    let token = github_token_for_repository(&owner, &repository)?;
    let input: BTreeMap<String, String> = env::vars().collect();
    let mut environment = sanitize_environment(&input, &BTreeSet::new());
    environment.insert("GH_TOKEN".into(), token.expose().into());
    environment.insert("GH_PROMPT_DISABLED".into(), "1".into());
    environment.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
    environment.insert("GH_REPO".into(), format!("{owner}/{repository}"));
    Command::new(GH)
        .args(arguments)
        .env_clear()
        .envs(environment)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("run repository-scoped gh command")
}

pub fn credential_erase(input: &[u8]) -> Result<()> {
    let paths = RuntimePaths::discover()?;
    let config = load_config(&paths)?;
    let request = CredentialRequest::parse(input)?;
    let (owner, repository) = request.repository()?;
    let selected = config.github.select_repository(owner, repository)?;
    ensure_runtime(&paths)?;
    let key = cache_key(
        selected.installation_id,
        selected.repository_id,
        &config.github.permissions,
    )?;
    let cache = paths.cache_dir().join(format!("{key}.json"));
    match fs::remove_file(&cache) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("remove installation-token cache"),
    }
}

fn declared_profile<'a>(config: &'a Config, name: &str) -> Result<&'a ExecProfile> {
    config
        .profiles
        .get(name)
        .context("requested execution profile is not declared")
}

pub fn exec_profile(profile_name: &str, command: &[String]) -> Result<ExitStatus> {
    let paths = RuntimePaths::discover()?;
    let config = load_config(&paths)?;
    let profile = declared_profile(&config, profile_name)?;
    let executable = command.first().context("profile command is missing")?;
    if !profile.executables.contains(executable) {
        bail!("command executable is not admitted by the selected profile");
    }
    let input: BTreeMap<String, String> = env::vars().collect();
    let mut child_environment = sanitize_environment(&input, &BTreeSet::new());
    for (variable, reference) in &profile.environment {
        child_environment.insert(
            variable.clone(),
            read_automation_secret(reference)?.expose().into(),
        );
    }
    let mut child = Command::new(executable);
    child
        .args(&command[1..])
        .env_clear()
        .envs(child_environment)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    child.status().context("run declared credential profile")
}

fn ssh_agent_socket(paths: &RuntimePaths) -> PathBuf {
    paths.runtime.join("ssh-agent.sock")
}

fn validate_ssh_agent_socket(paths: &RuntimePaths) -> Result<PathBuf> {
    let socket = ssh_agent_socket(paths);
    let metadata = fs::symlink_metadata(&socket).context("inspect dedicated SSH agent socket")?;
    if !metadata.file_type().is_socket() || metadata.uid() != rustix::process::geteuid().as_raw() {
        bail!("dedicated SSH agent socket is unavailable or not current-user owned");
    }
    Ok(socket)
}

fn ssh_add_command(paths: &RuntimePaths) -> Result<Command> {
    let socket = validate_ssh_agent_socket(paths)?;
    let mut command = Command::new(SSH_ADD);
    command
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("SSH_AUTH_SOCK", socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(command)
}

pub fn run_ssh_keygen(arguments: &[String]) -> Result<ExitStatus> {
    let paths = RuntimePaths::discover()?;
    ensure_runtime(&paths)?;
    let config = load_config(&paths)?;
    let socket = validate_ssh_agent_socket(&paths)?;
    let loaded = loaded_ssh_fingerprints(&paths)?;
    let profile = unique_declared_ssh_profile(&config, &loaded)?;
    validate_signing_key_argument(arguments, profile)?;
    let input: BTreeMap<String, String> = env::vars().collect();
    let mut environment = sanitize_environment(&input, &BTreeSet::new());
    environment.insert(
        "SSH_AUTH_SOCK".into(),
        socket
            .into_os_string()
            .into_string()
            .map_err(|_| anyhow::anyhow!("SSH agent socket path is not UTF-8"))?,
    );
    Command::new(SSH_KEYGEN)
        .args(arguments)
        .env_clear()
        .envs(environment)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("run OpenSSH key operation with the dedicated agent")
}

fn unique_declared_ssh_profile<'a>(
    config: &'a Config,
    loaded: &BTreeSet<String>,
) -> Result<&'a SshProfile> {
    let mut matches = config.ssh_profiles.values().filter(|profile| {
        profile
            .keys
            .iter()
            .map(|key| key.fingerprint.clone())
            .collect::<BTreeSet<_>>()
            == *loaded
    });
    let profile = matches
        .next()
        .context("dedicated SSH agent keys do not match a declared profile")?;
    if matches.next().is_some() {
        bail!("dedicated SSH agent keys match more than one declared profile");
    }
    Ok(profile)
}

fn validate_signing_key_argument(arguments: &[String], profile: &SshProfile) -> Result<()> {
    let operation = arguments
        .windows(2)
        .find(|pair| pair[0] == "-Y")
        .map(|pair| pair[1].as_str());
    if operation != Some("sign") {
        return Ok(());
    }
    let public_key = exact_option_value(arguments, "-f")?;
    let namespace = exact_option_value(arguments, "-n")?;
    if namespace != "git" {
        bail!("automation signing is restricted to the git namespace");
    }
    let expected = profile
        .keys
        .iter()
        .find(|key| key.purpose == SshKeyPurpose::Signing)
        .context("declared SSH profile has no signing key")?;
    let output = Command::new(SSH_KEYGEN)
        .args(["-lf", public_key, "-E", "sha256"])
        .env_clear()
        .env("PATH", "/usr/bin")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("inspect requested SSH signing key")?;
    if !output.status.success() {
        bail!("requested SSH signing public key is unreadable or invalid");
    }
    let text = String::from_utf8(output.stdout).context("SSH signing fingerprint is not UTF-8")?;
    let fingerprint = text
        .split_whitespace()
        .nth(1)
        .context("SSH signing fingerprint output is invalid")?;
    if fingerprint != expected.fingerprint {
        bail!("requested SSH signing key does not match the declared signing fingerprint");
    }
    Ok(())
}

fn exact_option_value<'a>(arguments: &'a [String], option: &str) -> Result<&'a str> {
    let mut values = arguments
        .windows(2)
        .filter(|pair| pair[0] == option)
        .map(|pair| pair[1].as_str());
    let value = values
        .next()
        .with_context(|| format!("SSH signing operation requires exactly one {option} value"))?;
    if values.next().is_some() || value.starts_with('-') {
        bail!("SSH signing operation requires exactly one {option} value");
    }
    Ok(value)
}

fn clear_ssh_agent(paths: &RuntimePaths) -> Result<()> {
    let status = ssh_add_command(paths)?
        .arg("-D")
        .stdin(Stdio::null())
        .status()
        .context("clear dedicated SSH agent")?;
    if !status.success() {
        bail!("dedicated SSH agent rejected key removal");
    }
    Ok(())
}

fn load_one_ssh_key(paths: &RuntimePaths, key: &SecretString) -> Result<()> {
    let mut child = ssh_add_command(paths)?
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .context("start dedicated SSH key load")?;
    let mut input = child.stdin.take().context("open dedicated SSH key input")?;
    input
        .write_all(key.expose().as_bytes())
        .context("write dedicated SSH key input")?;
    input
        .write_all(b"\n")
        .context("terminate dedicated SSH key input")?;
    drop(input);
    let status = child.wait().context("wait for dedicated SSH key load")?;
    if !status.success() {
        bail!("dedicated SSH agent rejected a declared key");
    }
    Ok(())
}

fn loaded_ssh_fingerprints(paths: &RuntimePaths) -> Result<BTreeSet<String>> {
    let output = ssh_add_command(paths)?
        .args(["-l", "-E", "sha256"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .output()
        .context("list dedicated SSH agent keys")?;
    if !output.status.success() {
        bail!("dedicated SSH agent rejected key listing");
    }
    let text = String::from_utf8(output.stdout).context("SSH agent key list is not UTF-8")?;
    let mut fingerprints = BTreeSet::new();
    for line in text.lines() {
        let fingerprint = line
            .split_whitespace()
            .nth(1)
            .context("SSH agent returned an invalid key-list row")?;
        if !crate::is_sha256_fingerprint(fingerprint)
            || !fingerprints.insert(fingerprint.to_owned())
        {
            bail!("SSH agent returned an invalid or duplicate fingerprint");
        }
    }
    Ok(fingerprints)
}

pub fn ssh_load(profile_name: &str) -> Result<()> {
    let paths = RuntimePaths::discover()?;
    ensure_runtime(&paths)?;
    let config = load_config(&paths)?;
    let profile = config
        .ssh_profiles
        .get(profile_name)
        .context("requested SSH profile is not declared")?;
    let lock = private_open(&paths.runtime.join("ssh-load.lock"))?;
    lock.lock_exclusive()
        .context("lock dedicated SSH agent load")?;
    clear_ssh_agent(&paths)?;
    let result = (|| -> Result<()> {
        for key in &profile.keys {
            let private_key = read_automation_secret(&key.private_key_ref)?;
            load_one_ssh_key(&paths, &private_key)?;
        }
        let expected: BTreeSet<String> = profile
            .keys
            .iter()
            .map(|key| key.fingerprint.clone())
            .collect();
        let loaded = loaded_ssh_fingerprints(&paths)?;
        if loaded != expected {
            bail!("dedicated SSH agent fingerprints do not match the declared profile");
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = clear_ssh_agent(&paths);
    }
    result
}

pub fn runtime_status() -> Result<RuntimeStatus> {
    let paths = RuntimePaths::discover()?;
    let config_ready = load_config(&paths).is_ok();
    let service_token_enrolled = service_account_token().is_ok();
    let runtime_ready = ensure_runtime(&paths).is_ok();
    let cached_installation_tokens = fs::read_dir(paths.cache_dir())
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .path()
                        .extension()
                        .is_some_and(|value| value == "json")
                })
                .count()
        })
        .unwrap_or(0);
    Ok(RuntimeStatus {
        config_ready,
        service_token_enrolled,
        runtime_ready,
        cached_installation_tokens,
    })
}

pub fn purge_runtime() -> Result<()> {
    let paths = RuntimePaths::discover()?;
    let cache_dir = paths.cache_dir();
    if !cache_dir.exists() {
        return Ok(());
    }
    ensure_runtime(&paths)?;
    if ssh_agent_socket(&paths).exists() {
        clear_ssh_agent(&paths)?;
    }
    for entry in fs::read_dir(&cache_dir).context("enumerate dev-auth runtime cache")? {
        let entry = entry.context("read dev-auth runtime cache entry")?;
        let path = entry.path();
        let extension = path.extension().and_then(|value| value.to_str());
        if matches!(extension, Some("json") | Some("lock")) {
            fs::remove_file(&path)
                .with_context(|| format!("remove dev-auth runtime file {}", path.display()))?;
        } else {
            bail!("unknown file in dev-auth runtime cache");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GitHubProfile, SshKey};
    use std::os::unix::fs::PermissionsExt;

    fn config_with_profiles(profiles: BTreeMap<String, SshProfile>) -> Config {
        Config {
            version: 1,
            github: GitHubProfile {
                app_id: 1,
                private_key_ref: "op://Automation/app/private-key".into(),
                installations: Vec::new(),
                permissions: BTreeMap::new(),
            },
            profiles: BTreeMap::new(),
            ssh_profiles: profiles,
        }
    }

    fn profile(authentication: &str, signing: &str) -> SshProfile {
        SshProfile {
            keys: vec![
                SshKey {
                    purpose: SshKeyPurpose::Authentication,
                    private_key_ref: "op://Automation/ssh-auth/private-key".into(),
                    fingerprint: authentication.into(),
                },
                SshKey {
                    purpose: SshKeyPurpose::Signing,
                    private_key_ref: "op://Automation/ssh-sign/private-key".into(),
                    fingerprint: signing.into(),
                },
            ],
        }
    }

    #[test]
    fn signing_agent_must_match_exactly_one_declared_profile() {
        let authentication = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let signing = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let loaded = BTreeSet::from([authentication.into(), signing.into()]);
        let config = config_with_profiles(BTreeMap::from([(
            "automation".into(),
            profile(authentication, signing),
        )]));
        assert!(unique_declared_ssh_profile(&config, &loaded).is_ok());

        let wrong = BTreeSet::from([authentication.into()]);
        assert!(unique_declared_ssh_profile(&config, &wrong).is_err());

        let duplicated = config_with_profiles(BTreeMap::from([
            ("automation".into(), profile(authentication, signing)),
            ("duplicate".into(), profile(authentication, signing)),
        ]));
        assert!(unique_declared_ssh_profile(&duplicated, &loaded).is_err());
    }

    #[test]
    fn credential_store_keeps_only_the_session_bus_context() {
        let retained = secret_service_environment([
            (
                "DBUS_SESSION_BUS_ADDRESS".into(),
                "unix:path=/run/user/1000/bus".into(),
            ),
            ("XDG_RUNTIME_DIR".into(), "/run/user/1000".into()),
            ("DISPLAY".into(), ":0".into()),
            ("OP_SERVICE_ACCOUNT_TOKEN".into(), "must-not-survive".into()),
        ]);
        assert_eq!(retained.len(), 2);
        assert_eq!(
            retained.get(&OsString::from("DBUS_SESSION_BUS_ADDRESS")),
            Some(&OsString::from("unix:path=/run/user/1000/bus"))
        );
        assert_eq!(
            retained.get(&OsString::from("XDG_RUNTIME_DIR")),
            Some(&OsString::from("/run/user/1000"))
        );
    }

    #[test]
    fn git_signing_requires_the_declared_signing_public_key() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let signing_key = directory.path().join("signing");
        let authentication_key = directory.path().join("authentication");
        for key in [&signing_key, &authentication_key] {
            assert!(Command::new(SSH_KEYGEN)
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(key)
                .status()
                .unwrap()
                .success());
        }
        let fingerprint = |key: &Path| {
            let output = Command::new(SSH_KEYGEN)
                .args(["-lf"])
                .arg(key.with_extension("pub"))
                .args(["-E", "sha256"])
                .output()
                .unwrap();
            String::from_utf8(output.stdout)
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
                .to_owned()
        };
        let profile = profile(
            &fingerprint(&authentication_key),
            &fingerprint(&signing_key),
        );
        let arguments = |key: &Path| {
            vec![
                "-Y".into(),
                "sign".into(),
                "-n".into(),
                "git".into(),
                "-f".into(),
                key.with_extension("pub").display().to_string(),
            ]
        };
        assert!(validate_signing_key_argument(&arguments(&signing_key), &profile).is_ok());
        assert!(validate_signing_key_argument(&arguments(&authentication_key), &profile).is_err());
        let mut wrong_namespace = arguments(&signing_key);
        wrong_namespace[3] = "file".into();
        assert!(validate_signing_key_argument(&wrong_namespace, &profile).is_err());
    }
}
