use crate::SshKeyPurpose;
use crate::{
    parse_config, render_git_credential, sanitize_environment, CacheEntry, Config,
    CredentialRequest, CredentialStore, ExecProfile, SecretString, SelectedRepository, SshProfile,
};
use anyhow::{bail, Context, Result};
use directories::{BaseDirs, ProjectDirs};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use fs2::FileExt;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signature::Signer;
use ssh_agent_lib::agent::{listen, Session};
#[cfg(windows)]
use ssh_agent_lib::agent::{Agent, ListeningSocket};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, PublicCredential, SignRequest};
use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::{Algorithm as SshAlgorithm, HashAlg, PrivateKey, PublicKey, Signature};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
#[cfg(unix)]
use tokio::net::UnixListener;

const CONFIG_LIMIT: u64 = 1024 * 1024;
const RESPONSE_LIMIT: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStatus {
    pub config_ready: bool,
    pub service_token_enrolled: bool,
    pub runtime_ready: bool,
    pub ssh_agent_ready: bool,
    pub cached_installation_tokens: usize,
}

#[derive(Debug)]
struct RuntimePaths {
    config: PathBuf,
    runtime: PathBuf,
}

impl RuntimePaths {
    fn discover() -> Result<Self> {
        let project = ProjectDirs::from("", "", "dev-auth")
            .context("the operating system has no user configuration directory")?;
        let base = BaseDirs::new().context("the operating system has no user home directory")?;
        let login_runtime = secure_login_runtime_dir();
        let runtime_root = select_runtime_root(
            base.runtime_dir(),
            login_runtime.as_deref(),
            project.cache_dir(),
        );
        Ok(Self {
            config: project.config_dir().join("config.toml"),
            runtime: runtime_root,
        })
    }

    fn cache_dir(&self) -> PathBuf {
        self.runtime.join("github-installation-tokens")
    }
}

fn select_runtime_root(
    environment_runtime: Option<&Path>,
    login_runtime: Option<&Path>,
    cache: &Path,
) -> PathBuf {
    environment_runtime
        .or(login_runtime)
        .map(|path| path.join("dev-auth"))
        .unwrap_or_else(|| cache.join("runtime"))
}

#[cfg(target_os = "linux")]
fn secure_login_runtime_dir() -> Option<PathBuf> {
    let path = PathBuf::from("/run/user").join(rustix::process::geteuid().as_raw().to_string());
    let metadata = fs::symlink_metadata(&path).ok()?;
    if metadata.file_type().is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.permissions().mode() & 0o077 == 0
    {
        Some(path)
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
fn secure_login_runtime_dir() -> Option<PathBuf> {
    None
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
    #[cfg(unix)]
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        bail!("{description} is not owned by the current user");
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("{description} permissions must not grant group or other access");
    }
    Ok(())
}

fn private_read(path: &Path, description: &str) -> Result<File> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {description} at {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("{description} must be a non-symlink regular file");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    let file = options
        .open(path)
        .with_context(|| format!("open {description} at {}", path.display()))?;
    validate_open_private_file(&file, description)?;
    Ok(file)
}

fn validate_open_private_file(file: &File, description: &str) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {description}"))?;
    if !metadata.file_type().is_file() {
        bail!("{description} is not a regular file");
    }
    #[cfg(unix)]
    if metadata.uid() != rustix::process::geteuid().as_raw()
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
        builder.recursive(false);
        #[cfg(unix)]
        builder.mode(0o700);
        builder
            .create(path)
            .with_context(|| format!("create private runtime directory {}", path.display()))?;
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect private runtime directory {}", path.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!("private runtime path is not a directory");
    }
    #[cfg(unix)]
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        bail!("private runtime directory is not owned by the current user");
    }
    #[cfg(unix)]
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
    if !parent.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder
            .create(parent)
            .with_context(|| format!("create runtime root {}", parent.display()))?;
    }
    let parent_metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("inspect runtime root {}", parent.display()))?;
    if !parent_metadata.file_type().is_dir() || parent_metadata.file_type().is_symlink() {
        bail!("runtime root is not a directory");
    }
    #[cfg(unix)]
    if parent_metadata.uid() != rustix::process::geteuid().as_raw()
        || parent_metadata.permissions().mode() & 0o077 != 0
    {
        bail!("runtime root is not a private current-user directory");
    }
    ensure_private_directory(&paths.runtime)?;
    ensure_private_directory(&paths.cache_dir())?;
    remove_legacy_token_files(paths)?;
    Ok(())
}

fn remove_legacy_token_files(paths: &RuntimePaths) -> Result<()> {
    for entry in fs::read_dir(paths.cache_dir()).context("enumerate runtime cache")? {
        let entry = entry.context("read runtime cache entry")?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let _ = private_read(&path, "legacy installation-token cache")?;
            fs::remove_file(&path).context("remove legacy file-backed installation-token cache")?;
        }
    }
    Ok(())
}

fn credential_entry(store: &CredentialStore) -> Result<Entry> {
    Entry::new(&store.service, &store.account).context("open native OS credential-store entry")
}

fn sanitized_current_environment() -> BTreeMap<String, String> {
    let input: BTreeMap<String, String> = env::vars().collect();
    sanitize_environment(&input, &BTreeSet::new())
}

fn service_account_token(store: &CredentialStore) -> Result<SecretString> {
    let value = credential_entry(store)?
        .get_password()
        .context("the dev-auth service credential is not enrolled or the keyring is locked")?;
    if value.is_empty() || value.contains(['\n', '\r', '\0']) {
        bail!("credential-store value is malformed");
    }
    Ok(SecretString::new(value))
}

pub fn enroll_service_account_token(value: &[u8]) -> Result<()> {
    let paths = RuntimePaths::discover()?;
    let config = load_config(&paths)?;
    let value = std::str::from_utf8(value).context("service credential is not UTF-8")?;
    let value = value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value);
    if value.is_empty() || value.contains(['\n', '\r', '\0']) {
        bail!("service credential must be exactly one nonempty line");
    }
    credential_entry(&config.credential_store)?
        .set_password(value)
        .context("store service credential in the native OS credential store")
}

fn read_declared_secret(config: &Config, reference: &str) -> Result<SecretString> {
    crate::validate_op_reference(reference)?;
    let service_token = service_account_token(&config.credential_store)?;
    let output = Command::new(&config.programs.op)
        .args(["read", "--no-newline", reference])
        .env_clear()
        .envs(sanitized_current_environment())
        .env("OP_SERVICE_ACCOUNT_TOKEN", service_token.expose())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("run bounded 1Password item read")?;
    if !output.status.success() {
        bail!("1Password denied the declared item read");
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
    repositories: [&'a str; 1],
    permissions: &'a BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct InstallationTokenResponse {
    token: String,
    expires_at: String,
    permissions: BTreeMap<String, String>,
    repository_selection: String,
}

#[derive(Deserialize)]
struct RepositoryResponse {
    id: u64,
    full_name: String,
}

#[derive(Deserialize)]
struct InstallationAccountResponse {
    login: String,
}

#[derive(Deserialize)]
struct RepositoryInstallationResponse {
    id: u64,
    app_id: u64,
    account: InstallationAccountResponse,
    permissions: BTreeMap<String, String>,
    suspended_at: Option<serde_json::Value>,
}

fn github_app_jwt(config: &Config, now: i64) -> Result<String> {
    let private_key = read_declared_secret(config, &config.github.private_key_ref)?;
    let key = EncodingKey::from_rsa_pem(private_key.expose().as_bytes())
        .context("GitHub App private key is not a valid RSA PEM key")?;
    encode(
        &Header::new(Algorithm::RS256),
        &AppJwtClaims {
            iat: now - 60,
            exp: now + 540,
            iss: config.github.app_id.to_string(),
        },
        &key,
    )
    .context("sign GitHub App JWT")
}

fn github_api_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(true)
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(format!("dev-auth/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

fn discover_repository_installation(
    config: &Config,
    owner: &str,
    repository: &str,
    now: i64,
) -> Result<SelectedRepository> {
    let jwt = github_app_jwt(config, now)?;
    let url = format!("https://api.github.com/repos/{owner}/{repository}/installation");
    let mut response = github_api_agent()
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("X-GitHub-Api-Version", "2026-03-10")
        .call()
        .context("discover exact repository GitHub App installation")?;
    if !response.status().is_success() {
        bail!(
            "GitHub App repository installation lookup returned HTTP {}",
            response.status()
        );
    }
    let bytes = response
        .body_mut()
        .with_config()
        .limit(RESPONSE_LIMIT)
        .read_to_vec()
        .context("read bounded GitHub App installation response")?;
    validate_repository_installation_response(config, owner, repository, &bytes)
}

fn validate_repository_installation_response(
    config: &Config,
    owner: &str,
    repository: &str,
    bytes: &[u8],
) -> Result<SelectedRepository> {
    let installation: RepositoryInstallationResponse = serde_json::from_slice(bytes)
        .context("parse GitHub App repository installation response")?;
    if installation.id == 0
        || installation.app_id != config.github.app_id
        || !installation.account.login.eq_ignore_ascii_case(owner)
        || installation.permissions != config.github.permissions
        || installation.suspended_at.is_some()
    {
        bail!("GitHub App repository installation does not match the declared authority");
    }
    Ok(SelectedRepository {
        installation_id: installation.id,
        owner: owner.to_ascii_lowercase(),
        repository: repository.to_ascii_lowercase(),
    })
}

fn mint_installation_token(
    config: &Config,
    installation_id: u64,
    owner: &str,
    repository: &str,
    now: i64,
) -> Result<CacheEntry> {
    let jwt = github_app_jwt(config, now)?;
    let agent = github_api_agent();
    let url = format!("https://api.github.com/app/installations/{installation_id}/access_tokens");
    let mut response = agent
        .post(&url)
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("X-GitHub-Api-Version", "2026-03-10")
        .send_json(&InstallationTokenRequest {
            repositories: [repository],
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
        || response.permissions != config.github.permissions
        || response.repository_selection != "selected"
    {
        bail!("GitHub returned an invalid installation token contract");
    }
    let expected_full_name = format!("{owner}/{repository}");
    let repository_url = format!("https://api.github.com/repos/{expected_full_name}");
    let mut repository_response = agent
        .get(&repository_url)
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {}", response.token))
        .header("X-GitHub-Api-Version", "2026-03-10")
        .call()
        .context("validate narrowed GitHub App repository token")?;
    if !repository_response.status().is_success() {
        bail!(
            "GitHub repository scope validation returned HTTP {}",
            repository_response.status()
        );
    }
    let repository_bytes = repository_response
        .body_mut()
        .with_config()
        .limit(RESPONSE_LIMIT)
        .read_to_vec()
        .context("read bounded GitHub repository response")?;
    let repository_response: RepositoryResponse = serde_json::from_slice(&repository_bytes)
        .context("parse GitHub repository scope response")?;
    if repository_response.id == 0
        || !repository_response
            .full_name
            .eq_ignore_ascii_case(&expected_full_name)
    {
        bail!("GitHub repository token scope does not match the requested repository");
    }
    Ok(CacheEntry::new(
        SecretString::new(response.token),
        expires_at,
        installation_id,
        owner.to_ascii_lowercase(),
        repository.to_owned(),
        config.github.permissions.clone(),
    ))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheFile {
    token: String,
    expires_at: i64,
    installation_id: u64,
    owner: String,
    repository: String,
    permissions: BTreeMap<String, String>,
}

impl From<&CacheEntry> for CacheFile {
    fn from(entry: &CacheEntry) -> Self {
        Self {
            token: entry.token().expose().to_owned(),
            expires_at: entry.expires_at(),
            installation_id: entry.installation_id(),
            owner: entry.owner().to_owned(),
            repository: entry.repository().to_owned(),
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
            value.owner,
            value.repository,
            value.permissions,
        )
    }
}

fn cache_key(
    installation_id: u64,
    repository: &str,
    permissions: &BTreeMap<String, String>,
) -> Result<String> {
    let public_scope = serde_json::to_vec(&(installation_id, repository, permissions))
        .context("serialize installation-token cache scope")?;
    Ok(format!("{:x}", Sha256::digest(public_scope)))
}

fn dynamic_cache_key(
    owner: &str,
    repository: &str,
    permissions: &BTreeMap<String, String>,
) -> Result<String> {
    let public_scope = serde_json::to_vec(&(
        "dynamic",
        owner.to_ascii_lowercase(),
        repository.to_ascii_lowercase(),
        permissions,
    ))
    .context("serialize dynamic installation-token cache scope")?;
    Ok(format!("{:x}", Sha256::digest(public_scope)))
}

fn locked_cache_entry<F>(
    paths: &RuntimePaths,
    store: &CredentialStore,
    installation_id: u64,
    owner: &str,
    repository: &str,
    permissions: &BTreeMap<String, String>,
    create: F,
) -> Result<CacheEntry>
where
    F: FnOnce() -> Result<CacheEntry>,
{
    ensure_runtime(paths)?;
    let key = cache_key(installation_id, repository, permissions)?;
    let lock_path = paths.cache_dir().join(format!("{key}.lock"));
    let lock = private_open(&lock_path)?;
    lock.lock_exclusive()
        .context("lock installation-token cache")?;
    let now = OffsetDateTime::now_utc().unix_timestamp();

    if let Ok(entry) = read_cache(store, &key) {
        if entry.is_usable_at(now, installation_id, owner, repository, permissions) {
            return Ok(entry);
        }
    }
    let entry = create()?;
    if !entry.is_usable_at(now, installation_id, owner, repository, permissions) {
        bail!("new installation token is not usable for the requested scope");
    }
    write_cache(store, &key, &entry)?;
    Ok(entry)
}

fn locked_dynamic_cache_entry(
    paths: &RuntimePaths,
    config: &Config,
    owner: &str,
    repository: &str,
) -> Result<CacheEntry> {
    ensure_runtime(paths)?;
    let owner = owner.to_ascii_lowercase();
    let repository = repository.to_ascii_lowercase();
    let key = dynamic_cache_key(&owner, &repository, &config.github.permissions)?;
    let lock_path = paths.cache_dir().join(format!("{key}.lock"));
    let lock = private_open(&lock_path)?;
    lock.lock_exclusive()
        .context("lock dynamic installation-token cache")?;
    let now = OffsetDateTime::now_utc().unix_timestamp();

    if let Ok(entry) = read_cache(&config.credential_store, &key) {
        if entry.is_usable_for_repository_at(now, &owner, &repository, &config.github.permissions) {
            return Ok(entry);
        }
    }

    let selected = discover_repository_installation(config, &owner, &repository, now)?;
    let entry = mint_installation_token(
        config,
        selected.installation_id,
        &selected.owner,
        &selected.repository,
        OffsetDateTime::now_utc().unix_timestamp(),
    )?;
    if !entry.is_usable_for_repository_at(now, &owner, &repository, &config.github.permissions) {
        bail!("new installation token is not usable for the requested repository");
    }
    write_cache(&config.credential_store, &key, &entry)?;
    Ok(entry)
}

fn private_open(path: &Path) -> Result<File> {
    if path.is_symlink() {
        bail!("private runtime path must not be a symlink");
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    options
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .mode(0o600);
    let file = options
        .open(path)
        .with_context(|| format!("open private runtime file {}", path.display()))?;
    validate_open_private_file(&file, "private runtime file")?;
    Ok(file)
}

fn cache_entry(store: &CredentialStore, key: &str) -> Result<Entry> {
    Entry::new(&format!("{}:github-installation-token", store.service), key)
        .context("open native installation-token cache entry")
}

fn read_cache(store: &CredentialStore, key: &str) -> Result<CacheEntry> {
    let secret = cache_entry(store, key)?
        .get_password()
        .context("read native installation-token cache")?;
    let value: CacheFile =
        serde_json::from_str(&secret).context("parse installation-token cache")?;
    if value.token.is_empty() || value.token.contains(['\n', '\r', '\0']) {
        bail!("installation-token cache is malformed");
    }
    Ok(value.into())
}

fn write_cache(store: &CredentialStore, key: &str, entry: &CacheEntry) -> Result<()> {
    let secret = serde_json::to_string(&CacheFile::from(entry))
        .context("serialize installation-token cache")?;
    cache_entry(store, key)?
        .set_password(&secret)
        .context("write native installation-token cache")
}

fn token_entry_for_repository(
    paths: &RuntimePaths,
    config: &Config,
    owner: &str,
    repository: &str,
) -> Result<CacheEntry> {
    if config.github.discover_installations {
        return locked_dynamic_cache_entry(paths, config, owner, repository);
    }
    let selected = config.github.select_repository(owner, repository)?;
    locked_cache_entry(
        paths,
        &config.credential_store,
        selected.installation_id,
        &selected.owner,
        &selected.repository,
        &config.github.permissions,
        || {
            mint_installation_token(
                config,
                selected.installation_id,
                &selected.owner,
                &selected.repository,
                OffsetDateTime::now_utc().unix_timestamp(),
            )
        },
    )
}

pub fn credential_get(input: &[u8]) -> Result<String> {
    let paths = RuntimePaths::discover()?;
    let config = load_config(&paths)?;
    let request = CredentialRequest::parse(input)?;
    let (owner, repository) = request.repository()?;
    let entry = token_entry_for_repository(&paths, &config, owner, repository)?;
    render_git_credential(entry.token().expose(), entry.expires_at())
}

pub fn github_token_for_repository(owner: &str, repository: &str) -> Result<SecretString> {
    let paths = RuntimePaths::discover()?;
    let config = load_config(&paths)?;
    let entry = token_entry_for_repository(&paths, &config, owner, repository)?;
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
    if let Some(value) = repo_view_positional_repository(arguments)? {
        if selected.as_ref().is_some_and(|current| current != &value) {
            bail!("gh command contains conflicting repository selectors");
        }
        selected = Some(value);
    }
    Ok(selected)
}

fn repo_view_positional_repository(arguments: &[String]) -> Result<Option<String>> {
    if arguments.first().map(String::as_str) != Some("repo")
        || arguments.get(1).map(String::as_str) != Some("view")
    {
        return Ok(None);
    }

    let mut positional: Option<String> = None;
    let mut index = 2;
    let mut options_ended = false;
    while index < arguments.len() {
        let argument = &arguments[index];
        if !options_ended && argument == "--" {
            options_ended = true;
            index += 1;
            continue;
        }
        if !options_ended && matches!(argument.as_str(), "-R" | "--repo") {
            index += 1;
            arguments
                .get(index)
                .context("gh repository flag has no value")?;
        } else if !options_ended
            && matches!(
                argument.as_str(),
                "-b" | "--branch" | "-q" | "--jq" | "--json" | "-t" | "--template"
            )
        {
            index += 1;
            arguments
                .get(index)
                .with_context(|| format!("gh repo view flag {argument} has no value"))?;
        } else if !options_ended
            && (matches!(argument.as_str(), "-w" | "--web" | "--help")
                || argument.starts_with("--repo=")
                || ["--branch=", "--jq=", "--json=", "--template="]
                    .iter()
                    .any(|prefix| argument.starts_with(prefix)))
        {
            // Flag is complete in this argument.
        } else if !options_ended && argument.starts_with('-') {
            bail!("unsupported gh repo view flag: {argument}");
        } else {
            crate::parse_github_repository(argument)?;
            if positional.is_some() {
                bail!("gh repo view contains more than one positional repository");
            }
            positional = Some(argument.clone());
        }
        index += 1;
    }
    Ok(positional)
}

fn forwarded_gh_arguments(
    arguments: &[String],
    owner: &str,
    repository: &str,
) -> Result<Vec<String>> {
    if arguments.first().map(String::as_str) != Some("repo")
        || arguments.get(1).map(String::as_str) != Some("view")
        || repo_view_positional_repository(arguments)?.is_some()
    {
        return Ok(arguments.to_vec());
    }

    let mut forwarded = Vec::with_capacity(arguments.len() + 1);
    forwarded.extend_from_slice(&arguments[..2]);
    forwarded.push(format!("{owner}/{repository}"));
    let mut index = 2;
    while index < arguments.len() {
        if matches!(arguments[index].as_str(), "-R" | "--repo") {
            index += 2;
        } else if arguments[index].starts_with("--repo=") {
            index += 1;
        } else {
            forwarded.push(arguments[index].clone());
            index += 1;
        }
    }
    Ok(forwarded)
}

fn origin_repository(program: &str) -> Result<String> {
    let output = Command::new(program)
        .args(["remote", "get-url", "origin"])
        .env_clear()
        .envs(sanitized_current_environment())
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

fn resolve_gh_repository(arguments: &[String], git_program: &str) -> Result<(String, String)> {
    let selected = match explicit_gh_repository(arguments)? {
        Some(value) => value,
        None => match env::var("GH_REPO") {
            Ok(value) => value,
            Err(_) => origin_repository(git_program)?,
        },
    };
    crate::parse_github_repository(&selected)
}

pub fn run_gh(arguments: &[String]) -> Result<ExitStatus> {
    crate::admit_gh_arguments(arguments)?;
    let paths = RuntimePaths::discover()?;
    let config = load_config(&paths)?;
    let (owner, repository) = resolve_gh_repository(arguments, &config.programs.git)?;
    let forwarded = forwarded_gh_arguments(arguments, &owner, &repository)?;
    let entry = token_entry_for_repository(&paths, &config, &owner, &repository)?;
    let token = entry.token().clone();
    let input: BTreeMap<String, String> = env::vars().collect();
    let mut environment = sanitize_environment(&input, &BTreeSet::new());
    environment.insert("GH_TOKEN".into(), token.expose().into());
    environment.insert("GH_PROMPT_DISABLED".into(), "1".into());
    environment.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
    environment.insert("GH_REPO".into(), format!("{owner}/{repository}"));
    Command::new(&config.programs.gh)
        .args(forwarded)
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
    ensure_runtime(&paths)?;
    let key = if config.github.discover_installations {
        dynamic_cache_key(owner, repository, &config.github.permissions)?
    } else {
        let selected = config.github.select_repository(owner, repository)?;
        cache_key(
            selected.installation_id,
            &selected.repository,
            &config.github.permissions,
        )?
    };
    match cache_entry(&config.credential_store, &key)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => {}
        Err(error) => return Err(error).context("remove native installation-token cache"),
    }
    let lock = paths.cache_dir().join(format!("{key}.lock"));
    match fs::remove_file(lock) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("remove installation-token cache lock"),
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
            read_declared_secret(&config, reference)?.expose().into(),
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

#[cfg(unix)]
fn ssh_agent_socket(paths: &RuntimePaths) -> PathBuf {
    paths.runtime.join("ssh-agent.sock")
}

#[cfg(windows)]
fn ssh_agent_pipe(paths: &RuntimePaths) -> String {
    let identity = Sha256::digest(paths.config.to_string_lossy().as_bytes());
    format!(r"\\.\pipe\dev-auth-ssh-agent-{identity:x}")
}

#[cfg(windows)]
#[derive(Debug)]
struct PrivateNamedPipeListener {
    server: NamedPipeServer,
    name: std::ffi::OsString,
}

#[cfg(windows)]
impl PrivateNamedPipeListener {
    fn bind(name: impl Into<std::ffi::OsString>) -> io::Result<Self> {
        let name = name.into();
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(&name)?;
        Ok(Self { server, name })
    }

    fn next_server(&self) -> io::Result<NamedPipeServer> {
        ServerOptions::new()
            .reject_remote_clients(true)
            .create(&self.name)
    }
}

#[cfg(windows)]
#[ssh_agent_lib::async_trait]
impl ListeningSocket for PrivateNamedPipeListener {
    type Stream = NamedPipeServer;

    async fn accept(&mut self) -> io::Result<Self::Stream> {
        self.server.connect().await?;
        let next = self.next_server()?;
        Ok(std::mem::replace(&mut self.server, next))
    }
}

#[cfg(unix)]
fn ssh_agent_endpoint(paths: &RuntimePaths) -> Result<String> {
    ssh_agent_socket(paths)
        .into_os_string()
        .into_string()
        .map_err(|_| anyhow::anyhow!("SSH agent socket path is not UTF-8"))
}

#[cfg(windows)]
fn ssh_agent_endpoint(paths: &RuntimePaths) -> Result<String> {
    Ok(ssh_agent_pipe(paths))
}

pub fn agent_endpoint() -> Result<String> {
    ssh_agent_endpoint(&RuntimePaths::discover()?)
}

#[cfg(unix)]
fn validate_ssh_agent_socket(paths: &RuntimePaths) -> Result<PathBuf> {
    let socket = ssh_agent_socket(paths);
    let metadata = fs::symlink_metadata(&socket).context("inspect dedicated SSH agent socket")?;
    if !metadata.file_type().is_socket() || metadata.uid() != rustix::process::geteuid().as_raw() {
        bail!("dedicated SSH agent socket is unavailable or not current-user owned");
    }
    Ok(socket)
}

fn ssh_add_command(paths: &RuntimePaths, config: &Config) -> Result<Command> {
    #[cfg(unix)]
    validate_ssh_agent_socket(paths)?;
    let mut command = Command::new(&config.programs.ssh_add);
    command
        .env_clear()
        .envs(sanitized_current_environment())
        .env("SSH_AUTH_SOCK", ssh_agent_endpoint(paths)?)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(command)
}

pub fn run_ssh_keygen(arguments: &[String]) -> Result<ExitStatus> {
    let paths = RuntimePaths::discover()?;
    let config = load_config(&paths)?;
    if is_git_verification_operation(arguments)? {
        return Command::new(&config.programs.ssh_keygen)
            .args(arguments)
            .env_clear()
            .envs(sanitized_current_environment())
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .context("run public OpenSSH Git verification");
    }
    ensure_runtime(&paths)?;
    #[cfg(unix)]
    validate_ssh_agent_socket(&paths)?;
    let loaded = loaded_ssh_fingerprints(&paths, &config)?;
    let profile = unique_declared_ssh_profile(&config, &loaded)?;
    validate_signing_key_argument(arguments, profile, &config.programs.ssh_keygen)?;
    let input: BTreeMap<String, String> = env::vars().collect();
    let mut environment = sanitize_environment(&input, &BTreeSet::new());
    environment.insert("SSH_AUTH_SOCK".into(), ssh_agent_endpoint(&paths)?);
    Command::new(&config.programs.ssh_keygen)
        .args(arguments)
        .env_clear()
        .envs(environment)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("run OpenSSH key operation with the dedicated agent")
}

fn is_git_verification_operation(arguments: &[String]) -> Result<bool> {
    let operation = exact_option_value(arguments, "-Y")?;
    match operation {
        "sign" => Ok(false),
        "find-principals" => Ok(true),
        "verify" => {
            if exact_option_value(arguments, "-n")? != "git" {
                bail!("automation verification is restricted to the git namespace");
            }
            Ok(true)
        }
        _ => bail!("unsupported OpenSSH operation for Git signing or verification"),
    }
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

fn validate_signing_key_argument(
    arguments: &[String],
    profile: &SshProfile,
    ssh_keygen_program: &str,
) -> Result<()> {
    if exact_option_value(arguments, "-Y")? != "sign" {
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
    let output = Command::new(ssh_keygen_program)
        .args(["-lf", public_key, "-E", "sha256"])
        .env_clear()
        .envs(sanitized_current_environment())
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
        .with_context(|| format!("OpenSSH operation requires exactly one {option} value"))?;
    if values.next().is_some() || value.starts_with('-') {
        bail!("OpenSSH operation requires exactly one {option} value");
    }
    Ok(value)
}

fn clear_ssh_agent(paths: &RuntimePaths, config: &Config) -> Result<()> {
    let status = ssh_add_command(paths, config)?
        .arg("-D")
        .stdin(Stdio::null())
        .status()
        .context("clear dedicated SSH agent")?;
    if !status.success() {
        bail!("dedicated SSH agent rejected key removal");
    }
    Ok(())
}

fn loaded_ssh_fingerprints(paths: &RuntimePaths, config: &Config) -> Result<BTreeSet<String>> {
    let output = ssh_add_command(paths, config)?
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
    let expected: BTreeSet<String> = profile
        .keys
        .iter()
        .map(|key| key.fingerprint.clone())
        .collect();
    let loaded = loaded_ssh_fingerprints(&paths, &config)?;
    if loaded != expected {
        bail!("dedicated SSH agent fingerprints do not match the declared profile");
    }
    Ok(())
}

struct AgentIdentity {
    private_key: PrivateKey,
    public_key: PublicKey,
    fingerprint: String,
}

#[derive(Clone)]
struct DeclaredAgent {
    identities: Arc<RwLock<Vec<AgentIdentity>>>,
}

impl DeclaredAgent {
    fn new(identities: Vec<AgentIdentity>) -> Self {
        Self {
            identities: Arc::new(RwLock::new(identities)),
        }
    }
}

fn agent_failure(message: &'static str) -> AgentError {
    AgentError::other(io::Error::other(message))
}

#[ssh_agent_lib::async_trait]
impl Session for DeclaredAgent {
    async fn request_identities(&mut self) -> std::result::Result<Vec<Identity>, AgentError> {
        let identities = self
            .identities
            .read()
            .map_err(|_| agent_failure("SSH identity lock is poisoned"))?;
        Ok(identities
            .iter()
            .map(|identity| Identity {
                credential: PublicCredential::Key(identity.public_key.key_data().clone()),
                comment: format!("dev-auth:{}", identity.fingerprint),
            })
            .collect())
    }

    async fn sign(&mut self, request: SignRequest) -> std::result::Result<Signature, AgentError> {
        if request.flags != 0 {
            return Err(agent_failure("unsupported SSH signature flags"));
        }
        let PublicCredential::Key(requested) = request.credential else {
            return Err(agent_failure(
                "SSH certificates are not declared identities",
            ));
        };
        let identities = self
            .identities
            .read()
            .map_err(|_| agent_failure("SSH identity lock is poisoned"))?;
        let identity = identities
            .iter()
            .find(|identity| identity.public_key.key_data() == &requested)
            .ok_or_else(|| agent_failure("SSH signing identity is not declared"))?;
        identity
            .private_key
            .try_sign(&request.data)
            .map_err(AgentError::other)
    }

    async fn remove_all_identities(&mut self) -> std::result::Result<(), AgentError> {
        self.identities
            .write()
            .map_err(|_| agent_failure("SSH identity lock is poisoned"))?
            .clear();
        Ok(())
    }
}

#[cfg(windows)]
impl Agent<PrivateNamedPipeListener> for DeclaredAgent {
    fn new_session(&mut self, _socket: &NamedPipeServer) -> impl Session {
        self.clone()
    }
}

fn parse_declared_ssh_private_key(source: &SecretString) -> Result<PrivateKey> {
    if let Ok(private_key) = PrivateKey::from_openssh(source.expose().as_bytes()) {
        return Ok(private_key);
    }
    let signing_key = ed25519_dalek::SigningKey::from_pkcs8_pem(source.expose())
        .map_err(|_| anyhow::anyhow!("declared SSH key is not supported private-key material"))?;
    PrivateKey::new(
        KeypairData::Ed25519(Ed25519Keypair::from(signing_key)),
        "dev-auth automation key",
    )
    .context("construct declared Ed25519 SSH key")
}

fn declared_agent(config: &Config, profile: &SshProfile) -> Result<DeclaredAgent> {
    let mut identities = Vec::with_capacity(profile.keys.len());
    for declared in &profile.keys {
        let source = read_declared_secret(config, &declared.private_key_ref)?;
        let private_key = parse_declared_ssh_private_key(&source)?;
        if private_key.is_encrypted() || private_key.algorithm() != SshAlgorithm::Ed25519 {
            bail!("declared SSH key must be an unencrypted Ed25519 OpenSSH key");
        }
        let public_key = private_key.public_key().clone();
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        if fingerprint != declared.fingerprint {
            bail!("declared SSH key fingerprint does not match its private key");
        }
        identities.push(AgentIdentity {
            private_key,
            public_key,
            fingerprint,
        });
    }
    Ok(DeclaredAgent::new(identities))
}

#[cfg(unix)]
fn prepare_unix_agent_socket(paths: &RuntimePaths) -> Result<UnixListener> {
    let socket = ssh_agent_socket(paths);
    if socket.exists() {
        let metadata = fs::symlink_metadata(&socket).context("inspect stale SSH agent socket")?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            bail!("existing SSH agent endpoint is not a current-user socket");
        }
        fs::remove_file(&socket).context("remove stale SSH agent socket")?;
    }
    UnixListener::bind(&socket).context("bind dedicated SSH agent socket")
}

pub fn run_agent(profile_name: &str) -> Result<()> {
    let paths = RuntimePaths::discover()?;
    ensure_runtime(&paths)?;
    let config = load_config(&paths)?;
    let profile = config
        .ssh_profiles
        .get(profile_name)
        .context("requested SSH profile is not declared")?;
    let lock = private_open(&paths.runtime.join("ssh-agent.lock"))?;
    lock.try_lock_exclusive()
        .context("another dedicated SSH agent is already active")?;
    let agent = declared_agent(&config, profile)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .context("create dedicated SSH agent runtime")?;

    #[cfg(unix)]
    {
        let listener = {
            let _runtime_guard = runtime.enter();
            prepare_unix_agent_socket(&paths)?
        };
        let result = runtime.block_on(listen(listener, agent));
        let _ = fs::remove_file(ssh_agent_socket(&paths));
        result.context("run dedicated SSH agent")?;
    }
    #[cfg(windows)]
    {
        let listener = {
            let _runtime_guard = runtime.enter();
            PrivateNamedPipeListener::bind(ssh_agent_pipe(&paths))
                .context("bind dedicated SSH agent named pipe")?
        };
        runtime
            .block_on(listen(listener, agent))
            .context("run dedicated SSH agent")?;
    }
    Ok(())
}

pub fn runtime_status() -> Result<RuntimeStatus> {
    let paths = RuntimePaths::discover()?;
    let config = load_config(&paths);
    let config_ready = config.is_ok();
    let service_token_enrolled = config
        .as_ref()
        .is_ok_and(|config| service_account_token(&config.credential_store).is_ok());
    let runtime_ready = ensure_runtime(&paths).is_ok();
    let ssh_agent_ready = config.as_ref().is_ok_and(|config| {
        config.ssh_profiles.is_empty()
            || loaded_ssh_fingerprints(&paths, config)
                .and_then(|loaded| unique_declared_ssh_profile(config, &loaded).map(|_| ()))
                .is_ok()
    });
    let cached_installation_tokens = config
        .as_ref()
        .ok()
        .and_then(|config| {
            fs::read_dir(paths.cache_dir()).ok().map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter_map(|entry| {
                        let path = entry.path();
                        if !path.extension().is_some_and(|value| value == "lock") {
                            return None;
                        }
                        path.file_stem()?.to_str().map(str::to_owned)
                    })
                    .filter(|key| read_cache(&config.credential_store, key).is_ok())
                    .count()
            })
        })
        .unwrap_or(0);
    Ok(RuntimeStatus {
        config_ready,
        service_token_enrolled,
        runtime_ready,
        ssh_agent_ready,
        cached_installation_tokens,
    })
}

pub fn purge_runtime() -> Result<()> {
    let paths = RuntimePaths::discover()?;
    let config = load_config(&paths)?;
    let cache_dir = paths.cache_dir();
    if !cache_dir.exists() {
        return Ok(());
    }
    ensure_runtime(&paths)?;
    if loaded_ssh_fingerprints(&paths, &config).is_ok() {
        clear_ssh_agent(&paths, &config)?;
    }
    for entry in fs::read_dir(&cache_dir).context("enumerate dev-auth runtime cache")? {
        let entry = entry.context("read dev-auth runtime cache entry")?;
        let path = entry.path();
        let extension = path.extension().and_then(|value| value.to_str());
        if extension == Some("lock") {
            let key = path
                .file_stem()
                .and_then(|value| value.to_str())
                .context("runtime lock has an invalid cache key")?;
            match cache_entry(&config.credential_store, key)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(error) => return Err(error).context("purge native installation-token cache"),
            }
            fs::remove_file(&path).context("remove installation-token cache lock")?;
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
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ssh_key::private::{Ed25519Keypair, KeypairData};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn config_with_profiles(profiles: BTreeMap<String, SshProfile>) -> Config {
        Config {
            version: 1,
            credential_store: CredentialStore::default(),
            programs: crate::Programs {
                op: "/usr/bin/op".into(),
                gh: "/usr/bin/gh".into(),
                git: "/usr/bin/git".into(),
                ssh_add: "/usr/bin/ssh-add".into(),
                ssh_keygen: "/usr/bin/ssh-keygen".into(),
            },
            github: GitHubProfile {
                app_id: 1,
                private_key_ref: "op://Machine Vault/app/private-key".into(),
                discover_installations: false,
                installations: Vec::new(),
                permissions: BTreeMap::new(),
            },
            profiles: BTreeMap::new(),
            ssh_profiles: profiles,
        }
    }

    #[test]
    fn installation_token_request_is_narrowed_by_repository_name() {
        let permissions = BTreeMap::from([("contents".into(), "write".into())]);
        let request = InstallationTokenRequest {
            repositories: ["brand-new-repository"],
            permissions: &permissions,
        };
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({
                "repositories": ["brand-new-repository"],
                "permissions": {"contents": "write"}
            })
        );
    }

    #[test]
    fn dynamic_cache_scope_is_case_insensitive_and_owner_specific() {
        let permissions = BTreeMap::from([("contents".into(), "write".into())]);
        let expected = dynamic_cache_key("ExampleOrg", "Sample-Repo", &permissions).unwrap();
        assert_eq!(
            expected,
            dynamic_cache_key("exampleorg", "sample-repo", &permissions).unwrap()
        );
        assert_ne!(
            expected,
            dynamic_cache_key("AnotherOrg", "sample-repo", &permissions).unwrap()
        );
    }

    #[test]
    fn repository_view_flag_is_translated_to_its_native_positional_selector() {
        let arguments = vec![
            "repo".into(),
            "view".into(),
            "-R".into(),
            "ExampleOrg/sample-repo".into(),
            "--json".into(),
            "nameWithOwner".into(),
        ];
        assert_eq!(
            forwarded_gh_arguments(&arguments, "ExampleOrg", "sample-repo").unwrap(),
            vec![
                "repo",
                "view",
                "ExampleOrg/sample-repo",
                "--json",
                "nameWithOwner"
            ]
        );
    }

    #[test]
    fn repository_view_injects_the_resolved_repository_when_no_selector_is_positional() {
        let arguments = vec![
            "repo".into(),
            "view".into(),
            "--json".into(),
            "nameWithOwner".into(),
        ];
        assert_eq!(
            forwarded_gh_arguments(&arguments, "ExampleOrg", "sample-repo").unwrap(),
            vec![
                "repo",
                "view",
                "ExampleOrg/sample-repo",
                "--json",
                "nameWithOwner"
            ]
        );
    }

    #[test]
    fn native_repository_flags_are_preserved_for_commands_that_support_them() {
        let arguments = vec![
            "pr".into(),
            "list".into(),
            "-R".into(),
            "ExampleOrg/sample-repo".into(),
        ];
        assert_eq!(
            forwarded_gh_arguments(&arguments, "ExampleOrg", "sample-repo").unwrap(),
            arguments
        );
    }

    #[test]
    fn repository_view_positional_selects_the_token_scope_and_is_forwarded() {
        let arguments = vec![
            "repo".into(),
            "view".into(),
            "ExampleOrg/sample-repo".into(),
            "--json".into(),
            "nameWithOwner".into(),
        ];
        assert_eq!(
            explicit_gh_repository(&arguments).unwrap(),
            Some("ExampleOrg/sample-repo".into())
        );
        assert_eq!(
            forwarded_gh_arguments(&arguments, "ExampleOrg", "sample-repo").unwrap(),
            arguments
        );
    }

    #[test]
    fn repository_view_positional_after_value_flag_selects_the_token_scope() {
        let arguments = vec![
            "repo".into(),
            "view".into(),
            "--json".into(),
            "nameWithOwner".into(),
            "ExampleOrg/sample-repo".into(),
        ];
        assert_eq!(
            explicit_gh_repository(&arguments).unwrap(),
            Some("ExampleOrg/sample-repo".into())
        );
        assert_eq!(
            forwarded_gh_arguments(&arguments, "ExampleOrg", "sample-repo").unwrap(),
            arguments
        );
    }

    #[test]
    fn repository_view_rejects_conflicting_flag_and_late_positional_selectors() {
        let arguments = vec![
            "repo".into(),
            "view".into(),
            "--repo".into(),
            "ExampleOrg/first".into(),
            "--json".into(),
            "nameWithOwner".into(),
            "ExampleOrg/second".into(),
        ];
        assert!(explicit_gh_repository(&arguments)
            .unwrap_err()
            .to_string()
            .contains("conflicting repository selectors"));
    }

    #[test]
    fn dynamic_installation_response_must_match_exact_repository_authority() {
        let mut config = config_with_profiles(BTreeMap::new());
        config.github.app_id = 42;
        config.github.discover_installations = true;
        config.github.permissions = crate::approved_github_permissions();
        let response = serde_json::json!({
            "id": 101,
            "app_id": 42,
            "account": {"login": "ExampleOrg"},
            "permissions": config.github.permissions,
            "suspended_at": null
        });
        let selected = validate_repository_installation_response(
            &config,
            "exampleorg",
            "New-Repository",
            &serde_json::to_vec(&response).unwrap(),
        )
        .unwrap();
        assert_eq!(selected.installation_id, 101);
        assert_eq!(selected.owner, "exampleorg");
        assert_eq!(selected.repository, "new-repository");

        let mut wrong_app = response;
        wrong_app["app_id"] = serde_json::json!(99);
        assert!(validate_repository_installation_response(
            &config,
            "exampleorg",
            "New-Repository",
            &serde_json::to_vec(&wrong_app).unwrap(),
        )
        .is_err());
    }

    fn profile(authentication: &str, signing: &str) -> SshProfile {
        SshProfile {
            keys: vec![
                SshKey {
                    purpose: SshKeyPurpose::Authentication,
                    private_key_ref: "op://Machine Vault/ssh-auth/private-key".into(),
                    fingerprint: authentication.into(),
                },
                SshKey {
                    purpose: SshKeyPurpose::Signing,
                    private_key_ref: "op://Machine Vault/ssh-sign/private-key".into(),
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
    fn dedicated_agent_exposes_only_declared_keys_and_supports_purge() {
        let private_key = PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[42; 32])),
            "test automation key",
        )
        .unwrap();
        let public_key = private_key.public_key().clone();
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        let mut agent = DeclaredAgent::new(vec![AgentIdentity {
            private_key,
            public_key: public_key.clone(),
            fingerprint: fingerprint.clone(),
        }]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        let identities = runtime.block_on(agent.request_identities()).unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].comment, format!("dev-auth:{fingerprint}"));
        let message = b"bounded automation signature";
        let signature = runtime
            .block_on(agent.sign(SignRequest {
                credential: PublicCredential::Key(public_key.key_data().clone()),
                data: message.to_vec(),
                flags: 0,
            }))
            .unwrap();
        signature::Verifier::verify(&public_key, message, &signature).unwrap();

        runtime.block_on(agent.remove_all_identities()).unwrap();
        assert!(runtime
            .block_on(agent.request_identities())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn declared_ssh_key_accepts_native_ssh_and_pkcs8_ed25519_encodings() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[21; 32]);
        let pkcs8 = signing_key.to_pkcs8_pem(Default::default()).unwrap();
        let parsed = parse_declared_ssh_private_key(&SecretString::new(pkcs8.to_string())).unwrap();
        assert_eq!(parsed.algorithm(), SshAlgorithm::Ed25519);

        let native = PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[22; 32])),
            "native test key",
        )
        .unwrap()
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap();
        let parsed =
            parse_declared_ssh_private_key(&SecretString::new(native.to_string())).unwrap();
        assert_eq!(parsed.algorithm(), SshAlgorithm::Ed25519);
    }

    #[cfg(unix)]
    #[test]
    fn git_signing_requires_the_declared_signing_public_key() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let signing_key = directory.path().join("signing");
        let authentication_key = directory.path().join("authentication");
        for key in [&signing_key, &authentication_key] {
            assert!(Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(key)
                .status()
                .unwrap()
                .success());
        }
        let fingerprint = |key: &Path| {
            let output = Command::new("ssh-keygen")
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
        assert!(
            validate_signing_key_argument(&arguments(&signing_key), &profile, "ssh-keygen").is_ok()
        );
        assert!(validate_signing_key_argument(
            &arguments(&authentication_key),
            &profile,
            "ssh-keygen"
        )
        .is_err());
        let mut wrong_namespace = arguments(&signing_key);
        wrong_namespace[3] = "file".into();
        assert!(validate_signing_key_argument(&wrong_namespace, &profile, "ssh-keygen").is_err());
    }

    #[test]
    fn git_verification_operations_are_public_and_bounded() {
        assert!(is_git_verification_operation(&[
            "-Y".into(),
            "find-principals".into(),
            "-f".into(),
            "/tmp/allowed-signers".into(),
        ])
        .unwrap());
        assert!(is_git_verification_operation(&[
            "-Y".into(),
            "verify".into(),
            "-n".into(),
            "git".into(),
        ])
        .unwrap());
        assert!(!is_git_verification_operation(&[
            "-Y".into(),
            "sign".into(),
            "-n".into(),
            "git".into(),
        ])
        .unwrap());
        assert!(is_git_verification_operation(&[
            "-Y".into(),
            "verify".into(),
            "-n".into(),
            "file".into(),
        ])
        .is_err());
        assert!(is_git_verification_operation(&["-t".into(), "ed25519".into()]).is_err());
    }

    #[test]
    fn login_runtime_precedes_cache_when_the_environment_is_missing() {
        assert_eq!(
            select_runtime_root(None, Some(Path::new("/run/user/1000")), Path::new("/cache")),
            PathBuf::from("/run/user/1000/dev-auth")
        );
        assert_eq!(
            select_runtime_root(None, None, Path::new("/cache")),
            PathBuf::from("/cache/runtime")
        );
    }
}
