use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use zeroize::Zeroizing;

mod runtime;

pub use runtime::{
    agent_endpoint, credential_erase, credential_get, enroll_service_account_token, exec_profile,
    github_token_for_repository, purge_runtime, run_agent, run_gh, run_ssh_keygen, runtime_status,
    ssh_load, RuntimeStatus,
};

const MAX_CREDENTIAL_REQUEST_BYTES: usize = 64 * 1024;
const TOKEN_REFRESH_MARGIN_SECONDS: i64 = 300;

#[derive(Clone)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CredentialRequest {
    attributes: BTreeMap<String, String>,
}

impl fmt::Debug for CredentialRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialRequest")
            .field("repository", &self.repository().ok())
            .finish()
    }
}

impl CredentialRequest {
    pub fn parse(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_CREDENTIAL_REQUEST_BYTES {
            bail!("credential request exceeds the size limit");
        }
        let text = std::str::from_utf8(input).context("credential request is not UTF-8")?;
        let attributes_text = if let Some(value) = text.strip_suffix("\n\n") {
            value
        } else if let Some(value) = text.strip_suffix('\n') {
            value
        } else {
            bail!("credential request is not terminated by a blank line or end-of-file");
        };

        let mut attributes = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for line in attributes_text.lines() {
            if line.is_empty() {
                bail!("credential request contains data after its terminator");
            }
            let (key, value) = line
                .split_once('=')
                .context("credential request line has no equals sign")?;
            if key.is_empty() || value.contains(['\n', '\r', '\0']) {
                bail!("credential request contains an invalid attribute");
            }
            if matches!(key, "protocol" | "host" | "path") {
                if !seen.insert(key.to_owned()) {
                    bail!("credential request contains a duplicate attribute");
                }
                attributes.insert(key.to_owned(), value.to_owned());
            }
        }

        let request = Self { attributes };
        request.repository()?;
        Ok(request)
    }

    pub fn repository(&self) -> Result<(&str, &str)> {
        if self.attributes.get("protocol").map(String::as_str) != Some("https") {
            bail!("only HTTPS Git credentials are supported");
        }
        if self.attributes.get("host").map(String::as_str) != Some("github.com") {
            bail!("only github.com credentials are supported");
        }
        let path = self
            .attributes
            .get("path")
            .context("the exact repository path is required")?;
        let path = path.strip_suffix(".git").unwrap_or(path);
        let mut parts = path.split('/');
        let owner = parts.next().unwrap_or_default();
        let repository = parts.next().unwrap_or_default();
        if owner.is_empty() || repository.is_empty() || parts.next().is_some() {
            bail!("repository path must be exactly owner/repository");
        }
        if !is_github_component(owner) || !is_github_component(repository) {
            bail!("repository path contains unsupported characters");
        }
        Ok((owner, repository))
    }
}

fn is_github_component(value: &str) -> bool {
    !matches!(value, "" | "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GitHubInstallation {
    pub owner: String,
    pub installation_id: u64,
    #[serde(default)]
    pub all_repositories: bool,
    #[serde(default)]
    pub repositories: BTreeSet<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GitHubProfile {
    pub app_id: u64,
    pub private_key_ref: String,
    #[serde(default)]
    pub discover_installations: bool,
    #[serde(default)]
    pub installations: Vec<GitHubInstallation>,
    pub permissions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialStore {
    #[serde(default = "default_keyring_service")]
    pub service: String,
    #[serde(default = "default_keyring_account")]
    pub account: String,
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self {
            service: default_keyring_service(),
            account: default_keyring_account(),
        }
    }
}

fn default_keyring_service() -> String {
    "dev-auth".into()
}

fn default_keyring_account() -> String {
    "service-account-token".into()
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Programs {
    pub op: String,
    pub gh: String,
    pub git: String,
    pub ssh_add: String,
    pub ssh_keygen: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecProfile {
    pub executables: Vec<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SshKeyPurpose {
    Authentication,
    Signing,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SshKey {
    pub purpose: SshKeyPurpose,
    pub private_key_ref: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SshProfile {
    pub keys: Vec<SshKey>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    #[serde(default)]
    pub credential_store: CredentialStore,
    pub programs: Programs,
    pub github: GitHubProfile,
    #[serde(default)]
    pub profiles: BTreeMap<String, ExecProfile>,
    #[serde(default)]
    pub ssh_profiles: BTreeMap<String, SshProfile>,
}

pub fn parse_config(input: &[u8]) -> Result<Config> {
    let text = std::str::from_utf8(input).context("configuration is not UTF-8")?;
    let config: Config = toml::from_str(text).context("configuration is not valid TOML")?;
    if config.version != 1 {
        bail!("unsupported configuration version");
    }
    if config.github.app_id == 0 {
        bail!("GitHub App ID must be positive");
    }
    validate_public_identifier(&config.credential_store.service, "credential-store service")?;
    validate_public_identifier(&config.credential_store.account, "credential-store account")?;
    for (name, program) in [
        ("1Password CLI", &config.programs.op),
        ("GitHub CLI", &config.programs.gh),
        ("Git", &config.programs.git),
        ("ssh-add", &config.programs.ssh_add),
        ("ssh-keygen", &config.programs.ssh_keygen),
    ] {
        validate_program(program, name)?;
    }
    validate_op_reference(&config.github.private_key_ref)?;
    if config.github.discover_installations != config.github.installations.is_empty() {
        bail!("GitHub App must use either dynamic installation discovery or static installations");
    }
    if config.github.permissions != approved_github_permissions() {
        bail!("GitHub App permissions do not match the approved exact scope");
    }
    let mut owners = BTreeSet::new();
    let mut installation_ids = BTreeSet::new();
    for installation in &config.github.installations {
        let scope_is_valid = if installation.all_repositories {
            installation.repositories.is_empty()
        } else {
            !installation.repositories.is_empty()
        };
        if !is_github_component(&installation.owner)
            || !owners.insert(installation.owner.to_ascii_lowercase())
            || installation.installation_id == 0
            || !installation_ids.insert(installation.installation_id)
            || !scope_is_valid
        {
            bail!("GitHub App installation owner, ID, or repository set is invalid");
        }
        let mut repositories = BTreeSet::new();
        for repository in &installation.repositories {
            if !is_github_component(repository)
                || !repositories.insert(repository.to_ascii_lowercase())
            {
                bail!("GitHub App repository name is invalid");
            }
        }
    }
    for (name, profile) in &config.profiles {
        if name.is_empty() || !name.bytes().all(is_profile_character) {
            bail!("profile name contains unsupported characters");
        }
        if profile.executables.is_empty() {
            bail!("profile must declare at least one executable");
        }
        for executable in &profile.executables {
            validate_program(executable, "profile executable")?;
        }
        for (variable, reference) in &profile.environment {
            let mut bytes = variable.bytes();
            let valid_start = bytes
                .next()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_');
            if !valid_start || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
                bail!("profile environment variable is not a valid identifier");
            }
            validate_op_reference(reference)?;
        }
    }
    for (name, profile) in &config.ssh_profiles {
        if name.is_empty() || !name.bytes().all(is_profile_character) {
            bail!("SSH profile name contains unsupported characters");
        }
        if profile.keys.len() != 2 {
            bail!("SSH profile must declare one authentication and one signing key");
        }
        let authentication = profile
            .keys
            .iter()
            .filter(|key| key.purpose == SshKeyPurpose::Authentication)
            .count();
        let signing = profile
            .keys
            .iter()
            .filter(|key| key.purpose == SshKeyPurpose::Signing)
            .count();
        if authentication != 1 || signing != 1 {
            bail!("SSH profile must declare one authentication and one signing key");
        }
        let mut fingerprints = BTreeSet::new();
        for key in &profile.keys {
            validate_op_reference(&key.private_key_ref)?;
            if !is_sha256_fingerprint(&key.fingerprint)
                || !fingerprints.insert(key.fingerprint.as_str())
            {
                bail!("SSH profile contains an invalid or duplicate fingerprint");
            }
        }
    }
    Ok(config)
}

fn approved_github_permissions() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("actions".into(), "read".into()),
        ("checks".into(), "read".into()),
        ("contents".into(), "write".into()),
        ("metadata".into(), "read".into()),
        ("pull_requests".into(), "write".into()),
        ("statuses".into(), "read".into()),
    ])
}

fn is_sha256_fingerprint(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("SHA256:") else {
        return false;
    };
    encoded.len() == 43
        && encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'_' | b'-'))
}

fn is_profile_character(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
}

pub fn validate_op_reference(reference: &str) -> Result<()> {
    if reference.contains(['\n', '\r', '\0']) {
        bail!("secret reference contains a control character");
    }
    let Some(path) = reference.strip_prefix("op://") else {
        bail!("secret reference must use the op scheme");
    };
    let segments: Vec<_> = path.split('/').collect();
    if !(segments.len() == 3 || segments.len() == 4)
        || segments.iter().any(|segment| segment.is_empty())
    {
        bail!("secret reference must address one 1Password item field");
    }
    Ok(())
}

fn validate_public_identifier(value: &str, description: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("{description} contains unsupported characters");
    }
    Ok(())
}

fn validate_program(value: &str, description: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let windows_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    let absolute = std::path::Path::new(value).is_absolute() || windows_absolute;
    if value.is_empty() || value.contains(['\n', '\r', '\0']) || !absolute {
        bail!("{description} must be an absolute executable path");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedRepository {
    pub installation_id: u64,
    pub owner: String,
    pub repository: String,
}

impl GitHubProfile {
    pub fn select_repository(&self, owner: &str, repository: &str) -> Result<SelectedRepository> {
        let mut matches = self
            .installations
            .iter()
            .filter(|entry| entry.owner.eq_ignore_ascii_case(owner));
        let installation = matches
            .next()
            .context("repository owner is not approved for automation")?;
        if matches.next().is_some() {
            bail!("repository owner maps to more than one installation");
        }
        let repository = if installation.all_repositories {
            repository.to_ascii_lowercase()
        } else {
            installation
                .repositories
                .iter()
                .find(|name| name.eq_ignore_ascii_case(repository))
                .map(|name| name.to_ascii_lowercase())
                .context("repository is not approved for automation")?
        };
        Ok(SelectedRepository {
            installation_id: installation.installation_id,
            owner: installation.owner.to_ascii_lowercase(),
            repository,
        })
    }
}

#[derive(Clone)]
pub struct CacheEntry {
    token: SecretString,
    expires_at: i64,
    installation_id: u64,
    owner: String,
    repository: String,
    pub permissions: BTreeMap<String, String>,
}

impl fmt::Debug for CacheEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CacheEntry")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("installation_id", &self.installation_id)
            .field("owner", &self.owner)
            .field("repository", &self.repository)
            .field("permissions", &self.permissions)
            .finish()
    }
}

impl CacheEntry {
    pub fn new(
        token: SecretString,
        expires_at: i64,
        installation_id: u64,
        owner: String,
        repository: String,
        permissions: BTreeMap<String, String>,
    ) -> Self {
        Self {
            token,
            expires_at,
            installation_id,
            owner,
            repository,
            permissions,
        }
    }

    pub fn new_for_test(
        token: SecretString,
        expires_at: i64,
        installation_id: u64,
        owner: String,
        repository: String,
        permissions: BTreeMap<String, String>,
    ) -> Self {
        Self {
            token,
            expires_at,
            installation_id,
            owner,
            repository,
            permissions,
        }
    }

    pub fn is_usable_at(
        &self,
        now: i64,
        installation_id: u64,
        owner: &str,
        repository: &str,
        permissions: &BTreeMap<String, String>,
    ) -> bool {
        self.installation_id == installation_id
            && self.owner == owner
            && self.repository == repository
            && self.permissions == *permissions
            && now < self.expires_at - TOKEN_REFRESH_MARGIN_SECONDS
    }

    pub fn is_usable_for_repository_at(
        &self,
        now: i64,
        owner: &str,
        repository: &str,
        permissions: &BTreeMap<String, String>,
    ) -> bool {
        self.owner == owner
            && self.repository == repository
            && self.permissions == *permissions
            && now < self.expires_at - TOKEN_REFRESH_MARGIN_SECONDS
    }

    pub fn token(&self) -> &SecretString {
        &self.token
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    pub fn installation_id(&self) -> u64 {
        self.installation_id
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }
}

pub fn sanitize_environment(
    input: &BTreeMap<String, String>,
    additional_allowed: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    const BASE_ALLOWED: &[&str] = &[
        "APPDATA",
        "COLORTERM",
        "COMSPEC",
        "DBUS_SESSION_BUS_ADDRESS",
        "DISPLAY",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOCALAPPDATA",
        "LOGNAME",
        "PATH",
        "PATHEXT",
        "SHELL",
        "SYSTEMROOT",
        "TERM",
        "TMP",
        "TMPDIR",
        "TEMP",
        "USER",
        "USERPROFILE",
        "WAYLAND_DISPLAY",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
    ];

    input
        .iter()
        .filter(|(key, _)| {
            BASE_ALLOWED
                .iter()
                .any(|allowed| key.eq_ignore_ascii_case(allowed))
                || additional_allowed.contains(key.as_str())
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

pub fn render_git_credential(token: &str, expires_at: i64) -> Result<String> {
    if token.is_empty() || token.contains(['\n', '\r', '\0']) {
        bail!("installation token contains an invalid protocol character");
    }
    if expires_at <= 0 {
        bail!("installation token has no valid expiry");
    }
    Ok(format!(
        "username=x-access-token\npassword={token}\npassword_expiry_utc={expires_at}\n\n"
    ))
}

pub fn parse_github_repository(value: &str) -> Result<(String, String)> {
    if value.is_empty() || value.contains(['\n', '\r', '\0', '?', '#']) {
        bail!("GitHub repository identifier is malformed");
    }
    let path = if let Some(path) = value.strip_prefix("https://github.com/") {
        path
    } else if let Some(path) = value.strip_prefix("ssh://git@github.com/") {
        path
    } else if let Some(path) = value.strip_prefix("git@github.com:") {
        path
    } else if !value.contains("://") && !value.contains('@') && !value.contains(':') {
        value
    } else {
        bail!("only exact github.com repository identifiers are supported");
    };
    let path = path.strip_suffix(".git").unwrap_or(path);
    let mut components = path.split('/');
    let owner = components.next().unwrap_or_default();
    let repository = components.next().unwrap_or_default();
    if owner.is_empty() || repository.is_empty() || components.next().is_some() {
        bail!("GitHub repository identifier must be exactly owner/repository");
    }
    if !is_github_component(owner) || !is_github_component(repository) {
        bail!("GitHub repository identifier contains unsupported characters");
    }
    Ok((owner.to_owned(), repository.to_owned()))
}

pub fn admit_gh_arguments<S: AsRef<str>>(arguments: &[S]) -> Result<()> {
    let command = arguments
        .first()
        .map(AsRef::as_ref)
        .context("gh command is missing")?;
    let subcommand = arguments.get(1).map(AsRef::as_ref);
    let accepted = match command {
        "pr" => matches!(
            subcommand,
            Some(
                "list"
                    | "view"
                    | "create"
                    | "checks"
                    | "diff"
                    | "comment"
                    | "edit"
                    | "ready"
                    | "review"
                    | "merge"
                    | "close"
                    | "reopen"
            )
        ),
        "run" => matches!(subcommand, Some("list" | "view" | "watch" | "download")),
        "workflow" => matches!(subcommand, Some("list" | "view")),
        "release" => matches!(subcommand, Some("list" | "view" | "download")),
        "repo" => matches!(subcommand, Some("view")),
        _ => false,
    };
    if !accepted {
        bail!("gh command is outside the repository-scoped automation surface");
    }
    Ok(())
}
