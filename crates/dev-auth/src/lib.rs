use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use zeroize::Zeroizing;

mod runtime;

pub use runtime::{
    agent_endpoint, credential_erase, credential_get, enroll_service_account_token, exec_profile,
    github_token_for_repository, purge_runtime, run_agent, run_gh, run_gh_git_child, run_git,
    run_ssh_keygen, runtime_status, ssh_load, ssh_public, validate_configuration, workspace_status,
    RuntimeStatus, ValidationReport, WorkspaceContext,
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

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RepositorySelection {
    All,
    Selected,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GitHubProfile {
    pub app_id: u64,
    pub private_key_ref: String,
    pub repository_selection: RepositorySelection,
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

fn is_reserved_profile_environment(variable: &str) -> bool {
    const RESERVED: &[&str] = &[
        "APPDATA",
        "COLORTERM",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOCALAPPDATA",
        "PATH",
        "TEMP",
        "TERM",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
    ];
    RESERVED
        .iter()
        .any(|reserved| variable.eq_ignore_ascii_case(reserved))
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
pub struct GitPolicy {
    pub workspace_roots: Vec<String>,
    pub author_name: String,
    pub author_email: String,
    pub ssh_profile: String,
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
    #[serde(default)]
    pub git: Option<GitPolicy>,
    pub github: GitHubProfile,
    #[serde(default)]
    pub profiles: BTreeMap<String, ExecProfile>,
    #[serde(default)]
    pub ssh_profiles: BTreeMap<String, SshProfile>,
}

impl Config {
    pub fn declared_secret_references(&self) -> BTreeSet<String> {
        std::iter::once(&self.github.private_key_ref)
            .chain(
                self.profiles
                    .values()
                    .flat_map(|profile| profile.environment.values()),
            )
            .chain(
                self.ssh_profiles
                    .values()
                    .flat_map(|profile| profile.keys.iter().map(|key| &key.private_key_ref)),
            )
            .cloned()
            .collect()
    }
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
        } && installation.all_repositories
            == matches!(config.github.repository_selection, RepositorySelection::All);
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
            if is_reserved_profile_environment(variable) {
                bail!("profile environment variable conflicts with the private sandbox");
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
    if let Some(git) = &config.git {
        if git.workspace_roots.is_empty() {
            bail!("Git policy must declare at least one workspace root");
        }
        let mut roots = BTreeSet::new();
        for root in &git.workspace_roots {
            validate_workspace_root(root)?;
            let normalized = if cfg!(windows) {
                root.replace('\\', "/").to_ascii_lowercase()
            } else {
                root.clone()
            };
            if !roots.insert(normalized) {
                bail!("Git policy contains a duplicate workspace root");
            }
        }
        validate_git_author(&git.author_name, &git.author_email)?;
        if git.ssh_profile.is_empty()
            || !git.ssh_profile.bytes().all(is_profile_character)
            || !config.ssh_profiles.contains_key(&git.ssh_profile)
        {
            bail!("Git policy SSH profile is not declared");
        }
    }
    Ok(config)
}

fn validate_workspace_root(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 4096
        || value.contains(['\n', '\r', '\0'])
        || value.starts_with("\\\\")
    {
        bail!("Git workspace root is malformed");
    }
    if let Some(relative) = value.strip_prefix("~/") {
        if relative.is_empty()
            || relative.contains('\\')
            || relative.contains(':')
            || relative
                .split('/')
                .any(|component| matches!(component, "" | "." | ".."))
        {
            bail!("home-relative Git workspace root is malformed");
        }
        return Ok(());
    }
    if value.starts_with('~') || value.contains('$') || value.contains('%') {
        bail!("Git workspace root uses unsupported expansion");
    }
    validate_program(value, "Git workspace root")
}

fn validate_git_author(name: &str, email: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 256
        || name.contains(['\n', '\r', '\0', '<', '>'])
        || name.chars().any(char::is_control)
    {
        bail!("Git author name is malformed");
    }
    let Some((local, domain)) = email.split_once('@') else {
        bail!("Git author email is malformed");
    };
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || email.len() > 320
        || !email.is_ascii()
        || email
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'<' | b'>' | 0))
    {
        bail!("Git author email is malformed");
    }
    Ok(())
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

pub(crate) fn validate_program(value: &str, description: &str) -> Result<()> {
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
    app_id: u64,
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
            .field("app_id", &self.app_id)
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
        app_id: u64,
        installation_id: u64,
        owner: String,
        repository: String,
        permissions: BTreeMap<String, String>,
    ) -> Self {
        Self {
            token,
            expires_at,
            app_id,
            installation_id,
            owner,
            repository,
            permissions,
        }
    }

    pub fn new_for_test(
        token: SecretString,
        expires_at: i64,
        app_id: u64,
        installation_id: u64,
        owner: String,
        repository: String,
        permissions: BTreeMap<String, String>,
    ) -> Self {
        Self {
            token,
            expires_at,
            app_id,
            installation_id,
            owner,
            repository,
            permissions,
        }
    }

    pub fn is_usable_at(
        &self,
        now: i64,
        app_id: u64,
        installation_id: u64,
        owner: &str,
        repository: &str,
        permissions: &BTreeMap<String, String>,
    ) -> bool {
        self.app_id == app_id
            && self.installation_id == installation_id
            && self.owner == owner
            && self.repository == repository
            && self.permissions == *permissions
            && now < self.expires_at - TOKEN_REFRESH_MARGIN_SECONDS
    }

    pub fn is_usable_for_repository_at(
        &self,
        now: i64,
        app_id: u64,
        installation_id: u64,
        owner: &str,
        repository: &str,
        permissions: &BTreeMap<String, String>,
    ) -> bool {
        self.is_usable_at(now, app_id, installation_id, owner, repository, permissions)
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

    pub fn app_id(&self) -> u64 {
        self.app_id
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

fn git_argument_has_value(argument: &str, name: &str) -> bool {
    argument == name
        || argument
            .strip_prefix(name)
            .is_some_and(|value| value.starts_with('='))
}

fn git_argument_is_process_escape(argument: &str) -> bool {
    [
        "--config-env",
        "--exec-path",
        "--git-dir",
        "--namespace",
        "--super-prefix",
        "--work-tree",
        "--upload-pack",
        "--receive-pack",
        "--template",
        "--config",
        "--pathspec-from-file",
        "--output",
    ]
    .iter()
    .any(|name| git_argument_has_value(argument, name))
        || matches!(
            argument,
            "-C" | "-c"
                | "--bare"
                | "--ext-diff"
                | "--textconv"
                | "--recurse-submodules"
                | "--edit-description"
        )
        || argument.starts_with("-c") && argument.len() > 2
        || argument.starts_with("-C") && argument.len() > 2
}

fn git_argument_is_signing_escape(argument: &str) -> bool {
    matches!(
        argument,
        "--no-gpg-sign"
            | "--no-sign"
            | "--author"
            | "--date"
            | "--reset-author"
            | "--gpg-sign"
            | "-S"
            | "--local-user"
    ) || argument.starts_with("--author=")
        || argument.starts_with("--date=")
        || argument.starts_with("--gpg-sign=")
        || argument.starts_with("--local-user=")
}

fn validate_git_argument_text(arguments: &[&str]) -> Result<()> {
    for argument in arguments {
        if argument.is_empty() || argument.contains(['\n', '\r', '\0']) {
            bail!("Git argument is empty or contains a control character");
        }
        if argument.starts_with('-') && !argument.starts_with("--") && argument.len() > 2 {
            bail!("Git compact, attached, and bundled short options are not admitted");
        }
        if git_argument_is_process_escape(argument) || git_argument_is_signing_escape(argument) {
            bail!("Git argument can override the automation execution boundary");
        }
    }
    Ok(())
}

fn consume_git_value<'a>(
    arguments: &'a [&str],
    index: &mut usize,
    option: &str,
) -> Result<&'a str> {
    *index += 1;
    arguments
        .get(*index)
        .copied()
        .with_context(|| format!("Git option {option} has no value"))
}

fn validate_git_status(arguments: &[&str]) -> Result<()> {
    for argument in arguments {
        let admitted = matches!(
            *argument,
            "-s" | "--short"
                | "-b"
                | "--branch"
                | "--porcelain"
                | "--porcelain=v1"
                | "--porcelain=v2"
                | "--show-stash"
                | "--ahead-behind"
                | "--no-ahead-behind"
                | "--untracked-files=no"
                | "--untracked-files=normal"
                | "--untracked-files=all"
        );
        if !admitted {
            bail!("Git status option is outside the bounded automation grammar");
        }
    }
    Ok(())
}

fn validate_git_add(arguments: &[&str]) -> Result<()> {
    let mut pathspec = false;
    let mut paths = 0_usize;
    for argument in arguments {
        if pathspec {
            if !valid_explicit_git_path(argument) {
                bail!("Git add path is not an exact safe relative path");
            }
            paths += 1;
            continue;
        }
        match *argument {
            "--" => pathspec = true,
            "-N" | "--intent-to-add" | "-n" | "--dry-run" | "-v" | "--verbose" => {}
            _ => bail!("Git add requires bounded options and explicit -- pathspecs"),
        }
    }
    if paths == 0 {
        bail!("Git add requires at least one explicit -- path");
    }
    Ok(())
}

pub(crate) fn valid_explicit_git_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with(['-', '/', '~'])
        && !value.contains(['\\', ':', '\n', '\r', '\0'])
        && !value.chars().any(char::is_control)
        && value.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && !component.eq_ignore_ascii_case(".git")
        })
}

fn validate_git_restore(arguments: &[&str]) -> Result<()> {
    let mut index = 0_usize;
    let mut pathspec = false;
    let mut paths = 0_usize;
    while index < arguments.len() {
        let argument = arguments[index];
        if pathspec {
            if !valid_explicit_git_path(argument) {
                bail!("Git restore path is not an exact safe relative path");
            }
            paths += 1;
            index += 1;
            continue;
        }
        match argument {
            "--" => pathspec = true,
            "--worktree" | "--ours" | "--theirs" => {}
            _ => bail!("Git restore requires bounded options and explicit -- pathspecs"),
        }
        index += 1;
    }
    if paths == 0 {
        bail!("Git restore requires at least one explicit -- pathspec");
    }
    Ok(())
}

fn validate_git_checkout(arguments: &[&str]) -> Result<()> {
    let admitted = matches!(arguments, ["--", paths @ ..]
        if !paths.is_empty() && paths.iter().all(|path| valid_explicit_git_path(path)));
    if !admitted {
        bail!("Git checkout operation is outside the bounded automation grammar");
    }
    Ok(())
}

fn validate_git_history(command: &str, arguments: &[&str]) -> Result<()> {
    let mut index = 0_usize;
    let mut objects = 0_usize;
    while index < arguments.len() {
        let argument = arguments[index];
        match argument {
            "--oneline" | "--graph" | "--stat" | "--name-only" | "--name-status" | "--no-patch"
            | "--reverse" | "--first-parent" | "--merges" | "--no-merges" | "--no-renames" => {}
            "-n" | "--max-count" => {
                let value = consume_git_value(arguments, &mut index, argument)?;
                if !value.parse::<u64>().is_ok_and(|count| count > 0) {
                    bail!("Git history count is malformed");
                }
            }
            _ if argument
                .strip_prefix("--max-count=")
                .is_some_and(|value| value.parse::<u64>().is_ok_and(|count| count > 0)) => {}
            _ if matches!(argument.len(), 40 | 64)
                && argument.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
            {
                objects += 1;
            }
            _ => bail!("Git {command} option is outside the bounded automation grammar"),
        }
        index += 1;
    }
    if objects != 1 {
        bail!("Git {command} requires exactly one full object identifier");
    }
    Ok(())
}

fn validate_git_commit(arguments: &[&str]) -> Result<()> {
    let mut index = 0_usize;
    let mut messages = 0_usize;
    let mut no_status = 0_usize;
    while index < arguments.len() {
        let argument = arguments[index];
        match argument {
            "-m" | "--message" => {
                let value = consume_git_value(arguments, &mut index, argument)?;
                if value.is_empty() {
                    bail!("Git commit message must not be empty");
                }
                messages += 1;
            }
            "-F" | "--file" => {
                if consume_git_value(arguments, &mut index, argument)? != "-" {
                    bail!("Git commit file input is restricted to standard input");
                }
                messages += 1;
            }
            "--no-status" => no_status += 1,
            "--allow-empty" | "--allow-empty-message" | "-s" | "--signoff" | "-q" | "--quiet" => {}
            _ if argument.starts_with('-') => {
                bail!("Git commit option is outside the bounded automation grammar")
            }
            _ => bail!("Git commit is restricted to the staged index without pathspecs"),
        }
        index += 1;
    }
    if messages != 1 {
        bail!("Git commit requires exactly one explicit message source");
    }
    if no_status != 1 {
        bail!("Git commit requires exactly one explicit --no-status");
    }
    Ok(())
}

fn validate_git_tag(arguments: &[&str]) -> Result<()> {
    let mut index = 0_usize;
    let mut messages = 0_usize;
    let mut positionals = Vec::new();
    while index < arguments.len() {
        let argument = arguments[index];
        match argument {
            "-m" | "--message" => {
                let value = consume_git_value(arguments, &mut index, argument)?;
                if value.is_empty() {
                    bail!("Git tag message must not be empty");
                }
                messages += 1;
            }
            "-F" | "--file" => {
                if consume_git_value(arguments, &mut index, argument)? != "-" {
                    bail!("Git tag file input is restricted to standard input");
                }
                messages += 1;
            }
            "-a" | "--annotate" => {}
            "-u" => bail!("Git tag signing key overrides are not admitted"),
            _ if argument.starts_with('-') => {
                bail!("Git tag option is outside the bounded automation grammar")
            }
            _ => positionals.push(argument),
        }
        index += 1;
    }
    if messages != 1 || !(1..=2).contains(&positionals.len()) {
        bail!("Git tag creation requires exactly one message, a tag name, and an optional target");
    }
    let tag_name = positionals[0];
    let target_is_exact = positionals.get(1).is_none_or(|value| {
        *value == "HEAD"
            || valid_typed_git_ref(value, &["refs/heads/", "refs/tags/"])
            || matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    });
    if !valid_git_ref_name(tag_name) || tag_name.starts_with("refs/") || !target_is_exact {
        bail!("Git tag name or target is malformed");
    }
    Ok(())
}

fn valid_git_ref_operand(value: &str) -> bool {
    !value.starts_with('-')
        && (value == "HEAD"
            || value.len() <= 1024 && valid_git_ref_name(value)
            || matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn valid_push_refspec(value: &str) -> bool {
    let Some((source, destination)) = value.split_once(':') else {
        return false;
    };
    !source.starts_with('+')
        && ((source == "HEAD" && valid_typed_git_ref(destination, &["refs/heads/"]))
            || (valid_typed_git_ref(source, &["refs/heads/"])
                && valid_typed_git_ref(destination, &["refs/heads/"]))
            || (valid_typed_git_ref(source, &["refs/tags/"])
                && valid_typed_git_ref(destination, &["refs/tags/"])))
}

fn valid_git_ref_name(name: &str) -> bool {
    !name.is_empty()
        && name != "@"
        && !name.starts_with(['.', '/'])
        && !name.ends_with(['.', '/'])
        && !name.contains("..")
        && !name.contains("@{")
        && !name.contains("//")
        && !name.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(character, '~' | '^' | ':' | '?' | '*' | '[' | '\\')
        })
        && name.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && !component.ends_with('.')
                && !component.ends_with(".lock")
        })
}

fn valid_typed_git_ref(value: &str, prefixes: &[&str]) -> bool {
    prefixes
        .iter()
        .any(|prefix| value.strip_prefix(prefix).is_some_and(valid_git_ref_name))
}

fn valid_fetch_refspec(value: &str) -> bool {
    let Some((source, destination)) = value.split_once(':') else {
        return false;
    };
    if source.starts_with('+') || destination.is_empty() {
        return false;
    }
    (valid_typed_git_ref(source, &["refs/heads/"])
        && valid_typed_git_ref(destination, &["refs/remotes/origin/"]))
        || (valid_typed_git_ref(source, &["refs/tags/"])
            && valid_typed_git_ref(destination, &["refs/tags/"]))
        || (source == "HEAD" && destination == "refs/remotes/origin/HEAD")
}

fn validate_origin_network_command(command: &str, arguments: &[&str]) -> Result<()> {
    let mut positionals = Vec::new();
    for argument in arguments {
        if argument.starts_with('-') {
            let admitted = match command {
                "fetch" => matches!(
                    *argument,
                    "-q" | "--quiet" | "-v" | "--verbose" | "--dry-run"
                ),
                "push" => matches!(
                    *argument,
                    "--atomic"
                        | "--dry-run"
                        | "--porcelain"
                        | "-q"
                        | "--quiet"
                        | "-v"
                        | "--verbose"
                ),
                _ => false,
            };
            if !admitted {
                bail!("Git network option is outside the bounded automation grammar");
            }
        } else {
            positionals.push(*argument);
        }
    }
    if positionals.first() != Some(&"origin") {
        bail!("Git network operations require the literal origin remote");
    }
    if positionals.len() != 2 {
        bail!("Git network operations require exactly one explicit typed refspec");
    }
    let invalid_ref = positionals.iter().skip(1).any(|value| {
        if command == "push" {
            !valid_push_refspec(value)
        } else {
            !valid_fetch_refspec(value)
        }
    });
    if invalid_ref {
        bail!("Git network refspec is untyped, forceful, deleting, or malformed");
    }
    Ok(())
}

fn valid_git_clone_destination(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with(['-', '/', '~'])
        && !value.contains(['\\', ':', '\n', '\r', '\0'])
        && !value.chars().any(char::is_control)
        && value.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && !component.eq_ignore_ascii_case(".git")
        })
}

fn validate_git_clone(arguments: &[&str]) -> Result<()> {
    let mut index = 0_usize;
    let mut positionals = Vec::new();
    let mut no_checkout = 0_usize;
    while index < arguments.len() {
        let argument = arguments[index];
        match argument {
            "--no-checkout" => no_checkout += 1,
            "--single-branch" | "--no-tags" | "-q" | "--quiet" | "-v" | "--verbose" => {}
            "-b" | "--branch" => {
                let value = consume_git_value(arguments, &mut index, argument)?;
                if !valid_git_ref_operand(value) {
                    bail!("Git clone option value is malformed");
                }
            }
            "--depth" => {
                let value = consume_git_value(arguments, &mut index, argument)?;
                if !value.parse::<u64>().is_ok_and(|depth| depth > 0) {
                    bail!("Git clone depth is malformed");
                }
            }
            _ if argument.starts_with('-') => {
                bail!("Git clone option is outside the bounded automation grammar")
            }
            _ => positionals.push(argument),
        }
        index += 1;
    }
    if positionals.len() != 2 {
        bail!("Git clone requires one repository and one explicit destination");
    }
    if no_checkout != 1 {
        bail!("managed Git clone requires exactly one explicit --no-checkout");
    }
    let source = positionals[0];
    if !(source.starts_with("https://github.com/")
        || source.starts_with("ssh://git@github.com/")
        || source.starts_with("git@github.com:"))
    {
        bail!("managed Git clone requires an explicit github.com transport URL");
    }
    parse_github_repository(source)?;
    if !valid_git_clone_destination(positionals[1]) {
        bail!("Git clone destination is malformed");
    }
    Ok(())
}

pub(crate) fn managed_clone_repository<S: AsRef<str>>(
    arguments: &[S],
) -> Result<Option<(String, String)>> {
    let arguments: Vec<&str> = arguments.iter().map(AsRef::as_ref).collect();
    if arguments.first() != Some(&"clone") {
        return Ok(None);
    }
    admit_git_arguments(&arguments)?;
    let mut index = 1_usize;
    let mut positionals = Vec::new();
    while index < arguments.len() {
        match arguments[index] {
            "-b" | "--branch" | "--depth" => index += 1,
            "--single-branch" | "--no-tags" | "--no-checkout" | "-q" | "--quiet" | "-v"
            | "--verbose" => {}
            value if value.starts_with('-') => {
                bail!("Git clone option is outside the bounded automation grammar")
            }
            value => positionals.push(value),
        }
        index += 1;
    }
    let repository = positionals
        .first()
        .context("Git clone repository is missing")?;
    Ok(Some(parse_github_repository(repository)?))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GitCapability {
    NoAuthority,
    GitHubToken,
    Signing,
}

fn parse_git_capability<S: AsRef<str>>(arguments: &[S]) -> Result<GitCapability> {
    let arguments: Vec<&str> = arguments.iter().map(AsRef::as_ref).collect();
    let (command, tail) = arguments.split_first().context("Git command is required")?;
    if command.starts_with('-') || command.contains(['/', '\\']) {
        bail!("managed Git does not admit global options or executable paths");
    }
    let admitted = matches!(
        *command,
        "status"
            | "add"
            | "restore"
            | "checkout"
            | "log"
            | "show"
            | "commit"
            | "tag"
            | "fetch"
            | "push"
            | "clone"
    );
    if !admitted {
        bail!("Git command is outside the managed automation surface");
    }
    validate_git_argument_text(tail)?;
    let capability = match *command {
        "status" => validate_git_status(tail).map(|()| GitCapability::NoAuthority),
        "add" => validate_git_add(tail).map(|()| GitCapability::NoAuthority),
        "restore" => validate_git_restore(tail).map(|()| GitCapability::NoAuthority),
        "checkout" => validate_git_checkout(tail).map(|()| GitCapability::NoAuthority),
        "log" | "show" => validate_git_history(command, tail).map(|()| GitCapability::NoAuthority),
        "commit" => validate_git_commit(tail).map(|()| GitCapability::Signing),
        "tag" => validate_git_tag(tail).map(|()| GitCapability::Signing),
        "fetch" | "push" => {
            validate_origin_network_command(command, tail).map(|()| GitCapability::GitHubToken)
        }
        "clone" => validate_git_clone(tail).map(|()| GitCapability::GitHubToken),
        _ => bail!("Git command has no managed capability mapping"),
    }?;
    Ok(capability)
}

pub(crate) fn git_capability(arguments: &[String]) -> Result<GitCapability> {
    parse_git_capability(arguments)
}

/// Validate the exact managed-workspace Git grammar before configuration,
/// credentials, agent state, or runtime state may influence the invocation.
pub fn admit_git_arguments<S: AsRef<str>>(arguments: &[S]) -> Result<()> {
    parse_git_capability(arguments).map(|_| ())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GhInvocationPlan {
    pub(crate) repository: Option<(String, String)>,
    pub(crate) forwarded_arguments: Vec<String>,
    pub(crate) inject_repository_argument: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GhOptionKind {
    Flag,
    Value,
}

#[derive(Debug, Clone, Copy)]
struct GhOptionSpec {
    long: &'static str,
    short: Option<&'static str>,
    kind: GhOptionKind,
}

#[derive(Debug)]
struct ParsedGhTail {
    repository: Option<(String, String)>,
    forwarded: Vec<String>,
    positionals: Vec<String>,
    options: BTreeMap<String, Vec<Option<String>>>,
}

const fn gh_flag(long: &'static str, short: Option<&'static str>) -> GhOptionSpec {
    GhOptionSpec {
        long,
        short,
        kind: GhOptionKind::Flag,
    }
}

const fn gh_value(long: &'static str, short: Option<&'static str>) -> GhOptionSpec {
    GhOptionSpec {
        long,
        short,
        kind: GhOptionKind::Value,
    }
}

fn gh_specs(command: &str, subcommand: &str) -> Result<Vec<GhOptionSpec>> {
    let specs = match (command, subcommand) {
        ("pr", "list") => &[
            gh_value("--app", None),
            gh_value("--assignee", Some("-a")),
            gh_value("--author", Some("-A")),
            gh_value("--base", Some("-B")),
            gh_flag("--draft", Some("-d")),
            gh_value("--head", Some("-H")),
            gh_value("--jq", Some("-q")),
            gh_value("--json", None),
            gh_value("--label", Some("-l")),
            gh_value("--limit", Some("-L")),
            gh_value("--search", Some("-S")),
            gh_value("--state", Some("-s")),
            gh_value("--template", Some("-t")),
        ][..],
        ("pr", "view") => &[
            gh_flag("--comments", Some("-c")),
            gh_value("--jq", Some("-q")),
            gh_value("--json", None),
            gh_value("--template", Some("-t")),
        ],
        ("pr", "checks") => &[
            gh_flag("--fail-fast", None),
            gh_value("--interval", Some("-i")),
            gh_value("--jq", Some("-q")),
            gh_value("--json", None),
            gh_flag("--required", None),
            gh_value("--template", Some("-t")),
            gh_flag("--watch", None),
        ],
        ("pr", "diff") => &[
            gh_value("--color", None),
            gh_value("--exclude", Some("-e")),
            gh_flag("--name-only", None),
            gh_flag("--patch", None),
        ],
        ("pr", "create") => &[
            gh_value("--assignee", Some("-a")),
            gh_value("--base", Some("-B")),
            gh_value("--body", Some("-b")),
            gh_value("--body-file", Some("-F")),
            gh_flag("--draft", Some("-d")),
            gh_value("--head", Some("-H")),
            gh_value("--label", Some("-l")),
            gh_value("--milestone", Some("-m")),
            gh_flag("--no-maintainer-edit", None),
            gh_value("--project", Some("-p")),
            gh_value("--reviewer", Some("-r")),
            gh_value("--title", Some("-t")),
        ],
        ("pr", "comment") => &[
            gh_value("--body", Some("-b")),
            gh_value("--body-file", Some("-F")),
        ],
        ("pr", "edit") => &[
            gh_value("--add-assignee", None),
            gh_value("--add-label", None),
            gh_value("--add-project", None),
            gh_value("--add-reviewer", None),
            gh_value("--base", Some("-B")),
            gh_value("--body", Some("-b")),
            gh_value("--body-file", Some("-F")),
            gh_value("--milestone", Some("-m")),
            gh_value("--remove-assignee", None),
            gh_value("--remove-label", None),
            gh_flag("--remove-milestone", None),
            gh_value("--remove-project", None),
            gh_value("--remove-reviewer", None),
            gh_value("--title", Some("-t")),
        ],
        ("pr", "ready") => &[],
        ("pr", "review") => &[
            gh_flag("--approve", Some("-a")),
            gh_value("--body", Some("-b")),
            gh_value("--body-file", Some("-F")),
            gh_flag("--comment", Some("-c")),
            gh_flag("--request-changes", Some("-r")),
        ],
        ("pr", "merge") => &[
            gh_value("--author-email", Some("-A")),
            gh_value("--body", Some("-b")),
            gh_value("--body-file", Some("-F")),
            gh_value("--match-head-commit", None),
            gh_flag("--merge", Some("-m")),
            gh_flag("--rebase", Some("-r")),
            gh_flag("--squash", Some("-s")),
            gh_value("--subject", Some("-t")),
        ],
        ("pr", "close") | ("pr", "reopen") => &[gh_value("--comment", Some("-c"))],
        ("run", "list") => &[
            gh_flag("--all", Some("-a")),
            gh_value("--branch", Some("-b")),
            gh_value("--commit", Some("-c")),
            gh_value("--created", None),
            gh_value("--event", Some("-e")),
            gh_value("--jq", Some("-q")),
            gh_value("--json", None),
            gh_value("--limit", Some("-L")),
            gh_value("--status", Some("-s")),
            gh_value("--template", Some("-t")),
            gh_value("--user", Some("-u")),
            gh_value("--workflow", Some("-w")),
        ],
        ("run", "view") => &[
            gh_value("--attempt", Some("-a")),
            gh_flag("--exit-status", None),
            gh_value("--job", Some("-j")),
            gh_value("--jq", Some("-q")),
            gh_value("--json", None),
            gh_flag("--log", None),
            gh_flag("--log-failed", None),
            gh_value("--template", Some("-t")),
            gh_flag("--verbose", Some("-v")),
        ],
        ("run", "watch") => &[
            gh_flag("--compact", None),
            gh_flag("--exit-status", None),
            gh_value("--interval", Some("-i")),
        ],
        ("workflow", "list") => &[
            gh_flag("--all", Some("-a")),
            gh_value("--jq", Some("-q")),
            gh_value("--json", None),
            gh_value("--limit", Some("-L")),
            gh_value("--template", Some("-t")),
        ],
        ("workflow", "view") => &[gh_value("--ref", Some("-r")), gh_flag("--yaml", Some("-y"))],
        ("release", "list") => &[
            gh_flag("--exclude-drafts", None),
            gh_flag("--exclude-pre-releases", None),
            gh_value("--jq", Some("-q")),
            gh_value("--json", None),
            gh_value("--limit", Some("-L")),
            gh_value("--order", Some("-O")),
            gh_value("--template", Some("-t")),
        ],
        ("release", "view") => &[
            gh_value("--jq", Some("-q")),
            gh_value("--json", None),
            gh_value("--template", Some("-t")),
        ],
        ("repo", "view") => &[
            gh_value("--branch", Some("-b")),
            gh_value("--jq", Some("-q")),
            gh_value("--json", None),
            gh_value("--template", Some("-t")),
        ],
        _ => bail!("gh command is outside the repository-scoped automation surface"),
    };
    Ok(specs.to_vec())
}

fn exact_github_repository(value: &str) -> Result<(String, String)> {
    if value.contains(['\n', '\r', '\0', ':', '@', '?', '#']) {
        bail!("gh repository selector must be an exact github.com owner/repository");
    }
    let mut parts = value.split('/');
    let owner = parts.next().unwrap_or_default();
    let repository = parts.next().unwrap_or_default();
    if !is_github_component(owner) || !is_github_component(repository) || parts.next().is_some() {
        bail!("gh repository selector must be an exact github.com owner/repository");
    }
    Ok((owner.to_owned(), repository.to_owned()))
}

fn set_gh_repository(selected: &mut Option<(String, String)>, value: &str) -> Result<()> {
    if selected.is_some() {
        bail!("gh command contains more than one repository selector");
    }
    *selected = Some(exact_github_repository(value)?);
    Ok(())
}

fn find_gh_option<'a, 'b>(
    specs: &'a [GhOptionSpec],
    argument: &'b str,
) -> Option<(&'a GhOptionSpec, Option<&'b str>)> {
    if let Some((name, value)) = argument.split_once('=') {
        return specs
            .iter()
            .find(|spec| spec.long == name && spec.kind == GhOptionKind::Value)
            .map(|spec| (spec, Some(value)));
    }
    specs
        .iter()
        .find(|spec| spec.long == argument || spec.short == Some(argument))
        .map(|spec| (spec, None))
}

fn parse_gh_tail(
    command: &str,
    subcommand: &str,
    tail: &[&str],
    specs: &[GhOptionSpec],
) -> Result<ParsedGhTail> {
    let mut parsed = ParsedGhTail {
        repository: None,
        forwarded: vec![command.to_owned(), subcommand.to_owned()],
        positionals: Vec::new(),
        options: BTreeMap::new(),
    };
    let mut index = 0_usize;
    while index < tail.len() {
        let argument = tail[index];
        if argument == "--"
            || argument.starts_with('-') && !argument.starts_with("--") && argument.len() > 2
        {
            bail!("gh compact, attached, bundled, and option-terminator forms are not admitted");
        }

        let repository_value = if matches!(argument, "-R" | "--repo") {
            index += 1;
            Some(
                tail.get(index)
                    .copied()
                    .context("gh repository selector has no value")?,
            )
        } else {
            argument.strip_prefix("--repo=")
        };
        if let Some(value) = repository_value {
            set_gh_repository(&mut parsed.repository, value)?;
            index += 1;
            continue;
        }

        if argument.starts_with('-') {
            let (spec, attached) = find_gh_option(specs, argument)
                .context("gh option is outside the reviewed command grammar")?;
            match spec.kind {
                GhOptionKind::Flag => {
                    if attached.is_some() {
                        bail!("gh boolean option assignment is not admitted");
                    }
                    parsed
                        .options
                        .entry(spec.long.into())
                        .or_default()
                        .push(None);
                    parsed.forwarded.push(argument.into());
                }
                GhOptionKind::Value => {
                    let value = if let Some(value) = attached {
                        value
                    } else {
                        index += 1;
                        tail.get(index)
                            .copied()
                            .context("gh option value is missing")?
                    };
                    parsed
                        .options
                        .entry(spec.long.into())
                        .or_default()
                        .push(Some(value.into()));
                    parsed.forwarded.push(argument.into());
                    if attached.is_none() {
                        parsed.forwarded.push(value.into());
                    }
                }
            }
            index += 1;
            continue;
        }

        parsed.positionals.push(argument.into());
        if (command, subcommand) != ("repo", "view") {
            parsed.forwarded.push(argument.into());
        }
        index += 1;
    }
    Ok(parsed)
}

fn gh_occurrences(parsed: &ParsedGhTail, name: &str) -> usize {
    parsed.options.get(name).map_or(0, Vec::len)
}

fn gh_values<'a>(parsed: &'a ParsedGhTail, name: &str) -> Vec<&'a str> {
    parsed
        .options
        .get(name)
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_deref())
        .collect()
}

fn valid_positive_number(value: &str) -> bool {
    value.parse::<u64>().is_ok_and(|number| number > 0)
}

fn require_no_positionals(parsed: &ParsedGhTail) -> Result<()> {
    if !parsed.positionals.is_empty() {
        bail!("gh command does not accept positional inference");
    }
    Ok(())
}

fn require_numbered_target(parsed: &ParsedGhTail) -> Result<()> {
    if parsed.positionals.len() != 1 || !valid_positive_number(&parsed.positionals[0]) {
        bail!("gh command requires exactly one positive numeric target");
    }
    Ok(())
}

fn gh_body_source_count(parsed: &ParsedGhTail) -> Result<usize> {
    let files = gh_values(parsed, "--body-file");
    if files.iter().any(|value| *value != "-") {
        bail!("gh body-file input is restricted to standard input");
    }
    Ok(gh_occurrences(parsed, "--body") + files.len())
}

fn validate_gh_shape(command: &str, subcommand: &str, parsed: &mut ParsedGhTail) -> Result<bool> {
    match (command, subcommand) {
        ("pr", "list") | ("run", "list") | ("workflow", "list") | ("release", "list") => {
            require_no_positionals(parsed)?
        }
        ("pr", "view" | "checks" | "diff") => require_numbered_target(parsed)?,
        ("pr", "create") => {
            require_no_positionals(parsed)?;
            for (option, description) in [
                ("--head", "already-pushed head"),
                ("--base", "base"),
                ("--title", "title"),
            ] {
                let values = gh_values(parsed, option);
                if values.len() != 1 || values[0].is_empty() {
                    bail!("gh pull-request creation requires exactly one explicit {description}");
                }
            }
            if gh_body_source_count(parsed)? != 1 {
                bail!("gh pull-request creation requires exactly one explicit body source");
            }
            if gh_values(parsed, "--body")
                .first()
                .is_some_and(|value| value.is_empty())
            {
                bail!("gh pull-request creation requires a nonempty body");
            }
        }
        ("pr", "comment") => {
            require_numbered_target(parsed)?;
            if gh_body_source_count(parsed)? != 1 {
                bail!("gh pull-request comment requires exactly one explicit body source");
            }
        }
        ("pr", "edit") => {
            require_numbered_target(parsed)?;
            if parsed.options.is_empty() {
                bail!("gh pull-request edit requires an explicit mutation");
            }
            if gh_body_source_count(parsed)? > 1 {
                bail!("gh pull-request edit accepts at most one explicit body source");
            }
        }
        ("pr", "ready") => require_numbered_target(parsed)?,
        ("pr", "review") => {
            require_numbered_target(parsed)?;
            let actions = ["--approve", "--comment", "--request-changes"];
            if actions
                .iter()
                .map(|option| gh_occurrences(parsed, option))
                .sum::<usize>()
                != 1
            {
                bail!("gh pull-request review requires exactly one explicit review action");
            }
            let body_sources = gh_body_source_count(parsed)?;
            let needs_body = gh_occurrences(parsed, "--comment") == 1
                || gh_occurrences(parsed, "--request-changes") == 1;
            if body_sources > 1 || needs_body && body_sources != 1 {
                bail!("gh pull-request review has an invalid explicit body source");
            }
        }
        ("pr", "merge") => {
            require_numbered_target(parsed)?;
            if ["--merge", "--rebase", "--squash"]
                .iter()
                .map(|option| gh_occurrences(parsed, option))
                .sum::<usize>()
                != 1
            {
                bail!("gh pull-request merge requires exactly one explicit strategy");
            }
            if gh_body_source_count(parsed)? > 1 {
                bail!("gh pull-request merge accepts at most one explicit body source");
            }
        }
        ("pr", "close" | "reopen") => {
            require_numbered_target(parsed)?;
            if gh_occurrences(parsed, "--comment") > 1 {
                bail!("gh pull-request mutation accepts at most one explicit comment");
            }
        }
        ("run", "view" | "watch") => require_numbered_target(parsed)?,
        ("workflow", "view") | ("release", "view") => {
            if parsed.positionals.len() != 1 || parsed.positionals[0].is_empty() {
                bail!("gh command requires exactly one explicit target");
            }
        }
        ("repo", "view") => {
            if parsed.positionals.len() > 1 {
                bail!("gh repository view accepts at most one repository target");
            }
            if let Some(value) = parsed.positionals.first() {
                set_gh_repository(&mut parsed.repository, value)?;
            }
            return Ok(true);
        }
        _ => bail!("gh command is outside the repository-scoped automation surface"),
    }
    Ok(false)
}

pub(crate) fn parse_gh_invocation<S: AsRef<str>>(arguments: &[S]) -> Result<GhInvocationPlan> {
    let command = arguments
        .first()
        .map(AsRef::as_ref)
        .context("gh command is missing")?;
    let subcommand = arguments
        .get(1)
        .map(AsRef::as_ref)
        .context("gh subcommand is missing")?;
    if command.starts_with('-') || subcommand.starts_with('-') {
        bail!("gh global options and implicit command selection are not admitted");
    }
    let specs = gh_specs(command, subcommand)?;
    let tail: Vec<&str> = arguments.iter().skip(2).map(AsRef::as_ref).collect();
    let mut parsed = parse_gh_tail(command, subcommand, &tail, &specs)?;
    let inject_repository_argument = validate_gh_shape(command, subcommand, &mut parsed)?;
    Ok(GhInvocationPlan {
        repository: parsed.repository,
        forwarded_arguments: parsed.forwarded,
        inject_repository_argument,
    })
}

pub fn admit_gh_arguments<S: AsRef<str>>(arguments: &[S]) -> Result<()> {
    parse_gh_invocation(arguments).map(|_| ())
}

#[cfg(test)]
mod git_capability_tests {
    use super::{git_capability, GitCapability};

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn managed_git_capability_is_derived_from_the_admitted_command() {
        for values in [
            &["status", "--short"][..],
            &["add", "--", "src/lib.rs"],
            &["restore", "--", "src/lib.rs"],
            &["checkout", "--", "src/lib.rs"],
            &[
                "log",
                "--oneline",
                "0123456789abcdef0123456789abcdef01234567",
            ],
            &["show", "--stat", "0123456789abcdef0123456789abcdef01234567"],
        ] {
            assert_eq!(
                git_capability(&arguments(values)).unwrap(),
                GitCapability::NoAuthority,
                "{values:?}"
            );
        }

        for values in [
            &[
                "fetch",
                "origin",
                "refs/heads/main:refs/remotes/origin/main",
            ][..],
            &["push", "origin", "HEAD:refs/heads/main"],
            &[
                "clone",
                "--no-checkout",
                "https://github.com/ExampleOrg/repository.git",
                "repository",
            ],
        ] {
            assert_eq!(
                git_capability(&arguments(values)).unwrap(),
                GitCapability::GitHubToken,
                "{values:?}"
            );
        }

        for values in [
            &["commit", "--no-status", "--message", "bounded change"][..],
            &["tag", "--message", "release", "v1.2.3"],
        ] {
            assert_eq!(
                git_capability(&arguments(values)).unwrap(),
                GitCapability::Signing,
                "{values:?}"
            );
        }
    }

    #[test]
    fn rejected_git_commands_never_receive_a_capability() {
        for values in [
            &["pull", "--ff-only", "origin", "main"][..],
            &["add", "--all"],
            &["add", "--", "nested/../secret.txt"],
            &["restore", "--", ":(glob)**"],
            &["commit", "--message", "missing no-status"],
            &[
                "clone",
                "https://github.com/ExampleOrg/repository.git",
                "repository",
            ],
            &["fetch", "origin", "main"],
            &[
                "restore",
                "--source",
                "refs/heads/feature",
                "--",
                "src/lib.rs",
            ],
            &["branch", "new", "refs/heads/feature"],
            &["switch", "feature"],
            &["checkout", "feature"],
            &["log", "feature"],
            &["show", "refs/heads/feature"],
            &[
                "fetch",
                "origin",
                "refs/heads/one:refs/remotes/origin/one",
                "refs/heads/two:refs/remotes/origin/two",
            ],
        ] {
            assert!(git_capability(&arguments(values)).is_err(), "{values:?}");
        }
    }
}
