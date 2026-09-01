use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

const DOCUMENT_LIMIT: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DeploymentMode {
    Strong,
    UserOnly,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Stable,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Activation {
    Transparent,
    Inactive,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialIntent {
    Preserve,
    EnrollIfAbsent,
    Rotate,
    Revoke,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentUser {
    pub name: String,
    pub config: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentCredential {
    pub slot: String,
    pub intent: CredentialIntent,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentDocument {
    pub schema: String,
    pub mode: DeploymentMode,
    pub channel: Channel,
    #[serde(default)]
    pub offline: bool,
    pub activation: Activation,
    pub administrator_policy: PathBuf,
    #[serde(default)]
    pub users: Vec<DeploymentUser>,
    #[serde(default)]
    pub credentials: Vec<DeploymentCredential>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeploymentCliInput {
    pub mode: Option<DeploymentMode>,
    pub channel: Option<Channel>,
    pub offline: Option<bool>,
    pub activation: Option<Activation>,
    pub administrator_policy: Option<PathBuf>,
    pub user_configs: Vec<(String, PathBuf)>,
    pub user_policies: Vec<(String, PathBuf)>,
    pub credential_intents: Vec<(String, CredentialIntent)>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentIntent {
    pub schema: String,
    pub mode: DeploymentMode,
    pub channel: Channel,
    pub offline: bool,
    pub activation: Activation,
    pub administrator_policy: PathBuf,
    pub users: Vec<DeploymentUser>,
    pub credentials: Vec<DeploymentCredential>,
}

pub fn parse_deployment_document(input: &[u8]) -> Result<DeploymentDocument> {
    if input.is_empty() || input.len() > DOCUMENT_LIMIT || input.contains(&0) {
        bail!("dev-auth deployment document is empty or exceeds its public size bound");
    }
    let text = std::str::from_utf8(input).context("deployment document is not UTF-8")?;
    let document: DeploymentDocument =
        toml::from_str(text).context("parse dev-auth deployment document")?;
    validate_document(&document)?;
    Ok(document)
}

pub fn read_deployment_document(path: &Path) -> Result<DeploymentDocument> {
    if !path.is_absolute() {
        bail!("deployment document path must be absolute");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .with_context(|| format!("open deployment document {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect deployment document {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() as usize > DOCUMENT_LIMIT
    {
        bail!("deployment document has unsafe filesystem authority");
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
        bail!("deployment document has unsafe filesystem authority");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(DOCUMENT_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .context("read deployment document")?;
    if bytes.len() as u64 != metadata.len() {
        bail!("deployment document changed while being read");
    }
    parse_deployment_document(&bytes)
}

pub fn normalize_deployment(
    document: Option<DeploymentDocument>,
    cli: DeploymentCliInput,
) -> Result<DeploymentIntent> {
    if let Some(document) = &document {
        validate_document(document)?;
    }
    let cli_users = cli_users(&cli)?;
    let cli_credentials = unique_credentials(&cli.credential_intents, "CLI")?;

    let mode = agree(
        document.as_ref().map(|value| value.mode),
        cli.mode,
        "deployment mode",
    )?;
    let channel = agree(
        document.as_ref().map(|value| value.channel),
        cli.channel,
        "release channel",
    )?;
    let offline = match (document.as_ref().map(|value| value.offline), cli.offline) {
        (Some(left), Some(right)) if left != right => {
            bail!("offline release resolution conflicts between deployment document and CLI")
        }
        (Some(value), _) | (_, Some(value)) => value,
        (None, None) => false,
    };
    let activation = agree(
        document.as_ref().map(|value| value.activation),
        cli.activation,
        "launcher activation",
    )?;
    let administrator_policy = agree(
        document
            .as_ref()
            .map(|value| value.administrator_policy.clone()),
        cli.administrator_policy,
        "administrator policy",
    )?;

    let mut users = document
        .as_ref()
        .map(|value| user_map(&value.users, "deployment document"))
        .transpose()?
        .unwrap_or_default();
    merge_maps(&mut users, cli_users, "user")?;
    let mut credentials = document
        .as_ref()
        .map(|value| credential_map(&value.credentials, "deployment document"))
        .transpose()?
        .unwrap_or_default();
    merge_maps(&mut credentials, cli_credentials, "credential slot")?;

    if users.is_empty() {
        bail!("deployment intent must declare at least one native user");
    }
    if mode == DeploymentMode::Strong && users.values().any(|user| user.policy.is_some()) {
        bail!("strong mode does not accept per-user policy authority");
    }
    let intent = DeploymentIntent {
        schema: "dev-auth-deployment-intent-v1".into(),
        mode,
        channel,
        offline,
        activation,
        administrator_policy: normalized_absolute_path(
            &administrator_policy,
            "administrator policy",
        )?,
        users: users.into_values().collect(),
        credentials: credentials.into_values().collect(),
    };
    validate_intent(&intent)?;
    Ok(intent)
}

pub fn canonical_deployment_intent(intent: &DeploymentIntent) -> Result<Vec<u8>> {
    validate_intent(intent)?;
    serde_jcs::to_vec(intent).context("canonicalize dev-auth deployment intent")
}

fn agree<T>(document: Option<T>, cli: Option<T>, description: &str) -> Result<T>
where
    T: PartialEq,
{
    match (document, cli) {
        (Some(left), Some(right)) if left != right => {
            bail!("{description} conflicts between deployment document and CLI")
        }
        (Some(value), _) | (_, Some(value)) => Ok(value),
        (None, None) => bail!("{description} is required"),
    }
}

fn cli_users(cli: &DeploymentCliInput) -> Result<BTreeMap<String, DeploymentUser>> {
    let mut configs = BTreeMap::new();
    for (name, path) in &cli.user_configs {
        validate_identifier(name, "native user")?;
        let path = normalized_absolute_path(path, "user configuration")?;
        if configs.insert(name.clone(), path).is_some() {
            bail!("CLI contains a duplicate native user configuration");
        }
    }
    let mut policies = BTreeMap::new();
    for (name, path) in &cli.user_policies {
        validate_identifier(name, "native user")?;
        let path = normalized_absolute_path(path, "user policy")?;
        if policies.insert(name.clone(), path).is_some() {
            bail!("CLI contains a duplicate native user policy");
        }
    }
    if policies.keys().any(|name| !configs.contains_key(name)) {
        bail!("CLI user policy has no matching user configuration");
    }
    Ok(configs
        .into_iter()
        .map(|(name, config)| {
            let policy = policies.remove(&name);
            (
                name.clone(),
                DeploymentUser {
                    name,
                    config,
                    policy,
                },
            )
        })
        .collect())
}

fn unique_credentials(
    entries: &[(String, CredentialIntent)],
    source: &str,
) -> Result<BTreeMap<String, DeploymentCredential>> {
    let mut credentials = BTreeMap::new();
    for (slot, intent) in entries {
        validate_identifier(slot, "credential slot")?;
        if credentials
            .insert(
                slot.clone(),
                DeploymentCredential {
                    slot: slot.clone(),
                    intent: *intent,
                },
            )
            .is_some()
        {
            bail!("{source} contains a duplicate credential slot");
        }
    }
    Ok(credentials)
}

fn user_map(users: &[DeploymentUser], source: &str) -> Result<BTreeMap<String, DeploymentUser>> {
    let mut mapped = BTreeMap::new();
    for user in users {
        validate_user(user)?;
        if mapped.insert(user.name.clone(), user.clone()).is_some() {
            bail!("{source} contains a duplicate native user");
        }
    }
    Ok(mapped)
}

fn credential_map(
    credentials: &[DeploymentCredential],
    source: &str,
) -> Result<BTreeMap<String, DeploymentCredential>> {
    unique_credentials(
        &credentials
            .iter()
            .map(|entry| (entry.slot.clone(), entry.intent))
            .collect::<Vec<_>>(),
        source,
    )
}

fn merge_maps<T: PartialEq>(
    destination: &mut BTreeMap<String, T>,
    source: BTreeMap<String, T>,
    description: &str,
) -> Result<()> {
    for (name, value) in source {
        match destination.get(&name) {
            Some(existing) if existing != &value => {
                bail!("{description} {name} conflicts between deployment document and CLI")
            }
            Some(_) => {}
            None => {
                destination.insert(name, value);
            }
        }
    }
    Ok(())
}

fn validate_document(document: &DeploymentDocument) -> Result<()> {
    if document.schema != "dev-auth-deployment-v1" {
        bail!("dev-auth deployment document schema is unsupported");
    }
    normalized_absolute_path(&document.administrator_policy, "administrator policy")?;
    let users = user_map(&document.users, "deployment document")?;
    if users.is_empty() {
        bail!("deployment document must declare at least one native user");
    }
    if document.mode == DeploymentMode::Strong && users.values().any(|user| user.policy.is_some()) {
        bail!("strong mode does not accept per-user policy authority");
    }
    credential_map(&document.credentials, "deployment document")?;
    Ok(())
}

fn validate_intent(intent: &DeploymentIntent) -> Result<()> {
    if intent.schema != "dev-auth-deployment-intent-v1" {
        bail!("dev-auth deployment intent schema is unsupported");
    }
    normalized_absolute_path(&intent.administrator_policy, "administrator policy")?;
    let users = user_map(&intent.users, "deployment intent")?;
    credential_map(&intent.credentials, "deployment intent")?;
    if users.is_empty() {
        bail!("deployment intent must declare at least one native user");
    }
    if intent.mode == DeploymentMode::Strong && users.values().any(|user| user.policy.is_some()) {
        bail!("strong mode does not accept per-user policy authority");
    }
    Ok(())
}

fn validate_user(user: &DeploymentUser) -> Result<()> {
    validate_identifier(&user.name, "native user")?;
    normalized_absolute_path(&user.config, "user configuration")?;
    if let Some(policy) = &user.policy {
        normalized_absolute_path(policy, "user policy")?;
    }
    Ok(())
}

fn validate_identifier(value: &str, description: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || value.starts_with(['.', '-'])
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        bail!("{description} identifier is invalid");
    }
    Ok(())
}

fn normalized_absolute_path(path: &Path, description: &str) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("{description} path must be absolute");
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                normalized.push(component.as_os_str())
            }
            Component::CurDir => {}
            Component::ParentDir => bail!("{description} path cannot contain parent traversal"),
        }
    }
    if normalized == Path::new("/") {
        bail!("{description} path cannot be the filesystem root");
    }
    Ok(normalized)
}

impl FromStr for DeploymentMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "strong" => Ok(Self::Strong),
            "user-only" => Ok(Self::UserOnly),
            _ => bail!("deployment mode must be strong or user-only"),
        }
    }
}

impl FromStr for Channel {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "stable" => Ok(Self::Stable),
            _ => bail!("release channel must be stable"),
        }
    }
}

impl FromStr for Activation {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "transparent" => Ok(Self::Transparent),
            "inactive" => Ok(Self::Inactive),
            _ => bail!("activation must be transparent or inactive"),
        }
    }
}

impl FromStr for CredentialIntent {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "preserve" => Ok(Self::Preserve),
            "enroll-if-absent" => Ok(Self::EnrollIfAbsent),
            "rotate" => Ok(Self::Rotate),
            "revoke" => Ok(Self::Revoke),
            _ => bail!("credential intent must be preserve, enroll-if-absent, rotate, or revoke"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_form_is_stable() {
        let document = parse_deployment_document(
            br#"schema = "dev-auth-deployment-v1"
mode = "strong"
channel = "stable"
activation = "inactive"
administrator_policy = "/etc/dev-auth/policy.toml"
[[users]]
name = "automation"
config = "/srv/dev-auth/automation.toml"
"#,
        )
        .unwrap();
        let intent = normalize_deployment(Some(document), DeploymentCliInput::default()).unwrap();
        assert_eq!(
            canonical_deployment_intent(&intent).unwrap(),
            canonical_deployment_intent(&intent).unwrap()
        );
    }
}
