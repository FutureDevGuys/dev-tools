//! Trusted artifact catalog and deterministic target selection.
//!
//! Every selector and destination comes from local configuration. Remote
//! metadata is data only and cannot introduce commands, paths, or selectors.

use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

const CONFIG_SCHEMA: &str = "artifact-update-config-v1";
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_ARTIFACTS: usize = 1024;
const MAX_SELECTORS: usize = 64;
const MAX_CATALOG_SELECTORS: usize = 256;
const MAX_PATTERN_BYTES: usize = 1024;
const MAX_COMPONENT_BYTES: usize = 128;
const MAX_CANDIDATES: usize = 4096;
const MAX_COMPILED_REGEX_BYTES: usize = 64 * 1024;
const ALLOWED_CAPTURES: &[&str] = &[
    "version",
    "channel",
    "os",
    "architecture",
    "libc",
    "runtime",
    "variant",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactConfigErrorKind {
    InvalidDocument,
    InvalidSchema,
    InvalidIdentifier,
    DuplicateArtifact,
    InvalidSource,
    InvalidVersionRule,
    InvalidSelector,
    ResourceLimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactConfigError {
    kind: ArtifactConfigErrorKind,
}

impl ArtifactConfigError {
    fn new(kind: ArtifactConfigErrorKind) -> Self {
        Self { kind }
    }

    pub fn kind(self) -> ArtifactConfigErrorKind {
        self.kind
    }
}

impl fmt::Display for ArtifactConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            ArtifactConfigErrorKind::InvalidDocument => "artifact catalog is invalid",
            ArtifactConfigErrorKind::InvalidSchema => "artifact catalog schema is not supported",
            ArtifactConfigErrorKind::InvalidIdentifier => "artifact identifier is invalid",
            ArtifactConfigErrorKind::DuplicateArtifact => "artifact catalog contains a duplicate",
            ArtifactConfigErrorKind::InvalidSource => "artifact source is invalid",
            ArtifactConfigErrorKind::InvalidVersionRule => "artifact version rule is invalid",
            ArtifactConfigErrorKind::InvalidSelector => "artifact selector is invalid",
            ArtifactConfigErrorKind::ResourceLimitExceeded => {
                "artifact catalog exceeds a resource limit"
            }
        })
    }
}

impl Error for ArtifactConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactSelectionErrorKind {
    InvalidCandidate,
    Ambiguous,
    ResourceLimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactSelectionError {
    kind: ArtifactSelectionErrorKind,
}

impl ArtifactSelectionError {
    fn new(kind: ArtifactSelectionErrorKind) -> Self {
        Self { kind }
    }

    pub fn kind(self) -> ArtifactSelectionErrorKind {
        self.kind
    }
}

impl fmt::Display for ArtifactSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            ArtifactSelectionErrorKind::InvalidCandidate => "artifact candidate is invalid",
            ArtifactSelectionErrorKind::Ambiguous => "artifact selection is ambiguous",
            ArtifactSelectionErrorKind::ResourceLimitExceeded => {
                "artifact candidate inventory exceeds a resource limit"
            }
        })
    }
}

impl Error for ArtifactSelectionError {}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    NativeBinary,
    AppImage,
    Zip,
    Tar,
    Plugin,
    Extension,
    Jar,
    GoBinary,
    NodePackage,
    Other,
}

impl ArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NativeBinary => "native-binary",
            Self::AppImage => "app-image",
            Self::Zip => "zip",
            Self::Tar => "tar",
            Self::Plugin => "plugin",
            Self::Extension => "extension",
            Self::Jar => "jar",
            Self::GoBinary => "go-binary",
            Self::NodePackage => "node-package",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ArtifactSource {
    Github { owner: String, repository: String },
    StaticManifest { url: String },
}

impl ArtifactSource {
    pub fn provider_name(&self) -> &'static str {
        match self {
            Self::Github { .. } => "github",
            Self::StaticManifest { .. } => "static-manifest",
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum VersionRule {
    SemverTag {
        #[serde(default)]
        prefix: String,
    },
    Numeric,
    Calendar,
    ProviderOrder,
    OpaqueCheckOnly,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum VerificationPolicy {
    CheckOnly,
    Sha256Sidecar {
        selector: String,
    },
    SignedManifest {
        root: String,
        trusted_root_public_key: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCatalog {
    schema: String,
    artifacts: Vec<RawArtifact>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawArtifact {
    id: String,
    kind: ArtifactKind,
    source: ArtifactSource,
    version: VersionRule,
    verification: VerificationPolicy,
    selectors: Vec<RawSelector>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum RawSelector {
    Exact {
        pattern: String,
        #[serde(default)]
        os: Option<String>,
        #[serde(default)]
        architecture: Option<String>,
    },
    Glob {
        pattern: String,
        #[serde(default)]
        os: Option<String>,
        #[serde(default)]
        architecture: Option<String>,
    },
    Regex {
        pattern: String,
        #[serde(default)]
        os: Option<String>,
        #[serde(default)]
        architecture: Option<String>,
    },
}

impl RawSelector {
    fn parts(&self) -> (&str, Option<&str>, Option<&str>) {
        match self {
            Self::Exact {
                pattern,
                os,
                architecture,
            }
            | Self::Glob {
                pattern,
                os,
                architecture,
            }
            | Self::Regex {
                pattern,
                os,
                architecture,
            } => (pattern, os.as_deref(), architecture.as_deref()),
        }
    }
}

enum CompiledMatcher {
    Exact(String),
    Regex(Regex),
}

struct CompiledSelector {
    matcher: CompiledMatcher,
    os: Option<String>,
    architecture: Option<String>,
}

pub struct ArtifactRecord {
    id: String,
    kind: ArtifactKind,
    source: ArtifactSource,
    version: VersionRule,
    verification: VerificationPolicy,
    selectors: Vec<CompiledSelector>,
}

impl ArtifactRecord {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn kind(&self) -> ArtifactKind {
        self.kind
    }

    pub fn source(&self) -> &ArtifactSource {
        &self.source
    }

    pub fn version_rule(&self) -> &VersionRule {
        &self.version
    }

    pub fn verification(&self) -> VerificationPolicy {
        self.verification.clone()
    }

    pub fn selector_count(&self) -> usize {
        self.selectors.len()
    }

    pub fn select_asset(
        &self,
        os: &str,
        architecture: &str,
        candidates: &[AssetCandidate],
    ) -> Result<Option<SelectedAsset>, ArtifactSelectionError> {
        if candidates.len() > MAX_CANDIDATES {
            return Err(ArtifactSelectionError::new(
                ArtifactSelectionErrorKind::ResourceLimitExceeded,
            ));
        }
        require_component(os).map_err(|_| {
            ArtifactSelectionError::new(ArtifactSelectionErrorKind::InvalidCandidate)
        })?;
        require_component(architecture).map_err(|_| {
            ArtifactSelectionError::new(ArtifactSelectionErrorKind::InvalidCandidate)
        })?;
        for selector in &self.selectors {
            if selector.os.as_deref().is_some_and(|value| value != os)
                || selector
                    .architecture
                    .as_deref()
                    .is_some_and(|value| value != architecture)
            {
                continue;
            }
            let mut matches = candidates.iter().filter_map(|candidate| {
                selector
                    .capture(candidate)
                    .filter(|captures| {
                        !captures.get("os").is_some_and(|value| value != os)
                            && !captures
                                .get("architecture")
                                .is_some_and(|value| value != architecture)
                    })
                    .map(|captures| (candidate, captures))
            });
            let Some((candidate, captures)) = matches.next() else {
                continue;
            };
            if matches.next().is_some() {
                return Err(ArtifactSelectionError::new(
                    ArtifactSelectionErrorKind::Ambiguous,
                ));
            }
            return Ok(Some(SelectedAsset {
                candidate: candidate.clone(),
                captures,
            }));
        }
        Ok(None)
    }
}

impl CompiledSelector {
    fn capture(&self, candidate: &AssetCandidate) -> Option<BTreeMap<String, String>> {
        match &self.matcher {
            CompiledMatcher::Exact(expected) => (candidate.name == *expected).then(BTreeMap::new),
            CompiledMatcher::Regex(expression) => {
                let captures = expression.captures(&candidate.name)?;
                let matched = captures.get(0)?;
                if matched.start() != 0 || matched.end() != candidate.name.len() {
                    return None;
                }
                Some(
                    expression
                        .capture_names()
                        .flatten()
                        .filter_map(|name| {
                            captures
                                .name(name)
                                .map(|value| (name.to_owned(), value.as_str().to_owned()))
                        })
                        .collect(),
                )
            }
        }
    }
}

pub struct ArtifactCatalog {
    artifacts: BTreeMap<String, ArtifactRecord>,
}

impl ArtifactCatalog {
    pub fn parse(source: &str) -> Result<Self, ArtifactConfigError> {
        if source.len() > MAX_CONFIG_BYTES {
            return Err(ArtifactConfigError::new(
                ArtifactConfigErrorKind::ResourceLimitExceeded,
            ));
        }
        let raw: RawCatalog = toml::from_str(source)
            .map_err(|_| ArtifactConfigError::new(ArtifactConfigErrorKind::InvalidDocument))?;
        if raw.schema != CONFIG_SCHEMA {
            return Err(ArtifactConfigError::new(
                ArtifactConfigErrorKind::InvalidSchema,
            ));
        }
        if raw.artifacts.len() > MAX_ARTIFACTS {
            return Err(ArtifactConfigError::new(
                ArtifactConfigErrorKind::ResourceLimitExceeded,
            ));
        }
        if raw
            .artifacts
            .iter()
            .map(|artifact| artifact.selectors.len())
            .sum::<usize>()
            > MAX_CATALOG_SELECTORS
        {
            return Err(ArtifactConfigError::new(
                ArtifactConfigErrorKind::ResourceLimitExceeded,
            ));
        }
        let mut artifacts = BTreeMap::new();
        for raw_artifact in raw.artifacts {
            require_identifier(&raw_artifact.id)?;
            validate_source(&raw_artifact.source)?;
            validate_version_rule(&raw_artifact.version)?;
            validate_verification(&raw_artifact.verification)?;
            if raw_artifact.selectors.is_empty() || raw_artifact.selectors.len() > MAX_SELECTORS {
                return Err(ArtifactConfigError::new(
                    ArtifactConfigErrorKind::ResourceLimitExceeded,
                ));
            }
            let selectors = raw_artifact
                .selectors
                .into_iter()
                .map(compile_selector)
                .collect::<Result<Vec<_>, _>>()?;
            let id = raw_artifact.id;
            let record = ArtifactRecord {
                id: id.clone(),
                kind: raw_artifact.kind,
                source: raw_artifact.source,
                version: raw_artifact.version,
                verification: raw_artifact.verification,
                selectors,
            };
            if artifacts.insert(id, record).is_some() {
                return Err(ArtifactConfigError::new(
                    ArtifactConfigErrorKind::DuplicateArtifact,
                ));
            }
        }
        Ok(Self { artifacts })
    }

    pub fn get(&self, id: &str) -> Option<&ArtifactRecord> {
        self.artifacts.get(id)
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &ArtifactRecord)> {
        self.artifacts
            .iter()
            .map(|(id, artifact)| (id.as_str(), artifact))
    }
}

#[derive(Debug, Clone)]
pub struct AssetCandidate {
    name: String,
    url: String,
}

impl AssetCandidate {
    pub fn new(
        name: impl Into<String>,
        url: impl Into<String>,
    ) -> Result<Self, ArtifactSelectionError> {
        let name = name.into();
        let url = url.into();
        if name.is_empty()
            || name.len() > 1024
            || matches!(name.as_str(), "." | "..")
            || name.contains(['/', '\\'])
            || name.chars().any(char::is_control)
            || !valid_https_url(&url)
        {
            return Err(ArtifactSelectionError::new(
                ArtifactSelectionErrorKind::InvalidCandidate,
            ));
        }
        Ok(Self { name, url })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

#[derive(Debug, Clone)]
pub struct SelectedAsset {
    candidate: AssetCandidate,
    captures: BTreeMap<String, String>,
}

impl SelectedAsset {
    pub fn name(&self) -> &str {
        self.candidate.name()
    }

    pub fn url(&self) -> &str {
        self.candidate.url()
    }

    pub fn captures(&self) -> &BTreeMap<String, String> {
        &self.captures
    }
}

fn compile_selector(raw: RawSelector) -> Result<CompiledSelector, ArtifactConfigError> {
    let (pattern, os, architecture) = raw.parts();
    if pattern.is_empty() || pattern.len() > MAX_PATTERN_BYTES {
        return Err(ArtifactConfigError::new(
            ArtifactConfigErrorKind::InvalidSelector,
        ));
    }
    if let Some(value) = os {
        require_component(value)?;
    }
    if let Some(value) = architecture {
        require_component(value)?;
    }
    let matcher = match &raw {
        RawSelector::Exact { pattern, .. } => {
            if pattern.contains(['/', '\\', '\0', '\n', '\r']) {
                return Err(ArtifactConfigError::new(
                    ArtifactConfigErrorKind::InvalidSelector,
                ));
            }
            CompiledMatcher::Exact(pattern.clone())
        }
        RawSelector::Glob { pattern, .. } => {
            let expression = compile_expression(&glob_expression(pattern))?;
            CompiledMatcher::Regex(expression)
        }
        RawSelector::Regex { pattern, .. } => {
            if !pattern.starts_with('^') || !pattern.ends_with('$') {
                return Err(ArtifactConfigError::new(
                    ArtifactConfigErrorKind::InvalidSelector,
                ));
            }
            // Group the entire expression so alternation cannot escape the
            // filename boundary supplied by local configuration.
            let expression = compile_expression(&format!(r"\A(?:{pattern})\z"))?;
            let names = expression
                .capture_names()
                .flatten()
                .collect::<BTreeSet<_>>();
            if names.iter().any(|name| !ALLOWED_CAPTURES.contains(name)) {
                return Err(ArtifactConfigError::new(
                    ArtifactConfigErrorKind::InvalidSelector,
                ));
            }
            CompiledMatcher::Regex(expression)
        }
    };
    Ok(CompiledSelector {
        matcher,
        os: os.map(ToOwned::to_owned),
        architecture: architecture.map(ToOwned::to_owned),
    })
}

fn compile_expression(pattern: &str) -> Result<Regex, ArtifactConfigError> {
    RegexBuilder::new(pattern)
        .size_limit(MAX_COMPILED_REGEX_BYTES)
        .dfa_size_limit(MAX_COMPILED_REGEX_BYTES)
        .build()
        .map_err(|_| ArtifactConfigError::new(ArtifactConfigErrorKind::InvalidSelector))
}

fn glob_expression(pattern: &str) -> String {
    let mut expression = String::with_capacity(pattern.len() + 2);
    expression.push('^');
    for character in pattern.chars() {
        match character {
            '*' => expression.push_str(".*"),
            '?' => expression.push('.'),
            character => expression.push_str(&regex::escape(&character.to_string())),
        }
    }
    expression.push('$');
    expression
}

fn validate_source(source: &ArtifactSource) -> Result<(), ArtifactConfigError> {
    match source {
        ArtifactSource::Github { owner, repository } => {
            require_component(owner)?;
            require_component(repository)
        }
        ArtifactSource::StaticManifest { url } if valid_https_url(url) => Ok(()),
        ArtifactSource::StaticManifest { .. } => Err(ArtifactConfigError::new(
            ArtifactConfigErrorKind::InvalidSource,
        )),
    }
}

fn validate_version_rule(rule: &VersionRule) -> Result<(), ArtifactConfigError> {
    if let VersionRule::SemverTag { prefix } = rule {
        if prefix.len() > 64 || prefix.contains(['\0', '\n', '\r']) {
            return Err(ArtifactConfigError::new(
                ArtifactConfigErrorKind::InvalidVersionRule,
            ));
        }
    }
    Ok(())
}

fn validate_verification(policy: &VerificationPolicy) -> Result<(), ArtifactConfigError> {
    match policy {
        VerificationPolicy::CheckOnly => Ok(()),
        VerificationPolicy::Sha256Sidecar { selector } => {
            if selector.is_empty() || selector.len() > MAX_PATTERN_BYTES {
                Err(ArtifactConfigError::new(
                    ArtifactConfigErrorKind::InvalidSelector,
                ))
            } else {
                Ok(())
            }
        }
        VerificationPolicy::SignedManifest {
            root,
            trusted_root_public_key,
        } => {
            if valid_https_url(root)
                && dev_tools_release::parse_release_public_key(trusted_root_public_key).is_ok()
            {
                Ok(())
            } else {
                Err(ArtifactConfigError::new(
                    ArtifactConfigErrorKind::InvalidSource,
                ))
            }
        }
    }
}

fn require_identifier(value: &str) -> Result<(), ArtifactConfigError> {
    if value.is_empty()
        || value.len() > MAX_COMPONENT_BYTES
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || index > 0 && matches!(byte, b'-' | b'_')
        })
        || !value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
    {
        return Err(ArtifactConfigError::new(
            ArtifactConfigErrorKind::InvalidIdentifier,
        ));
    }
    Ok(())
}

fn require_component(value: &str) -> Result<(), ArtifactConfigError> {
    if value.is_empty()
        || value.len() > MAX_COMPONENT_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ArtifactConfigError::new(
            ArtifactConfigErrorKind::InvalidSource,
        ));
    }
    Ok(())
}

fn valid_https_url(value: &str) -> bool {
    if value.len() > 4096
        || value.contains(['\\', '#'])
        || value.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
    {
        return false;
    }
    let Ok(uri) = value.parse::<http::Uri>() else {
        return false;
    };
    let Some(authority) = uri.authority() else {
        return false;
    };
    let port_suffix = authority
        .as_str()
        .strip_prefix(authority.host())
        .unwrap_or("");
    uri.scheme_str() == Some("https")
        && !authority.host().is_empty()
        && !authority.as_str().contains('@')
        && (port_suffix.is_empty() || authority.port_u16().is_some_and(|port| port != 0))
}
