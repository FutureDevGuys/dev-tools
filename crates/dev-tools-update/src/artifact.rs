//! Trusted artifact catalog and deterministic target selection.
//!
//! Every selector and destination comes from local configuration. Remote
//! metadata is data only and cannot introduce commands, paths, or selectors.

use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::path::{Component, Path, PathBuf};

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
    InvalidInstallation,
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
            ArtifactConfigErrorKind::InvalidInstallation => {
                "artifact installation policy is invalid"
            }
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
    Github {
        owner: String,
        repository: String,
    },
    Gitlab {
        api: String,
        project: String,
    },
    Forgejo {
        api: String,
        owner: String,
        repository: String,
    },
    Gitea {
        api: String,
        owner: String,
        repository: String,
    },
    GenericJson {
        url: String,
        mapping: JsonReleaseMapping,
    },
    GenericXml {
        url: String,
        mapping: Box<XmlReleaseMapping>,
    },
    Npm {
        registry: String,
        package: String,
        tag: String,
    },
    CratesIo {
        package: String,
    },
    Maven {
        repository: String,
        group: String,
        artifact: String,
        extension: String,
        classifier: Option<String>,
    },
    Sparkle {
        url: String,
        version_field: SparkleVersionField,
    },
    Zsync {
        url: String,
    },
    Html {
        url: String,
    },
    Url {
        url: String,
        #[serde(default)]
        redirect_hosts: Vec<String>,
    },
    StaticManifest {
        url: String,
    },
}

impl ArtifactSource {
    pub fn provider_name(&self) -> &'static str {
        match self {
            Self::Github { .. } => "github",
            Self::Gitlab { .. } => "gitlab",
            Self::Forgejo { .. } => "forgejo",
            Self::Gitea { .. } => "gitea",
            Self::GenericJson { .. } => "generic-json",
            Self::GenericXml { .. } => "generic-xml",
            Self::Zsync { .. } => "zsync",
            Self::Html { .. } => "html",
            Self::Url { .. } => "url",
            Self::Npm { .. } => "npm",
            Self::CratesIo { .. } => "crates-io",
            Self::Maven { .. } => "maven",
            Self::Sparkle { .. } => "sparkle",
            Self::StaticManifest { .. } => "static-manifest",
        }
    }
}

/// The appcast's internal build identity and display identity are distinct.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SparkleVersionField {
    BundleVersion,
    ShortVersion,
}

/// Locally declared JSON Pointer strings. Remote metadata cannot replace these
/// mappings or supply an expression language, command, destination or verifier.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JsonReleaseMapping {
    pub releases: String,
    pub tag: String,
    pub assets: String,
    pub name: String,
    pub url: String,
    pub draft: Option<String>,
    pub prerelease: Option<String>,
}

/// An exact expanded XML name. Namespace prefixes are not lookup authority.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XmlName {
    #[serde(default)]
    pub namespace: String,
    pub name: String,
}

/// An exact relative path to scalar text or a named attribute; not XPath.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XmlValueMapping {
    pub path: Vec<XmlName>,
    pub attribute: Option<XmlName>,
}

/// An optional literal attribute equality on candidate elements.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XmlAttributeFilter {
    pub attribute: XmlName,
    pub equals: String,
}

/// Locally selected release fields. All paths traverse direct children only.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XmlReleaseMapping {
    pub inventory: Vec<XmlName>,
    pub release: XmlName,
    pub version: XmlValueMapping,
    pub assets: Vec<XmlName>,
    pub asset_filter: Option<XmlAttributeFilter>,
    pub url: XmlValueMapping,
    pub name: Option<XmlValueMapping>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum VersionRule {
    SemverTag {
        #[serde(default)]
        prefix: String,
    },
    #[serde(deserialize_with = "deserialize_empty_variant")]
    Numeric,
    #[serde(deserialize_with = "deserialize_empty_variant")]
    Calendar,
    CalendarTag {
        #[serde(default)]
        prefix: String,
        format: CalendarFormat,
    },
    #[serde(deserialize_with = "deserialize_empty_variant")]
    ProviderOrder,
    #[serde(deserialize_with = "deserialize_empty_variant")]
    OpaqueCheckOnly,
}

// Internally tagged unit variants otherwise discard remaining map fields, even
// with the enclosing enum's deny_unknown_fields. Keep their public unit shape.
fn deserialize_empty_variant<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<(), D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}
    Empty::deserialize(deserializer).map(|_| ())
}

/// Exact, locale-independent Gregorian date or year-month release syntax.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum CalendarFormat {
    #[serde(rename = "yyyy-mm-dd")]
    YearMonthDayHyphen,
    #[serde(rename = "yyyy.mm.dd")]
    YearMonthDayDot,
    #[serde(rename = "yyyymmdd")]
    YearMonthDayCompact,
    #[serde(rename = "yyyy-mm")]
    YearMonthHyphen,
    #[serde(rename = "yyyy.mm")]
    YearMonthDot,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum VerificationPolicy {
    #[serde(deserialize_with = "deserialize_empty_variant")]
    CheckOnly,
    Sha256Sidecar {
        selector: String,
    },
    SignedManifest {
        root: String,
        trusted_root_public_key: String,
        product: String,
        target: String,
        artifact_url: String,
    },
}

/// Local desired layout only. It grants neither release authenticity nor
/// ownership of existing paths; an installation adapter must prove both.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InstallationPolicy {
    VersionedBinary(BinaryInstallation),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryInstallation {
    data_root: PathBuf,
    bin_dir: PathBuf,
    artifact_name: String,
    aliases: Vec<String>,
}

impl BinaryInstallation {
    pub fn data_root(&self) -> &Path {
        &self.data_root
    }
    pub fn bin_dir(&self) -> &Path {
        &self.bin_dir
    }
    pub fn artifact_name(&self) -> &str {
        &self.artifact_name
    }
    pub fn aliases(&self) -> &[String] {
        &self.aliases
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum RawInstallation {
    VersionedBinary {
        data_root: String,
        bin_dir: String,
        artifact_name: String,
        aliases: Vec<String>,
    },
}

fn compile_installation(
    raw: RawInstallation,
    kind: ArtifactKind,
) -> Result<InstallationPolicy, ArtifactConfigError> {
    let error = || ArtifactConfigError::new(ArtifactConfigErrorKind::InvalidInstallation);
    let RawInstallation::VersionedBinary {
        data_root,
        bin_dir,
        artifact_name,
        aliases,
    } = raw;
    let data_root = installation_path(&data_root).ok_or_else(error)?;
    let bin_dir = installation_path(&bin_dir).ok_or_else(error)?;
    if !matches!(
        kind,
        ArtifactKind::NativeBinary | ArtifactKind::GoBinary | ArtifactKind::AppImage
    ) || installation_roots_overlap(&data_root, &bin_dir)
        || !installation_filename(&artifact_name)
        || aliases.is_empty()
        || aliases.len() > 32
        || aliases.iter().any(|name| !installation_filename(name))
        || aliases
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect::<BTreeSet<_>>()
            .len()
            != aliases.len()
    {
        return Err(error());
    }
    Ok(InstallationPolicy::VersionedBinary(BinaryInstallation {
        data_root,
        bin_dir,
        artifact_name,
        aliases,
    }))
}

fn installation_path(value: &str) -> Option<PathBuf> {
    let path = Path::new(value);
    if value.len() > 4096
        || value.chars().any(char::is_control)
        || !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
    {
        return None;
    }
    #[cfg(windows)]
    if !matches!(path.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), std::path::Prefix::Disk(_)))
        || path.components().any(
            |part| matches!(part, Component::Normal(name) if !windows_installation_component(&name.to_string_lossy())),
        )
    {
        return None;
    }
    #[cfg(not(windows))]
    if value.contains('\\') {
        return None;
    }
    Some(path.to_path_buf())
}

#[cfg(any(windows, test))]
fn windows_installation_component(value: &str) -> bool {
    !value.is_empty()
        && !value.ends_with(['.', ' '])
        && !value.contains(['<', '>', ':', '"', '/', '\\', '|', '?', '*'])
        && !value.chars().any(char::is_control)
        && !windows_device_name(value)
}

fn installation_roots_overlap(data_root: &Path, bin_dir: &Path) -> bool {
    // Conservative lexical screening; native identity and custody checks are
    // still required before mutation, including filesystem alias detection.
    #[cfg(windows)]
    let (data_root, bin_dir) = (
        PathBuf::from(data_root.to_string_lossy().to_uppercase()),
        PathBuf::from(bin_dir.to_string_lossy().to_uppercase()),
    );
    data_root.starts_with(bin_dir.as_os_str()) || bin_dir.starts_with(data_root.as_os_str())
}

#[cfg(test)]
mod installation_path_tests {
    #[test]
    fn windows_components_reject_namespace_aliases_without_rejecting_unicode_homes() {
        for name in [
            "NUL",
            "con.exe",
            "LPT1",
            "COM¹",
            "LPT².txt",
            "COM³",
            "folder.",
            "folder ",
            "file:stream",
            "a?b",
            "a|b",
            "a\nb",
        ] {
            assert!(
                !super::windows_installation_component(name),
                "unsafe component admitted: {name:?}"
            );
        }
        for name in ["work", "My Tools", "Zoë", "工具"] {
            assert!(super::windows_installation_component(name));
        }
    }
}

fn installation_filename(value: &str) -> bool {
    require_component(value).is_ok()
        && !value.starts_with(['.', '-'])
        && !value.ends_with('.')
        && !windows_device_name(value)
}

fn windows_device_name(value: &str) -> bool {
    // Microsoft documents superscript 1–3 as reserved COM/LPT digits too.
    // https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
    let stem = value.split('.').next().unwrap_or("").to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "COM¹"
            | "COM²"
            | "COM³"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
            | "LPT¹"
            | "LPT²"
            | "LPT³"
    )
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
    installation: Option<RawInstallation>,
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
    installation: Option<InstallationPolicy>,
}

impl ArtifactRecord {
    pub fn installation(&self) -> Option<&InstallationPolicy> {
        self.installation.as_ref()
    }

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

    /// Translate only validated local signed-manifest policy into verifier
    /// authority. This does not authenticate metadata or authorize installation.
    /// The local catalog ID is deliberately not the signed product identity.
    pub fn release_authority(&self) -> Option<dev_tools_release::ReleaseAuthority> {
        let VerificationPolicy::SignedManifest {
            trusted_root_public_key,
            product,
            target,
            artifact_url,
            ..
        } = &self.verification
        else {
            return None;
        };
        Some(dev_tools_release::ReleaseAuthority {
            trusted_root_key: trusted_root_public_key.clone(),
            product: product.clone(),
            accepted_manifest_schemas: vec!["dev-tools-product-v2".into()],
            target: target.clone(),
            artifact_url: dev_tools_release::ArtifactUrlPolicy::Exact(artifact_url.clone()),
            require_source_commit: true,
            engine_protocol: 1,
        })
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
            if matches!(
                raw_artifact.verification,
                VerificationPolicy::SignedManifest { .. }
            ) && !matches!(raw_artifact.version, VersionRule::SemverTag { .. })
            {
                return Err(ArtifactConfigError::new(
                    ArtifactConfigErrorKind::InvalidVersionRule,
                ));
            }
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
            if matches!(
                raw_artifact.source,
                ArtifactSource::Zsync { .. }
                    | ArtifactSource::Url { .. }
                    | ArtifactSource::Html { .. }
            ) && !matches!(
                raw_artifact.version,
                VersionRule::OpaqueCheckOnly | VersionRule::ProviderOrder
            ) && selectors.iter().any(|selector| match &selector.matcher {
                CompiledMatcher::Exact(_) => true,
                CompiledMatcher::Regex(expression) => !expression
                    .capture_names()
                    .flatten()
                    .any(|name| name == "version"),
            }) {
                return Err(ArtifactConfigError::new(
                    ArtifactConfigErrorKind::InvalidSelector,
                ));
            }
            let id = raw_artifact.id;
            let installation = raw_artifact
                .installation
                .map(|installation| compile_installation(installation, raw_artifact.kind))
                .transpose()?;
            let record = ArtifactRecord {
                id: id.clone(),
                kind: raw_artifact.kind,
                source: raw_artifact.source,
                version: raw_artifact.version,
                verification: raw_artifact.verification,
                selectors,
                installation,
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
        ArtifactSource::Github { owner, repository }
        | ArtifactSource::Forgejo {
            owner, repository, ..
        }
        | ArtifactSource::Gitea {
            owner, repository, ..
        } => {
            if let ArtifactSource::Forgejo { api, .. } | ArtifactSource::Gitea { api, .. } = source
            {
                if !valid_https_url(api)
                    || !api.ends_with("/api/v1")
                    || api.contains(['?', '%'])
                    || api.split('/').any(|part| matches!(part, "." | ".."))
                {
                    return Err(ArtifactConfigError::new(
                        ArtifactConfigErrorKind::InvalidSource,
                    ));
                }
            }
            if [owner.as_str(), repository.as_str()]
                .iter()
                .any(|component| matches!(*component, "." | ".."))
            {
                return Err(ArtifactConfigError::new(
                    ArtifactConfigErrorKind::InvalidSource,
                ));
            }
            require_component(owner)?;
            require_component(repository)
        }
        ArtifactSource::Gitlab { api, project } => {
            if !valid_https_url(api)
                || !api.ends_with("/api/v4")
                || api.contains(['?', '%'])
                || api.split('/').any(|part| matches!(part, "." | ".."))
                || project.len() > 1024
                || project.split('/').count() > 16
                || project
                    .split('/')
                    .any(|part| matches!(part, "." | "..") || require_component(part).is_err())
            {
                return Err(ArtifactConfigError::new(
                    ArtifactConfigErrorKind::InvalidSource,
                ));
            }
            Ok(())
        }
        ArtifactSource::Maven {
            repository,
            group,
            artifact,
            extension,
            classifier,
        } => {
            let component = |value: &str| {
                require_component(value).is_ok()
                    && value
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
            };
            if !valid_https_url(repository)
                || repository.contains(['?', '%'])
                || repository.split('/').any(|part| matches!(part, "." | ".."))
                || group.len() > 1024
                || group.split('.').count() > 16
                || !group.split('.').all(component)
                || !component(artifact)
                || extension.len() > 32
                || !extension.split('.').all(component)
                || classifier.as_deref().is_some_and(|value| !component(value))
            {
                return Err(ArtifactConfigError::new(
                    ArtifactConfigErrorKind::InvalidSource,
                ));
            }
            Ok(())
        }
        ArtifactSource::CratesIo { package } => {
            if package.len() > 64
                || !package
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphabetic)
                || !package
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(ArtifactConfigError::new(
                    ArtifactConfigErrorKind::InvalidSource,
                ));
            }
            Ok(())
        }
        ArtifactSource::Npm {
            registry,
            package,
            tag,
        } => {
            let name = package.strip_prefix('@').unwrap_or(package);
            let expected_parts = if package.starts_with('@') { 2 } else { 1 };
            let valid_name = package.len() <= 214
                && name.split('/').count() == expected_parts
                && name.split('/').all(|part| {
                    part.as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                        && part.bytes().all(|byte| {
                            byte.is_ascii_lowercase()
                                || byte.is_ascii_digit()
                                || matches!(byte, b'-' | b'_' | b'.')
                        })
                });
            let valid_tag = require_component(tag).is_ok()
                && tag.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                && semver::VersionReq::parse(tag).is_err()
                && tag
                    .strip_prefix('v')
                    .is_none_or(|suffix| semver::VersionReq::parse(suffix).is_err());
            if !valid_https_url(registry)
                || registry.contains(['?', '%'])
                || registry.split('/').any(|part| matches!(part, "." | ".."))
                || !valid_name
                || !valid_tag
            {
                return Err(ArtifactConfigError::new(
                    ArtifactConfigErrorKind::InvalidSource,
                ));
            }
            Ok(())
        }
        ArtifactSource::GenericXml { url, mapping } => {
            let valid_path = |path: &[XmlName]| path.len() <= 16 && path.iter().all(valid_xml_name);
            let valid_value = |value: &XmlValueMapping| {
                valid_path(&value.path) && value.attribute.as_ref().is_none_or(valid_xml_name)
            };
            if !valid_https_url(url)
                || mapping.inventory.is_empty()
                || !valid_path(&mapping.inventory)
                || !valid_xml_name(&mapping.release)
                || !valid_value(&mapping.version)
                || !valid_path(&mapping.assets)
                || !valid_value(&mapping.url)
                || mapping
                    .name
                    .as_ref()
                    .is_some_and(|value| !valid_value(value))
                || mapping.asset_filter.as_ref().is_some_and(|filter| {
                    !valid_xml_name(&filter.attribute)
                        || filter.equals.len() > 1024
                        || filter.equals.chars().any(char::is_control)
                })
            {
                return Err(ArtifactConfigError::new(
                    ArtifactConfigErrorKind::InvalidSource,
                ));
            }
            Ok(())
        }
        ArtifactSource::Url {
            url,
            redirect_hosts,
        } => {
            if !valid_https_url(url)
                || redirect_hosts.len() > 16
                || redirect_hosts.iter().collect::<BTreeSet<_>>().len() != redirect_hosts.len()
                || redirect_hosts.iter().any(|host| {
                    host.len() > 253
                        || host.contains('*')
                        || !dev_tools_release::canonical_https_host(&format!("https://{host}/"))
                            .is_ok_and(|canonical| &canonical == host)
                })
            {
                return Err(ArtifactConfigError::new(
                    ArtifactConfigErrorKind::InvalidSource,
                ));
            }
            Ok(())
        }
        ArtifactSource::GenericJson { url, mapping } => {
            if !valid_https_url(url)
                || [
                    mapping.releases.as_str(),
                    mapping.tag.as_str(),
                    mapping.assets.as_str(),
                    mapping.name.as_str(),
                    mapping.url.as_str(),
                ]
                .into_iter()
                .chain(mapping.draft.as_deref())
                .chain(mapping.prerelease.as_deref())
                .any(|pointer| !valid_json_pointer(pointer))
            {
                return Err(ArtifactConfigError::new(
                    ArtifactConfigErrorKind::InvalidSource,
                ));
            }
            Ok(())
        }
        ArtifactSource::StaticManifest { url }
        | ArtifactSource::Sparkle { url, .. }
        | ArtifactSource::Zsync { url }
        | ArtifactSource::Html { url }
            if valid_https_url(url) =>
        {
            Ok(())
        }
        ArtifactSource::StaticManifest { .. }
        | ArtifactSource::Sparkle { .. }
        | ArtifactSource::Zsync { .. }
        | ArtifactSource::Html { .. } => Err(ArtifactConfigError::new(
            ArtifactConfigErrorKind::InvalidSource,
        )),
    }
}

fn valid_json_pointer(pointer: &str) -> bool {
    if pointer.len() > 512
        || (!pointer.is_empty() && !pointer.starts_with('/'))
        || pointer.chars().any(char::is_control)
        || pointer.bytes().filter(|byte| *byte == b'/').count() > 16
    {
        return false;
    }
    let mut characters = pointer.chars();
    while let Some(character) = characters.next() {
        if character == '~' && !matches!(characters.next(), Some('0' | '1')) {
            return false;
        }
    }
    true
}

fn validate_version_rule(rule: &VersionRule) -> Result<(), ArtifactConfigError> {
    if let VersionRule::CalendarTag { prefix, .. } = rule {
        if prefix.len() > 64 || prefix.chars().any(char::is_control) {
            return Err(ArtifactConfigError::new(
                ArtifactConfigErrorKind::InvalidVersionRule,
            ));
        }
    }
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
            product,
            target,
            artifact_url,
        } => {
            if valid_https_url(root)
                && valid_https_url(artifact_url)
                && dev_tools_release::valid_product_id(product)
                && dev_tools_release::valid_release_target(target)
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

fn valid_xml_name(value: &XmlName) -> bool {
    value.namespace.len() <= 1024
        && !value
            .namespace
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        && value.name.len() <= 128
        && value
            .name
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && value
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
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
