//! Discovery and metadata authentication never grant installation authority.

use crate::artifact::{
    ArtifactRecord, ArtifactSource, AssetCandidate, CalendarFormat, SelectedAsset, VersionRule,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dev_tools_release::{
    fetch_conditional_https, fetch_https, ConditionalHttpsResponse, HttpsPolicy, HttpsValidators,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::time::{Duration, Instant};

const PAGE_LIMIT: usize = 2 * 1024 * 1024;
const PAGE_COUNT_LIMIT: usize = 10;
const PAGE_SIZE: usize = 100;
/// Maximum serialized metadata document accepted by the cache codec.
pub const GITHUB_CACHE_DOCUMENT_LIMIT: usize = 32 * 1024 * 1024;
const CACHE_SCHEMA: &str = "dev-tools-github-metadata-cache-v1";

mod crates_io;
mod forgejo;
mod generic_json;
mod generic_xml;
mod gitea;
mod gitlab;
mod html;
mod maven;
mod npm;
mod sparkle;
mod strict_json;
mod url_source;
mod xml;
mod zsync;
pub use crates_io::{
    check_crates_io_release, check_crates_io_release_cached, CratesIoMetadataCache,
    CRATES_IO_CACHE_DOCUMENT_LIMIT,
};
pub use forgejo::{
    check_forgejo_release, check_forgejo_release_cached, ForgejoMetadataCache,
    FORGEJO_CACHE_DOCUMENT_LIMIT,
};
pub use generic_json::{
    check_generic_json_release, check_generic_json_release_cached, GenericJsonMetadataCache,
    GENERIC_JSON_CACHE_DOCUMENT_LIMIT,
};
pub use generic_xml::{
    check_generic_xml_release, check_generic_xml_release_cached, GenericXmlMetadataCache,
    GENERIC_XML_CACHE_DOCUMENT_LIMIT,
};
pub use gitea::{
    check_gitea_release, check_gitea_release_cached, GiteaMetadataCache, GITEA_CACHE_DOCUMENT_LIMIT,
};
pub use gitlab::{
    check_gitlab_release, check_gitlab_release_cached, GitlabMetadataCache,
    GITLAB_CACHE_DOCUMENT_LIMIT,
};
pub use html::{
    check_html_release, check_html_release_cached, HtmlMetadataCache, HTML_CACHE_DOCUMENT_LIMIT,
};
pub use maven::{
    check_maven_release, check_maven_release_cached, MavenMetadataCache, MAVEN_CACHE_DOCUMENT_LIMIT,
};
pub use npm::{
    check_npm_release, check_npm_release_cached, NpmMetadataCache, NPM_CACHE_DOCUMENT_LIMIT,
};
pub use sparkle::{
    check_sparkle_release, check_sparkle_release_cached, SparkleMetadataCache,
    SPARKLE_CACHE_DOCUMENT_LIMIT,
};
pub use url_source::{
    check_url_release, check_url_release_cached, UrlMetadataCache, URL_CACHE_DOCUMENT_LIMIT,
};
pub use zsync::{
    check_zsync_release, check_zsync_release_cached, ZsyncMetadataCache, ZSYNC_CACHE_DOCUMENT_LIMIT,
};

fn observe_filename_release(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    assets: &[AssetCandidate],
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    let Some(asset) = artifact
        .select_asset(os, architecture, assets)
        .map_err(|_| DiscoveryError::Ambiguous)?
    else {
        return Ok(None);
    };
    let tag = if let Some(version) = asset.captures().get("version") {
        version.clone()
    } else if matches!(
        artifact.version_rule(),
        VersionRule::OpaqueCheckOnly | VersionRule::ProviderOrder
    ) {
        asset.name().to_owned()
    } else {
        return Err(DiscoveryError::InvalidMetadata);
    };
    if tag.is_empty() || tag.len() > 512 || tag.chars().any(char::is_control) {
        return Err(DiscoveryError::InvalidMetadata);
    }
    let Some((_, version)) = parse_version(artifact.version_rule(), &tag) else {
        return Ok(None);
    };
    Ok(Some(ObservedRelease {
        tag,
        version,
        asset,
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiscoveryError {
    UnsupportedSource,
    InvalidMetadata,
    Ambiguous,
    InventoryLimit,
    Unavailable,
    Authentication,
    Acceptance,
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedSource => "artifact source discovery is not supported",
            Self::InvalidMetadata => "artifact release metadata is invalid",
            Self::Ambiguous => "artifact release selection is ambiguous",
            Self::InventoryLimit => "artifact release inventory exceeds its bound",
            Self::Unavailable => "artifact release discovery is unavailable",
            Self::Authentication => "artifact release authentication failed",
            Self::Acceptance => "artifact release acceptance rejected",
        })
    }
}
impl std::error::Error for DiscoveryError {}

/// Explicit network retrieval and signature verification of a static manifest.
/// Each resource admits redirects only within its locally configured host. The
/// returned bytes support a separate product-owned durable acceptance transaction;
/// this call does not advance that ledger or download/install artifact bytes.
pub fn check_static_manifest(
    record: &ArtifactRecord,
) -> Result<
    (
        dev_tools_release::ReleaseMetadata,
        dev_tools_release::VerifiedRelease,
    ),
    DiscoveryError,
> {
    check_static_with_fetch(record, |url, policy, limit| {
        fetch_https(url, policy, limit, None)
            .map(|response| response.bytes)
            .map_err(|_| DiscoveryError::Unavailable)
    })
}

fn check_static_with_fetch(
    record: &ArtifactRecord,
    mut fetch: impl FnMut(&str, &HttpsPolicy, u64) -> Result<Vec<u8>, DiscoveryError>,
) -> Result<
    (
        dev_tools_release::ReleaseMetadata,
        dev_tools_release::VerifiedRelease,
    ),
    DiscoveryError,
> {
    let ArtifactSource::StaticManifest { url } = record.source() else {
        return Err(DiscoveryError::UnsupportedSource);
    };
    let crate::artifact::VerificationPolicy::SignedManifest { root, .. } = record.verification()
    else {
        return Err(DiscoveryError::Authentication);
    };
    let started = Instant::now();
    let mut retrieve = |url: &str| {
        let host = dev_tools_release::canonical_https_host(url)
            .map_err(|_| DiscoveryError::InvalidMetadata)?;
        let remaining = Duration::from_secs(60)
            .checked_sub(started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(DiscoveryError::Unavailable)?;
        let policy = HttpsPolicy {
            allowed_hosts: BTreeSet::from([host]),
            max_redirects: 2,
            timeout: remaining,
            user_agent: "dev-tools-update".into(),
        };
        let bytes = fetch(url, &policy, 512 * 1024)?;
        if bytes.is_empty() || bytes.len() > 512 * 1024 {
            return Err(DiscoveryError::InventoryLimit);
        }
        Ok(bytes)
    };
    let metadata = dev_tools_release::ReleaseMetadata {
        root: retrieve(&root)?,
        manifest: retrieve(url)?,
    };
    let verified = verify_static_manifest_metadata(record, &metadata)?;
    Ok((metadata, verified))
}

/// Authenticate already retrieved static metadata against explicit local policy.
/// This is network-free and does not download artifact bytes, advance a durable
/// acceptance ledger, or establish that the release is the newest available.
pub fn verify_static_manifest_metadata(
    record: &ArtifactRecord,
    metadata: &dev_tools_release::ReleaseMetadata,
) -> Result<dev_tools_release::VerifiedRelease, DiscoveryError> {
    if !matches!(record.source(), ArtifactSource::StaticManifest { .. }) {
        return Err(DiscoveryError::UnsupportedSource);
    }
    let authority = record
        .release_authority()
        .ok_or(DiscoveryError::Authentication)?;
    let verified = dev_tools_release::verify_release_metadata(metadata, &authority)
        .map_err(|_| DiscoveryError::Authentication)?;
    if !verified.version.pre.is_empty() {
        return Err(DiscoveryError::InvalidMetadata);
    }
    Ok(verified)
}

/// Relationship of available metadata to a caller-supplied installed tag.
/// This observation does not authenticate either tag or authorize installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReleaseComparison {
    Equivalent,
    Newer,
    Older,
    /// Different opaque tags, with no defensible ordering between them.
    Changed,
}

/// Compare full release tags using the same local version rule as discovery.
/// The caller obtains the installed tag from its own installation adapter; this
/// operation neither executes an installed program nor accesses the network.
/// Missing/invalid tags are errors, never evidence of a current installation.
pub fn compare_release_tags(
    rule: &VersionRule,
    installed_tag: &str,
    available_tag: &str,
) -> Result<ReleaseComparison, DiscoveryError> {
    for tag in [installed_tag, available_tag] {
        if tag.is_empty() || tag.len() > 512 || tag.chars().any(char::is_control) {
            return Err(DiscoveryError::InvalidMetadata);
        }
    }
    if matches!(
        rule,
        VersionRule::ProviderOrder | VersionRule::OpaqueCheckOnly
    ) {
        return Ok(if installed_tag == available_tag {
            ReleaseComparison::Equivalent
        } else {
            ReleaseComparison::Changed
        });
    }
    let (installed, _) =
        parse_version(rule, installed_tag).ok_or(DiscoveryError::InvalidMetadata)?;
    let (available, _) =
        parse_version(rule, available_tag).ok_or(DiscoveryError::InvalidMetadata)?;
    Ok(match available.compare(&installed)? {
        Ordering::Less => ReleaseComparison::Older,
        Ordering::Equal => ReleaseComparison::Equivalent,
        Ordering::Greater => ReleaseComparison::Newer,
    })
}

/// Unauthenticated observation. This type deliberately cannot be used as a
/// `VerifiedRelease` or an authenticated installation candidate.
#[derive(Debug, Clone)]
pub struct ObservedRelease {
    version: String,
    tag: String,
    asset: SelectedAsset,
}

impl ObservedRelease {
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn tag(&self) -> &str {
        &self.tag
    }
    pub fn asset(&self) -> &SelectedAsset {
        &self.asset
    }
}

struct ReleaseSelection<'a> {
    artifact: &'a ArtifactRecord,
    os: &'a str,
    architecture: &'a str,
    tags: BTreeSet<String>,
    precedences: BTreeSet<VersionKey>,
    selected: Option<(VersionKey, ObservedRelease)>,
}

impl<'a> ReleaseSelection<'a> {
    fn new(
        artifact: &'a ArtifactRecord,
        os: &'a str,
        architecture: &'a str,
    ) -> Result<Self, DiscoveryError> {
        // Target validity does not depend on whether the inventory is empty.
        artifact
            .select_asset(os, architecture, &[])
            .map_err(|_| DiscoveryError::InvalidMetadata)?;
        Ok(Self {
            artifact,
            os,
            architecture,
            tags: BTreeSet::new(),
            precedences: BTreeSet::new(),
            selected: None,
        })
    }

    fn consider(
        &mut self,
        tag: String,
        excluded: bool,
        candidates: impl FnOnce() -> Result<Vec<AssetCandidate>, DiscoveryError>,
    ) -> Result<(), DiscoveryError> {
        if tag.is_empty() || tag.len() > 512 || tag.chars().any(char::is_control) {
            return Err(DiscoveryError::InvalidMetadata);
        }
        if !self.tags.insert(tag.clone()) {
            return Err(DiscoveryError::Ambiguous);
        }
        if excluded {
            return Ok(());
        }
        let Some((key, version)) = parse_version(self.artifact.version_rule(), &tag) else {
            return Ok(());
        };
        let candidates = candidates()?;
        let Some(asset) = self
            .artifact
            .select_asset(self.os, self.architecture, &candidates)
            .map_err(|_| DiscoveryError::Ambiguous)?
        else {
            return Ok(());
        };
        let observation = ObservedRelease {
            version,
            tag,
            asset,
        };
        if !matches!(key, VersionKey::ProviderOrder) && !self.precedences.insert(key.clone()) {
            return Err(DiscoveryError::Ambiguous);
        }
        match &self.selected {
            None => self.selected = Some((key, observation)),
            Some((VersionKey::ProviderOrder, _)) => {}
            Some((previous, _)) => match key.compare(previous)? {
                Ordering::Greater => self.selected = Some((key, observation)),
                Ordering::Equal => return Err(DiscoveryError::Ambiguous),
                Ordering::Less => {}
            },
        }
        Ok(())
    }

    fn finish(self) -> Option<ObservedRelease> {
        self.selected.map(|(_, observation)| observation)
    }
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

/// Bounded original-resource metadata retained between explicit checks.
/// This is not authenticated release evidence or an installation receipt.
/// Failed checks leave it unchanged and still return an error to the caller.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct GithubMetadataCache {
    pages: Vec<CachedGithubPage>,
}

#[derive(Clone, PartialEq, Eq)]
struct CachedGithubPage {
    url: String,
    bytes: Vec<u8>,
    validators: HttpsValidators,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheDocument {
    schema: String,
    pages: Vec<CachePageDocument>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachePageDocument {
    url: String,
    body_base64: String,
    etag: Option<String>,
    last_modified: Option<String>,
}

impl CachedGithubPage {
    fn document(&self) -> CachePageDocument {
        CachePageDocument {
            url: self.url.clone(),
            body_base64: BASE64.encode(&self.bytes),
            etag: self.validators.etag.clone(),
            last_modified: self.validators.last_modified.clone(),
        }
    }

    fn from_document(page: CachePageDocument) -> Result<Self, DiscoveryError> {
        if page.url.len() > 8192 || page.body_base64.len() > PAGE_LIMIT.div_ceil(3) * 4 {
            return Err(DiscoveryError::InventoryLimit);
        }
        for validator in [&page.etag, &page.last_modified].into_iter().flatten() {
            if validator.is_empty()
                || validator.len() > 8192
                || validator.bytes().any(|byte| !(32..=126).contains(&byte))
            {
                return Err(DiscoveryError::InvalidMetadata);
            }
        }
        let body = BASE64
            .decode(page.body_base64)
            .map_err(|_| DiscoveryError::InvalidMetadata)?;
        if body.len() > PAGE_LIMIT {
            return Err(DiscoveryError::InventoryLimit);
        }
        Ok(Self {
            url: page.url,
            bytes: body,
            validators: HttpsValidators {
                etag: page.etag,
                last_modified: page.last_modified,
            },
        })
    }
}

impl GithubMetadataCache {
    /// Encode metadata only. The product owns private atomic file custody,
    /// timestamps, configuration binding and freshness, not this codec.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DiscoveryError> {
        self.encode(CACHE_SCHEMA)
    }

    fn encode(&self, schema: &str) -> Result<Vec<u8>, DiscoveryError> {
        if self.pages.is_empty() || self.pages.len() > PAGE_COUNT_LIMIT {
            return Err(DiscoveryError::InvalidMetadata);
        }
        let pages = self.pages.iter().map(CachedGithubPage::document).collect();
        let bytes = serde_json::to_vec(&CacheDocument {
            schema: schema.into(),
            pages,
        })
        .map_err(|_| DiscoveryError::InvalidMetadata)?;
        if bytes.len() > GITHUB_CACHE_DOCUMENT_LIMIT {
            return Err(DiscoveryError::InventoryLimit);
        }
        Ok(bytes)
    }

    /// Decode bounded untrusted cache bytes, then prove that they form the
    /// complete exact resource sequence required by current local selection.
    /// This performs no filesystem or network access and grants no authority.
    pub fn from_bytes(
        bytes: &[u8],
        artifact: &ArtifactRecord,
        os: &str,
        architecture: &str,
    ) -> Result<Self, DiscoveryError> {
        let cache = Self::decode(bytes, CACHE_SCHEMA)?;
        cache.observe(artifact, os, architecture)?;
        Ok(cache)
    }

    fn decode(bytes: &[u8], schema: &str) -> Result<Self, DiscoveryError> {
        if bytes.len() > GITHUB_CACHE_DOCUMENT_LIMIT {
            return Err(DiscoveryError::InventoryLimit);
        }
        let document: CacheDocument =
            serde_json::from_slice(bytes).map_err(|_| DiscoveryError::InvalidMetadata)?;
        if document.schema != schema
            || document.pages.is_empty()
            || document.pages.len() > PAGE_COUNT_LIMIT
        {
            return Err(DiscoveryError::InvalidMetadata);
        }
        let pages = document
            .pages
            .into_iter()
            .map(CachedGithubPage::from_document)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { pages })
    }

    /// Local-only reselection. Freshness and authenticity must be checked by
    /// the product before displaying these inert observations as usable cache.
    pub fn observe(
        &self,
        artifact: &ArtifactRecord,
        os: &str,
        architecture: &str,
    ) -> Result<Option<ObservedRelease>, DiscoveryError> {
        let mut position = 0;
        let observed = check_github_with_fetch(artifact, os, architecture, |url, _| {
            let page = self
                .pages
                .get(position)
                .filter(|page| page.url == url)
                .ok_or(DiscoveryError::InvalidMetadata)?;
            position += 1;
            Ok(page.bytes.clone())
        })?;
        if position != self.pages.len() {
            return Err(DiscoveryError::InvalidMetadata);
        }
        Ok(observed)
    }
}

/// Explicit conditional network check. All cached bytes are re-parsed and
/// re-selected under the supplied local configuration, never trusted as a
/// previously selected executable. Resource keys are exact generated URLs.
pub fn check_github_release_cached(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut GithubMetadataCache,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    check_github_cached_with_fetch(
        artifact,
        os,
        architecture,
        cache,
        |url, remaining, validators| {
            let policy = HttpsPolicy {
                allowed_hosts: BTreeSet::from(["api.github.com".into()]),
                max_redirects: 2,
                timeout: remaining,
                user_agent: "dev-tools-update".into(),
            };
            fetch_conditional_https(url, &policy, PAGE_LIMIT as u64, validators)
                .map_err(|_| DiscoveryError::Unavailable)
        },
    )
}

fn check_github_cached_with_fetch(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut GithubMetadataCache,
    mut fetch: impl FnMut(
        &str,
        Duration,
        &HttpsValidators,
    ) -> Result<ConditionalHttpsResponse, DiscoveryError>,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    let mut next = Vec::new();
    let observed = check_github_with_fetch(artifact, os, architecture, |url, remaining| {
        let page = cached_page(&cache.pages, url, |validators| {
            fetch(url, remaining, validators)
        })?;
        if next.len() >= PAGE_COUNT_LIMIT {
            return Err(DiscoveryError::InventoryLimit);
        }
        let bytes = page.bytes.clone();
        next.push(page);
        Ok(bytes)
    })?;
    cache.pages = next;
    Ok(observed)
}

fn cached_page(
    pages: &[CachedGithubPage],
    url: &str,
    fetch: impl FnOnce(&HttpsValidators) -> Result<ConditionalHttpsResponse, DiscoveryError>,
) -> Result<CachedGithubPage, DiscoveryError> {
    let prior = pages.iter().find(|page| page.url == url);
    let empty = HttpsValidators::default();
    let validators = prior.map(|page| &page.validators).unwrap_or(&empty);
    let (bytes, validators) = match fetch(validators)? {
        ConditionalHttpsResponse::Modified {
            response,
            validators,
        } => (response.bytes, validators),
        ConditionalHttpsResponse::NotModified { validators } => {
            let prior = prior
                .filter(|page| {
                    page.validators.etag.is_some() || page.validators.last_modified.is_some()
                })
                .ok_or(DiscoveryError::InvalidMetadata)?;
            let merged = HttpsValidators {
                etag: validators.etag.or_else(|| prior.validators.etag.clone()),
                last_modified: validators
                    .last_modified
                    .or_else(|| prior.validators.last_modified.clone()),
            };
            (prior.bytes.clone(), merged)
        }
        _ => return Err(DiscoveryError::InvalidMetadata),
    };
    if bytes.len() > PAGE_LIMIT {
        return Err(DiscoveryError::InventoryLimit);
    }
    Ok(CachedGithubPage {
        url: url.to_owned(),
        bytes,
        validators,
    })
}

/// Explicit network operation. It downloads only bounded release metadata,
/// never artifact bytes, and performs no local filesystem mutation.
pub fn check_github_release(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    check_github_with_fetch(artifact, os, architecture, |url, remaining| {
        let policy = HttpsPolicy {
            allowed_hosts: BTreeSet::from(["api.github.com".into()]),
            max_redirects: 2,
            timeout: remaining,
            user_agent: "dev-tools-update".into(),
        };
        fetch_https(url, &policy, PAGE_LIMIT as u64, None)
            .map(|response| response.bytes)
            .map_err(|_| DiscoveryError::Unavailable)
    })
}

fn check_github_with_fetch(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    mut fetch: impl FnMut(&str, Duration) -> Result<Vec<u8>, DiscoveryError>,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    let ArtifactSource::Github { owner, repository } = artifact.source() else {
        return Err(DiscoveryError::UnsupportedSource);
    };
    if [owner.as_str(), repository.as_str()]
        .iter()
        .any(|part| matches!(*part, "." | ".."))
    {
        return Err(DiscoveryError::InvalidMetadata);
    }
    let mut selection = ReleaseSelection::new(artifact, os, architecture)?;
    let started = Instant::now();
    for page in 1..=PAGE_COUNT_LIMIT {
        let remaining = Duration::from_secs(60)
            .checked_sub(started.elapsed())
            .filter(|budget| !budget.is_zero())
            .ok_or(DiscoveryError::Unavailable)?;
        let url = format!("https://api.github.com/repos/{owner}/{repository}/releases?per_page={PAGE_SIZE}&page={page}");
        let bytes = fetch(&url, remaining)?;
        if bytes.len() > PAGE_LIMIT {
            return Err(DiscoveryError::InventoryLimit);
        }
        let releases: Vec<GithubRelease> =
            serde_json::from_slice(&bytes).map_err(|_| DiscoveryError::InvalidMetadata)?;
        if releases.len() > PAGE_SIZE {
            return Err(DiscoveryError::InventoryLimit);
        }
        let complete = releases.len() < PAGE_SIZE;
        for release in releases {
            selection.consider(
                release.tag_name,
                release.draft || release.prerelease,
                || {
                    if release.assets.len() > 4096 {
                        return Err(DiscoveryError::InventoryLimit);
                    }
                    release
                        .assets
                        .into_iter()
                        .map(|asset| {
                            AssetCandidate::new(asset.name, asset.browser_download_url)
                                .map_err(|_| DiscoveryError::InvalidMetadata)
                        })
                        .collect()
                },
            )?;
        }
        if complete {
            return Ok(selection.finish());
        }
    }
    Err(DiscoveryError::InventoryLimit)
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum VersionKey {
    Semver(Version),
    Numeric(Vec<String>),
    Calendar((u16, u8, u8)),
    ProviderOrder,
}

impl VersionKey {
    fn compare(&self, other: &Self) -> Result<Ordering, DiscoveryError> {
        Ok(match (self, other) {
            (Self::Semver(left), Self::Semver(right)) => left.cmp_precedence(right),
            (Self::Calendar(left), Self::Calendar(right)) => left.cmp(right),
            (Self::Numeric(left), Self::Numeric(right)) => {
                let mut result = Ordering::Equal;
                for index in 0..left.len().max(right.len()) {
                    let left = left.get(index).map(String::as_str).unwrap_or("0");
                    let right = right.get(index).map(String::as_str).unwrap_or("0");
                    result = left.len().cmp(&right.len()).then_with(|| left.cmp(right));
                    if result != Ordering::Equal {
                        break;
                    }
                }
                result
            }
            _ => return Err(DiscoveryError::InvalidMetadata),
        })
    }
}

fn parse_version(rule: &VersionRule, tag: &str) -> Option<(VersionKey, String)> {
    match rule {
        VersionRule::SemverTag { prefix } => {
            let mut version = Version::parse(tag.strip_prefix(prefix)?).ok()?;
            if !version.pre.is_empty() {
                return None;
            }
            let text = version.to_string();
            version.build = semver::BuildMetadata::EMPTY;
            Some((VersionKey::Semver(version), text))
        }
        VersionRule::Numeric => {
            let mut components = tag
                .split('.')
                .map(|part| {
                    if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                        return None;
                    }
                    let normalized = part.trim_start_matches('0');
                    Some(
                        if normalized.is_empty() {
                            "0"
                        } else {
                            normalized
                        }
                        .to_owned(),
                    )
                })
                .collect::<Option<Vec<_>>>()?;
            if components.len() > 32 {
                return None;
            }
            while components.len() > 1 && components.last().is_some_and(|part| part == "0") {
                components.pop();
            }
            Some((VersionKey::Numeric(components), tag.to_owned()))
        }
        VersionRule::Calendar => {
            let date = calendar_date(tag)?;
            Some((VersionKey::Calendar(date), tag.to_owned()))
        }
        VersionRule::CalendarTag { prefix, format } => {
            let version = tag.strip_prefix(prefix)?;
            let date = calendar_tag_date(*format, version)?;
            Some((VersionKey::Calendar(date), version.to_owned()))
        }
        VersionRule::ProviderOrder | VersionRule::OpaqueCheckOnly => {
            Some((VersionKey::ProviderOrder, tag.to_owned()))
        }
    }
}

fn calendar_tag_date(format: CalendarFormat, tag: &str) -> Option<(u16, u8, u8)> {
    let (length, separator, month_start, day_start) = match format {
        CalendarFormat::YearMonthDayHyphen => (10, Some(b'-'), 5, Some(8)),
        CalendarFormat::YearMonthDayDot => (10, Some(b'.'), 5, Some(8)),
        CalendarFormat::YearMonthDayCompact => (8, None, 4, Some(6)),
        CalendarFormat::YearMonthHyphen => (7, Some(b'-'), 5, None),
        CalendarFormat::YearMonthDot => (7, Some(b'.'), 5, None),
    };
    let bytes = tag.as_bytes();
    if bytes.len() != length
        || bytes.iter().enumerate().any(|(index, byte)| {
            if let Some(separator) =
                separator.filter(|_| index == 4 || (index == 7 && length == 10))
            {
                *byte != separator
            } else {
                !byte.is_ascii_digit()
            }
        })
    {
        return None;
    }
    // Year-month rules compare periods within that one explicit local rule;
    // day 1 is an internal ordering key, not a claimed release day.
    let mut normalized = *b"0000-00-01";
    normalized[..4].copy_from_slice(&bytes[..4]);
    normalized[5..7].copy_from_slice(&bytes[month_start..month_start + 2]);
    if let Some(day_start) = day_start {
        normalized[8..].copy_from_slice(&bytes[day_start..day_start + 2]);
    }
    calendar_date(std::str::from_utf8(&normalized).ok()?)
}

fn calendar_date(tag: &str) -> Option<(u16, u8, u8)> {
    let bytes = tag.as_bytes();
    if bytes.len() != 10 || bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return None;
    }
    if bytes
        .iter()
        .enumerate()
        .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
    {
        return None;
    }
    let mut parts = tag.split('-');
    let year: u16 = parts.next()?.parse().ok()?;
    let month: u8 = parts.next()?.parse().ok()?;
    let day: u8 = parts.next()?.parse().ok()?;
    if year == 0 {
        return None;
    }
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => return None,
    };
    (day > 0 && day <= days).then_some((year, month, day))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactCatalog;
    use serde_json::json;

    fn catalog(rule: &str) -> ArtifactCatalog {
        ArtifactCatalog::parse(&format!(
            r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "native-binary"
source = {{ type = "github", owner = "ExampleOrg", repository = "example" }}
version = {{ {rule} }}
verification = {{ type = "check-only" }}
selectors = [{{ type = "exact", pattern = "tool-linux-x86_64" }}]
"#
        ))
        .unwrap()
    }

    fn release(tag: &str) -> serde_json::Value {
        json!({"tag_name": tag, "draft": false, "prerelease": false,
            "assets": [{"name": "tool-linux-x86_64", "browser_download_url": "https://example.test/tool"}]})
    }

    #[test]
    fn static_check_bounds_requests_to_each_locally_configured_host() {
        let source = ArtifactCatalog::parse(r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "native-binary"
source = { type = "static-manifest", url = "https://manifests.example/stable.json" }
version = { type = "semver-tag" }
verification = { type = "signed-manifest", root = "https://ROOTS.example/root.json", trusted_root_public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", product = "example", target = "linux-x86_64", artifact_url = "https://downloads.example/tool" }
selectors = [{ type = "exact", pattern = "tool" }]
"#).unwrap();
        let mut calls = Vec::new();
        let result =
            check_static_with_fetch(source.get("example").unwrap(), |url, policy, limit| {
                assert_eq!(limit, 512 * 1024);
                assert_eq!(policy.max_redirects, 2);
                assert!(
                    policy.timeout > Duration::ZERO && policy.timeout <= Duration::from_secs(60)
                );
                let host = url
                    .parse::<http::Uri>()
                    .unwrap()
                    .host()
                    .unwrap()
                    .to_ascii_lowercase();
                assert_eq!(policy.allowed_hosts, BTreeSet::from([host]));
                calls.push(url.to_owned());
                Ok(b"{}".to_vec())
            });
        assert_eq!(result.unwrap_err(), DiscoveryError::Authentication);
        assert_eq!(
            calls,
            [
                "https://ROOTS.example/root.json",
                "https://manifests.example/stable.json"
            ]
        );

        let github = catalog("type = 'semver-tag'");
        assert!(
            check_static_with_fetch(github.get("example").unwrap(), |_, _, _| panic!(
                "unsupported source accessed network"
            ))
            .is_err()
        );
        let mut calls = 0;
        assert!(
            check_static_with_fetch(source.get("example").unwrap(), |_, _, _| {
                calls += 1;
                Err(DiscoveryError::Unavailable)
            })
            .is_err()
        );
        assert_eq!(calls, 1);
    }

    #[test]
    fn durable_cache_roundtrip_revalidates_current_selection_without_network() {
        let source = catalog("type = 'semver-tag', prefix = 'v'");
        let artifact = source.get("example").unwrap();
        let cache = GithubMetadataCache {
            pages: vec![CachedGithubPage {
                url: "https://api.github.com/repos/ExampleOrg/example/releases?per_page=100&page=1"
                    .into(),
                bytes: serde_json::to_vec(&[release("v1.0.0")]).unwrap(),
                validators: HttpsValidators {
                    etag: Some("\"one\"".into()),
                    last_modified: None,
                },
            }],
        };
        let encoded = cache.to_bytes().unwrap();
        let decoded =
            GithubMetadataCache::from_bytes(&encoded, artifact, "linux", "x86_64").unwrap();
        assert!(decoded == cache);
        assert_eq!(
            decoded
                .observe(artifact, "linux", "x86_64")
                .unwrap()
                .unwrap()
                .version(),
            "1.0.0"
        );
        let changed = catalog("type = 'semver-tag', prefix = 'other/'");
        assert!(decoded
            .observe(changed.get("example").unwrap(), "linux", "x86_64")
            .unwrap()
            .is_none());
    }

    #[test]
    fn durable_cache_rejects_unknown_fields_changed_urls_and_missing_pages() {
        let source = catalog("type = 'semver-tag', prefix = 'v'");
        let artifact = source.get("example").unwrap();
        let cache = GithubMetadataCache {
            pages: vec![CachedGithubPage {
                url: "https://api.github.com/repos/ExampleOrg/example/releases?per_page=100&page=1"
                    .into(),
                bytes: serde_json::to_vec(&[release("v1.0.0")]).unwrap(),
                validators: HttpsValidators::default(),
            }],
        };
        let original: serde_json::Value =
            serde_json::from_slice(&cache.to_bytes().unwrap()).unwrap();
        for mutation in 0..7 {
            let mut value = original.clone();
            match mutation {
                0 => value["unknown"] = json!(true),
                1 => value["pages"][0]["url"] = json!("https://untrusted.test/metadata"),
                2 => value["pages"] = json!([]),
                3 => value["pages"][0]["body_base64"] = json!("not base64"),
                4 => value["pages"][0]["etag"] = json!("bad\nvalidator"),
                5 => value["schema"] = json!("unknown-v1"),
                _ => value["pages"]
                    .as_array_mut()
                    .unwrap()
                    .push(original["pages"][0].clone()),
            }
            assert!(GithubMetadataCache::from_bytes(
                &serde_json::to_vec(&value).unwrap(),
                artifact,
                "linux",
                "x86_64"
            )
            .is_err());
        }
    }

    #[test]
    fn cached_check_reuses_only_exact_resource_bytes_after_304() {
        use dev_tools_release::{ConditionalHttpsResponse, HttpsResponse, HttpsValidators};
        let catalog = catalog("type = 'semver-tag', prefix = 'v'");
        let artifact = catalog.get("example").unwrap();
        let mut cache = GithubMetadataCache::default();
        let validators = HttpsValidators {
            etag: Some("\"one\"".into()),
            last_modified: None,
        };
        let bytes = serde_json::to_vec(&[release("v1.0.0")]).unwrap();
        let first = check_github_cached_with_fetch(
            artifact,
            "linux",
            "x86_64",
            &mut cache,
            |_, _, prior| {
                assert_eq!(prior, &HttpsValidators::default());
                Ok(ConditionalHttpsResponse::Modified {
                    response: HttpsResponse {
                        bytes: bytes.clone(),
                        etag: validators.etag.clone(),
                    },
                    validators: validators.clone(),
                })
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(first.version(), "1.0.0");
        let second = check_github_cached_with_fetch(
            artifact,
            "linux",
            "x86_64",
            &mut cache,
            |_, _, prior| {
                assert_eq!(prior, &validators);
                Ok(ConditionalHttpsResponse::NotModified {
                    validators: HttpsValidators::default(),
                })
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(second.version(), "1.0.0");
        assert_eq!(cache.pages[0].validators, validators);
    }

    #[test]
    fn failed_refresh_does_not_advance_or_substitute_cache() {
        use dev_tools_release::{ConditionalHttpsResponse, HttpsResponse, HttpsValidators};
        let catalog = catalog("type = 'semver-tag', prefix = 'v'");
        let artifact = catalog.get("example").unwrap();
        let mut cache = GithubMetadataCache::default();
        check_github_cached_with_fetch(artifact, "linux", "x86_64", &mut cache, |_, _, _| {
            Ok(ConditionalHttpsResponse::Modified {
                response: HttpsResponse {
                    bytes: serde_json::to_vec(&[release("v1.0.0")]).unwrap(),
                    etag: None,
                },
                validators: HttpsValidators::default(),
            })
        })
        .unwrap();
        let before = cache.clone();
        assert!(check_github_cached_with_fetch(
            artifact,
            "linux",
            "x86_64",
            &mut cache,
            |_, _, _| Err(DiscoveryError::Unavailable)
        )
        .is_err());
        assert!(cache == before);
        assert!(check_github_cached_with_fetch(
            artifact,
            "linux",
            "x86_64",
            &mut cache,
            |_, _, _| {
                Ok(ConditionalHttpsResponse::Modified {
                    response: HttpsResponse {
                        bytes: b"invalid".to_vec(),
                        etag: None,
                    },
                    validators: HttpsValidators::default(),
                })
            }
        )
        .is_err());
        assert!(cache == before);
    }

    #[test]
    fn unsolicited_cached_304_has_no_bytes_to_reuse() {
        use dev_tools_release::{ConditionalHttpsResponse, HttpsValidators};
        let catalog = catalog("type = 'semver-tag', prefix = 'v'");
        assert!(check_github_cached_with_fetch(
            catalog.get("example").unwrap(),
            "linux",
            "x86_64",
            &mut GithubMetadataCache::default(),
            |_, _, _| {
                Ok(ConditionalHttpsResponse::NotModified {
                    validators: HttpsValidators::default(),
                })
            }
        )
        .is_err());
    }

    #[test]
    fn cache_validators_never_cross_repository_identity() {
        use dev_tools_release::{ConditionalHttpsResponse, HttpsResponse, HttpsValidators};
        let source = catalog("type = 'semver-tag', prefix = 'v'");
        let mut cache = GithubMetadataCache::default();
        check_github_cached_with_fetch(
            source.get("example").unwrap(),
            "linux",
            "x86_64",
            &mut cache,
            |_, _, _| {
                Ok(ConditionalHttpsResponse::Modified {
                    response: HttpsResponse {
                        bytes: serde_json::to_vec(&[release("v1.0.0")]).unwrap(),
                        etag: Some("\"private-to-resource\"".into()),
                    },
                    validators: HttpsValidators {
                        etag: Some("\"private-to-resource\"".into()),
                        last_modified: None,
                    },
                })
            },
        )
        .unwrap();
        let other = ArtifactCatalog::parse(
            r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "native-binary"
source = { type = "github", owner = "DifferentOrg", repository = "example" }
version = { type = "semver-tag", prefix = "v" }
verification = { type = "check-only" }
selectors = [{ type = "exact", pattern = "tool-linux-x86_64" }]
"#,
        )
        .unwrap();
        let before = cache.clone();
        assert!(check_github_cached_with_fetch(
            other.get("example").unwrap(),
            "linux",
            "x86_64",
            &mut cache,
            |_, _, validators| {
                assert_eq!(validators, &HttpsValidators::default());
                Ok(ConditionalHttpsResponse::NotModified {
                    validators: HttpsValidators::default(),
                })
            }
        )
        .is_err());
        assert!(cache == before);
    }

    #[test]
    fn semver_selection_ignores_provider_order_and_prereleases() {
        let catalog = catalog("type = 'semver-tag', prefix = 'v'");
        let document = serde_json::to_vec(&[
            release("v1.2.0"),
            release("v2.0.0-rc.1"),
            release("v1.10.0"),
        ])
        .unwrap();
        let observed = check_github_with_fetch(
            catalog.get("example").unwrap(),
            "linux",
            "x86_64",
            |url, _| {
                assert_eq!(
                    url,
                    "https://api.github.com/repos/ExampleOrg/example/releases?per_page=100&page=1"
                );
                Ok(document.clone())
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(observed.version(), "1.10.0");
        assert_eq!(observed.asset().name(), "tool-linux-x86_64");
    }

    #[test]
    fn equal_precedence_release_tags_are_ambiguous() {
        let catalog = catalog("type = 'semver-tag', prefix = 'v'");
        assert!(check_github_with_fetch(
            catalog.get("example").unwrap(),
            "linux",
            "x86_64",
            |_, _| Ok(serde_json::to_vec(&[release("v1.0.0+one"), release("v1.0.0+two")]).unwrap())
        )
        .is_err());
    }

    #[test]
    fn ordered_ambiguity_is_independent_of_provider_permutation() {
        for (rule, tags) in [
            (
                "type = 'semver-tag', prefix = 'v'",
                ["v2.0.0", "v1.0.0+one", "v1.0.0+two"],
            ),
            ("type = 'numeric'", ["2", "1", "01.0"]),
        ] {
            let catalog = catalog(rule);
            for order in [[0, 1, 2], [1, 0, 2], [1, 2, 0]] {
                let page = serde_json::to_vec(&order.map(|index| release(tags[index]))).unwrap();
                assert!(matches!(
                    check_github_with_fetch(
                        catalog.get("example").unwrap(),
                        "linux",
                        "x86_64",
                        |_, _| Ok(page.clone())
                    ),
                    Err(DiscoveryError::Ambiguous)
                ));
            }
        }
    }

    #[test]
    fn numeric_components_compare_numerically_without_integer_overflow() {
        let catalog = catalog("type = 'numeric'");
        let observed = check_github_with_fetch(
            catalog.get("example").unwrap(),
            "linux",
            "x86_64",
            |_, _| {
                Ok(serde_json::to_vec(&[
                    release("2.9"),
                    release("2.100000000000000000000000000000"),
                ])
                .unwrap())
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(observed.version(), "2.100000000000000000000000000000");
    }

    #[test]
    fn calendar_tag_cache_reselects_current_format_and_preserves_original_bytes() {
        let source = catalog("type = 'calendar-tag', prefix = 'release/', format = 'yyyy.mm.dd'");
        let mut cache = GithubMetadataCache::default();
        let observed = check_github_cached_with_fetch(
            source.get("example").unwrap(),
            "linux",
            "x86_64",
            &mut cache,
            |_, _, _| {
                Ok(ConditionalHttpsResponse::Modified {
                    response: dev_tools_release::HttpsResponse {
                        bytes: serde_json::to_vec(&[
                            release("release/2024.02.29"),
                            release("release/2025.02.29"),
                            release("release/2025.01.01"),
                            release("release/20260101"),
                        ])
                        .unwrap(),
                        etag: None,
                    },
                    validators: HttpsValidators::default(),
                })
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(observed.version(), "2025.01.01");
        let original = cache.to_bytes().unwrap();
        let decoded = GithubMetadataCache::from_bytes(
            &original,
            source.get("example").unwrap(),
            "linux",
            "x86_64",
        )
        .unwrap();
        let compact = catalog("type = 'calendar-tag', prefix = 'release/', format = 'yyyymmdd'");
        assert_eq!(
            decoded
                .observe(compact.get("example").unwrap(), "linux", "x86_64")
                .unwrap()
                .unwrap()
                .version(),
            "20260101"
        );
        let other = catalog("type = 'calendar-tag', prefix = 'other/', format = 'yyyymmdd'");
        assert!(decoded
            .observe(other.get("example").unwrap(), "linux", "x86_64")
            .unwrap()
            .is_none());
        assert_eq!(decoded.to_bytes().unwrap(), original);
    }

    #[test]
    fn calendar_rule_validates_dates_and_selects_the_latest() {
        let catalog = catalog("type = 'calendar'");
        let observed = check_github_with_fetch(
            catalog.get("example").unwrap(),
            "linux",
            "x86_64",
            |_, _| {
                Ok(serde_json::to_vec(&[
                    release("2024-02-29"),
                    release("2025-02-29"),
                    release("2025-01-01"),
                ])
                .unwrap())
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(observed.version(), "2025-01-01");
    }

    #[test]
    fn calendar_dates_require_exact_ascii_digits() {
        assert!(calendar_date("+024-01-01").is_none());
        assert!(calendar_date("2024-+1-01").is_none());
        assert!(calendar_date("2024-01-+1").is_none());
    }

    #[test]
    fn opaque_versions_report_provider_selection_without_inventing_order() {
        let catalog = catalog("type = 'opaque-check-only'");
        let observed = check_github_with_fetch(
            catalog.get("example").unwrap(),
            "linux",
            "x86_64",
            |_, _| Ok(serde_json::to_vec(&[release("release-z"), release("release-a")]).unwrap()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(observed.version(), "release-z");
    }

    #[test]
    fn a_full_page_requires_following_pages_before_claiming_a_selection() {
        let catalog = catalog("type = 'semver-tag', prefix = 'v'");
        let mut calls = 0;
        let observed = check_github_with_fetch(
            catalog.get("example").unwrap(),
            "linux",
            "x86_64",
            |url, _| {
                calls += 1;
                Ok(if calls == 1 {
                    serde_json::to_vec(
                        &(0..100)
                            .map(|i| release(&format!("v1.0.{i}")))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap()
                } else {
                    assert!(url.ends_with("page=2"));
                    serde_json::to_vec(&[release("v2.0.0")]).unwrap()
                })
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(observed.version(), "2.0.0");
        assert_eq!(calls, 2);
    }

    #[test]
    fn provider_errors_and_incomplete_inventory_are_never_current() {
        let catalog = catalog("type = 'semver-tag', prefix = 'v'");
        assert!(check_github_with_fetch(
            catalog.get("example").unwrap(),
            "linux",
            "x86_64",
            |_, _| Err(DiscoveryError::Unavailable)
        )
        .is_err());
        let mut calls = 0;
        assert!(check_github_with_fetch(
            catalog.get("example").unwrap(),
            "linux",
            "x86_64",
            |_, _| {
                calls += 1;
                Ok(serde_json::to_vec(
                    &(0..100)
                        .map(|i| release(&format!("v{calls}.0.{i}")))
                        .collect::<Vec<_>>(),
                )
                .unwrap())
            }
        )
        .is_err());
        assert_eq!(calls, PAGE_COUNT_LIMIT);
    }
}
