#[cfg(test)]
mod tests {
    use super::*;
    use dev_tools_update::artifact::ArtifactCatalog;
    use std::os::unix::fs::MetadataExt;

    fn fixture() -> (ArtifactCatalog, Metadata) {
        let catalog = ArtifactCatalog::parse(
            r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "native-binary"
source = { type = "github", owner = "ExampleOrg", repository = "example" }
version = { type = "semver-tag", prefix = "v" }
verification = { type = "check-only" }
selectors = [{ type = "exact", pattern = "tool" }]
"#,
        )
        .unwrap();
        let cache = GithubMetadataCache::from_bytes(br#"{"schema":"dev-tools-github-metadata-cache-v1","pages":[{"url":"https://api.github.com/repos/ExampleOrg/example/releases?per_page=100&page=1","body_base64":"W10=","etag":null,"last_modified":null}]}"#, catalog.get("example").unwrap(), "linux", "x86_64").unwrap();
        (catalog, Metadata::Github(cache))
    }

    #[test]
    fn storage_roundtrip_is_atomic_context_bound_and_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("cache");
        let store = CacheStore::new(root.clone(), temp.path().metadata().unwrap().uid()).unwrap();
        let key = cache_key(b"config-a", "example", "linux", "x86_64");
        let (catalog, cache) = fixture();
        let artifact = catalog.get("example").unwrap();
        assert!(store
            .load(&key, artifact, "linux", "x86_64")
            .unwrap()
            .is_none());
        assert!(
            !root.exists(),
            "local absent-cache inspection must not create directories"
        );
        assert!(store.save(&key, &cache, 100).unwrap());
        assert!(root
            .join(".publication-staging-v1")
            .join(format!("{key}.cache"))
            .join("staging-reservation-v1.json")
            .exists());
        assert!(!store.save(&key, &cache, 100).unwrap());
        let snapshot = store
            .load(&key, artifact, "linux", "x86_64")
            .unwrap()
            .unwrap();
        assert!(snapshot.is_fresh(100));
        assert!(snapshot.is_fresh(100 + 86400));
        assert!(!snapshot.is_fresh(101 + 86400));
        assert!(!snapshot.is_fresh(99));
        assert!(snapshot.metadata == cache);
        let changed = cache_key(b"config-b", "example", "linux", "x86_64");
        assert!(store
            .load(&changed, artifact, "linux", "x86_64")
            .unwrap()
            .is_none());
    }

    #[test]
    fn storage_rejects_linked_root_without_writing_through_it() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let root = temp.path().join("linked");
        std::os::unix::fs::symlink(&target, &root).unwrap();
        let store = CacheStore::new(root, temp.path().metadata().unwrap().uid()).unwrap();
        let (_, cache) = fixture();
        assert!(store
            .save(
                &cache_key(b"config", "example", "linux", "x86_64"),
                &cache,
                100
            )
            .is_err());
        assert_eq!(std::fs::read_dir(target).unwrap().count(), 0);
    }
}
use crate::private_directory::PrivateDirectory;
use dev_tools_installation::{read_atomic_document, DocumentAuthority, InstallationLock};
use dev_tools_update::artifact::{ArtifactRecord, ArtifactSource};
use dev_tools_update::discovery::{CratesIoMetadataCache, CRATES_IO_CACHE_DOCUMENT_LIMIT};
use dev_tools_update::discovery::{
    DiscoveryError, ForgejoMetadataCache, GithubMetadataCache, GitlabMetadataCache,
    ObservedRelease, FORGEJO_CACHE_DOCUMENT_LIMIT, GITHUB_CACHE_DOCUMENT_LIMIT,
    GITLAB_CACHE_DOCUMENT_LIMIT,
};
use dev_tools_update::discovery::{GenericJsonMetadataCache, GENERIC_JSON_CACHE_DOCUMENT_LIMIT};
use dev_tools_update::discovery::{GenericXmlMetadataCache, GENERIC_XML_CACHE_DOCUMENT_LIMIT};
use dev_tools_update::discovery::{GiteaMetadataCache, GITEA_CACHE_DOCUMENT_LIMIT};
use dev_tools_update::discovery::{HtmlMetadataCache, HTML_CACHE_DOCUMENT_LIMIT};
use dev_tools_update::discovery::{MavenMetadataCache, MAVEN_CACHE_DOCUMENT_LIMIT};
use dev_tools_update::discovery::{NpmMetadataCache, NPM_CACHE_DOCUMENT_LIMIT};
use dev_tools_update::discovery::{SparkleMetadataCache, SPARKLE_CACHE_DOCUMENT_LIMIT};
use dev_tools_update::discovery::{UrlMetadataCache, URL_CACHE_DOCUMENT_LIMIT};
use dev_tools_update::discovery::{ZsyncMetadataCache, ZSYNC_CACHE_DOCUMENT_LIMIT};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const HEADER_LIMIT: usize = 4096;
const SCHEMA: &str = "artifact-update-cache-entry-v1";
const ERROR: &str = "metadata cache is unavailable or has invalid custody";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema: String,
    key: String,
    checked_at: u64,
}

pub(super) struct Snapshot {
    pub metadata: Metadata,
    pub checked_at: u64,
}

#[derive(PartialEq, Eq)]
pub(super) enum Metadata {
    Github(GithubMetadataCache),
    Gitlab(GitlabMetadataCache),
    Forgejo(ForgejoMetadataCache),
    Gitea(GiteaMetadataCache),
    GenericJson(GenericJsonMetadataCache),
    Npm(NpmMetadataCache),
    CratesIo(CratesIoMetadataCache),
    Maven(MavenMetadataCache),
    Sparkle(SparkleMetadataCache),
    GenericXml(GenericXmlMetadataCache),
    Zsync(ZsyncMetadataCache),
    Html(HtmlMetadataCache),
    Url(UrlMetadataCache),
}

impl Metadata {
    pub fn empty(artifact: &ArtifactRecord) -> Result<Self, DiscoveryError> {
        match artifact.source() {
            ArtifactSource::Zsync { .. } => Ok(Self::Zsync(ZsyncMetadataCache::default())),
            ArtifactSource::Html { .. } => Ok(Self::Html(HtmlMetadataCache::default())),
            ArtifactSource::Url { .. } => Ok(Self::Url(UrlMetadataCache::default())),
            ArtifactSource::Maven { .. } => Ok(Self::Maven(MavenMetadataCache::default())),
            ArtifactSource::Sparkle { .. } => Ok(Self::Sparkle(SparkleMetadataCache::default())),
            ArtifactSource::GenericXml { .. } => {
                Ok(Self::GenericXml(GenericXmlMetadataCache::default()))
            }
            ArtifactSource::CratesIo { .. } => Ok(Self::CratesIo(CratesIoMetadataCache::default())),
            ArtifactSource::Npm { .. } => Ok(Self::Npm(NpmMetadataCache::default())),
            ArtifactSource::Github { .. } => Ok(Self::Github(GithubMetadataCache::default())),
            ArtifactSource::Gitlab { .. } => Ok(Self::Gitlab(GitlabMetadataCache::default())),
            ArtifactSource::Forgejo { .. } => Ok(Self::Forgejo(ForgejoMetadataCache::default())),
            ArtifactSource::Gitea { .. } => Ok(Self::Gitea(GiteaMetadataCache::default())),
            ArtifactSource::GenericJson { .. } => {
                Ok(Self::GenericJson(GenericJsonMetadataCache::default()))
            }
            _ => Err(DiscoveryError::UnsupportedSource),
        }
    }

    fn from_bytes(
        bytes: &[u8],
        artifact: &ArtifactRecord,
        os: &str,
        architecture: &str,
    ) -> Result<Self, DiscoveryError> {
        match artifact.source() {
            ArtifactSource::Url { .. } => {
                UrlMetadataCache::from_bytes(bytes, artifact, os, architecture).map(Self::Url)
            }
            ArtifactSource::Html { .. } => {
                HtmlMetadataCache::from_bytes(bytes, artifact, os, architecture).map(Self::Html)
            }
            ArtifactSource::Zsync { .. } => {
                ZsyncMetadataCache::from_bytes(bytes, artifact, os, architecture).map(Self::Zsync)
            }
            ArtifactSource::GenericXml { .. } => {
                GenericXmlMetadataCache::from_bytes(bytes, artifact, os, architecture)
                    .map(Self::GenericXml)
            }
            ArtifactSource::Sparkle { .. } => {
                SparkleMetadataCache::from_bytes(bytes, artifact, os, architecture)
                    .map(Self::Sparkle)
            }
            ArtifactSource::Maven { .. } => {
                MavenMetadataCache::from_bytes(bytes, artifact, os, architecture).map(Self::Maven)
            }
            ArtifactSource::CratesIo { .. } => {
                CratesIoMetadataCache::from_bytes(bytes, artifact, os, architecture)
                    .map(Self::CratesIo)
            }
            ArtifactSource::Npm { .. } => {
                NpmMetadataCache::from_bytes(bytes, artifact, os, architecture).map(Self::Npm)
            }
            ArtifactSource::Github { .. } => {
                GithubMetadataCache::from_bytes(bytes, artifact, os, architecture).map(Self::Github)
            }
            ArtifactSource::Gitlab { .. } => {
                GitlabMetadataCache::from_bytes(bytes, artifact, os, architecture).map(Self::Gitlab)
            }
            ArtifactSource::Forgejo { .. } => {
                ForgejoMetadataCache::from_bytes(bytes, artifact, os, architecture)
                    .map(Self::Forgejo)
            }
            ArtifactSource::Gitea { .. } => {
                GiteaMetadataCache::from_bytes(bytes, artifact, os, architecture).map(Self::Gitea)
            }
            ArtifactSource::GenericJson { .. } => {
                GenericJsonMetadataCache::from_bytes(bytes, artifact, os, architecture)
                    .map(Self::GenericJson)
            }
            _ => Err(DiscoveryError::UnsupportedSource),
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>, DiscoveryError> {
        match self {
            Self::Maven(cache) => cache.to_bytes(),
            Self::Sparkle(cache) => cache.to_bytes(),
            Self::GenericXml(cache) => cache.to_bytes(),
            Self::Zsync(cache) => cache.to_bytes(),
            Self::Html(cache) => cache.to_bytes(),
            Self::Url(cache) => cache.to_bytes(),
            Self::CratesIo(cache) => cache.to_bytes(),
            Self::Npm(cache) => cache.to_bytes(),
            Self::Github(cache) => cache.to_bytes(),
            Self::Gitlab(cache) => cache.to_bytes(),
            Self::Forgejo(cache) => cache.to_bytes(),
            Self::Gitea(cache) => cache.to_bytes(),
            Self::GenericJson(cache) => cache.to_bytes(),
        }
    }

    pub fn observe(
        &self,
        artifact: &ArtifactRecord,
        os: &str,
        architecture: &str,
    ) -> Result<Option<ObservedRelease>, DiscoveryError> {
        match self {
            Self::Maven(cache) => cache.observe(artifact, os, architecture),
            Self::Sparkle(cache) => cache.observe(artifact, os, architecture),
            Self::GenericXml(cache) => cache.observe(artifact, os, architecture),
            Self::Zsync(cache) => cache.observe(artifact, os, architecture),
            Self::Html(cache) => cache.observe(artifact, os, architecture),
            Self::Url(cache) => cache.observe(artifact, os, architecture),
            Self::CratesIo(cache) => cache.observe(artifact, os, architecture),
            Self::Npm(cache) => cache.observe(artifact, os, architecture),
            Self::Github(cache) => cache.observe(artifact, os, architecture),
            Self::Gitlab(cache) => cache.observe(artifact, os, architecture),
            Self::Forgejo(cache) => cache.observe(artifact, os, architecture),
            Self::Gitea(cache) => cache.observe(artifact, os, architecture),
            Self::GenericJson(cache) => cache.observe(artifact, os, architecture),
        }
    }

    pub fn check(
        &mut self,
        artifact: &ArtifactRecord,
        os: &str,
        architecture: &str,
    ) -> Result<Option<ObservedRelease>, DiscoveryError> {
        match self {
            Self::Url(cache) => dev_tools_update::discovery::check_url_release_cached(
                artifact,
                os,
                architecture,
                cache,
            ),
            Self::Html(cache) => dev_tools_update::discovery::check_html_release_cached(
                artifact,
                os,
                architecture,
                cache,
            ),
            Self::Zsync(cache) => dev_tools_update::discovery::check_zsync_release_cached(
                artifact,
                os,
                architecture,
                cache,
            ),
            Self::GenericXml(cache) => {
                dev_tools_update::discovery::check_generic_xml_release_cached(
                    artifact,
                    os,
                    architecture,
                    cache,
                )
            }
            Self::Sparkle(cache) => dev_tools_update::discovery::check_sparkle_release_cached(
                artifact,
                os,
                architecture,
                cache,
            ),
            Self::Maven(cache) => dev_tools_update::discovery::check_maven_release_cached(
                artifact,
                os,
                architecture,
                cache,
            ),
            Self::CratesIo(cache) => dev_tools_update::discovery::check_crates_io_release_cached(
                artifact,
                os,
                architecture,
                cache,
            ),
            Self::Npm(cache) => dev_tools_update::discovery::check_npm_release_cached(
                artifact,
                os,
                architecture,
                cache,
            ),
            Self::Github(cache) => dev_tools_update::discovery::check_github_release_cached(
                artifact,
                os,
                architecture,
                cache,
            ),
            Self::Gitlab(cache) => dev_tools_update::discovery::check_gitlab_release_cached(
                artifact,
                os,
                architecture,
                cache,
            ),
            Self::Forgejo(cache) => dev_tools_update::discovery::check_forgejo_release_cached(
                artifact,
                os,
                architecture,
                cache,
            ),
            Self::Gitea(cache) => dev_tools_update::discovery::check_gitea_release_cached(
                artifact,
                os,
                architecture,
                cache,
            ),
            Self::GenericJson(cache) => {
                dev_tools_update::discovery::check_generic_json_release_cached(
                    artifact,
                    os,
                    architecture,
                    cache,
                )
            }
        }
    }
}
impl Snapshot {
    pub fn is_fresh(&self, now: u64) -> bool {
        now.checked_sub(self.checked_at)
            .is_some_and(|age| age <= dev_tools_update::MAX_CACHE_AGE_SECONDS)
    }
}

pub(super) fn cache_key(config: &[u8], id: &str, os: &str, architecture: &str) -> String {
    let mut hash = Sha256::new();
    for part in [
        config,
        id.as_bytes(),
        os.as_bytes(),
        architecture.as_bytes(),
    ] {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part);
    }
    format!("{:x}", hash.finalize())
}

pub(super) struct CacheStore {
    directory: PrivateDirectory,
}
impl CacheStore {
    pub fn new(root: PathBuf, owner: u32) -> Result<Self, String> {
        Ok(Self {
            directory: PrivateDirectory::new(root, owner).map_err(|_| ERROR)?,
        })
    }

    fn path(&self, key: &str) -> Result<PathBuf, String> {
        if key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ERROR.into());
        }
        Ok(self.directory.path.join(format!("{key}.cache")))
    }

    fn authority(&self) -> DocumentAuthority {
        DocumentAuthority {
            owner_uid: self.directory.owner,
            mode: 0o600,
            limit: (HEADER_LIMIT
                + 1
                + GITHUB_CACHE_DOCUMENT_LIMIT
                    .max(GITLAB_CACHE_DOCUMENT_LIMIT)
                    .max(GITEA_CACHE_DOCUMENT_LIMIT)
                    .max(GENERIC_JSON_CACHE_DOCUMENT_LIMIT)
                    .max(NPM_CACHE_DOCUMENT_LIMIT)
                    .max(CRATES_IO_CACHE_DOCUMENT_LIMIT)
                    .max(MAVEN_CACHE_DOCUMENT_LIMIT)
                    .max(SPARKLE_CACHE_DOCUMENT_LIMIT)
                    .max(GENERIC_XML_CACHE_DOCUMENT_LIMIT)
                    .max(ZSYNC_CACHE_DOCUMENT_LIMIT)
                    .max(HTML_CACHE_DOCUMENT_LIMIT)
                    .max(URL_CACHE_DOCUMENT_LIMIT)
                    .max(FORGEJO_CACHE_DOCUMENT_LIMIT)) as u64,
        }
    }

    fn inspect_root(&self) -> Result<bool, String> {
        self.directory.inspect().map_err(|_| ERROR.into())
    }

    pub fn load(
        &self,
        key: &str,
        artifact: &ArtifactRecord,
        os: &str,
        architecture: &str,
    ) -> Result<Option<Snapshot>, String> {
        let path = self.path(key)?;
        if !self.inspect_root()? {
            return Ok(None);
        }
        let Some(document) =
            read_atomic_document(&path, &self.authority()).map_err(|_| ERROR.to_owned())?
        else {
            return Ok(None);
        };
        let split = document
            .bytes
            .iter()
            .take(HEADER_LIMIT + 1)
            .position(|byte| *byte == b'\n')
            .ok_or(ERROR)?;
        let header: Header = serde_json::from_slice(&document.bytes[..split]).map_err(|_| ERROR)?;
        if header.schema != SCHEMA || header.key != key {
            return Err(ERROR.into());
        }
        let metadata =
            Metadata::from_bytes(&document.bytes[split + 1..], artifact, os, architecture)
                .map_err(|_| ERROR)?;
        Ok(Some(Snapshot {
            metadata,
            checked_at: header.checked_at,
        }))
    }

    pub fn save(&self, key: &str, cache: &Metadata, checked_at: u64) -> Result<bool, String> {
        let path = self.path(key)?;
        self.directory.ensure().map_err(|_| ERROR)?;
        let _lock = InstallationLock::try_acquire(&self.directory.path.join("cache.lock"))
            .map_err(|_| ERROR)?
            .ok_or("metadata cache is busy")?;
        let current = read_atomic_document(&path, &self.authority()).map_err(|_| ERROR)?;
        let mut bytes = serde_json::to_vec(&Header {
            schema: SCHEMA.into(),
            key: key.into(),
            checked_at,
        })
        .map_err(|_| ERROR)?;
        if bytes.len() > HEADER_LIMIT {
            return Err(ERROR.into());
        }
        bytes.push(b'\n');
        bytes.extend(cache.to_bytes().map_err(|_| ERROR)?);
        self.directory
            .publish_cache_entry(
                path.file_name()
                    .and_then(|name| name.to_str())
                    .ok_or(ERROR)?,
                &bytes,
                &self.authority(),
                current.as_ref().map(|document| &document.identity),
            )
            .map_err(|_| ERROR.into())
    }
}
