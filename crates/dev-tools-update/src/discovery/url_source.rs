//! Header-only direct/final URL observations without artifact retrieval.
use super::*;

pub const URL_CACHE_DOCUMENT_LIMIT: usize = 64 * 1024;
const CACHE_SCHEMA: &str = "dev-tools-url-metadata-cache-v1";

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct UrlCacheDocument {
    schema: String,
    url: String,
    final_url: String,
}

/// Unauthenticated location metadata, not cached artifact bytes or a receipt.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct UrlMetadataCache {
    document: Option<UrlCacheDocument>,
}

impl UrlMetadataCache {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DiscoveryError> {
        let document = self
            .document
            .as_ref()
            .ok_or(DiscoveryError::InvalidMetadata)?;
        let bytes = serde_json::to_vec(document).map_err(|_| DiscoveryError::InvalidMetadata)?;
        if bytes.len() > URL_CACHE_DOCUMENT_LIMIT {
            return Err(DiscoveryError::InventoryLimit);
        }
        Ok(bytes)
    }

    pub fn from_bytes(
        bytes: &[u8],
        artifact: &ArtifactRecord,
        os: &str,
        architecture: &str,
    ) -> Result<Self, DiscoveryError> {
        if bytes.len() > URL_CACHE_DOCUMENT_LIMIT {
            return Err(DiscoveryError::InventoryLimit);
        }
        let document: UrlCacheDocument =
            serde_json::from_slice(bytes).map_err(|_| DiscoveryError::InvalidMetadata)?;
        if document.schema != CACHE_SCHEMA {
            return Err(DiscoveryError::InvalidMetadata);
        }
        let cache = Self {
            document: Some(document),
        };
        cache.observe(artifact, os, architecture)?;
        Ok(cache)
    }

    /// Reapply current local URL admission and selectors without network access.
    pub fn observe(
        &self,
        artifact: &ArtifactRecord,
        os: &str,
        architecture: &str,
    ) -> Result<Option<ObservedRelease>, DiscoveryError> {
        let (url, policy) = source_policy(artifact)?;
        artifact
            .select_asset(os, architecture, &[])
            .map_err(|_| DiscoveryError::InvalidMetadata)?;
        let document = self
            .document
            .as_ref()
            .ok_or(DiscoveryError::InvalidMetadata)?;
        if document.url != url {
            return Err(DiscoveryError::InvalidMetadata);
        }
        let host = dev_tools_release::canonical_https_host(&document.final_url)
            .map_err(|_| DiscoveryError::InvalidMetadata)?;
        if !policy.allowed_hosts.contains(&host) {
            return Err(DiscoveryError::InvalidMetadata);
        }
        let uri: http::Uri = document
            .final_url
            .parse()
            .map_err(|_| DiscoveryError::InvalidMetadata)?;
        let name = uri
            .path()
            .rsplit('/')
            .next()
            .ok_or(DiscoveryError::InvalidMetadata)?;
        let asset = AssetCandidate::new(name, &document.final_url)
            .map_err(|_| DiscoveryError::InvalidMetadata)?;
        observe_filename_release(artifact, os, architecture, &[asset])
    }
}

fn source_policy(artifact: &ArtifactRecord) -> Result<(&str, HttpsPolicy), DiscoveryError> {
    let ArtifactSource::Url {
        url,
        redirect_hosts,
    } = artifact.source()
    else {
        return Err(DiscoveryError::UnsupportedSource);
    };
    let host = dev_tools_release::canonical_https_host(url)
        .map_err(|_| DiscoveryError::InvalidMetadata)?;
    let mut allowed_hosts = BTreeSet::from([host]);
    allowed_hosts.extend(redirect_hosts.iter().cloned());
    Ok((
        url,
        HttpsPolicy {
            allowed_hosts,
            max_redirects: 2,
            timeout: Duration::from_secs(60),
            user_agent: "dev-tools-update".into(),
        },
    ))
}

fn check_with_probe(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut UrlMetadataCache,
    mut probe: impl FnMut(&str, &HttpsPolicy) -> Result<String, DiscoveryError>,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    let (url, policy) = source_policy(artifact)?;
    artifact
        .select_asset(os, architecture, &[])
        .map_err(|_| DiscoveryError::InvalidMetadata)?;
    let final_url = probe(url, &policy)?;
    let next = UrlMetadataCache {
        document: Some(UrlCacheDocument {
            schema: CACHE_SCHEMA.into(),
            url: url.into(),
            final_url,
        }),
    };
    let observed = next.observe(artifact, os, architecture)?;
    *cache = next;
    Ok(observed)
}

/// Explicit HEAD-only check. A failed probe never advances cached observation.
pub fn check_url_release_cached(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut UrlMetadataCache,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    check_with_probe(artifact, os, architecture, cache, |url, policy| {
        dev_tools_release::probe_https_location(url, policy)
            .map_err(|_| DiscoveryError::Unavailable)
    })
}

pub fn check_url_release(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    check_url_release_cached(artifact, os, architecture, &mut UrlMetadataCache::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactCatalog;

    const CONFIG: &str = r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "zip"
source = { type = "url", url = "https://example.org/latest", redirect_hosts = ["cdn.example.org"] }
version = { type = "numeric" }
verification = { type = "check-only" }
selectors = [{ type = "regex", pattern = '^app-(?P<version>[0-9]+)\.zip$', os = "linux", architecture = "x86_64" }]
"#;

    #[test]
    fn url_observation_rejects_unadmitted_metadata_and_reselects_version_captures() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let artifact = catalog.get("example").unwrap();
        let mut cache = UrlMetadataCache::default();
        check_with_probe(artifact, "linux", "x86_64", &mut cache, |_, _| {
            Ok("https://example.org/app-42.zip".into())
        })
        .unwrap();
        let before = cache.to_bytes().unwrap();
        for final_url in [
            "http://example.org/app-42.zip",
            "https://user@example.org/app-42.zip",
            "https://evil.example/app-42.zip",
            "https://example.org/app-42.zip#fragment",
            "https://example.org/",
            "relative.zip",
        ] {
            assert!(
                check_with_probe(artifact, "linux", "x86_64", &mut cache, |_, _| Ok(
                    final_url.into()
                ))
                .is_err()
            );
            assert_eq!(cache.to_bytes().unwrap(), before);
        }
        assert!(
            check_with_probe(artifact, "../linux", "x86_64", &mut cache, |_, _| panic!(
                "invalid target started a request"
            ))
            .is_err()
        );
        let changed = ArtifactCatalog::parse(
            &CONFIG.replace("(?P<version>[0-9]+)", "(?P<version>[0-9])[0-9]"),
        )
        .unwrap();
        assert_eq!(
            cache
                .observe(changed.get("example").unwrap(), "linux", "x86_64")
                .unwrap()
                .unwrap()
                .version(),
            "4"
        );
        let mut document: serde_json::Value = serde_json::from_slice(&before).unwrap();
        document["url"] = "https://example.org/other".into();
        assert!(UrlMetadataCache::from_bytes(
            &serde_json::to_vec(&document).unwrap(),
            artifact,
            "linux",
            "x86_64"
        )
        .is_err());
        assert_eq!(
            UrlMetadataCache::from_bytes(
                &vec![0; URL_CACHE_DOCUMENT_LIMIT + 1],
                artifact,
                "linux",
                "x86_64"
            )
            .err(),
            Some(DiscoveryError::InventoryLimit)
        );
    }

    #[test]
    fn url_cache_reselects_final_location_and_preserves_failed_probe() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let artifact = catalog.get("example").unwrap();
        let mut cache = UrlMetadataCache::default();
        let observed = check_with_probe(artifact, "linux", "x86_64", &mut cache, |url, policy| {
            assert_eq!(url, "https://example.org/latest");
            assert_eq!(
                policy.allowed_hosts,
                BTreeSet::from(["example.org".into(), "cdn.example.org".into()])
            );
            Ok("https://cdn.example.org/files/app-42.zip?download=1".into())
        })
        .unwrap()
        .unwrap();
        assert_eq!(observed.version(), "42");
        assert_eq!(observed.asset().name(), "app-42.zip");
        let before = cache.to_bytes().unwrap();
        assert!(
            UrlMetadataCache::from_bytes(&before, artifact, "linux", "x86_64").unwrap() == cache
        );
        assert!(cache
            .observe(artifact, "macos", "aarch64")
            .unwrap()
            .is_none());
        assert!(
            check_with_probe(artifact, "linux", "x86_64", &mut cache, |_, _| Err(
                DiscoveryError::Unavailable
            ))
            .is_err()
        );
        assert_eq!(cache.to_bytes().unwrap(), before);
        let restricted =
            ArtifactCatalog::parse(&CONFIG.replace("[\"cdn.example.org\"]", "[]")).unwrap();
        assert!(cache
            .observe(restricted.get("example").unwrap(), "linux", "x86_64")
            .is_err());
    }
}
