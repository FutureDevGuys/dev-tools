//! Explicit npm distribution-tag metadata, without package execution or credentials.
use super::*;

pub const NPM_CACHE_DOCUMENT_LIMIT: usize = GITHUB_CACHE_DOCUMENT_LIMIT;
const NPM_CACHE_SCHEMA: &str = "dev-tools-npm-metadata-cache-v1";

/// Original bytes of one explicitly configured package/tag resource.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct NpmMetadataCache {
    inner: GithubMetadataCache,
}

impl NpmMetadataCache {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DiscoveryError> {
        self.inner.encode(NPM_CACHE_SCHEMA)
    }

    pub fn from_bytes(
        bytes: &[u8],
        artifact: &ArtifactRecord,
        os: &str,
        architecture: &str,
    ) -> Result<Self, DiscoveryError> {
        let cache = Self {
            inner: GithubMetadataCache::decode(bytes, NPM_CACHE_SCHEMA)?,
        };
        cache.observe(artifact, os, architecture)?;
        Ok(cache)
    }

    /// Reselect under current local rules without refreshing or granting trust.
    pub fn observe(
        &self,
        artifact: &ArtifactRecord,
        os: &str,
        architecture: &str,
    ) -> Result<Option<ObservedRelease>, DiscoveryError> {
        let [page] = self.inner.pages.as_slice() else {
            return Err(DiscoveryError::InvalidMetadata);
        };
        check_with_fetch(artifact, os, architecture, |url, _| {
            if page.url != url {
                return Err(DiscoveryError::InvalidMetadata);
            }
            Ok(page.bytes.clone())
        })
    }
}

fn check_cached_with_fetch(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut NpmMetadataCache,
    mut fetch: impl FnMut(
        &str,
        &HttpsPolicy,
        &HttpsValidators,
    ) -> Result<ConditionalHttpsResponse, DiscoveryError>,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    let mut next = Vec::new();
    let observed = check_with_fetch(artifact, os, architecture, |url, policy| {
        let page = cached_page(&cache.inner.pages, url, |validators| {
            fetch(url, policy, validators)
        })?;
        let bytes = page.bytes.clone();
        next.push(page);
        Ok(bytes)
    })?;
    cache.inner.pages = next;
    Ok(observed)
}

/// Conditional metadata refresh. Failure preserves the previous cache unchanged.
pub fn check_npm_release_cached(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut NpmMetadataCache,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    check_cached_with_fetch(
        artifact,
        os,
        architecture,
        cache,
        |url, policy, validators| {
            dev_tools_release::fetch_conditional_json_https(
                url,
                policy,
                PAGE_LIMIT as u64,
                validators,
            )
            .map_err(|_| DiscoveryError::Unavailable)
        },
    )
}

/// Observe the explicitly named distribution tag, not a highest-version search.
/// This does not resolve dependencies, verify package integrity or run scripts.
pub fn check_npm_release(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    check_npm_release_cached(artifact, os, architecture, &mut NpmMetadataCache::default())
}

fn check_with_fetch(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    mut fetch: impl FnMut(&str, &HttpsPolicy) -> Result<Vec<u8>, DiscoveryError>,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    let ArtifactSource::Npm {
        registry,
        package,
        tag,
    } = artifact.source()
    else {
        return Err(DiscoveryError::UnsupportedSource);
    };
    let mut selection = ReleaseSelection::new(artifact, os, architecture)?;
    let host = dev_tools_release::canonical_https_host(registry)
        .map_err(|_| DiscoveryError::InvalidMetadata)?;
    // Configuration admits only literal package components: these are the only
    // two reserved characters, and must not become endpoint path separators.
    let encoded_package = package.replace('@', "%40").replace('/', "%2F");
    let url = format!("{}/{encoded_package}/{tag}", registry.trim_end_matches('/'));
    let policy = HttpsPolicy {
        allowed_hosts: BTreeSet::from([host]),
        max_redirects: 2,
        timeout: Duration::from_secs(60),
        user_agent: "dev-tools-update".into(),
    };
    let bytes = fetch(&url, &policy)?;
    if bytes.len() > PAGE_LIMIT {
        return Err(DiscoveryError::InventoryLimit);
    }
    let document =
        super::strict_json::parse(&bytes).map_err(|_| DiscoveryError::InvalidMetadata)?;
    if document.get("name").and_then(serde_json::Value::as_str) != Some(package.as_str()) {
        return Err(DiscoveryError::InvalidMetadata);
    }
    let version = document
        .get("version")
        .and_then(serde_json::Value::as_str)
        .ok_or(DiscoveryError::InvalidMetadata)?;
    let parsed = Version::parse(version).map_err(|_| DiscoveryError::InvalidMetadata)?;
    let tarball = document
        .pointer("/dist/tarball")
        .and_then(serde_json::Value::as_str)
        .ok_or(DiscoveryError::InvalidMetadata)?;
    let uri: http::Uri = tarball
        .parse()
        .map_err(|_| DiscoveryError::InvalidMetadata)?;
    let name = uri
        .path()
        .rsplit('/')
        .next()
        .ok_or(DiscoveryError::InvalidMetadata)?;
    let candidate =
        AssetCandidate::new(name, tarball).map_err(|_| DiscoveryError::InvalidMetadata)?;
    selection.consider(version.to_owned(), !parsed.pre.is_empty(), || {
        Ok(vec![candidate])
    })?;
    Ok(selection.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactCatalog;
    use serde_json::json;

    const CONFIG: &str = r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "node-package"
source = { type = "npm", registry = "https://registry.example/npm/", package = "@scope/tool", tag = "latest" }
version = { type = "semver-tag", prefix = "" }
verification = { type = "check-only" }
selectors = [{ type = "exact", pattern = "tool-1.2.3.tgz", os = "linux", architecture = "x86_64" }]
"#;

    fn metadata() -> serde_json::Value {
        json!({"name":"@scope/tool", "version":"1.2.3", "dist":{"tarball":"https://downloads.example/tool-1.2.3.tgz?download=true"}, "scripts":{"install":"ignored"}, "engines":{"node":">=999"}, "destination":"/ignored"})
    }

    #[test]
    fn npm_cache_roundtrip_conditional_reuse_and_failure_preservation() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let record = catalog.get("example").unwrap();
        let mut cache = NpmMetadataCache::default();
        let selected =
            check_cached_with_fetch(record, "linux", "x86_64", &mut cache, |_, _, validators| {
                assert!(validators.etag.is_none());
                Ok(ConditionalHttpsResponse::Modified {
                    response: dev_tools_release::HttpsResponse {
                        bytes: serde_json::to_vec(&metadata()).unwrap(),
                        etag: None,
                    },
                    validators: HttpsValidators {
                        etag: Some("\"npm-fixture\"".into()),
                        last_modified: None,
                    },
                })
            })
            .unwrap()
            .unwrap();
        assert_eq!(selected.version(), "1.2.3");
        let before = cache.to_bytes().unwrap();
        assert!(NpmMetadataCache::from_bytes(&before, record, "linux", "x86_64").unwrap() == cache);
        assert!(cache
            .observe(record, "windows", "x86_64")
            .unwrap()
            .is_none());
        assert!(check_cached_with_fetch(
            record,
            "windows",
            "x86_64",
            &mut cache,
            |_, _, validators| {
                assert_eq!(validators.etag.as_deref(), Some("\"npm-fixture\""));
                Ok(ConditionalHttpsResponse::NotModified {
                    validators: HttpsValidators::default(),
                })
            }
        )
        .unwrap()
        .is_none());
        assert_eq!(cache.to_bytes().unwrap(), before);
        for malformed in [false, true] {
            assert!(
                check_cached_with_fetch(record, "linux", "x86_64", &mut cache, |_, _, _| {
                    if !malformed {
                        return Err(DiscoveryError::Unavailable);
                    }
                    Ok(ConditionalHttpsResponse::Modified {
                        response: dev_tools_release::HttpsResponse {
                            bytes: b"{}".to_vec(),
                            etag: None,
                        },
                        validators: HttpsValidators::default(),
                    })
                })
                .is_err()
            );
            assert_eq!(cache.to_bytes().unwrap(), before);
        }
        let mut absent = NpmMetadataCache::default();
        assert!(
            check_cached_with_fetch(record, "linux", "x86_64", &mut absent, |_, _, _| Ok(
                ConditionalHttpsResponse::NotModified {
                    validators: HttpsValidators::default()
                }
            ))
            .is_err()
        );
        assert!(absent.inner.pages.is_empty());
        for (from, to) in [
            ("npm-metadata", "generic-json-metadata"),
            ("/latest", "/next"),
        ] {
            let changed = std::str::from_utf8(&before).unwrap().replace(from, to);
            assert!(
                NpmMetadataCache::from_bytes(changed.as_bytes(), record, "linux", "x86_64")
                    .is_err()
            );
        }
        let mut extra = cache.clone();
        extra.inner.pages.push(cache.inner.pages[0].clone());
        assert!(extra.observe(record, "linux", "x86_64").is_err());
    }

    #[test]
    fn npm_rejects_wrong_identity_invalid_versions_urls_and_duplicate_members() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let record = catalog.get("example").unwrap();
        for (pointer, value) in [
            ("/name", json!("another-package")),
            ("/name", json!(null)),
            ("/version", json!("latest")),
            ("/version", json!("v1.2.3")),
            ("/version", json!(123)),
            ("/dist/tarball", json!("http://downloads.example/tool.tgz")),
            (
                "/dist/tarball",
                json!("https://user:secret@downloads.example/tool.tgz"),
            ),
            ("/dist/tarball", json!("https://downloads.example/")),
            ("/dist/tarball", json!(null)),
        ] {
            let mut body = metadata();
            *body.pointer_mut(pointer).unwrap() = value;
            assert!(matches!(
                check_with_fetch(record, "linux", "x86_64", |_, _| Ok(serde_json::to_vec(
                    &body
                )
                .unwrap())),
                Err(DiscoveryError::InvalidMetadata)
            ));
        }
        for bytes in [br#"{"name":"other","name":"@scope/tool","version":"1.2.3","dist":{"tarball":"https://downloads.example/tool.tgz"}}"#.as_slice(), br#"{"name":"@scope/tool","version":"1.2.3","dist":{"tarball":"https://downloads.example/tool.tgz"},"scripts":{"install":1,"install":2}}"#, b"{} trailing"] {
            assert!(matches!(check_with_fetch(record, "linux", "x86_64", |_, _| Ok(bytes.to_vec())), Err(DiscoveryError::InvalidMetadata)));
        }
    }

    #[test]
    fn npm_excludes_prereleases_and_applies_current_local_target_and_version_rules() {
        for config in [
            CONFIG.to_owned(),
            CONFIG.replace(
                "type = \"semver-tag\", prefix = \"\"",
                "type = \"provider-order\"",
            ),
        ] {
            let catalog = ArtifactCatalog::parse(&config).unwrap();
            let mut body = metadata();
            body["version"] = json!("2.0.0-rc.1");
            assert!(check_with_fetch(
                catalog.get("example").unwrap(),
                "linux",
                "x86_64",
                |_, _| Ok(serde_json::to_vec(&body).unwrap())
            )
            .unwrap()
            .is_none());
        }
        for (config, os) in [
            (CONFIG.to_owned(), "windows"),
            (CONFIG.replace("prefix = \"\"", "prefix = \"v\""), "linux"),
        ] {
            let catalog = ArtifactCatalog::parse(&config).unwrap();
            assert!(
                check_with_fetch(catalog.get("example").unwrap(), os, "x86_64", |_, _| Ok(
                    serde_json::to_vec(&metadata()).unwrap()
                ))
                .unwrap()
                .is_none()
            );
        }
    }

    #[test]
    fn npm_bounds_metadata_and_propagates_transport_failure_without_fallback() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let record = catalog.get("example").unwrap();
        assert!(matches!(
            check_with_fetch(record, "linux", "x86_64", |_, _| Ok(vec![
                b' ';
                PAGE_LIMIT + 1
            ])),
            Err(DiscoveryError::InventoryLimit)
        ));
        assert!(matches!(
            check_with_fetch(record, "linux", "x86_64", |_, _| Err(
                DiscoveryError::Unavailable
            )),
            Err(DiscoveryError::Unavailable)
        ));
        assert!(
            check_with_fetch(record, "invalid/target", "x86_64", |_, _| panic!(
                "invalid target must not fetch"
            ))
            .is_err()
        );
    }

    #[test]
    fn npm_resolves_only_explicit_tag_and_uses_inert_tarball_basename() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let mut calls = 0;
        let selected = check_with_fetch(
            catalog.get("example").unwrap(),
            "linux",
            "x86_64",
            |url, policy| {
                calls += 1;
                assert_eq!(url, "https://registry.example/npm/%40scope%2Ftool/latest");
                assert_eq!(
                    policy.allowed_hosts,
                    BTreeSet::from(["registry.example".into()])
                );
                assert_eq!(policy.timeout, Duration::from_secs(60));
                assert_eq!(policy.max_redirects, 2);
                Ok(serde_json::to_vec(&metadata()).unwrap())
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(selected.version(), "1.2.3");
        assert_eq!(
            selected.asset().url(),
            "https://downloads.example/tool-1.2.3.tgz?download=true"
        );
    }
}
