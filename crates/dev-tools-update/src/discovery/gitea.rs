//! Gitea release attachments are observations, not installation authority.
use super::*;

pub const GITEA_CACHE_DOCUMENT_LIMIT: usize = GITHUB_CACHE_DOCUMENT_LIMIT;
const GITEA_CACHE_SCHEMA: &str = "dev-tools-gitea-metadata-cache-v1";

/// Bounded original resource pages. This cache carries no release authentication.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct GiteaMetadataCache {
    inner: GithubMetadataCache,
}

impl GiteaMetadataCache {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DiscoveryError> {
        self.inner.encode(GITEA_CACHE_SCHEMA)
    }

    pub fn from_bytes(
        bytes: &[u8],
        artifact: &ArtifactRecord,
        os: &str,
        architecture: &str,
    ) -> Result<Self, DiscoveryError> {
        let cache = Self {
            inner: GithubMetadataCache::decode(bytes, GITEA_CACHE_SCHEMA)?,
        };
        cache.observe(artifact, os, architecture)?;
        Ok(cache)
    }

    /// Reselect locally without network access, requiring the original complete
    /// resource sequence and the terminal empty page under current configuration.
    pub fn observe(
        &self,
        artifact: &ArtifactRecord,
        os: &str,
        architecture: &str,
    ) -> Result<Option<ObservedRelease>, DiscoveryError> {
        let mut position = 0;
        let observed = check_with_fetch(artifact, os, architecture, |url, _| {
            let page = self
                .inner
                .pages
                .get(position)
                .filter(|page| page.url == url)
                .ok_or(DiscoveryError::InvalidMetadata)?;
            position += 1;
            Ok(page.bytes.clone())
        })?;
        if position != self.inner.pages.len() {
            return Err(DiscoveryError::InvalidMetadata);
        }
        Ok(observed)
    }
}

/// Refresh conditionally and publish new cache state only after a complete,
/// valid inventory. Reused pages are reselected under current local rules.
pub fn check_gitea_release_cached(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut GiteaMetadataCache,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    check_cached_with_fetch(
        artifact,
        os,
        architecture,
        cache,
        |url, policy, validators| {
            fetch_conditional_https(url, policy, PAGE_LIMIT as u64, validators)
                .map_err(|_| DiscoveryError::Unavailable)
        },
    )
}

fn check_cached_with_fetch(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut GiteaMetadataCache,
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
        if next.len() >= PAGE_COUNT_LIMIT {
            return Err(DiscoveryError::InventoryLimit);
        }
        let bytes = page.bytes.clone();
        next.push(page);
        Ok(bytes)
    })?;
    cache.inner.pages = next;
    Ok(observed)
}

/// Explicit anonymous release discovery within locally configured HTTPS authority.
/// The result never authenticates, downloads, installs or executes an artifact.
pub fn check_gitea_release(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    check_with_fetch(artifact, os, architecture, |url, policy| {
        fetch_https(url, policy, PAGE_LIMIT as u64, None)
            .map(|response| response.bytes)
            .map_err(|_| DiscoveryError::Unavailable)
    })
}

fn check_with_fetch(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    fetch: impl FnMut(&str, &HttpsPolicy) -> Result<Vec<u8>, DiscoveryError>,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    let ArtifactSource::Gitea {
        api,
        owner,
        repository,
    } = artifact.source()
    else {
        return Err(DiscoveryError::UnsupportedSource);
    };
    super::forgejo::check_release_pages(artifact, os, architecture, api, owner, repository, fetch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactCatalog;
    use serde_json::json;

    fn catalog() -> ArtifactCatalog {
        ArtifactCatalog::parse(r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "native-binary"
source = { type = "gitea", api = "https://forge.example/prefix/api/v1", owner = "group", repository = "tool" }
version = { type = "semver-tag", prefix = "v" }
verification = { type = "check-only" }
selectors = [{ type = "exact", pattern = "tool-linux-x86_64", os = "linux", architecture = "x86_64" }]
"#).unwrap()
    }

    fn release(tag: &str) -> serde_json::Value {
        json!({"tag_name": tag, "draft": false, "prerelease": false,
            "assets": [{"name": "tool-linux-x86_64", "browser_download_url": "https://downloads.example/tool"}],
            "tarball_url": "ignored archive", "body": "ignored release instructions"})
    }

    #[test]
    fn gitea_conditional_cache_reselects_complete_pages_and_preserves_failed_refresh() {
        let catalog = catalog();
        let record = catalog.get("example").unwrap();
        let mut cache = GiteaMetadataCache::default();
        let selected = check_cached_with_fetch(
            record,
            "linux",
            "x86_64",
            &mut cache,
            |url, _, validators| {
                assert!(validators.etag.is_none());
                let bytes = if url.ends_with("page=1") {
                    serde_json::to_vec(&vec![release("v1.0.0")]).unwrap()
                } else {
                    b"[]".to_vec()
                };
                Ok(ConditionalHttpsResponse::Modified {
                    response: dev_tools_release::HttpsResponse { bytes, etag: None },
                    validators: HttpsValidators {
                        etag: Some("\"fixture\"".into()),
                        last_modified: None,
                    },
                })
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.version(), "1.0.0");
        let before = cache.to_bytes().unwrap();
        let selected =
            check_cached_with_fetch(record, "linux", "x86_64", &mut cache, |_, _, validators| {
                assert_eq!(validators.etag.as_deref(), Some("\"fixture\""));
                Ok(ConditionalHttpsResponse::NotModified {
                    validators: HttpsValidators::default(),
                })
            })
            .unwrap()
            .unwrap();
        assert_eq!(selected.version(), "1.0.0");
        assert_eq!(cache.to_bytes().unwrap(), before);
        assert!(cache
            .observe(record, "windows", "x86_64")
            .unwrap()
            .is_none());
        assert!(
            check_cached_with_fetch(record, "windows", "x86_64", &mut cache, |_, _, _| {
                Ok(ConditionalHttpsResponse::NotModified {
                    validators: HttpsValidators::default(),
                })
            })
            .unwrap()
            .is_none()
        );
        assert_eq!(cache.to_bytes().unwrap(), before);
        for malformed in [false, true] {
            assert!(
                check_cached_with_fetch(record, "linux", "x86_64", &mut cache, |url, _, _| {
                    if url.ends_with("page=2") && !malformed {
                        return Err(DiscoveryError::Unavailable);
                    }
                    let bytes = if url.ends_with("page=1") {
                        serde_json::to_vec(&vec![release("v2.0.0")]).unwrap()
                    } else {
                        b"invalid".to_vec()
                    };
                    Ok(ConditionalHttpsResponse::Modified {
                        response: dev_tools_release::HttpsResponse { bytes, etag: None },
                        validators: HttpsValidators::default(),
                    })
                })
                .is_err()
            );
            assert_eq!(cache.to_bytes().unwrap(), before);
        }
        let mut empty = GiteaMetadataCache::default();
        assert!(
            check_cached_with_fetch(record, "linux", "x86_64", &mut empty, |_, _, _| Ok(
                ConditionalHttpsResponse::NotModified {
                    validators: HttpsValidators::default()
                }
            ))
            .is_err()
        );
        assert!(empty.inner.pages.is_empty());
        let roundtrip = GiteaMetadataCache::from_bytes(&before, record, "linux", "x86_64").unwrap();
        assert!(roundtrip == cache);
        assert_eq!(
            roundtrip
                .observe(record, "linux", "x86_64")
                .unwrap()
                .unwrap()
                .version(),
            "1.0.0"
        );
        assert!(GithubMetadataCache::from_bytes(&before, record, "linux", "x86_64").is_err());
        assert!(GitlabMetadataCache::from_bytes(&before, record, "linux", "x86_64").is_err());
        assert!(ForgejoMetadataCache::from_bytes(&before, record, "linux", "x86_64").is_err());
        for (from, to) in [
            ("gitea-metadata", "github-metadata"),
            ("/group/tool/", "/other/tool/"),
            ("page=1", "page=3"),
        ] {
            let changed = std::str::from_utf8(&before).unwrap().replace(from, to);
            assert!(
                GiteaMetadataCache::from_bytes(changed.as_bytes(), record, "linux", "x86_64")
                    .is_err()
            );
        }
        let mut truncated = cache.clone();
        truncated.inner.pages.pop();
        assert!(truncated.observe(record, "linux", "x86_64").is_err());
        let mut trailing = cache.clone();
        trailing.inner.pages.push(cache.inner.pages[1].clone());
        assert!(trailing.observe(record, "linux", "x86_64").is_err());
    }

    #[test]
    fn gitea_short_pages_are_not_terminal_and_requests_keep_local_authority() {
        let catalog = catalog();
        let mut calls = 0;
        let selected = check_with_fetch(catalog.get("example").unwrap(), "linux", "x86_64", |url, policy| {
            calls += 1;
            assert_eq!(url, format!("https://forge.example/prefix/api/v1/repos/group/tool/releases?limit=100&page={calls}"));
            assert_eq!(policy.allowed_hosts, BTreeSet::from(["forge.example".into()]));
            assert!(policy.timeout <= Duration::from_secs(60));
            Ok(serde_json::to_vec(&match calls {
                1 => vec![release("v1.0.0")],
                2 => vec![release("v2.0.0")],
                3 => vec![],
                _ => panic!("no request after the terminal empty page"),
            }).unwrap())
        }).unwrap().unwrap();
        assert_eq!(calls, 3);
        assert_eq!(selected.version(), "2.0.0");
        assert_eq!(selected.asset().url(), "https://downloads.example/tool");
    }

    #[test]
    fn gitea_drafts_and_prereleases_cannot_win_selection() {
        let catalog = catalog();
        let mut draft = release("v9.0.0");
        draft["draft"] = json!(true);
        let mut prerelease = release("v8.0.0");
        prerelease["prerelease"] = json!(true);
        let mut first = true;
        let selected = check_with_fetch(
            catalog.get("example").unwrap(),
            "linux",
            "x86_64",
            |_, _| {
                let releases = if std::mem::take(&mut first) {
                    vec![
                        draft.clone(),
                        prerelease.clone(),
                        release("v3.0.0-rc.1"),
                        release("v2.0.0"),
                    ]
                } else {
                    vec![]
                };
                Ok(serde_json::to_vec(&releases).unwrap())
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.version(), "2.0.0");
    }

    #[test]
    fn gitea_incomplete_or_oversized_inventory_fails_without_partial_selection() {
        let catalog = catalog();
        let record = catalog.get("example").unwrap();
        let mut calls = 0;
        assert!(matches!(
            check_with_fetch(record, "linux", "x86_64", |_, _| {
                calls += 1;
                if calls == 1 {
                    Ok(serde_json::to_vec(&vec![release("v1.0.0")]).unwrap())
                } else {
                    Err(DiscoveryError::Unavailable)
                }
            }),
            Err(DiscoveryError::Unavailable)
        ));
        let mut calls = 0;
        assert!(matches!(
            check_with_fetch(record, "linux", "x86_64", |_, _| {
                calls += 1;
                Ok(serde_json::to_vec(&vec![release(&format!("v{calls}.0.0"))]).unwrap())
            }),
            Err(DiscoveryError::InventoryLimit)
        ));
        assert_eq!(calls, 10);
        assert!(matches!(
            check_with_fetch(record, "linux", "x86_64", |_, _| Ok(vec![
                b' ';
                PAGE_LIMIT + 1
            ])),
            Err(DiscoveryError::InventoryLimit)
        ));
        assert!(matches!(
            check_with_fetch(record, "linux", "x86_64", |_, _| Ok(serde_json::to_vec(
                &vec![release("v1.0.0"); 101]
            )
            .unwrap())),
            Err(DiscoveryError::InventoryLimit)
        ));
    }

    #[test]
    fn gitea_malformed_ambiguous_and_hostile_candidates_fail_closed() {
        let catalog = catalog();
        let record = catalog.get("example").unwrap();
        let mut bad_url = release("v1.0.0");
        bad_url["assets"][0]["browser_download_url"] =
            json!("https://user:password@downloads.example/tool");
        let mut bad_name = release("v1.0.0");
        bad_name["assets"][0]["name"] = json!("../tool");
        let mut ambiguous = release("v1.0.0");
        ambiguous["assets"] = json!([
            {"name": "tool-linux-x86_64", "browser_download_url": "https://downloads.example/one"},
            {"name": "tool-linux-x86_64", "browser_download_url": "https://downloads.example/two"}
        ]);
        for releases in [
            vec![bad_url],
            vec![bad_name],
            vec![ambiguous],
            vec![release("v1.0.0"), release("v1.0.0")],
            vec![release("v1.0.0+one"), release("v1.0.0+two")],
            vec![json!({"tag_name": "v1.0.0", "assets": []})],
        ] {
            assert!(
                check_with_fetch(record, "linux", "x86_64", |_, _| Ok(serde_json::to_vec(
                    &releases
                )
                .unwrap()))
                .is_err()
            );
        }
        assert!(
            check_with_fetch(record, "invalid/target", "x86_64", |_, _| panic!(
                "invalid target must not fetch"
            ))
            .is_err()
        );
    }
}
