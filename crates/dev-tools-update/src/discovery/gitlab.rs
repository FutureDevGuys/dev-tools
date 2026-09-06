//! GitLab release links are inert observations, never installation authority.
use super::*;

pub const GITLAB_CACHE_DOCUMENT_LIMIT: usize = GITHUB_CACHE_DOCUMENT_LIMIT;
const GITLAB_CACHE_SCHEMA: &str = "dev-tools-gitlab-metadata-cache-v1";

/// Original bounded GitLab resource pages, not release authentication. Products
/// own private storage, configuration binding and freshness independently.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct GitlabMetadataCache {
    inner: GithubMetadataCache,
}

impl GitlabMetadataCache {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DiscoveryError> {
        self.inner.encode(GITLAB_CACHE_SCHEMA)
    }

    pub fn from_bytes(
        bytes: &[u8],
        artifact: &ArtifactRecord,
        os: &str,
        architecture: &str,
    ) -> Result<Self, DiscoveryError> {
        let cache = Self {
            inner: GithubMetadataCache::decode(bytes, GITLAB_CACHE_SCHEMA)?,
        };
        cache.observe(artifact, os, architecture)?;
        Ok(cache)
    }

    /// Network-free reselection against the exact locally generated resources.
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

/// Explicit bounded anonymous GitLab release discovery. No artifact download,
/// filesystem mutation, credential lookup, or release authentication occurs.
pub fn check_gitlab_release(
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
    mut fetch: impl FnMut(&str, &HttpsPolicy) -> Result<Vec<u8>, DiscoveryError>,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    let ArtifactSource::Gitlab { api, project } = artifact.source() else {
        return Err(DiscoveryError::UnsupportedSource);
    };
    let host = dev_tools_release::canonical_https_host(api)
        .map_err(|_| DiscoveryError::InvalidMetadata)?;
    let project = project.split('/').collect::<Vec<_>>().join("%2F");
    let mut selection = ReleaseSelection::new(artifact, os, architecture)?;
    let started = Instant::now();
    for page in 1..=PAGE_COUNT_LIMIT {
        let remaining = Duration::from_secs(60)
            .checked_sub(started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(DiscoveryError::Unavailable)?;
        let policy = HttpsPolicy {
            allowed_hosts: BTreeSet::from([host.clone()]),
            max_redirects: 2,
            timeout: remaining,
            user_agent: "dev-tools-update".into(),
        };
        // Offset pagination stays bound to the locally declared project. Remote
        // asset or pagination URLs never widen metadata retrieval authority.
        let url = format!("{api}/projects/{project}/releases?order_by=released_at&sort=desc&per_page={PAGE_SIZE}&page={page}");
        let bytes = fetch(&url, &policy)?;
        if bytes.len() > PAGE_LIMIT {
            return Err(DiscoveryError::InventoryLimit);
        }
        let releases: Vec<GitlabRelease> =
            serde_json::from_slice(&bytes).map_err(|_| DiscoveryError::InvalidMetadata)?;
        if releases.len() > PAGE_SIZE {
            return Err(DiscoveryError::InventoryLimit);
        }
        let complete = releases.len() < PAGE_SIZE;
        for release in releases {
            selection.consider(release.tag_name, release.upcoming_release, || {
                if release.assets.links.len() > 4096 {
                    return Err(DiscoveryError::InventoryLimit);
                }
                release
                    .assets
                    .links
                    .into_iter()
                    .map(|link| {
                        AssetCandidate::new(link.name, link.url)
                            .map_err(|_| DiscoveryError::InvalidMetadata)
                    })
                    .collect()
            })?;
        }
        if complete {
            return Ok(selection.finish());
        }
    }
    Err(DiscoveryError::InventoryLimit)
}

/// Conditional explicit check. A failed refresh leaves the cache unchanged;
/// reused pages are parsed and selected again under the current local rules.
pub fn check_gitlab_release_cached(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut GitlabMetadataCache,
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
    cache: &mut GitlabMetadataCache,
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

#[derive(Deserialize)]
struct GitlabRelease {
    tag_name: String,
    #[serde(default)]
    upcoming_release: bool,
    assets: GitlabAssets,
}

#[derive(Deserialize)]
struct GitlabAssets {
    links: Vec<GitlabLink>,
}

#[derive(Deserialize)]
struct GitlabLink {
    name: String,
    url: String,
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
source = { type = "gitlab", api = "https://gitlab.example/api/v4", project = "group/subgroup/example" }
version = { type = "semver-tag", prefix = "v" }
verification = { type = "check-only" }
selectors = [{ type = "exact", pattern = "example-linux-x86_64", os = "linux", architecture = "x86_64" }]
"#).unwrap()
    }

    fn release(tag: &str) -> serde_json::Value {
        json!({"tag_name": tag, "assets": {"links": [{"name": "example-linux-x86_64", "url": "https://downloads.example/example"}], "sources": [{"url": "not a selected asset"}]}})
    }

    #[test]
    fn gitlab_conditional_refresh_reselects_and_never_commits_failure() {
        let catalog = catalog();
        let record = catalog.get("example").unwrap();
        let mut cache = GitlabMetadataCache::default();
        let first =
            check_cached_with_fetch(record, "linux", "x86_64", &mut cache, |_, _, validators| {
                assert!(validators.etag.is_none());
                Ok(ConditionalHttpsResponse::Modified {
                    response: dev_tools_release::HttpsResponse {
                        bytes: serde_json::to_vec(&vec![release("v1.0.0")]).unwrap(),
                        etag: None,
                    },
                    validators: HttpsValidators {
                        etag: Some("\"fixture\"".into()),
                        last_modified: None,
                    },
                })
            })
            .unwrap()
            .unwrap();
        assert_eq!(first.version(), "1.0.0");
        let before = cache.to_bytes().unwrap();
        let second =
            check_cached_with_fetch(record, "linux", "x86_64", &mut cache, |_, _, validators| {
                assert_eq!(validators.etag.as_deref(), Some("\"fixture\""));
                Ok(ConditionalHttpsResponse::NotModified {
                    validators: HttpsValidators::default(),
                })
            })
            .unwrap()
            .unwrap();
        assert_eq!(second.version(), "1.0.0");
        assert_eq!(cache.to_bytes().unwrap(), before);
        for malformed in [false, true] {
            assert!(
                check_cached_with_fetch(record, "linux", "x86_64", &mut cache, |_, _, _| {
                    if !malformed {
                        return Err(DiscoveryError::Unavailable);
                    }
                    Ok(ConditionalHttpsResponse::Modified {
                        response: dev_tools_release::HttpsResponse {
                            bytes: b"invalid".to_vec(),
                            etag: None,
                        },
                        validators: HttpsValidators::default(),
                    })
                })
                .is_err()
            );
            assert_eq!(cache.to_bytes().unwrap(), before);
        }
        let mut absent = GitlabMetadataCache::default();
        assert!(
            check_cached_with_fetch(record, "linux", "x86_64", &mut absent, |_, _, _| Ok(
                ConditionalHttpsResponse::NotModified {
                    validators: HttpsValidators::default()
                }
            ))
            .is_err()
        );
        assert!(absent.inner.pages.is_empty());
    }

    #[test]
    fn gitlab_cache_codec_is_resource_bound_and_distinct_from_github() {
        let catalog = catalog();
        let record = catalog.get("example").unwrap();
        let bytes = br#"{"schema":"dev-tools-gitlab-metadata-cache-v1","pages":[{"url":"https://gitlab.example/api/v4/projects/group%2Fsubgroup%2Fexample/releases?order_by=released_at&sort=desc&per_page=100&page=1","body_base64":"W10=","etag":null,"last_modified":null}]}"#;
        let cache = GitlabMetadataCache::from_bytes(bytes, record, "linux", "x86_64").unwrap();
        assert!(cache.observe(record, "linux", "x86_64").unwrap().is_none());
        assert!(
            GitlabMetadataCache::from_bytes(&cache.to_bytes().unwrap(), record, "linux", "x86_64")
                .unwrap()
                == cache
        );
        assert!(GithubMetadataCache::from_bytes(bytes, record, "linux", "x86_64").is_err());
        for (from, to) in [
            ("gitlab-metadata", "github-metadata"),
            ("page=1", "page=2"),
            ("group%2Fsubgroup", "different%2Fproject"),
        ] {
            let changed = std::str::from_utf8(bytes).unwrap().replace(from, to);
            assert!(
                GitlabMetadataCache::from_bytes(changed.as_bytes(), record, "linux", "x86_64")
                    .is_err()
            );
        }
    }

    #[test]
    fn gitlab_full_pages_require_completion_and_preserve_later_failure() {
        let catalog = catalog();
        let record = catalog.get("example").unwrap();
        let full: Vec<_> = (0..100)
            .map(|index| release(&format!("v1.0.{index}")))
            .collect();
        let mut calls = 0;
        let observed = check_with_fetch(record, "linux", "x86_64", |url, _| {
            calls += 1;
            assert!(url.ends_with(&format!("page={calls}")));
            Ok(if calls == 1 {
                serde_json::to_vec(&full)
            } else {
                serde_json::to_vec(&vec![release("v2.0.0")])
            }
            .unwrap())
        })
        .unwrap()
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(observed.version(), "2.0.0");
        let mut calls = 0;
        assert!(matches!(
            check_with_fetch(record, "linux", "x86_64", |_, _| {
                calls += 1;
                if calls == 1 {
                    Ok(serde_json::to_vec(&full).unwrap())
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
                Ok(serde_json::to_vec(
                    &(0..100)
                        .map(|index| release(&format!("v{calls}.0.{index}")))
                        .collect::<Vec<_>>(),
                )
                .unwrap())
            }),
            Err(DiscoveryError::InventoryLimit)
        ));
        assert_eq!(calls, 10);
    }

    #[test]
    fn gitlab_invalid_or_ambiguous_metadata_never_becomes_a_selection() {
        let catalog = catalog();
        let record = catalog.get("example").unwrap();
        let mut credential_url = release("v1.0.0");
        credential_url["assets"]["links"][0]["url"] =
            json!("https://user:password@downloads.example/tool");
        let mut executable_name = release("v1.0.0");
        executable_name["assets"]["links"][0]["name"] = json!("../tool");
        let mut ambiguous = release("v1.0.0");
        ambiguous["assets"]["links"] = json!([
            {"name": "example-linux-x86_64", "url": "https://downloads.example/one"},
            {"name": "example-linux-x86_64", "url": "https://downloads.example/two"}
        ]);
        for releases in [
            vec![credential_url],
            vec![executable_name],
            vec![ambiguous],
            vec![release("v1.0.0"), release("v1.0.0")],
            vec![release("v1.0.0+one"), release("v1.0.0+two")],
            vec![json!({"tag_name": "v1.0.0", "assets": {}})],
        ] {
            assert!(
                check_with_fetch(record, "linux", "x86_64", |_, _| Ok(serde_json::to_vec(
                    &releases
                )
                .unwrap()))
                .is_err()
            );
        }
        assert!(matches!(
            check_with_fetch(record, "linux", "x86_64", |_, _| Ok(vec![
                b' ';
                PAGE_LIMIT + 1
            ])),
            Err(DiscoveryError::InventoryLimit)
        ));
        assert!(
            check_with_fetch(record, "invalid/target", "x86_64", |_, _| panic!(
                "invalid target must not fetch"
            ))
            .is_err()
        );
    }

    #[test]
    fn gitlab_selects_named_links_by_local_version_and_omits_upcoming() {
        let catalog = catalog();
        let record = catalog.get("example").unwrap();
        let mut upcoming = release("v9.0.0");
        upcoming["upcoming_release"] = json!(true);
        let mut calls = 0;
        let selected = check_with_fetch(record, "linux", "x86_64", |url, policy| {
            calls += 1;
            assert_eq!(url, "https://gitlab.example/api/v4/projects/group%2Fsubgroup%2Fexample/releases?order_by=released_at&sort=desc&per_page=100&page=1");
            assert_eq!(policy.allowed_hosts, BTreeSet::from(["gitlab.example".into()]));
            assert!(policy.timeout <= Duration::from_secs(60));
            Ok(serde_json::to_vec(&vec![release("v1.0.0"), upcoming.clone(), release("v2.0.0-rc.1"), release("v2.0.0")]).unwrap())
        }).unwrap().unwrap();
        assert_eq!(calls, 1);
        assert_eq!(selected.version(), "2.0.0");
        assert_eq!(selected.asset().url(), "https://downloads.example/example");
    }
}
