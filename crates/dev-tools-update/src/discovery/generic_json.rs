//! One explicit JSON document, mapped only by local configuration.
use super::*;

pub const GENERIC_JSON_CACHE_DOCUMENT_LIMIT: usize = GITHUB_CACHE_DOCUMENT_LIMIT;
const GENERIC_JSON_CACHE_SCHEMA: &str = "dev-tools-generic-json-metadata-cache-v1";

/// Original bounded bytes for one configured resource, never release authority.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct GenericJsonMetadataCache {
    inner: GithubMetadataCache,
}

impl GenericJsonMetadataCache {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DiscoveryError> {
        self.inner.encode(GENERIC_JSON_CACHE_SCHEMA)
    }

    pub fn from_bytes(
        bytes: &[u8],
        artifact: &ArtifactRecord,
        os: &str,
        architecture: &str,
    ) -> Result<Self, DiscoveryError> {
        let cache = Self {
            inner: GithubMetadataCache::decode(bytes, GENERIC_JSON_CACHE_SCHEMA)?,
        };
        cache.observe(artifact, os, architecture)?;
        Ok(cache)
    }

    /// Reparse the exact resource with the current local field and asset mappings.
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

/// Conditionally refresh one resource; failures never replace prior cache bytes.
pub fn check_generic_json_release_cached(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut GenericJsonMetadataCache,
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
    cache: &mut GenericJsonMetadataCache,
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

/// Retrieve one explicitly configured document. This neither follows remote
/// pagination nor claims completeness beyond that document's mapped inventory.
pub fn check_generic_json_release(
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
    let ArtifactSource::GenericJson { url, mapping } = artifact.source() else {
        return Err(DiscoveryError::UnsupportedSource);
    };
    let mut selection = ReleaseSelection::new(artifact, os, architecture)?;
    let host = dev_tools_release::canonical_https_host(url)
        .map_err(|_| DiscoveryError::InvalidMetadata)?;
    let policy = HttpsPolicy {
        allowed_hosts: BTreeSet::from([host]),
        max_redirects: 2,
        timeout: Duration::from_secs(60),
        user_agent: "dev-tools-update".into(),
    };
    let bytes = fetch(url, &policy)?;
    if bytes.len() > PAGE_LIMIT {
        return Err(DiscoveryError::InventoryLimit);
    }
    let document =
        super::strict_json::parse(&bytes).map_err(|_| DiscoveryError::InvalidMetadata)?;
    let releases = document
        .pointer(&mapping.releases)
        .and_then(serde_json::Value::as_array)
        .ok_or(DiscoveryError::InvalidMetadata)?;
    if releases.len() > 1000 {
        return Err(DiscoveryError::InventoryLimit);
    }
    for release in releases {
        let tag = string_at(release, &mapping.tag)?;
        let draft = flag_at(release, mapping.draft.as_deref())?;
        let prerelease = flag_at(release, mapping.prerelease.as_deref())?;
        selection.consider(tag.to_owned(), draft || prerelease, || {
            let assets = release
                .pointer(&mapping.assets)
                .and_then(serde_json::Value::as_array)
                .ok_or(DiscoveryError::InvalidMetadata)?;
            if assets.len() > 4096 {
                return Err(DiscoveryError::InventoryLimit);
            }
            assets
                .iter()
                .map(|asset| {
                    AssetCandidate::new(
                        string_at(asset, &mapping.name)?,
                        string_at(asset, &mapping.url)?,
                    )
                    .map_err(|_| DiscoveryError::InvalidMetadata)
                })
                .collect()
        })?;
    }
    Ok(selection.finish())
}

fn string_at<'a>(value: &'a serde_json::Value, pointer: &str) -> Result<&'a str, DiscoveryError> {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .ok_or(DiscoveryError::InvalidMetadata)
}

fn flag_at(value: &serde_json::Value, pointer: Option<&str>) -> Result<bool, DiscoveryError> {
    match pointer {
        None => Ok(false),
        Some(pointer) => value
            .pointer(pointer)
            .and_then(serde_json::Value::as_bool)
            .ok_or(DiscoveryError::InvalidMetadata),
    }
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
kind = "native-binary"
source = { type = "generic-json", url = "https://updates.example/catalog.json?channel=stable", mapping = { releases = "/inventory/releases", tag = "/meta/version", assets = "/artifacts", name = "/name", url = "/download/url", draft = "/draft", prerelease = "/preview" } }
version = { type = "semver-tag", prefix = "v" }
verification = { type = "check-only" }
selectors = [{ type = "exact", pattern = "tool", os = "linux", architecture = "x86_64" }]
"#;

    fn release(version: &str) -> serde_json::Value {
        json!({"meta": {"version": version}, "artifacts": [{"name": "tool", "download": {"url": "https://downloads.example/tool"}}], "draft": false, "preview": false})
    }

    #[test]
    fn generic_json_cache_reselects_current_mapping_and_never_commits_failed_checks() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let record = catalog.get("example").unwrap();
        let mut entry = release("v1.0.0");
        entry["meta"]["alternate"] = json!("v2.0.0");
        let body = serde_json::to_vec(&json!({"inventory": {"releases": [entry]}})).unwrap();
        let mut cache = GenericJsonMetadataCache::default();
        let first =
            check_cached_with_fetch(record, "linux", "x86_64", &mut cache, |_, _, validators| {
                assert!(validators.etag.is_none());
                Ok(ConditionalHttpsResponse::Modified {
                    response: dev_tools_release::HttpsResponse {
                        bytes: body.clone(),
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
        let changed =
            ArtifactCatalog::parse(&CONFIG.replace("/meta/version", "/meta/alternate")).unwrap();
        assert_eq!(
            cache
                .observe(changed.get("example").unwrap(), "linux", "x86_64")
                .unwrap()
                .unwrap()
                .version(),
            "2.0.0"
        );
        let reused = check_cached_with_fetch(
            changed.get("example").unwrap(),
            "linux",
            "x86_64",
            &mut cache,
            |_, _, validators| {
                assert_eq!(validators.etag.as_deref(), Some("\"fixture\""));
                Ok(ConditionalHttpsResponse::NotModified {
                    validators: HttpsValidators::default(),
                })
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(reused.version(), "2.0.0");
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
        let mut absent = GenericJsonMetadataCache::default();
        assert!(
            check_cached_with_fetch(record, "linux", "x86_64", &mut absent, |_, _, _| Ok(
                ConditionalHttpsResponse::NotModified {
                    validators: HttpsValidators::default()
                }
            ))
            .is_err()
        );
        assert!(absent.inner.pages.is_empty());
        assert!(
            GenericJsonMetadataCache::from_bytes(&before, record, "linux", "x86_64").unwrap()
                == cache
        );
        assert!(ForgejoMetadataCache::from_bytes(&before, record, "linux", "x86_64").is_err());
        for (from, to) in [
            ("generic-json-metadata", "github-metadata"),
            ("catalog.json", "other.json"),
        ] {
            let changed = std::str::from_utf8(&before).unwrap().replace(from, to);
            assert!(GenericJsonMetadataCache::from_bytes(
                changed.as_bytes(),
                record,
                "linux",
                "x86_64"
            )
            .is_err());
        }
        let mut extra = cache.clone();
        extra.inner.pages.push(cache.inner.pages[0].clone());
        assert!(extra.observe(record, "linux", "x86_64").is_err());
    }

    #[test]
    fn generic_json_uses_only_local_mappings_and_chooses_stable_matching_metadata() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let mut draft = release("v9.0.0");
        draft["draft"] = json!(true);
        let mut preview = release("v8.0.0");
        preview["preview"] = json!(true);
        let body = json!({"inventory": {"releases": [release("v1.0.0"), release("v2.0.0"), draft, preview, release("v3.0.0-rc.1")]}, "mapping": "ignored remote policy", "command": "ignored remote command", "destination": "/ignored", "next": "https://untrusted.example/ignored-page"});
        let mut calls = 0;
        let selected = check_with_fetch(
            catalog.get("example").unwrap(),
            "linux",
            "x86_64",
            |url, policy| {
                calls += 1;
                assert_eq!(url, "https://updates.example/catalog.json?channel=stable");
                assert_eq!(
                    policy.allowed_hosts,
                    BTreeSet::from(["updates.example".into()])
                );
                assert_eq!(policy.timeout, Duration::from_secs(60));
                Ok(serde_json::to_vec(&body).unwrap())
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(selected.version(), "2.0.0");
        assert_eq!(selected.asset().url(), "https://downloads.example/tool");
    }

    #[test]
    fn generic_json_pointer_escapes_and_root_arrays_work_without_implicit_fields() {
        let escaped = CONFIG
            .replace("/inventory/releases", "/inventory~1releases")
            .replace("/meta/version", "/meta~0version");
        let catalog = ArtifactCatalog::parse(&escaped).unwrap();
        let mut entry = release("v1.0.0");
        entry["meta~version"] = json!("v2.0.0");
        let selected = check_with_fetch(
            catalog.get("example").unwrap(),
            "linux",
            "x86_64",
            |_, _| Ok(serde_json::to_vec(&json!({"inventory/releases": [entry.clone()]})).unwrap()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.version(), "2.0.0");
        let root_array = CONFIG
            .replace("/inventory/releases", "")
            .replace(", draft = \"/draft\", prerelease = \"/preview\"", "");
        let catalog = ArtifactCatalog::parse(&root_array).unwrap();
        let mut entry = release("v1.0.0");
        entry.as_object_mut().unwrap().remove("draft");
        entry.as_object_mut().unwrap().remove("preview");
        assert!(check_with_fetch(
            catalog.get("example").unwrap(),
            "linux",
            "x86_64",
            |_, _| Ok(serde_json::to_vec(&vec![entry.clone()]).unwrap())
        )
        .unwrap()
        .is_some());
        assert!(check_with_fetch(
            catalog.get("example").unwrap(),
            "linux",
            "x86_64",
            |_, _| Ok(b"[]".to_vec())
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn generic_json_rejects_duplicate_missing_mistyped_and_ambiguous_metadata() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let record = catalog.get("example").unwrap();
        let mut bad_flag = release("v1.0.0");
        bad_flag["draft"] = json!("false");
        let mut bad_url = release("v1.0.0");
        bad_url["artifacts"][0]["download"]["url"] =
            json!("https://user:password@downloads.example/tool");
        let mut ambiguous = release("v1.0.0");
        let duplicate_asset = ambiguous["artifacts"][0].clone();
        ambiguous["artifacts"]
            .as_array_mut()
            .unwrap()
            .push(duplicate_asset);
        for releases in [
            vec![bad_flag],
            vec![bad_url],
            vec![ambiguous],
            vec![release("v1.0.0"), release("v1.0.0")],
            vec![json!({"meta": {"version": "v1.0.0"}})],
        ] {
            let body = serde_json::to_vec(&json!({"inventory": {"releases": releases}})).unwrap();
            assert!(check_with_fetch(record, "linux", "x86_64", |_, _| Ok(body.clone())).is_err());
        }
        for bytes in [
            br#"{"inventory":{"releases":[]},"inventory":{"releases":[]}}"#.as_slice(),
            br#"{"inventory":{"releases":null}}"#,
            br#"{"inventory":{"releases":[]}} trailing"#,
        ] {
            assert!(matches!(
                check_with_fetch(record, "linux", "x86_64", |_, _| Ok(bytes.to_vec())),
                Err(DiscoveryError::InvalidMetadata)
            ));
        }
    }

    #[test]
    fn generic_json_inventory_and_transport_failures_do_not_yield_partial_results() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let record = catalog.get("example").unwrap();
        assert!(matches!(
            check_with_fetch(record, "linux", "x86_64", |_, _| Err(
                DiscoveryError::Unavailable
            )),
            Err(DiscoveryError::Unavailable)
        ));
        assert!(matches!(
            check_with_fetch(record, "linux", "x86_64", |_, _| Ok(vec![
                b' ';
                PAGE_LIMIT + 1
            ])),
            Err(DiscoveryError::InventoryLimit)
        ));
        let body =
            serde_json::to_vec(&json!({"inventory": {"releases": vec![release("v1.0.0"); 1001]}}))
                .unwrap();
        assert!(matches!(
            check_with_fetch(record, "linux", "x86_64", |_, _| Ok(body.clone())),
            Err(DiscoveryError::InventoryLimit)
        ));
        assert!(
            check_with_fetch(record, "invalid/target", "x86_64", |_, _| panic!(
                "invalid target must not fetch"
            ))
            .is_err()
        );
    }
}
