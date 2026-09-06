//! The public crates.io sparse index, without Cargo execution or configuration.
use super::*;

pub const CRATES_IO_CACHE_DOCUMENT_LIMIT: usize = GITHUB_CACHE_DOCUMENT_LIMIT;
const CACHE_SCHEMA: &str = "dev-tools-crates-io-metadata-cache-v1";

/// Original bytes of one public sparse-index resource, not authenticated evidence.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct CratesIoMetadataCache {
    inner: GithubMetadataCache,
}

impl CratesIoMetadataCache {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DiscoveryError> {
        self.inner.encode(CACHE_SCHEMA)
    }

    pub fn from_bytes(
        bytes: &[u8],
        artifact: &ArtifactRecord,
        os: &str,
        architecture: &str,
    ) -> Result<Self, DiscoveryError> {
        let cache = Self {
            inner: GithubMetadataCache::decode(bytes, CACHE_SCHEMA)?,
        };
        cache.observe(artifact, os, architecture)?;
        Ok(cache)
    }

    /// Reselect original bytes under current local rules, without a timestamp refresh.
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
    cache: &mut CratesIoMetadataCache,
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

/// Refresh one public sparse-index entry; failure leaves the previous cache unchanged.
pub fn check_crates_io_release_cached(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut CratesIoMetadataCache,
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

/// Observe stable, non-yanked crate archives under local selection rules.
/// This does not resolve dependencies, authenticate crate bytes, compile or install.
pub fn check_crates_io_release(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    check_crates_io_release_cached(
        artifact,
        os,
        architecture,
        &mut CratesIoMetadataCache::default(),
    )
}

fn check_with_fetch(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    mut fetch: impl FnMut(&str, &HttpsPolicy) -> Result<Vec<u8>, DiscoveryError>,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    let ArtifactSource::CratesIo { package } = artifact.source() else {
        return Err(DiscoveryError::UnsupportedSource);
    };
    let mut selection = ReleaseSelection::new(artifact, os, architecture)?;
    // The catalog has validated ASCII and a nonempty literal package name.
    let lower = package.to_ascii_lowercase();
    let prefix = match lower.len() {
        1 => "1".to_owned(),
        2 => "2".to_owned(),
        3 => format!("3/{}", &lower[..1]),
        _ => format!("{}/{}", &lower[..2], &lower[2..4]),
    };
    let url = format!("https://index.crates.io/{prefix}/{lower}");
    let policy = HttpsPolicy {
        allowed_hosts: BTreeSet::from(["index.crates.io".into()]),
        max_redirects: 2,
        timeout: Duration::from_secs(60),
        user_agent: "dev-tools-update (https://github.com/FutureDevGuys/dev-tools)".into(),
    };
    let bytes = fetch(&url, &policy)?;
    if bytes.len() > PAGE_LIMIT {
        return Err(DiscoveryError::InventoryLimit);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| DiscoveryError::InvalidMetadata)?;
    if text.is_empty() {
        return Err(DiscoveryError::InvalidMetadata);
    }
    let mut versions = BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        if index >= 1000 {
            return Err(DiscoveryError::InventoryLimit);
        }
        let document = super::strict_json::parse(line.as_bytes())
            .map_err(|_| DiscoveryError::InvalidMetadata)?;
        if document.get("name").and_then(serde_json::Value::as_str) != Some(package.as_str())
            || document
                .get("v")
                .is_some_and(|schema| !matches!(schema.as_u64(), Some(1 | 2)))
        {
            return Err(DiscoveryError::InvalidMetadata);
        }
        let version = document
            .get("vers")
            .and_then(serde_json::Value::as_str)
            .ok_or(DiscoveryError::InvalidMetadata)?;
        let mut parsed = Version::parse(version).map_err(|_| DiscoveryError::InvalidMetadata)?;
        let yanked = document
            .get("yanked")
            .and_then(serde_json::Value::as_bool)
            .ok_or(DiscoveryError::InvalidMetadata)?;
        let excluded = yanked || !parsed.pre.is_empty();
        // crates.io requires uniqueness even when only build metadata differs.
        // Check excluded records too: filtering cannot hide contradictory input.
        parsed.build = semver::BuildMetadata::EMPTY;
        if !versions.insert(parsed) {
            return Err(DiscoveryError::Ambiguous);
        }
        selection.consider(version.to_owned(), excluded, || {
            let name = format!("{package}-{version}.crate");
            let url = format!("https://static.crates.io/crates/{package}/{name}");
            Ok(vec![
                AssetCandidate::new(&name, &url).map_err(|_| DiscoveryError::InvalidMetadata)?
            ])
        })?;
    }
    Ok(selection.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactCatalog;

    const CONFIG: &str = r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "tar"
source = { type = "crates-io", package = "Example_tool" }
version = { type = "semver-tag", prefix = "" }
verification = { type = "check-only" }
selectors = [{ type = "glob", pattern = "*.crate", os = "linux", architecture = "x86_64" }]
"#;

    fn line(version: &str, yanked: bool) -> String {
        serde_json::json!({"name":"Example_tool", "vers":version, "yanked":yanked, "v":2, "deps":[], "cksum":"ignored"}).to_string()
    }

    #[test]
    fn sparse_index_cache_reselects_and_preserves_previous_bytes_on_failure() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let record = catalog.get("example").unwrap();
        let mut cache = CratesIoMetadataCache::default();
        let selected =
            check_cached_with_fetch(record, "linux", "x86_64", &mut cache, |_, _, validators| {
                assert!(validators.etag.is_none());
                Ok(ConditionalHttpsResponse::Modified {
                    response: dev_tools_release::HttpsResponse {
                        bytes: line("1.2.3", false).into_bytes(),
                        etag: None,
                    },
                    validators: HttpsValidators {
                        etag: Some("\"index-fixture\"".into()),
                        last_modified: None,
                    },
                })
            })
            .unwrap()
            .unwrap();
        assert_eq!(selected.version(), "1.2.3");
        let before = cache.to_bytes().unwrap();
        assert!(
            CratesIoMetadataCache::from_bytes(&before, record, "linux", "x86_64").unwrap() == cache
        );
        assert!(check_cached_with_fetch(
            record,
            "windows",
            "x86_64",
            &mut cache,
            |_, _, validators| {
                assert_eq!(validators.etag.as_deref(), Some("\"index-fixture\""));
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
        let mut empty = CratesIoMetadataCache::default();
        assert!(
            check_cached_with_fetch(record, "linux", "x86_64", &mut empty, |_, _, _| Ok(
                ConditionalHttpsResponse::NotModified {
                    validators: HttpsValidators::default()
                }
            ))
            .is_err()
        );
        assert!(empty.inner.pages.is_empty());
        for (from, to) in [
            ("crates-io-metadata", "npm-metadata"),
            ("/ex/am/example_tool", "/ot/he/other"),
        ] {
            let changed = std::str::from_utf8(&before).unwrap().replace(from, to);
            assert!(CratesIoMetadataCache::from_bytes(
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
        let changed_catalog =
            ArtifactCatalog::parse(&CONFIG.replace("pattern = \"*.crate\"", "pattern = \"*.zip\""))
                .unwrap();
        assert!(cache
            .observe(changed_catalog.get("example").unwrap(), "linux", "x86_64")
            .unwrap()
            .is_none());
    }

    #[test]
    fn sparse_index_validates_all_records_and_bounds_the_complete_inventory() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let record = catalog.get("example").unwrap();
        let valid = line("1.2.3", false);
        for body in [
            String::new(),
            "\n".into(),
            format!("{valid}\n\n{valid}"),
            valid.replace("Example_tool", "example_tool"),
            valid.replace("1.2.3", "v1.2.3"),
            valid.replace("\"yanked\":false", "\"yanked\":null"),
            valid.replace("\"v\":2", "\"v\":3"),
            valid.replace("\"v\":2", "\"v\":null"),
            valid.replace("\"v\":2", "\"v\":2,\"v\":1"),
            valid.replace("\"deps\":[]", "\"deps\":[{\"x\":1,\"x\":2}]"),
            format!("{valid} trailing"),
            format!("{valid}\n{}", line("broken", true)),
        ] {
            assert!(
                matches!(
                    check_with_fetch(record, "linux", "x86_64", |_, _| Ok(body
                        .as_bytes()
                        .to_vec())),
                    Err(DiscoveryError::InvalidMetadata)
                ),
                "invalid metadata was not rejected"
            );
        }
        for body in [
            format!("{valid}\n{valid}"),
            format!(
                "{}\n{}",
                line("1.2.3+first", true),
                line("1.2.3+second", false)
            ),
        ] {
            assert!(matches!(
                check_with_fetch(record, "linux", "x86_64", |_, _| Ok(body
                    .as_bytes()
                    .to_vec())),
                Err(DiscoveryError::Ambiguous)
            ));
        }
        for body in [
            vec![b' '; PAGE_LIMIT + 1],
            (0..1001)
                .map(|n| line(&format!("1.0.{n}"), false))
                .collect::<Vec<_>>()
                .join("\n")
                .into_bytes(),
        ] {
            assert!(matches!(
                check_with_fetch(record, "linux", "x86_64", |_, _| Ok(body.clone())),
                Err(DiscoveryError::InventoryLimit)
            ));
        }
        assert!(matches!(
            check_with_fetch(record, "linux", "x86_64", |_, _| Ok(vec![0xff])),
            Err(DiscoveryError::InvalidMetadata)
        ));
        assert!(matches!(
            check_with_fetch(record, "linux", "x86_64", |_, _| Err(
                DiscoveryError::Unavailable
            )),
            Err(DiscoveryError::Unavailable)
        ));
        assert!(
            check_with_fetch(record, "invalid/target", "x86_64", |_, _| panic!(
                "invalid target must not retrieve"
            ))
            .is_err()
        );
        for body in [
            valid.replace(",\"v\":2", ""),
            valid.replace("\"v\":2", "\"v\":1"),
            format!("{valid}\r\n"),
        ] {
            assert!(check_with_fetch(record, "linux", "x86_64", |_, _| Ok(body
                .as_bytes()
                .to_vec()))
            .unwrap()
            .is_some());
        }
    }

    #[test]
    fn sparse_index_paths_and_current_local_rules_are_applied() {
        for (package, path) in [
            ("A", "1/a"),
            ("Ab", "2/ab"),
            ("Abc", "3/a/abc"),
            ("Abcd", "ab/cd/abcd"),
        ] {
            let config = CONFIG.replace("Example_tool", package);
            let catalog = ArtifactCatalog::parse(&config).unwrap();
            let body = line("1.2.3", false).replace("Example_tool", package);
            assert!(check_with_fetch(
                catalog.get("example").unwrap(),
                "linux",
                "x86_64",
                |url, _| {
                    assert_eq!(url, format!("https://index.crates.io/{path}"));
                    Ok(body.as_bytes().to_vec())
                }
            )
            .unwrap()
            .is_some());
        }
        for config in [
            CONFIG.to_owned(),
            CONFIG.replace(
                "type = \"semver-tag\", prefix = \"\"",
                "type = \"provider-order\"",
            ),
        ] {
            let catalog = ArtifactCatalog::parse(&config).unwrap();
            let body = format!("{}\n{}", line("1.2.3", true), line("2.0.0-rc.1", false));
            assert!(check_with_fetch(
                catalog.get("example").unwrap(),
                "linux",
                "x86_64",
                |_, _| Ok(body.as_bytes().to_vec())
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
                    line("1.2.3", false).into_bytes()
                ))
                .unwrap()
                .is_none()
            );
        }
    }

    #[test]
    fn sparse_index_ranks_stable_unyanked_versions_and_derives_fixed_download() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let body = [
            line("1.0.0", false),
            line("3.0.0", true),
            line("2.0.0", false),
            line("4.0.0-rc.1", false),
        ]
        .join("\n")
            + "\n";
        let selected = check_with_fetch(
            catalog.get("example").unwrap(),
            "linux",
            "x86_64",
            |url, policy| {
                assert_eq!(url, "https://index.crates.io/ex/am/example_tool");
                assert_eq!(
                    policy.allowed_hosts,
                    BTreeSet::from(["index.crates.io".into()])
                );
                assert_eq!(policy.max_redirects, 2);
                assert_eq!(policy.timeout, Duration::from_secs(60));
                Ok(body.as_bytes().to_vec())
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.version(), "2.0.0");
        assert_eq!(
            selected.asset().url(),
            "https://static.crates.io/crates/Example_tool/Example_tool-2.0.0.crate"
        );
    }
}
