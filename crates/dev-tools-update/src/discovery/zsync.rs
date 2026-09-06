//! Zsync control metadata only; no reconstruction or checksum authentication.
use super::*;
use dev_tools_release::LocatedConditionalHttpsResponse;

pub const ZSYNC_CACHE_DOCUMENT_LIMIT: usize = GITHUB_CACHE_DOCUMENT_LIMIT;
const CACHE_SCHEMA: &str = "dev-tools-zsync-metadata-cache-v1";

/// Original control bytes plus their actual resource location; never release authentication.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ZsyncMetadataCache {
    resource: Option<(CachedGithubPage, String)>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ZsyncCacheDocument {
    schema: String,
    final_url: String,
    resource: CachePageDocument,
}

impl ZsyncMetadataCache {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DiscoveryError> {
        let (page, final_url) = self
            .resource
            .as_ref()
            .ok_or(DiscoveryError::InvalidMetadata)?;
        let bytes = serde_json::to_vec(&ZsyncCacheDocument {
            schema: CACHE_SCHEMA.into(),
            final_url: final_url.clone(),
            resource: page.document(),
        })
        .map_err(|_| DiscoveryError::InvalidMetadata)?;
        if bytes.len() > ZSYNC_CACHE_DOCUMENT_LIMIT {
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
        if bytes.len() > ZSYNC_CACHE_DOCUMENT_LIMIT {
            return Err(DiscoveryError::InventoryLimit);
        }
        let document: ZsyncCacheDocument =
            serde_json::from_slice(bytes).map_err(|_| DiscoveryError::InvalidMetadata)?;
        if document.schema != CACHE_SCHEMA {
            return Err(DiscoveryError::InvalidMetadata);
        }
        let cache = Self {
            resource: Some((
                CachedGithubPage::from_document(document.resource)?,
                document.final_url,
            )),
        };
        cache.observe(artifact, os, architecture)?;
        Ok(cache)
    }

    /// Network-free reselection under current local selectors and URL policy.
    pub fn observe(
        &self,
        artifact: &ArtifactRecord,
        os: &str,
        architecture: &str,
    ) -> Result<Option<ObservedRelease>, DiscoveryError> {
        let ArtifactSource::Zsync { url } = artifact.source() else {
            return Err(DiscoveryError::UnsupportedSource);
        };
        artifact
            .select_asset(os, architecture, &[])
            .map_err(|_| DiscoveryError::InvalidMetadata)?;
        let (page, final_url) = self
            .resource
            .as_ref()
            .ok_or(DiscoveryError::InvalidMetadata)?;
        if &page.url != url {
            return Err(DiscoveryError::InvalidMetadata);
        }
        let canonical = dev_tools_release::resolve_https_reference(url, url)
            .map_err(|_| DiscoveryError::InvalidMetadata)?;
        let host = dev_tools_release::canonical_https_host(url)
            .map_err(|_| DiscoveryError::InvalidMetadata)?;
        if dev_tools_release::canonical_https_host(final_url)
            .map_err(|_| DiscoveryError::InvalidMetadata)?
            != host
            || (final_url != &canonical
                && (page.validators.etag.is_some() || page.validators.last_modified.is_some()))
        {
            return Err(DiscoveryError::InvalidMetadata);
        }
        let assets = parse_control(&page.bytes, final_url)?;
        observe_filename_release(artifact, os, architecture, &assets)
    }
}

fn check_cached_with_fetch(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut ZsyncMetadataCache,
    mut fetch: impl FnMut(
        &str,
        &HttpsPolicy,
        &HttpsValidators,
    ) -> Result<LocatedConditionalHttpsResponse, DiscoveryError>,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    let ArtifactSource::Zsync { url } = artifact.source() else {
        return Err(DiscoveryError::UnsupportedSource);
    };
    artifact
        .select_asset(os, architecture, &[])
        .map_err(|_| DiscoveryError::InvalidMetadata)?;
    let host = dev_tools_release::canonical_https_host(url)
        .map_err(|_| DiscoveryError::InvalidMetadata)?;
    let policy = HttpsPolicy {
        allowed_hosts: BTreeSet::from([host]),
        max_redirects: 2,
        timeout: Duration::from_secs(60),
        user_agent: "dev-tools-update".into(),
    };
    let pages = cache
        .resource
        .as_ref()
        .map(|(page, _)| std::slice::from_ref(page))
        .unwrap_or(&[]);
    let mut final_url = None;
    let page = cached_page(pages, url, |validators| {
        let fetched = fetch(url, &policy, validators)?;
        if matches!(
            fetched.response,
            ConditionalHttpsResponse::NotModified { .. }
        ) && fetched.final_url
            != dev_tools_release::resolve_https_reference(url, url)
                .map_err(|_| DiscoveryError::InvalidMetadata)?
        {
            return Err(DiscoveryError::InvalidMetadata);
        }
        final_url = Some(fetched.final_url);
        Ok(fetched.response)
    })?;
    let next = ZsyncMetadataCache {
        resource: Some((page, final_url.ok_or(DiscoveryError::InvalidMetadata)?)),
    };
    let observed = next.observe(artifact, os, architecture)?;
    *cache = next;
    Ok(observed)
}

/// Fetch control metadata only; the full-file candidates are never retrieved.
pub fn check_zsync_release_cached(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut ZsyncMetadataCache,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    check_cached_with_fetch(
        artifact,
        os,
        architecture,
        cache,
        |url, policy, validators| {
            dev_tools_release::fetch_located_conditional_https(
                url,
                policy,
                PAGE_LIMIT as u64,
                validators,
            )
            .map_err(|_| DiscoveryError::Unavailable)
        },
    )
}

pub fn check_zsync_release(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    check_zsync_release_cached(
        artifact,
        os,
        architecture,
        &mut ZsyncMetadataCache::default(),
    )
}

fn parse_control(bytes: &[u8], final_url: &str) -> Result<Vec<AssetCandidate>, DiscoveryError> {
    if bytes.len() > PAGE_LIMIT {
        return Err(DiscoveryError::InventoryLimit);
    }
    let boundary = bytes
        .windows(2)
        .position(|value| value == b"\n\n")
        .map(|index| (index, 2))
        .into_iter()
        .chain(
            bytes
                .windows(4)
                .position(|value| value == b"\r\n\r\n")
                .map(|index| (index, 4)),
        )
        .min_by_key(|(index, _)| *index)
        .ok_or(DiscoveryError::InvalidMetadata)?;
    if boundary.0 > 65536 {
        return Err(DiscoveryError::InventoryLimit);
    }
    let header =
        std::str::from_utf8(&bytes[..boundary.0]).map_err(|_| DiscoveryError::InvalidMetadata)?;
    let mut fields = std::collections::BTreeMap::new();
    let mut urls = Vec::new();
    for (index, line) in header.lines().enumerate() {
        if index >= 128 || line.len() > 8192 {
            return Err(DiscoveryError::InventoryLimit);
        }
        let (name, value) = line
            .split_once(": ")
            .ok_or(DiscoveryError::InvalidMetadata)?;
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value.is_empty()
            || value.chars().any(char::is_control)
            || (index == 0 && name != "zsync")
            || name == "Z-Map2"
        {
            return Err(DiscoveryError::InvalidMetadata);
        }
        if name == "URL" {
            if urls.len() >= 64 {
                return Err(DiscoveryError::InventoryLimit);
            }
            urls.push(value);
        } else if fields.insert(name, value).is_some() {
            return Err(DiscoveryError::InvalidMetadata);
        }
    }
    if fields.get("zsync") == Some(&"0.0.4") || urls.is_empty() {
        return Err(DiscoveryError::InvalidMetadata);
    }
    let required = |name| {
        fields
            .get(name)
            .copied()
            .ok_or(DiscoveryError::InvalidMetadata)
    };
    let number = |value: &str| -> Result<u64, DiscoveryError> {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(DiscoveryError::InvalidMetadata);
        }
        value.parse().map_err(|_| DiscoveryError::InvalidMetadata)
    };
    let length = number(required("Length")?)?;
    let blocksize = number(required("Blocksize")?)?;
    if length == 0 || !blocksize.is_power_of_two() {
        return Err(DiscoveryError::InvalidMetadata);
    }
    let digest_bytes = match fields
        .get("Strong-Hash-Algorithm")
        .copied()
        .unwrap_or("MD4")
    {
        "MD4" | "MD5" => 16,
        "SHA-224" => 28,
        "SHA-256" => 32,
        _ => return Err(DiscoveryError::InvalidMetadata),
    };
    let record_bytes = if let Some(value) = fields.get("Hash-Lengths") {
        let parts = value
            .split(',')
            .map(number)
            .collect::<Result<Vec<_>, _>>()?;
        let [sequence, weak, strong] = parts.as_slice() else {
            return Err(DiscoveryError::InvalidMetadata);
        };
        if !(1..=2).contains(sequence)
            || !(1..=4).contains(weak)
            || !(1..=digest_bytes).contains(strong)
        {
            return Err(DiscoveryError::InvalidMetadata);
        }
        weak + strong
    } else {
        4 + digest_bytes
    };
    let expected = length
        .div_ceil(blocksize)
        .checked_mul(record_bytes)
        .ok_or(DiscoveryError::InventoryLimit)?;
    if expected != (bytes.len() - boundary.0 - boundary.1) as u64 {
        return Err(DiscoveryError::InvalidMetadata);
    }
    let name = required("Filename")?;
    urls.into_iter()
        .map(|url| {
            let url = dev_tools_release::resolve_https_reference(final_url, url)
                .map_err(|_| DiscoveryError::InvalidMetadata)?;
            AssetCandidate::new(name, url).map_err(|_| DiscoveryError::InvalidMetadata)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactCatalog;

    const CONFIG: &str = r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "app-image"
source = { type = "zsync", url = "https://example.org/latest.zsync" }
version = { type = "numeric" }
verification = { type = "check-only" }
selectors = [{ type = "regex", pattern = '^app-(?P<version>[0-9]+)\.AppImage$', os = "linux", architecture = "x86_64" }]
"#;

    #[test]
    fn zsync_cache_binds_final_location_and_reselects_original_bytes() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let artifact = catalog.get("example").unwrap();
        let mut cache = ZsyncMetadataCache::default();
        let observed = check_cached_with_fetch(
            artifact,
            "linux",
            "x86_64",
            &mut cache,
            |url, policy, validators| {
                assert_eq!(url, "https://example.org/latest.zsync");
                assert_eq!(policy.allowed_hosts, BTreeSet::from(["example.org".into()]));
                assert!(validators.etag.is_none());
                Ok(LocatedConditionalHttpsResponse {
                    final_url: "https://example.org/releases/feed.zsync".into(),
                    response: ConditionalHttpsResponse::Modified {
                        response: dev_tools_release::HttpsResponse {
                            bytes: control("app-42.AppImage"),
                            etag: None,
                        },
                        validators: HttpsValidators::default(),
                    },
                })
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(observed.version(), "42");
        assert_eq!(
            observed.asset().url(),
            "https://example.org/releases/app-42.AppImage"
        );
        let before = cache.to_bytes().unwrap();
        assert!(
            ZsyncMetadataCache::from_bytes(&before, artifact, "linux", "x86_64").unwrap() == cache
        );
        for final_url in [
            "https://evil.example/feed.zsync",
            "relative.zsync",
            "https://user@example.org/feed.zsync",
        ] {
            let mut document: serde_json::Value = serde_json::from_slice(&before).unwrap();
            document["final_url"] = final_url.into();
            assert!(ZsyncMetadataCache::from_bytes(
                &serde_json::to_vec(&document).unwrap(),
                artifact,
                "linux",
                "x86_64"
            )
            .is_err());
        }
        let mut document: serde_json::Value = serde_json::from_slice(&before).unwrap();
        document["resource"]["etag"] = "\"wrong-resource\"".into();
        assert!(ZsyncMetadataCache::from_bytes(
            &serde_json::to_vec(&document).unwrap(),
            artifact,
            "linux",
            "x86_64"
        )
        .is_err());
        assert!(cache
            .observe(artifact, "macos", "aarch64")
            .unwrap()
            .is_none());
        assert!(
            check_cached_with_fetch(artifact, "linux", "x86_64", &mut cache, |_, _, _| Ok(
                LocatedConditionalHttpsResponse {
                    final_url: "https://untrusted.example/feed.zsync".into(),
                    response: ConditionalHttpsResponse::Modified {
                        response: dev_tools_release::HttpsResponse {
                            bytes: control("app-42.AppImage"),
                            etag: None
                        },
                        validators: HttpsValidators::default()
                    },
                }
            ))
            .is_err()
        );
        assert_eq!(cache.to_bytes().unwrap(), before);
    }

    fn control(url: &str) -> Vec<u8> {
        let mut bytes = format!("zsync: 0.6.2\nFilename: app-42.AppImage\nMTime: irrelevant metadata\nBlocksize: 2048\nLength: 1\nHash-Lengths: 1,2,3\nURL: {url}\nSHA-1: {}\n\n", "0".repeat(40)).into_bytes();
        bytes.extend_from_slice(&[0, 255, 1, 2, 3]);
        bytes
    }

    #[test]
    fn zsync_conditional_cache_preserves_failed_refresh_and_rejects_mirrors_as_ambiguous() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let artifact = catalog.get("example").unwrap();
        let mut cache = ZsyncMetadataCache::default();
        check_cached_with_fetch(artifact, "linux", "x86_64", &mut cache, |url, _, _| {
            Ok(LocatedConditionalHttpsResponse {
                final_url: url.into(),
                response: ConditionalHttpsResponse::Modified {
                    response: dev_tools_release::HttpsResponse {
                        bytes: control("app-42.AppImage"),
                        etag: None,
                    },
                    validators: HttpsValidators {
                        etag: Some("\"control\"".into()),
                        last_modified: None,
                    },
                },
            })
        })
        .unwrap();
        check_cached_with_fetch(
            artifact,
            "linux",
            "x86_64",
            &mut cache,
            |url, _, validators| {
                assert_eq!(validators.etag.as_deref(), Some("\"control\""));
                Ok(LocatedConditionalHttpsResponse {
                    final_url: url.into(),
                    response: ConditionalHttpsResponse::NotModified {
                        validators: HttpsValidators::default(),
                    },
                })
            },
        )
        .unwrap();
        let before = cache.to_bytes().unwrap();
        for bytes in [
            b"not zsync".to_vec(),
            control("app-42.AppImage\nURL: https://mirror.example/app-42.AppImage"),
        ] {
            assert!(check_cached_with_fetch(
                artifact,
                "linux",
                "x86_64",
                &mut cache,
                |url, _, _| Ok(LocatedConditionalHttpsResponse {
                    final_url: url.into(),
                    response: ConditionalHttpsResponse::Modified {
                        response: dev_tools_release::HttpsResponse {
                            bytes: bytes.clone(),
                            etag: None
                        },
                        validators: HttpsValidators::default()
                    },
                })
            )
            .is_err());
            assert_eq!(cache.to_bytes().unwrap(), before);
        }
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
    }

    #[test]
    fn zsync_metadata_accepts_binary_checksums_and_resolves_relative_asset_urls() {
        let assets = parse_control(
            &control("../assets/app-42.AppImage"),
            "https://example.org/releases/feed.zsync",
        )
        .unwrap();
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].name(), "app-42.AppImage");
        assert_eq!(
            assets[0].url(),
            "https://example.org/assets/app-42.AppImage"
        );
        let assets = parse_control(
            &control("https://cdn.example.org/app-42.AppImage"),
            "https://example.org/feed.zsync",
        )
        .unwrap();
        assert_eq!(assets[0].url(), "https://cdn.example.org/app-42.AppImage");
    }

    #[test]
    fn zsync_metadata_bounds_headers_and_rejects_unsafe_references() {
        for url in [
            "http://example.org/app",
            "https://user@example.org/app",
            "file:///not-read",
            "app#fragment",
            "app with spaces",
        ] {
            assert!(parse_control(&control(url), "https://example.org/feed.zsync").is_err());
        }
        assert_eq!(
            parse_control(&vec![0; PAGE_LIMIT + 1], "https://example.org/feed.zsync").err(),
            Some(DiscoveryError::InventoryLimit)
        );
        for (from, to) in [
            ("Length: 1", "Length: 18446744073709551616"),
            ("Blocksize: 2048", "Blocksize: 0"),
            ("Hash-Lengths: 1,2,3", "Hash-Lengths: 1,2,99"),
            ("Hash-Lengths: 1,2,3", "Z-Map2: 1"),
            ("zsync: 0.6.2", "zsync: 0.0.4"),
        ] {
            let bytes = control("app.AppImage");
            let header = std::str::from_utf8(&bytes[..bytes.len() - 5])
                .unwrap()
                .replace(from, to);
            let mut invalid = header.into_bytes();
            invalid.extend_from_slice(&[0; 5]);
            assert!(parse_control(&invalid, "https://example.org/feed.zsync").is_err());
        }
        let bytes = control("app.AppImage");
        let header = std::str::from_utf8(&bytes[..bytes.len() - 5])
            .unwrap()
            .replace('\n', "\r\n");
        let mut crlf = header.into_bytes();
        crlf.extend_from_slice(&[0; 5]);
        assert_eq!(
            parse_control(&crlf, "https://example.org/feed.zsync")
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn zsync_metadata_rejects_truncated_control_data_and_conflicting_headers() {
        let bytes = control("https://example.org/app-42.AppImage");
        assert!(
            parse_control(&bytes[..bytes.len() - 1], "https://example.org/feed.zsync").is_err()
        );
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(parse_control(&extra, "https://example.org/feed.zsync").is_err());
        for from_to in [
            ("Filename: app-42.AppImage", "Filename: ../app-42.AppImage"),
            ("Blocksize: 2048", "Blocksize: 3"),
            ("Length: 1", "Length: 1\nLength: 2"),
            ("zsync: 0.6.2", "not-zsync: 0.6.2"),
        ] {
            let mut bytes = String::from_utf8(
                control("https://example.org/app-42.AppImage")
                    [..control("https://example.org/app-42.AppImage").len() - 5]
                    .to_vec(),
            )
            .unwrap()
            .replace(from_to.0, from_to.1)
            .into_bytes();
            bytes.extend_from_slice(&[0; 5]);
            assert!(parse_control(&bytes, "https://example.org/feed.zsync").is_err());
        }
    }
}
