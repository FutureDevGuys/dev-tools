//! Inert Sparkle appcast metadata, not a Sparkle installation engine.
use super::xml::{XmlEvent, XmlReader};
use super::*;
use crate::artifact::SparkleVersionField;

const SPARKLE: &str = "http://www.andymatuschak.org/xml-namespaces/sparkle";
pub const SPARKLE_CACHE_DOCUMENT_LIMIT: usize = GITHUB_CACHE_DOCUMENT_LIMIT;
const CACHE_SCHEMA: &str = "dev-tools-sparkle-metadata-cache-v1";

/// Original Sparkle metadata resource bytes; these are not authenticated releases.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SparkleMetadataCache {
    inner: GithubMetadataCache,
}

impl SparkleMetadataCache {
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

    /// Reselect current local version and asset rules without refreshing or granting trust.
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
    cache: &mut SparkleMetadataCache,
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

/// Conditional metadata retrieval; failure leaves the previous cache unchanged.
pub fn check_sparkle_release_cached(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut SparkleMetadataCache,
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

/// Observe explicit appcast metadata without artifact retrieval or installation authority.
pub fn check_sparkle_release(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    check_sparkle_release_cached(
        artifact,
        os,
        architecture,
        &mut SparkleMetadataCache::default(),
    )
}

fn check_with_fetch(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    mut fetch: impl FnMut(&str, &HttpsPolicy) -> Result<Vec<u8>, DiscoveryError>,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    let ArtifactSource::Sparkle { url, version_field } = artifact.source() else {
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
    let text = std::str::from_utf8(&bytes).map_err(|_| DiscoveryError::InvalidMetadata)?;
    for (version, assets) in parse_appcast(text, *version_field)? {
        selection.consider(version, false, || Ok(assets))?;
    }
    Ok(selection.finish())
}

#[derive(Default)]
struct Item {
    modern: Option<String>,
    legacy: Option<String>,
    assets: Vec<AssetCandidate>,
    channel: Option<String>,
}

fn merge_version(slot: &mut Option<String>, value: &str) -> Result<(), DiscoveryError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(DiscoveryError::InvalidMetadata);
    }
    if slot.as_deref().is_some_and(|previous| previous != value) {
        return Err(DiscoveryError::InvalidMetadata);
    }
    *slot = Some(value.to_owned());
    Ok(())
}

fn parse_appcast(
    text: &str,
    field: SparkleVersionField,
) -> Result<Vec<(String, Vec<AssetCandidate>)>, DiscoveryError> {
    let version_name = match field {
        SparkleVersionField::BundleVersion => "version",
        SparkleVersionField::ShortVersion => "shortVersionString",
    };
    let mut reader = XmlReader::new(text)?;
    let mut path: Vec<(String, String)> = Vec::new();
    let mut channel_seen = false;
    let mut item = Item::default();
    let mut capture: Option<String> = None;
    let mut capturing_channel = false;
    let mut item_count = 0;
    let mut releases = Vec::new();
    while let Some(event) = reader.next()? {
        match event {
            XmlEvent::Start {
                namespace,
                name,
                attributes,
            } => {
                if capture.is_some() {
                    return Err(DiscoveryError::InvalidMetadata);
                }
                if path.is_empty()
                    && (!namespace.is_empty()
                        || name != "rss"
                        || !attributes.iter().any(|attribute| {
                            attribute.namespace.is_empty()
                                && attribute.name == "version"
                                && attribute.value == "2.0"
                        }))
                {
                    return Err(DiscoveryError::InvalidMetadata);
                }
                if namespace.is_empty() && name == "channel" && path.len() != 1 {
                    return Err(DiscoveryError::InvalidMetadata);
                }
                if path.len() == 1 && namespace.is_empty() && name == "channel" {
                    if channel_seen {
                        return Err(DiscoveryError::InvalidMetadata);
                    }
                    channel_seen = true;
                }
                let in_channel = path.len() >= 2 && path[1].0.is_empty() && path[1].1 == "channel";
                let in_item =
                    in_channel && path.len() >= 3 && path[2].0.is_empty() && path[2].1 == "item";
                if in_channel && path.len() == 2 && namespace.is_empty() && name == "item" {
                    if item_count >= 1000 {
                        return Err(DiscoveryError::InventoryLimit);
                    }
                    item_count += 1;
                    item = Item::default();
                }
                if in_item && path.len() == 3 {
                    if namespace == SPARKLE && name == version_name {
                        if item.modern.is_some() {
                            return Err(DiscoveryError::InvalidMetadata);
                        }
                        capture = Some(String::new());
                        capturing_channel = false;
                    }
                    if namespace == SPARKLE && name == "channel" {
                        if item.channel.is_some() {
                            return Err(DiscoveryError::InvalidMetadata);
                        }
                        capture = Some(String::new());
                        capturing_channel = true;
                    }
                    if namespace.is_empty() && name == "enclosure" {
                        if item.assets.len() >= 4096 {
                            return Err(DiscoveryError::InventoryLimit);
                        }
                        for attribute in &attributes {
                            if attribute.namespace == SPARKLE && attribute.name == version_name {
                                merge_version(&mut item.legacy, &attribute.value)?;
                            }
                        }
                        let url = attributes
                            .iter()
                            .find(|attribute| {
                                attribute.namespace.is_empty() && attribute.name == "url"
                            })
                            .ok_or(DiscoveryError::InvalidMetadata)?;
                        let uri: http::Uri = url
                            .value
                            .parse()
                            .map_err(|_| DiscoveryError::InvalidMetadata)?;
                        let name = uri
                            .path()
                            .rsplit('/')
                            .next()
                            .ok_or(DiscoveryError::InvalidMetadata)?;
                        item.assets.push(
                            AssetCandidate::new(name, &url.value)
                                .map_err(|_| DiscoveryError::InvalidMetadata)?,
                        );
                    }
                }
                path.push((namespace, name));
            }
            XmlEvent::Text(text) => {
                if let Some(capture) = &mut capture {
                    if capture.len() + text.len() > 1024 {
                        return Err(DiscoveryError::InventoryLimit);
                    }
                    capture.push_str(&text);
                }
            }
            XmlEvent::End => {
                if let Some(value) = capture.take() {
                    if capturing_channel {
                        item.channel = Some(value.trim().to_owned());
                    } else {
                        merge_version(&mut item.modern, &value)?;
                    }
                }
                if path.len() == 3
                    && path[1].0.is_empty()
                    && path[1].1 == "channel"
                    && path[2].0.is_empty()
                    && path[2].1 == "item"
                {
                    if let Some(legacy) = &item.legacy {
                        merge_version(&mut item.modern, legacy)?;
                    }
                    let version = item.modern.take().ok_or(DiscoveryError::InvalidMetadata)?;
                    if item.channel.as_deref().is_none_or(str::is_empty) {
                        releases.push((version, std::mem::take(&mut item.assets)));
                    }
                }
                path.pop().ok_or(DiscoveryError::InvalidMetadata)?;
            }
        }
    }
    if !channel_seen {
        return Err(DiscoveryError::InvalidMetadata);
    }
    Ok(releases)
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
source = { type = "sparkle", url = "https://example.org/appcast.xml", version_field = "bundle-version" }
version = { type = "numeric" }
verification = { type = "check-only" }
selectors = [{ type = "exact", pattern = "app.zip", os = "macos", architecture = "aarch64" }]
"#;
    const FEED: &str = r#"<rss version="2.0" xmlns:s="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><item><s:version>42</s:version><enclosure url="https://example.org/app.zip" /></item></channel></rss>"#;

    #[test]
    fn sparkle_rejects_ambiguous_candidates_and_duplicate_release_versions() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let artifact = catalog.get("example").unwrap();
        for feed in [
            FEED.replace("</item>", "<enclosure url=\"https://other.example/app.zip\"/></item>"),
            FEED.replace("</channel>", "<item><s:version>42</s:version><enclosure url=\"https://example.org/app.zip\"/></item></channel>"),
        ] {
            assert_eq!(check_with_fetch(artifact, "macos", "aarch64", |_, _| Ok(feed.as_bytes().to_vec())).err(), Some(DiscoveryError::Ambiguous));
        }
        let newer = FEED.replace("</channel>", "<item><s:version>43</s:version><enclosure url=\"https://example.org/app.zip\"/></item></channel>");
        assert_eq!(
            check_with_fetch(artifact, "macos", "aarch64", |_, _| Ok(newer
                .as_bytes()
                .to_vec()))
            .unwrap()
            .unwrap()
            .version(),
            "43"
        );
    }

    #[test]
    fn sparkle_bounds_and_hostile_xml_remain_inert() {
        let oversized_inventory = FEED.replace(
            "</channel>",
            &format!(
                "{}</channel>",
                "<item><s:version>43</s:version><s:channel>beta</s:channel></item>".repeat(1000)
            ),
        );
        let oversized_assets = FEED.replace(
            "</item>",
            &format!(
                "{}</item>",
                "<enclosure url=\"https://example.org/app.zip\"/>".repeat(4096)
            ),
        );
        let oversized_scalar = FEED.replace(">42<", &format!(">{}<", "4".repeat(1025)));
        for feed in [
            oversized_inventory,
            oversized_assets,
            oversized_scalar,
            " ".repeat(PAGE_LIMIT + 1),
        ] {
            assert_eq!(
                parse_appcast(&feed, SparkleVersionField::BundleVersion).err(),
                Some(DiscoveryError::InventoryLimit)
            );
        }
        for feed in [
            format!("<!DOCTYPE rss [<!ENTITY x SYSTEM 'file:///not-read'>]>{FEED}"),
            FEED.replace(">42<", ">&unknown;<"),
            FEED.replace("<channel>", "<channel><?do ignored?>"),
            FEED.replace("xmlns:s=", "xmlns:other="),
            FEED.replace(
                "http://www.andymatuschak.org/xml-namespaces/sparkle",
                "https://untrusted.example/spoof",
            ),
            FEED.replace(
                "https://example.org/app.zip",
                "https://user@example.org/app.zip",
            ),
            FEED.replace("https://example.org/app.zip", "app.zip"),
            FEED.replace("<channel>", "<channel><item><version>99</version></item>"),
        ] {
            assert!(parse_appcast(&feed, SparkleVersionField::BundleVersion).is_err());
        }
        let inert = FEED.replace("</item>", "<description><![CDATA[<!DOCTYPE html><script>ignored</script>]]></description><s:releaseNotesLink>file:///not-read</s:releaseNotesLink></item>");
        assert_eq!(
            parse_appcast(&inert, SparkleVersionField::BundleVersion)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn sparkle_cache_reselects_conditional_bytes_and_preserves_failed_refresh() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let artifact = catalog.get("example").unwrap();
        let mut cache = SparkleMetadataCache::default();
        let release = check_cached_with_fetch(
            artifact,
            "macos",
            "aarch64",
            &mut cache,
            |url, policy, validators| {
                assert_eq!(url, "https://example.org/appcast.xml");
                assert_eq!(policy.allowed_hosts, BTreeSet::from(["example.org".into()]));
                assert!(validators.etag.is_none());
                Ok(ConditionalHttpsResponse::Modified {
                    response: dev_tools_release::HttpsResponse {
                        bytes: FEED.as_bytes().to_vec(),
                        etag: None,
                    },
                    validators: HttpsValidators {
                        etag: Some("\"feed\"".into()),
                        last_modified: None,
                    },
                })
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(release.version(), "42");
        let before = cache.to_bytes().unwrap();
        assert!(
            SparkleMetadataCache::from_bytes(&before, artifact, "macos", "aarch64").unwrap()
                == cache
        );
        assert!(cache
            .observe(artifact, "linux", "x86_64")
            .unwrap()
            .is_none());
        assert!(check_cached_with_fetch(
            artifact,
            "macos",
            "aarch64",
            &mut cache,
            |_, _, validators| {
                assert_eq!(validators.etag.as_deref(), Some("\"feed\""));
                Ok(ConditionalHttpsResponse::NotModified {
                    validators: HttpsValidators::default(),
                })
            }
        )
        .unwrap()
        .is_some());
        let after_reuse = cache.to_bytes().unwrap();
        assert!(
            check_cached_with_fetch(artifact, "macos", "aarch64", &mut cache, |_, _, _| {
                Ok(ConditionalHttpsResponse::Modified {
                    response: dev_tools_release::HttpsResponse {
                        bytes: b"<bad/>".to_vec(),
                        etag: None,
                    },
                    validators: HttpsValidators::default(),
                })
            })
            .is_err()
        );
        assert_eq!(cache.to_bytes().unwrap(), after_reuse);
    }

    #[test]
    fn appcast_excludes_named_channels_and_rejects_invalid_structure() {
        let feed = r#"<rss version="2.0" xmlns:s="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><item><s:version>42</s:version><s:channel>beta</s:channel><enclosure url="https://example.org/app.zip" /></item></channel></rss>"#;
        assert!(parse_appcast(feed, SparkleVersionField::BundleVersion)
            .unwrap()
            .is_empty());
        for invalid in [
            feed.replace("version=\"2.0\"", "version=\"1.0\""),
            feed.replace("<s:channel>beta</s:channel>", "<s:version>42</s:version>"),
            feed.replace("https://example.org/app.zip", "http://example.org/app.zip"),
            feed.replace(
                "<s:version>42</s:version>",
                "<s:version><b>42</b></s:version>",
            ),
            feed.replace("<channel>", "<channel><channel/>"),
        ] {
            assert!(
                parse_appcast(&invalid, SparkleVersionField::BundleVersion).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn appcast_selects_explicit_modern_or_legacy_version_without_delta_assets() {
        let feed = r#"<rss version="2.0" xmlns:s="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><item>
            <s:version>42</s:version><s:shortVersionString>1.2.3</s:shortVersionString>
            <description><![CDATA[<html>inert</html>]]></description>
            <enclosure url="https://example.org/app.zip" s:version="42" s:shortVersionString="1.2.3" />
            <s:deltas><enclosure url="https://example.org/delta.zip" /></s:deltas>
        </item></channel></rss>"#;
        let bundle = parse_appcast(feed, SparkleVersionField::BundleVersion).unwrap();
        assert_eq!(bundle.len(), 1);
        assert_eq!(bundle[0].0, "42");
        assert_eq!(bundle[0].1.len(), 1);
        let short = parse_appcast(feed, SparkleVersionField::ShortVersion).unwrap();
        assert_eq!(short[0].0, "1.2.3");
        let legacy = feed.replace("<s:version>42</s:version>", "");
        assert_eq!(
            parse_appcast(&legacy, SparkleVersionField::BundleVersion).unwrap()[0].0,
            "42"
        );
        let conflicting = feed.replace("s:version=\"42\"", "s:version=\"43\"");
        assert!(parse_appcast(&conflicting, SparkleVersionField::BundleVersion).is_err());
    }
}
