//! Literal local mappings over bounded, inert XML metadata.

pub const GENERIC_XML_CACHE_DOCUMENT_LIMIT: usize = GITHUB_CACHE_DOCUMENT_LIMIT;
const CACHE_SCHEMA: &str = "dev-tools-generic-xml-metadata-cache-v1";

/// Original locally mapped XML metadata bytes; these are not authenticated releases.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct GenericXmlMetadataCache {
    inner: GithubMetadataCache,
}

impl GenericXmlMetadataCache {
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
    cache: &mut GenericXmlMetadataCache,
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
pub fn check_generic_xml_release_cached(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut GenericXmlMetadataCache,
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

/// Observe explicit mapped XML metadata without artifact retrieval or installation authority.
pub fn check_generic_xml_release(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    check_generic_xml_release_cached(
        artifact,
        os,
        architecture,
        &mut GenericXmlMetadataCache::default(),
    )
}

fn check_with_fetch(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    mut fetch: impl FnMut(&str, &HttpsPolicy) -> Result<Vec<u8>, DiscoveryError>,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    let ArtifactSource::GenericXml { url, mapping } = artifact.source() else {
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
    for (version, assets) in parse_inventory(text, mapping)? {
        selection.consider(version, false, || Ok(assets))?;
    }
    Ok(selection.finish())
}

use super::xml::{XmlAttribute, XmlEvent, XmlReader};
use super::*;
use crate::artifact::{XmlName, XmlReleaseMapping, XmlValueMapping};

struct Node {
    name: XmlName,
    attributes: Vec<XmlAttribute>,
    text: String,
    children: Vec<Node>,
}

fn document(text: &str) -> Result<Node, DiscoveryError> {
    let mut reader = XmlReader::new(text)?;
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;
    let mut retained_bytes = 0usize;
    while let Some(event) = reader.next()? {
        match event {
            XmlEvent::Start {
                namespace,
                name,
                attributes,
            } => {
                retained_bytes += namespace.len()
                    + name.len()
                    + attributes
                        .iter()
                        .map(|attribute| {
                            attribute.namespace.len() + attribute.name.len() + attribute.value.len()
                        })
                        .sum::<usize>();
                if retained_bytes > PAGE_LIMIT * 4 {
                    return Err(DiscoveryError::InventoryLimit);
                }
                stack.push(Node {
                    name: XmlName { namespace, name },
                    attributes,
                    text: String::new(),
                    children: Vec::new(),
                });
            }
            XmlEvent::Text(value) => {
                retained_bytes += value.len();
                if retained_bytes > PAGE_LIMIT * 4 {
                    return Err(DiscoveryError::InventoryLimit);
                }
                stack
                    .last_mut()
                    .ok_or(DiscoveryError::InvalidMetadata)?
                    .text
                    .push_str(&value);
            }
            XmlEvent::End => {
                let node = stack.pop().ok_or(DiscoveryError::InvalidMetadata)?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else if root.replace(node).is_some() {
                    return Err(DiscoveryError::InvalidMetadata);
                }
            }
        }
    }
    root.ok_or(DiscoveryError::InvalidMetadata)
}

// Each path step partitions a bounded tree; there are no descendant searches or expressions.
fn nodes_at<'a>(node: &'a Node, path: &[XmlName]) -> Vec<&'a Node> {
    let mut nodes = vec![node];
    for name in path {
        nodes = nodes
            .into_iter()
            .flat_map(|node| &node.children)
            .filter(|node| &node.name == name)
            .collect();
    }
    nodes
}

fn attribute<'a>(node: &'a Node, name: &XmlName) -> Option<&'a str> {
    node.attributes
        .iter()
        .find(|value| value.namespace == name.namespace && value.name == name.name)
        .map(|value| value.value.as_str())
}

fn scalar<'a>(node: &'a Node, mapping: &XmlValueMapping) -> Result<&'a str, DiscoveryError> {
    let nodes = nodes_at(node, &mapping.path);
    let [node] = nodes.as_slice() else {
        return Err(DiscoveryError::InvalidMetadata);
    };
    let value = if let Some(name) = &mapping.attribute {
        attribute(node, name).ok_or(DiscoveryError::InvalidMetadata)?
    } else {
        if !node.children.is_empty() {
            return Err(DiscoveryError::InvalidMetadata);
        }
        &node.text
    };
    Ok(value.trim())
}

fn parse_inventory(
    text: &str,
    mapping: &XmlReleaseMapping,
) -> Result<Vec<(String, Vec<AssetCandidate>)>, DiscoveryError> {
    let root = document(text)?;
    let (name, path) = mapping
        .inventory
        .split_first()
        .ok_or(DiscoveryError::InvalidMetadata)?;
    if &root.name != name {
        return Err(DiscoveryError::InvalidMetadata);
    }
    let containers = nodes_at(&root, path);
    let [container] = containers.as_slice() else {
        return Err(DiscoveryError::InvalidMetadata);
    };
    let mut releases = Vec::new();
    for item in container
        .children
        .iter()
        .filter(|node| node.name == mapping.release)
    {
        if releases.len() >= 1000 {
            return Err(DiscoveryError::InventoryLimit);
        }
        let version = scalar(item, &mapping.version)?;
        if version.is_empty() || version.len() > 512 || version.chars().any(char::is_control) {
            return Err(DiscoveryError::InvalidMetadata);
        }
        let candidates = nodes_at(item, &mapping.assets);
        if candidates.len() > 4096 {
            return Err(DiscoveryError::InventoryLimit);
        }
        let mut assets = Vec::new();
        for candidate in candidates {
            if mapping.asset_filter.as_ref().is_some_and(|filter| {
                attribute(candidate, &filter.attribute) != Some(filter.equals.as_str())
            }) {
                continue;
            }
            let url = scalar(candidate, &mapping.url)?;
            let uri: http::Uri = url.parse().map_err(|_| DiscoveryError::InvalidMetadata)?;
            let name = if let Some(mapping) = &mapping.name {
                scalar(candidate, mapping)?
            } else {
                uri.path()
                    .rsplit('/')
                    .next()
                    .ok_or(DiscoveryError::InvalidMetadata)?
            };
            assets
                .push(AssetCandidate::new(name, url).map_err(|_| DiscoveryError::InvalidMetadata)?);
        }
        releases.push((version.to_owned(), assets));
    }
    Ok(releases)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactCatalog;

    fn mapping(atom: bool) -> XmlReleaseMapping {
        let source = if atom {
            r#"source = { type = "generic-xml", url = "https://example.org/feed", mapping = { inventory = [{ namespace = "http://www.w3.org/2005/Atom", name = "feed" }], release = { namespace = "http://www.w3.org/2005/Atom", name = "entry" }, version = { path = [{ namespace = "urn:release", name = "version" }] }, assets = [{ namespace = "http://www.w3.org/2005/Atom", name = "link" }], asset_filter = { attribute = { name = "rel" }, equals = "enclosure" }, url = { path = [], attribute = { name = "href" } } } }"#
        } else {
            r#"source = { type = "generic-xml", url = "https://example.org/feed", mapping = { inventory = [{ name = "rss" }, { name = "channel" }], release = { name = "item" }, version = { path = [{ name = "title" }] }, assets = [{ name = "enclosure" }], url = { path = [], attribute = { name = "url" } } } }"#
        };
        let config = format!(
            r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "zip"
{source}
version = {{ type = "numeric" }}
verification = {{ type = "check-only" }}
selectors = [{{ type = "exact", pattern = "app.zip", os = "linux", architecture = "x86_64" }}]
"#
        );
        let catalog = ArtifactCatalog::parse(&config).unwrap();
        let ArtifactSource::GenericXml { mapping, .. } = catalog.get("example").unwrap().source()
        else {
            panic!("XML source")
        };
        (**mapping).clone()
    }

    const RSS: &str = r#"<rss><channel><item><title>42</title><enclosure url="https://example.org/app.zip"/></item></channel></rss>"#;

    #[test]
    fn literal_xml_cache_reselects_local_rules_and_preserves_failed_refresh() {
        let config = r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "zip"
source = { type = "generic-xml", url = "https://example.org/feed", mapping = { inventory = [{ name = "rss" }, { name = "channel" }], release = { name = "item" }, version = { path = [{ name = "title" }] }, assets = [{ name = "enclosure" }], url = { path = [], attribute = { name = "url" } } } }
version = { type = "numeric" }
verification = { type = "check-only" }
selectors = [{ type = "exact", pattern = "app.zip", os = "linux", architecture = "x86_64" }]
"#;
        let catalog = ArtifactCatalog::parse(config).unwrap();
        let artifact = catalog.get("example").unwrap();
        let mut cache = GenericXmlMetadataCache::default();
        let observed =
            check_cached_with_fetch(artifact, "linux", "x86_64", &mut cache, |url, _, _| {
                assert_eq!(url, "https://example.org/feed");
                Ok(ConditionalHttpsResponse::Modified {
                    response: dev_tools_release::HttpsResponse {
                        bytes: RSS
                            .replace("</item>", "<build>43</build></item>")
                            .into_bytes(),
                        etag: None,
                    },
                    validators: HttpsValidators {
                        etag: Some("\"feed\"".into()),
                        last_modified: None,
                    },
                })
            })
            .unwrap()
            .unwrap();
        assert_eq!(observed.version(), "42");
        let bytes = cache.to_bytes().unwrap();
        assert!(
            GenericXmlMetadataCache::from_bytes(&bytes, artifact, "linux", "x86_64").unwrap()
                == cache
        );
        let remapped =
            ArtifactCatalog::parse(&config.replace("name = \"title\"", "name = \"build\""))
                .unwrap();
        assert_eq!(
            cache
                .observe(remapped.get("example").unwrap(), "linux", "x86_64")
                .unwrap()
                .unwrap()
                .version(),
            "43"
        );
        assert!(cache
            .observe(artifact, "macos", "aarch64")
            .unwrap()
            .is_none());
        assert!(check_cached_with_fetch(
            artifact,
            "linux",
            "x86_64",
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
        let before = cache.to_bytes().unwrap();
        assert!(
            check_cached_with_fetch(artifact, "linux", "x86_64", &mut cache, |_, _, _| Ok(
                ConditionalHttpsResponse::Modified {
                    response: dev_tools_release::HttpsResponse {
                        bytes: b"<bad/>".to_vec(),
                        etag: None
                    },
                    validators: HttpsValidators::default(),
                }
            ))
            .is_err()
        );
        assert_eq!(cache.to_bytes().unwrap(), before);
    }

    #[test]
    fn literal_xml_maps_rss_and_namespace_qualified_atom_assets() {
        let rss = parse_inventory(RSS, &mapping(false)).unwrap();
        assert_eq!(rss[0].0, "42");
        assert_eq!(rss[0].1.len(), 1);
        let atom = r#"<feed xmlns="http://www.w3.org/2005/Atom" xmlns:r="urn:release"><entry><r:version>43</r:version><link rel="alternate" href="ignored"/><link rel="enclosure" href="https://example.org/app.zip"/><content><![CDATA[<script>inert</script>]]></content></entry></feed>"#;
        let releases = parse_inventory(atom, &mapping(true)).unwrap();
        assert_eq!(releases[0].0, "43");
        assert_eq!(releases[0].1.len(), 1);
    }

    #[test]
    fn literal_xml_bounds_expanded_namespace_storage() {
        let text = format!(
            "<rss xmlns:x=\"{}\"><channel>{}</channel></rss>",
            "n".repeat(65536),
            "<x:ignored/>".repeat(200)
        );
        assert_eq!(
            parse_inventory(&text, &mapping(false)).err(),
            Some(DiscoveryError::InventoryLimit)
        );
    }

    #[test]
    fn literal_xml_bounds_and_untrusted_fields() {
        let mapping = mapping(false);
        for text in [
            RSS.replace(
                "<title>42</title>",
                "<title>42</title><description><![CDATA[<script>ignored</script>]]></description>",
            ),
            RSS.replace("<rss>", "<rss xml:base=\"file:///ignored/\">"),
        ] {
            assert_eq!(parse_inventory(&text, &mapping).unwrap()[0].0, "42");
        }
        for text in [
            format!("<!DOCTYPE rss [<!ENTITY x SYSTEM 'file:///not-read'>]>{RSS}"),
            RSS.replace(">42<", ">&unknown;<"),
            RSS.replace("<channel>", "<channel><?ignored code?>"),
            RSS.replace("https://example.org/app.zip", "app.zip"),
            RSS.replace("https://example.org/app.zip", "http://example.org/app.zip"),
            RSS.replace(
                "https://example.org/app.zip",
                "https://user@example.org/app.zip",
            ),
            RSS.replace("<title>", "<title xmlns=\"urn:spoof\">"),
        ] {
            assert!(parse_inventory(&text, &mapping).is_err());
        }
        for text in [
            " ".repeat(PAGE_LIMIT + 1),
            format!(
                "<rss><channel>{}</channel></rss>",
                "<item><title>42</title></item>".repeat(1001)
            ),
            format!(
                "<rss><channel><item><title>42</title>{}</item></channel></rss>",
                "<enclosure/>".repeat(4097)
            ),
            format!("{}{}", "<a>".repeat(65), "</a>".repeat(65)),
        ] {
            assert_eq!(
                parse_inventory(&text, &mapping).err(),
                Some(DiscoveryError::InventoryLimit)
            );
        }
    }

    #[test]
    fn literal_xml_can_map_flat_attribute_records_and_explicit_names() {
        let mapping: XmlReleaseMapping = toml::from_str(
            r#"
inventory = [{ name = "releases" }]
release = { name = "release" }
version = { path = [], attribute = { name = "version" } }
assets = []
url = { path = [], attribute = { name = "url" } }
name = { path = [], attribute = { name = "name" } }
"#,
        )
        .unwrap();
        let releases = parse_inventory(r#"<releases><release version="42" name="app.zip" url="https://example.org/download?id=42&amp;os=linux"/></releases>"#, &mapping).unwrap();
        assert_eq!(releases[0].0, "42");
        assert_eq!(releases[0].1.len(), 1);
    }

    #[test]
    fn literal_xml_rejects_ambiguous_or_nested_scalars() {
        for text in [
            RSS.replace("</title>", "</title><title>43</title>"),
            RSS.replace(">42<", "><b>42</b><"),
            RSS.replace("</rss>", "<channel/></rss>"),
        ] {
            assert!(parse_inventory(&text, &mapping(false)).is_err());
        }
    }
}
