//! Maven repository metadata, without POM resolution or build execution.
use super::xml::{XmlEvent, XmlReader};
use super::*;

pub const MAVEN_CACHE_DOCUMENT_LIMIT: usize = GITHUB_CACHE_DOCUMENT_LIMIT;
const CACHE_SCHEMA: &str = "dev-tools-maven-metadata-cache-v1";

/// Original Maven metadata resource bytes; these are not authenticated releases.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct MavenMetadataCache {
    inner: GithubMetadataCache,
}

impl MavenMetadataCache {
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

    /// Reselect current local coordinates and rules without refreshing or granting trust.
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
    cache: &mut MavenMetadataCache,
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
pub fn check_maven_release_cached(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut MavenMetadataCache,
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

/// Observe an explicitly configured Maven artifact without resolving or executing POMs.
/// Metadata establishes a version inventory, not existence of the derived classifier/extension.
pub fn check_maven_release(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    check_maven_release_cached(
        artifact,
        os,
        architecture,
        &mut MavenMetadataCache::default(),
    )
}

fn check_with_fetch(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    mut fetch: impl FnMut(&str, &HttpsPolicy) -> Result<Vec<u8>, DiscoveryError>,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    let ArtifactSource::Maven {
        repository,
        group,
        artifact: name,
        extension,
        classifier,
    } = artifact.source()
    else {
        return Err(DiscoveryError::UnsupportedSource);
    };
    let mut selection = ReleaseSelection::new(artifact, os, architecture)?;
    let host = dev_tools_release::canonical_https_host(repository)
        .map_err(|_| DiscoveryError::InvalidMetadata)?;
    let base = format!(
        "{}/{}/{name}",
        repository.trim_end_matches('/'),
        group.replace('.', "/")
    );
    let policy = HttpsPolicy {
        allowed_hosts: BTreeSet::from([host]),
        max_redirects: 2,
        timeout: Duration::from_secs(60),
        user_agent: "dev-tools-update".into(),
    };
    let bytes = fetch(&format!("{base}/maven-metadata.xml"), &policy)?;
    if bytes.len() > PAGE_LIMIT {
        return Err(DiscoveryError::InventoryLimit);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| DiscoveryError::InvalidMetadata)?;
    let metadata = parse_metadata(text)?;
    if metadata.group.as_deref() != Some(group) || metadata.artifact.as_deref() != Some(name) {
        return Err(DiscoveryError::InvalidMetadata);
    }
    for version in metadata.versions {
        if version.is_empty()
            || version.len() > 128
            || !version
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !version.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+')
            })
        {
            return Err(DiscoveryError::InvalidMetadata);
        }
        let excluded = version.to_ascii_uppercase().ends_with("-SNAPSHOT");
        let suffix = classifier
            .as_ref()
            .map(|value| format!("-{value}"))
            .unwrap_or_default();
        selection.consider(version.clone(), excluded, || {
            let filename = format!("{name}-{version}{suffix}.{extension}");
            let url = format!("{base}/{version}/{filename}");
            Ok(vec![AssetCandidate::new(&filename, &url)
                .map_err(|_| DiscoveryError::InvalidMetadata)?])
        })?;
    }
    Ok(selection.finish())
}

#[derive(Default)]
struct Metadata {
    group: Option<String>,
    artifact: Option<String>,
    versions: Vec<String>,
}

struct Frame {
    name: String,
    value: Option<String>,
}

fn parse_metadata(text: &str) -> Result<Metadata, DiscoveryError> {
    let mut reader = XmlReader::new(text)?;
    let mut stack: Vec<Frame> = Vec::new();
    let mut result = Metadata::default();
    let mut versioning_seen = false;
    let mut versions_seen = false;
    let mut root_namespace = String::new();
    while let Some(event) = reader.next()? {
        match event {
            XmlEvent::Start {
                namespace, name, ..
            } => {
                if stack.last().is_some_and(|frame| frame.value.is_some()) {
                    return Err(DiscoveryError::InvalidMetadata);
                }
                if stack.is_empty() {
                    if name != "metadata"
                        || !matches!(
                            namespace.as_str(),
                            "" | "http://maven.apache.org/METADATA/1.1.0"
                        )
                    {
                        return Err(DiscoveryError::InvalidMetadata);
                    }
                    root_namespace = namespace;
                } else if namespace != root_namespace {
                    return Err(DiscoveryError::InvalidMetadata);
                }
                let path: Vec<_> = stack.iter().map(|frame| frame.name.as_str()).collect();
                let scalar = match (path.as_slice(), name.as_str()) {
                    (["metadata"], "groupId" | "artifactId") => true,
                    (["metadata"], "versioning") => {
                        if versioning_seen {
                            return Err(DiscoveryError::InvalidMetadata);
                        }
                        versioning_seen = true;
                        false
                    }
                    (["metadata", "versioning"], "versions") => {
                        if versions_seen {
                            return Err(DiscoveryError::InvalidMetadata);
                        }
                        versions_seen = true;
                        false
                    }
                    (["metadata", "versioning", "versions"], "version") => true,
                    (["metadata", "versioning", "versions"], _) => {
                        return Err(DiscoveryError::InvalidMetadata)
                    }
                    _ => false,
                };
                stack.push(Frame {
                    name,
                    value: scalar.then(String::new),
                });
            }
            XmlEvent::End => {
                let frame = stack.pop().ok_or(DiscoveryError::InvalidMetadata)?;
                if let Some(value) = frame.value {
                    let value = value.trim().to_owned();
                    match frame.name.as_str() {
                        "groupId" => {
                            if result.group.replace(value).is_some() {
                                return Err(DiscoveryError::InvalidMetadata);
                            }
                        }
                        "artifactId" => {
                            if result.artifact.replace(value).is_some() {
                                return Err(DiscoveryError::InvalidMetadata);
                            }
                        }
                        "version" => {
                            if result.versions.len() >= 1000 {
                                return Err(DiscoveryError::InventoryLimit);
                            }
                            result.versions.push(value);
                        }
                        _ => return Err(DiscoveryError::InvalidMetadata),
                    }
                }
            }
            XmlEvent::Text(text) => {
                if let Some(Frame {
                    value: Some(value), ..
                }) = stack.last_mut()
                {
                    if value.len() + text.len() > 1024 {
                        return Err(DiscoveryError::InventoryLimit);
                    }
                    value.push_str(&text);
                }
            }
        }
    }
    if !versioning_seen || !versions_seen {
        return Err(DiscoveryError::InvalidMetadata);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactCatalog;

    const CONFIG: &str = r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "jar"
source = { type = "maven", repository = "https://repo.example/maven2/", group = "org.example", artifact = "tool", extension = "jar" }
version = { type = "semver-tag", prefix = "" }
verification = { type = "check-only" }
selectors = [{ type = "glob", pattern = "*.jar", os = "linux", architecture = "x86_64" }]
"#;

    fn metadata() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata><groupId>org.example</groupId><artifactId>tool</artifactId><versioning>
<latest>9.0.0-SNAPSHOT</latest><release>1.0.0</release>
<versions><version>2.0.0</version><version>1.0.0</version><version>9.0.0-SNAPSHOT</version></versions>
</versioning></metadata>"#
    }

    #[test]
    fn maven_cache_reselects_coordinates_and_preserves_failed_refreshes() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let record = catalog.get("example").unwrap();
        let mut cache = MavenMetadataCache::default();
        let selected =
            check_cached_with_fetch(record, "linux", "x86_64", &mut cache, |_, _, validators| {
                assert!(validators.etag.is_none());
                Ok(ConditionalHttpsResponse::Modified {
                    response: dev_tools_release::HttpsResponse {
                        bytes: metadata().as_bytes().to_vec(),
                        etag: None,
                    },
                    validators: HttpsValidators {
                        etag: Some("\"maven-fixture\"".into()),
                        last_modified: None,
                    },
                })
            })
            .unwrap()
            .unwrap();
        assert_eq!(selected.version(), "2.0.0");
        let before = cache.to_bytes().unwrap();
        assert!(
            MavenMetadataCache::from_bytes(&before, record, "linux", "x86_64").unwrap() == cache
        );
        let changed = ArtifactCatalog::parse(&CONFIG.replace(
            "extension = \"jar\"",
            "extension = \"jar\", classifier = \"sources\"",
        ))
        .unwrap();
        assert!(check_cached_with_fetch(
            changed.get("example").unwrap(),
            "linux",
            "x86_64",
            &mut cache,
            |_, _, validators| {
                assert_eq!(validators.etag.as_deref(), Some("\"maven-fixture\""));
                Ok(ConditionalHttpsResponse::NotModified {
                    validators: HttpsValidators::default(),
                })
            }
        )
        .unwrap()
        .unwrap()
        .asset()
        .url()
        .ends_with("tool-2.0.0-sources.jar"));
        assert_eq!(cache.to_bytes().unwrap(), before);
        for malformed in [false, true] {
            assert!(
                check_cached_with_fetch(record, "linux", "x86_64", &mut cache, |_, _, _| {
                    if !malformed {
                        return Err(DiscoveryError::Unavailable);
                    }
                    Ok(ConditionalHttpsResponse::Modified {
                        response: dev_tools_release::HttpsResponse {
                            bytes: b"<metadata/>".to_vec(),
                            etag: None,
                        },
                        validators: HttpsValidators::default(),
                    })
                })
                .is_err()
            );
            assert_eq!(cache.to_bytes().unwrap(), before);
        }
        let mut empty = MavenMetadataCache::default();
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
            ("maven-metadata-cache", "npm-metadata-cache"),
            ("/org/example/", "/org/other/"),
        ] {
            let changed = std::str::from_utf8(&before).unwrap().replace(from, to);
            assert!(
                MavenMetadataCache::from_bytes(changed.as_bytes(), record, "linux", "x86_64")
                    .is_err()
            );
        }
        let mut extra = cache.clone();
        extra.inner.pages.push(cache.inner.pages[0].clone());
        assert!(extra.observe(record, "linux", "x86_64").is_err());
        assert!(cache
            .observe(record, "windows", "x86_64")
            .unwrap()
            .is_none());
    }

    #[test]
    fn maven_rejects_hostile_or_ambiguous_xml_and_coordinate_mismatches() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let record = catalog.get("example").unwrap();
        let body = metadata();
        let root = body.split_once('\n').unwrap().1;
        for invalid in [
            String::new(), "not xml".into(), "<metadata/>".into(), format!("{root}{root}"),
            format!("<!DOCTYPE metadata>{root}"),
            format!("<!DOCTYPE metadata [<!ENTITY remote SYSTEM 'https://untrusted.example/entity'>]>{root}"),
            body.replace("org.example", "other.example"),
            body.replace("<artifactId>tool</artifactId>", "<artifactId>other</artifactId>"),
            body.replace("<groupId>org.example</groupId>", "<groupId>org.example</groupId><groupId>org.example</groupId>"),
            body.replace("</versioning>", "</versioning><versioning><versions/></versioning>"),
            body.replace("</versions>", "</versions><versions/>"),
            body.replace("</versions>", "</incorrect>"),
            body.replace("</metadata>", ""),
            body.replace("<version>2.0.0</version>", "<version><nested>2.0.0</nested></version>"),
            body.replace("<version>2.0.0</version>", "<version>&remote;</version>"),
            body.replace("<version>2.0.0</version>", "<other>2.0.0</other>"),
            body.replace("<metadata>", "<metadata xmlns='https://wrong.example'>"),
            body.replace("<groupId>", "<groupId xmlns='https://wrong.example'>"),
            body.replace("<metadata>", "<metadata x='1' x='2'>"),
            body.replace("<metadata>", "<metadata xmlns:p='urn:same' xmlns:q='urn:same' p:x='1' q:x='2'>"),
            body.replace("<metadata>", "<metadata unknown:x='1'>"),
            body.replace("<metadata>", "<metadata><1invalid/></metadata><metadata>"),
            body.replace("<metadata>", "<metadata bad='&#0;'>"),
            body.replace("<metadata>", "<metadata bad='a<b'>"),
            body.replace("<metadata>", "<metadata>bad]]>text"),
            body.replace("<metadata>", "<metadata><!--bad\u{0}comment-->"),
            body.replace("<metadata>", "<metadata><?instruction ignored?>"),
            body.replace("UTF-8", "ISO-8859-1"),
            body.replace("version=\"1.0\"", "version=\"1.0\" version=\"1.0\""),
            body.replace("UTF-8\"", "UTF-8\" encoding=\"UTF-8\""),
            body.replace("encoding=\"UTF-8\"", "standalone=\"yes\" encoding=\"UTF-8\""),
            format!("<!--comment-->{body}"),
            body.replace("2.0.0", "../../outside"),
            body.replace("2.0.0", "2.0.0%2foutside"),
            body.replace("2.0.0", "2.0.0?query"),
        ] {
            assert!(check_with_fetch(record, "linux", "x86_64", |_, _| Ok(invalid.as_bytes().to_vec())).is_err(), "hostile metadata must fail: {invalid}");
        }
        let duplicate = body.replace("<version>1.0.0</version>", "<version>2.0.0</version>");
        assert!(matches!(
            check_with_fetch(record, "linux", "x86_64", |_, _| Ok(duplicate
                .as_bytes()
                .to_vec())),
            Err(DiscoveryError::Ambiguous)
        ));
    }

    #[test]
    fn maven_bounds_bytes_depth_events_attributes_scalar_text_and_versions() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let record = catalog.get("example").unwrap();
        for body in [
            " ".repeat(PAGE_LIMIT + 1),
            metadata().replace(
                "<release>1.0.0</release>",
                &format!("{}{}", "<nested>".repeat(65), "</nested>".repeat(65)),
            ),
            metadata().replace("<release>1.0.0</release>", &"<extra/>".repeat(8200)),
            metadata().replace(
                "<metadata>",
                &format!(
                    "<metadata {}>",
                    (0..65)
                        .map(|n| format!("a{n}='x'"))
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
            ),
            metadata().replace(
                "<groupId>org.example</groupId>",
                &format!("<groupId>{}</groupId>", "a".repeat(1025)),
            ),
            metadata().replace(
                "<version>2.0.0</version><version>1.0.0</version><version>9.0.0-SNAPSHOT</version>",
                &(0..1001)
                    .map(|n| format!("<version>1.0.{n}</version>"))
                    .collect::<String>(),
            ),
        ] {
            assert!(
                matches!(
                    check_with_fetch(record, "linux", "x86_64", |_, _| Ok(body
                        .as_bytes()
                        .to_vec())),
                    Err(DiscoveryError::InventoryLimit)
                ),
                "inventory bounds must reject oversized input"
            );
        }
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
    }

    #[test]
    fn maven_accepts_namespaces_text_segments_classifier_and_local_filtering() {
        for body in [
            metadata().to_owned(),
            "<m:metadata xmlns:m='http://maven.apache.org/METADATA/1.1.0'><m:groupId>org.example</m:groupId><m:artifactId>tool</m:artifactId><m:versioning><m:versions><m:version>2.0.0</m:version></m:versions></m:versioning></m:metadata>".into(),
            metadata().replace(
                "<metadata>",
                "<metadata xmlns='http://maven.apache.org/METADATA/1.1.0'>",
            ),
            metadata().replace("org.example", "org.<!--comment-->example"),
            metadata().replace("org.example", "<![CDATA[org.example]]>"),
            metadata().replace("org.example", "org.&#101;xample"),
        ] {
            let config = CONFIG.replace(
                "extension = \"jar\"",
                "extension = \"jar\", classifier = \"sources\"",
            );
            let catalog = ArtifactCatalog::parse(&config).unwrap();
            let selected = check_with_fetch(
                catalog.get("example").unwrap(),
                "linux",
                "x86_64",
                |_, _| Ok(body.as_bytes().to_vec()),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                selected.asset().url(),
                "https://repo.example/maven2/org/example/tool/2.0.0/tool-2.0.0-sources.jar"
            );
        }
        for config in [
            CONFIG.to_owned(),
            CONFIG.replace(
                "type = \"semver-tag\", prefix = \"\"",
                "type = \"provider-order\"",
            ),
        ] {
            let catalog = ArtifactCatalog::parse(&config).unwrap();
            let body = metadata().replace("<version>2.0.0</version><version>1.0.0</version>", "");
            assert!(check_with_fetch(
                catalog.get("example").unwrap(),
                "linux",
                "x86_64",
                |_, _| Ok(body.as_bytes().to_vec())
            )
            .unwrap()
            .is_none());
        }
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        assert!(check_with_fetch(
            catalog.get("example").unwrap(),
            "windows",
            "x86_64",
            |_, _| Ok(metadata().as_bytes().to_vec())
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn maven_ranks_inventory_and_derives_only_local_coordinate_urls() {
        let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
        let selected = check_with_fetch(
            catalog.get("example").unwrap(),
            "linux",
            "x86_64",
            |url, policy| {
                assert_eq!(
                    url,
                    "https://repo.example/maven2/org/example/tool/maven-metadata.xml"
                );
                assert_eq!(
                    policy.allowed_hosts,
                    BTreeSet::from(["repo.example".into()])
                );
                assert_eq!(policy.timeout, Duration::from_secs(60));
                assert_eq!(policy.max_redirects, 2);
                Ok(metadata().as_bytes().to_vec())
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.version(), "2.0.0");
        assert_eq!(
            selected.asset().url(),
            "https://repo.example/maven2/org/example/tool/2.0.0/tool-2.0.0.jar"
        );
    }
}
