//! Bounded static HTML link inventories, not browser execution or DOM interpretation.
use super::*;
use dev_tools_release::LocatedConditionalHttpsResponse;

pub const HTML_CACHE_DOCUMENT_LIMIT: usize = GITHUB_CACHE_DOCUMENT_LIMIT;
const CACHE_SCHEMA: &str = "dev-tools-html-metadata-cache-v1";

/// Original HTML bytes plus their actual resource location; never release authentication.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct HtmlMetadataCache {
    resource: Option<(CachedGithubPage, String)>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HtmlCacheDocument {
    schema: String,
    final_url: String,
    resource: CachePageDocument,
}

impl HtmlMetadataCache {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DiscoveryError> {
        let (page, final_url) = self
            .resource
            .as_ref()
            .ok_or(DiscoveryError::InvalidMetadata)?;
        let bytes = serde_json::to_vec(&HtmlCacheDocument {
            schema: CACHE_SCHEMA.into(),
            final_url: final_url.clone(),
            resource: page.document(),
        })
        .map_err(|_| DiscoveryError::InvalidMetadata)?;
        if bytes.len() > HTML_CACHE_DOCUMENT_LIMIT {
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
        if bytes.len() > HTML_CACHE_DOCUMENT_LIMIT {
            return Err(DiscoveryError::InventoryLimit);
        }
        let document: HtmlCacheDocument =
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
        let ArtifactSource::Html { url } = artifact.source() else {
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
        let assets = parse_links(&page.bytes, final_url)?;
        observe_links(artifact, os, architecture, &assets)
    }
}

fn check_cached_with_fetch(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut HtmlMetadataCache,
    mut fetch: impl FnMut(
        &str,
        &HttpsPolicy,
        &HttpsValidators,
    ) -> Result<LocatedConditionalHttpsResponse, DiscoveryError>,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    let ArtifactSource::Html { url } = artifact.source() else {
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
    let next = HtmlMetadataCache {
        resource: Some((page, final_url.ok_or(DiscoveryError::InvalidMetadata)?)),
    };
    let observed = next.observe(artifact, os, architecture)?;
    *cache = next;
    Ok(observed)
}

/// Fetch HTML metadata only; the full-file candidates are never retrieved.
pub fn check_html_release_cached(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    cache: &mut HtmlMetadataCache,
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

pub fn check_html_release(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    check_html_release_cached(
        artifact,
        os,
        architecture,
        &mut HtmlMetadataCache::default(),
    )
}

fn observe_links(
    artifact: &ArtifactRecord,
    os: &str,
    architecture: &str,
    assets: &[AssetCandidate],
) -> Result<Option<ObservedRelease>, DiscoveryError> {
    let mut selection = ReleaseSelection::new(artifact, os, architecture)?;
    let mut releases = 0;
    for asset in assets {
        let Some(observed) =
            observe_filename_release(artifact, os, architecture, std::slice::from_ref(asset))?
        else {
            continue;
        };
        releases += 1;
        if releases > 1000 {
            return Err(DiscoveryError::InventoryLimit);
        }
        selection.consider(observed.tag, false, || Ok(vec![asset.clone()]))?;
    }
    Ok(selection.finish())
}

fn parse_links(bytes: &[u8], final_url: &str) -> Result<Vec<AssetCandidate>, DiscoveryError> {
    if bytes.len() > PAGE_LIMIT {
        return Err(DiscoveryError::InventoryLimit);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| DiscoveryError::InvalidMetadata)?;
    let mut emitter = html5gum::DefaultEmitter::default();
    // Raw-text/RCDATA elements must not turn quoted markup into download links.
    emitter.naively_switch_states(true);
    let tokenizer = html5gum::Tokenizer::new_with_emitter(text, emitter);
    let mut links = Vec::new();
    let mut anchors = 0;
    for (index, token) in tokenizer.enumerate() {
        if index >= 16_384 {
            return Err(DiscoveryError::InventoryLimit);
        }
        let token = token.map_err(|_| DiscoveryError::InvalidMetadata)?;
        let tag = match token {
            html5gum::Token::Error(_) => return Err(DiscoveryError::InvalidMetadata),
            html5gum::Token::StartTag(tag) => tag,
            _ => continue,
        };
        if tag.name.len() > 128 || tag.attributes.len() > 64 {
            return Err(DiscoveryError::InventoryLimit);
        }
        // These contexts need a DOM/tree builder to determine the active HTML namespace
        // or document fragment. This narrow inventory parser does not guess that state.
        if matches!(
            tag.name.as_ref(),
            b"svg" | b"math" | b"template" | b"noscript"
        ) {
            return Err(DiscoveryError::InvalidMetadata);
        }
        if tag.name.as_ref() != b"a" {
            continue;
        }
        anchors += 1;
        if anchors > 4096 {
            return Err(DiscoveryError::InventoryLimit);
        }
        let Some(href) = tag.attributes.get(b"href".as_slice()) else {
            continue;
        };
        let href = std::str::from_utf8(href).map_err(|_| DiscoveryError::InvalidMetadata)?;
        if href.len() > 4096 {
            return Err(DiscoveryError::InventoryLimit);
        }
        if href.is_empty() || href.starts_with('#') {
            continue;
        }
        // Navigation and non-HTTPS schemes are not artifact candidates. No reference
        // is fetched here, including references naming another host.
        let Ok(url) = dev_tools_release::resolve_https_reference(final_url, href) else {
            continue;
        };
        let uri: http::Uri = url.parse().map_err(|_| DiscoveryError::InvalidMetadata)?;
        let name = uri.path().rsplit('/').next().unwrap_or("");
        if name.is_empty() {
            continue;
        }
        links.push(AssetCandidate::new(name, &url).map_err(|_| DiscoveryError::InvalidMetadata)?);
    }
    Ok(links)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "app"
kind = "other"
source = { type = "html", url = "https://updates.example/releases/" }
version = { type = "numeric" }
verification = { type = "check-only" }
selectors = [{ type = "regex", pattern = '^app-(?P<version>[0-9]+)\.zip$' }]
"#;

    fn catalog() -> crate::artifact::ArtifactCatalog {
        crate::artifact::ArtifactCatalog::parse(CONFIG).unwrap()
    }

    #[test]
    fn html_conditional_reuse_reselects_current_local_configuration() {
        let catalog = catalog();
        let artifact = catalog.get("app").unwrap();
        let mut cache = HtmlMetadataCache::default();
        check_cached_with_fetch(artifact, "linux", "x86_64", &mut cache, |url, _, _| {
            Ok(LocatedConditionalHttpsResponse {
                final_url: url.into(),
                response: ConditionalHttpsResponse::Modified {
                    response: dev_tools_release::HttpsResponse {
                        bytes: b"<a href='app-10.zip'>".to_vec(),
                        etag: None,
                    },
                    validators: HttpsValidators {
                        etag: Some("\"html\"".into()),
                        last_modified: None,
                    },
                },
            })
        })
        .unwrap();
        let before = cache.to_bytes().unwrap();
        let other =
            crate::artifact::ArtifactCatalog::parse(&CONFIG.replace("^app-", "^different-"))
                .unwrap();
        assert!(cache
            .observe(other.get("app").unwrap(), "linux", "x86_64")
            .unwrap()
            .is_none());
        let release = check_cached_with_fetch(
            artifact,
            "linux",
            "x86_64",
            &mut cache,
            |url, _, validators| {
                assert_eq!(validators.etag.as_deref(), Some("\"html\""));
                Ok(LocatedConditionalHttpsResponse {
                    final_url: url.into(),
                    response: ConditionalHttpsResponse::NotModified {
                        validators: validators.clone(),
                    },
                })
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(release.version(), "10");
        assert_eq!(cache.to_bytes().unwrap(), before);
    }

    #[test]
    fn html_inventory_bounds_tokens_attributes_and_matching_releases() {
        for text in [
            "<p></p>".repeat(8193),
            format!(
                "<p {}>",
                (0..65)
                    .map(|i| format!("a{i}='v'"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            format!("<a href='{}'>", "a".repeat(4097)),
        ] {
            assert!(matches!(
                parse_links(text.as_bytes(), "https://updates.example/"),
                Err(DiscoveryError::InventoryLimit)
            ));
        }
        let catalog = catalog();
        let links = (0..1001)
            .map(|i| {
                AssetCandidate::new(
                    format!("app-{i}.zip"),
                    format!("https://updates.example/app-{i}.zip"),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            observe_links(catalog.get("app").unwrap(), "linux", "x86_64", &links),
            Err(DiscoveryError::InventoryLimit)
        ));
    }

    #[test]
    fn html_cache_preserves_final_location_and_failed_refresh() {
        let catalog = catalog();
        let artifact = catalog.get("app").unwrap();
        let mut cache = HtmlMetadataCache::default();
        let observed = check_cached_with_fetch(
            artifact,
            "linux",
            "x86_64",
            &mut cache,
            |url, policy, validators| {
                assert_eq!(url, "https://updates.example/releases/");
                assert_eq!(
                    policy.allowed_hosts,
                    BTreeSet::from(["updates.example".into()])
                );
                assert_eq!(validators, &HttpsValidators::default());
                Ok(LocatedConditionalHttpsResponse {
                    final_url: "https://updates.example/archive/index.html".into(),
                    response: ConditionalHttpsResponse::Modified {
                        response: dev_tools_release::HttpsResponse {
                            bytes: b"<a href='app-10.zip'>".to_vec(),
                            etag: None,
                        },
                        validators: HttpsValidators::default(),
                    },
                })
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            observed.asset().url(),
            "https://updates.example/archive/app-10.zip"
        );
        let before = cache.to_bytes().unwrap();
        assert!(
            HtmlMetadataCache::from_bytes(&before, artifact, "linux", "x86_64").unwrap() == cache
        );
        assert!(
            check_cached_with_fetch(artifact, "linux", "x86_64", &mut cache, |url, _, _| Ok(
                LocatedConditionalHttpsResponse {
                    final_url: url.into(),
                    response: ConditionalHttpsResponse::Modified {
                        response: dev_tools_release::HttpsResponse {
                            bytes: b"<a href='broken".to_vec(),
                            etag: None
                        },
                        validators: HttpsValidators::default(),
                    },
                }
            ))
            .is_err()
        );
        assert_eq!(cache.to_bytes().unwrap(), before);
        let mut document: serde_json::Value = serde_json::from_slice(&before).unwrap();
        document["final_url"] = "https://untrusted.example/index.html".into();
        assert!(HtmlMetadataCache::from_bytes(
            &serde_json::to_vec(&document).unwrap(),
            artifact,
            "linux",
            "x86_64"
        )
        .is_err());
    }

    #[test]
    fn html_ranks_local_filename_versions_and_refuses_duplicate_candidates() {
        let catalog = catalog();
        let artifact = catalog.get("app").unwrap();
        let links = parse_links(
            b"<a href='app-2.zip'><a href='app-10.zip'><a href='other-999.zip'>",
            "https://updates.example/releases/",
        )
        .unwrap();
        let release = observe_links(artifact, "linux", "x86_64", &links)
            .unwrap()
            .unwrap();
        assert_eq!(release.version(), "10");
        assert!(matches!(
            observe_links(
                artifact,
                "linux",
                "x86_64",
                &[links[0].clone(), links[0].clone()]
            ),
            Err(DiscoveryError::Ambiguous)
        ));
        assert!(observe_links(artifact, "linux", "x86_64", &links[2..])
            .unwrap()
            .is_none());
    }

    #[test]
    fn html_links_decode_attributes_and_ignore_nonlink_content() {
        let bytes = br##"<!doctype html><html><head>
<base href="https://ignored.example/">
<script>const text = '<a href="app-999.zip">';</script>
<style>.x { content: '<a href="app-998.zip">'; }</style>
<title>&lt;a href="app-997.zip"&gt;</title>
</head><body><!-- <a href="app-996.zip"> -->
<A HREF='app-2.zip?a=1&amp;b=2'>ignored display name</A>
<a href=../app-3.zip>three</a>
<a href="#top">navigation</a><a href="mailto:test@example.org">mail</a>
<a href="javascript:run()">script</a><a href="subdirectory/">directory</a>
</body></html>"##;
        let links = parse_links(bytes, "https://updates.example/releases/index.html").unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].name(), "app-2.zip");
        assert_eq!(
            links[0].url(),
            "https://updates.example/releases/app-2.zip?a=1&b=2"
        );
        assert_eq!(links[1].url(), "https://updates.example/app-3.zip");
    }

    #[test]
    fn html_inventory_rejects_ambiguous_or_unsupported_syntax() {
        for bytes in [
            b"<a href='app-2.zip' HREF='app-3.zip'>".as_slice(),
            b"<a href='app-2.zip",
            b"<svg><a href='app-2.zip'></a></svg>",
            b"<template><a href='app-2.zip'></a></template>",
            b"<a href='app-2.zip'>&bogus;</a>",
            b"\xff",
        ] {
            assert!(parse_links(bytes, "https://updates.example/").is_err());
        }
        assert!(matches!(
            parse_links(&vec![b' '; PAGE_LIMIT + 1], "https://updates.example/"),
            Err(DiscoveryError::InventoryLimit)
        ));
        assert!(matches!(
            parse_links(
                "<a href='a.zip'>".repeat(4097).as_bytes(),
                "https://updates.example/"
            ),
            Err(DiscoveryError::InventoryLimit)
        ));
    }
}
