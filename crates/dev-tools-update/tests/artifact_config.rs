use dev_tools_update::artifact::{
    ArtifactCatalog, ArtifactSelectionErrorKind, AssetCandidate, VerificationPolicy,
};

const CONFIG: &str = r#"
schema = "artifact-update-config-v1"

[[artifacts]]
id = "gearlever"
kind = "app-image"

[artifacts.source]
type = "github"
owner = "mijorus"
repository = "gearlever"

[artifacts.version]
type = "semver-tag"
prefix = "v"

[artifacts.verification]
type = "check-only"

[[artifacts.selectors]]
type = "exact"
pattern = "gearlever-linux-x86_64.AppImage"
os = "linux"
architecture = "x86_64"

[[artifacts.selectors]]
type = "regex"
pattern = "^gearlever-(?P<version>[0-9]+\\.[0-9]+\\.[0-9]+)-(?P<os>linux)-(?P<architecture>x86_64)\\.AppImage$"
os = "linux"
architecture = "x86_64"
"#;

#[test]
fn strict_catalog_parses_and_compiles_selectors_once() {
    let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
    let artifact = catalog.get("gearlever").unwrap();

    assert_eq!(artifact.source().provider_name(), "github");
    assert_eq!(artifact.verification(), VerificationPolicy::CheckOnly);
    assert_eq!(artifact.selector_count(), 2);
    assert!(ArtifactCatalog::parse(&CONFIG.replace(
        "kind = \"app-image\"",
        "kind = \"app-image\"\nunknown = true"
    ))
    .is_err());
}

#[test]
fn selection_uses_ordered_fallbacks_and_platform_constraints() {
    let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
    let artifact = catalog.get("gearlever").unwrap();
    let candidates = vec![
        AssetCandidate::new(
            "gearlever-1.2.3-linux-x86_64.AppImage",
            "https://github.com/mijorus/gearlever/releases/download/v1.2.3/gearlever-1.2.3-linux-x86_64.AppImage",
        )
        .unwrap(),
        AssetCandidate::new(
            "gearlever-1.2.3-linux-aarch64.AppImage",
            "https://github.com/mijorus/gearlever/releases/download/v1.2.3/gearlever-1.2.3-linux-aarch64.AppImage",
        )
        .unwrap(),
    ];

    let selected = artifact
        .select_asset("linux", "x86_64", &candidates)
        .unwrap()
        .unwrap();
    assert_eq!(selected.name(), "gearlever-1.2.3-linux-x86_64.AppImage");
    assert_eq!(selected.captures().get("version").unwrap(), "1.2.3");
}

#[test]
fn one_selector_matching_multiple_assets_is_terminal_ambiguity() {
    let config = CONFIG.replace(
        "type = \"exact\"\npattern = \"gearlever-linux-x86_64.AppImage\"",
        "type = \"glob\"\npattern = \"gearlever-*-linux-x86_64.AppImage\"",
    );
    let catalog = ArtifactCatalog::parse(&config).unwrap();
    let artifact = catalog.get("gearlever").unwrap();
    let candidates = [
        AssetCandidate::new(
            "gearlever-one-linux-x86_64.AppImage",
            "https://example.invalid/one",
        )
        .unwrap(),
        AssetCandidate::new(
            "gearlever-two-linux-x86_64.AppImage",
            "https://example.invalid/two",
        )
        .unwrap(),
    ];

    let error = artifact
        .select_asset("linux", "x86_64", &candidates)
        .unwrap_err();
    assert_eq!(error.kind(), ArtifactSelectionErrorKind::Ambiguous);
}

#[test]
fn regexes_are_anchored_bounded_and_reject_unsupported_syntax() {
    const CONFIGURED_REGEX: &str = r"^gearlever-(?P<version>[0-9]+\\.[0-9]+\\.[0-9]+)-(?P<os>linux)-(?P<architecture>x86_64)\\.AppImage$";
    for pattern in ["gearlever-.*", r"^(a)\\1$", "(?=gearlever)"] {
        let invalid = CONFIG.replace(CONFIGURED_REGEX, pattern);
        assert!(ArtifactCatalog::parse(&invalid).is_err(), "{pattern}");
    }
}

fn regex_catalog(pattern: &str) -> ArtifactCatalog {
    let prefix = CONFIG.split("[[artifacts.selectors]]").next().unwrap();
    ArtifactCatalog::parse(&format!(
        "{prefix}\n[[artifacts.selectors]]\ntype = \"regex\"\npattern = '{pattern}'\n"
    ))
    .unwrap()
}

#[test]
fn regex_alternation_cannot_select_partial_filenames() {
    let catalog = regex_catalog("^approved|other$");
    let artifact = catalog.get("gearlever").unwrap();
    for name in ["approved-unwanted", "unwanted-other"] {
        let candidate = AssetCandidate::new(name, "https://example.invalid/asset").unwrap();
        assert!(
            artifact
                .select_asset("linux", "x86_64", &[candidate])
                .unwrap()
                .is_none(),
            "partial match accepted: {name}"
        );
    }
    let candidate = AssetCandidate::new("approved", "https://example.invalid/asset").unwrap();
    assert!(artifact
        .select_asset("linux", "x86_64", &[candidate])
        .unwrap()
        .is_some());
}

#[test]
fn named_target_captures_must_match_requested_platform() {
    let catalog = regex_catalog("^tool-(?P<os>linux|windows)-(?P<architecture>x86_64|aarch64)$");
    let artifact = catalog.get("gearlever").unwrap();
    let candidates = [
        "tool-windows-x86_64",
        "tool-linux-aarch64",
        "tool-linux-x86_64",
    ]
    .map(|name| AssetCandidate::new(name, "https://example.invalid/asset").unwrap());
    let selected = artifact
        .select_asset("linux", "x86_64", &candidates)
        .unwrap()
        .unwrap();
    assert_eq!(selected.name(), "tool-linux-x86_64");
    assert!(artifact
        .select_asset("linux", "x86_64", &candidates[..2])
        .unwrap()
        .is_none());
}

#[test]
fn selection_rejects_oversized_candidate_inventory_before_matching() {
    let catalog = ArtifactCatalog::parse(CONFIG).unwrap();
    let candidate = AssetCandidate::new("unmatched", "https://example.invalid/asset").unwrap();
    assert!(catalog
        .get("gearlever")
        .unwrap()
        .select_asset("linux", "x86_64", &vec![candidate; 4097])
        .is_err());
}

#[test]
fn catalog_bounds_compiled_regex_expansion() {
    let prefix = CONFIG.split("[[artifacts.selectors]]").next().unwrap();
    let config =
        format!("{prefix}\n[[artifacts.selectors]]\ntype = \"regex\"\npattern = '^a{{10000}}$'\n");
    assert!(ArtifactCatalog::parse(&config).is_err());
}

#[test]
fn candidate_names_are_inert_single_filename_components() {
    for name in [".", "..", "tool\tname", "tool\u{1b}name"] {
        assert!(AssetCandidate::new(name, "https://example.invalid/asset").is_err());
    }
}

#[test]
fn candidate_urls_reject_credentials_fragments_and_missing_authority() {
    for url in [
        "https:///asset",
        "https://user:password@example.invalid/asset",
        "https://example.invalid/asset#fragment",
        "https://example.invalid\\evil/asset",
        "https://example.invalid:invalid/asset",
        "https://example.invalid:/asset",
    ] {
        assert!(
            AssetCandidate::new("tool", url).is_err(),
            "invalid URL admitted"
        );
    }
    for url in [
        "https://example.invalid/asset?download=1",
        "https://example.invalid:8443/asset",
        "https://[::1]/asset",
    ] {
        assert!(AssetCandidate::new("tool", url).is_ok());
    }
}

#[test]
fn catalog_has_an_aggregate_selector_budget() {
    let artifact = CONFIG
        .split("[[artifacts]]")
        .nth(1)
        .unwrap()
        .split("[[artifacts.selectors]]")
        .next()
        .unwrap();
    let mut config = String::from("schema = \"artifact-update-config-v1\"\n");
    for index in 0..257 {
        config.push_str("\n[[artifacts]]\n");
        config.push_str(&artifact.replace("id = \"gearlever\"", &format!("id = \"tool-{index}\"")));
        config.push_str("\n[[artifacts.selectors]]\ntype = \"exact\"\npattern = \"tool\"\n");
    }
    assert!(ArtifactCatalog::parse(&config).is_err());
}

#[test]
fn signed_manifest_policy_requires_a_local_public_trust_anchor() {
    let unpinned = CONFIG.replace(
        "type = \"check-only\"",
        "type = \"signed-manifest\"\nroot = \"https://example.invalid/root.json\"",
    );
    assert!(ArtifactCatalog::parse(&unpinned).is_err());
    let pinned = unpinned.replace("root = \"https://example.invalid/root.json\"",
        "root = \"https://example.invalid/root.json\"\ntrusted_root_public_key = \"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\"");
    assert!(ArtifactCatalog::parse(&pinned).is_ok());
    assert!(ArtifactCatalog::parse(&pinned.replace(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "invalid"
    ))
    .is_err());
}
