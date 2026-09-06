use dev_tools_update::artifact::{
    ArtifactCatalog, ArtifactSelectionErrorKind, AssetCandidate, InstallationPolicy,
    VerificationPolicy,
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
fn check_only_verification_does_not_ignore_unknown_authority_fields() {
    let config = CONFIG.replace(
        "type = \"check-only\"",
        "type = \"check-only\"\ntrusted_root_public_key = \"ignored\"",
    );
    assert!(ArtifactCatalog::parse(&config).is_err());
}

#[test]
fn calendar_tags_require_an_explicit_supported_format_and_bounded_literal_prefix() {
    let original = "type = \"semver-tag\"\nprefix = \"v\"";
    for format in ["yyyy-mm-dd", "yyyy.mm.dd", "yyyymmdd", "yyyy-mm", "yyyy.mm"] {
        let config = CONFIG.replace(
            original,
            &format!("type = 'calendar-tag'\nprefix = 'release/'\nformat = '{format}'"),
        );
        assert!(
            ArtifactCatalog::parse(&config).is_ok(),
            "explicit {format} calendar convention"
        );
    }
    assert!(ArtifactCatalog::parse(
        &CONFIG.replace(original, "type = 'calendar-tag'\nformat = 'yyyymmdd'")
    )
    .is_ok());
    for rule in [
        "type = 'calendar-tag'".to_owned(),
        "type = 'calendar-tag'\nformat = '%Y-%m-%d'".into(),
        "type = 'calendar-tag'\nformat = 'dd-mm-yyyy'".into(),
        "type = 'calendar-tag'\nformat = 'yyyy-mm-dd'\ntimezone = 'UTC'".into(),
        format!(
            "type = 'calendar-tag'\nformat = 'yyyy-mm-dd'\nprefix = '{}'",
            "a".repeat(65)
        ),
        "type = 'calendar-tag'\nformat = 'yyyy-mm-dd'\nprefix = \"release\\t\"".into(),
    ] {
        assert!(ArtifactCatalog::parse(&CONFIG.replace(original, &rule)).is_err());
    }
    // Existing calendar syntax remains exact and does not acquire ignored options.
    assert!(ArtifactCatalog::parse(&CONFIG.replace(original, "type = 'calendar'")).is_ok());
    for unit in ["calendar", "numeric", "provider-order", "opaque-check-only"] {
        assert!(ArtifactCatalog::parse(
            &CONFIG.replace(original, &format!("type = '{unit}'\nformat = 'yyyymmdd'"))
        )
        .is_err());
    }
}

#[test]
fn gitea_source_requires_literal_repository_and_https_api_authority() {
    let configured = CONFIG.replace(
        "type = \"github\"\nowner = \"mijorus\"\nrepository = \"gearlever\"",
        "type = \"gitea\"\napi = \"https://gitea.example/prefix/api/v1\"\nowner = \"mijorus\"\nrepository = \"gearlever\"",
    );
    let catalog = ArtifactCatalog::parse(&configured).expect("explicit Gitea source");
    assert_eq!(
        catalog.get("gearlever").unwrap().source().provider_name(),
        "gitea"
    );
    for invalid in [
        configured.replace("https://gitea.example", "http://gitea.example"),
        configured.replace("/api/v1", "/api/v2"),
        configured.replace("/prefix/", "/../"),
        configured.replace("owner = \"mijorus\"", "owner = \"../other\""),
        configured.replace(
            "repository = \"gearlever\"",
            "repository = \"encoded%2Frepo\"",
        ),
    ] {
        assert!(ArtifactCatalog::parse(&invalid).is_err());
    }
}

#[test]
fn html_inventory_requires_local_filename_version_selection() {
    let config = r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "other"
source = { type = "html", url = "https://example.org/releases/" }
version = { type = "numeric" }
verification = { type = "check-only" }
selectors = [{ type = "regex", pattern = '^app-(?P<version>[0-9]+)\.zip$' }]
"#;
    let catalog = ArtifactCatalog::parse(config).expect("bounded HTML inventory source");
    assert_eq!(
        catalog.get("example").unwrap().source().provider_name(),
        "html"
    );
    for invalid in [
        config.replace(
            "https://example.org/releases/",
            "http://example.org/releases/",
        ),
        config.replace("(?P<version>[0-9]+)", "[0-9]+"),
        config.replace("type = \"html\"", "type = \"html\", script = \"remote()\""),
    ] {
        assert!(ArtifactCatalog::parse(&invalid).is_err());
    }
}

#[test]
fn generic_xml_source_requires_bounded_literal_local_mappings() {
    let source = "type = \"github\"\nowner = \"mijorus\"\nrepository = \"gearlever\"";
    let configured = CONFIG.replace(source, r#"type = "generic-xml"
url = "https://updates.example/releases.xml"
mapping = { inventory = [{ name = "rss" }, { name = "channel" }], release = { name = "item" }, version = { path = [{ name = "title" }] }, assets = [{ name = "enclosure" }], url = { path = [], attribute = { name = "url" } } }"#);
    let catalog = ArtifactCatalog::parse(&configured).expect("explicit XML mapping must parse");
    assert_eq!(
        catalog.get("gearlever").unwrap().source().provider_name(),
        "generic-xml"
    );
    for invalid in [
        configured.replace("https://", "http://"),
        configured.replace("https://updates", "https://user@updates"),
        configured.replace("name = \"title\"", "name = \"*\""),
        configured.replace("name = \"title\"", "name = \"prefix:title\""),
        configured.replace("name = \"title\"", "name = \"../title\""),
        configured.replace("name = \"rss\"", "name = \"\""),
        configured.replace("name = \"rss\"", "name = \"rss\", namespace = \"a b\""),
        configured.replace(
            "inventory = [{ name = \"rss\" }, { name = \"channel\" }]",
            "inventory = []",
        ),
        configured.replace(
            "name = \"title\"",
            &format!("name = \"{}\"", "a".repeat(129)),
        ),
        configured.replace(
            "assets = [{ name = \"enclosure\" }]",
            &format!("assets = [{}]", vec!["{name=\"a\"}"; 17].join(",")),
        ),
        configured.replace("name = \"title\"", "name = \"title\", xpath = \"//title\""),
    ] {
        assert!(ArtifactCatalog::parse(&invalid).is_err(), "{invalid}");
    }
}

#[test]
fn sparkle_source_requires_explicit_https_feed_and_version_field() {
    let source = "type = \"github\"\nowner = \"mijorus\"\nrepository = \"gearlever\"";
    let configured = CONFIG.replace(source, "type = 'sparkle'\nurl = 'https://updates.example/appcast.xml'\nversion_field = 'bundle-version'");
    let catalog = ArtifactCatalog::parse(&configured).expect("explicit Sparkle source must parse");
    assert_eq!(
        catalog.get("gearlever").unwrap().source().provider_name(),
        "sparkle"
    );
    assert!(ArtifactCatalog::parse(&configured.replace("bundle-version", "short-version")).is_ok());
    for invalid in [
        configured.replace("https://", "http://"),
        configured.replace("https://updates", "https://user@updates"),
        configured.replace("appcast.xml", "appcast.xml#fragment"),
        configured.replace("bundle-version", "auto"),
        configured.replace("\nversion_field = 'bundle-version'", ""),
        configured.replace(
            "version_field = 'bundle-version'",
            "version_field = 'bundle-version'\ntoken = 'not-admitted'",
        ),
    ] {
        assert!(ArtifactCatalog::parse(&invalid).is_err());
    }
}

#[test]
fn maven_source_requires_explicit_literal_coordinates_and_repository() {
    let source = "type = \"github\"\nowner = \"mijorus\"\nrepository = \"gearlever\"";
    let configured = CONFIG.replace(source, "type = 'maven'\nrepository = 'https://repo.example/maven2'\ngroup = 'org.example'\nartifact = 'tool'\nextension = 'tar.gz'\nclassifier = 'bin'");
    let catalog =
        ArtifactCatalog::parse(&configured).expect("explicit Maven coordinates must parse");
    assert_eq!(
        catalog.get("gearlever").unwrap().source().provider_name(),
        "maven"
    );
    assert!(ArtifactCatalog::parse(&configured.replace("\nclassifier = 'bin'", "")).is_ok());
    for (from, to) in [
        ("https://", "http://"),
        ("https://repo", "https://user@repo"),
        ("/maven2'", "/maven2?token=value'"),
        ("/maven2'", "/../maven2'"),
        ("/maven2'", "/%2e%2e/maven2'"),
        ("org.example", "org..example"),
        ("org.example", ".org.example"),
        ("org.example", "org/example"),
        ("artifact = 'tool'", "artifact = '..'"),
        ("artifact = 'tool'", "artifact = 'tool/name'"),
        ("extension = 'tar.gz'", "extension = ''"),
        ("extension = 'tar.gz'", "extension = '../jar'"),
        ("extension = 'tar.gz'", "extension = 'tar..gz'"),
        ("classifier = 'bin'", "classifier = ''"),
        ("classifier = 'bin'", "classifier = '../bin'"),
        (
            "classifier = 'bin'",
            "classifier = 'bin'\ntoken = 'not-admitted'",
        ),
    ] {
        assert!(ArtifactCatalog::parse(&configured.replace(from, to)).is_err());
    }
}

#[test]
fn crates_io_source_accepts_only_literal_bounded_package_identity() {
    let source = "type = \"github\"\nowner = \"mijorus\"\nrepository = \"gearlever\"";
    let configured = CONFIG.replace(source, "type = 'crates-io'\npackage = 'Example_tool-2'");
    let catalog = ArtifactCatalog::parse(&configured).expect("crates.io source must parse");
    assert_eq!(
        catalog.get("gearlever").unwrap().source().provider_name(),
        "crates-io"
    );
    for package in ["a", "ab", "abc", "abcd", &"a".repeat(64)] {
        assert!(ArtifactCatalog::parse(&configured.replace("Example_tool-2", package)).is_ok());
    }
    for package in [
        "",
        "1tool",
        "_tool",
        "-tool",
        "tool.name",
        "../tool",
        "tool/name",
        "tool%2fname",
        "tool?query",
        "töol",
        &"a".repeat(65),
    ] {
        assert!(ArtifactCatalog::parse(&configured.replace("Example_tool-2", package)).is_err());
    }
    for extra in [
        "registry = 'https://other.example'",
        "token = 'not-admitted'",
        "command = 'ignored'",
    ] {
        assert!(ArtifactCatalog::parse(&configured.replace(
            "package = 'Example_tool-2'",
            &format!("package = 'Example_tool-2'\n{extra}")
        ))
        .is_err());
    }
}

#[test]
fn npm_source_requires_explicit_registry_package_and_distribution_tag() {
    let source = "type = \"github\"\nowner = \"mijorus\"\nrepository = \"gearlever\"";
    let configured = CONFIG.replace(source, "type = 'npm'\nregistry = 'https://registry.example/npm'\npackage = '@example/tool'\ntag = 'latest'");
    let catalog = ArtifactCatalog::parse(&configured).expect("explicit npm source must parse");
    assert_eq!(
        catalog.get("gearlever").unwrap().source().provider_name(),
        "npm"
    );
    for invalid in [
        configured.replace("https://", "http://"),
        configured.replace("https://registry", "https://user@registry"),
        configured.replace("/npm'", "/npm?token=value'"),
        configured.replace("/npm'", "/../npm'"),
        configured.replace("/npm'", "/%2e%2e/npm'"),
        configured.replace("@example/tool", "@example%2ftool"),
        configured.replace("@example/tool", "example/tool"),
        configured.replace("@example/tool", "@example/../tool"),
        configured.replace("@example/tool", "@/tool"),
        configured.replace("@example/tool", "@example/.tool"),
        configured.replace("@example/tool", "tool?query"),
        configured.replace("tag = 'latest'", "tag = '../latest'"),
        configured.replace("tag = 'latest'", "tag = ''"),
        configured.replace("tag = 'latest'", "tag = '1.2.3'"),
        configured.replace("tag = 'latest'", "tag = 'v1.2'"),
        configured.replace("tag = 'latest'", "tag = 'x'"),
        configured.replace("tag = 'latest'", "token = 'not-admitted'"),
        configured.replace("@example/tool", &"a".repeat(215)),
    ] {
        assert!(
            ArtifactCatalog::parse(&invalid).is_err(),
            "unsafe npm source must fail"
        );
    }
    for package in ["tool", "@example/tool", "tool.name-with_underscore"] {
        assert!(ArtifactCatalog::parse(&configured.replace("@example/tool", package)).is_ok());
    }
}

#[test]
fn gitlab_source_accepts_explicit_https_api_and_unencoded_project_path() {
    let source = "type = \"github\"\nowner = \"mijorus\"\nrepository = \"gearlever\"";
    let configured = CONFIG.replace(source, "type = \"gitlab\"\napi = \"https://gitlab.example/api/v4\"\nproject = \"group/subgroup/gearlever\"");
    let catalog = ArtifactCatalog::parse(&configured).expect("explicit GitLab source must parse");
    assert_eq!(
        catalog.get("gearlever").unwrap().source().provider_name(),
        "gitlab"
    );
    assert!(matches!(
        catalog.get("gearlever").unwrap().verification(),
        VerificationPolicy::CheckOnly
    ));
    for invalid in [
        "type = 'gitlab'\napi = 'http://gitlab.example/api/v4'\nproject = 'group/tool'",
        "type = 'gitlab'\napi = 'https://user@gitlab.example/api/v4'\nproject = 'group/tool'",
        "type = 'gitlab'\napi = 'https://gitlab.example/api/v4?token=value'\nproject = 'group/tool'",
        "type = 'gitlab'\napi = 'https://gitlab.example/not-an-api'\nproject = 'group/tool'",
        "type = 'gitlab'\napi = 'https://gitlab.example/api/v4'\nproject = 'group/../tool'",
        "type = 'gitlab'\napi = 'https://gitlab.example/api/v4'\nproject = 'group%2Ftool'",
        "type = 'gitlab'\napi = 'https://gitlab.example/api/v4'\nproject = '/group/tool'",
        "type = 'gitlab'\napi = 'https://gitlab.example/api/v4'\nproject = 'group//tool'",
        "type = 'gitlab'\napi = 'https://gitlab.example/api/v4'\nproject = 'group/tool'\ntoken = 'not-admitted'",
    ] {
        assert!(ArtifactCatalog::parse(&CONFIG.replace(source, invalid)).is_err());
    }
}

#[test]
fn forgejo_source_requires_explicit_api_and_literal_repository_components() {
    let source = "type = \"github\"\nowner = \"mijorus\"\nrepository = \"gearlever\"";
    let configured = CONFIG.replace(source, "type = 'forgejo'\napi = 'https://forge.example/prefix/api/v1'\nowner = 'example'\nrepository = 'tool'");
    let catalog = ArtifactCatalog::parse(&configured).expect("explicit Forgejo source must parse");
    assert_eq!(
        catalog.get("gearlever").unwrap().source().provider_name(),
        "forgejo"
    );
    for invalid in [
        configured.replace("https://", "http://"),
        configured.replace("https://forge", "https://user@forge"),
        configured.replace("/api/v1", "/api/v1?token=value"),
        configured.replace("/api/v1", "/api/v1/"),
        configured.replace("/prefix/", "/../"),
        configured.replace("/prefix/", "/%2e%2e/"),
        configured.replace("owner = 'example'", "owner = '..'"),
        configured.replace("repository = 'tool'", "repository = 'group/tool'"),
        configured.replace("repository = 'tool'", "repository = 'group%2Ftool'"),
        configured.replace(
            "repository = 'tool'",
            "repository = 'tool'\ntoken = 'not-admitted'",
        ),
    ] {
        assert!(ArtifactCatalog::parse(&invalid).is_err());
    }
}

#[test]
fn generic_json_source_accepts_only_bounded_local_json_pointer_mappings() {
    let source = "type = \"github\"\nowner = \"mijorus\"\nrepository = \"gearlever\"";
    let configured = CONFIG.replace(
        source,
        r#"type = "generic-json"
url = "https://updates.example/inventory.json?channel=stable"
[artifacts.source.mapping]
releases = "/releases"
tag = "/version"
assets = "/artifacts"
name = "/name"
url = "/url"
draft = "/draft"
prerelease = "/preview"
"#,
    );
    let catalog =
        ArtifactCatalog::parse(&configured).expect("explicit generic JSON mapping must parse");
    assert_eq!(
        catalog.get("gearlever").unwrap().source().provider_name(),
        "generic-json"
    );
    assert!(ArtifactCatalog::parse(
        &configured.replace("releases = \"/releases\"", "releases = \"\"")
    )
    .is_ok());
    assert!(ArtifactCatalog::parse(&configured.replace("/releases", "/a~1b/m~0n")).is_ok());
    for invalid in [
        configured.replace("https://", "http://"),
        configured.replace("https://updates", "https://user@updates"),
        configured.replace("channel=stable", "channel=stable#fragment"),
        configured.replace("/releases", "releases"),
        configured.replace("/releases", "#/releases"),
        configured.replace("/releases", "/bad~2escape"),
        configured.replace("/releases", "/bad~"),
        configured.replace("/releases", &format!("/{}", "x".repeat(512))),
        configured.replace("/releases", &"/x".repeat(17)),
        configured.replace(
            "name = \"/name\"",
            "name = \"/name\"\ncommand = \"not-admitted\"",
        ),
    ] {
        assert!(ArtifactCatalog::parse(&invalid).is_err());
    }
}

#[test]
fn explicit_local_binary_installation_is_optional_and_parseable() {
    let (data_root, bin_dir) = if cfg!(windows) {
        (
            r"C:\Users\fixture\AppData\Local\gearlever",
            r"C:\Users\fixture\bin",
        )
    } else {
        (
            "/home/fixture/.local/share/gearlever",
            "/home/fixture/.local/bin",
        )
    };
    let configured = CONFIG.replace("kind = \"app-image\"", &format!(
        "kind = \"app-image\"\ninstallation = {{ type = 'versioned-binary', data_root = '{data_root}', bin_dir = '{bin_dir}', artifact_name = 'gearlever', aliases = ['gearlever'] }}"
    ));
    assert!(
        ArtifactCatalog::parse(&configured).is_ok(),
        "locally declared binary layout must be accepted without accessing its paths"
    );
    assert!(
        ArtifactCatalog::parse(CONFIG).is_ok(),
        "existing check-only catalogs remain valid"
    );
    assert!(ArtifactCatalog::parse(CONFIG)
        .unwrap()
        .get("gearlever")
        .unwrap()
        .installation()
        .is_none());
    let catalog = ArtifactCatalog::parse(&configured).unwrap();
    let record = catalog.get("gearlever").unwrap();
    let Some(InstallationPolicy::VersionedBinary(layout)) = record.installation() else {
        panic!("expected declared binary layout");
    };
    assert_eq!(layout.data_root(), std::path::Path::new(data_root));
    assert_eq!(layout.bin_dir(), std::path::Path::new(bin_dir));
    assert_eq!(layout.artifact_name(), "gearlever");
    assert_eq!(layout.aliases(), ["gearlever"]);
    assert_eq!(
        record.verification(),
        VerificationPolicy::CheckOnly,
        "declaring paths cannot upgrade verification"
    );
    for (from, to) in [
        ("type = 'versioned-binary'", "type = 'shell-command'"),
        ("artifact_name = 'gearlever'", "artifact_name = '../escape'"),
        ("aliases = ['gearlever']", "aliases = []"),
        (
            "aliases = ['gearlever']",
            "aliases = ['gearlever', 'GEARLEVER']",
        ),
        ("aliases = ['gearlever']", "aliases = ['../escape']"),
        ("aliases = ['gearlever']", "aliases = ['con.exe']"),
        ("aliases = ['gearlever']", "aliases = ['tool.']"),
        (
            "aliases = ['gearlever']",
            "aliases = ['gearlever'], command = 'do-not-run'",
        ),
        ("kind = \"app-image\"", "kind = \"zip\""),
    ] {
        assert!(
            ArtifactCatalog::parse(&configured.replace(from, to)).is_err(),
            "invalid installation admitted: {to}"
        );
    }
    for path in [
        "relative",
        "/",
        "C:\\",
        "",
        "/home/fixture/../escape",
        "/home/fixture/./escape",
    ] {
        assert!(
            ArtifactCatalog::parse(&configured.replace(data_root, path)).is_err(),
            "invalid root admitted"
        );
    }
    assert!(
        ArtifactCatalog::parse(&configured.replace(data_root, bin_dir)).is_err(),
        "data and alias roots cannot overlap"
    );
    let nested = std::path::Path::new(bin_dir).join("nested");
    assert!(
        ArtifactCatalog::parse(&configured.replace(data_root, nested.to_str().unwrap())).is_err()
    );
    let oversized = (0..33)
        .map(|index| format!("'alias{index}'"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(ArtifactCatalog::parse(
        &configured.replace("['gearlever']", &format!("[{oversized}]"))
    )
    .is_err());
    #[cfg(windows)]
    for path in [
        r"C:relative",
        r"\\?\C:\fixture",
        r"\\server\share\fixture",
        r"C:\fixture\file:stream",
        r"C:\fixture\..\escape",
        r"C:\fixture\.\escape",
        r"C:\fixture\NUL",
        r"C:\fixture\trailing.",
        r"C:\fixture\trailing ",
        r"C:\fixture\COM¹",
    ] {
        assert!(
            ArtifactCatalog::parse(&configured.replace(data_root, path)).is_err(),
            "unsafe Windows root admitted"
        );
    }
    #[cfg(windows)]
    assert!(
        ArtifactCatalog::parse(&configured.replace(data_root, r"C:\Users\fixture\BIN\nested"))
            .is_err(),
        "case-insensitive overlapping roots must be rejected"
    );
}

#[test]
fn github_components_cannot_change_the_endpoint_path() {
    for component in [".", ".."] {
        assert!(ArtifactCatalog::parse(
            &CONFIG.replace("owner = \"mijorus\"", &format!("owner = \"{component}\""))
        )
        .is_err());
        assert!(ArtifactCatalog::parse(&CONFIG.replace(
            "repository = \"gearlever\"",
            &format!("repository = \"{component}\"")
        ))
        .is_err());
    }
}

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
fn zsync_source_requires_https_and_version_capture_for_ordered_rules() {
    let config = r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "app-image"
source = { type = "zsync", url = "https://example.org/latest.zsync" }
version = { type = "numeric" }
verification = { type = "check-only" }
selectors = [{ type = "regex", pattern = '^app-(?P<version>[0-9]+)\.AppImage$' }]
"#;
    let catalog = ArtifactCatalog::parse(config).unwrap();
    assert_eq!(
        catalog.get("example").unwrap().source().provider_name(),
        "zsync"
    );
    for invalid in [
        config.replace(
            "https://example.org/latest.zsync",
            "http://example.org/latest.zsync",
        ),
        config.replace(
            "https://example.org/latest.zsync",
            "https://user@example.org/latest.zsync",
        ),
        config.replace("(?P<version>[0-9]+)", "[0-9]+"),
    ] {
        assert!(ArtifactCatalog::parse(&invalid).is_err());
    }
    assert!(ArtifactCatalog::parse(
        &config
            .replace("type = \"numeric\"", "type = \"opaque-check-only\"")
            .replace("(?P<version>[0-9]+)", "[0-9]+")
    )
    .is_ok());
}

#[test]
fn url_source_admits_only_explicit_bounded_redirect_hosts_and_version_captures() {
    let config = r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "zip"
source = { type = "url", url = "https://example.org/latest", redirect_hosts = ["cdn.example.org"] }
version = { type = "numeric" }
verification = { type = "check-only" }
selectors = [{ type = "regex", pattern = '^app-(?P<version>[0-9]+)\.zip$' }]
"#;
    let catalog = ArtifactCatalog::parse(config).unwrap();
    assert_eq!(
        catalog.get("example").unwrap().source().provider_name(),
        "url"
    );
    assert!(ArtifactCatalog::parse(
        &config.replace(", redirect_hosts = [\"cdn.example.org\"]", "")
    )
    .is_ok());
    for host in [
        "https://cdn.example.org",
        "*.example.org",
        "user@cdn.example.org",
        "cdn.example.org:443",
        "cdn.example.org/path",
        "UPPER.example.org",
    ] {
        assert!(ArtifactCatalog::parse(&config.replace("cdn.example.org", host)).is_err());
    }
    for invalid in [
        config.replace("https://example.org/latest", "http://example.org/latest"),
        config.replace("(?P<version>[0-9]+)", "[0-9]+"),
        config.replace(
            "[\"cdn.example.org\"]",
            "[\"cdn.example.org\", \"cdn.example.org\"]",
        ),
    ] {
        assert!(ArtifactCatalog::parse(&invalid).is_err());
    }
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
    assert!(ArtifactCatalog::parse(&pinned).is_err());
    let pinned = pinned.replace(
        "type = \"signed-manifest\"",
        "type = \"signed-manifest\"\nproduct = \"gearlever\"\ntarget = \"linux-x86_64\"\nartifact_url = \"https://example.invalid/gearlever.AppImage\"",
    );
    assert!(ArtifactCatalog::parse(&pinned).is_ok());
    let catalog =
        ArtifactCatalog::parse(&pinned.replace("id = \"gearlever\"", "id = \"local-alias\""))
            .unwrap();
    let authority = catalog
        .get("local-alias")
        .unwrap()
        .release_authority()
        .unwrap();
    assert_eq!(authority.product, "gearlever");
    assert_eq!(authority.target, "linux-x86_64");
    assert_eq!(
        authority.accepted_manifest_schemas,
        ["dev-tools-product-v2"]
    );
    assert!(authority.require_source_commit);
    assert_eq!(authority.engine_protocol, 1);
    assert_eq!(
        authority.artifact_url,
        dev_tools_release::ArtifactUrlPolicy::Exact(
            "https://example.invalid/gearlever.AppImage".into()
        )
    );
    for (from, to) in [
        ("product = \"gearlever\"", "product = \"../other\""),
        ("target = \"linux-x86_64\"", "target = \"..\""),
        (
            "https://example.invalid/gearlever.AppImage",
            "http://example.invalid/gearlever.AppImage",
        ),
        (
            "type = \"semver-tag\"\nprefix = \"v\"",
            "type = \"numeric\"",
        ),
    ] {
        assert!(ArtifactCatalog::parse(&pinned.replace(from, to)).is_err());
    }
    for target in [
        "Linux-x86_64".to_owned(),
        "linux.x86_64".to_owned(),
        "a".repeat(65),
    ] {
        assert!(ArtifactCatalog::parse(&pinned.replace(
            "target = \"linux-x86_64\"",
            &format!("target = \"{target}\"")
        ))
        .is_err());
    }
    assert!(ArtifactCatalog::parse(&pinned.replace(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "invalid"
    ))
    .is_err());
}
