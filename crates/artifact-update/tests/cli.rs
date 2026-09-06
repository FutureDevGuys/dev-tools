use std::fs;
use std::process::Command;

const CONFIG: &str = r#"
schema = "artifact-update-config-v1"

[[artifacts]]
id = "example"
kind = "native-binary"
source = { type = "github", owner = "ExampleOrg", repository = "example" }
version = { type = "semver-tag", prefix = "v" }
verification = { type = "check-only" }
selectors = [{ type = "exact", pattern = "example-linux-x86_64", os = "linux", architecture = "x86_64" }]
"#;

#[cfg(target_os = "linux")]
const SIGNED_CONFIG: &str = r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "native-binary"
source = { type = "static-manifest", url = "https://example.invalid/stable.json" }
version = { type = "semver-tag" }
verification = { type = "signed-manifest", root = "https://example.invalid/root.json", trusted_root_public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", product = "example", target = "linux-x86_64", artifact_url = "https://example.invalid/tool" }
selectors = [{ type = "exact", pattern = "tool" }]
"#;

#[test]
fn configuration_editing_requires_explicit_complete_nonduplicated_authority() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("missing/config.toml");
    let source = root.path().join("proposal.toml");
    fs::write(&source, CONFIG).unwrap();
    for arguments in [
        vec!["apply"],
        vec!["apply", "--expect", "absent"],
        vec!["apply", "--from", source.to_str().unwrap()],
        vec![
            "apply",
            "--from",
            source.to_str().unwrap(),
            "--expect",
            "not-a-digest",
        ],
        vec![
            "apply",
            "--from",
            source.to_str().unwrap(),
            "--expect",
            "absent",
            "--expect",
            "absent",
        ],
        vec!["inspect", "--expect", "absent"],
        vec!["inspect", "--from", source.to_str().unwrap()],
        vec!["inspect", "--json"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
            .arg("config")
            .args(arguments)
            .args(["--config"])
            .arg(&target)
            .arg("--json")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(!target.parent().unwrap().exists());
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn configuration_mutation_is_blocked_without_a_native_custody_backend() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("missing/config.toml");
    let source = root.path().join("absent-proposal.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .args(["config", "apply", "--from"])
        .arg(&source)
        .args(["--expect", "absent", "--config"])
        .arg(&target)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["outcome"], "unsupported-platform");
    assert_eq!(result["changed"], false);
    assert_eq!(result["network_accessed"], false);
    assert!(!target.parent().unwrap().exists());
}

#[test]
fn rollback_and_recover_check_only_are_structured_network_free_and_reject_offline_flag() {
    for operation in ["rollback", "recover"] {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("config.toml");
        fs::write(&config, CONFIG).unwrap();
        let invoke = |extra: &[&str]| {
            Command::new(env!("CARGO_BIN_EXE_artifact-update"))
                .args([operation, "example", "--json", "--config"])
                .arg(&config)
                .args(extra)
                .env("XDG_STATE_HOME", temp.path().join("state"))
                .env("XDG_CACHE_HOME", temp.path().join("cache"))
                .env("HTTPS_PROXY", "http://127.0.0.1:1")
                .output()
                .unwrap()
        };
        let output = invoke(&[]);
        assert_eq!(output.status.code(), Some(3));
        let row: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(row["schema"], format!("artifact-update-{operation}-v1"));
        assert_eq!(row["outcome"], "check-only");
        assert_eq!(row["changed"], false);
        assert_eq!(row["network_accessed"], false);
        assert_eq!(invoke(&["--offline"]).status.code(), Some(2));
        assert!(!temp.path().join("state").exists());
        assert!(!temp.path().join("cache").exists());
    }
}

#[test]
fn install_keeps_check_only_sources_and_offline_requests_outside_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    fs::write(&config, CONFIG).unwrap();
    for offline in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_artifact-update"));
        command
            .args(["install", "example", "--json", "--config"])
            .arg(&config);
        if offline {
            command.arg("--offline");
        }
        let output = command
            .env("XDG_STATE_HOME", temp.path().join("state"))
            .env("XDG_CACHE_HOME", temp.path().join("cache"))
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(3),
            "install must report a structured blocked result"
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["schema"], "artifact-update-install-v1");
        assert_eq!(value["id"], "example");
        assert_eq!(value["changed"], false);
        assert_eq!(value["network_accessed"], false);
        assert!(!temp.path().join("state").exists());
        assert!(!temp.path().join("cache").exists());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn signed_install_cli_preflights_trust_external_aliases_and_native_target() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    let native_target = format!("linux-{}", std::env::consts::ARCH);
    let text = format!("{SIGNED_CONFIG}\ninstallation = {{ type = \"versioned-binary\", data_root = {}, bin_dir = {}, artifact_name = \"tool\", aliases = [\"example\"] }}\n",
        serde_json::to_string(&temp.path().join("data")).unwrap(), serde_json::to_string(&temp.path().join("bin")).unwrap()).replace("linux-x86_64", &native_target);
    fs::write(&config, &text).unwrap();
    let invoke = |offline: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_artifact-update"));
        command.args(["install", "example"]);
        if offline {
            command.arg("--offline");
        }
        let output = command
            .args(["--json", "--config"])
            .arg(&config)
            .env("XDG_STATE_HOME", temp.path().join("state"))
            .env("XDG_CACHE_HOME", temp.path().join("cache"))
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3));
        let row: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(row["network_accessed"], false);
        assert_eq!(row["changed"], false);
        assert!(!temp.path().join("data").exists());
        assert!(!temp.path().join("cache").exists());
        assert!(!temp.path().join("state").exists());
        row
    };
    assert_eq!(invoke(false)["outcome"], "trust-initialization-required");
    assert_eq!(invoke(true)["outcome"], "trust-initialization-required");
    fs::create_dir(temp.path().join("bin")).unwrap();
    fs::set_permissions(temp.path().join("bin"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(temp.path().join("bin/example"), b"external-owned").unwrap();
    assert_eq!(invoke(false)["outcome"], "external");
    assert_eq!(invoke(true)["outcome"], "external");
    assert_eq!(
        fs::read(temp.path().join("bin/example")).unwrap(),
        b"external-owned"
    );
    fs::write(&config, text.replace(&native_target, "windows-x86_64")).unwrap();
    assert_eq!(invoke(false)["outcome"], "non-native-target");
    assert_eq!(invoke(true)["outcome"], "non-native-target");
}

#[cfg(target_os = "linux")]
#[test]
fn trust_initialization_is_explicit_local_and_never_replaces_existing_state() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    let state = temp.path().join("state");
    fs::write(&config, SIGNED_CONFIG).unwrap();
    let invoke = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_artifact-update"))
            .args(args)
            .arg("--config")
            .arg(&config)
            .arg("--json")
            .env("XDG_STATE_HOME", &state)
            .env("XDG_CACHE_HOME", temp.path().join("cache"))
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .output()
            .unwrap()
    };
    let output = invoke(&["trust", "status", "example"]);
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["outcome"], "absent");
    assert_eq!(value["changed"], false);
    assert!(!state.exists());
    let output = invoke(&["trust", "initialize", "example"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["outcome"], "initialized");
    assert_eq!(value["network_accessed"], false);
    assert_eq!(value["installation_authorized"], false);
    let ledger = state.join("artifact-update/release-ledgers-v1/428d172207370ee0ef6d2f419c526d17b76f739b176d798c39dc9cead14280aa/ledger.json");
    let original = fs::read(&ledger).unwrap();
    let modified = fs::metadata(&ledger).unwrap().modified().unwrap();
    let output = invoke(&["trust", "status", "example"]);
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["outcome"], "present");
    assert_eq!(value["changed"], false);
    assert_eq!(fs::metadata(&ledger).unwrap().modified().unwrap(), modified);
    assert_eq!(fs::read_dir(ledger.parent().unwrap()).unwrap().count(), 1);
    let output = invoke(&[
        "check",
        "example",
        "--os",
        "windows",
        "--architecture",
        "aarch64",
    ]);
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["network_accessed"], false);
    assert_eq!(
        value["artifacts"][0]["diagnostic"],
        "signed checks use the configured target and do not accept target overrides"
    );
    assert_eq!(fs::read(&ledger).unwrap(), original);
    let output = invoke(&["trust", "initialize", "example"]);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(fs::read(&ledger).unwrap(), original);
    assert!(!temp.path().join("cache").exists());
    fs::remove_file(&ledger).unwrap();
    let output = invoke(&["status"]);
    assert_eq!(output.status.code(), Some(4));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["network_accessed"], false);
    assert_eq!(value["artifacts"][0]["outcome"], "authority-unavailable");
    assert_eq!(value["artifacts"][0]["installation_authorized"], false);
    let output = invoke(&["trust", "initialize", "example"]);
    assert_eq!(output.status.code(), Some(4));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        value["changed"].is_null(),
        "authority/publication failure cannot claim unchanged state"
    );
    assert!(!ledger.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn signed_check_requires_existing_ledger_before_network_or_cache_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    fs::write(&config, SIGNED_CONFIG).unwrap();
    let state = temp.path().join("state");
    let cache = temp.path().join("cache");
    let output = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .args(["check", "example", "--config"])
        .arg(config)
        .arg("--json")
        .env("XDG_STATE_HOME", &state)
        .env("XDG_CACHE_HOME", &cache)
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["network_accessed"], false);
    assert_eq!(
        value["artifacts"][0]["diagnostic"],
        "release trust requires explicit initialization"
    );
    assert!(!state.exists());
    assert!(!cache.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn relative_cache_authority_does_not_silently_fall_back_to_home() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    fs::write(&config, CONFIG).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .args(["status", "--config"])
        .arg(config)
        .arg("--json")
        .env("HOME", temp.path())
        .env("XDG_CACHE_HOME", "relative-cache")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!temp.path().join(".cache").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn gitlab_cached_status_is_read_only_and_cannot_authorize_installation() {
    assert_observed_provider_cache(
        "type = \"gitlab\", api = \"https://gitlab.example/api/v4\", project = \"group/example\"",
        br#"{"schema":"dev-tools-gitlab-metadata-cache-v1","pages":[{"url":"https://gitlab.example/api/v4/projects/group%2Fexample/releases?order_by=released_at&sort=desc&per_page=100&page=1","body_base64":"W10=","etag":null,"last_modified":null}]}"#,
    );
}

#[cfg(target_os = "linux")]
#[test]
fn forgejo_cached_status_is_read_only_and_cannot_authorize_installation() {
    assert_observed_provider_cache(
        "type = \"forgejo\", api = \"https://forge.example/api/v1\", owner = \"group\", repository = \"example\"",
        br#"{"schema":"dev-tools-forgejo-metadata-cache-v1","pages":[{"url":"https://forge.example/api/v1/repos/group/example/releases?limit=100&page=1","body_base64":"W10=","etag":null,"last_modified":null}]}"#,
    );
}

#[cfg(target_os = "linux")]
#[test]
fn gitea_cached_status_is_read_only_and_cannot_authorize_installation() {
    assert_observed_provider_cache(
        "type = \"gitea\", api = \"https://gitea.example/api/v1\", owner = \"group\", repository = \"example\"",
        br#"{"schema":"dev-tools-gitea-metadata-cache-v1","pages":[{"url":"https://gitea.example/api/v1/repos/group/example/releases?limit=100&page=1","body_base64":"W10=","etag":null,"last_modified":null}]}"#,
    );
}

#[cfg(target_os = "linux")]
#[test]
fn generic_json_cached_status_is_read_only_and_cannot_authorize_installation() {
    assert_observed_provider_cache(
        "type = \"generic-json\", url = \"https://updates.example/catalog.json\", mapping = { releases = \"\", tag = \"/version\", assets = \"/assets\", name = \"/name\", url = \"/url\" }",
        br#"{"schema":"dev-tools-generic-json-metadata-cache-v1","pages":[{"url":"https://updates.example/catalog.json","body_base64":"W10=","etag":null,"last_modified":null}]}"#,
    );
}

#[cfg(target_os = "linux")]
#[test]
fn npm_cached_status_is_read_only_and_cannot_authorize_installation() {
    assert_observed_provider_cache(
        "type = \"npm\", registry = \"https://registry.example\", package = \"example\", tag = \"latest\"",
        br#"{"schema":"dev-tools-npm-metadata-cache-v1","pages":[{"url":"https://registry.example/example/latest","body_base64":"eyJuYW1lIjoiZXhhbXBsZSIsInZlcnNpb24iOiIxLjIuMyIsImRpc3QiOnsidGFyYmFsbCI6Imh0dHBzOi8vZG93bmxvYWRzLmV4YW1wbGUvdG9vbC50Z3oifX0=","etag":null,"last_modified":null}]}"#,
    );
}

#[cfg(target_os = "linux")]
#[test]
fn crates_io_cached_status_is_read_only_and_cannot_authorize_installation() {
    assert_observed_provider_cache(
        "type = \"crates-io\", package = \"example\"",
        br#"{"schema":"dev-tools-crates-io-metadata-cache-v1","pages":[{"url":"https://index.crates.io/ex/am/example","body_base64":"eyJuYW1lIjoiZXhhbXBsZSIsInZlcnMiOiIxLjIuMyIsInlhbmtlZCI6ZmFsc2V9","etag":null,"last_modified":null}]}"#,
    );
}

#[cfg(target_os = "linux")]
#[test]
fn sparkle_cached_status_is_read_only_and_cannot_authorize_installation() {
    assert_observed_provider_cache(
        "type = \"sparkle\", url = \"https://example.org/appcast.xml\", version_field = \"bundle-version\"",
        br#"{"schema":"dev-tools-sparkle-metadata-cache-v1","pages":[{"url":"https://example.org/appcast.xml","body_base64":"PHJzcyB2ZXJzaW9uPSIyLjAiPjxjaGFubmVsLz48L3Jzcz4=","etag":null,"last_modified":null}]}"#,
    );
}

#[cfg(target_os = "linux")]
#[test]
fn generic_xml_cached_status_is_read_only_and_cannot_authorize_installation() {
    assert_observed_provider_cache(
        r#"type = "generic-xml", url = "https://example.org/feed", mapping = { inventory = [{ name = "rss" }, { name = "channel" }], release = { name = "item" }, version = { path = [{ name = "title" }] }, assets = [{ name = "enclosure" }], url = { path = [], attribute = { name = "url" } } }"#,
        br#"{"schema":"dev-tools-generic-xml-metadata-cache-v1","pages":[{"url":"https://example.org/feed","body_base64":"PHJzcz48Y2hhbm5lbC8+PC9yc3M+","etag":null,"last_modified":null}]}"#,
    );
}

#[cfg(target_os = "linux")]
#[test]
fn zsync_cached_status_is_read_only_and_cannot_authorize_installation() {
    let configured = CONFIG
        .replace(
            "type = \"github\", owner = \"ExampleOrg\", repository = \"example\"",
            "type = \"zsync\", url = \"https://example.org/feed.zsync\"",
        )
        .replace(
            "type = \"semver-tag\", prefix = \"v\"",
            "type = \"opaque-check-only\"",
        );
    assert_configured_observed_provider_cache(&configured, br#"{"schema":"dev-tools-zsync-metadata-cache-v1","final_url":"https://example.org/feed.zsync","resource":{"url":"https://example.org/feed.zsync","body_base64":"enN5bmM6IDAuNi4yCkZpbGVuYW1lOiBleGFtcGxlCkJsb2Nrc2l6ZTogMjA0OApMZW5ndGg6IDEKSGFzaC1MZW5ndGhzOiAxLDIsMwpVUkw6IGh0dHBzOi8vZXhhbXBsZS5vcmcvZXhhbXBsZQoKAAAAAAA=","etag":null,"last_modified":null}}"#);
}

#[cfg(target_os = "linux")]
#[test]
fn url_cached_status_is_read_only_and_cannot_authorize_installation() {
    let configured = CONFIG
        .replace(
            "type = \"github\", owner = \"ExampleOrg\", repository = \"example\"",
            "type = \"url\", url = \"https://example.org/latest\"",
        )
        .replace(
            "type = \"semver-tag\", prefix = \"v\"",
            "type = \"opaque-check-only\"",
        );
    assert_configured_observed_provider_cache(&configured, br#"{"schema":"dev-tools-url-metadata-cache-v1","url":"https://example.org/latest","final_url":"https://example.org/example-linux-x86_64"}"#);
}

#[cfg(target_os = "linux")]
#[test]
fn html_cached_status_is_read_only_and_cannot_authorize_installation() {
    let configured = CONFIG
        .replace(
            "type = \"github\", owner = \"ExampleOrg\", repository = \"example\"",
            "type = \"html\", url = \"https://example.org/releases/\"",
        )
        .replace(
            "type = \"semver-tag\", prefix = \"v\"",
            "type = \"opaque-check-only\"",
        );
    assert_configured_observed_provider_cache(&configured, br#"{"schema":"dev-tools-html-metadata-cache-v1","final_url":"https://example.org/releases/","resource":{"url":"https://example.org/releases/","body_base64":"PGEgaHJlZj0nZXhhbXBsZS1saW51eC14ODZfNjQnPg==","etag":null,"last_modified":null}}"#);
}

#[test]
#[cfg(target_os = "linux")]
fn maven_cached_status_is_read_only_and_cannot_authorize_installation() {
    assert_observed_provider_cache(
        "type = \"maven\", repository = \"https://repo.example/maven2\", group = \"org.example\", artifact = \"tool\", extension = \"jar\"",
        br#"{"schema":"dev-tools-maven-metadata-cache-v1","pages":[{"url":"https://repo.example/maven2/org/example/tool/maven-metadata.xml","body_base64":"PG1ldGFkYXRhPjxncm91cElkPm9yZy5leGFtcGxlPC9ncm91cElkPjxhcnRpZmFjdElkPnRvb2w8L2FydGlmYWN0SWQ+PHZlcnNpb25pbmc+PHZlcnNpb25zLz48L3ZlcnNpb25pbmc+PC9tZXRhZGF0YT4=","etag":null,"last_modified":null}]}"#,
    );
}

#[cfg(target_os = "linux")]
fn assert_observed_provider_cache(source: &str, metadata: &[u8]) {
    let configured = CONFIG.replace(
        "type = \"github\", owner = \"ExampleOrg\", repository = \"example\"",
        source,
    );
    assert_configured_observed_provider_cache(&configured, metadata);
}

#[cfg(target_os = "linux")]
fn assert_configured_observed_provider_cache(configured: &str, metadata: &[u8]) {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    fs::write(&config, configured).unwrap();
    let cache_home = temp.path().join("cache");
    let cache_root = cache_home.join("artifact-update/metadata-v1");
    fs::create_dir_all(&cache_root).unwrap();
    fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o700)).unwrap();
    let mut hash = Sha256::new();
    for part in [
        configured.as_bytes(),
        b"example",
        std::env::consts::OS.as_bytes(),
        std::env::consts::ARCH.as_bytes(),
    ] {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part);
    }
    let key = format!("{:x}", hash.finalize());
    let path = cache_root.join(format!("{key}.cache"));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut bytes = serde_json::to_vec(&serde_json::json!({"schema": "artifact-update-cache-entry-v1", "key": key, "checked_at": now})).unwrap();
    bytes.push(b'\n');
    bytes.extend_from_slice(metadata);
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    for operation in ["status", "install"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_artifact-update"));
        command.arg(operation);
        if operation == "install" {
            command.arg("example");
        }
        let output = command
            .args(["--json", "--config"])
            .arg(&config)
            .env("XDG_CACHE_HOME", &cache_home)
            .env("XDG_STATE_HOME", temp.path().join("state"))
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(if operation == "status" { 0 } else { 3 }),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["network_accessed"], false);
        if operation == "status" {
            assert_eq!(result["artifacts"][0]["cache_freshness"], "fresh");
            assert_eq!(result["artifacts"][0]["installation_authorized"], false);
        } else {
            assert_eq!(result["outcome"], "check-only");
        }
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::read_dir(&cache_root).unwrap().count(), 1);
    }
    let failed = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .args(["check", "example", "--json", "--config"])
        .arg(&config)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("https_proxy", "http://127.0.0.1:1")
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(1));
    let result: serde_json::Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(result["network_accessed"], true);
    assert_eq!(result["artifacts"][0]["outcome"], "unknown");
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[cfg(target_os = "linux")]
#[test]
fn unsafe_cache_rejects_before_entering_the_network_boundary() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    fs::write(&config, CONFIG).unwrap();
    let cache_home = temp.path().join("cache");
    let cache_root = cache_home.join("artifact-update/metadata-v1");
    fs::create_dir_all(&cache_root).unwrap();
    fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .args(["check", "example", "--config"])
        .arg(config)
        .arg("--json")
        .env("XDG_CACHE_HOME", cache_home)
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["network_accessed"], false);
    assert_eq!(value["artifacts"][0]["outcome"], "unknown");
    assert_eq!(value["artifacts"][0]["installation_authorized"], false);
    assert_eq!(fs::read_dir(cache_root).unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn cached_status_is_local_read_only_and_never_claims_installation_authority() {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    fs::write(&config, CONFIG).unwrap();
    let cache_home = temp.path().join("cache");
    let cache_root = cache_home.join("artifact-update/metadata-v1");
    fs::create_dir_all(&cache_root).unwrap();
    fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o700)).unwrap();
    let mut hash = Sha256::new();
    for part in [
        CONFIG.as_bytes(),
        b"example",
        std::env::consts::OS.as_bytes(),
        std::env::consts::ARCH.as_bytes(),
    ] {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part);
    }
    let key = format!("{:x}", hash.finalize());
    let path = cache_root.join(format!("{key}.cache"));
    let metadata = br#"{"schema":"dev-tools-github-metadata-cache-v1","pages":[{"url":"https://api.github.com/repos/ExampleOrg/example/releases?per_page=100&page=1","body_base64":"W10=","etag":null,"last_modified":null}]}"#;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (checked_at, expected) in [
        (now, "fresh"),
        (now - 90000, "stale"),
        (now + 90000, "stale"),
    ] {
        let mut bytes = serde_json::to_vec(&serde_json::json!({"schema": "artifact-update-cache-entry-v1", "key": key, "checked_at": checked_at})).unwrap();
        bytes.push(b'\n');
        bytes.extend_from_slice(metadata);
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
            .args(["status", "--config"])
            .arg(&config)
            .arg("--json")
            .env("XDG_CACHE_HOME", &cache_home)
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(value["network_accessed"], false);
        assert_eq!(value["artifacts"][0]["cache_freshness"], expected);
        assert_eq!(value["artifacts"][0]["outcome"], "unknown");
        assert_eq!(value["artifacts"][0]["installation_authorized"], false);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
        assert_eq!(
            fs::read_dir(&cache_root).unwrap().count(),
            1,
            "status must not create a lock"
        );
    }
    fs::write(&config, format!("{CONFIG}\n# changed desired source\n")).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .args(["status", "--config"])
        .arg(config)
        .arg("--json")
        .env("XDG_CACHE_HOME", cache_home)
        .output()
        .unwrap();
    assert!(result.status.success());
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["artifacts"][0]["cache_freshness"], "absent");
}

#[test]
fn explicit_check_of_an_empty_catalog_is_a_structured_noop() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config.toml");
    fs::write(
        &config,
        "schema = 'artifact-update-config-v1'\nartifacts = []\n",
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .args(["check", "--all", "--config"])
        .arg(&config)
        .arg("--json")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["schema"], "artifact-update-check-v1");
    assert_eq!(result["network_accessed"], false);
    assert_eq!(result["artifacts"], serde_json::json!([]));
}

#[test]
fn check_rejects_an_unknown_selected_id_without_network() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config.toml");
    fs::write(&config, CONFIG).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .args(["check", "absent", "--config"])
        .arg(&config)
        .arg("--json")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&result.stderr).trim(),
        "artifact-update: selected artifact is not configured"
    );
    assert!(result.stdout.is_empty());
}

#[test]
fn list_and_status_are_standalone_structured_and_local_only() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config.toml");
    fs::write(&config, CONFIG).unwrap();

    let listed = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .args(["list", "--config", config.to_str().unwrap(), "--json"])
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["schema"], "artifact-update-list-v1");
    assert_eq!(listed["artifacts"][0]["id"], "example");

    let status = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .args(["status", "--config", config.to_str().unwrap(), "--json"])
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["schema"], "artifact-update-status-v1");
    assert_eq!(status["network_accessed"], false);
    assert_eq!(status["artifacts"][0]["outcome"], "unknown");
}

#[cfg(target_os = "linux")]
#[test]
fn configured_external_alias_is_observed_without_adoption_or_state_creation() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    let bin = temp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    let alias = bin.join("example");
    fs::write(&alias, b"externally managed fixture").unwrap();
    let config = temp.path().join("config.toml");
    fs::write(&config, CONFIG.replace("kind = \"native-binary\"", &format!(
        "kind = \"native-binary\"\ninstallation = {{ type = 'versioned-binary', data_root = '{}', bin_dir = '{}', artifact_name = 'example', aliases = ['example'] }}", data.display(), bin.display()))).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .args(["status", "--config"])
        .arg(config)
        .arg("--json")
        .env("XDG_CACHE_HOME", temp.path().join("cache"))
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["network_accessed"], false);
    assert_eq!(value["artifacts"][0]["installation_state"], "external");
    assert_eq!(value["artifacts"][0]["outcome"], "unknown");
    assert_eq!(value["artifacts"][0]["installation_authorized"], false);
    assert_eq!(fs::read(alias).unwrap(), b"externally managed fixture");
    assert!(!data.exists());
    assert!(!temp.path().join("cache").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn status_reports_verified_receipt_content_without_claiming_release_authentication() {
    use dev_tools_installation::{
        apply_versioned_installation, ArtifactIdentity, VersionedInstallRequest, VersionedLayout,
    };
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    let bin = temp.path().join("bin");
    let source = temp.path().join("source");
    fs::write(&source, b"inert test artifact; never executed").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    let layout = VersionedLayout {
        product: "example".into(),
        data_root: data.clone(),
        bin_dir: bin.clone(),
        artifact_name: "example".into(),
        owner_uid: temp.path().metadata().unwrap().uid(),
        directory_mode: 0o700,
        bin_directory_mode: Some(0o755),
    };
    apply_versioned_installation(
        &VersionedInstallRequest {
            layout,
            version: "1.2.3".into(),
            identity: ArtifactIdentity::from_file(&source, 4096).unwrap(),
            source,
            aliases: vec!["example".into()],
        },
        |_| Ok(()),
    )
    .unwrap();
    let config = temp.path().join("config.toml");
    fs::write(&config, CONFIG.replace("kind = \"native-binary\"", &format!(
        "kind = \"native-binary\"\ninstallation = {{ type = 'versioned-binary', data_root = '{}', bin_dir = '{}', artifact_name = 'example', aliases = ['example'] }}", data.display(), bin.display()))).unwrap();
    let receipt = data.join("installation-receipt-v1.json");
    let original = fs::read(&receipt).unwrap();
    let modified = fs::metadata(&receipt).unwrap().modified().unwrap();
    let invoke = || {
        Command::new(env!("CARGO_BIN_EXE_artifact-update"))
            .args(["status", "--config"])
            .arg(&config)
            .arg("--json")
            .env("XDG_CACHE_HOME", temp.path().join("cache"))
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .output()
            .unwrap()
    };
    let result = invoke();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let row = &value["artifacts"][0];
    assert_eq!(value["network_accessed"], false);
    assert_eq!(row["installation_state"], "managed");
    assert_eq!(row["installed_version"], "1.2.3");
    assert_eq!(row["installed_verification"], "receipt-content");
    assert_eq!(row["outcome"], "unknown");
    assert_eq!(row["installation_authorized"], false);
    assert!(row.get("available_version").is_none());
    assert_eq!(
        fs::metadata(&receipt).unwrap().modified().unwrap(),
        modified
    );
    assert_eq!(fs::read(&receipt).unwrap(), original);
    assert!(!temp.path().join("cache").exists());
    fs::remove_file(bin.join("example")).unwrap();
    let result = invoke();
    assert_eq!(result.status.code(), Some(4));
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["artifacts"][0]["outcome"], "authority-unavailable");
    assert!(value["artifacts"][0].get("installed_version").is_none());
    assert!(!bin.join("example").exists());
    assert_eq!(fs::read(receipt).unwrap(), original);
}

#[cfg(target_os = "linux")]
#[test]
fn signed_status_and_offline_install_preserve_independent_ledger_and_cache_authority() {
    use dev_tools_installation::{
        apply_versioned_installation, ensure_owned_directory, ArtifactIdentity,
        VersionedInstallRequest, VersionedLayout,
    };
    use dev_tools_release::{
        build_signed_envelope, build_unsigned_product_manifest, build_unsigned_root_document,
        release_key_id, root_key_id, EnvelopeSignature, ManifestArtifact, ProductManifestSpec,
        ReleaseMetadata, RootDocumentSpec, RootReleaseKey,
    };
    use dev_tools_update::{artifact::ArtifactCatalog, manifest_ledger::ManifestLedger};
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let temp = tempfile::tempdir().unwrap();
    let owner = temp.path().metadata().unwrap().uid();
    let data = temp.path().join("data");
    let bin = temp.path().join("bin");
    let state = temp.path().join("state");
    let source = temp.path().join("source");
    fs::write(&source, b"signed inert fixture; never executed").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    let identity = ArtifactIdentity::from_file(&source, 4096).unwrap();
    let root_key = SigningKey::from_bytes(&[7; 32]);
    let release_key = SigningKey::from_bytes(&[8; 32]);
    let public = |key: &SigningKey| {
        key.verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let unsigned = build_unsigned_root_document(&RootDocumentSpec {
        generation: 1,
        release_keys: vec![RootReleaseKey {
            public_key: public(&release_key),
            revoked: false,
        }],
    })
    .unwrap();
    let root = build_signed_envelope(
        &unsigned,
        &[EnvelopeSignature {
            key_id: root_key_id(&public(&root_key)).unwrap(),
            signature: root_key.sign(&unsigned).to_bytes().to_vec(),
        }],
    )
    .unwrap();
    let unsigned = build_unsigned_product_manifest(&ProductManifestSpec {
        product: "example".into(),
        generation: 2,
        version: "1.2.3".into(),
        source_commit: "a".repeat(40),
        artifacts: vec![ManifestArtifact {
            target: format!("linux-{}", std::env::consts::ARCH),
            url: "https://example.invalid/tool".into(),
            length: identity.length,
            sha256: identity.sha256.clone(),
        }],
    })
    .unwrap();
    let manifest = build_signed_envelope(
        &unsigned,
        &[EnvelopeSignature {
            key_id: release_key_id(&public(&release_key)).unwrap(),
            signature: release_key.sign(&unsigned).to_bytes().to_vec(),
        }],
    )
    .unwrap();
    let metadata = ReleaseMetadata { root, manifest };
    let config_text = SIGNED_CONFIG.replace("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", &public(&root_key)).replace("kind = \"native-binary\"", &format!("kind = \"native-binary\"\ninstallation = {{ type = 'versioned-binary', data_root = '{}', bin_dir = '{}', artifact_name = 'example', aliases = ['example'] }}", data.display(), bin.display()));
    let config_text =
        config_text.replace("linux-x86_64", &format!("linux-{}", std::env::consts::ARCH));
    let catalog = ArtifactCatalog::parse(&config_text).unwrap();
    let record = catalog.get("example").unwrap();
    let mut ledger = ManifestLedger::new(record).unwrap();
    ledger.accept(record, &metadata).unwrap();
    let authority = ledger
        .authority_id()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let ledger_root = state
        .join("artifact-update/release-ledgers-v1")
        .join(authority);
    ensure_owned_directory(&ledger_root, owner, 0o700).unwrap();
    let ledger_path = ledger_root.join("ledger.json");
    fs::write(&ledger_path, ledger.to_bytes().unwrap()).unwrap();
    fs::set_permissions(&ledger_path, fs::Permissions::from_mode(0o600)).unwrap();
    apply_versioned_installation(
        &VersionedInstallRequest {
            layout: VersionedLayout {
                product: "example".into(),
                data_root: data.clone(),
                bin_dir: bin,
                artifact_name: "example".into(),
                owner_uid: owner,
                directory_mode: 0o700,
                bin_directory_mode: Some(0o755),
            },
            version: "1.2.3".into(),
            identity: identity.clone(),
            source,
            aliases: vec!["example".into()],
        },
        |_| Ok(()),
    )
    .unwrap();
    let config = temp.path().join("config.toml");
    fs::write(&config, config_text).unwrap();
    let invoke = || {
        Command::new(env!("CARGO_BIN_EXE_artifact-update"))
            .args(["status", "--config"])
            .arg(&config)
            .arg("--json")
            .env("XDG_STATE_HOME", &state)
            .env("XDG_CACHE_HOME", temp.path().join("cache"))
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .output()
            .unwrap()
    };
    let absent = invoke();
    assert!(absent.status.success());
    let value: serde_json::Value = serde_json::from_slice(&absent.stdout).unwrap();
    assert_eq!(
        value["artifacts"][0]["installed_verification"],
        "receipt-content"
    );
    let proof_root = data.join("release-evidence-v1");
    assert!(!proof_root.exists());
    ensure_owned_directory(&proof_root, owner, 0o700).unwrap();
    let mut hash = Sha256::new();
    for value in [
        "artifact-update-retained-evidence-v1",
        "1.2.3",
        &identity.sha256,
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.update(identity.length.to_be_bytes());
    let key = format!("{:x}", hash.finalize());
    let proof = proof_root.join(format!("{key}.cache"));
    let mut bytes = serde_json::to_vec(&serde_json::json!({"schema": "artifact-update-signed-metadata-v1", "key": key, "checked_at": 0, "root_length": metadata.root.len()})).unwrap();
    bytes.push(b'\n');
    bytes.extend_from_slice(&metadata.root);
    bytes.extend_from_slice(&metadata.manifest);
    fs::write(&proof, &bytes).unwrap();
    fs::set_permissions(&proof, fs::Permissions::from_mode(0o600)).unwrap();
    let before = fs::metadata(&proof).unwrap().modified().unwrap();
    let accepted = invoke();
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&accepted.stdout).unwrap();
    let row = &value["artifacts"][0];
    assert_eq!(
        row["installed_verification"],
        "signed-manifest-and-receipt-content"
    );
    assert_eq!(row["outcome"], "unknown");
    assert_eq!(row["installation_authorized"], false);
    assert_eq!(value["network_accessed"], false);
    assert!(!temp.path().join("cache").exists());
    assert_eq!(fs::metadata(&proof).unwrap().modified().unwrap(), before);
    assert_eq!(fs::read(&ledger_path).unwrap(), ledger.to_bytes().unwrap());
    fs::write(&proof, b"invalid proof").unwrap();
    let invalid = invoke();
    assert_eq!(invalid.status.code(), Some(4));
    let value: serde_json::Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert!(value["artifacts"][0].get("installed_version").is_none());
    assert_eq!(fs::read(&proof).unwrap(), b"invalid proof");

    // Exercise the real offline CLI with independent cache fixtures and new
    // local destinations. The original managed installation remains untouched.
    let offline_data = temp.path().join("offline-data");
    let offline_bin = temp.path().join("offline-bin");
    let offline_text = fs::read_to_string(&config)
        .unwrap()
        .replace(data.to_str().unwrap(), offline_data.to_str().unwrap())
        .replace(
            temp.path().join("bin").to_str().unwrap(),
            offline_bin.to_str().unwrap(),
        );
    let offline_config = temp.path().join("offline.toml");
    fs::write(&offline_config, &offline_text).unwrap();
    let cache_root = temp.path().join("cache/artifact-update");
    let metadata_root = cache_root.join("signed-metadata-v1");
    let artifact_root = cache_root.join("artifacts-v1");
    ensure_owned_directory(&metadata_root, owner, 0o700).unwrap();
    ensure_owned_directory(&artifact_root, owner, 0o700).unwrap();
    let mut hash = Sha256::new();
    for part in [
        offline_text.as_bytes(),
        b"example",
        b"signed-metadata-v1",
        b"configured-target",
    ] {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part);
    }
    let key = format!("{:x}", hash.finalize());
    let metadata_path = metadata_root.join(format!("{key}.cache"));
    let mut cache_bytes = serde_json::to_vec(&serde_json::json!({"schema": "artifact-update-signed-metadata-v1", "key": key, "checked_at": 0, "root_length": metadata.root.len()})).unwrap();
    cache_bytes.push(b'\n');
    cache_bytes.extend_from_slice(&metadata.root);
    cache_bytes.extend_from_slice(&metadata.manifest);
    fs::write(&metadata_path, &cache_bytes).unwrap();
    fs::set_permissions(&metadata_path, fs::Permissions::from_mode(0o600)).unwrap();
    let artifact_path =
        artifact_root.join(format!("{}-{}.artifact", identity.sha256, identity.length));
    let artifact_bytes = fs::read(data.join("active")).unwrap();
    fs::write(&artifact_path, &artifact_bytes).unwrap();
    fs::set_permissions(&artifact_path, fs::Permissions::from_mode(0o600)).unwrap();
    let metadata_modified = metadata_path.metadata().unwrap().modified().unwrap();
    let ledger_modified = ledger_path.metadata().unwrap().modified().unwrap();
    let offline = || {
        let output = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
            .args(["install", "example", "--offline", "--json", "--config"])
            .arg(&offline_config)
            .env("XDG_STATE_HOME", &state)
            .env("XDG_CACHE_HOME", temp.path().join("cache"))
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .output()
            .unwrap();
        let row: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(row["network_accessed"], false);
        assert_eq!(row["metadata_cache_changed"], false);
        assert_eq!(row["artifact_cache_changed"], false);
        assert_eq!(fs::read(&ledger_path).unwrap(), ledger.to_bytes().unwrap());
        assert_eq!(
            ledger_path.metadata().unwrap().modified().unwrap(),
            ledger_modified
        );
        assert_eq!(fs::read(&metadata_path).unwrap(), cache_bytes);
        assert_eq!(
            metadata_path.metadata().unwrap().modified().unwrap(),
            metadata_modified
        );
        (output.status.code(), row)
    };
    for expected_changed in [true, false] {
        let (code, row) = offline();
        assert_eq!(code, Some(0), "{row}");
        assert_eq!(row["changed"], expected_changed);
        assert_eq!(row["installed_version"], "1.2.3");
        assert_eq!(
            fs::read(offline_bin.join("example")).unwrap(),
            artifact_bytes
        );
    }
    let receipt_path = offline_data.join("installation-receipt-v1.json");
    let receipt_bytes = fs::read(&receipt_path).unwrap();
    fs::write(&artifact_path, b"corrupt").unwrap();
    let (code, row) = offline();
    assert_eq!(code, Some(4));
    assert_eq!(row["changed"], false);
    assert_eq!(row["outcome"], "artifact-cache-invalid");
    assert_eq!(fs::read(&receipt_path).unwrap(), receipt_bytes);
    fs::write(
        &offline_config,
        format!("{offline_text}\n# changed local configuration\n"),
    )
    .unwrap();
    let (code, row) = offline();
    assert_eq!(code, Some(3));
    assert_eq!(row["outcome"], "offline-metadata-unavailable");
    assert_eq!(fs::read(receipt_path).unwrap(), receipt_bytes);
}

#[test]
fn build_identity_and_help_are_checkout_independent() {
    let version = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .arg("--version")
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(version.stdout).unwrap(),
        "artifact-update 0.1.0\n"
    );

    let info = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .args(["build-info", "--json"])
        .output()
        .unwrap();
    assert!(info.status.success());
    let info: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(info["schema"], "dev-tools-build-info-v1");
    assert_eq!(info["product"], "artifact-update");
}

#[cfg(target_os = "linux")]
#[test]
fn fifo_configuration_is_rejected_without_waiting_for_a_writer() {
    use dev_tools_command::run_prepared_bounded_command;
    use std::time::Duration;

    let root = tempfile::tempdir().unwrap();
    let fifo = root.path().join("config.toml");
    let fixture = run_prepared_bounded_command(
        Command::new("/usr/bin/mkfifo").arg(&fifo),
        Duration::from_secs(5),
        4096,
    )
    .expect("create FIFO fixture");
    assert!(fixture.status.success());
    let output = run_prepared_bounded_command(
        Command::new(env!("CARGO_BIN_EXE_artifact-update"))
            .args(["list", "--config"])
            .arg(&fifo),
        Duration::from_secs(5),
        4096,
    )
    .expect("non-regular configuration must fail without blocking");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}
