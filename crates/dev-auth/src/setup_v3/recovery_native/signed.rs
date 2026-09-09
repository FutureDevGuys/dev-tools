//! Public signed intake in a fresh disposable native root. The runner supplies
//! exact release sets at /signed/candidate and /signed/prior; no fake provenance.
use super::*;

const ACCOUNT: &str = "dev-auth-release-test";

fn fixture() -> nix::unistd::User {
    assert_eq!(
        std::env::var("DEV_AUTH_NATIVE_SYSTEMD_FIXTURE").as_deref(),
        Ok("disposable")
    );
    assert!(nix::unistd::Uid::effective().is_root());
    assert!(Path::new("/run/.containerenv").is_file());
    assert_eq!(
        fs::read_to_string("/proc/1/comm").unwrap().trim(),
        "systemd"
    );
    for path in [
        "/usr/local/lib/dev-auth",
        "/usr/local/bin/dev-auth",
        "/etc/dev-auth/policy.toml",
    ] {
        assert_eq!(
            fs::symlink_metadata(path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }
    assert!(nix::unistd::User::from_name(ACCOUNT).unwrap().is_none());
    let output = command(
        Path::new("/usr/sbin/useradd"),
        &["--create-home", "--no-log-init", ACCOUNT],
    );
    assert!(output.status.success());
    let account = nix::unistd::User::from_name(ACCOUNT).unwrap().unwrap();
    for relative in [
        "",
        ".config",
        ".config/dev-auth",
        ".local",
        ".local/bin",
        ".local/share",
        ".local/share/dev-auth",
        ".local/share/applications",
    ] {
        let path = account.dir.join(relative);
        fs::create_dir_all(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        nix::unistd::chown(&path, Some(account.uid), Some(account.gid)).unwrap();
    }
    account
}

fn json(executable: &Path, arguments: &[&str]) -> serde_json::Value {
    let output = command(executable, arguments);
    assert!(
        output.status.success(),
        "public fixture failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn release_path(generation: &str, version: &str) -> PathBuf {
    PathBuf::from(format!(
        "/signed/{generation}/dev-auth-{version}-linux-x86_64"
    ))
}

fn install(generation: &str, version: &str, policy: &[u8], config: &[u8]) -> PathBuf {
    let source = release_path(generation, version);
    let root = format!("/signed/{generation}/dev-tools-root.json");
    let manifest = format!("/signed/{generation}/dev-auth-stable.json");
    let verified = json(
        &source,
        &[
            "setup",
            "verify-release",
            "--root",
            &root,
            "--manifest",
            &manifest,
            "--artifact",
            source.to_str().unwrap(),
        ],
    );
    assert_eq!(verified["version"], version);
    let policy_path = format!("/fixture-input/{generation}-policy.toml");
    let config_path = format!("/fixture-input/{generation}-config.toml");
    publish(Path::new(&policy_path), policy, 0o600);
    publish(Path::new(&config_path), config, 0o600);
    let user_config = format!("{ACCOUNT}={config_path}");
    let plan_path = format!("/fixture-input/{generation}-plan.json");
    for pass in 0..2 {
        let plan = json(
            &source,
            &[
                "setup",
                "plan",
                "--mode",
                "strong",
                "--offline",
                "--release-root",
                &root,
                "--release-manifest",
                &manifest,
                "--release-artifact",
                source.to_str().unwrap(),
                "--activation",
                "transparent",
                "--administrator-policy",
                &policy_path,
                "--user-config",
                &user_config,
                "--credential-intent",
                "automation=preserve",
                "--output",
                &plan_path,
                "--format",
                "json",
            ],
        );
        assert_eq!(plan["release_version"], version);
        let digest = plan["sha256"].as_str().unwrap();
        let applied = json(
            &source,
            &[
                "setup", "apply", "--plan", &plan_path, "--sha256", digest, "--format", "json",
            ],
        );
        assert_eq!(applied["verified"], true, "{applied}");
        assert_eq!(applied["changed"], pass == 0, "{applied}");
        let verified = json(
            &source,
            &[
                "setup", "verify", "--plan", &plan_path, "--sha256", digest, "--format", "json",
            ],
        );
        assert_eq!(verified["verified"], true, "{verified}");
    }
    let installed = PathBuf::from(format!(
        "/usr/local/lib/dev-auth/versions/{version}/dev-auth"
    ));
    assert_eq!(
        fs::canonicalize("/usr/local/bin/dev-auth").unwrap(),
        installed
    );
    installed
}

#[test]
#[ignore = "requires an owned rootful disposable systemd container with the clean signed candidate release set"]
fn native_disposable_signed_fresh_install_workload_and_restore() {
    let account = fixture();
    let (policy, config) = workload::prepare(&account);
    let installed = install("candidate", env!("CARGO_PKG_VERSION"), &policy, &config);
    workload::exercise(&account, &installed);
}

#[test]
#[ignore = "requires an owned rootful disposable systemd container with clean signed candidate and 0.3.11 release sets"]
fn native_disposable_signed_legacy_upgrade_and_restore() {
    let account = fixture();
    let (policy, config) = workload::prepare(&account);
    let prior_policy = format!(
        r#"version = 2
mode = "strong"
allowed_users = ["{ACCOUNT}"]
[programs]
op = "/usr/local/libexec/dev-auth-fixture-provider"
git = "/usr/bin/true"
gh = "/usr/bin/false"
ssh = "/usr/bin/true"
ssh_keygen = "/usr/bin/true"
[trusted_launchers]
worker = "/usr/local/libexec/dev-auth-fixture-worker"
[github_apps]
[credential_slots.automation]
users = ["{ACCOUNT}"]
authority_caps = ["worker"]
secret_references = ["op://Fixture/Token/value"]
[authority_caps.worker]
secret_references = ["op://Fixture/Token/value"]
[workspace_caps]
"#
    );
    let prior_config = br#"version = 2
[authority_profiles.worker]
cap = "worker"
secret_references = ["op://Fixture/Token/value"]
[[workloads]]
name = "worker"
profile = "worker"
launcher = "worker"
secret_references = ["op://Fixture/Token/value"]
workspace_roots = []
[workloads.sandbox]
mode = "none"
"#;
    install("prior", "0.3.11", prior_policy.as_bytes(), prior_config);
    let prior_policy_bytes = fs::read("/etc/dev-auth/policy.toml").unwrap();
    let prior_config_path = account.dir.join(".config/dev-auth/config-v2.toml");
    let prior_config_bytes = fs::read(&prior_config_path).unwrap();
    let installed = install("candidate", env!("CARGO_PKG_VERSION"), &policy, &config);
    workload::require_credential_operation(&account, &installed);
    let restored = json(
        &installed,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    assert_eq!(restored["verified"], true, "{restored}");
    assert_eq!(restored["changed"], true);
    assert_eq!(
        fs::read("/etc/dev-auth/policy.toml").unwrap(),
        prior_policy_bytes
    );
    assert_eq!(fs::read(prior_config_path).unwrap(), prior_config_bytes);
    assert!(!account.dir.join(".config/dev-auth/config-v3.toml").exists());
    assert!(crate::setup::system_service_credential_slot_ready(
        "automation"
    ));
    assert_eq!(
        fs::canonicalize("/usr/local/bin/dev-auth").unwrap(),
        Path::new("/usr/local/lib/dev-auth/versions/0.3.11/dev-auth")
    );
    for socket in ["/run/dev-auth/broker.sock", "/run/dev-auth/control.sock"] {
        assert!(!Path::new(socket).exists());
    }
    let prior_verified = command(
        Path::new("/usr/local/bin/dev-auth"),
        &["setup", "verify", "--mode", "strong"],
    );
    assert!(
        prior_verified.status.success(),
        "{}",
        String::from_utf8_lossy(&prior_verified.stderr)
    );
    let retry = json(
        &installed,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    assert_eq!(retry["verified"], true);
    assert_eq!(retry["changed"], false);
}
