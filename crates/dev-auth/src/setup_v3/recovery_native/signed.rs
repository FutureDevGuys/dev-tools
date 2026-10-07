#![cfg(test)]

//! Public signed intake in a fresh disposable native root. The runner supplies
//! exact release sets at /signed/candidate and /signed/prior; no fake provenance.
use super::*;
use crate::setup::maintenance;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;

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
        maintenance::POLICY_PATH,
        maintenance::POLKIT_PATH,
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

fn require_ready_diagnostics(account: &nix::unistd::User, executable: &Path) {
    let held = dev_tools_command::HeldExecutable::open(executable).unwrap();
    let mut selected = held.command(executable.as_os_str()).unwrap();
    selected
        .uid(account.uid.as_raw())
        .gid(account.gid.as_raw())
        .env_clear()
        .current_dir(&account.dir)
        .args(["doctor", "--json"]);
    let output = dev_tools_command::run_prepared_bounded_command(
        &mut selected,
        std::time::Duration::from_secs(40),
        64 * 1024,
    )
    .unwrap();
    assert!(
        output.status.success(),
        "native doctor failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    for field in [
        "policy_ready",
        "user_config_ready",
        "policy_resolution_ready",
    ] {
        assert_eq!(report["details"][field], true, "{report}");
    }
    assert_eq!(report["details"]["broker_state"], "not_probed");
    assert_eq!(report["details"]["provider_use_observation"], "not_checked");
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
    let mut maintenance_snapshot = None;
    for pass in 0..2 {
        let plan = json(
            &source,
            &[
                "setup",
                "plan",
                "--mode",
                "strong",
                "--channel",
                "stable",
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
        if maintenance::supports_version(version) {
            let installed = PathBuf::from(format!(
                "/usr/local/lib/dev-auth/versions/{version}/dev-auth"
            ));
            let observed = require_maintenance_group(&installed, version);
            if let Some(previous) = &maintenance_snapshot {
                assert_eq!(
                    previous, &observed,
                    "repeat setup must preserve helper-group file identity"
                );
            }
            maintenance_snapshot = Some(observed);
        }
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

#[derive(Debug, PartialEq, Eq)]
struct MaintenanceSnapshot {
    files: Vec<(u64, u64, u32, Vec<u8>)>,
}

fn require_maintenance_group(installed: &Path, version: &str) -> MaintenanceSnapshot {
    let installation: serde_json::Value =
        serde_json::from_slice(&fs::read("/usr/local/lib/dev-auth/install-v2.json").unwrap())
            .unwrap();
    assert_eq!(installation["version"], version);
    assert!(installation["source_commit"]
        .as_str()
        .is_some_and(|value| value.len() == 40));
    assert!(installation["root_generation"]
        .as_u64()
        .is_some_and(|value| value > 0));
    assert!(installation["manifest_generation"]
        .as_u64()
        .is_some_and(|value| value > 0));
    let mut files = Vec::new();
    for (path, mode) in [
        (maintenance::HELPER_PATH, 0o755),
        (maintenance::RECEIPT_PATH, 0o644),
        (maintenance::POLKIT_PATH, 0o644),
    ] {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.uid(), 0);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.mode() & 0o7777, mode);
        files.push((
            metadata.dev(),
            metadata.ino(),
            mode,
            fs::read(path).unwrap(),
        ));
    }
    let helper = fs::metadata(maintenance::HELPER_PATH).unwrap();
    assert_eq!(
        fs::read(maintenance::HELPER_PATH).unwrap(),
        fs::read(installed).unwrap()
    );
    for path in [
        installed,
        Path::new("/usr/local/lib/dev-auth/dev-auth-workload-launcher"),
        Path::new("/usr/local/lib/dev-auth/dev-auth-setup-helper"),
    ] {
        let other = fs::metadata(path).unwrap();
        assert_ne!(
            (helper.dev(), helper.ino()),
            (other.dev(), other.ino()),
            "maintenance must be a distinct ordinary copy"
        );
    }
    let sidecar: serde_json::Value = serde_json::from_slice(&files[1].3).unwrap();
    assert_eq!(sidecar["schema"], "dev-auth-maintenance-helper-v1");
    assert_eq!(sidecar["protocol"], "dev-auth-maintenance-helper-v1");
    assert_eq!(sidecar["helper"]["helper_path"], maintenance::HELPER_PATH);
    assert_eq!(sidecar["helper"]["source_version"], version);
    assert_eq!(
        sidecar["helper"]["active_executable"],
        installed.to_str().unwrap()
    );
    for (sidecar_key, receipt_key) in [
        ("helper_length", "executable_length"),
        ("helper_sha256", "executable_sha256"),
        ("source_commit", "source_commit"),
        ("root_generation", "root_generation"),
        ("manifest_generation", "manifest_generation"),
    ] {
        assert_eq!(sidecar["helper"][sidecar_key], installation[receipt_key]);
    }
    assert_eq!(sidecar["polkit_path"], maintenance::POLKIT_PATH);
    assert_eq!(
        sidecar["polkit_sha256"],
        sha256_hex(maintenance::POLKIT.as_bytes())
    );
    assert_eq!(files[2].3, maintenance::POLKIT.as_bytes());
    assert!(maintenance::POLKIT.contains("<allow_active>auth_admin</allow_active>"));
    assert!(!maintenance::POLKIT.contains("auth_admin_keep"));
    assert!(
        fs::read_to_string("/usr/share/polkit-1/actions/com.futuredevguys.dev-auth.policy")
            .unwrap()
            .contains("<allow_active>auth_self</allow_active>")
    );
    assert_eq!(
        crate::setup::validate_installed_maintenance_helper().unwrap(),
        installed
    );
    MaintenanceSnapshot { files }
}

fn require_maintenance_absent() {
    for path in [
        maintenance::HELPER_PATH,
        maintenance::RECEIPT_PATH,
        maintenance::POLKIT_PATH,
        maintenance::POLICY_PATH,
    ] {
        assert_eq!(
            fs::symlink_metadata(path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound,
            "restoration must remove newly installed maintenance authority"
        );
    }
}

fn require_absent_policy_denies_planning(account: &nix::unistd::User, installed: &Path) {
    assert_eq!(
        fs::symlink_metadata(maintenance::POLICY_PATH)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    let request = serde_json::json!({"schema":"dev-auth-privilege-request-v1", "capability":"signed-fixture", "owner_uid":account.uid.as_raw(), "idle_seconds":5, "hard_seconds":10, "total_uses":1, "operations":{"probe":{"uses":1,"plans":["probe"]}}});
    let bytes = serde_json::to_vec(&request).unwrap();
    crate::privilege::policy::parse_request(&bytes).unwrap();
    let request_path = account.dir.join("maintenance-denied-request.json");
    let output_path = account.dir.join("maintenance-denied-plan.json");
    publish(&request_path, &bytes, 0o600);
    nix::unistd::chown(&request_path, Some(account.uid), Some(account.gid)).unwrap();
    let held = dev_tools_command::HeldExecutable::open(installed).unwrap();
    let mut selected = held.command(installed.as_os_str()).unwrap();
    selected
        .uid(account.uid.as_raw())
        .gid(account.gid.as_raw())
        .env_clear()
        .current_dir(&account.dir)
        .args([
            "privilege",
            "plan",
            "--request",
            request_path.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
            "--json",
        ]);
    let output = dev_tools_command::run_prepared_bounded_command(
        &mut selected,
        std::time::Duration::from_secs(20),
        64 * 1024,
    )
    .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        fs::symlink_metadata(output_path).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        fs::symlink_metadata(maintenance::POLICY_PATH)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
}

#[test]
#[ignore = "requires an owned rootful disposable systemd container with the clean signed candidate release set"]
fn native_disposable_signed_fresh_install_workload_and_restore() {
    let account = fixture();
    let (policy, config) = workload::prepare(&account);
    let installed = install("candidate", env!("CARGO_PKG_VERSION"), &policy, &config);
    require_ready_diagnostics(&account, &installed);
    if maintenance::supports_version(env!("CARGO_PKG_VERSION")) {
        require_absent_policy_denies_planning(&account, &installed);
    }
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
git = "/usr/bin/git"
gh = "/usr/bin/gh"
ssh = "/usr/bin/ssh"
ssh_keygen = "/usr/bin/ssh-keygen"
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
    require_ready_diagnostics(&account, &installed);
    if maintenance::supports_version(env!("CARGO_PKG_VERSION")) {
        require_absent_policy_denies_planning(&account, &installed);
    }
    workload::require_credential_operation(&account, &installed);
    let restored = json(
        &installed,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    assert_eq!(restored["verified"], true, "{restored}");
    assert_eq!(restored["changed"], true);
    require_maintenance_absent();
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

#[test]
#[ignore = "requires an owned rootful disposable systemd container with clean signed candidate and 0.4.0 release sets"]
fn native_disposable_signed_v3_patch_upgrade_and_restore() {
    let account = fixture();
    let (policy, config) = workload::prepare(&account);
    install("prior", "0.4.0", &policy, &config);
    let prior_policy = fs::read("/etc/dev-auth/policy.toml").unwrap();
    let config_path = account.dir.join(".config/dev-auth/config-v3.toml");
    let prior_config = fs::read(&config_path).unwrap();
    let installed = install("candidate", env!("CARGO_PKG_VERSION"), &policy, &config);
    require_ready_diagnostics(&account, &installed);
    if maintenance::supports_version(env!("CARGO_PKG_VERSION")) {
        require_absent_policy_denies_planning(&account, &installed);
    }
    workload::require_credential_operation(&account, &installed);
    let restored = json(
        &installed,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    assert_eq!(restored["verified"], true, "{restored}");
    assert_eq!(restored["changed"], true);
    require_maintenance_absent();
    assert_eq!(fs::read("/etc/dev-auth/policy.toml").unwrap(), prior_policy);
    assert_eq!(fs::read(config_path).unwrap(), prior_config);
    assert!(crate::setup::system_service_credential_slot_ready(
        "automation"
    ));
    assert_eq!(
        fs::canonicalize("/usr/local/bin/dev-auth").unwrap(),
        Path::new("/usr/local/lib/dev-auth/versions/0.4.0/dev-auth")
    );
    for socket in ["/run/dev-auth/broker.sock", "/run/dev-auth/control.sock"] {
        assert!(!Path::new(socket).exists());
    }
    let retry = json(
        &installed,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    assert_eq!(retry["verified"], true);
    assert_eq!(retry["changed"], false);
}

#[test]
#[ignore = "requires clean signed maintenance-capable prior and candidate release sets in an owned rootful disposable systemd container"]
fn native_disposable_signed_maintenance_prior_policy_preservation() {
    let account = fixture();
    let candidate_version = env!("CARGO_PKG_VERSION");
    let prior_version = std::env::var("DEV_AUTH_SIGNED_MAINTENANCE_PRIOR_VERSION")
        .unwrap_or_else(|_| "0.5.0".into());
    assert!(maintenance::supports_version(&prior_version));
    assert!(
        semver::Version::parse(&prior_version).unwrap()
            <= semver::Version::parse(candidate_version).unwrap()
    );
    if prior_version == candidate_version {
        assert_eq!(
            fs::read(release_path("prior", &prior_version)).unwrap(),
            fs::read(release_path("candidate", candidate_version)).unwrap(),
            "same-version signed sources must be identical"
        );
    }
    let (policy, prior_config) = workload::prepare(&account);
    let prior_installed = install("prior", &prior_version, &policy, &prior_config);
    require_absent_policy_denies_planning(&account, &prior_installed);
    let privilege_policy =
        b"{\n  \"schema\": \"dev-auth-privilege-policy-v1\",\n  \"capabilities\": {}\n}\n";
    let source = Path::new("/fixture-input/explicit-maintenance-policy.json");
    publish(source, privilege_policy, 0o644);
    let digest = sha256_hex(privilege_policy);
    let published = json(
        &prior_installed,
        &[
            "setup",
            "install-privilege-policy",
            "--source",
            source.to_str().unwrap(),
            "--sha256",
            &digest,
        ],
    );
    assert_eq!(published["changed"], true);
    assert_eq!(published["granted"], false);
    let no_op = json(
        &prior_installed,
        &[
            "setup",
            "update-privilege-policy",
            "--source",
            source.to_str().unwrap(),
            "--sha256",
            &digest,
            "--current-sha256",
            &digest,
        ],
    );
    assert_eq!(no_op["changed"], false);
    let prior_sidecar = fs::read(maintenance::RECEIPT_PATH).unwrap();
    let prior_action = fs::read(maintenance::POLKIT_PATH).unwrap();
    let prior_policy_metadata = fs::symlink_metadata(maintenance::POLICY_PATH).unwrap();
    assert_eq!(prior_policy_metadata.uid(), 0);
    assert_eq!(prior_policy_metadata.mode() & 0o7777, 0o644);
    assert_eq!(prior_policy_metadata.nlink(), 1);
    // Distinct document bytes select a real retained configuration transition
    // even when the first maintenance-capable signed version is also candidate.
    let mut candidate_config = prior_config.clone();
    candidate_config.extend_from_slice(b"\n# candidate configuration retention fixture\n");
    let installed = install("candidate", candidate_version, &policy, &candidate_config);
    assert_eq!(
        fs::read(maintenance::POLICY_PATH).unwrap(),
        privilege_policy
    );
    require_maintenance_group(&installed, candidate_version);
    let restored = json(
        &installed,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    assert_eq!(restored["verified"], true);
    assert_eq!(restored["changed"], true);
    assert_eq!(
        fs::read(account.dir.join(".config/dev-auth/config-v3.toml")).unwrap(),
        prior_config
    );
    assert_eq!(fs::read(maintenance::RECEIPT_PATH).unwrap(), prior_sidecar);
    assert_eq!(fs::read(maintenance::POLKIT_PATH).unwrap(), prior_action);
    assert_eq!(
        fs::read(maintenance::POLICY_PATH).unwrap(),
        privilege_policy
    );
    let restored_policy_metadata = fs::symlink_metadata(maintenance::POLICY_PATH).unwrap();
    assert_eq!(
        (
            restored_policy_metadata.dev(),
            restored_policy_metadata.ino()
        ),
        (prior_policy_metadata.dev(), prior_policy_metadata.ino()),
        "unchanged independent administrator policy must not be republished"
    );
    assert_eq!(
        fs::canonicalize("/usr/local/bin/dev-auth").unwrap(),
        prior_installed
    );
    require_maintenance_group(&prior_installed, &prior_version);
    let retry = json(
        &installed,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    assert_eq!(retry["verified"], true);
    assert_eq!(retry["changed"], false);
}
