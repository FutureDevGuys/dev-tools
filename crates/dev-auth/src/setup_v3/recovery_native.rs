//! Standalone CLI recovery in a disposable systemd root. Retained provenance
//! is synthetic; the actual candidate executable is supplied by the runner.
use super::*;
use crate::setup::{InstallMode, SetupPaths};
use dev_tools_installation::{ArtifactIdentity, VersionedInstallRequest, VersionedLayout};
use std::os::unix::fs::PermissionsExt;

#[test]
#[ignore = "requires an owned disposable systemd container and /candidate/dev-auth; never run on the host"]
fn native_disposable_public_strong_initial_staged_recovery() {
    exercise(true, false);
}

#[test]
#[ignore = "requires an owned disposable systemd container and /candidate/dev-auth; never run on the host"]
fn native_disposable_public_strong_initial_unstaged_recovery() {
    exercise(false, false);
}

#[test]
#[ignore = "requires an owned rootful disposable systemd container and /candidate/dev-auth; never run on the host"]
fn native_disposable_public_strong_enrolled_workload() {
    exercise(false, true);
}

mod signed;
mod workload;

fn command(executable: &Path, arguments: &[&str]) -> dev_tools_command::BoundedCommandOutput {
    eprintln!("fixture command: {} {arguments:?}", executable.display());
    dev_tools_command::run_bounded_command(&dev_tools_command::BoundedCommand {
        executable,
        arguments: &arguments
            .iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>(),
        environment: &BTreeMap::from([("LC_ALL".into(), "C".into())]),
        cwd: Some(Path::new("/")),
        timeout: std::time::Duration::from_secs(90),
        output_limit: 64 * 1024,
    })
    .unwrap()
}

fn publish(path: &Path, bytes: &[u8], mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn recover(executable: &Path) -> SetupRecoveryReportV1 {
    let output = command(
        executable,
        &["setup", "recover", "--mode", "strong", "--format", "json"],
    );
    let report: SetupRecoveryReportV1 =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "fixture CLI result: {error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(output.status.code(), Some(report.exit_code));
    report
}

fn exercise(staged: bool, with_workload: bool) {
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
    let paths = SetupPaths::strong();
    let source = Path::new("/candidate/dev-auth");
    let aliases = [
        "dev-auth",
        "git-credential-dev-auth",
        "git-dev-auth",
        "gh-dev-auth",
        "ssh-keygen-dev-auth",
    ];
    for path in std::iter::once(paths.data_root.clone())
        .chain(std::iter::once(PathBuf::from(
            crate::policy_store::SYSTEM_POLICY_PATH,
        )))
        .chain(
            crate::setup::linux_system_assets()
                .iter()
                .map(|(path, _, _)| path.to_path_buf()),
        )
        .chain(
            aliases
                .into_iter()
                .chain(["git", "gh"])
                .map(|name| paths.bin_dir.join(name)),
        )
    {
        assert_eq!(
            fs::symlink_metadata(path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }
    let name = "dev-auth-recover-alpha";
    assert!(nix::unistd::User::from_name(name).unwrap().is_none());
    assert!(command(
        Path::new("/usr/sbin/useradd"),
        &["--create-home", "--no-log-init", name]
    )
    .status
    .success());
    let account = nix::unistd::User::from_name(name).unwrap().unwrap();
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
    let policy_path = Path::new("/fixture-input/policy.toml");
    let config_path = Path::new("/fixture-input/config.toml");
    let empty_policy = format!(
        r#"schema = "dev-auth-administrator-policy-v3"
mode = "strong"
allowed_users = ["{name}"]
[programs]
git = "/usr/bin/true"
gh = "/usr/bin/false"
ssh = "/usr/bin/true"
ssh_keygen = "/usr/bin/true"
[trusted_launchers]
[credentials.providers]
[credentials.credential_slots]
[credentials.resources]
[credentials.resource_caps]
[workload_caps]
"#
    )
    .into_bytes();
    let (policy, config) = if with_workload {
        workload::prepare(&account)
    } else {
        (
            empty_policy,
            b"schema = \"dev-auth-user-config-v3\"\nworkloads = []\n[authority_profiles]\n"
                .to_vec(),
        )
    };
    publish(policy_path, &policy, 0o600);
    publish(config_path, &config, 0o600);
    let identity = ArtifactIdentity::from_file(source, 256 * 1024 * 1024).unwrap();
    let version = env!("CARGO_PKG_VERSION");
    let installation = SetupPlan {
        schema: "dev-auth-setup-plan-v2".into(),
        paths: paths.clone(),
        request: crate::setup::InstallRequest {
            mode: InstallMode::Strong,
            version: version.into(),
            source_executable: source.into(),
            native_git: "/usr/bin/true".into(),
            native_gh: "/usr/bin/false".into(),
            activate_transparent_launchers: false,
        },
        source_length: identity.length,
        source_sha256: identity.sha256.clone(),
        verified_release: Some(crate::release_manifest::VerifiedDevAuthRelease {
            schema: "dev-auth-verified-release-v1".into(),
            root_path: "/unavailable-root".into(),
            manifest_path: "/unavailable-manifest".into(),
            root_generation: 1,
            manifest_generation: 1,
            version: version.into(),
            source_commit: "a".repeat(40),
            target: crate::release_manifest::target_id().unwrap(),
            artifact_path: source.into(),
            artifact_url: "https://example.invalid/fixture".into(),
            artifact_length: identity.length,
            artifact_sha256: identity.sha256.clone(),
            root_sha256: "b".repeat(64),
            manifest_sha256: "c".repeat(64),
        }),
    };
    let intent = DeploymentIntent {
        schema: "dev-auth-deployment-intent-v1".into(),
        mode: DeploymentMode::Strong,
        channel: crate::deployment::Channel::Stable,
        offline: true,
        activation: if with_workload {
            Activation::Transparent
        } else {
            Activation::Inactive
        },
        administrator_policy: policy_path.into(),
        users: vec![crate::deployment::DeploymentUser {
            name: name.into(),
            config: config_path.into(),
            policy: None,
        }],
        credentials: if with_workload {
            vec![DeploymentCredential {
                slot: "automation".into(),
                intent: CredentialIntent::Preserve,
            }]
        } else {
            Vec::new()
        },
    };
    let plan = build_setup_plan_v3_with_reader(
        intent,
        installation,
        true,
        &read_document,
        &|_| Ok(()),
        None,
    )
    .unwrap();
    let digest = sha256_hex(&serde_jcs::to_vec(&plan).unwrap());
    let lock = crate::setup_transition::lock_path(DeploymentMode::Strong, None).unwrap();
    {
        let _lease = InstallationLock::try_acquire(&lock).unwrap().unwrap();
        crate::setup_transition::begin(&paths, 0, &digest, || {
            capture_retained_generation(&plan, &digest)
        })
        .unwrap();
    }
    let marker = crate::setup_transition::state_path(&paths);
    let pending_marker = fs::read(&marker).unwrap();
    let generation = crate::setup_transition::retained_transition(&paths, 0)
        .unwrap()
        .unwrap()
        .bytes;
    let executable = paths
        .data_root
        .join("versions")
        .join(version)
        .join("dev-auth");
    let invocation = if staged {
        let mut aliases = aliases.map(str::to_owned).to_vec();
        aliases.sort();
        let shared = dev_tools_installation::apply_versioned_installation(
            &VersionedInstallRequest {
                layout: VersionedLayout {
                    product: "dev-auth".into(),
                    data_root: paths.data_root.clone(),
                    bin_dir: paths.bin_dir.clone(),
                    artifact_name: "dev-auth".into(),
                    owner_uid: 0,
                    directory_mode: 0o755,
                    bin_directory_mode: None,
                },
                version: version.into(),
                source: source.into(),
                identity,
                aliases,
            },
            |_| Ok(()),
        )
        .unwrap()
        .receipt;
        publish(
            &paths.data_root.join("installation-transition-v1.json"),
            &serde_json::to_vec(&serde_json::json!({
                "schema": "dev-tools-versioned-transition-v1", "prior": null, "next": shared,
            }))
            .unwrap(),
            0o600,
        );
        fs::remove_file(paths.data_root.join("installation-receipt-v1.json")).unwrap();
        fs::remove_file(paths.data_root.join("active")).unwrap();
        fs::remove_file(paths.bin_dir.join("git-dev-auth")).unwrap();
        fs::remove_file(source).unwrap();
        executable.as_path()
    } else {
        source
    };
    fs::remove_file(policy_path).unwrap();
    fs::remove_file(config_path).unwrap();
    let report = recover(invocation);
    if !report.verified {
        // Value-free public results intentionally omit internal context. This
        // fixture has no secrets and can expose its own failed component check.
        let evidence = crate::setup::retained_candidate_validation_from_source(
            &plan.installation,
            None,
            Some(invocation),
        );
        panic!(
            "public recovery failed: {report:?}; fixture binary proof: {:?}",
            evidence.err()
        );
    }
    assert_eq!(report.changed, Some(true));
    assert_eq!(report.exit_code, 0);
    let policy_digest = sha256_hex(&policy);
    for busy in [true, false] {
        let _lease = busy.then(|| {
            InstallationLock::try_acquire_shared(&lock)
                .unwrap()
                .unwrap()
        });
        for operation in ["install-policy", "update-policy"] {
            let mut arguments = vec![
                "setup",
                operation,
                "--source",
                crate::policy_store::SYSTEM_POLICY_PATH,
                "--sha256",
                policy_digest.as_str(),
            ];
            if operation == "update-policy" {
                arguments.extend(["--current-sha256", policy_digest.as_str()]);
            }
            let result = command(&executable, &arguments);
            assert!(!result.status.success());
            assert!(String::from_utf8_lossy(&result.stderr).contains(if busy {
                "requires active workloads and setup to finish"
            } else {
                "full setup generation requires transaction-aware maintenance"
            }));
            assert_eq!(
                fs::read(crate::policy_store::SYSTEM_POLICY_PATH).unwrap(),
                policy
            );
        }
    }
    assert_eq!(
        fs::read(crate::policy_store::SYSTEM_POLICY_PATH).unwrap(),
        policy
    );
    let config_destination = account
        .dir
        .join(crate::policy_store::USER_CONFIG_V3_RELATIVE_PATH);
    assert_eq!(fs::read(&config_destination).unwrap(), config);
    assert_eq!(
        fs::metadata(config_destination).unwrap().uid(),
        account.uid.as_raw()
    );
    assert_eq!(
        crate::setup_transition::retained_transition(&paths, 0)
            .unwrap()
            .unwrap()
            .bytes,
        generation
    );
    if source.exists() {
        fs::remove_file(source).unwrap();
    }
    let report = recover(&executable);
    assert!(report.verified);
    assert_eq!(report.changed, Some(false));
    assert!(report.actions.is_empty());
    if with_workload {
        workload::exercise(&account, &executable);
        return;
    }
    // An accepted generation cannot be replayed to repair an incomplete state.
    fs::remove_file(paths.data_root.join("install-v2.json")).unwrap();
    let rejected = recover(&executable);
    assert!(!rejected.verified);
    assert_eq!(rejected.changed, Some(false));
    assert!(!paths.data_root.join("install-v2.json").exists());
    // Construct the retained pending interruption, not a new approval or release.
    publish(&marker, &pending_marker, 0o600);
    assert!(recover(&executable).verified);
    crate::setup::verify_at_read_only(&paths).unwrap();
    assert!(!Path::new("/run/dev-auth/broker.sock").exists());
    assert!(!Path::new("/run/dev-auth/control.sock").exists());
}
