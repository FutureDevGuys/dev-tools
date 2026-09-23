//! Exercise an existing credential installation gaining receipt-owned privilege
//! without changing its installation purpose or credential authority.
use super::*;

pub(super) fn upgrade_and_restore(
    prior: &SetupPlanV3,
    account: &nix::unistd::User,
    policy: &[u8],
    config: &[u8],
    executable: &Path,
) {
    let paths = &prior.installation.paths;
    let receipt_path = paths.data_root.join("install-v2.json");
    let original_receipt: crate::setup::InstallReceipt =
        serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    let user_config = account
        .dir
        .join(crate::policy_store::USER_CONFIG_V3_RELATIVE_PATH);
    let original_sudo_conf = fs::read("/etc/sudo.conf").ok();
    let privilege_paths = crate::setup_v3::privilege::paths();
    for (_, _, path) in privilege_paths
        .iter()
        .filter(|(_, _, path)| path != Path::new("/etc/sudo.conf"))
    {
        assert!(
            !path.exists(),
            "upgrade fixture requires no privilege component"
        );
    }
    workload::require_credential_operation(account, executable);

    let administrator_source = Path::new("/fixture-input/policy.toml");
    let user_source = Path::new("/fixture-input/config.toml");
    let privilege_source = Path::new("/fixture-input/privilege-policy.json");
    publish(administrator_source, policy, 0o600);
    publish(user_source, config, 0o600);
    let privilege_policy =
        serde_json::to_vec(&crate::privilege::policy::Policy::template()).unwrap();
    publish(privilege_source, &privilege_policy, 0o600);

    let mut intent = prior.intent.clone();
    intent.schema = "dev-auth-deployment-intent-v2".into();
    intent.privilege_policy = Some(privilege_source.into());
    let plan = build_setup_plan_v3_with_reader(
        intent,
        prior.installation.clone(),
        true,
        &read_document,
        &|_| Ok(()),
        Some(policy),
    )
    .unwrap();
    assert_eq!(plan.schema, "dev-auth-setup-plan-v4");
    assert_eq!(
        plan.installation.request.purpose,
        crate::deployment::SetupPurpose::Credentials
    );
    assert_eq!(plan.accounts.len(), 1);
    assert!(!plan.privilege_payload.is_empty());
    let digest = sha256_hex(&serde_jcs::to_vec(&plan).unwrap());
    let lock = crate::setup_transition::lock_path(DeploymentMode::Strong, None).unwrap();
    {
        let _lease = InstallationLock::try_acquire(&lock).unwrap().unwrap();
        crate::setup_transition::begin(paths, 0, &digest, || {
            capture_retained_generation(&plan, &digest)
        })
        .unwrap();
    }
    for source in [administrator_source, user_source, privilege_source] {
        fs::remove_file(source).unwrap();
    }
    let recovered = recover(executable);
    assert!(recovered.verified, "{recovered:?}");
    assert_eq!(recovered.changed, Some(true));
    assert_eq!(
        fs::read(crate::policy_store::SYSTEM_POLICY_PATH).unwrap(),
        policy
    );
    assert_eq!(fs::read(&user_config).unwrap(), config);
    assert!(crate::setup::system_service_credential_slot_ready(
        "automation"
    ));
    let upgraded: crate::setup::InstallReceipt =
        serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    assert_eq!(upgraded.purpose, original_receipt.purpose);
    assert_eq!(upgraded.version, original_receipt.version);
    assert_eq!(
        upgraded.executable_sha256,
        original_receipt.executable_sha256
    );
    assert_eq!(
        fs::read(crate::privilege::SYSTEM_POLICY).unwrap(),
        privilege_policy
    );
    assert_eq!(
        fs::metadata(crate::privilege::SYSTEM_POLICY)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(command(
        Path::new("/usr/bin/systemctl"),
        &["is-active", "dev-auth-privilege.service"]
    )
    .status
    .success());
    assert!(
        command(Path::new("/usr/bin/sudo"), &["-n", "--", "/usr/bin/true"])
            .status
            .success()
    );
    workload::require_credential_operation(account, executable);
    let repeat = recover(executable);
    assert!(repeat.verified, "{repeat:?}");
    assert_eq!(repeat.changed, Some(false));

    let restoration = command(
        executable,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    let restored: crate::setup_v3::restoration::SetupRestorationReportV1 =
        serde_json::from_slice(&restoration.stdout).unwrap();
    assert_eq!(restoration.status.code(), Some(restored.exit_code));
    assert!(restored.verified, "{restored:?}");
    assert_eq!(restored.changed, Some(true));
    assert_eq!(
        fs::read(crate::policy_store::SYSTEM_POLICY_PATH).unwrap(),
        policy
    );
    assert_eq!(fs::read(&user_config).unwrap(), config);
    assert!(crate::setup::system_service_credential_slot_ready(
        "automation"
    ));
    let restored_receipt: crate::setup::InstallReceipt =
        serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    assert_eq!(restored_receipt.purpose, original_receipt.purpose);
    assert_eq!(restored_receipt.version, original_receipt.version);
    assert_eq!(
        restored_receipt.executable_sha256,
        original_receipt.executable_sha256
    );
    assert!(restored_receipt.transparent_aliases.is_empty());
    assert_eq!(fs::read("/etc/sudo.conf").ok(), original_sudo_conf);
    for (_, _, path) in privilege_paths
        .iter()
        .filter(|(_, _, path)| path != Path::new("/etc/sudo.conf"))
    {
        assert!(!path.exists(), "restoration left a privilege component");
    }
    let repeat = command(
        executable,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    let unchanged: crate::setup_v3::restoration::SetupRestorationReportV1 =
        serde_json::from_slice(&repeat.stdout).unwrap();
    assert_eq!(repeat.status.code(), Some(unchanged.exit_code));
    assert!(unchanged.verified);
    assert_eq!(unchanged.changed, Some(false));
    publish(
        Path::new("/fixture/privilege-combined-result.json"),
        b"{\"schema\":\"dev-auth-native-combined-setup-v1\",\"passed\":true,\"credential_preserved\":true,\"privilege_receipted\":true,\"signed_release\":false}\n",
        0o644,
    );
}
