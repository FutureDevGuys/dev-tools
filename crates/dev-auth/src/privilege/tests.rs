use super::{adapter, policy::*, protocol};
use dev_tools_privilege_session::{Cleanup, LeaseState, StopReason};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

fn policy() -> Policy {
    let plan = ExactPlan {
        executable: "/usr/libexec/dev-auth-privilege-native-fixture".into(),
        executable_sha256: "11".repeat(32),
        arguments: vec![
            b"helper".to_vec(),
            b"probe".to_vec(),
            b"/var/tmp/dev-auth-privilege-native-unit/scope/probe".to_vec(),
        ],
        environment: BTreeMap::new(),
        working_directory: "/var/tmp/dev-auth-privilege-native-unit/scope".into(),
        resources: BTreeMap::from([(
            "fixture".into(),
            Resource {
                path: "/var/tmp/dev-auth-privilege-native-unit/scope".into(),
                access: Access::ReadWrite,
            },
        )]),
        input: Vec::new(),
        timeout_seconds: 5,
        output_limit: 8192,
    };
    Policy {
        schema: POLICY_SCHEMA.into(),
        capabilities: BTreeMap::from([(
            "maintenance".into(),
            Capability {
                users: BTreeSet::from([1000]),
                max_idle_seconds: 30,
                max_hard_seconds: 60,
                max_uses: 5,
                operations: BTreeMap::from([(
                    "verify".into(),
                    Operation {
                        protocol: "dev-auth-native-fixture-v1".into(),
                        adapter: None,
                        max_uses: 3,
                        plans: BTreeMap::from([
                            ("first".into(), plan.clone()),
                            ("second".into(), plan),
                        ]),
                    },
                )]),
            },
        )]),
    }
}
fn request() -> Request {
    Request {
        schema: REQUEST_SCHEMA.into(),
        capability: "maintenance".into(),
        owner_uid: 1000,
        idle_seconds: 20,
        hard_seconds: 50,
        total_uses: 4,
        operations: BTreeMap::from([(
            "verify".into(),
            Selection {
                uses: 2,
                plans: BTreeSet::from(["first".into(), "second".into()]),
            },
        )]),
    }
}
fn approved() -> ApprovalPlan {
    resolve(&canonical(&policy()).unwrap(), request(), &"22".repeat(32)).unwrap()
}

#[test]
fn authority_is_explicit_closed_and_canonical() {
    let policy = canonical(&policy()).unwrap();
    let plan = resolve(&policy, request(), &"22".repeat(32)).unwrap();
    let bytes = canonical(&plan).unwrap();
    assert_eq!(
        verify_plan(&bytes, &digest(&bytes), &policy, &"22".repeat(32)).unwrap(),
        plan
    );
    assert!(verify_plan(&bytes, &"00".repeat(32), &policy, &"22".repeat(32)).is_err());
    assert!(verify_plan(&bytes, &digest(&bytes), &policy, &"33".repeat(32)).is_err());
    let mut changed: serde_json::Value = serde_json::from_slice(&policy).unwrap();
    changed["arbitrary_root"] = serde_json::json!(true);
    assert!(parse_policy(&serde_json::to_vec(&changed).unwrap()).is_err());
    let mut expanded = plan.clone();
    expanded.operations.get_mut("verify").unwrap().max_uses = 999;
    let expanded = canonical(&expanded).unwrap();
    assert!(verify_plan(&expanded, &digest(&expanded), &policy, &"22".repeat(32)).is_err());
}
#[test]
fn owner_operation_duration_and_budget_cannot_expand() {
    let bytes = canonical(&policy()).unwrap();
    for change in 0..7 {
        let mut r = request();
        match change {
            0 => r.owner_uid = 0,
            1 => r.owner_uid = 1001,
            2 => r.hard_seconds = 61,
            3 => r.idle_seconds = 31,
            4 => r.total_uses = 6,
            5 => r.operations.get_mut("verify").unwrap().uses = 4,
            _ => {
                r.operations
                    .get_mut("verify")
                    .unwrap()
                    .plans
                    .insert("unapproved".into());
            }
        }
        assert!(resolve(&bytes, r, &"22".repeat(32)).is_err());
    }
}
#[test]
fn incompatible_helper_inputs_and_enforcement_resources_reject() {
    for change in 0..9 {
        let mut p = policy();
        let cap = p.capabilities.get_mut("maintenance").unwrap();
        let operation = cap.operations.get_mut("verify").unwrap();
        let plan = operation.plans.get_mut("first").unwrap();
        match change {
            0 => plan.executable = "relative".into(),
            1 => plan.arguments = vec![vec![0]],
            2 => plan
                .environment
                .insert("LD_PRELOAD".into(), "/tmp/object".into())
                .map(|_| ())
                .unwrap_or(()),
            3 => plan.output_limit = 0,
            4 => plan.timeout_seconds = 0,
            5 => plan.resources.get_mut("fixture").unwrap().path = "/etc".into(),
            6 => plan.resources.get_mut("fixture").unwrap().path = "/sys/fs/cgroup".into(),
            7 => plan.resources.get_mut("fixture").unwrap().path = "/".into(),
            _ => operation.protocol = "arbitrary-exec".into(),
        };
        assert!(parse_policy(&canonical(&p).unwrap()).is_err());
    }
}
#[test]
fn eight_hour_limit_is_not_silently_removed() {
    let mut p = policy();
    p.capabilities
        .get_mut("maintenance")
        .unwrap()
        .max_hard_seconds = 28_801;
    assert!(parse_policy(&canonical(&p).unwrap()).is_err());
}
#[test]
fn same_grant_runs_separate_plans_and_conserves_operation_budget() {
    let p = approved();
    let mut authority = adapter::create(&p, &"44".repeat(32), 1000).unwrap();
    for (i, plan) in ["first", "second"].iter().enumerate() {
        let request =
            adapter::request(&authority, &p, &format!("{:064x}", i + 1), "verify", plan).unwrap();
        let id = authority
            .admit_checked(
                || Duration::from_secs(2 + i as u64),
                request,
                |_, _, _| true,
            )
            .unwrap();
        authority
            .release_checked(
                || Duration::from_secs(2 + i as u64),
                id,
                |_, _, _| true,
                |_| Ok::<_, ()>(()),
            )
            .unwrap();
        authority
            .complete_operation(Duration::from_secs(3 + i as u64), id)
            .unwrap();
        assert_eq!(authority.status().state, LeaseState::Active);
    }
    let request = adapter::request(&authority, &p, &"55".repeat(32), "verify", "first").unwrap();
    assert!(authority
        .admit_checked(|| Duration::from_secs(5), request, |_, _, _| true)
        .is_err());
    assert_eq!(authority.status().remaining_uses, 2);
}
#[test]
fn revoke_between_request_and_gate_prevents_release() {
    let p = approved();
    let mut a = adapter::create(&p, &"44".repeat(32), 1000).unwrap();
    let r = adapter::request(&a, &p, &"55".repeat(32), "verify", "first").unwrap();
    let id = a
        .admit_checked(|| Duration::from_secs(2), r, |_, _, _| true)
        .unwrap();
    a.stop(StopReason::Revoked);
    assert!(a
        .release_checked(
            || Duration::from_secs(2),
            id,
            |_, _, _| true,
            |_| -> Result<(), ()> { panic!("gate must stay closed") }
        )
        .is_err());
    a.report_cleanup(Cleanup::Failed).unwrap();
    assert!(!a.status().state.is_terminal());
}
#[test]
fn control_rejects_unknown_unit_fields_and_payload_replacement() {
    let id = "11".repeat(32);
    for action in [
        serde_json::json!({"operation":"status","duration":999}),
        serde_json::json!({"operation":"revoke","run":"shell"}),
        serde_json::json!({"operation":"execute","name":"verify","plan":"first","arguments":["injected"]}),
    ] {
        let bytes = serde_json::to_vec(
            &serde_json::json!({"version":1,"session":id,"request_id":id,"action":action}),
        )
        .unwrap();
        assert!(protocol::parse_request(&bytes).is_err());
    }
}

#[test]
fn retained_resource_survives_child_creation_but_rejects_path_replacement() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("resource");
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let held = super::custody::HeldResource::open(&path, nix::unistd::getuid().as_raw()).unwrap();
    std::fs::create_dir(path.join("new-child")).unwrap();
    held.verify().unwrap();
    std::fs::rename(&path, root.path().join("old")).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(held.verify().is_err());
}

#[test]
fn resource_ancestor_symlinks_are_never_followed() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = tempfile::tempdir().unwrap();
    let actual = root.path().join("actual");
    std::fs::create_dir(&actual).unwrap();
    std::fs::set_permissions(&actual, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(actual.join("file"), b"data").unwrap();
    symlink(&actual, root.path().join("alias")).unwrap();
    assert!(super::custody::HeldResource::open(
        &root.path().join("alias/file"),
        nix::unistd::getuid().as_raw()
    )
    .is_err());
}

#[test]
fn generic_helpers_and_privilege_persistence_are_not_effect_adapters() {
    for change in 0..3 {
        let mut p = policy();
        let op = p
            .capabilities
            .get_mut("maintenance")
            .unwrap()
            .operations
            .get_mut("verify")
            .unwrap();
        let plan = op.plans.get_mut("first").unwrap();
        match change {
            0 => op.protocol = "dev-auth-reviewed-helper-v1".into(),
            1 => {
                plan.executable = "/usr/bin/install".into();
                plan.arguments = vec![
                    b"-m".to_vec(),
                    b"4755".to_vec(),
                    b"/srv/maintenance/input".to_vec(),
                    b"/srv/maintenance/output".to_vec(),
                ];
            }
            _ => plan.resources.get_mut("fixture").unwrap().path = "/etc/cron.d".into(),
        }
        assert!(parse_policy(&canonical(&p).unwrap()).is_err());
    }
}

#[test]
fn positive_later_cleanup_does_not_erase_a_terminal_failure() {
    let observation = protocol::Observation {
        version: 1,
        outcome: "failed".into(),
        started: Some(true),
        exit_code: Some(1),
        signal: None,
        remaining_uses: 0,
        hard_deadline_boot_ms: 100,
        cleanup_complete: true,
        error_kind: Some("cleanup_failed".into()),
    };
    assert!(!observation.terminal_success());
}

#[test]
fn native_zero_never_masks_failed_or_cancelled_execution() {
    let mut observation = protocol::Observation {
        version: 1,
        outcome: "exited".into(),
        started: Some(true),
        exit_code: Some(0),
        signal: None,
        remaining_uses: 1,
        hard_deadline_boot_ms: 1,
        cleanup_complete: true,
        error_kind: None,
    };
    assert_eq!(observation.execution_exit_code(), 0);
    observation.error_kind = Some("receipt_install_result_unknown".into());
    assert_eq!(observation.execution_exit_code(), 1);
    observation.error_kind = None;
    observation.outcome = "cancelled".into();
    assert_eq!(observation.execution_exit_code(), 1);
    observation.outcome = "failed".into();
    assert_eq!(observation.execution_exit_code(), 1);
    observation.outcome = "exited".into();
    observation.cleanup_complete = false;
    assert_eq!(observation.execution_exit_code(), 1);
    assert_eq!(observation.exit_code, Some(0));
    observation.cleanup_complete = true;
    observation.exit_code = None;
    assert_eq!(observation.execution_exit_code(), 1);
    observation.exit_code = Some(0);
    observation.signal = Some(15);
    assert_eq!(observation.execution_exit_code(), 1);
}
