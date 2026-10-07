//! External-crate checks exercise the production cfg, unlike unit-test cfg.
#![cfg(target_os = "linux")]
use dev_auth::privilege::policy;

fn fixture(protocol: &str, executable: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema": "dev-auth-privilege-policy-v1",
        "capabilities": { "fixture": {
            "users": [1000], "max_idle_seconds": 10, "max_hard_seconds": 20,
            "max_uses": 2, "operations": { "fixture": {
                "protocol": protocol, "max_uses": 2, "plans": { "probe": {
                    "executable": executable, "executable_sha256": "11".repeat(32),
                    "arguments": [b"helper".to_vec(), b"probe".to_vec(), b"/var/tmp/dev-auth-privilege-native-contract/scope/probe".to_vec()],
                    "environment": {}, "working_directory": "/",
                    "resources": { "scope": { "path": "/var/tmp/dev-auth-privilege-native-contract/scope", "access": "read_write" } },
                    "input": [], "timeout_seconds": 5, "output_limit": 8192
                } }
            } }
        } }
    })).unwrap()
}

#[test]
fn no_generic_executable_protocol_in_any_build() {
    assert!(
        policy::parse_policy(&fixture("dev-auth-reviewed-helper-v1", "/usr/bin/install")).is_err()
    );
    assert!(
        policy::parse_policy(&fixture("dev-auth-native-fixture-v1", "/usr/bin/install")).is_err()
    );
}

#[cfg(not(feature = "native-privilege-fixture"))]
#[test]
fn ordinary_product_build_has_no_synthetic_effect_adapter() {
    assert!(policy::parse_policy(&fixture(
        "dev-auth-native-fixture-v1",
        "/usr/libexec/dev-auth-privilege-native-fixture"
    ))
    .is_err());
}

#[cfg(feature = "native-privilege-fixture")]
#[test]
fn only_explicit_test_feature_admits_closed_fixture_definition() {
    assert!(policy::parse_policy(&fixture(
        "dev-auth-native-fixture-v1",
        "/usr/libexec/dev-auth-privilege-native-fixture"
    ))
    .is_ok());
}

#[test]
fn absence_of_capabilities_is_deny_all() {
    let bytes = br#"{"schema":"dev-auth-privilege-policy-v1","capabilities":{}}"#;
    assert!(policy::parse_policy(bytes).unwrap().capabilities.is_empty());
}

#[test]
fn ordinary_contract_admits_the_closed_receipt_adapter_without_reading_root_state() {
    use dev_auth::privilege::receipt_install as effect;
    use std::collections::{BTreeMap, BTreeSet};
    let wire = effect::Request {
        action: effect::Action::Install,
        binary: "tool".into(),
        candidate: effect::Artifact {
            generation: format!(
                "/var/lib/dev-tools-maintenance/generations/example-{}",
                "11".repeat(32)
            ),
            receipt_sha256: format!("sha256:{}", "11".repeat(32)),
            source_fingerprint: format!("sha256:{}", "22".repeat(32)),
        },
        destination: "/opt/dev-tools-maintenance/approved/bin".into(),
        journal: "/var/lib/dev-tools-maintenance/journals/approved/tool".into(),
        previous: None,
        schema: effect::PROTOCOL.into(),
        tool: "tool".into(),
    };
    let plan = policy::ExactPlan {
        executable: "/usr/local/lib/dev-tools-maintenance/executors/reviewed/executor".into(),
        executable_sha256: "33".repeat(32),
        arguments: vec![b"maintenance-v1".to_vec()],
        environment: BTreeMap::new(),
        working_directory: "/".into(),
        resources: effect::resources(&wire),
        input: policy::canonical(&wire).unwrap(),
        timeout_seconds: 5,
        output_limit: 8192,
    };
    let op = policy::Operation {
        protocol: effect::PROTOCOL.into(),
        adapter: Some(effect::ExecutorBinding {
            receipt_path:
                "/usr/local/lib/dev-tools-maintenance/executors/reviewed/executor-v1.json".into(),
            receipt_sha256: "44".repeat(32),
            source_fingerprint: format!("sha256:{}", "55".repeat(32)),
            build_receipt_sha256: format!("sha256:{}", "66".repeat(32)),
        }),
        max_uses: 2,
        plans: BTreeMap::from([("install".into(), plan)]),
    };
    let value = policy::Policy {
        schema: policy::POLICY_SCHEMA.into(),
        capabilities: BTreeMap::from([(
            "approved".into(),
            policy::Capability {
                users: BTreeSet::from([1000]),
                max_idle_seconds: 10,
                max_hard_seconds: 20,
                max_uses: 2,
                operations: BTreeMap::from([("receipt".into(), op)]),
            },
        )]),
    };
    let bytes = policy::canonical(&value).unwrap();
    assert!(policy::parse_policy(&bytes).is_ok());
    // Public planning validates declarative authority without elevating or
    // opening private generations. Root native admission remains a later gate.
    for target in [
        "/usr/local/bin",
        "/etc/cron.d",
        "/usr/libexec",
        "/var/lib/dev-auth",
        "/usr/local/lib/dev-tools-maintenance/executors/reviewed",
    ] {
        let mut changed = value.clone();
        changed
            .capabilities
            .get_mut("approved")
            .unwrap()
            .operations
            .get_mut("receipt")
            .unwrap()
            .plans
            .get_mut("install")
            .unwrap()
            .resources
            .get_mut("destination")
            .unwrap()
            .path = target.into();
        assert!(policy::parse_policy(&policy::canonical(&changed).unwrap()).is_err());
    }
}
