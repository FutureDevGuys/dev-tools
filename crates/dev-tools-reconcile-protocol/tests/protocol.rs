use dev_tools_reconcile_protocol::{ReconcileResult, RESULT_JSON_SCHEMA, RESULT_SCHEMA};

#[test]
fn published_json_schema_is_the_same_strict_wire_contract() {
    let schema: serde_json::Value = serde_json::from_str(RESULT_JSON_SCHEMA).unwrap();
    assert_eq!(schema["$id"], "https://futuredevguys.github.io/dev-tools/schemas/dev-tools-reconcile-result-v1.schema.json");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["properties"]["schema"]["const"], RESULT_SCHEMA);
    assert_eq!(
        schema["properties"]["next_action"]["pattern"],
        "^[a-z0-9_-]{1,128}$"
    );
}

#[test]
fn result_constructors_preserve_the_fixed_value_free_wire_contract() {
    let planned = ReconcileResult::change_required("apply").unwrap();
    assert!(planned.changed);
    assert!(!planned.verified);
    assert!(!planned.deferred);
    assert_eq!(planned.next_action, "apply");

    let changed = ReconcileResult::changed();
    assert_eq!(changed.schema, RESULT_SCHEMA);
    assert!(changed.changed);
    assert!(changed.verified);
    assert!(!changed.deferred);
    assert!(changed.input_required.is_empty());
    assert_eq!(changed.next_action, "none");
    assert!(changed.diagnostics.is_empty());

    let deferred = ReconcileResult::deferred("setup", ["system_installation_absent"]).unwrap();
    assert!(!deferred.changed);
    assert!(!deferred.verified);
    assert!(deferred.deferred);
    assert_eq!(deferred.next_action, "setup");
    assert_eq!(deferred.diagnostics, ["system_installation_absent"]);

    let input = ReconcileResult::input_required("enroll", ["automation"]).unwrap();
    assert!(!input.changed);
    assert!(!input.verified);
    assert!(!input.deferred);
    assert_eq!(input.input_required, ["automation"]);
    assert_eq!(input.next_action, "enroll");
}

#[test]
fn protocol_rejects_secret_shaped_or_ambiguous_public_tokens() {
    let invalid = [
        "".to_owned(),
        "contains space".to_owned(),
        "vault/item/field".to_owned(),
        "token=value".to_owned(),
        "UPPERCASE".to_owned(),
        "../escape".to_owned(),
        "a".repeat(129),
    ];
    for invalid in invalid {
        assert!(ReconcileResult::deferred("setup", [invalid]).is_err());
    }
    assert!(ReconcileResult::deferred("next action", ["blocked"]).is_err());
    assert!(ReconcileResult::input_required("enroll", ["slot=secret"]).is_err());
}

#[test]
fn canonical_result_bytes_and_digest_are_stable() {
    let result = ReconcileResult::deferred(
        "start_broker",
        ["administrator_policy_absent", "system_broker_unavailable"],
    )
    .unwrap();
    let first = result.canonical().unwrap();
    let second = result.canonical().unwrap();
    assert_eq!(first, second);
    assert_eq!(first.sha256.len(), 64);
    assert!(first.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let decoded: serde_json::Value = serde_json::from_slice(&first.bytes).unwrap();
    assert_eq!(decoded["schema"], RESULT_SCHEMA);
    assert_eq!(decoded["next_action"], "start_broker");
}
