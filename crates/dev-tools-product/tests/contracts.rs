use dev_tools_product::{
    BuildInfo, BuildProfile, CacheFreshness, CommonOperation, ErrorKind, ExitCategory,
    InstallationState, OperationOutcome, OperationResult, ProductId, SourceState,
    BUILD_INFO_JSON_SCHEMA, BUILD_INFO_SCHEMA, OPERATION_RESULT_JSON_SCHEMA,
    OPERATION_RESULT_SCHEMA,
};

#[test]
fn common_operation_result_has_stable_schema_and_success_contract() {
    let result = OperationResult::completed(
        ProductId::parse("demo-tool").expect("valid product id"),
        CommonOperation::UpdateStatus,
        OperationOutcome::Current,
        false,
    )
    .expect("valid completed outcome")
    .with_installation_state(InstallationState::Managed)
    .with_cache_freshness(CacheFreshness::Fresh)
    .with_versions(Some("1.2.3"), Some("1.2.3"));
    let value = serde_json::to_value(result).expect("serialize operation result");

    assert_eq!(OPERATION_RESULT_SCHEMA, "dev-tools-operation-result-v1");
    assert_eq!(value["schema"], "dev-tools-operation-result-v1");
    assert_eq!(value["product"], "demo-tool");
    assert_eq!(value["operation"], "update_status");
    assert_eq!(value["outcome"], "current");
    assert_eq!(value["changed"], false);
    assert_eq!(value["exit_code"], 0);
    assert_eq!(value["installation_state"], "managed");
    assert_eq!(value["cache_freshness"], "fresh");
    assert_eq!(value["installed_version"], "1.2.3");
    assert_eq!(value["available_version"], "1.2.3");
    assert!(value.get("error_kind").is_none());
}

#[test]
fn exit_categories_are_stable_and_complete() {
    assert_eq!(ExitCategory::Completed.code(), 0);
    assert_eq!(ExitCategory::OperationalFailure.code(), 1);
    assert_eq!(ExitCategory::InvalidInput.code(), 2);
    assert_eq!(ExitCategory::Blocked.code(), 3);
    assert_eq!(ExitCategory::AuthorityViolation.code(), 4);
    assert_eq!(ExitCategory::Interrupted.code(), 130);
}

#[test]
fn blocked_and_failed_results_carry_only_fixed_error_kinds() {
    let product = ProductId::parse("demo-tool").expect("valid product id");
    let blocked = OperationResult::blocked(
        product.clone(),
        CommonOperation::UpdateInstall,
        OperationOutcome::RequiresSetup,
        ErrorKind::RequiresSetup,
    )
    .expect("valid blocked outcome");
    let violation = OperationResult::failed(
        product,
        CommonOperation::UpdateApply,
        OperationOutcome::IntegrityViolation,
        ExitCategory::AuthorityViolation,
        ErrorKind::Integrity,
    )
    .expect("valid failure category");

    let blocked = serde_json::to_value(blocked).expect("serialize blocked result");
    let violation = serde_json::to_value(violation).expect("serialize failure result");
    assert_eq!(blocked["exit_code"], 3);
    assert_eq!(blocked["error_kind"], "requires_setup");
    assert_eq!(violation["exit_code"], 4);
    assert_eq!(violation["error_kind"], "integrity");
    assert!(!violation.to_string().contains("caller-controlled"));
}

#[test]
fn result_construction_rejects_inconsistent_failure_categories() {
    let error = OperationResult::failed(
        ProductId::parse("demo-tool").expect("valid product id"),
        CommonOperation::Doctor,
        OperationOutcome::Failed,
        ExitCategory::Completed,
        ErrorKind::Operational,
    )
    .expect_err("completed is not a failure category");

    assert_eq!(
        error.to_string(),
        "operation result category is inconsistent"
    );
}

#[test]
fn result_construction_rejects_outcome_and_error_kind_confusion() {
    let product = ProductId::parse("demo-tool").expect("valid product id");
    assert!(OperationResult::completed(
        product.clone(),
        CommonOperation::UpdateApply,
        OperationOutcome::IntegrityViolation,
        false,
    )
    .is_err());
    assert!(OperationResult::blocked(
        product.clone(),
        CommonOperation::UpdateInstall,
        OperationOutcome::RequiresSetup,
        ErrorKind::Unsupported,
    )
    .is_err());
    assert!(OperationResult::failed(
        product,
        CommonOperation::UpdateCheck,
        OperationOutcome::Failed,
        ExitCategory::AuthorityViolation,
        ErrorKind::Network,
    )
    .is_err());
}

#[test]
fn product_ids_are_bounded_ascii_tokens() {
    for valid in ["update-all", "dev-auth", "x1"] {
        assert_eq!(ProductId::parse(valid).expect("valid id").as_str(), valid);
    }
    for invalid in ["", "-tool", "Tool", "tool_name", "tool/name", "tool name"] {
        assert!(ProductId::parse(invalid).is_err(), "accepted {invalid:?}");
    }
    assert!(ProductId::parse("a".repeat(65)).is_err());
}

#[test]
fn build_info_has_checkout_independent_stable_identity() {
    let info = BuildInfo::new(
        ProductId::parse("demo-tool").expect("valid product id"),
        "1.2.3",
        "0123456789abcdef0123456789abcdef01234567",
        SourceState::Clean,
        "x86_64-unknown-linux-gnu",
        BuildProfile::Release,
        1_788_000_000,
    )
    .expect("valid build info");
    let value = serde_json::to_value(info).expect("serialize build info");

    assert_eq!(BUILD_INFO_SCHEMA, "dev-tools-build-info-v1");
    assert_eq!(value["schema"], BUILD_INFO_SCHEMA);
    assert_eq!(value["product"], "demo-tool");
    assert_eq!(value["version"], "1.2.3");
    assert_eq!(
        value["source_commit"],
        "0123456789abcdef0123456789abcdef01234567"
    );
    assert_eq!(value["source_state"], "clean");
    assert_eq!(value["target"], "x86_64-unknown-linux-gnu");
    assert_eq!(value["profile"], "release");
    assert_eq!(value["built_unix"], 1_788_000_000_u64);
    assert!(!value.to_string().contains("/home/"));
}

#[test]
fn build_info_maps_shared_compile_time_values_without_product_branches() {
    let info = BuildInfo::from_build_values(
        ProductId::parse("demo-tool").expect("valid product id"),
        "1.2.3",
        Some("0123456789abcdef0123456789abcdef01234567"),
        Some("0"),
        Some("x86_64-unknown-linux-gnu"),
        Some("release"),
        Some("1788000000"),
    )
    .expect("valid compile-time build values");
    let value = serde_json::to_value(info).expect("serialize build info");

    assert_eq!(value["source_state"], "clean");
    assert_eq!(value["profile"], "release");
    assert_eq!(value["built_unix"], 1_788_000_000_u64);
}

#[test]
fn embedded_public_schemas_are_valid_and_observationally_extensible() {
    for (document, schema_name) in [
        (OPERATION_RESULT_JSON_SCHEMA, OPERATION_RESULT_SCHEMA),
        (BUILD_INFO_JSON_SCHEMA, BUILD_INFO_SCHEMA),
    ] {
        let schema: serde_json::Value =
            serde_json::from_str(document).expect("public schema is valid JSON");
        assert_eq!(schema["properties"]["schema"]["const"], schema_name);
        assert_eq!(schema["additionalProperties"], true);
    }
}
