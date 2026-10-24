#![cfg(target_os = "linux")]
use dev_auth::privilege::grants::policy::{
    Account, ExecutionPlan, ExitPolicy, PlanCommand, PlanPipe, Policy, SubjectPolicy,
};
use dev_auth::privilege::grants::{
    Authority, ControlRequest, Execution, Failure, GrantRequest, GrantScope,
};
use std::time::Duration;

#[test]
fn grant_policy_cannot_be_reinterpreted_as_finite_maintenance_authority() {
    let grant = Policy::template();
    let bytes = serde_json::to_vec(&grant).unwrap();
    assert!(dev_auth::privilege::policy::parse_policy(&bytes).is_err());

    let finite = serde_json::json!({
        "schema": dev_auth::privilege::policy::POLICY_SCHEMA,
        "capabilities": {}
    });
    let bytes = serde_json::to_vec(&finite).unwrap();
    assert!(dev_auth::privilege::policy::parse_policy(&bytes).is_ok());
    assert!(serde_json::from_value::<Policy>(finite.clone()).is_err());

    let mut mislabeled_finite = finite;
    mislabeled_finite["schema"] = dev_auth::privilege::grants::policy::POLICY_SCHEMA.into();
    assert!(dev_auth::privilege::policy::parse_policy(
        &serde_json::to_vec(&mislabeled_finite).unwrap()
    )
    .is_err());

    let mut mislabeled = grant;
    mislabeled.schema = dev_auth::privilege::policy::POLICY_SCHEMA.into();
    assert_eq!(mislabeled.validate(), Err(Failure::InvalidRequest));
}

#[test]
fn every_grant_control_request_rejects_undeclared_authority_fields() {
    let id = "0".repeat(32);
    let execution = Execution {
        program: "/usr/bin/true".into(),
        arguments: vec![],
        working_directory: "/".into(),
        environment: vec![],
        terminal: false,
    };
    for request in [
        ControlRequest::Request { request: request() },
        ControlRequest::Status,
        ControlRequest::Inspect { grant: id.clone() },
        ControlRequest::Exec {
            grant: None,
            execution: execution.clone(),
        },
        ControlRequest::RunPlan {
            grant: None,
            authority: Authority::Typed {
                operations: vec!["inspect".into()],
            },
            terminal: false,
        },
        ControlRequest::SudoRelay {
            grant: id.clone(),
            execution,
        },
        ControlRequest::Delegate {
            grant: id.clone(),
            request: request(),
        },
        ControlRequest::Revoke { grant: id },
        ControlRequest::Leave,
    ] {
        let mut value = serde_json::to_value(&request).unwrap();
        let decoded: ControlRequest = serde_json::from_value(value.clone()).unwrap();
        decoded.validate().unwrap();
        value["caller_pid"] = 1.into();
        assert!(
            serde_json::from_value::<ControlRequest>(value).is_err(),
            "{} accepted an undeclared authority field",
            request.operation()
        );
    }
}

#[test]
fn grant_requests_reject_undeclared_fields_inside_administrator_authority() {
    let mut value = serde_json::to_value(request()).unwrap();
    value["authority"]["scope"] = "workload".into();
    assert!(serde_json::from_value::<GrantRequest>(value).is_err());
}

fn request() -> GrantRequest {
    GrantRequest {
        scope: GrantScope::User,
        authority: Authority::Administrator,
        duration_seconds: 43200,
        idle_seconds: None,
        uses: None,
    }
}
fn policy() -> Policy {
    let mut policy = Policy::template();
    policy.subjects.push(SubjectPolicy {
        account: Account::Unix { uid: 1000 },
        scopes: vec![GrantScope::User, GrantScope::Workload],
        authorities: vec![Authority::Administrator],
        maximum_duration_seconds: 86400,
        idle_timeout_seconds: None,
        maximum_uses: None,
        allow_delegation: true,
    });
    policy
}

#[test]
fn the_template_neither_authorizes_an_account_nor_requires_credentials() {
    let policy = Policy::template();
    policy.validate().unwrap();
    assert_eq!(
        policy.approve_limits(&Account::Unix { uid: 1000 }, &request()),
        Err(Failure::AuthorityDenied)
    );
    let value = serde_json::to_value(policy).unwrap();
    assert!(value.get("credential_slots").is_none());
    assert!(value.get("github").is_none());
}

#[test]
fn no_idle_cutoff_is_imposed_on_an_explicitly_approved_overnight_request() {
    let policy = policy();
    policy.validate().unwrap();
    let limits = policy
        .approve_limits(&Account::Unix { uid: 1000 }, &request())
        .unwrap();
    assert_eq!(limits.hard_timeout(), Duration::from_secs(43200));
    assert_eq!(limits.idle_timeout(), Duration::from_secs(43200));
}

#[test]
fn a_request_cannot_widen_account_scope_time_idle_or_use_policy() {
    let mut policy = policy();
    policy.subjects[0].idle_timeout_seconds = Some(1800);
    policy.subjects[0].maximum_uses = Some(10);
    let mut request = request();
    assert_eq!(
        policy.approve_limits(&Account::Unix { uid: 1000 }, &request),
        Err(Failure::AuthorityDenied)
    );
    request.uses = Some(10);
    let limits = policy
        .approve_limits(&Account::Unix { uid: 1000 }, &request)
        .unwrap();
    assert_eq!(limits.idle_timeout(), Duration::from_secs(1800));
    assert_eq!(
        policy.approve_limits(&Account::Unix { uid: 1001 }, &request),
        Err(Failure::AuthorityDenied)
    );
    request.duration_seconds = 86401;
    assert_eq!(
        policy.approve_limits(&Account::Unix { uid: 1000 }, &request),
        Err(Failure::AuthorityDenied)
    );
    request.duration_seconds = 43200;
    request.idle_seconds = Some(1801);
    assert_eq!(
        policy.approve_limits(&Account::Unix { uid: 1000 }, &request),
        Err(Failure::AuthorityDenied)
    );
    request.idle_seconds = None;
    policy.subjects[0].scopes = vec![GrantScope::Workload];
    assert_eq!(
        policy.approve_limits(&Account::Unix { uid: 1000 }, &request),
        Err(Failure::AuthorityDenied)
    );
}

#[test]
fn policy_rejects_unknown_fields_duplicate_accounts_and_unbound_plan_digests() {
    let policy = policy();
    let mut value = serde_json::to_value(&policy).unwrap();
    value["automatic_approval"] = true.into();
    assert!(serde_json::from_value::<Policy>(value).is_err());
    let mut duplicate = policy.clone();
    duplicate.subjects.push(duplicate.subjects[0].clone());
    assert_eq!(duplicate.validate(), Err(Failure::InvalidRequest));
    let mut unbound = policy;
    unbound.subjects[0].authorities = vec![Authority::ExactPlan {
        sha256: "a".repeat(64),
    }];
    assert_eq!(unbound.validate(), Err(Failure::InvalidRequest));
}

#[test]
fn executable_plans_bind_literal_native_inputs_and_reject_cycles_or_ambiguous_pipes() {
    let node = PlanCommand {
        program: "/usr/bin/printf".into(),
        arguments: vec!["%s".into(), "literal;$text".into()],
        working_directory: "/".into(),
        environment: vec![("LANG".into(), "C".into())],
        run_as: None,
        stdin: None,
        stdout: None,
        stderr: None,
        after: Vec::new(),
    };
    let mut plan = ExecutionPlan {
        nodes: vec![node.clone(), node.clone(), node],
        pipes: vec![PlanPipe { from: 0, to: 1 }],
        exit_policy: ExitPolicy::Pipefail,
        output_limit_bytes: None,
    };
    plan.validate().unwrap();
    let digest = plan.digest().unwrap();
    plan.nodes[0].arguments[1] = "different".into();
    assert_ne!(plan.digest().unwrap(), digest);
    plan.pipes.push(PlanPipe { from: 1, to: 0 });
    assert_eq!(plan.validate(), Err(Failure::InvalidRequest));
    plan.pipes = vec![PlanPipe { from: 0, to: 2 }, PlanPipe { from: 1, to: 2 }];
    assert_eq!(plan.validate(), Err(Failure::InvalidRequest));
}

#[test]
fn empty_completion_dependencies_preserve_the_legacy_plan_digest() {
    let legacy = serde_json::json!({
        "nodes": [{
            "program": "/usr/bin/true",
            "arguments": [],
            "working_directory": "/",
            "environment": []
        }],
        "pipes": [],
        "exit_policy": "last"
    });
    let plan: ExecutionPlan = serde_json::from_value(legacy.clone()).unwrap();
    plan.validate().unwrap();
    assert!(plan.nodes[0].after.is_empty());
    assert!(plan.nodes[0].run_as.is_none());
    assert!(plan.nodes[0].stdin.is_none());
    assert!(plan.nodes[0].stdout.is_none());
    assert!(plan.nodes[0].stderr.is_none());
    assert_eq!(serde_json::to_value(&plan).unwrap(), legacy);
    assert_eq!(
        serde_jcs::to_vec(&plan).unwrap().as_slice(),
        br#"{"exit_policy":"last","nodes":[{"arguments":[],"environment":[],"program":"/usr/bin/true","working_directory":"/"}],"pipes":[]}"#
    );
    assert_eq!(
        plan.digest().unwrap(),
        "7eac7f70fd5579d33e660b9ed97733b95292307d30c2dbe8bbbb74650ca11383"
    );

    for field in ["run_as", "stdin", "stdout", "stderr"] {
        let mut explicit_none = legacy.clone();
        explicit_none["nodes"][0][field] = serde_json::Value::Null;
        let decoded: ExecutionPlan = serde_json::from_value(explicit_none).unwrap();
        assert_eq!(serde_json::to_value(&decoded).unwrap(), legacy);
        assert_eq!(decoded.digest().unwrap(), plan.digest().unwrap());
    }

    let mut explicit_empty = legacy;
    explicit_empty["nodes"][0]["after"] = serde_json::json!([]);
    let decoded: ExecutionPlan = serde_json::from_value(explicit_empty).unwrap();
    assert_eq!(decoded.digest().unwrap(), plan.digest().unwrap());
}

#[test]
fn plan_node_run_as_is_closed_bounded_and_exactly_digest_bound() {
    let legacy = serde_json::json!({
        "nodes": [{"program":"/usr/bin/true", "arguments":[], "working_directory":"/", "environment":[]}],
        "pipes":[], "exit_policy":"last"
    });
    let original: ExecutionPlan = serde_json::from_value(legacy.clone()).unwrap();
    let original_digest = original.digest().unwrap();
    let identity = serde_json::json!({"uid":0, "gid":0, "supplementary_groups":[]});
    let mut selected = legacy.clone();
    selected["nodes"][0]["run_as"] = identity.clone();
    let plan: ExecutionPlan = serde_json::from_value(selected.clone()).unwrap();
    plan.validate().unwrap();
    let selected_digest = plan.digest().unwrap();
    assert_ne!(selected_digest, original_digest);
    assert!(plan.nodes[0]
        .run_as
        .as_ref()
        .unwrap()
        .supplementary_groups
        .is_empty());
    assert_eq!(serde_json::to_value(&plan).unwrap(), selected);
    for identity in [
        serde_json::json!({"uid":1000, "gid":0, "supplementary_groups":[]}),
        serde_json::json!({"uid":0, "gid":1000, "supplementary_groups":[]}),
        serde_json::json!({"uid":0, "gid":0, "supplementary_groups":[1000]}),
    ] {
        selected["nodes"][0]["run_as"] = identity;
        let changed: ExecutionPlan = serde_json::from_value(selected.clone()).unwrap();
        assert_ne!(changed.digest().unwrap(), selected_digest);
        let decoded: ExecutionPlan =
            serde_json::from_slice(&serde_jcs::to_vec(&changed).unwrap()).unwrap();
        assert_eq!(decoded.digest().unwrap(), changed.digest().unwrap());
    }
    selected["nodes"][0]["run_as"] = serde_json::json!({
        "uid":1000, "gid":1000, "supplementary_groups":(0..64_u32).collect::<Vec<_>>()
    });
    serde_json::from_value::<ExecutionPlan>(selected.clone())
        .unwrap()
        .validate()
        .unwrap();
    for invalid in [
        serde_json::json!({"uid":u32::MAX, "gid":0, "supplementary_groups":[]}),
        serde_json::json!({"uid":0, "gid":u32::MAX, "supplementary_groups":[]}),
        serde_json::json!({"uid":0, "gid":0, "supplementary_groups":[u32::MAX]}),
        serde_json::json!({"uid":0, "gid":0, "supplementary_groups":[7,7]}),
        serde_json::json!({"uid":0, "gid":0, "supplementary_groups":(0..65_u32).collect::<Vec<_>>()}),
    ] {
        selected["nodes"][0]["run_as"] = invalid;
        let invalid: ExecutionPlan = serde_json::from_value(selected.clone()).unwrap();
        assert_eq!(invalid.validate(), Err(Failure::InvalidRequest));
        assert_eq!(invalid.digest(), Err(Failure::InvalidRequest));
    }
    for invalid in [
        serde_json::json!({"uid":0, "gid":0}),
        serde_json::json!({"uid":0, "gid":0, "supplementary_groups":null}),
        serde_json::json!({"uid":-1, "gid":0, "supplementary_groups":[]}),
        serde_json::json!({"uid":0, "gid":u64::from(u32::MAX)+1, "supplementary_groups":[]}),
        serde_json::json!({"uid":0.0, "gid":0, "supplementary_groups":[]}),
        serde_json::json!({"uid":0, "gid":0, "supplementary_groups":[], "account":"root"}),
    ] {
        selected["nodes"][0]["run_as"] = invalid;
        assert!(serde_json::from_value::<ExecutionPlan>(selected.clone()).is_err());
    }
}

#[test]
fn plan_node_stream_modes_are_closed_and_each_selected_channel_changes_the_digest() {
    let legacy = serde_json::json!({
        "nodes": [{"program":"/usr/bin/true", "arguments":[], "working_directory":"/", "environment":[]}],
        "pipes":[], "exit_policy":"last"
    });
    let original: ExecutionPlan = serde_json::from_value(legacy.clone()).unwrap();
    for field in ["stdin", "stdout", "stderr"] {
        let mut selected_digests = Vec::new();
        for mode in ["inherit", "null"] {
            let mut selected = legacy.clone();
            selected["nodes"][0][field] = serde_json::json!(mode);
            let plan: ExecutionPlan = serde_json::from_value(selected.clone()).unwrap();
            plan.validate().unwrap();
            let digest = plan.digest().unwrap();
            assert_ne!(digest, original.digest().unwrap());
            assert_eq!(serde_json::to_value(&plan).unwrap(), selected);
            let decoded: ExecutionPlan =
                serde_json::from_slice(&serde_jcs::to_vec(&plan).unwrap()).unwrap();
            assert_eq!(decoded.digest().unwrap(), digest);
            selected_digests.push(digest);
        }
        assert_ne!(selected_digests[0], selected_digests[1]);
        for invalid in [
            serde_json::json!("file"),
            serde_json::json!("pipe"),
            serde_json::json!(true),
            serde_json::json!({"kind":"inherit"}),
        ] {
            let mut selected = legacy.clone();
            selected["nodes"][0][field] = invalid;
            assert!(serde_json::from_value::<ExecutionPlan>(selected).is_err());
        }
    }
}

#[test]
fn plan_pipe_endpoints_reject_stream_modes_that_wiring_would_overwrite() {
    let node = serde_json::json!({
        "program":"/usr/bin/true", "arguments":[], "working_directory":"/", "environment":[]
    });
    let original = serde_json::json!({
        "nodes":[node.clone(),node], "pipes":[{"from":0,"to":1}], "exit_policy":"pipefail"
    });
    serde_json::from_value::<ExecutionPlan>(original.clone())
        .unwrap()
        .validate()
        .unwrap();
    for (index, field) in [(0, "stdout"), (1, "stdin")] {
        for mode in ["inherit", "null"] {
            let mut conflict = original.clone();
            conflict["nodes"][index][field] = serde_json::json!(mode);
            let plan: ExecutionPlan = serde_json::from_value(conflict).unwrap();
            assert_eq!(plan.validate(), Err(Failure::InvalidRequest));
            assert_eq!(plan.digest(), Err(Failure::InvalidRequest));
        }
    }
    let mut allowed = original;
    allowed["nodes"][0]["stdin"] = serde_json::json!("null");
    allowed["nodes"][1]["stdout"] = serde_json::json!("null");
    allowed["nodes"][0]["stderr"] = serde_json::json!("null");
    serde_json::from_value::<ExecutionPlan>(allowed)
        .unwrap()
        .validate()
        .unwrap();
}

#[test]
fn completion_dependencies_are_retained_digest_bound_and_checked_independent_of_source_order() {
    let node = PlanCommand {
        program: "/usr/bin/true".into(),
        arguments: vec![],
        working_directory: "/".into(),
        environment: vec![],
        run_as: None,
        stdin: None,
        stdout: None,
        stderr: None,
        after: Vec::new(),
    };
    let mut plan = ExecutionPlan {
        nodes: vec![node.clone(), node.clone(), node],
        pipes: vec![],
        exit_policy: ExitPolicy::All,
        output_limit_bytes: None,
    };
    let original_digest = plan.digest().unwrap();
    plan.nodes[0].after = vec![2];
    plan.nodes[1].after = vec![0];
    plan.validate().unwrap();
    assert_ne!(plan.digest().unwrap(), original_digest);

    let value = serde_json::to_value(&plan).unwrap();
    assert_eq!(value["nodes"][0]["after"], serde_json::json!([2]));
    assert_eq!(value["nodes"][1]["after"], serde_json::json!([0]));
    let decoded: ExecutionPlan = serde_json::from_value(value).unwrap();
    decoded.validate().unwrap();
    assert_eq!(decoded.digest().unwrap(), plan.digest().unwrap());

    plan.nodes[2].after = vec![1];
    assert_eq!(plan.validate(), Err(Failure::InvalidRequest));
}

#[test]
fn administrator_policy_does_not_approve_undefined_narrow_authority() {
    let policy = policy();
    for authority in [
        Authority::ExactPlan {
            sha256: "b".repeat(64),
        },
        Authority::Typed {
            operations: vec!["missing".into()],
        },
    ] {
        let mut request = request();
        request.authority = authority;
        assert_eq!(
            policy.approve_limits(&Account::Unix { uid: 1000 }, &request),
            Err(Failure::AuthorityDenied)
        );
    }
}

#[test]
fn output_budget_is_optional_digest_bound_and_bounded_by_product_policy() {
    let value = serde_json::json!({
        "nodes": [{"program":"/usr/bin/true", "arguments":[], "working_directory":"/", "environment":[]}],
        "pipes":[], "exit_policy":"last"
    });
    let mut plan: ExecutionPlan = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(plan.output_limit_bytes, None);
    assert_eq!(serde_json::to_value(&plan).unwrap(), value);
    let uncapped = plan.digest().unwrap();
    let mut null = value;
    null["output_limit_bytes"] = serde_json::Value::Null;
    let explicit_none: ExecutionPlan = serde_json::from_value(null).unwrap();
    assert_eq!(explicit_none.digest().unwrap(), uncapped);
    plan.output_limit_bytes = Some(4096);
    plan.validate().unwrap();
    let capped = plan.digest().unwrap();
    assert_ne!(capped, uncapped);
    let decoded: ExecutionPlan =
        serde_json::from_value(serde_json::to_value(&plan).unwrap()).unwrap();
    assert_eq!(decoded.output_limit_bytes, Some(4096));
    assert_eq!(decoded.digest().unwrap(), capped);
    plan.output_limit_bytes = Some(4097);
    assert_ne!(plan.digest().unwrap(), capped);
    for denied in [
        0,
        dev_auth::privilege::grants::policy::MAX_PLAN_OUTPUT_BYTES + 1,
        u64::MAX,
    ] {
        plan.output_limit_bytes = Some(denied);
        assert_eq!(plan.validate(), Err(Failure::InvalidRequest));
        assert_eq!(plan.digest(), Err(Failure::InvalidRequest));
    }
    for denied in [9_007_199_254_740_992_u64, 9_007_199_254_740_993_u64] {
        plan.output_limit_bytes = Some(denied);
        assert_eq!(plan.digest(), Err(Failure::InvalidRequest));
    }
    assert!(serde_json::from_str::<ExecutionPlan>(r#"{"nodes":[{"program":"/usr/bin/true","arguments":[],"working_directory":"/","environment":[]}],"pipes":[],"exit_policy":"last","output_limit_bytes":1.5}"#).is_err());
}

#[test]
fn human_policy_uses_readable_strings_and_preserves_native_argument_bytes() {
    let mut policy = policy();
    policy.operations.insert(
        "inspect".into(),
        ExecutionPlan {
            nodes: vec![PlanCommand {
                program: "/usr/bin/printf".into(),
                arguments: vec!["%s".into(), "literal value".into()],
                working_directory: "/".into(),
                environment: vec![("LANG".into(), "C".into())],
                run_as: None,
                stdin: None,
                stdout: None,
                stderr: None,
                after: Vec::new(),
            }],
            pipes: vec![],
            exit_policy: ExitPolicy::Last,
            output_limit_bytes: None,
        },
    );
    let value = serde_json::to_value(&policy).unwrap();
    assert_eq!(value["sudo_program"], "/usr/bin/sudo");
    assert_eq!(
        value["operations"]["inspect"]["nodes"][0]["arguments"][1],
        "literal value"
    );
    let decoded: Policy = serde_json::from_value(value).unwrap();
    assert_eq!(
        decoded.operations["inspect"].digest().unwrap(),
        policy.operations["inspect"].digest().unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let argument = std::ffi::OsString::from_vec(vec![b'x', 0xff]);
        policy.operations.get_mut("inspect").unwrap().nodes[0]
            .arguments
            .push(argument.clone());
        let value = serde_json::to_value(&policy).unwrap();
        assert_eq!(
            value["operations"]["inspect"]["nodes"][0]["arguments"][2],
            serde_json::json!({"unix_bytes": [120, 255]})
        );
        let decoded: Policy = serde_json::from_value(value).unwrap();
        assert_eq!(
            decoded.operations["inspect"].nodes[0].arguments[2],
            argument
        );
    }
}

#[test]
fn plans_reject_nuls_and_ambiguous_native_environments_before_approval() {
    let mut plan = ExecutionPlan {
        nodes: vec![PlanCommand {
            program: "/usr/bin/printf".into(),
            arguments: vec!["%s".into(), "bad\0argument".into()],
            working_directory: "/".into(),
            environment: vec![],
            run_as: None,
            stdin: None,
            stdout: None,
            stderr: None,
            after: Vec::new(),
        }],
        pipes: vec![],
        exit_policy: ExitPolicy::Last,
        output_limit_bytes: None,
    };
    assert_eq!(plan.validate(), Err(Failure::InvalidRequest));
    plan.nodes[0].arguments.pop();
    for environment in [
        vec![("".into(), "x".into())],
        vec![("A=B".into(), "x".into())],
        vec![("A".into(), "x\0y".into())],
        vec![("A".into(), "x".into()), ("A".into(), "y".into())],
    ] {
        plan.nodes[0].environment = environment;
        assert_eq!(plan.validate(), Err(Failure::InvalidRequest));
    }
}

#[test]
fn ordinary_execution_environments_do_not_expand_to_byte_arrays_on_the_wire() {
    let execution = dev_auth::privilege::grants::Execution {
        program: "/usr/bin/true".into(),
        arguments: vec![],
        working_directory: "/".into(),
        environment: (0..128)
            .map(|index| {
                (
                    format!("PUBLIC_VARIABLE_{index}").into(),
                    "x".repeat(128).into(),
                )
            })
            .collect(),
        terminal: false,
    };
    let encoded = serde_json::to_vec(&execution).unwrap();
    assert!(encoded.len() < 24 * 1024);
    let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(value["program"], "/usr/bin/true");
    let decoded: dev_auth::privilege::grants::Execution = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded.environment, execution.environment);
}
