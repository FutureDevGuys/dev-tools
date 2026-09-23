use dev_auth::privilege::policy::{
    Account, ExecutionPlan, ExitPolicy, PlanCommand, PlanPipe, Policy, SubjectPolicy,
};
use dev_auth::privilege::{Authority, Failure, GrantRequest, GrantScope};
use std::time::Duration;

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
    };
    let mut plan = ExecutionPlan {
        nodes: vec![node.clone(), node.clone(), node],
        pipes: vec![PlanPipe { from: 0, to: 1 }],
        exit_policy: ExitPolicy::Pipefail,
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
            }],
            pipes: vec![],
            exit_policy: ExitPolicy::Last,
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
        }],
        pipes: vec![],
        exit_policy: ExitPolicy::Last,
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
    let execution = dev_auth::privilege::Execution {
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
    let decoded: dev_auth::privilege::Execution = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded.environment, execution.environment);
}
