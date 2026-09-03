#![cfg(target_os = "linux")]

use std::cell::RefCell;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::Result;
use dev_auth::setup_authorization::{
    authorize_strong_apply_with, SetupApplyCredentialInput, StrongSetupApplyAuthorization,
    StrongSetupApplyAuthorizationOutcome,
};
use dev_tools_privilege::{
    ExactHelperRequest, PrivilegeAuthorizer, PrivilegeOutcome, ProcessTermination, StdioPolicy,
    UnavailableReason, UserInteraction,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedRequest {
    helper: PathBuf,
    arguments: Vec<OsString>,
    deadline_is_none: bool,
    interaction: UserInteraction,
    stdio: StdioPolicy,
}

struct FakeAuthorizer {
    calls: RefCell<Vec<CapturedRequest>>,
    outcome: PrivilegeOutcome,
}

impl FakeAuthorizer {
    fn returning(outcome: PrivilegeOutcome) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            outcome,
        }
    }
}

impl PrivilegeAuthorizer for FakeAuthorizer {
    fn authorize_and_run_exact_helper(
        &self,
        request: &ExactHelperRequest<'_>,
    ) -> Result<PrivilegeOutcome> {
        self.calls.borrow_mut().push(CapturedRequest {
            helper: request.helper.to_path_buf(),
            arguments: request.arguments.to_vec(),
            deadline_is_none: request.deadline.is_none(),
            interaction: request.interaction,
            stdio: request.stdio,
        });
        Ok(self.outcome)
    }
}

#[test]
fn strong_apply_authorizes_one_exact_helper_transaction() {
    let request = StrongSetupApplyAuthorization::new(
        "/run/dev-auth/setup/approved.plan.json",
        "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90",
        "json",
        vec![
            SetupApplyCredentialInput::file("second", "/run/dev-auth/credentials/second.secret"),
            SetupApplyCredentialInput::stdin("first"),
        ],
    )
    .unwrap();
    let authorizer = FakeAuthorizer::returning(PrivilegeOutcome::Exited(ProcessTermination {
        code: Some(3),
        signal: None,
    }));

    let outcome = authorize_strong_apply_with(&authorizer, &request).unwrap();

    assert_eq!(
        outcome,
        StrongSetupApplyAuthorizationOutcome::HelperExited(ProcessTermination {
            code: Some(3),
            signal: None,
        })
    );
    assert_eq!(authorizer.calls.borrow().len(), 1);
    assert_eq!(
        authorizer.calls.borrow()[0],
        CapturedRequest {
            helper: PathBuf::from("/usr/local/lib/dev-auth/dev-auth-setup-helper"),
            arguments: vec![
                "apply-v3".into(),
                "--plan".into(),
                "/run/dev-auth/setup/approved.plan.json".into(),
                "--sha256".into(),
                "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".into(),
                "--credential-stdin".into(),
                "first".into(),
                "--credential-file".into(),
                "second=/run/dev-auth/credentials/second.secret".into(),
                "--format".into(),
                "json".into(),
            ],
            deadline_is_none: true,
            interaction: UserInteraction::Allowed,
            stdio: StdioPolicy::Inherit,
        }
    );
}

#[test]
fn strong_apply_request_rejects_noncanonical_or_ambiguous_inputs() {
    let digest = "0".repeat(64);
    let cases = [
        StrongSetupApplyAuthorization::new("relative.plan", &digest, "json", Vec::new()),
        StrongSetupApplyAuthorization::new(
            "/run/dev-auth/../dev-auth/setup.plan",
            &digest,
            "json",
            Vec::new(),
        ),
        StrongSetupApplyAuthorization::new(
            "/run//dev-auth/setup.plan",
            &digest,
            "json",
            Vec::new(),
        ),
        StrongSetupApplyAuthorization::new("/run/dev-auth/setup.plan", "0", "json", Vec::new()),
        StrongSetupApplyAuthorization::new(
            "/run/dev-auth/setup.plan",
            "g".repeat(64),
            "json",
            Vec::new(),
        ),
        StrongSetupApplyAuthorization::new("/run/dev-auth/setup.plan", &digest, "yaml", Vec::new()),
        StrongSetupApplyAuthorization::new(
            "/run/dev-auth/setup.plan",
            &digest,
            "human",
            vec![SetupApplyCredentialInput::stdin("")],
        ),
        StrongSetupApplyAuthorization::new(
            "/run/dev-auth/setup.plan",
            &digest,
            "human",
            vec![
                SetupApplyCredentialInput::stdin("automation"),
                SetupApplyCredentialInput::file("automation", "/run/secret"),
            ],
        ),
        StrongSetupApplyAuthorization::new(
            "/run/dev-auth/setup.plan",
            &digest,
            "human",
            vec![
                SetupApplyCredentialInput::stdin("automation"),
                SetupApplyCredentialInput::stdin("secondary"),
            ],
        ),
        StrongSetupApplyAuthorization::new(
            "/run/dev-auth/setup.plan",
            &digest,
            "human",
            vec![SetupApplyCredentialInput::file(
                "automation",
                "relative.secret",
            )],
        ),
        StrongSetupApplyAuthorization::new(
            "/run/dev-auth/setup.plan",
            &digest,
            "human",
            vec![SetupApplyCredentialInput::file(
                "automation",
                "/run/dev-auth/../secret",
            )],
        ),
        StrongSetupApplyAuthorization::new(
            "/run/dev-auth/setup.plan",
            &digest,
            "human",
            vec![SetupApplyCredentialInput::file_descriptor("automation", 7)],
        ),
    ];

    for result in cases {
        assert!(result.is_err());
    }
}

#[test]
fn strong_apply_coarsens_nonterminal_authorizer_outcomes() {
    let request = StrongSetupApplyAuthorization::new(
        Path::new("/run/dev-auth/setup.plan"),
        "f".repeat(64),
        "human",
        Vec::new(),
    )
    .unwrap();

    for privilege_outcome in [
        PrivilegeOutcome::Denied,
        PrivilegeOutcome::Cancelled,
        PrivilegeOutcome::TimedOut,
    ] {
        let authorizer = FakeAuthorizer::returning(privilege_outcome);
        assert_eq!(
            authorize_strong_apply_with(&authorizer, &request).unwrap(),
            StrongSetupApplyAuthorizationOutcome::AuthorizationNotCompleted
        );
        assert_eq!(authorizer.calls.borrow().len(), 1);
    }

    let authorizer = FakeAuthorizer::returning(PrivilegeOutcome::Unavailable(
        UnavailableReason::AuthorizationProgram,
    ));
    assert_eq!(
        authorize_strong_apply_with(&authorizer, &request).unwrap(),
        StrongSetupApplyAuthorizationOutcome::Unavailable(UnavailableReason::AuthorizationProgram)
    );
    assert_eq!(authorizer.calls.borrow().len(), 1);
}
