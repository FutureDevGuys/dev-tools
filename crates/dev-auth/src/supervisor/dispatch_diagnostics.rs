//! Value-free observations at the enrolled dispatcher's suppressed error boundary.
use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EnrolledDispatchStage {
    Request,
    Admission,
    IdentityNormalization,
    Authority,
    EnvironmentReceive,
    BoundaryCreate,
    ServiceStart,
    BoundaryAccept,
    BrokerPrepare,
    SupervisorRelease,
    ServiceWait,
    TerminationReceive,
    TerminationSend,
}

impl EnrolledDispatchStage {
    fn diagnostic(self) -> &'static str {
        match self {
            Self::Request => "dev-auth: enrolled workload launch denied: request",
            Self::Admission => "dev-auth: enrolled workload launch denied: admission",
            Self::IdentityNormalization => {
                "dev-auth: enrolled workload launch denied: identity_normalization"
            }
            Self::Authority => "dev-auth: enrolled workload launch denied: authority",
            Self::EnvironmentReceive => {
                "dev-auth: enrolled workload launch denied: environment_receive"
            }
            Self::BoundaryCreate => "dev-auth: enrolled workload launch denied: boundary_create",
            Self::ServiceStart => "dev-auth: enrolled workload launch denied: service_start",
            Self::BoundaryAccept => "dev-auth: enrolled workload launch denied: boundary_accept",
            Self::BrokerPrepare => "dev-auth: enrolled workload launch denied: broker_prepare",
            Self::SupervisorRelease => {
                "dev-auth: enrolled workload launch denied: supervisor_release"
            }
            Self::ServiceWait => "dev-auth: enrolled workload launch denied: service_wait",
            Self::TerminationReceive => {
                "dev-auth: enrolled workload launch denied: termination_receive"
            }
            Self::TerminationSend => "dev-auth: enrolled workload launch denied: termination_send",
        }
    }
}

impl std::fmt::Display for EnrolledDispatchStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.diagnostic())
    }
}

impl std::error::Error for EnrolledDispatchStage {}

/// No error text is inspected or rendered. An untagged request failed before
/// entering the observed dispatcher, and is not classified as a policy denial.
pub fn enrolled_dispatch_diagnostic(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<EnrolledDispatchStage>()
        .copied()
        .unwrap_or(EnrolledDispatchStage::Request)
        .diagnostic()
}

/// Preserve the interactive dispatcher error and every successful exit status.
/// A stage identifies the operation returning an error, never proof of launch,
/// authority, or the underlying reason that operation failed.
pub(super) fn observe_dispatch<T>(
    enrolled: bool,
    operation: impl FnOnce(&mut EnrolledDispatchStage) -> Result<T>,
) -> Result<T> {
    let mut stage = EnrolledDispatchStage::Admission;
    operation(&mut stage).map_err(|error| {
        if enrolled {
            error.context(stage)
        } else {
            error
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrolled_stage_diagnostics_never_render_nested_error_content() {
        for (stage, suffix) in [
            (EnrolledDispatchStage::Request, "request"),
            (EnrolledDispatchStage::Admission, "admission"),
            (
                EnrolledDispatchStage::IdentityNormalization,
                "identity_normalization",
            ),
            (EnrolledDispatchStage::Authority, "authority"),
            (
                EnrolledDispatchStage::EnvironmentReceive,
                "environment_receive",
            ),
            (EnrolledDispatchStage::BoundaryCreate, "boundary_create"),
            (EnrolledDispatchStage::ServiceStart, "service_start"),
            (EnrolledDispatchStage::BoundaryAccept, "boundary_accept"),
            (EnrolledDispatchStage::BrokerPrepare, "broker_prepare"),
            (
                EnrolledDispatchStage::SupervisorRelease,
                "supervisor_release",
            ),
            (EnrolledDispatchStage::ServiceWait, "service_wait"),
            (
                EnrolledDispatchStage::TerminationReceive,
                "termination_receive",
            ),
            (EnrolledDispatchStage::TerminationSend, "termination_send"),
        ] {
            let error = observe_dispatch::<()>(true, |observed| {
                *observed = stage;
                Err(anyhow::anyhow!(
                    "secret=fixture-private-value uid=12345 /private/path argument=private"
                )
                .context("OP_SERVICE_ACCOUNT_TOKEN=fixture-private-token"))
            })
            .unwrap_err()
            .context("private outer context");
            assert_eq!(
                enrolled_dispatch_diagnostic(&error),
                format!("dev-auth: enrolled workload launch denied: {suffix}")
            );
        }
    }

    #[test]
    fn untyped_error_text_cannot_select_an_enrolled_stage() {
        let error = anyhow::anyhow!("broker_prepare secret=fixture-private-value")
            .context("dev-auth: enrolled workload launch denied: termination_send");
        assert_eq!(
            enrolled_dispatch_diagnostic(&error),
            "dev-auth: enrolled workload launch denied: request"
        );
    }

    #[test]
    fn enrolled_caller_rejection_has_an_admission_stage_without_dispatch() {
        let error = crate::supervisor::run_enrolled_dispatcher(
            0,
            "fixture",
            std::path::Path::new("/"),
            0,
            std::path::Path::new("/unused-fixture-socket"),
            &[],
        )
        .unwrap_err();
        assert_eq!(
            enrolled_dispatch_diagnostic(&error),
            "dev-auth: enrolled workload launch denied: admission"
        );
    }

    #[test]
    fn observation_preserves_interactive_errors_and_native_exit_statuses() {
        use std::os::unix::process::ExitStatusExt;
        let error = observe_dispatch::<()>(false, |stage| {
            *stage = EnrolledDispatchStage::BrokerPrepare;
            Err(anyhow::anyhow!("original interactive error"))
        })
        .unwrap_err();
        assert!(error.downcast_ref::<EnrolledDispatchStage>().is_none());
        assert_eq!(error.to_string(), "original interactive error");
        for enrolled in [false, true] {
            for raw_status in [0, 4 << 8, nix::libc::SIGTERM] {
                let status = observe_dispatch(enrolled, |stage| {
                    *stage = EnrolledDispatchStage::TerminationReceive;
                    Ok(std::process::ExitStatus::from_raw(raw_status))
                })
                .unwrap();
                assert_eq!(status.into_raw(), raw_status);
            }
        }
    }
}
