use super::model::{Envelope, FRAME_LIMIT, WIRE_SCHEMA};
use super::{ControlRequest, ControlResult, Failure};

/// Send one control request over an authenticated native connection. This never
/// obtains a password or retries an entered mutation after an uncertain reply.
pub fn control(request: ControlRequest) -> ControlResult {
    control_inner(request, None)
}

#[cfg(target_os = "linux")]
pub(crate) fn activate_bootstrap(
    grant: String,
    proof: &std::os::fd::OwnedFd,
    spawn: &std::os::fd::OwnedFd,
    release: &std::os::fd::OwnedFd,
) -> ControlResult {
    use std::os::fd::AsRawFd;
    control_inner(
        ControlRequest::ActivateLaunch {
            grant,
            bootstrap: true,
        },
        Some([proof.as_raw_fd(), spawn.as_raw_fd(), release.as_raw_fd()]),
    )
}

fn control_inner(request: ControlRequest, launch: Option<[i32; 3]>) -> ControlResult {
    let operation = request.operation();
    if let Err(failure) = request.validate() {
        return ControlResult::failure(operation, failure, Some(false));
    }
    let frame = serde_json::to_vec(&Envelope {
        schema: WIRE_SCHEMA.to_owned(),
        request: request.clone(),
    });
    let frame = match frame {
        Ok(frame) if frame.len() <= FRAME_LIMIT => frame,
        _ => return ControlResult::failure(operation, Failure::InvalidRequest, Some(false)),
    };
    #[cfg(target_os = "linux")]
    {
        let execution = request.execution_terminal();
        let deadline = if matches!(
            request,
            ControlRequest::Request { .. } | ControlRequest::LaunchRequest { .. }
        ) {
            330
        } else if matches!(
            request,
            ControlRequest::ActivateLaunch {
                bootstrap: true,
                ..
            }
        ) {
            35
        } else if execution.is_some() {
            10
        } else {
            15
        };
        let endpoint = std::env::var_os("DEV_AUTH_GRANT_SOCKET")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| super::SYSTEM_SOCKET.into());
        if !endpoint.is_absolute() {
            return ControlResult::failure(operation, Failure::InvalidRequest, Some(false));
        }
        let approval = matches!(
            request,
            ControlRequest::Request { .. } | ControlRequest::LaunchRequest { .. }
        );
        let response = if let Some(launch) = &launch {
            super::transport::exchange_with_launch_descriptors(
                &endpoint,
                &frame,
                execution,
                deadline,
                approval,
                Some(launch),
            )
        } else {
            super::transport::exchange(&endpoint, &frame, execution, deadline, approval)
        };
        match response {
            Ok(bytes) => match serde_json::from_slice::<ControlResult>(&bytes) {
                Ok(response)
                    if response.schema == super::RESULT_SCHEMA
                        && response.operation == operation =>
                {
                    response
                }
                _ => ControlResult::failure(
                    operation,
                    Failure::ProtocolViolation,
                    request.is_observation().then_some(false),
                ),
            },
            Err((failure, progress)) => ControlResult::failure(
                operation,
                failure,
                if request.is_observation() {
                    Some(false)
                } else {
                    progress
                },
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (frame, launch);
        ControlResult::failure(operation, Failure::NativeUnavailable, Some(false))
    }
}
