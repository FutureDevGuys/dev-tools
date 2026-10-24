use super::model::{Envelope, FRAME_LIMIT, WIRE_SCHEMA};
use super::{ControlRequest, ControlResult, Failure};

/// Send one control request over an authenticated native connection. This never
/// obtains a password or retries an entered mutation after an uncertain reply.
pub fn control(request: ControlRequest) -> ControlResult {
    control_inner(request, None, None)
}

/// Send one `run` request with the program's open descriptor beside it. The
/// coordinator digests and executes exactly that descriptor (ADR 0139).
pub fn run_program(request: ControlRequest, program: &std::fs::File) -> ControlResult {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        control_inner(request, None, Some(program.as_raw_fd()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = program;
        control_inner(request, None, None)
    }
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
        None,
    )
}

fn control_inner(
    request: ControlRequest,
    launch: Option<[i32; 3]>,
    program: Option<i32>,
) -> ControlResult {
    let operation = request.operation();
    if let Err(failure) = request.validate() {
        return ControlResult::failure(operation, failure, Some(false));
    }
    if matches!(request, ControlRequest::Run { .. }) != program.is_some() {
        return ControlResult::failure(operation, Failure::InvalidRequest, Some(false));
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
        let approval = matches!(
            request,
            ControlRequest::Request { .. }
                | ControlRequest::LaunchRequest { .. }
                | ControlRequest::Run { .. }
        );
        let deadline = if approval {
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
            // Revocation and `leave` wait for the stopped work (ADR 0141).
            super::STOP_SETTLE.as_secs() as u32 + 10
        };
        let endpoint = std::env::var_os("DEV_AUTH_GRANT_SOCKET")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| super::SYSTEM_SOCKET.into());
        if !endpoint.is_absolute() {
            return ControlResult::failure(operation, Failure::InvalidRequest, Some(false));
        }
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
            super::transport::exchange(&endpoint, &frame, execution, deadline, approval, program)
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
        let _ = (frame, launch, program);
        ControlResult::failure(operation, Failure::NativeUnavailable, Some(false))
    }
}
