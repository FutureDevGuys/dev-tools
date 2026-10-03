//! Native-argument workload invocation; definitions also drive static completion.
use crate::execution_result::{ExecutionResult, ResultDestination};
use clap::{builder::OsStringValueParser, Arg, ArgAction, Command, ValueHint};
use std::ffi::{OsStr, OsString};
use std::path::Path;

pub(super) fn specification() -> Command {
    Command::new("launch")
        .bin_name("dev-auth workload launch")
        .about("Launch a configured workload with native argument and stream handling")
        .disable_help_subcommand(true)
        .arg(Arg::new("name").required(true))
        .arg(
            Arg::new("non-interactive")
                .long("non-interactive")
                .help("Return promptly when admission requires interactive approval")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("result-file")
                .long("result-file")
                .help("Write a separate value-free execution result to a new private file")
                .value_hint(ValueHint::FilePath)
                .value_parser(OsStringValueParser::new()),
        )
        .arg(
            Arg::new("arguments")
                .last(true)
                .num_args(0..)
                .allow_hyphen_values(true)
                .value_parser(OsStringValueParser::new()),
        )
}

pub(super) fn run(arguments: Vec<OsString>) -> anyhow::Result<i32> {
    let has_separator = arguments.iter().any(|arg| arg == OsStr::new("--"));
    let parsed = specification()
        .try_get_matches_from(std::iter::once(OsString::from("launch")).chain(arguments));
    let parsed = match parsed {
        Ok(parsed) => parsed,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            use std::io::Write;
            return Ok(
                if std::io::stdout()
                    .lock()
                    .write_all(help().as_bytes())
                    .is_ok()
                {
                    0
                } else {
                    1
                },
            );
        }
        Err(_) => {
            eprintln!("dev-auth: invalid workload launch invocation");
            return Ok(2);
        }
    };
    if !has_separator {
        eprintln!("dev-auth: workload launch requires -- before workload arguments");
        return Ok(2);
    }
    let Some(name) = parsed.get_one::<String>("name") else {
        return Ok(2);
    };
    if name.is_empty()
        || name.len() > 64
        || !name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        eprintln!("dev-auth: invalid workload name");
        return Ok(2);
    }
    let destination = parsed.get_one::<OsString>("result-file");
    let result_sink = match destination
        .map(|path| ResultDestination::reserve(Path::new(path)))
        .transpose()
    {
        Ok(sink) => sink,
        Err(_) => {
            eprintln!("dev-auth: result destination is unavailable; workload was not started");
            return Ok(1);
        }
    };
    let arguments = parsed
        .get_many::<OsString>("arguments")
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    execute(
        name,
        &arguments,
        parsed.get_flag("non-interactive"),
        result_sink,
    )
}

pub(super) fn help() -> String {
    specification().render_long_help().to_string()
}

fn finish(result: ExecutionResult, sink: Option<ResultDestination>) -> anyhow::Result<i32> {
    let code = result.exit_code;
    if let Some(sink) = sink {
        if sink.finish(&result).is_err() {
            eprintln!("dev-auth: execution result could not be finalized; inspect workload state before retrying");
            return Ok(1);
        }
    }
    if let Some(kind) = result.error_kind {
        eprintln!("dev-auth: workload launch {kind}");
    }
    Ok(code)
}

#[cfg(target_os = "linux")]
fn execute(
    name: &str,
    arguments: &[OsString],
    noninteractive: bool,
    sink: Option<ResultDestination>,
) -> anyhow::Result<i32> {
    if !dev_auth::setup::running_executable_has_version_layout()? {
        return finish(
            ExecutionResult::launch("requires_setup", Some(false), 3).error("requires_setup"),
            sink,
        );
    }
    let outcome = dev_auth::supervisor::run_workload_alias_request(
        name,
        arguments,
        noninteractive,
        sink.is_some(),
    );
    finish_native_outcome(outcome, sink)
}

#[cfg(target_os = "linux")]
fn finish_native_outcome(
    outcome: anyhow::Result<dev_auth::supervisor::WorkloadLaunchOutcome>,
    sink: Option<ResultDestination>,
) -> anyhow::Result<i32> {
    use dev_auth::supervisor::WorkloadLaunchOutcome;
    match outcome {
        Ok(WorkloadLaunchOutcome::ApprovalRequired) => finish(
            ExecutionResult::launch("approval_required", Some(false), 3).error("approval_required"),
            sink,
        ),
        Ok(WorkloadLaunchOutcome::NoninteractiveStoreUnsupported) => finish(
            ExecutionResult::launch("unsupported", Some(false), 3)
                .error("noninteractive_credential_store_unsupported"),
            sink,
        ),
        Ok(WorkloadLaunchOutcome::EnrollmentUnavailable) => finish(
            ExecutionResult::launch("blocked", Some(false), 3)
                .error("enrollment_unavailable_without_interaction"),
            sink,
        ),
        Ok(WorkloadLaunchOutcome::ChildExited(status)) => {
            let code = crate::exit_status_code(status);
            let reported = finish(ExecutionResult::launch("exited", Some(true), code), sink)?;
            if reported != code {
                return Ok(reported);
            }
            crate::workload_status_code(status)
        }
        Ok(WorkloadLaunchOutcome::Exited(status)) => {
            let code = crate::exit_status_code(status);
            let reported = finish(ExecutionResult::launch("exited", None, code), sink)?;
            if reported != code {
                return Ok(reported);
            }
            crate::workload_status_code(status)
        }
        Err(_) => finish(
            ExecutionResult::launch("failed", None, 1).error("operational"),
            sink,
        ),
    }
}

#[cfg(not(target_os = "linux"))]
fn execute(
    _name: &str,
    _arguments: &[OsString],
    _noninteractive: bool,
    sink: Option<ResultDestination>,
) -> anyhow::Result<i32> {
    finish(
        ExecutionResult::launch("unsupported", Some(false), 3).error("unsupported"),
        sink,
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn unavailable_enrollment_reports_blocked_without_starting_a_child() {
        let root = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("result.json");
        let sink = ResultDestination::reserve(&path).unwrap();
        let code = finish_native_outcome(
            Ok(dev_auth::supervisor::WorkloadLaunchOutcome::EnrollmentUnavailable),
            Some(sink),
        )
        .unwrap();
        let result: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(code, 3);
        assert_eq!(result["started"], false);
        assert_eq!(result["outcome"], "blocked");
        assert_eq!(
            result["error_kind"],
            "enrollment_unavailable_without_interaction"
        );
    }

    #[test]
    fn entered_backend_error_keeps_unknown_progress_and_fixed_diagnostics() {
        let root = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("result.json");
        let sink = ResultDestination::reserve(&path).unwrap();
        assert_eq!(
            finish_native_outcome(Err(anyhow::anyhow!("fixture backend text")), Some(sink))
                .unwrap(),
            1
        );
        let bytes = std::fs::read(path).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(result["started"].is_null());
        assert_eq!(result["error_kind"], "operational");
        assert!(!String::from_utf8(bytes)
            .unwrap()
            .contains("fixture backend text"));
    }
}
