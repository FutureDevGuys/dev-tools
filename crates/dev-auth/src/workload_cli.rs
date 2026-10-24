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
            Arg::new("privilege-scope")
                .long("privilege-scope")
                .value_parser(["user", "workload"])
                .requires("privilege-duration")
                .help("Request fresh administrator approval in this scope before starting the workload"),
        )
        .arg(
            Arg::new("privilege-duration")
                .long("privilege-duration")
                .requires("privilege-scope")
                .help("Explicit finite administrator-grant duration, for example 30m or 12h"),
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
    #[cfg(not(target_os = "linux"))]
    let privilege: Option<()> = None;
    #[cfg(target_os = "linux")]
    let privilege = match parsed.get_one::<String>("privilege-scope") {
        Some(scope) => {
            let duration = parsed
                .get_one::<String>("privilege-duration")
                .and_then(|value| dev_auth::privilege::grants::parse_duration(value).ok());
            let Some(duration) = duration else {
                eprintln!("dev-auth: invalid administrator launch duration");
                return Ok(2);
            };
            let request = dev_auth::privilege::grants::GrantRequest {
                scope: if scope == "workload" {
                    dev_auth::privilege::grants::GrantScope::Workload
                } else {
                    dev_auth::privilege::grants::GrantScope::User
                },
                authority: dev_auth::privilege::grants::Authority::Administrator,
                duration_seconds: duration.as_secs(),
                idle_seconds: None,
                uses: None,
            };
            if request.validate().is_err() {
                eprintln!("dev-auth: invalid administrator launch duration");
                return Ok(2);
            }
            Some(request)
        }
        None => None,
    };
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
        privilege.as_ref(),
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
    privilege: Option<&dev_auth::privilege::grants::GrantRequest>,
) -> anyhow::Result<i32> {
    if noninteractive && privilege.is_some() {
        return finish(
            ExecutionResult::launch("approval_required", Some(false), 3).error("approval_required"),
            sink,
        );
    }
    if !dev_auth::setup::running_executable_has_version_layout()? {
        return finish(
            ExecutionResult::launch("requires_setup", Some(false), 3).error("requires_setup"),
            sink,
        );
    }
    let outcome = dev_auth::supervisor::run_workload_alias_request_with_grant(
        name,
        arguments,
        noninteractive,
        sink.is_some(),
        privilege,
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
        Err(error) => {
            let kind = error
                .downcast_ref::<dev_auth::supervisor::WorkloadLaunchFailure>()
                .map_or("operational", |failure| failure.error_kind());
            finish(ExecutionResult::launch("failed", None, 1).error(kind), sink)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn execute(
    _name: &str,
    _arguments: &[OsString],
    _noninteractive: bool,
    sink: Option<ResultDestination>,
    _privilege: Option<&()>,
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
    fn privilege_launch_requires_both_explicit_scope_and_finite_duration() {
        for arguments in [
            vec!["launch", "tool", "--privilege-scope", "workload", "--"],
            vec!["launch", "tool", "--privilege-duration", "1h", "--"],
            vec![
                "launch",
                "tool",
                "--privilege-scope",
                "process",
                "--privilege-duration",
                "1h",
                "--",
            ],
        ] {
            assert!(specification().try_get_matches_from(arguments).is_err());
        }
        let parsed = specification()
            .try_get_matches_from([
                "launch",
                "tool",
                "--privilege-scope",
                "workload",
                "--privilege-duration",
                "12h",
                "--",
                "--privilege-duration",
                "spoofed",
            ])
            .unwrap();
        assert_eq!(
            parsed.get_one::<String>("privilege-duration").unwrap(),
            "12h"
        );
        assert_eq!(
            parsed
                .get_many::<OsString>("arguments")
                .unwrap()
                .cloned()
                .collect::<Vec<_>>(),
            [
                OsString::from("--privilege-duration"),
                OsString::from("spoofed")
            ]
        );
    }

    #[test]
    fn noninteractive_fresh_grant_reports_no_start_without_setup_or_authorization() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let result = root.path().join("result.json");
        let code = run(vec![
            "unconfigured-workload".into(),
            "--non-interactive".into(),
            "--privilege-scope".into(),
            "workload".into(),
            "--privilege-duration".into(),
            "30m".into(),
            "--result-file".into(),
            result.as_os_str().to_owned(),
            "--".into(),
        ])
        .unwrap();
        assert_eq!(code, 3);
        let result: serde_json::Value =
            serde_json::from_slice(&std::fs::read(result).unwrap()).unwrap();
        assert_eq!(result["started"], false);
        assert_eq!(result["outcome"], "approval_required");
    }

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

    #[test]
    fn typed_outer_launch_failures_report_only_fixed_kinds_with_unknown_progress() {
        use dev_auth::supervisor::WorkloadLaunchFailure;
        use std::os::unix::fs::PermissionsExt;

        for (failure, expected_kind) in [
            (
                WorkloadLaunchFailure::DispatcherStart,
                "dispatcher_start_failed",
            ),
            (
                WorkloadLaunchFailure::DispatcherExitedBeforeHandoff,
                "dispatcher_exited_before_handoff",
            ),
            (
                WorkloadLaunchFailure::EnvironmentHandoffTimedOut,
                "environment_handoff_timed_out",
            ),
            (
                WorkloadLaunchFailure::EnvironmentHandoff,
                "environment_handoff_failed",
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let path = root.path().join("result.json");
            let sink = ResultDestination::reserve(&path).unwrap();
            let error = anyhow::anyhow!("private underlying path, argument and credential fixture")
                .context(failure)
                .context("private outer fixture detail");
            assert_eq!(finish_native_outcome(Err(error), Some(sink)).unwrap(), 1);
            let result: serde_json::Value =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert_eq!(
                result,
                serde_json::json!({
                    "schema": "dev-auth-execution-result-v1",
                    "product": "dev-auth",
                    "operation": "workload_launch",
                    "outcome": "failed",
                    "started": null,
                    "exit_code": 1,
                    "error_kind": expected_kind,
                })
            );
        }
    }
}
