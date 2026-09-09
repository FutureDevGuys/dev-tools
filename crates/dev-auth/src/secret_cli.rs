//! Logical resource front door. Secret bytes never share stdout with control JSON.
use crate::execution_result::{ExecutionResult, ResultDestination};
use clap::{builder::OsStringValueParser, Arg, ArgAction, Command, ValueHint};
use std::ffi::OsString;
use std::io::Write;
use std::path::Path;

pub(super) fn specification() -> Command {
    let mut command = Command::new("secret")
        .bin_name("dev-auth secret")
        .about("Use admitted logical resources without provider references")
        .disable_help_subcommand(true)
        .subcommand_required(true);
    for name in ["read", "public"] {
        command = command.subcommand(
            Command::new(name)
                .arg(Arg::new("resource").required(true))
                .arg(
                    Arg::new("non-interactive")
                        .long("non-interactive")
                        .action(ArgAction::SetTrue)
                        .help("Return promptly without requesting interactive admission"),
                )
                .arg(
                    Arg::new("result-file")
                        .long("result-file")
                        .value_parser(OsStringValueParser::new())
                        .value_hint(ValueHint::FilePath)
                        .help("Write value-free execution results separately from resource bytes"),
                ),
        );
    }
    command.subcommand(
        Command::new("exec")
            .about("Project admitted resources into one native child")
            .arg(Arg::new("stdin").long("stdin").value_name("RESOURCE"))
            .arg(
                Arg::new("fd")
                    .long("fd")
                    .value_name("FD=RESOURCE")
                    .action(ArgAction::Append),
            )
            .arg(
                Arg::new("file")
                    .long("file")
                    .value_name("VARIABLE=RESOURCE")
                    .action(ArgAction::Append),
            )
            .arg(
                Arg::new("env")
                    .long("env")
                    .value_name("VARIABLE=RESOURCE")
                    .action(ArgAction::Append),
            )
            .arg(
                Arg::new("non-interactive")
                    .long("non-interactive")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("result-file")
                    .long("result-file")
                    .value_parser(OsStringValueParser::new())
                    .value_hint(ValueHint::FilePath),
            )
            .arg(
                Arg::new("command")
                    .last(true)
                    .required(true)
                    .num_args(1..)
                    .allow_hyphen_values(true)
                    .value_parser(OsStringValueParser::new()),
            ),
    )
}

pub(super) fn help() -> String {
    specification().render_long_help().to_string()
}

pub(super) fn run(arguments: Vec<OsString>) -> anyhow::Result<i32> {
    let parsed = match specification()
        .try_get_matches_from(std::iter::once(OsString::from("secret")).chain(arguments))
    {
        Ok(parsed) => parsed,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return Ok(
                if std::io::stdout()
                    .lock()
                    .write_all(error.to_string().as_bytes())
                    .is_ok()
                {
                    0
                } else {
                    1
                },
            );
        }
        Err(_) => {
            eprintln!("dev-auth: invalid secret invocation");
            return Ok(2);
        }
    };
    let Some((operation, parsed)) = parsed.subcommand() else {
        return Ok(2);
    };
    if operation == "exec" {
        return run_exec(parsed);
    }
    let Some(resource) = parsed.get_one::<String>("resource") else {
        return Ok(2);
    };
    if dev_tools_secret::LogicalSecretName::parse(resource).is_err() {
        eprintln!("dev-auth: invalid logical resource name");
        return Ok(2);
    }
    let sink = match parsed
        .get_one::<OsString>("result-file")
        .map(|path| ResultDestination::reserve(Path::new(path)))
        .transpose()
    {
        Ok(sink) => sink,
        Err(_) => {
            eprintln!("dev-auth: result destination is unavailable; resource was not requested");
            return Ok(1);
        }
    };
    let operation = if operation == "read" {
        "secret_read"
    } else {
        "secret_public"
    };
    finish(execute(operation, resource), sink)
}

fn finish(result: ExecutionResult, sink: Option<ResultDestination>) -> anyhow::Result<i32> {
    let operation = result.operation;
    if let Some(kind) = result.error_kind {
        eprintln!("dev-auth: {operation} {kind}");
    }
    let code = result.exit_code;
    if sink.is_some_and(|sink| sink.finish(&result).is_err()) {
        eprintln!("dev-auth: resource result could not be finalized");
        return Ok(1);
    }
    Ok(code)
}

fn parse_projections(
    parsed: &clap::ArgMatches,
) -> anyhow::Result<Vec<crate::secret_execution::Request>> {
    use crate::secret_execution::{Request, Target};
    let mut requests = Vec::new();
    if let Some(resource) = parsed.get_one::<String>("stdin") {
        requests.push(Request {
            target: Target::Stdin,
            resource: resource.clone(),
        });
    }
    for option in ["fd", "file", "env"] {
        for value in parsed.get_many::<String>(option).into_iter().flatten() {
            let (target, resource) = value
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("projection assignment is invalid"))?;
            let target = match option {
                "fd" => Target::Descriptor(target.parse()?),
                "file" => Target::File(target.into()),
                _ => Target::Environment(target.into()),
            };
            requests.push(Request {
                target,
                resource: resource.into(),
            });
        }
    }
    crate::secret_execution::validate(&requests)?;
    Ok(requests)
}

fn run_exec(parsed: &clap::ArgMatches) -> anyhow::Result<i32> {
    let requests = match parse_projections(parsed) {
        Ok(requests) => requests,
        Err(_) => {
            eprintln!("dev-auth: invalid secret projection invocation");
            return Ok(2);
        }
    };
    let arguments = parsed
        .get_many::<OsString>("command")
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    if arguments.first().is_none_or(|argument| argument.is_empty()) {
        eprintln!("dev-auth: secret exec requires a native command after --");
        return Ok(2);
    }
    let sink = match parsed
        .get_one::<OsString>("result-file")
        .map(|path| ResultDestination::reserve(Path::new(path)))
        .transpose()
    {
        Ok(sink) => sink,
        Err(_) => {
            eprintln!("dev-auth: result destination is unavailable; child was not started");
            return Ok(1);
        }
    };
    execute_child(&requests, &arguments, sink)
}

#[cfg(target_os = "linux")]
fn execute_child(
    requests: &[crate::secret_execution::Request],
    arguments: &[OsString],
    sink: Option<ResultDestination>,
) -> anyhow::Result<i32> {
    use dev_auth::broker_protocol::{BrokerRequest, BrokerResponse};
    use std::os::unix::process::CommandExt;
    let (session, deadline) = match active_execution_lease() {
        Ok(lease) => lease,
        Err(report) => return finish(report, sink),
    };
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(_) => {
            return finish(
                result(
                    "secret_exec",
                    "working_directory_unavailable",
                    Some(false),
                    1,
                ),
                sink,
            )
        }
    };
    let executable = match resolve_child(&arguments[0], &cwd) {
        Some(executable) => executable,
        None => {
            return finish(
                result("secret_exec", "executable_unavailable", Some(false), 2),
                sink,
            )
        }
    };
    let mut values = Vec::new();
    for projection in requests {
        let response = dev_auth::broker_client::request_active(BrokerRequest::SecretRead {
            resource: projection.resource.clone(),
            projection: Some(projection.projection()),
        });
        match response {
            Ok(BrokerResponse::SecretMaterial { material }) => values.push(material),
            Ok(BrokerResponse::Denied { .. }) => {
                return finish(
                    result("secret_exec", "resource_denied", Some(false), 4),
                    sink,
                )
            }
            Ok(_) => {
                return finish(
                    result("secret_exec", "invalid_response", Some(false), 4),
                    sink,
                )
            }
            Err(_) => return finish(result("secret_exec", "broker_failed", Some(false), 1), sink),
        }
    }
    // Revalidate the same admission after retrieval. Resource calls and keepalive
    // cannot replace this deadline or move the child into another grant.
    if !matches!(active_execution_lease(), Ok((current, end)) if current == session && end == deadline)
    {
        return finish(
            result("secret_exec", "admission_invalid", Some(false), 4),
            sink,
        );
    }
    let mut command = std::process::Command::new(executable);
    command
        .arg0(&arguments[0])
        .args(&arguments[1..])
        .current_dir(cwd);
    let prepared = match crate::secret_execution::Prepared::new(command, requests, values) {
        Ok(prepared) => prepared,
        Err(_) => {
            return finish(
                result("secret_exec", "projection_failed", Some(false), 1),
                sink,
            )
        }
    };
    match prepared
        .run(|| dev_auth::linux_platform::boot_time_millis().is_ok_and(|now| now < deadline))
    {
        Ok(output) if output.cancelled => {
            finish(result("secret_exec", "expired", Some(true), 3), sink)
        }
        Ok(output) => {
            let code = crate::exit_status_code(output.status);
            let mut report = ExecutionResult::launch("exited", Some(true), code);
            report.operation = "secret_exec";
            let reported = finish(report, sink)?;
            if reported != code {
                return Ok(reported);
            }
            crate::workload_status_code(output.status)
        }
        Err(_) => finish(result("secret_exec", "execution_failed", None, 1), sink),
    }
}

#[cfg(target_os = "linux")]
fn resolve_child(command: &std::ffi::OsStr, cwd: &Path) -> Option<std::path::PathBuf> {
    let path = Path::new(command);
    if path.components().count() > 1 || path.is_absolute() {
        let path = if path.is_absolute() {
            path.to_owned()
        } else {
            cwd.join(path)
        };
        return dev_tools_command::is_executable_file(&path).then_some(path);
    }
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| {
            if directory.is_absolute() {
                directory.join(path)
            } else {
                cwd.join(directory).join(path)
            }
        })
        .find(|path| dev_tools_command::is_executable_file(path))
}

#[cfg(target_os = "linux")]
fn active_execution_lease() -> std::result::Result<(String, u64), ExecutionResult> {
    use dev_auth::broker_protocol::{
        BrokerRequest, BrokerResponse, BrokerSessionProbe, LocalSessionClaim,
    };
    match dev_auth::broker_client::active_claim_and_probe() {
        Ok((LocalSessionClaim::Absent, BrokerSessionProbe::NoSession)) => {
            return Err(result("secret_exec", "admission_required", Some(false), 3))
        }
        Ok((LocalSessionClaim::Present { .. }, BrokerSessionProbe::Verified { .. })) => {}
        Ok((_, BrokerSessionProbe::Unavailable { .. })) => {
            return Err(result("secret_exec", "broker_unavailable", Some(false), 1))
        }
        _ => return Err(result("secret_exec", "admission_invalid", Some(false), 4)),
    }
    match dev_auth::broker_client::request_active(BrokerRequest::Probe) {
        Ok(BrokerResponse::Ready {
            session_id,
            hard_deadline_boot_ms: Some(deadline),
            ..
        }) if dev_auth::linux_platform::boot_time_millis().is_ok_and(|now| now < deadline) => {
            Ok((session_id, deadline))
        }
        _ => Err(result("secret_exec", "admission_invalid", Some(false), 4)),
    }
}

#[cfg(not(target_os = "linux"))]
fn execute_child(
    _requests: &[crate::secret_execution::Request],
    _arguments: &[OsString],
    sink: Option<ResultDestination>,
) -> anyhow::Result<i32> {
    finish(result("secret_exec", "unsupported", Some(false), 3), sink)
}

fn result(
    operation: &'static str,
    outcome: &'static str,
    started: Option<bool>,
    code: i32,
) -> ExecutionResult {
    let mut result = ExecutionResult::launch(outcome, started, code);
    result.operation = operation;
    if code != 0 {
        result.error_kind = Some(outcome);
    }
    result
}

#[cfg(target_os = "linux")]
fn execute(operation: &'static str, resource: &str) -> ExecutionResult {
    use dev_auth::broker_protocol::{
        BrokerRequest, BrokerResponse, BrokerSessionProbe, LocalSessionClaim,
    };
    match dev_auth::broker_client::active_claim_and_probe() {
        Ok((LocalSessionClaim::Absent, BrokerSessionProbe::NoSession)) => {
            return result(operation, "admission_required", Some(false), 3)
        }
        Ok((LocalSessionClaim::Present { .. }, BrokerSessionProbe::Verified { .. })) => {}
        Ok((_, BrokerSessionProbe::Unavailable { .. })) => {
            return result(operation, "broker_unavailable", Some(false), 1)
        }
        _ => return result(operation, "admission_invalid", Some(false), 4),
    }
    let request = if operation == "secret_read" {
        BrokerRequest::SecretRead {
            resource: resource.into(),
            projection: None,
        }
    } else {
        BrokerRequest::SecretPublic {
            resource: resource.into(),
        }
    };
    match dev_auth::broker_client::request_active(request) {
        Ok(BrokerResponse::SecretMaterial { material }) => {
            let mut output = std::io::stdout().lock();
            if output
                .write_all(material.expose())
                .and_then(|()| output.flush())
                .is_err()
            {
                result(operation, "output_failed", Some(true), 1)
            } else {
                result(operation, "completed", Some(true), 0)
            }
        }
        Ok(BrokerResponse::Denied { .. }) => result(operation, "resource_denied", Some(false), 4),
        Ok(_) => result(operation, "invalid_response", Some(false), 4),
        Err(_) => result(operation, "broker_failed", Some(false), 1),
    }
}

#[cfg(not(target_os = "linux"))]
fn execute(operation: &'static str, _resource: &str) -> ExecutionResult {
    result(operation, "unsupported", Some(false), 3)
}
