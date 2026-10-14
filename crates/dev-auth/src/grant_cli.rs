use clap::{Arg, Command};
use dev_auth::privilege::grants::{
    parse_duration, Authority, ControlRequest, ControlResult, Execution, Failure, GrantRequest,
    GrantScope,
};
use std::ffi::OsString;
use std::io::Write;

fn command(name: &'static str) -> Command {
    Command::new(name).disable_help_subcommand(true)
}

pub(super) fn specification() -> Command {
    dev_auth::privilege::grants::specification()
}

fn grant_request(arguments: &clap::ArgMatches) -> Result<GrantRequest, Failure> {
    let duration = parse_duration(
        arguments
            .get_one::<String>("duration")
            .ok_or(Failure::InvalidRequest)?,
    )?;
    let idle = arguments
        .get_one::<String>("idle")
        .map(|value| parse_duration(value).map(|duration| duration.as_secs()))
        .transpose()?;
    let scope = match arguments.get_one::<String>("scope").map(String::as_str) {
        Some("user") => GrantScope::User,
        Some("workload") => GrantScope::Workload,
        _ => return Err(Failure::InvalidRequest),
    };
    let plan = arguments.get_one::<String>("plan-sha256");
    let operations = arguments.get_many::<String>("operation");
    let authority = match arguments.get_one::<String>("authority").map(String::as_str) {
        Some("administrator") if plan.is_none() && operations.is_none() => Authority::Administrator,
        Some("exact-plan") if operations.is_none() => Authority::ExactPlan {
            sha256: plan.ok_or(Failure::InvalidRequest)?.clone(),
        },
        Some("typed") if plan.is_none() => Authority::Typed {
            operations: operations
                .ok_or(Failure::InvalidRequest)?
                .cloned()
                .collect(),
        },
        _ => return Err(Failure::InvalidRequest),
    };
    let request = GrantRequest {
        scope,
        authority,
        duration_seconds: duration.as_secs(),
        idle_seconds: idle,
        uses: arguments.get_one::<u64>("uses").copied(),
    };
    request.validate()?;
    Ok(request)
}

fn request(name: &str, arguments: &clap::ArgMatches) -> Result<ControlRequest, Failure> {
    let grant = || {
        arguments
            .get_one::<String>("grant")
            .cloned()
            .ok_or(Failure::InvalidRequest)
    };
    let request = match name {
        "request" => ControlRequest::Request {
            request: grant_request(arguments)?,
        },
        "status" => ControlRequest::Status,
        "inspect" => ControlRequest::Inspect { grant: grant()? },
        "revoke" => ControlRequest::Revoke { grant: grant()? },
        "delegate" => ControlRequest::Delegate {
            grant: grant()?,
            request: grant_request(arguments)?,
        },
        "leave" => ControlRequest::Leave,
        "exec" => {
            let authority = arguments
                .get_one::<String>("plan-sha256")
                .map(|sha256| Authority::ExactPlan {
                    sha256: sha256.clone(),
                })
                .or_else(|| {
                    arguments
                        .get_one::<String>("operation")
                        .map(|name| Authority::Typed {
                            operations: vec![name.clone()],
                        })
                });
            if let Some(authority) = authority {
                let request = ControlRequest::RunPlan {
                    grant: arguments.get_one::<String>("grant").cloned(),
                    authority,
                    terminal: std::io::IsTerminal::is_terminal(&std::io::stdin()),
                };
                request.validate()?;
                return Ok(request);
            }
            let mut command = arguments
                .get_many::<OsString>("command")
                .ok_or(Failure::InvalidRequest)?
                .cloned();
            let program = command.next().ok_or(Failure::InvalidRequest)?;
            ControlRequest::Exec {
                grant: arguments.get_one::<String>("grant").cloned(),
                execution: Execution {
                    program,
                    arguments: command.collect(),
                    working_directory: std::env::current_dir()
                        .map_err(|_| Failure::InvalidRequest)?
                        .into_os_string(),
                    environment: std::env::vars_os().collect(),
                    terminal: std::io::IsTerminal::is_terminal(&std::io::stdin()),
                },
            }
        }
        _ => return Err(Failure::InvalidRequest),
    };
    request.validate()?;
    Ok(request)
}

pub(super) fn run(arguments: Vec<OsString>) -> i32 {
    run_with_specification(arguments, specification(), "grant")
}

pub(super) fn run_direct(arguments: Vec<OsString>) -> i32 {
    run_with_specification(
        arguments,
        dev_auth::privilege::grants::direct_specification(),
        "privilege",
    )
}

fn run_with_specification(arguments: Vec<OsString>, grammar: Command, name: &str) -> i32 {
    let options = &arguments[..arguments
        .iter()
        .position(|argument| argument == "--")
        .unwrap_or(arguments.len())];
    let json = options
        .windows(2)
        .any(|values| values[0] == "--format" && values[1] == "json")
        || options.iter().any(|value| value == "--format=json");
    let parsed =
        grammar.try_get_matches_from(std::iter::once(OsString::from(name)).chain(arguments));
    let parsed = match parsed {
        Ok(parsed) => parsed,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return if error.print().is_ok() { 0 } else { 1 }
        }
        Err(_) => {
            return output(
                ControlResult::failure("request", Failure::InvalidRequest, Some(false)),
                json,
            )
        }
    };
    let Some((name, arguments)) = parsed.subcommand() else {
        return output(
            ControlResult::failure("request", Failure::InvalidRequest, Some(false)),
            json,
        );
    };
    let json = arguments.get_one::<String>("format").map(String::as_str) == Some("json");
    let request = match request(name, arguments) {
        Ok(request) => request,
        Err(failure) => return output(ControlResult::failure(name, failure, Some(false)), json),
    };
    if matches!(request, ControlRequest::Request { .. }) && arguments.get_flag("non-interactive") {
        return output(
            ControlResult::failure(name, Failure::ApprovalRequired, Some(false)),
            json,
        );
    }
    if matches!(
        request,
        ControlRequest::Exec { .. } | ControlRequest::RunPlan { .. }
    ) {
        let destination = arguments.get_one::<OsString>("result-file");
        if json && destination.is_none() {
            return output(
                ControlResult::failure(name, Failure::InvalidRequest, Some(false)),
                true,
            );
        }
        let destination = match destination
            .map(|path| {
                crate::execution_result::ResultDestination::reserve(std::path::Path::new(path))
            })
            .transpose()
        {
            Ok(destination) => destination,
            Err(_) => {
                return output(
                    ControlResult::failure(name, Failure::InvalidRequest, Some(false)),
                    json,
                )
            }
        };
        let result = dev_auth::privilege::grants::control(request);
        let code = result.exit_code();
        if let Some(destination) = destination {
            if destination.finish_grant(&result).is_err() {
                eprintln!("dev-auth: could not complete the separate privilege execution result");
                return 1;
            }
        }
        if let Some(error) = result.error_kind {
            eprintln!("dev-auth: {}", error.message());
        }
        #[cfg(target_os = "linux")]
        if result.error_kind.is_none() {
            if let Some(signal) = result.child_signal {
                use std::os::unix::process::ExitStatusExt;
                return crate::workload_status_code(std::process::ExitStatus::from_raw(signal))
                    .unwrap_or(1);
            }
        }
        return code;
    }
    let result = dev_auth::privilege::grants::control(request);
    output(result, json)
}

#[cfg(target_os = "linux")]
pub(super) fn daemon(arguments: Vec<OsString>) -> i32 {
    let parsed = command("privilege-daemon")
        .arg(
            Arg::new("policy")
                .long("policy")
                .required(true)
                .value_parser(clap::builder::OsStringValueParser::new()),
        )
        .arg(
            Arg::new("runtime")
                .long("runtime")
                .required(true)
                .value_parser(clap::builder::OsStringValueParser::new()),
        )
        .try_get_matches_from(std::iter::once(OsString::from("privilege-daemon")).chain(arguments));
    let Ok(parsed) = parsed else {
        eprintln!("dev-auth: invalid native administrator service invocation");
        return 2;
    };
    let (Some(policy), Some(runtime)) = (
        parsed.get_one::<OsString>("policy"),
        parsed.get_one::<OsString>("runtime"),
    ) else {
        return 2;
    };
    match dev_auth::privilege::grants::service::serve(
        dev_auth::privilege::grants::service::Configuration {
            policy: policy.into(),
            runtime: runtime.into(),
        },
    ) {
        Ok(()) => 0,
        Err(failure) => {
            eprintln!("dev-auth: {}", failure.message());
            failure.exit_code()
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn sudo_relay(arguments: Vec<OsString>) -> i32 {
    let Some((grant, tail)) = arguments.split_first() else {
        return 2;
    };
    let Some(grant) = grant.to_str() else {
        return 2;
    };
    let Some((separator, command)) = tail.split_first() else {
        return 2;
    };
    let Some((program, arguments)) = command.split_first() else {
        return 2;
    };
    if separator != "--" {
        return 2;
    }
    let directory = match std::env::current_dir() {
        Ok(directory) => directory.into_os_string(),
        Err(_) => return 2,
    };
    let request = ControlRequest::SudoRelay {
        grant: grant.into(),
        execution: Execution {
            program: program.clone(),
            arguments: arguments.to_vec(),
            working_directory: directory,
            environment: std::env::vars_os().collect(),
            terminal: std::io::IsTerminal::is_terminal(&std::io::stdin()),
        },
    };
    let result = dev_auth::privilege::grants::control(request);
    if let Some(failure) = result.error_kind {
        eprintln!("dev-auth: {}", failure.message());
        return failure.exit_code();
    }
    if let Some(signal) = result.child_signal {
        use std::os::unix::process::ExitStatusExt;
        return crate::workload_status_code(std::process::ExitStatus::from_raw(signal))
            .unwrap_or(1);
    }
    result.exit_code()
}

#[cfg(target_os = "linux")]
pub(super) fn payload(arguments: Vec<OsString>) -> i32 {
    use std::os::unix::fs::OpenOptionsExt;
    let [destination] = arguments.as_slice() else {
        return 2;
    };
    let destination = std::path::Path::new(destination);
    if !destination.is_absolute() {
        return 2;
    }
    let bytes = dev_auth::privilege::grants::assets::SUDO_LIBRARY;
    if bytes.is_empty() {
        eprintln!("dev-auth: native sudo helper is absent from this development build");
        return 3;
    }
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(destination)
    {
        Ok(file) => file,
        Err(_) => return 2,
    };
    if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
        eprintln!(
            "dev-auth: helper export failed; the newly created destination may be incomplete"
        );
        return 1;
    }
    0
}

fn output(result: ControlResult, json: bool) -> i32 {
    let code = result.exit_code();
    if json {
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        if serde_json::to_writer(&mut stdout, &result).is_err() || stdout.write_all(b"\n").is_err()
        {
            return 1;
        }
    } else if let Some(error) = result.error_kind {
        eprintln!("dev-auth: {}", error.message());
    } else {
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        for grant in result.grants.iter().chain(result.grant.iter()) {
            if writeln!(
                stdout,
                "{}  {:?}  {:?}  {}s remaining",
                grant.id,
                grant.scope,
                grant.state,
                grant.remaining_milliseconds / 1000
            )
            .is_err()
            {
                return 1;
            }
        }
    }
    code
}
