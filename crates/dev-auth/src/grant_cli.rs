use clap::{Arg, Command};
use dev_auth::privilege::grants::{
    parse_duration, Authority, ControlRequest, ControlResult, Execution, Failure, GrantRequest,
    GrantRequirement, GrantScope,
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

/// The deny-all policy template with exactly one subject, the native account
/// named on the command line. The policy's own validation decides acceptance.
pub(super) fn policy_template(arguments: &clap::ArgMatches) -> anyhow::Result<String> {
    use anyhow::Context;
    let account = nix::unistd::User::from_name(
        arguments
            .get_one::<String>("user")
            .context("an administrator grant subject requires --user NAME")?,
    )
    .context("read the native account database")?
    .context("the administrator grant subject account does not exist")?;
    subject_policy_template(account.uid.as_raw(), arguments)
}

fn subject_policy_template(uid: u32, arguments: &clap::ArgMatches) -> anyhow::Result<String> {
    use anyhow::{anyhow, bail, Context};
    use dev_auth::privilege::grants::policy::{Account, Policy, SubjectPolicy};
    if uid == 0 {
        bail!("administrator grant subjects must be non-root accounts");
    }
    let maximum_duration = parse_duration(
        arguments
            .get_one::<String>("maximum-duration")
            .context("an administrator grant subject requires --maximum-duration DURATION")?,
    )
    .map_err(|_| anyhow!("--maximum-duration must be a positive whole number of s, m, h or d"))?;
    let scopes = arguments
        .get_many::<String>("scope")
        .into_iter()
        .flatten()
        .map(|scope| match scope.as_str() {
            "user" => Ok(GrantScope::User),
            "workload" => Ok(GrantScope::Workload),
            "command" => Ok(GrantScope::Command),
            _ => Err(anyhow!(
                "administrator grant scope must be user, workload or command"
            )),
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let authority = match arguments.get_one::<String>("authority").map(String::as_str) {
        Some("administrator") => Authority::Administrator,
        _ => bail!("administrator grant subject authority must be administrator"),
    };
    let mut policy = Policy::template();
    policy.subjects.push(SubjectPolicy {
        account: Account::Unix { uid },
        scopes,
        authorities: vec![authority],
        maximum_duration_seconds: maximum_duration.as_secs(),
        idle_timeout_seconds: None,
        maximum_uses: None,
        allow_delegation: arguments.get_flag("allow-delegation"),
    });
    policy.validate().map_err(|_| {
        anyhow!("the administrator grant subject violates the grant policy; check for a repeated --scope or a --maximum-duration beyond the native deadline range")
    })?;
    let mut document = serde_json::to_string_pretty(&policy)?;
    document.push('\n');
    Ok(document)
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
        "status" => ControlRequest::Status {
            requirement: arguments
                .get_one::<String>("require-remaining")
                .map(|value| {
                    Ok::<_, Failure>(GrantRequirement {
                        remaining_seconds: parse_duration(value)?.as_secs(),
                        scope: arguments
                            .get_one::<String>("scope")
                            .map(|scope| match scope.as_str() {
                                "user" => Ok(GrantScope::User),
                                "workload" => Ok(GrantScope::Workload),
                                "command" => Ok(GrantScope::Command),
                                _ => Err(Failure::InvalidRequest),
                            })
                            .transpose()?,
                    })
                })
                .transpose()?,
        },
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

/// The variables a login gives a user's first process. A program that `run`
/// starts gets these and the ones named with `--preserve-env`, so that its
/// approval can show every variable it receives.
const LOGIN_ENVIRONMENT: [&str; 7] = ["PATH", "HOME", "SHELL", "USER", "LOGNAME", "TERM", "LANG"];

fn run_environment<'a>(
    preserved: impl IntoIterator<Item = &'a str>,
    environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<Vec<(OsString, OsString)>, Failure> {
    let kept = LOGIN_ENVIRONMENT
        .into_iter()
        .chain(preserved)
        .map(|name| {
            if name.is_empty() || name.contains('=') {
                Err(Failure::InvalidRequest)
            } else {
                Ok(name)
            }
        })
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    Ok(environment
        .into_iter()
        .filter(|(name, _)| name.to_str().is_some_and(|name| kept.contains(name)))
        .collect())
}

/// One `run` request and the program's descriptor, opened as the caller.
fn run_request(arguments: &clap::ArgMatches) -> Result<(ControlRequest, std::fs::File), Failure> {
    let duration = parse_duration(
        arguments
            .get_one::<String>("duration")
            .ok_or(Failure::InvalidRequest)?,
    )?;
    let authority = match arguments.get_one::<String>("authority").map(String::as_str) {
        Some("administrator") => Authority::Administrator,
        _ => return Err(Failure::InvalidRequest),
    };
    let mut command = arguments
        .get_many::<OsString>("command")
        .ok_or(Failure::InvalidRequest)?
        .cloned();
    let program = command.next().ok_or(Failure::InvalidRequest)?;
    let (executable, file) = native_program(&program)?;
    let request = ControlRequest::Run {
        authority,
        duration_seconds: duration.as_secs(),
        executable: executable.into_os_string(),
        execution: Execution {
            program,
            arguments: command.collect(),
            working_directory: std::env::current_dir()
                .map_err(|_| Failure::InvalidRequest)?
                .into_os_string(),
            environment: run_environment(
                arguments
                    .get_many::<String>("preserve-env")
                    .into_iter()
                    .flatten()
                    .map(String::as_str),
                std::env::vars_os(),
            )?,
            terminal: std::io::IsTerminal::is_terminal(&std::io::stdin()),
        },
    };
    request.validate()?;
    Ok((request, file))
}

/// Resolve a program as a shell does and open it as the caller. Only a native
/// ELF program can be approved by its digest and run from its descriptor.
fn native_program(
    program: &std::ffi::OsStr,
) -> Result<(std::path::PathBuf, std::fs::File), Failure> {
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let candidate = if program.as_bytes().contains(&b'/') {
        Some(std::path::PathBuf::from(program))
    } else {
        std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|directory| {
                    if directory.as_os_str().is_empty() {
                        std::path::PathBuf::from(".")
                    } else {
                        directory
                    }
                    .join(program)
                })
                .find(|candidate| {
                    std::fs::metadata(candidate).is_ok_and(|metadata| {
                        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                    })
                })
        })
    };
    let Some(path) = candidate.and_then(|candidate| std::fs::canonicalize(candidate).ok()) else {
        eprintln!("dev-auth: privilege run could not find the program in PATH");
        return Err(Failure::InvalidRequest);
    };
    let Ok(mut file) = std::fs::File::open(&path) else {
        eprintln!("dev-auth: privilege run needs read access to the program");
        return Err(Failure::InvalidRequest);
    };
    let mut magic = [0_u8; 4];
    if file.read_exact(&mut magic).is_err() || &magic != b"\x7fELF" {
        eprintln!("dev-auth: privilege run starts a native program; run a script through its interpreter, such as -- /usr/bin/bash SCRIPT");
        return Err(Failure::InvalidRequest);
    }
    Ok((path, file))
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
    let prepared = if name == "run" {
        run_request(arguments).map(|(request, program)| (request, Some(program)))
    } else {
        request(name, arguments).map(|request| (request, None))
    };
    let (request, program) = match prepared {
        Ok(prepared) => prepared,
        Err(failure) => return output(ControlResult::failure(name, failure, Some(false)), json),
    };
    if matches!(
        request,
        ControlRequest::Request { .. } | ControlRequest::Run { .. }
    ) && arguments.get_flag("non-interactive")
    {
        return output(
            ControlResult::failure(name, Failure::ApprovalRequired, Some(false)),
            json,
        );
    }
    if matches!(
        request,
        ControlRequest::Exec { .. } | ControlRequest::RunPlan { .. } | ControlRequest::Run { .. }
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
        let result = match &program {
            Some(program) => dev_auth::privilege::grants::run_program(request, program),
            None => dev_auth::privilege::grants::control(request),
        };
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
        let covering = result
            .grant
            .iter()
            .filter(|grant| result.grants.iter().all(|listed| listed.id != grant.id));
        for grant in result.grants.iter().chain(covering) {
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

#[cfg(test)]
mod tests {
    use dev_auth::privilege::grants::policy::{Account, Policy};
    use dev_auth::privilege::grants::{Authority, GrantScope};

    const SUBJECT_UID: u32 = 4242;

    fn subject_policy(uid: u32, options: &[&str]) -> anyhow::Result<Policy> {
        let arguments = crate::completion::setup_template_command()
            .try_get_matches_from(
                [
                    "template",
                    "administrator-grant-policy",
                    "--user",
                    "fixture-account",
                ]
                .into_iter()
                .chain(options.iter().copied()),
            )
            .unwrap();
        let document = super::subject_policy_template(uid, &arguments)?;
        let policy: Policy = serde_json::from_str(&document).unwrap();
        policy.validate().unwrap();
        Ok(policy)
    }

    #[test]
    fn a_run_passes_only_the_login_environment_and_named_variables() {
        let environment = || {
            [
                ("PATH", "/usr/bin"),
                ("HOME", "/home/account"),
                ("LD_PRELOAD", "/tmp/x.so"),
                ("SSH_AUTH_SOCK", "/run/agent"),
                ("TERM", "xterm"),
            ]
            .map(|(name, value)| (name.into(), value.into()))
        };
        let names = |kept: Vec<(std::ffi::OsString, std::ffi::OsString)>| {
            kept.into_iter()
                .map(|(name, _)| name.into_string().unwrap())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(super::run_environment([], environment()).unwrap()),
            ["PATH", "HOME", "TERM"]
        );
        assert_eq!(
            names(super::run_environment(["SSH_AUTH_SOCK"], environment()).unwrap()),
            ["PATH", "HOME", "SSH_AUTH_SOCK", "TERM"]
        );
        for invalid in ["", "A=B"] {
            assert!(super::run_environment([invalid], environment()).is_err());
        }
    }

    #[test]
    fn a_resolved_uid_becomes_the_only_subject_with_documented_defaults() {
        let policy = subject_policy(SUBJECT_UID, &["--maximum-duration", "30m"]).unwrap();
        let [subject] = policy.subjects.as_slice() else {
            panic!("expected exactly one subject");
        };
        assert_eq!(subject.account, Account::Unix { uid: SUBJECT_UID });
        assert_eq!(subject.scopes, [GrantScope::User, GrantScope::Workload]);
        assert_eq!(subject.authorities, [Authority::Administrator]);
        assert_eq!(subject.maximum_duration_seconds, 30 * 60);
        assert!(!subject.allow_delegation);
    }

    #[test]
    fn root_repeated_scopes_and_out_of_range_durations_produce_no_document() {
        assert!(subject_policy(0, &["--maximum-duration", "12h"]).is_err());
        for options in [
            [
                "--maximum-duration",
                "12h",
                "--scope",
                "user",
                "--scope",
                "user",
            ]
            .as_slice(),
            &["--maximum-duration", "106752d"],
            &["--maximum-duration", "0m"],
        ] {
            assert!(subject_policy(SUBJECT_UID, options).is_err(), "{options:?}");
        }
    }
}
