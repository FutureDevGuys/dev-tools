//! Public administrative commands. Static metadata never reads policy or grants.
use super::{custody, launch, policy, protocol, runtime};
use anyhow::{bail, Context, Result};
use clap::{builder::OsStringValueParser, Arg, ArgAction, Command, ValueHint};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

fn path(name: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .value_parser(OsStringValueParser::new())
        .value_hint(ValueHint::FilePath)
}
fn value(name: &'static str) -> Arg {
    Arg::new(name).long(name)
}
fn session() -> Arg {
    value("session")
        .help("Public session selector; kernel workload membership supplies execution authority")
}
pub fn specification() -> Command {
    Command::new("privilege")
        .about("Request and use a bounded reusable administrative session")
        .subcommand_required(true)
        .subcommand(Command::new("plan").args([
            path("request").required(true),
            path("output").required(true),
            Arg::new("json").long("json").action(ArgAction::SetTrue),
        ]))
        .subcommand(
            Command::new("request").args([
                path("plan").required(true),
                value("sha256").required(true),
                value("authorize").value_parser(["polkit"]),
                Arg::new("non-interactive")
                    .long("non-interactive")
                    .action(ArgAction::SetTrue),
                path("result-file"),
                Arg::new("controller")
                    .last(true)
                    .num_args(1..)
                    .required(true)
                    .value_parser(OsStringValueParser::new()),
            ]),
        )
        .subcommand(Command::new("execute").args([
            session(),
            value("operation").required(true),
            path("request").required(true),
            path("result-file"),
        ]))
        .subcommand(Command::new("execute-plan").args([
            session(),
            value("operation").required(true),
            value("plan-id").required(true),
            path("result-file"),
        ]))
        .subcommand(Command::new("status").args([
            session(),
            Arg::new("json").long("json").action(ArgAction::SetTrue),
        ]))
        .subcommand(Command::new("revoke").args([
            session(),
            Arg::new("json").long("json").action(ArgAction::SetTrue),
        ]))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TypedRequest {
    schema: String,
    plan: String,
}

pub fn run(arguments: Vec<OsString>) -> i32 {
    let matches = match specification()
        .try_get_matches_from(std::iter::once(OsString::from("privilege")).chain(arguments))
    {
        Ok(m) => m,
        Err(e) if e.kind() == clap::error::ErrorKind::DisplayHelp => {
            let _ = e.print();
            return 0;
        }
        Err(_) => {
            eprintln!("dev-auth: invalid administrative invocation");
            return 2;
        }
    };
    let result = (|| -> Result<i32> {
        let uid = nix::unistd::getuid().as_raw();
        match matches.subcommand() {
            Some(("plan", m)) => {
                let request = policy::parse_request(&custody::read_document(
                    argument_path(m, "request")?,
                    uid,
                    0o600,
                )?)?;
                if request.owner_uid != uid {
                    bail!("administrative plan owner does not match native caller");
                }
                let plan = policy::resolve(
                    &custody::policy_bytes()?,
                    request,
                    &custody::installation_identity()?,
                )?;
                let bytes = policy::canonical(&plan)?;
                custody::write_new_document(argument_path(m, "output")?, &bytes, uid)?;
                print(
                    &serde_json::json!({"schema":"dev-auth-privilege-plan-result-v1","sha256":policy::digest(&bytes),"granted":false}),
                )?;
                Ok(0)
            }
            Some(("request", m)) => {
                if m.get_flag("non-interactive")
                    || m.get_one::<String>("authorize").map(String::as_str) != Some("polkit")
                {
                    print(
                        &serde_json::json!({"schema":"dev-auth-operation-result-v1","outcome":"approval_required","started":false,"exit_code":3}),
                    )?;
                    return Ok(3);
                }
                if crate::setup::validate_installed_maintenance_helper().is_err() {
                    print(
                        &serde_json::json!({"schema":"dev-auth-operation-result-v1","outcome":"requires_setup","started":false,"exit_code":3}),
                    )?;
                    return Ok(3);
                }
                let approval = custody::read_document(argument_path(m, "plan")?, uid, 0o600)?;
                let digest = m
                    .get_one::<String>("sha256")
                    .context("administrative digest is absent")?
                    .clone();
                let command = m
                    .get_many::<OsString>("controller")
                    .context("native controller is absent")?
                    .collect::<Vec<_>>();
                let controller = runtime::Controller {
                    executable: command[0].as_os_str().as_bytes().to_vec(),
                    arguments: command[1..]
                        .iter()
                        .map(|a| a.as_os_str().as_bytes().to_vec())
                        .collect(),
                    cwd: std::env::current_dir()?.as_os_str().as_bytes().to_vec(),
                    environment: std::env::vars()
                        .filter(|(k, _)| launch::allowed_environment(k))
                        .collect(),
                };
                let terminal = launch::request(approval, digest, controller)?;
                result_file(m, &terminal.observation, uid)?;
                Ok(if terminal.observation.terminal_success() {
                    preserve_signal(&terminal.observation)?;
                    terminal.observation.exit_code.unwrap_or(0)
                } else {
                    1
                })
            }
            Some((kind, m)) if kind == "execute" || kind == "execute-plan" => {
                let session = selected_session(m)?;
                let operation = m
                    .get_one::<String>("operation")
                    .context("administrative operation is absent")?
                    .clone();
                let plan = if kind == "execute" {
                    let request: TypedRequest = policy::parse(&custody::read_document(
                        argument_path(m, "request")?,
                        uid,
                        0o600,
                    )?)?;
                    if request.schema != "dev-auth-privilege-operation-v1" {
                        bail!("administrative operation schema is unsupported");
                    }
                    request.plan
                } else {
                    m.get_one::<String>("plan-id")
                        .context("administrative plan selector is absent")?
                        .clone()
                };
                policy::identifier(&operation)?;
                policy::identifier(&plan)?;
                let mut stream = connect(&session)?;
                protocol::write(
                    &mut stream,
                    &protocol::Envelope {
                        version: 1,
                        session,
                        request_id: custody::random_id()?,
                        action: protocol::Action::Execute {
                            name: operation,
                            plan,
                        },
                    },
                    protocol::CONTROL_BUDGET,
                )?;
                let reply: protocol::ExecutionReply = policy::parse(&protocol::read(
                    &mut stream,
                    Duration::from_secs(8 * 60 * 60 + 15),
                )?)?;
                if reply.observation.version != 1 {
                    bail!("administrative result version is unsupported");
                }
                std::io::stdout().write_all(&reply.stdout)?;
                std::io::stderr().write_all(&reply.stderr)?;
                result_file(m, &reply.observation, uid)?;
                preserve_signal(&reply.observation)?;
                Ok(reply.observation.execution_exit_code())
            }
            Some((kind, m)) if kind == "status" || kind == "revoke" => {
                let session = selected_session(m)?;
                if let Some(terminal) = launch::terminal(&session, uid)? {
                    print(&terminal.observation)?;
                    return Ok(if terminal.observation.terminal_success() {
                        0
                    } else {
                        1
                    });
                }
                let mut stream = connect(&session)?;
                let action = if kind == "status" {
                    protocol::Action::Status {}
                } else {
                    protocol::Action::Revoke {}
                };
                protocol::write(
                    &mut stream,
                    &protocol::Envelope {
                        version: 1,
                        session: session.clone(),
                        request_id: custody::random_id()?,
                        action,
                    },
                    protocol::CONTROL_BUDGET,
                )?;
                let observation: protocol::Observation =
                    policy::parse(&protocol::read(&mut stream, protocol::CONTROL_BUDGET)?)?;
                if kind == "status" {
                    print(&observation)?;
                    return Ok(0);
                }
                let started = Instant::now();
                while started.elapsed() < Duration::from_secs(30) {
                    if let Some(terminal) = launch::terminal(&session, uid)? {
                        print(&terminal.observation)?;
                        return Ok(if terminal.observation.terminal_success() {
                            0
                        } else {
                            1
                        });
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                print(
                    &serde_json::json!({"schema":"dev-auth-privilege-result-v1","outcome":"failed","cleanup_complete":false,"error_kind":"revocation_cleanup_unproven"}),
                )?;
                Ok(1)
            }
            _ => Ok(2),
        }
    })();
    match result {
        Ok(code) => code,
        Err(_) => {
            eprintln!("dev-auth: administrative operation failed; no successful effect or cleanup is implied");
            1
        }
    }
}
fn preserve_signal(observation: &protocol::Observation) -> Result<()> {
    if let Some(signal) = observation.signal {
        // Commit result metadata and child bytes before restoring native status.
        std::io::stdout().flush()?;
        std::io::stderr().flush()?;
        let signal = nix::sys::signal::Signal::try_from(signal)?;
        if signal != nix::sys::signal::Signal::SIGKILL {
            unsafe {
                nix::sys::signal::signal(signal, nix::sys::signal::SigHandler::SigDfl)?;
            }
        }
        let mut unblocked = nix::sys::signal::SigSet::empty();
        unblocked.add(signal);
        unblocked.thread_unblock()?;
        nix::sys::signal::raise(signal)?;
        bail!("administrative signal did not terminate frontend");
    }
    Ok(())
}

fn argument_path<'a>(m: &'a clap::ArgMatches, name: &str) -> Result<&'a Path> {
    Ok(Path::new(
        m.get_one::<OsString>(name)
            .context("administrative path argument is absent")?,
    ))
}
fn selected_session(m: &clap::ArgMatches) -> Result<String> {
    let value = m
        .get_one::<String>("session")
        .cloned()
        .or_else(|| std::env::var("DEV_AUTH_PRIVILEGE_SESSION").ok())
        .context("administrative session selector is absent")?;
    protocol::token(&value)?;
    Ok(value)
}
fn result_file(m: &clap::ArgMatches, value: &protocol::Observation, uid: u32) -> Result<()> {
    if let Some(path) = m.get_one::<OsString>("result-file") {
        custody::write_new_document(Path::new(path), &policy::canonical(value)?, uid)?;
    }
    Ok(())
}
fn print(value: &impl Serialize) -> Result<()> {
    let mut out = serde_json::to_vec(value)?;
    out.push(b'\n');
    std::io::stdout().write_all(&out)?;
    Ok(())
}
fn connect(session: &str) -> Result<UnixStream> {
    let path = runtime::socket_path(session)?;
    custody::validate_parents(&path, 0, false)?;
    let stream = UnixStream::connect(path)?;
    if crate::linux_admission::peer_evidence(&stream)?.uid != 0 {
        bail!("administrative coordinator is not native root");
    }
    Ok(stream)
}

pub fn private(arguments: Vec<OsString>) -> i32 {
    let result = (|| -> Result<i32> {
        super::platform::protect_infrastructure()?;
        crate::setup::validate_running_maintenance_helper()?;
        let args = arguments
            .into_iter()
            .map(|a| {
                a.into_string()
                    .map_err(|_| anyhow::anyhow!("private administrative selector is not UTF-8"))
            })
            .collect::<Result<Vec<_>>>()?;
        match args.as_slice() {
            [kind, a, socket, b, owner, c, digest]
                if kind == "admit-v1" && a == "--socket" && b == "--owner" && c == "--sha256" =>
            {
                launch::admit(Path::new(socket), owner.parse()?, digest)
            }
            [kind, a, session, b, handoff]
                if kind == "serve-v1" && a == "--session" && b == "--handoff" =>
            {
                launch::serve(session, Path::new(handoff))
            }
            [kind, a, fd] if kind == "child-v1" && a == "--payload-fd" => {
                runtime::child(fd.parse()?)
            }
            _ => bail!("private administrative entry is invalid"),
        }
    })();
    match result {
        Ok(code) => code,
        Err(_) => {
            eprintln!("dev-auth: administrative helper denied");
            4
        }
    }
}
