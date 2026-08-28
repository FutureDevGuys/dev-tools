use anyhow::{bail, Context, Result};
use std::io::{self, Read};
use zeroize::Zeroize;

const REQUEST_LIMIT: u64 = 64 * 1024;

fn usage() -> &'static str {
    "Usage:\n  dev-auth enroll\n  dev-auth exec --profile NAME -- COMMAND [args...]\n  dev-auth agent --profile NAME\n  dev-auth agent-endpoint\n  dev-auth ssh-load --profile NAME\n  dev-auth status\n  dev-auth purge"
}

fn run() -> Result<i32> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().context(usage())?;
    match command.as_str() {
        "enroll" => {
            if arguments.next().is_some() {
                bail!("enroll accepts no arguments");
            }
            let mut value = Vec::new();
            io::stdin()
                .take(REQUEST_LIMIT + 1)
                .read_to_end(&mut value)
                .context("read service credential from standard input")?;
            if value.len() as u64 > REQUEST_LIMIT {
                value.zeroize();
                bail!("service credential exceeds the size limit");
            }
            let result = dev_auth::enroll_service_account_token(&value);
            value.zeroize();
            result?;
            Ok(0)
        }
        "status" => {
            if arguments.next().is_some() {
                bail!("status accepts no arguments");
            }
            let status = dev_auth::runtime_status()?;
            println!(
                "config_ready={} service_token_enrolled={} runtime_ready={} ssh_agent_ready={} cached_installation_tokens={}",
                status.config_ready,
                status.service_token_enrolled,
                status.runtime_ready,
                status.ssh_agent_ready,
                status.cached_installation_tokens
            );
            Ok(
                if status.config_ready
                    && status.service_token_enrolled
                    && status.runtime_ready
                    && status.ssh_agent_ready
                {
                    0
                } else {
                    1
                },
            )
        }
        "purge" => {
            if arguments.next().is_some() {
                bail!("purge accepts no arguments");
            }
            dev_auth::purge_runtime()?;
            Ok(0)
        }
        "exec" => {
            if arguments.next().as_deref() != Some("--profile") {
                bail!("exec requires --profile NAME");
            }
            let profile = arguments.next().context("exec profile name is missing")?;
            if arguments.next().as_deref() != Some("--") {
                bail!("exec requires -- before the command");
            }
            let child: Vec<String> = arguments.collect();
            let status = dev_auth::exec_profile(&profile, &child)?;
            Ok(status.code().unwrap_or(128))
        }
        "agent" => {
            if arguments.next().as_deref() != Some("--profile") {
                bail!("agent requires --profile NAME");
            }
            let profile = arguments.next().context("agent profile name is missing")?;
            if arguments.next().is_some() {
                bail!("agent accepts no additional arguments");
            }
            dev_auth::run_agent(&profile)?;
            Ok(0)
        }
        "agent-endpoint" => {
            if arguments.next().is_some() {
                bail!("agent-endpoint accepts no arguments");
            }
            println!("{}", dev_auth::agent_endpoint()?);
            Ok(0)
        }
        "ssh-load" => {
            if arguments.next().as_deref() != Some("--profile") {
                bail!("ssh-load requires --profile NAME");
            }
            let profile = arguments
                .next()
                .context("ssh-load profile name is missing")?;
            if arguments.next().is_some() {
                bail!("ssh-load accepts no additional arguments");
            }
            dev_auth::ssh_load(&profile)?;
            Ok(0)
        }
        "--help" | "-h" | "help" => {
            println!("{}", usage());
            Ok(0)
        }
        _ => bail!("unknown command\n{}", usage()),
    }
}

fn run_credential_frontend() -> Result<i32> {
    let operation = std::env::args()
        .nth(1)
        .context("credential-helper operation is required")?;
    let mut input = Vec::new();
    io::stdin()
        .take(REQUEST_LIMIT + 1)
        .read_to_end(&mut input)
        .context("read Git credential request")?;
    if input.len() as u64 > REQUEST_LIMIT {
        bail!("Git credential request exceeds the size limit");
    }
    match operation.as_str() {
        "get" => print!("{}", dev_auth::credential_get(&input)?),
        "store" => {
            dev_auth::CredentialRequest::parse(&input)?;
        }
        "erase" => dev_auth::credential_erase(&input)?,
        _ => bail!("unsupported credential-helper operation"),
    }
    Ok(0)
}

fn run_gh_frontend() -> Result<i32> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let status = dev_auth::run_gh(&arguments)?;
    Ok(status.code().unwrap_or(128))
}

fn run_ssh_keygen_frontend() -> Result<i32> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let status = dev_auth::run_ssh_keygen(&arguments)?;
    Ok(status.code().unwrap_or(128))
}

fn main() {
    let program = std::env::args_os()
        .next()
        .and_then(|value| {
            std::path::PathBuf::from(value)
                .file_name()
                .map(|name| name.to_owned())
        })
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| "dev-auth".into());
    let normalized_program = program.to_ascii_lowercase();
    let frontend = normalized_program
        .strip_suffix(".exe")
        .unwrap_or(&normalized_program);
    let result = match frontend {
        "git-credential-dev-auth" => run_credential_frontend(),
        "gh-dev-auth" => run_gh_frontend(),
        "ssh-keygen-dev-auth" => run_ssh_keygen_frontend(),
        _ => run(),
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            if frontend == "git-credential-dev-auth"
                && std::env::args().nth(1).as_deref() == Some("get")
            {
                println!("quit=true");
            }
            eprintln!("{program}: {error:#}");
            std::process::exit(2);
        }
    }
}
