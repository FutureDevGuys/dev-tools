use anyhow::{bail, Context, Result};
use std::io::{self, Read};
use zeroize::Zeroize;

const REQUEST_LIMIT: u64 = 64 * 1024;

fn usage() -> &'static str {
    "Usage:\n  dev-auth enroll\n  dev-auth validate [--online]\n  dev-auth workspace-status\n  dev-auth exec --profile NAME -- COMMAND [args...]\n  dev-auth agent --profile NAME\n  dev-auth agent-endpoint\n  dev-auth ssh-load --profile NAME\n  dev-auth ssh-public --profile NAME --purpose authentication|signing\n  dev-auth status\n  dev-auth purge"
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
        "validate" => {
            let online = match arguments.next().as_deref() {
                None => false,
                Some("--online") if arguments.next().is_none() => true,
                _ => bail!("validate accepts only the optional --online flag"),
            };
            let report = dev_auth::validate_configuration(online)?;
            println!(
                "config_valid=true online={} declared_exec_profiles={} declared_ssh_profiles={} declared_secret_references={}",
                report.online,
                report.declared_exec_profiles,
                report.declared_ssh_profiles,
                report.declared_secret_references
            );
            Ok(0)
        }
        "workspace-status" => {
            if arguments.next().is_some() {
                bail!("workspace-status accepts no arguments");
            }
            match dev_auth::workspace_status()? {
                dev_auth::WorkspaceContext::Managed => {
                    println!("managed");
                    Ok(0)
                }
                dev_auth::WorkspaceContext::Unmanaged => {
                    println!("unmanaged");
                    Ok(3)
                }
            }
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
        "ssh-public" => {
            if arguments.next().as_deref() != Some("--profile") {
                bail!("ssh-public requires --profile NAME --purpose authentication|signing");
            }
            let profile = arguments
                .next()
                .context("ssh-public profile name is missing")?;
            if arguments.next().as_deref() != Some("--purpose") {
                bail!("ssh-public requires --purpose authentication|signing");
            }
            let purpose = match arguments.next().as_deref() {
                Some("authentication") => dev_auth::SshKeyPurpose::Authentication,
                Some("signing") => dev_auth::SshKeyPurpose::Signing,
                _ => bail!("ssh-public purpose must be authentication or signing"),
            };
            if arguments.next().is_some() {
                bail!("ssh-public accepts no additional arguments");
            }
            println!("{}", dev_auth::ssh_public(&profile, purpose)?);
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
        "store" => {}
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

fn run_git_frontend() -> Result<i32> {
    let arguments: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let status = dev_auth::run_git(&arguments)?;
    Ok(status.code().unwrap_or(128))
}

fn run_ssh_keygen_frontend() -> Result<i32> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let status = dev_auth::run_ssh_keygen(&arguments)?;
    Ok(status.code().unwrap_or(128))
}

fn run_gh_git_child_frontend() -> Result<i32> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let status = dev_auth::run_gh_git_child(&arguments)?;
    Ok(status.code().unwrap_or(128))
}

fn run_gh_pager_frontend() -> Result<i32> {
    if std::env::args().nth(1).is_some() {
        bail!("the internal gh pager accepts no file arguments");
    }
    io::copy(&mut io::stdin().lock(), &mut io::stdout().lock())
        .context("forward bounded gh output")?;
    Ok(0)
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
    let gh_child = std::env::var("DEV_AUTH_GH_CHILD").as_deref() == Ok("1");
    let git_child = std::env::var("DEV_AUTH_GIT_CHILD").as_deref() == Ok("1");
    let result = match (frontend, gh_child, git_child) {
        ("git", true, _) => run_gh_git_child_frontend(),
        ("cat", true, _) => run_gh_pager_frontend(),
        ("false", true, _) => Ok(1),
        ("cat", _, true) => run_gh_pager_frontend(),
        ("false", _, true) => Ok(1),
        ("git-dev-auth", _, _) => run_git_frontend(),
        ("git-credential-dev-auth", _, _) => run_credential_frontend(),
        ("gh-dev-auth", _, _) => run_gh_frontend(),
        ("ssh-keygen-dev-auth", _, _) => run_ssh_keygen_frontend(),
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
