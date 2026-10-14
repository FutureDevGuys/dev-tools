//! One parsing/help/completion definition for the public source-only lifecycle.
use crate::smart_binding::{
    self, source, BindingCodeTrust, BindingIntent, BindingResolution, BindingTargetIntent,
};
use anyhow::{bail, Context, Result};
use clap::{Arg, ArgAction, ArgMatches, Command, ValueHint};
use std::io::Read;
use std::path::PathBuf;

fn value(name: &'static str) -> Arg {
    Arg::new(name).long(name).value_hint(ValueHint::Other)
}
fn path(name: &'static str) -> Arg {
    value(name).value_hint(ValueHint::FilePath)
}
fn flag(name: &'static str) -> Arg {
    Arg::new(name).long(name).action(ArgAction::SetTrue)
}
fn command(name: &'static str) -> Command {
    Command::new(name).disable_help_subcommand(true)
}
fn source_arguments(command: Command) -> Command {
    command.args([
        path("source").required(true),
        value("source-sha256").required(true),
        value("user").required(true),
        path("output").required(true),
        flag("json"),
    ])
}
fn plan_command(name: &'static str, rebind: bool) -> Command {
    command(name).arg(Arg::new("name").required(true)).args([
        value("workload").required(true),
        value("command-name").required(true),
        value("target")
            .value_parser(["current-resolution", "structured", "pinned-shell"])
            .required(true),
        value("code-trust")
            .value_parser(["pinned", "mutable"])
            .default_value("pinned"),
        flag("desktop-entry"),
        path("executable"),
        value("arg")
            .allow_hyphen_values(true)
            .action(ArgAction::Append),
        value("caller-argument-index"),
        path("shell"),
        flag("source-stdin"),
        flag("acknowledge-public-shell-source"),
        path("source").required(rebind),
        value("source-sha256").required(rebind),
        value("user").required(rebind),
        path("output").required(true),
        flag("json"),
    ])
}

/// The main binary uses this definition directly for parsing and completion.
pub fn specification() -> Command {
    command("bind")
        .bin_name("dev-auth workload bind")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            command("discover")
                .arg(Arg::new("command-name").required(true))
                .arg(flag("json")),
        )
        .subcommand(plan_command("plan", false))
        .subcommand(plan_command("rebind", true))
        .subcommand(source_arguments(
            command("refresh").arg(Arg::new("name").required(true)),
        ))
        .subcommand(source_arguments(command("propose").args([
            path("plan").required(true),
            value("sha256").required(true),
        ])))
        .subcommand(source_arguments(
            command("remove").arg(Arg::new("name").required(true)),
        ))
        .subcommand(source_arguments(
            command("rollback")
                .arg(Arg::new("name").required(true))
                .arg(path("plan-output").required(true)),
        ))
}

fn text<'a>(matches: &'a ArgMatches, key: &str) -> Result<&'a str> {
    matches
        .get_one::<String>(key)
        .map(String::as_str)
        .context("binding invocation is missing a required selector")
}
fn selected(matches: &ArgMatches, name: &str) -> Result<source::SelectedBinding> {
    source::read_binding(
        &PathBuf::from(text(matches, "source")?),
        text(matches, "source-sha256")?,
        text(matches, "user")?,
        name,
    )
}

pub fn run(arguments: &[String]) -> Result<i32> {
    let matches = match specification()
        .try_get_matches_from(std::iter::once("bind").chain(arguments.iter().map(String::as_str)))
    {
        Ok(matches) => matches,
        Err(error) => {
            let code = if error.use_stderr() { 2 } else { 0 };
            error.print()?;
            return Ok(code);
        }
    };
    let (operation, matches) = matches
        .subcommand()
        .context("binding operation is missing")?;
    let excluded = smart_binding::default_proxy_directories()?;
    if operation == "discover" {
        let name = text(matches, "command-name")?;
        let resolved = smart_binding::resolve_continuation(
            name,
            &std::env::var_os("PATH").context("PATH is not set")?,
            &excluded,
        )?;
        if matches.get_flag("json") {
            println!(
                "{}",
                serde_json::to_string(
                    &serde_json::json!({"schema":"dev-auth-workload-binding-discovery-v1","command_name":name,"resolved":resolved})
                )?
            );
        } else {
            println!("command_name={name}");
            println!("visible_path={}", resolved.visible_path.display());
            println!("canonical_path={}", resolved.canonical_path.display());
            println!("authority={:?}", resolved.identity.authority);
        }
        return Ok(0);
    }
    let output = PathBuf::from(text(matches, "output")?);
    match operation {
        "plan" | "rebind" => {
            let name = text(matches, "name")?;
            let source_count = ["source", "source-sha256", "user"]
                .iter()
                .filter(|key| matches.get_one::<String>(key).is_some())
                .count();
            if source_count != 0 && source_count != 3 {
                bail!("binding predecessor selection requires source, source digest and native user together");
            }
            let current = if source_count == 3 {
                Some(selected(matches, name)?)
            } else {
                None
            };
            let (intent, resolved) = plan_target(matches, &excluded)?;
            let plan = smart_binding::build_binding_plan(
                name,
                intent,
                resolved,
                current.as_ref().map(|selected| &selected.receipt),
            )?;
            let digest = smart_binding::write_binding_plan(&output, &plan)?;
            report_plan(matches, &output, &digest, plan.change)?;
        }
        "refresh" => {
            let name = text(matches, "name")?;
            let current = selected(matches, name)?;
            let plan = smart_binding::refresh_binding_plan(name, &current.receipt, &excluded)?;
            let digest = smart_binding::write_binding_plan(&output, &plan)?;
            report_plan(matches, &output, &digest, plan.change)?;
        }
        "propose" | "remove" | "rollback" => {
            let source_path = PathBuf::from(text(matches, "source")?);
            let source_sha256 = text(matches, "source-sha256")?;
            let user = text(matches, "user")?;
            let mut rollback_path = None;
            let mut rollback_digest = None;
            if operation == "rollback" {
                let name = text(matches, "name")?;
                let current = selected(matches, name)?;
                let plan = smart_binding::rollback_binding_plan(name, &current.receipt)?;
                let path = PathBuf::from(text(matches, "plan-output")?);
                rollback_digest = Some(smart_binding::write_binding_plan(&path, &plan)?);
                rollback_path = Some(path);
            }
            let plan_path = if operation == "propose" {
                Some(PathBuf::from(text(matches, "plan")?))
            } else {
                rollback_path
            };
            let digest = source::propose(
                &source_path,
                source_sha256,
                user,
                match plan_path.as_ref() {
                    Some(path) => source::SourceChange::Plan {
                        plan_path: path,
                        plan_sha256: match rollback_digest.as_deref() {
                            Some(digest) => digest,
                            None => text(matches, "sha256")?,
                        },
                    },
                    None => source::SourceChange::Remove {
                        name: text(matches, "name")?,
                    },
                },
                &output,
            )?;
            if matches.get_flag("json") {
                println!(
                    "{}",
                    serde_json::to_string(
                        &serde_json::json!({"schema":"dev-auth-workload-binding-source-proposal-v1","proposal":output,"sha256":digest,"activated":false})
                    )?
                );
            } else {
                println!("binding_proposal={}", output.display());
                println!("binding_proposal_sha256={digest}");
            }
        }
        _ => bail!("binding operation is unsupported"),
    }
    Ok(0)
}

fn plan_target(
    matches: &ArgMatches,
    excluded: &[PathBuf],
) -> Result<(BindingIntent, BindingResolution)> {
    let alias = text(matches, "command-name")?;
    let workload = text(matches, "workload")?;
    let trust = match text(matches, "code-trust")? {
        "mutable" => BindingCodeTrust::Mutable,
        _ => BindingCodeTrust::Pinned,
    };
    let fixed = matches
        .get_many::<String>("arg")
        .map(|values| values.cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let index = matches
        .get_one::<String>("caller-argument-index")
        .map(|value| value.parse::<usize>())
        .transpose()
        .context("binding caller argument position is invalid")?;
    let executable = matches.get_one::<String>("executable");
    let shell = matches.get_one::<String>("shell");
    let source_stdin = matches.get_flag("source-stdin");
    let acknowledged = matches.get_flag("acknowledge-public-shell-source");
    let target = text(matches, "target")?;
    if target != "structured" && (executable.is_some() || !fixed.is_empty() || index.is_some()) {
        bail!("structured selectors require a structured binding target");
    }
    if target != "pinned-shell" && (shell.is_some() || source_stdin || acknowledged) {
        bail!("public shell selectors require a pinned-shell target");
    }
    let (mut intent, resolved) = match target {
        "current-resolution" => (
            BindingIntent::continuation(alias, workload)?,
            smart_binding::resolve_continuation(
                alias,
                &std::env::var_os("PATH").context("PATH is not set")?,
                excluded,
            )?
            .into(),
        ),
        "structured" => {
            let executable = PathBuf::from(
                executable.context("structured target requires executable selection")?,
            );
            let resolved =
                smart_binding::resolve_structured_target_excluding(&executable, excluded)?;
            let mut intent = BindingIntent::structured(alias, workload, executable, fixed)?;
            if let (
                Some(index),
                BindingTargetIntent::Structured {
                    caller_argument_index,
                    ..
                },
            ) = (index, &mut intent.target)
            {
                *caller_argument_index = index;
            }
            (intent, resolved)
        }
        "pinned-shell" => {
            if trust != BindingCodeTrust::Pinned || !source_stdin || !acknowledged {
                bail!("pinned shell requires pinned trust, stdin source and public-source acknowledgement");
            }
            let shell =
                PathBuf::from(shell.context("pinned shell requires exact shell selection")?);
            let mut bytes = Vec::new();
            std::io::stdin()
                .lock()
                .take(64 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 64 * 1024 {
                bail!("public shell source exceeds its bound");
            }
            let source = String::from_utf8(bytes)
                .map_err(|_| anyhow::anyhow!("public shell source is not UTF-8"))?;
            smart_binding::pinned_shell_binding(
                alias,
                workload,
                &shell,
                source,
                acknowledged,
                excluded,
            )?
        }
        _ => bail!("binding target is unsupported"),
    };
    intent.code_trust = trust;
    intent.desktop_entry = matches.get_flag("desktop-entry");
    Ok((intent, resolved))
}

fn report_plan(
    matches: &ArgMatches,
    output: &std::path::Path,
    digest: &str,
    change: smart_binding::BindingPlanChange,
) -> Result<()> {
    if matches.get_flag("json") {
        println!(
            "{}",
            serde_json::to_string(
                &serde_json::json!({"schema":"dev-auth-workload-binding-plan-result-v1","plan":output,"sha256":digest,"change":change})
            )?
        );
    } else {
        println!("binding_plan={}", output.display());
        println!("binding_plan_sha256={digest}");
        println!("change={change:?}");
    }
    Ok(())
}
