//! Static native-shell output only; never discovery, configuration or execution.
use clap::{Arg, ArgAction, Command, ValueHint};
use dev_tools_completion::Shell;
use std::io::Write;

pub(super) fn run(arguments: &[String]) -> Result<i32, String> {
    let [shell] = arguments else {
        return Err("completion requires bash|zsh|fish|elvish|powershell".into());
    };
    let shell: Shell = shell
        .parse()
        .map_err(|_| "completion requires bash|zsh|fish|elvish|powershell")?;
    let bytes = dev_tools_completion::render(shell, specification(), "artifact-update")
        .map_err(|error| error.to_string())?;
    if std::io::stdout().lock().write_all(&bytes).is_err() {
        eprintln!("artifact-update: could not write completion output");
        return Ok(1);
    }
    Ok(0)
}

fn command(name: &'static str) -> Command {
    // The current hand-written CLI accepts help only at its root.
    Command::new(name)
        .disable_help_flag(true)
        .disable_help_subcommand(true)
}

fn flag(name: &'static str) -> Arg {
    Arg::new(name).long(name).action(ArgAction::SetTrue)
}

fn catalog_options(command: Command) -> Command {
    command
        .arg(
            Arg::new("config")
                .long("config")
                .value_name("PATH")
                .value_hint(ValueHint::FilePath),
        )
        .arg(flag("json"))
}

fn id() -> Arg {
    Arg::new("id").value_name("ID").value_hint(ValueHint::Other)
}

// This is completion metadata for the implemented grammar, not a replacement
// for its authority validators. Contract tests cover its command/option shape.
fn specification() -> Command {
    let mut root = command("artifact-update")
        .arg(flag("help").short('h'))
        .arg(flag("version").short('V'))
        .subcommand(command("build-info").arg(flag("json").required(true)))
        .subcommand(
            command("completion").arg(Arg::new("shell").required(true).value_parser([
                "bash",
                "zsh",
                "fish",
                "elvish",
                "powershell",
            ])),
        );
    for name in ["list", "status", "doctor"] {
        root = root.subcommand(catalog_options(command(name)));
    }
    root = root.subcommand(
        catalog_options(command("check"))
            .arg(id().conflicts_with("all"))
            .arg(flag("all"))
            .arg(
                Arg::new("os")
                    .long("os")
                    .value_name("OS")
                    .value_hint(ValueHint::Other),
            )
            .arg(
                Arg::new("architecture")
                    .long("architecture")
                    .value_name("ARCH")
                    .value_hint(ValueHint::Other),
            ),
    );
    for name in ["install", "rollback", "recover"] {
        let mut operation = catalog_options(command(name)).arg(id().required(true));
        if name == "install" {
            operation = operation.arg(flag("offline"));
        }
        root = root.subcommand(operation);
    }
    root.subcommand(
        command("trust")
            .subcommand(catalog_options(command("initialize")).arg(id().required(true)))
            .subcommand(catalog_options(command("status")).arg(id().required(true)))
            .subcommand(catalog_options(command("recover")).arg(id().required(true))),
    )
    .subcommand(
        command("config")
            .subcommand(catalog_options(command("inspect")))
            .subcommand(catalog_options(command("recover")))
            .subcommand(
                catalog_options(command("apply"))
                    .arg(
                        Arg::new("from")
                            .long("from")
                            .required(true)
                            .value_name("PATH")
                            .value_hint(ValueHint::FilePath),
                    )
                    .arg(
                        Arg::new("expect")
                            .long("expect")
                            .required(true)
                            .value_name("absent|SHA256")
                            .value_hint(ValueHint::Other),
                    ),
            ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_metadata_covers_current_grammar_without_invented_commands() {
        specification().debug_assert();
        let names: Vec<_> = specification()
            .get_subcommands()
            .map(|command| command.get_name().to_owned())
            .collect();
        assert_eq!(
            names,
            [
                "build-info",
                "completion",
                "list",
                "status",
                "doctor",
                "check",
                "install",
                "rollback",
                "recover",
                "trust",
                "config"
            ]
        );
        for arguments in [
            vec![
                "check",
                "--all",
                "--os",
                "linux",
                "--architecture",
                "x86_64",
            ],
            vec!["install", "example", "--offline", "--json"],
            vec!["trust", "initialize", "example", "--config", "/config.toml"],
            vec!["trust", "recover", "example", "--json"],
            vec!["config", "recover", "--config", "/config.toml"],
            vec![
                "config",
                "apply",
                "--from",
                "/proposal.toml",
                "--expect",
                "absent",
            ],
        ] {
            assert!(specification()
                .try_get_matches_from(std::iter::once("artifact-update").chain(arguments))
                .is_ok());
        }
        for arguments in [
            vec!["rollback", "example", "--offline"],
            vec!["list", "--help"],
            vec!["update"],
            vec!["config", "recover", "--expect", "absent"],
        ] {
            assert!(specification()
                .try_get_matches_from(std::iter::once("artifact-update").chain(arguments))
                .is_err());
        }
    }
}
