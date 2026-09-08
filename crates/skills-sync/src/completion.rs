//! Source-owned completion metadata; no operational environment or lock lookup.
use clap::{Arg, ArgAction, Command, ValueHint};
use dev_tools_completion::Shell;
use std::io::Write;

pub(super) fn run(arguments: &[String]) -> i32 {
    let shell = match arguments {
        [shell] => shell.parse::<Shell>().ok(),
        _ => None,
    };
    let Some(shell) = shell else {
        eprintln!("skills-sync: completion requires bash|zsh|fish|elvish|powershell");
        return 2;
    };
    let Ok(bytes) = dev_tools_completion::render(shell, specification(), "skills-sync") else {
        eprintln!("skills-sync: could not render completion output");
        return 1;
    };
    if std::io::stdout().lock().write_all(&bytes).is_err() {
        eprintln!("skills-sync: could not write completion output");
        return 1;
    }
    0
}

fn command(name: &'static str) -> Command {
    Command::new(name)
        .disable_help_flag(true)
        .disable_help_subcommand(true)
}

fn flag(name: &'static str) -> Arg {
    Arg::new(name).long(name).action(ArgAction::SetTrue)
}

fn operational_options(mut command: Command) -> Command {
    for (name, short) in [
        ("help", 'h'),
        ("dry-run", 'n'),
        ("json", 'j'),
        ("yes", 'y'),
        ("quiet", 'q'),
        ("verbose", 'v'),
        ("global", 'g'),
        ("project", 'p'),
        ("both", 'b'),
        ("all-agents", 'A'),
    ] {
        command = command.arg(flag(name).short(short));
    }
    for name in ["apply", "no-project-lock", "no-color"] {
        command = command.arg(flag(name));
    }
    for (name, short, hint) in [
        ("global-lock-file", Some('G'), ValueHint::FilePath),
        ("project-lock-file", Some('P'), ValueHint::FilePath),
        ("skills-cmd", Some('c'), ValueHint::Other),
        ("command-timeout", None, ValueHint::Other),
        ("agent", Some('a'), ValueHint::Other),
        ("agent-dir", None, ValueHint::DirPath),
        ("source", None, ValueHint::Other),
        ("skill", None, ValueHint::Other),
    ] {
        let mut arg = Arg::new(name).long(name).value_hint(hint);
        if let Some(short) = short {
            arg = arg.short(short);
        }
        command = command.arg(arg);
    }
    for (name, values) in [
        ("scope", vec!["global", "project", "both"]),
        ("color", vec!["auto", "always", "never"]),
        ("link-policy", vec!["default", "off"]),
        ("adopt-policy", vec!["inferred", "off", "all"]),
        (
            "agent-link-policy",
            vec!["off", "warn", "safe", "reconcile"],
        ),
    ] {
        command = command.arg(Arg::new(name).long(name).value_parser(values));
    }
    command
}

// Describes the existing manual parser without replacing its compatibility
// behavior. No unimplemented common update or read-only doctor is advertised.
fn specification() -> Command {
    let mut root = operational_options(command("skills-sync"))
        .arg(flag("version"))
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
    for name in ["sync", "status", "doctor", "repair", "adopt", "help"] {
        root = root.subcommand(operational_options(command(name)));
    }
    root.subcommand(
        operational_options(command("lock"))
            .subcommand(operational_options(command("status")))
            .subcommand(operational_options(command("repair"))),
    )
}
