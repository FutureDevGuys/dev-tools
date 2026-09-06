//! Static public-command metadata, kept outside all credential and helper paths.
use clap::{Arg, ArgAction, Command, ValueHint};
use dev_tools_completion::Shell;
use std::io::Write;

pub(super) fn run(arguments: &[String]) -> i32 {
    let shell = match arguments {
        [shell] => shell.parse::<Shell>().ok(),
        _ => None,
    };
    let Some(shell) = shell else {
        eprintln!("dev-auth: completion requires bash|zsh|fish|elvish|powershell");
        return 2;
    };
    let Ok(bytes) = dev_tools_completion::render(shell, specification(), "dev-auth") else {
        eprintln!("dev-auth: could not render completion output");
        return 1;
    };
    if std::io::stdout().lock().write_all(&bytes).is_err() {
        eprintln!("dev-auth: could not write completion output");
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

fn value(name: &'static str) -> Arg {
    Arg::new(name).long(name).value_hint(ValueHint::Other)
}

fn path(name: &'static str) -> Arg {
    value(name).value_hint(ValueHint::FilePath)
}

fn choice<const N: usize>(name: &'static str, values: [&'static str; N]) -> Arg {
    // Closed values are complete tokens. Unlike opaque names/assignments they
    // should permit the shell to append a space after selecting a candidate.
    value(name)
        .value_hint(ValueHint::Unknown)
        .value_parser(values)
}

fn mode() -> Arg {
    choice("mode", ["strong", "user-only"])
}

fn format() -> Arg {
    choice("format", ["human", "json"])
}

fn positional(name: &'static str) -> Arg {
    Arg::new(name).value_hint(ValueHint::Other)
}

fn setup() -> Command {
    let mut setup = command("setup")
        .subcommand(
            command("template").arg(positional("template").value_parser([
                "deployment",
                "administrator-policy",
                "user-only-policy",
                "user-config",
            ])),
        )
        .subcommand(
            command("discover")
                .arg(mode())
                .arg(path("administrator-policy"))
                .arg(value("user-config")),
        )
        .subcommand(command("verify-release").args([
            path("root"),
            path("manifest"),
            path("artifact"),
        ]))
        .subcommand(command("plan-release").args([
            path("root"),
            path("manifest"),
            path("artifact"),
            path("output"),
            mode(),
        ]))
        .subcommand(command("plan").args([
            path("deployment"),
            mode(),
            choice("channel", ["stable"]),
            flag("offline"),
            path("release-root"),
            path("release-manifest"),
            path("release-artifact"),
            choice("activation", ["transparent", "inactive"]),
            path("administrator-policy"),
            value("user-config"),
            value("user-policy"),
            value("credential-intent"),
            path("output"),
            format(),
        ]))
        .subcommand(command("apply").args([
            path("plan"),
            value("sha256"),
            choice("authorize", ["sudo"]),
            value("credential-stdin"),
            value("credential-fd"),
            value("credential-file"),
            format(),
        ]))
        .subcommand(command("verify").args([mode(), path("plan"), value("sha256"), format()]))
        .subcommand(command("migrate-v1-preview").arg(path("output")))
        .subcommand(command("migrate-v1").args([
            path("config"),
            value("sha256"),
            value("v1-sha256"),
        ]));
    for name in ["readiness", "repair", "rollback", "deactivate", "uninstall"] {
        setup = setup.subcommand(command(name).arg(mode()));
    }
    for name in [
        "install-policy",
        "install-user-policy",
        "install-user-config",
    ] {
        setup = setup.subcommand(command(name).args([path("source"), value("sha256")]));
    }
    for name in ["update-policy", "update-user-policy", "update-user-config"] {
        setup = setup.subcommand(command(name).args([
            path("source"),
            value("sha256"),
            value("current-sha256"),
        ]));
    }
    for name in [
        "enroll-system",
        "enroll-user",
        "rotate-system",
        "rotate-user",
        "revoke-system",
        "revoke-user",
        "start-system",
        "stop-system",
        "purge-system-state",
        "purge-user-state",
    ] {
        setup = setup.subcommand(command(name));
    }
    setup
}

// Only implemented public grammar belongs here. This does not parse operations,
// discover profiles, expose private helper entrypoints or grant any authority.
fn specification() -> Command {
    let mut root = command("dev-auth")
        .arg(flag("help").short('h'))
        .arg(flag("version"))
        .subcommand(command("build-info").arg(flag("json")))
        .subcommand(command("help"))
        .subcommand(command("completion").arg(positional("shell").value_parser([
            "bash",
            "zsh",
            "fish",
            "elvish",
            "powershell",
        ])))
        .subcommand(setup())
        .subcommand(command("broker").subcommand(command("serve")))
        .subcommand(command("status").arg(flag("broker")))
        .subcommand(command("validate").arg(flag("online")))
        .subcommand(command("explain").arg(positional("command").value_parser(["git", "gh"])))
        .subcommand(command("ssh-public").args([
            value("profile"),
            choice("purpose", ["authentication", "signing"]),
        ]))
        .subcommand(
            command("exec")
                .arg(value("profile"))
                .arg(positional("command").last(true).num_args(1..)),
        )
        .subcommand(
            command("workload")
                .subcommand(
                    command("launch")
                        .arg(positional("name"))
                        .arg(positional("arguments").last(true).num_args(0..)),
                )
                .subcommand(
                    command("bind")
                        .subcommand(
                            command("discover")
                                .arg(positional("command"))
                                .arg(flag("json")),
                        )
                        .subcommand(
                            command("plan").args([
                                positional("name"),
                                value("workload"),
                                value("command-name"),
                                choice("target", ["current-resolution", "structured"]),
                                path("executable"),
                                value("arg")
                                    .action(clap::ArgAction::Append)
                                    .allow_hyphen_values(true),
                                value("caller-argument-index"),
                                path("output"),
                                flag("json"),
                            ]),
                        ),
                ),
        )
        .subcommand(
            command("reconcile")
                .subcommand(command("plan").args([
                    path("source"),
                    path("output"),
                    choice("format", ["json"]),
                ]))
                .subcommand(command("apply").args([
                    path("plan"),
                    value("sha256"),
                    choice("format", ["json"]),
                ]))
                .subcommand(command("verify").args([path("source"), choice("format", ["json"])])),
        );
    for name in ["sign-release-manifest", "agent", "ssh-load"] {
        root = root.subcommand(command(name).arg(value("profile")));
    }
    for name in ["enroll", "workspace-status", "agent-endpoint", "purge"] {
        root = root.subcommand(command(name));
    }
    root
}
