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

pub(super) fn setup_recovery_command() -> Command {
    command("recover")
        .bin_name("dev-auth setup recover")
        .disable_help_flag(false)
        .about("Resume retained setup using the exact installed candidate, without original input files")
        .args([
            mode(),
            format().default_value("human"),
            value("credential-stdin").value_name("SLOT"),
            value("credential-fd").value_name("SLOT=FD").action(ArgAction::Append),
            path("credential-file").value_name("SLOT=PATH").action(ArgAction::Append),
        ])
}

pub(super) fn setup_template_command() -> Command {
    command("template")
        .bin_name("dev-auth setup template")
        .disable_help_flag(false)
        .about("Print a version-matched setup source document")
        .long_about("Print a version-matched setup source document. administrator-grant-policy alone prints the deny-all grant policy; with --user and --maximum-duration it authorizes exactly one native account. The other templates accept no options.")
        .arg(
            positional("template")
                .required(true)
                .value_parser(dev_auth::SETUP_TEMPLATE_NAMES),
        )
        .args([
            value("user")
                .value_name("NAME")
                .value_hint(ValueHint::Username)
                .requires("maximum-duration")
                .help("Authorize this existing non-root account, resolved by name from the native account database (Linux)"),
            value("maximum-duration")
                .value_name("DURATION")
                .requires("user")
                .help("Longest grant the account may request, such as 30m, 12h or 2d"),
            choice("scope", ["user", "workload", "command"])
                .action(ArgAction::Append)
                .default_values(["user", "workload"])
                .requires("user")
                .help("Grant scope the account may request; repeat for each allowed scope"),
            choice("authority", ["administrator"])
                .default_value("administrator")
                .requires("user")
                .help("Authority the account may request"),
            flag("allow-delegation")
                .requires("user")
                .help("Allow the account to delegate narrowed grants [default: no delegation]"),
        ])
}

pub(super) fn setup_restoration_command() -> Command {
    command("restore")
        .bin_name("dev-auth setup restore")
        .disable_help_flag(false)
        .about("Restore the retained generation with integrations inactive; run the exact retained candidate")
        .args([mode(), format().default_value("human")])
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
        .subcommand(setup_template_command())
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
            choice("purpose", ["credentials", "privilege-only"]),
            path("grant-policy"),
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
            choice("authorize", ["sudo", "polkit"]),
            value("credential-stdin"),
            value("credential-fd"),
            value("credential-file"),
            format(),
        ]))
        .subcommand(command("verify").args([mode(), path("plan"), value("sha256"), format()]))
        .subcommand(setup_recovery_command())
        .subcommand(setup_restoration_command())
        .subcommand(command("migrate-v1-preview").arg(path("output")))
        .subcommand(command("migrate-v1").args([
            path("config"),
            value("sha256"),
            value("v1-sha256"),
        ]));
    #[cfg(target_os = "linux")]
    {
        setup = setup
            .subcommand(command("install-privilege-policy").args([path("source"), value("sha256")]))
            .subcommand(command("update-privilege-policy").args([
                path("source"),
                value("sha256"),
                value("current-sha256"),
            ]));
    }
    for name in ["readiness", "repair", "rollback", "deactivate", "uninstall"] {
        let mut operation = command(name).arg(mode());
        if name == "repair" {
            operation =
                operation.about("Repair exact retained owned state while preserving credentials");
        }
        if name == "uninstall" {
            operation = operation
                .about("Retire owned enforcement while preserving policy and credential state");
        }
        setup = setup.subcommand(operation);
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
        .subcommand(crate::update_cli::specification())
        .subcommand(crate::doctor::specification())
        .subcommand(crate::secret_cli::specification())
        .subcommand(command("broker").subcommand(command("serve")))
        .subcommand(command("status").arg(flag("broker")))
        .subcommand(crate::validation_cli::specification())
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
                .subcommand(crate::workload_cli::specification())
                .subcommand(dev_auth::binding_cli::specification()),
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
    #[cfg(target_os = "linux")]
    {
        root = root.subcommand(dev_auth::privilege::cli::specification());
    }
    for name in ["sign-release-manifest", "agent", "ssh-load"] {
        root = root.subcommand(command(name).arg(value("profile")));
    }
    for name in ["enroll", "workspace-status", "agent-endpoint", "purge"] {
        root = root.subcommand(command(name));
    }
    root
}
