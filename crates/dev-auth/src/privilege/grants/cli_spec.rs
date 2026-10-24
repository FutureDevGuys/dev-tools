//! One authoritative static grammar for the administrator grant family.
use clap::{Arg, ArgAction, Command, ValueHint};
use std::ffi::OsStr;

fn command(name: &'static str) -> Command {
    Command::new(name).disable_help_subcommand(true)
}

/// Direct public aliases for the administrator grant operations whose names do
/// not overlap the bounded maintenance family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectGrantCommand {
    Inspect,
    Exec,
    Delegate,
    Leave,
    Run,
}

impl DirectGrantCommand {
    const ALL: [Self; 5] = [
        Self::Inspect,
        Self::Exec,
        Self::Delegate,
        Self::Leave,
        Self::Run,
    ];

    /// Select only an exact native command name, without policy observation or
    /// lossy conversion of caller-owned arguments.
    pub fn from_name(name: &OsStr) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| name == OsStr::new(kind.name()))
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Exec => "exec",
            Self::Delegate => "delegate",
            Self::Leave => "leave",
            Self::Run => "run",
        }
    }

    fn command(self) -> Command {
        let command = command(self.name());
        match self {
            Self::Inspect => command
                .about("Inspect one grant without extending its lifetime")
                .arg(Arg::new("grant").required(true)),
            Self::Exec => command
                .about("Execute within an eligible native administrator grant")
                .arg(Arg::new("grant").long("grant"))
                .arg(
                    Arg::new("plan-sha256")
                        .long("plan-sha256")
                        .conflicts_with_all(["operation", "command"]),
                )
                .arg(
                    Arg::new("operation")
                        .long("operation")
                        .conflicts_with_all(["plan-sha256", "command"]),
                )
                .arg(result_file())
                .arg(
                    command_arguments()
                        .required_unless_present_any(["plan-sha256", "operation"]),
                ),
            Self::Delegate => command
                .about("Conserve and narrow an existing grant")
                .arg(Arg::new("grant").required(true))
                .args(grant_arguments()),
            Self::Leave => command
                .about("End the selected grant and explicitly leave managed privilege routing"),
            Self::Run => command
                .about("Run a program as yourself under a freshly approved grant that only its process tree can use")
                .arg(
                    Arg::new("duration")
                        .long("duration")
                        .required(true)
                        .help("Explicit finite duration, such as 30m, 12h, or 2d; the grant ends sooner when the program exits"),
                )
                .arg(
                    Arg::new("authority")
                        .long("authority")
                        .default_value("administrator")
                        .value_parser(["administrator"]),
                )
                .arg(
                    Arg::new("preserve-env")
                        .long("preserve-env")
                        .value_name("NAME")
                        .action(ArgAction::Append)
                        .help("Also pass this environment variable; the program otherwise gets only PATH, HOME, SHELL, USER, LOGNAME, TERM and LANG"),
                )
                .arg(result_file())
                .arg(command_arguments().required(true)),
        }
    }
}

fn result_file() -> Arg {
    Arg::new("result-file")
        .long("result-file")
        .value_parser(clap::builder::OsStringValueParser::new())
        .value_hint(ValueHint::FilePath)
        .help("Write value-free execution metadata separately from child streams; required with --format json")
}

fn command_arguments() -> Arg {
    Arg::new("command")
        .last(true)
        .num_args(1..)
        .value_parser(clap::builder::OsStringValueParser::new())
        .value_hint(ValueHint::CommandWithArguments)
}

fn control_arguments() -> [Arg; 2] {
    [
        Arg::new("format")
            .long("format")
            .global(true)
            .default_value("human")
            .value_parser(["human", "json"]),
        Arg::new("non-interactive")
            .long("non-interactive")
            .global(true)
            .action(ArgAction::SetTrue),
    ]
}

/// The consumed grammar for direct administrator aliases. Each alias carries
/// its grant controls so composing this tree does not widen maintenance options.
pub fn direct_specification() -> Command {
    command("privilege")
        .bin_name("dev-auth privilege")
        .about("Inspect, use, narrow, leave, and run under native administrator grants")
        .subcommand_required(true)
        .subcommands(
            DirectGrantCommand::ALL
                .into_iter()
                .map(|kind| kind.command().args(control_arguments())),
        )
}

fn grant_arguments() -> [Arg; 7] {
    [
        Arg::new("scope")
            .long("scope")
            .required(true)
            .value_parser(["user", "workload"]),
        Arg::new("authority")
            .long("authority")
            .required(true)
            .value_parser(["administrator", "exact-plan", "typed"]),
        Arg::new("duration")
            .long("duration")
            .required(true)
            .help("Explicit finite duration, such as 30m, 12h, or 2d"),
        Arg::new("idle")
            .long("idle")
            .help("Optional shorter idle expiry; omitted means no requested idle cutoff"),
        Arg::new("uses")
            .long("uses")
            .value_parser(clap::value_parser!(u64).range(1..)),
        Arg::new("plan-sha256").long("plan-sha256"),
        Arg::new("operation")
            .long("operation")
            .action(ArgAction::Append),
    ]
}

pub fn specification() -> Command {
    command("grant")
        .bin_name("dev-auth privilege grant")
        .about("Request, use, inspect, narrow, end, and run under native administrator grants")
        .subcommand_required(true)
        .args(control_arguments())
        .subcommand(
            command("request")
                .about("Obtain one freshly approved finite grant")
                .args(grant_arguments()),
        )
        .subcommand(
            command("status")
                .about("Observe only the caller's administrator grants")
                .arg(
                    Arg::new("require-remaining")
                        .long("require-remaining")
                        .value_name("DURATION")
                        .help("Fail unless the grant that covers this process is active with at least this long before its hard deadline"),
                )
                .arg(
                    Arg::new("scope")
                        .long("scope")
                        .requires("require-remaining")
                        .value_parser(["user", "workload", "command"])
                        .help("Check the covering grant of this scope instead of the one sudo routing selects"),
                ),
        )
        .subcommand(DirectGrantCommand::Inspect.command())
        .subcommand(
            command("revoke")
                .about("Revoke a grant and terminate its privileged descendants")
                .arg(Arg::new("grant").required(true)),
        )
        .subcommand(DirectGrantCommand::Leave.command())
        .subcommand(DirectGrantCommand::Delegate.command())
        .subcommand(DirectGrantCommand::Exec.command())
        .subcommand(DirectGrantCommand::Run.command())
}
