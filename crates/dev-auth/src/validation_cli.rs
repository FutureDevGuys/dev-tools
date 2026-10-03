//! Component selection and rendering share their definition with completion.
use clap::{Arg, ArgAction, Command};
use dev_auth::{ComponentValidationReport, ValidationComponent, ValidationRequest};
use std::ffi::{OsStr, OsString};
use std::io::Write;

pub(super) fn specification() -> Command {
    Command::new("validate")
        .bin_name("dev-auth validate")
        .about("Observe configuration, tools and provider access independently")
        .disable_help_subcommand(true)
        .arg(
            Arg::new("component")
                .long("component")
                .value_parser(["all", "configuration", "tools", "providers"])
                .default_value("all")
                .help("Select checks; provider checks do not execute Git or GitHub CLI"),
        )
        .arg(
            Arg::new("online")
                .long("online")
                .action(ArgAction::SetTrue)
                .help("Explicitly check selected provider resources using enrolled credentials"),
        )
        .arg(
            Arg::new("non-interactive")
                .long("non-interactive")
                .action(ArgAction::SetTrue)
                .help("Never unlock or prompt for enrollment; report unavailable access promptly"),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .action(ArgAction::SetTrue)
                .help("Emit one value-free versioned observation document"),
        )
}

pub(super) fn run(arguments: Vec<OsString>) -> i32 {
    let json = arguments.iter().any(|value| value == OsStr::new("--json"));
    let parsed = specification()
        .try_get_matches_from(std::iter::once(OsString::from("validate")).chain(arguments));
    let parsed = match parsed {
        Ok(parsed) => parsed,
        Err(error) if !json && error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return if std::io::stdout()
                .lock()
                .write_all(specification().render_long_help().to_string().as_bytes())
                .is_ok()
            {
                0
            } else {
                1
            };
        }
        Err(_) => return render(ComponentValidationReport::invalid_invocation(), json, false),
    };
    let component = match parsed.get_one::<String>("component").map(String::as_str) {
        Some("all") => ValidationComponent::All,
        Some("configuration") => ValidationComponent::Configuration,
        Some("tools") => ValidationComponent::Tools,
        Some("providers") => ValidationComponent::Providers,
        _ => return render(ComponentValidationReport::invalid_invocation(), json, false),
    };
    let request = ValidationRequest {
        component,
        online: parsed.get_flag("online"),
        noninteractive: parsed.get_flag("non-interactive"),
    };
    render(
        dev_auth::validate_components(request),
        json,
        component == ValidationComponent::All,
    )
}

fn render(report: ComponentValidationReport, json: bool, aggregate: bool) -> i32 {
    let code = report.exit_code;
    let bytes = if json {
        match serde_json::to_vec(&report) {
            Ok(mut bytes) => {
                bytes.push(b'\n');
                bytes
            }
            Err(_) => return 1,
        }
    } else if code == 0 && aggregate && report.authority == Some("legacy_v1") {
        format!(
            "config_valid=true online={} declared_exec_profiles={} declared_ssh_profiles={} declared_secret_references={}\n",
            report.online,
            report.declared_exec_profiles.unwrap_or(0),
            report.declared_ssh_profiles.unwrap_or(0),
            report.declared_secret_references.unwrap_or(0),
        ).into_bytes()
    } else {
        let mut text = format!("validation_exit_code={code}\n");
        if let Some(kind) = report.error_kind {
            text.push_str(&format!("error_kind={kind}\n"));
        }
        for check in &report.checks {
            text.push_str(&format!(
                "{}={:?} checked={}\n",
                check.component, check.status, check.checked
            ));
        }
        text.into_bytes()
    };
    let written = if json || code == 0 {
        std::io::stdout().lock().write_all(&bytes)
    } else {
        std::io::stderr().lock().write_all(&bytes)
    };
    if written.is_ok() {
        code
    } else {
        1
    }
}
