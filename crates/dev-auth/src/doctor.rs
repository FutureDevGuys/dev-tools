//! Local common diagnostics. This frontend never performs a provider operation.
use clap::{Arg, ArgAction, Command};
use dev_tools_product::{
    CommonOperation, ErrorKind, ExitCategory, InstallationState, OperationOutcome, OperationResult,
    ProductId,
};
use serde::Serialize;
use std::ffi::{OsStr, OsString};
use std::io::Write;

pub(super) fn specification() -> Command {
    Command::new("doctor")
        .bin_name("dev-auth doctor")
        .about("Inspect local installation readiness without contacting a provider or broker")
        .disable_help_subcommand(true)
        .arg(
            Arg::new("json")
                .long("json")
                .help("Emit one versioned JSON observation")
                .action(ArgAction::SetTrue),
        )
}

pub(super) fn help() -> String {
    specification().render_long_help().to_string()
}

#[derive(Serialize)]
struct Report {
    #[serde(flatten)]
    result: OperationResult,
    invoked_version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

pub(super) fn run(arguments: Vec<OsString>) -> i32 {
    let json = arguments.iter().any(|arg| arg == OsStr::new("--json"));
    let parsed = specification()
        .try_get_matches_from(std::iter::once(OsString::from("doctor")).chain(arguments));
    if !json
        && parsed
            .as_ref()
            .is_err_and(|error| error.kind() == clap::error::ErrorKind::DisplayHelp)
    {
        return if std::io::stdout()
            .lock()
            .write_all(help().as_bytes())
            .is_ok()
        {
            0
        } else {
            1
        };
    }
    let result = if parsed.is_err() {
        failure(
            ExitCategory::InvalidInput,
            ErrorKind::InvalidInvocation,
            OperationOutcome::Failed,
        )
        .map(|result| (result, None))
    } else {
        inspect()
    };
    let Ok((result, details)) = result else {
        eprintln!("dev-auth: local diagnostic result could not be constructed");
        return 1;
    };
    let code = result.exit_code;
    let report = Report {
        result,
        invoked_version: env!("CARGO_PKG_VERSION"),
        details,
    };
    let bytes = if json {
        serde_json::to_vec(&report)
    } else {
        Ok(format!(
            "dev-auth {} doctor: {:?}; installation={:?}; changed=false",
            report.invoked_version, report.result.outcome, report.result.installation_state
        )
        .into_bytes())
    };
    let Ok(mut bytes) = bytes else {
        return 1;
    };
    bytes.push(b'\n');
    if std::io::stdout().lock().write_all(&bytes).is_err() {
        return 1;
    }
    code
}

fn failure(
    category: ExitCategory,
    kind: ErrorKind,
    outcome: OperationOutcome,
) -> anyhow::Result<OperationResult> {
    Ok(OperationResult::failed(
        ProductId::parse("dev-auth")?,
        CommonOperation::Doctor,
        outcome,
        category,
        kind,
    )?)
}

#[cfg(target_os = "linux")]
fn inspect() -> anyhow::Result<(OperationResult, Option<serde_json::Value>)> {
    use dev_auth::diagnostics::CredentialObservation;
    let product = ProductId::parse("dev-auth")?;
    if !dev_auth::setup::running_executable_has_version_layout()? {
        return Ok((
            OperationResult::completed(
                product,
                CommonOperation::Doctor,
                OperationOutcome::External,
                false,
            )?
            .with_installation_state(InstallationState::External),
            None,
        ));
    }
    let status = match dev_auth::diagnostics::local_status() {
        Ok(status) => status,
        Err(_) => {
            return Ok((
                failure(
                    ExitCategory::OperationalFailure,
                    ErrorKind::Operational,
                    OperationOutcome::Failed,
                )?
                .with_installation_state(InstallationState::Unknown),
                None,
            ));
        }
    };
    let configured = status.policy_ready
        && status.user_config_ready
        && status.policy_resolution_ready
        && status.workload_launchers_ready
        && status.desktop_entries_ready
        && status.workload_tool_plane_ready;
    let result = if status.credential_observation == CredentialObservation::Unsafe {
        failure(
            ExitCategory::AuthorityViolation,
            ErrorKind::Authority,
            OperationOutcome::AuthorityViolation,
        )?
    } else if !configured || status.credential_observation == CredentialObservation::Missing {
        OperationResult::blocked(
            product,
            CommonOperation::Doctor,
            OperationOutcome::RequiresSetup,
            ErrorKind::RequiresSetup,
        )?
    } else {
        OperationResult::completed(
            product,
            CommonOperation::Doctor,
            if status.credential_observation == CredentialObservation::NotObservable {
                OperationOutcome::Unknown
            } else {
                OperationOutcome::Completed
            },
            false,
        )?
    }
    .with_installation_state(InstallationState::Managed)
    .with_versions(Some(&status.version), None);
    Ok((result, Some(serde_json::to_value(status)?)))
}

#[cfg(not(target_os = "linux"))]
fn inspect() -> anyhow::Result<(OperationResult, Option<serde_json::Value>)> {
    Ok((
        OperationResult::blocked(
            ProductId::parse("dev-auth")?,
            CommonOperation::Doctor,
            OperationOutcome::Unsupported,
            ErrorKind::Unsupported,
        )?
        .with_installation_state(InstallationState::Unknown),
        None,
    ))
}
