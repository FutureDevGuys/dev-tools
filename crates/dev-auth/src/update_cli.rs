//! Common update grammar and value-free public result presentation.
use clap::{Arg, ArgAction, Command};
use dev_tools_product::{
    CommonOperation, ErrorKind, InstallationState, OperationOutcome, OperationResultV2, ProductId,
};
use std::ffi::{OsStr, OsString};
use std::io::Write;

pub(super) fn specification() -> Command {
    let flag = |name: &'static str| Arg::new(name).long(name).action(ArgAction::SetTrue);
    let operation = |name: &'static str| Command::new(name).arg(flag("json"));
    Command::new("update")
        .bin_name("dev-auth update")
        .disable_help_subcommand(true)
        .subcommand_required(true)
        .subcommand(operation("status"))
        .subcommand(operation("check"))
        .subcommand(operation("install").arg(flag("offline")))
        .subcommand(operation("apply").arg(flag("offline")))
        .subcommand(operation("rollback"))
}

pub(super) fn run(arguments: Vec<OsString>) -> i32 {
    let json = arguments
        .iter()
        .any(|argument| argument == OsStr::new("--json"));
    let requested = match arguments.first().and_then(|argument| argument.to_str()) {
        Some("check") => CommonOperation::UpdateCheck,
        Some("install") => CommonOperation::UpdateInstall,
        Some("apply") => CommonOperation::UpdateApply,
        Some("rollback") => CommonOperation::UpdateRollback,
        _ => CommonOperation::UpdateStatus,
    };
    let matches = specification()
        .try_get_matches_from(std::iter::once(OsString::from("update")).chain(arguments));
    if !json
        && matches
            .as_ref()
            .is_err_and(|error| error.kind() == clap::error::ErrorKind::DisplayHelp)
    {
        let help = matches.unwrap_err().to_string();
        return if std::io::stdout().lock().write_all(help.as_bytes()).is_ok() {
            0
        } else {
            1
        };
    }
    let report = match matches {
        Ok(matches) => {
            let (name, arguments) = matches.subcommand().expect("required update subcommand");
            #[cfg(target_os = "linux")]
            {
                use dev_auth::update_status::UpdateOperation;
                let operation = match name {
                    "status" => UpdateOperation::Status,
                    "check" => UpdateOperation::Check,
                    "install" => UpdateOperation::Install {
                        offline: arguments.get_flag("offline"),
                    },
                    "apply" => UpdateOperation::Apply {
                        offline: arguments.get_flag("offline"),
                    },
                    "rollback" => UpdateOperation::Rollback,
                    _ => unreachable!("closed update grammar"),
                };
                dev_auth::update_status::execute(operation)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (name, arguments);
                let external = requested == CommonOperation::UpdateStatus
                    && crate::product_cli::running_has_version_layout()
                        .is_ok_and(|managed| !managed);
                result(
                    requested,
                    if external {
                        OperationOutcome::External
                    } else {
                        OperationOutcome::Unsupported
                    },
                    if external { 0 } else { 3 },
                    (!external).then_some(ErrorKind::Unsupported),
                    if external {
                        InstallationState::External
                    } else {
                        InstallationState::Unknown
                    },
                )
            }
        }
        Err(_) => result(
            requested,
            OperationOutcome::Failed,
            2,
            Some(ErrorKind::InvalidInvocation),
            InstallationState::Unknown,
        ),
    };
    let code = report.exit_code;
    if json {
        let encoded = match serde_json::to_vec(&report) {
            Ok(encoded) => encoded,
            Err(_) => return 1,
        };
        let mut output = std::io::stdout().lock();
        if output
            .write_all(&encoded)
            .and_then(|_| output.write_all(b"\n"))
            .is_err()
        {
            return 1;
        }
    } else {
        println!("outcome={:?}", report.outcome);
        println!("installation_state={:?}", report.installation_state);
        if let Some(version) = report.installed_version {
            println!("installed_version={version}");
        }
        if let Some(version) = report.available_version {
            println!("available_version={version}");
        }
        if let Some(freshness) = report.cache_freshness {
            println!("cache_freshness={freshness:?}");
        }
        if let Some(kind) = report.error_kind {
            eprintln!("dev-auth: update {kind:?}");
        }
    }
    code
}

fn result(
    operation: CommonOperation,
    outcome: OperationOutcome,
    exit_code: i32,
    error_kind: Option<ErrorKind>,
    state: InstallationState,
) -> OperationResultV2 {
    OperationResultV2 {
        schema: dev_tools_product::OPERATION_RESULT_V2_SCHEMA,
        product: ProductId::parse("dev-auth").expect("fixed product id"),
        operation,
        outcome,
        changed: Some(false),
        installed_version: None,
        available_version: None,
        cache_freshness: Some(dev_tools_product::CacheFreshness::NotApplicable),
        installation_state: Some(state),
        exit_code,
        error_kind,
    }
}

#[cfg(target_os = "linux")]
pub(super) fn worker(arguments: Vec<std::ffi::OsString>) -> i32 {
    use std::ffi::OsStr;
    if arguments.len() != 10
        || arguments[0] != OsStr::new("--request")
        || arguments[2] != OsStr::new("--sha256")
        || arguments[4] != OsStr::new("--result")
        || arguments[6] != OsStr::new("--staging-lock-fd")
        || arguments[8] != OsStr::new("--staging-dir-fd")
    {
        return 2;
    }
    let digest = match arguments[3].to_str() {
        Some(digest)
            if digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) =>
        {
            digest
        }
        _ => return 2,
    };
    let plan = std::path::Path::new(&arguments[1]);
    let result = std::path::Path::new(&arguments[5]);
    let lock_fd = match arguments[7]
        .to_str()
        .and_then(|value| value.parse::<i32>().ok())
    {
        Some(fd) if fd >= 3 => fd,
        _ => return 2,
    };
    let directory_fd = match arguments[9]
        .to_str()
        .and_then(|value| value.parse::<i32>().ok())
    {
        Some(fd) if fd >= 3 && fd != lock_fd => fd,
        _ => return 2,
    };
    if !plan.is_absolute() || !result.is_absolute() {
        return 2;
    }
    dev_auth::update_status::run_apply_worker(plan, digest, result, lock_fd, directory_fd)
}
