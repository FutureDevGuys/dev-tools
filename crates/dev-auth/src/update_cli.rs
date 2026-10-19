//! Common update presentation. Linux mutation uses the full retained setup
//! transaction; platforms without a native adapter report unsupported.

use anyhow::{bail, Result};
#[cfg(target_os = "linux")]
use dev_auth::update_status::{execute, UpdateOperation};

#[cfg(target_os = "linux")]
pub(super) fn run(mut arguments: impl Iterator<Item = String>) -> Result<i32> {
    let operation = match arguments.next().as_deref() {
        Some("status") => UpdateOperation::Status,
        Some("check") => UpdateOperation::Check,
        Some("install") => UpdateOperation::Install { offline: false },
        Some("apply") => UpdateOperation::Apply { offline: false },
        Some("rollback") => UpdateOperation::Rollback,
        _ => bail!("update requires status, check, install, apply, or rollback"),
    };
    let mut json = false;
    let mut offline = false;
    for argument in arguments {
        match argument.as_str() {
            "--json" if !json => json = true,
            "--offline"
                if !offline
                    && matches!(
                        operation,
                        UpdateOperation::Install { .. } | UpdateOperation::Apply { .. }
                    ) =>
            {
                offline = true;
            }
            _ => bail!("update operation received an unsupported or duplicate argument"),
        }
    }
    let operation = match operation {
        UpdateOperation::Install { .. } => UpdateOperation::Install { offline },
        UpdateOperation::Apply { .. } => UpdateOperation::Apply { offline },
        operation => operation,
    };
    let report = execute(operation);
    if json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!("outcome={:?}", report.outcome);
        println!("installation_state={:?}", report.installation_state);
        if let Some(version) = &report.installed_version {
            println!("installed_version={version}");
        }
        if let Some(version) = &report.available_version {
            println!("available_version={version}");
        }
        if let Some(freshness) = report.cache_freshness {
            println!("cache_freshness={freshness:?}");
        }
        if let Some(kind) = report.error_kind {
            eprintln!("dev-auth: update {kind:?}");
        }
    }
    Ok(report.exit_code)
}

#[cfg(target_os = "linux")]
pub(super) fn worker(arguments: Vec<std::ffi::OsString>) -> i32 {
    use std::ffi::OsStr;
    if arguments.len() != 8
        || arguments[0] != OsStr::new("--plan")
        || arguments[2] != OsStr::new("--sha256")
        || arguments[4] != OsStr::new("--result")
        || arguments[6] != OsStr::new("--staging-lock-fd")
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
    if !plan.is_absolute() || !result.is_absolute() {
        return 2;
    }
    dev_auth::update_status::run_apply_worker(plan, digest, result, lock_fd)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn run(mut arguments: impl Iterator<Item = String>) -> Result<i32> {
    let operation = match arguments.next().as_deref() {
        Some("status") => dev_tools_product::CommonOperation::UpdateStatus,
        Some("check") => dev_tools_product::CommonOperation::UpdateCheck,
        Some("install") => dev_tools_product::CommonOperation::UpdateInstall,
        Some("apply") => dev_tools_product::CommonOperation::UpdateApply,
        Some("rollback") => dev_tools_product::CommonOperation::UpdateRollback,
        _ => bail!("update requires status, check, install, apply, or rollback"),
    };
    let mut json = false;
    let mut offline = false;
    for argument in arguments {
        match argument.as_str() {
            "--json" if !json => json = true,
            "--offline"
                if !offline
                    && matches!(
                        operation,
                        dev_tools_product::CommonOperation::UpdateInstall
                            | dev_tools_product::CommonOperation::UpdateApply
                    ) =>
            {
                offline = true;
            }
            _ => bail!("update operation received an unsupported or duplicate argument"),
        }
    }
    let _ = offline;
    let external = matches!(operation, dev_tools_product::CommonOperation::UpdateStatus)
        && crate::product_cli::running_has_version_layout().is_ok_and(|managed| !managed);
    let report = dev_tools_product::OperationResultV2 {
        schema: dev_tools_product::OPERATION_RESULT_V2_SCHEMA,
        product: dev_tools_product::ProductId::parse("dev-auth")?,
        operation,
        outcome: if external {
            dev_tools_product::OperationOutcome::External
        } else {
            dev_tools_product::OperationOutcome::Unsupported
        },
        changed: Some(false),
        installed_version: None,
        available_version: None,
        cache_freshness: Some(dev_tools_product::CacheFreshness::NotApplicable),
        installation_state: Some(if external {
            dev_tools_product::InstallationState::External
        } else {
            dev_tools_product::InstallationState::Unknown
        }),
        exit_code: if external { 0 } else { 3 },
        error_kind: (!external).then_some(dev_tools_product::ErrorKind::Unsupported),
    };
    if json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!(
            "outcome={}",
            if external { "external" } else { "unsupported" }
        );
        if !external {
            eprintln!("dev-auth: update requires a native platform adapter");
        }
    }
    Ok(report.exit_code)
}
