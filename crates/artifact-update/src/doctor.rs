use dev_tools_product::{
    CommonOperation, ErrorKind, ExitCategory, OperationOutcome, OperationResult, ProductId,
};
use dev_tools_update::artifact::ArtifactCatalog;
use serde::Serialize;

#[derive(Serialize)]
struct DoctorResult {
    #[serde(flatten)]
    common: OperationResult,
    scope: &'static str,
    healthy: bool,
    network_accessed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_count: Option<usize>,
}

pub(super) fn run(arguments: &[String]) -> Result<i32, String> {
    let json = arguments.iter().any(|argument| argument == "--json");
    let inspection = inspect(arguments);
    let product = ProductId::parse("artifact-update").map_err(|error| error.to_string())?;
    let common = match inspection {
        Ok(_) => OperationResult::completed(
            product,
            CommonOperation::Doctor,
            OperationOutcome::Completed,
            false,
        ),
        Err(kind) => OperationResult::failed(
            product,
            CommonOperation::Doctor,
            OperationOutcome::Failed,
            ExitCategory::InvalidInput,
            kind,
        ),
    }
    .map_err(|error| error.to_string())?;
    let exit_code = common.exit_code;
    let result = DoctorResult {
        common,
        scope: "configuration",
        healthy: inspection.is_ok(),
        network_accessed: false,
        artifact_count: inspection.ok(),
    };
    if json {
        super::write_json(&result)?;
    } else if let Some(count) = result.artifact_count {
        println!("configuration=valid artifacts={count}");
    }
    if let Some(kind) = result.common.error_kind {
        let message = match kind {
            ErrorKind::InvalidInvocation => "doctor invocation is invalid",
            _ => "configuration is unavailable or invalid",
        };
        eprintln!("artifact-update: {message}");
    }
    Ok(exit_code)
}

fn inspect(arguments: &[String]) -> Result<usize, ErrorKind> {
    let (config, _) =
        super::parse_catalog_options(arguments).map_err(|_| ErrorKind::InvalidInvocation)?;
    let bytes = super::read_bounded_config(&config).map_err(|_| ErrorKind::InvalidConfiguration)?;
    let source = std::str::from_utf8(&bytes).map_err(|_| ErrorKind::InvalidConfiguration)?;
    let catalog = ArtifactCatalog::parse(source).map_err(|_| ErrorKind::InvalidConfiguration)?;
    let count = catalog.iter().len();
    Ok(count)
}
