use dev_tools_command::{run_bounded_command, BoundedCommand};
use dev_tools_product::{ProductId, BUILD_INFO_SCHEMA, OPERATION_RESULT_SCHEMA};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const OUTPUT_LIMIT: usize = 1 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductLifecycle {
    Current,
    Planned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductStandardStage {
    Inventory,
    BuildInfo,
    Full,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductDefinition {
    pub name: &'static str,
    pub lifecycle: ProductLifecycle,
    pub standard_stage: ProductStandardStage,
}

pub const PUBLIC_PRODUCTS: [ProductDefinition; 6] = [
    ProductDefinition {
        name: "update-all",
        lifecycle: ProductLifecycle::Current,
        standard_stage: ProductStandardStage::BuildInfo,
    },
    ProductDefinition {
        name: "dev-auth",
        lifecycle: ProductLifecycle::Current,
        standard_stage: ProductStandardStage::Inventory,
    },
    ProductDefinition {
        name: "dev-cache",
        lifecycle: ProductLifecycle::Current,
        standard_stage: ProductStandardStage::BuildInfo,
    },
    ProductDefinition {
        name: "sync-configs",
        lifecycle: ProductLifecycle::Current,
        standard_stage: ProductStandardStage::BuildInfo,
    },
    ProductDefinition {
        name: "skills-sync",
        lifecycle: ProductLifecycle::Current,
        standard_stage: ProductStandardStage::BuildInfo,
    },
    ProductDefinition {
        name: "release-admin",
        lifecycle: ProductLifecycle::Planned,
        standard_stage: ProductStandardStage::Inventory,
    },
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceDependencyFailure {
    WorkspacePackageOutsideRoot,
    ExternalPathDependency,
    ProductRuntimeCoupling,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkspaceDependencyReport {
    pub workspace_package_count: usize,
    pub failures: Vec<WorkspaceDependencyFailure>,
}

impl WorkspaceDependencyReport {
    pub fn is_conformant(&self) -> bool {
        self.failures.is_empty()
    }
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    manifest_path: PathBuf,
    dependencies: Vec<CargoDependency>,
}

#[derive(Deserialize)]
struct CargoDependency {
    name: String,
    path: Option<PathBuf>,
}

pub fn audit_workspace_metadata(
    workspace_root: &Path,
    metadata: &[u8],
) -> Result<WorkspaceDependencyReport, ConformanceError> {
    if !workspace_root.is_absolute() {
        return Err(ConformanceError::new(
            ConformanceErrorKind::InvalidWorkspace,
        ));
    }
    let metadata: CargoMetadata = serde_json::from_slice(metadata)
        .map_err(|_| ConformanceError::new(ConformanceErrorKind::Metadata))?;
    let current_products = PUBLIC_PRODUCTS
        .iter()
        .filter(|product| product.lifecycle == ProductLifecycle::Current)
        .map(|product| product.name)
        .collect::<Vec<_>>();
    let mut failures = Vec::new();
    for package in &metadata.packages {
        if !package.manifest_path.is_absolute()
            || !package.manifest_path.starts_with(workspace_root)
        {
            failures.push(WorkspaceDependencyFailure::WorkspacePackageOutsideRoot);
        }
        let package_is_product = current_products.contains(&package.name.as_str());
        for dependency in &package.dependencies {
            if dependency
                .path
                .as_deref()
                .is_some_and(|path| !path.is_absolute() || !path.starts_with(workspace_root))
            {
                failures.push(WorkspaceDependencyFailure::ExternalPathDependency);
            }
            if package_is_product
                && dependency.name != package.name
                && current_products.contains(&dependency.name.as_str())
            {
                failures.push(WorkspaceDependencyFailure::ProductRuntimeCoupling);
            }
        }
    }
    failures.sort_unstable();
    failures.dedup();
    Ok(WorkspaceDependencyReport {
        workspace_package_count: metadata.packages.len(),
        failures,
    })
}

pub struct ProductUnderTest {
    definition: ProductDefinition,
    identity: ProductId,
    executable: PathBuf,
    sandbox: PathBuf,
    environment: BTreeMap<OsString, OsString>,
}

impl ProductUnderTest {
    pub fn new(
        definition: ProductDefinition,
        executable: PathBuf,
        sandbox: &Path,
    ) -> Result<Self, ConformanceError> {
        if definition.lifecycle != ProductLifecycle::Current {
            return Err(ConformanceError::new(ConformanceErrorKind::PlannedProduct));
        }
        let identity = ProductId::parse(definition.name)
            .map_err(|_| ConformanceError::new(ConformanceErrorKind::InvalidProduct))?;
        let executable = validate_real_absolute_file(&executable)?;
        let sandbox = validate_real_absolute_directory(sandbox)?;
        let roots = SandboxRoots::create(&sandbox)?;
        Ok(Self {
            definition,
            identity,
            executable,
            sandbox,
            environment: roots.environment(),
        })
    }
}

struct SandboxRoots {
    home: PathBuf,
    config: PathBuf,
    cache: PathBuf,
    data: PathBuf,
    state: PathBuf,
    runtime: PathBuf,
    temp: PathBuf,
}

impl SandboxRoots {
    fn create(sandbox: &Path) -> Result<Self, ConformanceError> {
        let roots = Self {
            home: sandbox.join("home"),
            config: sandbox.join("config"),
            cache: sandbox.join("cache"),
            data: sandbox.join("data"),
            state: sandbox.join("state"),
            runtime: sandbox.join("runtime"),
            temp: sandbox.join("temp"),
        };
        for root in [
            &roots.home,
            &roots.config,
            &roots.cache,
            &roots.data,
            &roots.state,
            &roots.runtime,
            &roots.temp,
        ] {
            fs::create_dir(root)
                .map_err(|_| ConformanceError::new(ConformanceErrorKind::Sandbox))?;
        }
        Ok(roots)
    }

    fn environment(&self) -> BTreeMap<OsString, OsString> {
        [
            ("HOME", &self.home),
            ("USERPROFILE", &self.home),
            ("XDG_CONFIG_HOME", &self.config),
            ("XDG_CACHE_HOME", &self.cache),
            ("XDG_DATA_HOME", &self.data),
            ("XDG_STATE_HOME", &self.state),
            ("XDG_RUNTIME_DIR", &self.runtime),
            ("APPDATA", &self.config),
            ("LOCALAPPDATA", &self.state),
            ("TMPDIR", &self.temp),
            ("TEMP", &self.temp),
            ("TMP", &self.temp),
        ]
        .into_iter()
        .map(|(name, value)| (OsString::from(name), value.as_os_str().to_owned()))
        .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceFailure {
    Execution,
    Exit,
    Stdout,
    Stderr,
    Json,
    Schema,
    Identity,
    Grammar,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConformanceCheck {
    pub name: &'static str,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<ConformanceFailure>,
}

impl ConformanceCheck {
    fn passed(name: &'static str) -> Self {
        Self {
            name,
            passed: true,
            failure: None,
        }
    }

    fn failed(name: &'static str, failure: ConformanceFailure) -> Self {
        Self {
            name,
            passed: false,
            failure: Some(failure),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConformanceReport {
    pub product: String,
    pub stage: ProductStandardStage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub checks: Vec<ConformanceCheck>,
}

impl ConformanceReport {
    pub fn is_conformant(&self) -> bool {
        self.stage == ProductStandardStage::Full && self.passed_declared_stage()
    }

    pub fn passed_declared_stage(&self) -> bool {
        self.checks.iter().all(|check| check.passed)
    }
}

pub fn inspect_product(subject: &ProductUnderTest) -> Result<ConformanceReport, ConformanceError> {
    let mut checks = Vec::with_capacity(10);
    let version = inspect_version(subject, &mut checks);
    inspect_json_identity(
        subject,
        &["build-info", "--json"],
        "build_info",
        BUILD_INFO_SCHEMA,
        version.as_deref(),
        &mut checks,
    );
    for (shell, name) in [
        ("bash", "completion_bash"),
        ("zsh", "completion_zsh"),
        ("fish", "completion_fish"),
        ("elvish", "completion_elvish"),
        ("powershell", "completion_powershell"),
    ] {
        inspect_completion(subject, shell, name, &mut checks);
    }
    inspect_json_identity(
        subject,
        &["doctor", "--json"],
        "doctor",
        OPERATION_RESULT_SCHEMA,
        None,
        &mut checks,
    );
    inspect_json_identity(
        subject,
        &["update", "status", "--json"],
        "update_status",
        OPERATION_RESULT_SCHEMA,
        None,
        &mut checks,
    );
    inspect_help(subject, &mut checks);
    Ok(ConformanceReport {
        product: subject.definition.name.to_owned(),
        stage: ProductStandardStage::Full,
        version,
        checks,
    })
}

pub fn inspect_declared_stage(
    subject: &ProductUnderTest,
) -> Result<ConformanceReport, ConformanceError> {
    match subject.definition.standard_stage {
        ProductStandardStage::Inventory => Ok(ConformanceReport {
            product: subject.definition.name.to_owned(),
            stage: ProductStandardStage::Inventory,
            version: None,
            checks: Vec::new(),
        }),
        ProductStandardStage::BuildInfo => {
            let mut checks = Vec::with_capacity(2);
            let version = inspect_version(subject, &mut checks);
            inspect_json_identity(
                subject,
                &["build-info", "--json"],
                "build_info",
                BUILD_INFO_SCHEMA,
                version.as_deref(),
                &mut checks,
            );
            Ok(ConformanceReport {
                product: subject.definition.name.to_owned(),
                stage: ProductStandardStage::BuildInfo,
                version,
                checks,
            })
        }
        ProductStandardStage::Full => inspect_product(subject),
    }
}

fn inspect_version(
    subject: &ProductUnderTest,
    checks: &mut Vec<ConformanceCheck>,
) -> Option<String> {
    let name = "version";
    let output = match run(subject, &["--version"]) {
        Ok(output) => output,
        Err(failure) => {
            checks.push(ConformanceCheck::failed(name, failure));
            return None;
        }
    };
    if !output.status.success() {
        checks.push(ConformanceCheck::failed(name, ConformanceFailure::Exit));
        return None;
    }
    if !output.stderr.is_empty() {
        checks.push(ConformanceCheck::failed(name, ConformanceFailure::Stderr));
        return None;
    }
    let stdout = match std::str::from_utf8(&output.stdout) {
        Ok(stdout) => stdout,
        Err(_) => {
            checks.push(ConformanceCheck::failed(name, ConformanceFailure::Stdout));
            return None;
        }
    };
    let expected_prefix = format!("{} ", subject.identity);
    let line = stdout.strip_suffix('\n').unwrap_or(stdout);
    if line.contains(['\r', '\n']) || !line.starts_with(&expected_prefix) {
        checks.push(ConformanceCheck::failed(name, ConformanceFailure::Identity));
        return None;
    }
    let version = &line[expected_prefix.len()..];
    if Version::parse(version).is_err() {
        checks.push(ConformanceCheck::failed(name, ConformanceFailure::Identity));
        return None;
    }
    checks.push(ConformanceCheck::passed(name));
    Some(version.to_owned())
}

fn inspect_json_identity(
    subject: &ProductUnderTest,
    arguments: &[&str],
    name: &'static str,
    schema: &str,
    expected_version: Option<&str>,
    checks: &mut Vec<ConformanceCheck>,
) {
    let output = match run(subject, arguments) {
        Ok(output) => output,
        Err(failure) => {
            checks.push(ConformanceCheck::failed(name, failure));
            return;
        }
    };
    if !output.status.success() {
        checks.push(ConformanceCheck::failed(name, ConformanceFailure::Exit));
        return;
    }
    if !output.stderr.is_empty() {
        checks.push(ConformanceCheck::failed(name, ConformanceFailure::Stderr));
        return;
    }
    let value: Value = match serde_json::from_slice(&output.stdout) {
        Ok(value) => value,
        Err(_) => {
            checks.push(ConformanceCheck::failed(name, ConformanceFailure::Json));
            return;
        }
    };
    if value.get("schema").and_then(Value::as_str) != Some(schema) {
        checks.push(ConformanceCheck::failed(name, ConformanceFailure::Schema));
        return;
    }
    if value.get("product").and_then(Value::as_str) != Some(subject.identity.as_str()) {
        checks.push(ConformanceCheck::failed(name, ConformanceFailure::Identity));
        return;
    }
    if expected_version.is_some()
        && value.get("version").and_then(Value::as_str) != expected_version
    {
        checks.push(ConformanceCheck::failed(name, ConformanceFailure::Identity));
        return;
    }
    checks.push(ConformanceCheck::passed(name));
}

fn inspect_completion(
    subject: &ProductUnderTest,
    shell: &str,
    name: &'static str,
    checks: &mut Vec<ConformanceCheck>,
) {
    let output = match run(subject, &["completion", shell]) {
        Ok(output) => output,
        Err(failure) => {
            checks.push(ConformanceCheck::failed(name, failure));
            return;
        }
    };
    let failure = if !output.status.success() {
        Some(ConformanceFailure::Exit)
    } else if !output.stderr.is_empty() {
        Some(ConformanceFailure::Stderr)
    } else if output.stdout.is_empty() {
        Some(ConformanceFailure::Stdout)
    } else {
        None
    };
    checks.push(match failure {
        Some(failure) => ConformanceCheck::failed(name, failure),
        None => ConformanceCheck::passed(name),
    });
}

fn inspect_help(subject: &ProductUnderTest, checks: &mut Vec<ConformanceCheck>) {
    let name = "help_grammar";
    let output = match run(subject, &["--help"]) {
        Ok(output) => output,
        Err(failure) => {
            checks.push(ConformanceCheck::failed(name, failure));
            return;
        }
    };
    if !output.status.success() {
        checks.push(ConformanceCheck::failed(name, ConformanceFailure::Exit));
        return;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let required = [
        "build-info",
        "completion",
        "doctor",
        "update",
        "status",
        "check",
        "install",
        "apply",
        "rollback",
    ];
    if required.iter().any(|token| !stdout.contains(token)) {
        checks.push(ConformanceCheck::failed(name, ConformanceFailure::Grammar));
        return;
    }
    checks.push(ConformanceCheck::passed(name));
}

fn run(
    subject: &ProductUnderTest,
    arguments: &[&str],
) -> Result<dev_tools_command::BoundedCommandOutput, ConformanceFailure> {
    let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
    run_bounded_command(&BoundedCommand {
        executable: &subject.executable,
        arguments: &arguments,
        environment: &subject.environment,
        cwd: Some(&subject.sandbox),
        timeout: COMMAND_TIMEOUT,
        output_limit: OUTPUT_LIMIT,
    })
    .map_err(|_| ConformanceFailure::Execution)
}

fn validate_real_absolute_file(path: &Path) -> Result<PathBuf, ConformanceError> {
    if !path.is_absolute() || !dev_tools_command::is_executable_file(path) {
        return Err(ConformanceError::new(
            ConformanceErrorKind::InvalidExecutable,
        ));
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| ConformanceError::new(ConformanceErrorKind::InvalidExecutable))?;
    if canonical != path {
        return Err(ConformanceError::new(
            ConformanceErrorKind::InvalidExecutable,
        ));
    }
    Ok(canonical)
}

fn validate_real_absolute_directory(path: &Path) -> Result<PathBuf, ConformanceError> {
    if !path.is_absolute() {
        return Err(ConformanceError::new(ConformanceErrorKind::InvalidSandbox));
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| ConformanceError::new(ConformanceErrorKind::InvalidSandbox))?;
    if canonical != path || !canonical.is_dir() {
        return Err(ConformanceError::new(ConformanceErrorKind::InvalidSandbox));
    }
    Ok(canonical)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConformanceErrorKind {
    PlannedProduct,
    InvalidProduct,
    InvalidExecutable,
    InvalidSandbox,
    Sandbox,
    InvalidWorkspace,
    Metadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConformanceError {
    kind: ConformanceErrorKind,
}

impl ConformanceError {
    const fn new(kind: ConformanceErrorKind) -> Self {
        Self { kind }
    }
}

impl fmt::Display for ConformanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            ConformanceErrorKind::PlannedProduct => "planned product cannot be inspected",
            ConformanceErrorKind::InvalidProduct => "product identity is invalid",
            ConformanceErrorKind::InvalidExecutable => "product executable is invalid",
            ConformanceErrorKind::InvalidSandbox => "conformance sandbox is invalid",
            ConformanceErrorKind::Sandbox => "conformance sandbox could not be prepared",
            ConformanceErrorKind::InvalidWorkspace => "workspace root is invalid",
            ConformanceErrorKind::Metadata => "workspace metadata is invalid",
        })
    }
}

impl Error for ConformanceError {}
