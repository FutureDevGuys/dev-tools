//! One finite standalone receipt-install ABI. Deployment evidence is supplied
//! independently by native root; no producer checkout or sibling runtime is read.
use super::{
    custody,
    policy::{self, Access, ExactPlan, Resource},
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub const PROTOCOL: &str = "dev-tools-receipt-install-v1";
pub const EXECUTOR_SCHEMA: &str = "dev-tools-maintenance-executor-v1";
pub const RESULT_SCHEMA: &str = "dev-tools-receipt-install-result-v1";
const EXECUTORS: &str = "/usr/local/lib/dev-tools-maintenance/executors/";
const GENERATIONS: &str = "/var/lib/dev-tools-maintenance/generations/";
const TARGETS: &str = "/opt/dev-tools-maintenance/";
const JOURNALS: &str = "/var/lib/dev-tools-maintenance/journals/";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutorBinding {
    pub receipt_path: String,
    pub receipt_sha256: String,
    pub source_fingerprint: String,
    pub build_receipt_sha256: String,
}

/// Explicit administrator deployment record, not a signature or self-report.
/// Policy independently pins all provenance fields and these exact bytes.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutorReceipt {
    pub schema: String,
    pub protocol: String,
    pub executable: String,
    pub executable_sha256: String,
    pub executable_length: u64,
    pub source_fingerprint: String,
    pub build_receipt_sha256: String,
}

// Declaration order is lexicographic, matching the closed ABI's compact JCS
// bytes. There are no numbers, flexible maps or omitted optional fields here.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub action: Action,
    pub binary: String,
    pub candidate: Artifact,
    pub destination: String,
    pub journal: String,
    pub previous: Option<Artifact>,
    pub schema: String,
    pub tool: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Status,
    Install,
    Resume,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub generation: String,
    pub receipt_sha256: String,
    pub source_fingerprint: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub attempted: bool,
    pub cleanup_errors: Vec<String>,
    pub error: Option<String>,
    pub outcome: String,
    pub retained_staging: Option<String>,
    pub schema: String,
}

fn component(value: &str, limit: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > limit
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
    {
        bail!("receipt installation identifier is invalid");
    }
    Ok(())
}
fn prefixed_digest(value: &str) -> Result<()> {
    policy::hex_digest(
        value
            .strip_prefix("sha256:")
            .context("receipt installation digest prefix is absent")?,
    )
}
fn executor_directory(executable: &str) -> Result<PathBuf> {
    let id = executable
        .strip_prefix(EXECUTORS)
        .and_then(|v| v.strip_suffix("/executor"))
        .context("receipt installer is outside its fixed deployment namespace")?;
    component(id, 64)?;
    Ok(Path::new(EXECUTORS).join(id))
}
fn validate_artifact(artifact: &Artifact) -> Result<()> {
    let id = artifact
        .generation
        .strip_prefix(GENERATIONS)
        .context("receipt generation is outside its fixed namespace")?;
    // Producer naming stays opaque here. Its owner verifies the generation's
    // exact filename/receipt relationship without a product branch in Dev Auth.
    component(id, 128)?;
    prefixed_digest(&artifact.receipt_sha256)?;
    prefixed_digest(&artifact.source_fingerprint)
}

pub fn parse_request(bytes: &[u8]) -> Result<Request> {
    if bytes.is_empty() || bytes.len() > policy::MAX_ARGUMENT_BYTES {
        bail!("receipt installation request exceeds bounds");
    }
    let request: Request =
        serde_json::from_slice(bytes).context("invalid receipt installation request")?;
    if policy::canonical(&request)? != bytes || request.schema != PROTOCOL {
        bail!("receipt installation request is not canonical");
    }
    component(&request.tool, 64)?;
    component(&request.binary, 64)?;
    validate_artifact(&request.candidate)?;
    if let Some(previous) = &request.previous {
        validate_artifact(previous)?;
        if request.action == Action::Status
            || previous.generation == request.candidate.generation
            || previous.receipt_sha256 == request.candidate.receipt_sha256
        {
            bail!("receipt installation predecessor is invalid");
        }
    }
    let audience = request
        .destination
        .strip_prefix(TARGETS)
        .and_then(|v| v.strip_suffix("/bin"))
        .context("receipt target is outside its fixed system namespace")?;
    component(audience, 64)?;
    if request.journal != format!("{JOURNALS}{audience}/{}", request.binary) {
        bail!("receipt journal does not match its exact target audience");
    }
    Ok(request)
}

pub fn resources(request: &Request) -> BTreeMap<String, Resource> {
    let mut result = BTreeMap::from([
        (
            "candidate".into(),
            Resource {
                path: request.candidate.generation.clone(),
                access: Access::ReadOnly,
            },
        ),
        (
            "destination".into(),
            Resource {
                path: request.destination.clone(),
                access: if request.action == Action::Status {
                    Access::ReadOnly
                } else {
                    Access::ReadWrite
                },
            },
        ),
        (
            "journal".into(),
            Resource {
                path: request.journal.clone(),
                access: if request.action == Action::Status {
                    Access::ReadOnly
                } else {
                    Access::ReadWrite
                },
            },
        ),
    ]);
    if let Some(previous) = &request.previous {
        result.insert(
            "previous".into(),
            Resource {
                path: previous.generation.clone(),
                access: Access::ReadOnly,
            },
        );
    }
    result
}

pub fn validate_plan(binding: Option<&ExecutorBinding>, plan: &ExactPlan) -> Result<Request> {
    let binding =
        binding.context("receipt installer requires independently pinned deployment evidence")?;
    let directory = executor_directory(&plan.executable)?;
    if Path::new(&binding.receipt_path) != directory.join("executor-v1.json") {
        bail!("receipt installer deployment receipt is outside its exact namespace");
    }
    policy::hex_digest(&binding.receipt_sha256)?;
    prefixed_digest(&binding.source_fingerprint)?;
    prefixed_digest(&binding.build_receipt_sha256)?;
    if plan.arguments != [b"maintenance-v1".to_vec()]
        || !plan.environment.is_empty()
        || plan.working_directory != "/"
    {
        bail!("receipt installer command is not the closed native entrypoint");
    }
    let request = parse_request(&plan.input)?;
    if plan.resources != resources(&request) {
        bail!("receipt installation resources differ from the derived effect scope");
    }
    Ok(request)
}

fn validate_receipt_bytes(
    binding: &ExecutorBinding,
    plan: &ExactPlan,
    bytes: &[u8],
) -> Result<ExecutorReceipt> {
    let receipt: ExecutorReceipt = policy::parse(bytes)?;
    if policy::canonical(&receipt)? != bytes
        || policy::digest(bytes) != binding.receipt_sha256
        || receipt.schema != EXECUTOR_SCHEMA
        || receipt.protocol != PROTOCOL
        || receipt.executable != plan.executable
        || receipt.executable_sha256 != plan.executable_sha256
        || receipt.executable_length == 0
        || receipt.executable_length > 256 * 1024 * 1024
        || receipt.source_fingerprint != binding.source_fingerprint
        || receipt.build_receipt_sha256 != binding.build_receipt_sha256
    {
        bail!("receipt installer deployment evidence differs from independent approval");
    }
    Ok(receipt)
}

/// Called only in root infrastructure after native administrator approval. Public
/// planning never needs to open private root generations or installation state.
pub fn verify_native(
    binding: &ExecutorBinding,
    plan: &ExactPlan,
    held: &BTreeMap<String, custody::HeldResource>,
) -> Result<()> {
    validate_plan(Some(binding), plan)?;
    let bytes = custody::read_document(Path::new(&binding.receipt_path), 0, 0o644)?;
    let receipt = validate_receipt_bytes(binding, plan, &bytes)?;
    let executable =
        custody::held_root_executable(Path::new(&plan.executable), &plan.executable_sha256)?;
    if executable.open_read_handle()?.metadata()?.len() != receipt.executable_length {
        bail!("receipt installer artifact length differs from deployment evidence");
    }
    if held.len() != plan.resources.len()
        || held.iter().any(|(name, resource)| {
            plan.resources
                .get(name)
                .is_none_or(|expected| resource.path != Path::new(&expected.path))
        })
    {
        bail!("receipt installation retained resource scope differs from its plan");
    }
    let protected = protected_directory_identities(binding, plan)?;
    let mut identities = Vec::new();
    for (name, resource) in held {
        let stat = rustix::fs::fstat(&resource.descriptor)?;
        identities.push(((stat.st_dev, stat.st_ino), plan.resources[name].access));
    }
    reject_aliases(&identities, &protected)?;
    for (name, resource) in held {
        custody::validate_parents(&resource.path, 0, false)?;
        resource.verify()?;
        let metadata = rustix::fs::fstat(&resource.descriptor)?;
        let mode = metadata.st_mode & 0o7777;
        if metadata.st_uid != 0
            || rustix::fs::FileType::from_raw_mode(metadata.st_mode)
                != rustix::fs::FileType::Directory
            || (name == "destination" && !matches!(mode, 0o700 | 0o755))
            || (name != "destination" && mode != 0o700)
        {
            bail!("receipt installation resource lacks native root custody");
        }
    }
    Ok(())
}

fn reject_aliases(
    resources: &[((u64, u64), Access)],
    protected: &BTreeSet<(u64, u64)>,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for (identity, access) in resources {
        if !seen.insert(*identity) || (*access == Access::ReadWrite && protected.contains(identity))
        {
            bail!("receipt installation resource aliases protected or another resource authority");
        }
    }
    Ok(())
}
fn protected_directory_identities(
    binding: &ExecutorBinding,
    plan: &ExactPlan,
) -> Result<BTreeSet<(u64, u64)>> {
    let main = crate::setup::validate_installed_maintenance_helper()?;
    let mut names = BTreeSet::<PathBuf>::new();
    for leaf in [
        Path::new(&plan.executable),
        Path::new(&binding.receipt_path),
        main.as_path(),
        Path::new(custody::HELPER_PATH),
        Path::new(custody::POLICY_PATH),
        Path::new(custody::RECEIPT_PATH),
        Path::new(custody::POLKIT_PATH),
    ] {
        names.extend(leaf.ancestors().skip(1).map(Path::to_path_buf));
    }
    for directory in [
        "/usr/local/bin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/lib",
        "/usr/lib64",
        "/usr/libexec",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/etc/systemd",
        "/usr/lib/systemd",
        "/lib/systemd",
        "/etc/polkit-1",
        "/etc/sudoers.d",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
        "/proc",
        "/sys",
        "/dev",
        "/run",
    ] {
        names.insert(directory.into());
    }
    let mut identities = BTreeSet::new();
    for name in names {
        // Fixed protected runtime aliases (/bin,/lib) are resolved only for
        // defensive identity comparison, never to acquire writable authority.
        match std::fs::metadata(&name) {
            Ok(metadata) if metadata.is_dir() => {
                identities.insert((metadata.dev(), metadata.ino()));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => bail!("protected maintenance parent is not a directory"),
            Err(error) => return Err(error).context("observe protected maintenance directory"),
        }
    }
    Ok(identities)
}

/// A malformed success report is not an observed successful installation. Actual
/// child exit/signal remains a separate native fact in the public observation.
pub fn verify_report(request: &Request, bytes: &[u8], exit_code: i32) -> Result<Report> {
    let report: Report = policy::parse(bytes)?;
    if policy::canonical(&report)? != bytes
        || report.schema != RESULT_SCHEMA
        || report.cleanup_errors.len() > 32
        || report.cleanup_errors.iter().any(|s| s.len() > 256)
        || report.error.as_ref().is_some_and(|s| s.len() > 256)
        || report
            .retained_staging
            .as_ref()
            .is_some_and(|s| s.len() > 4096)
    {
        bail!("receipt installation result is not the bounded canonical protocol");
    }
    let success = matches!(report.outcome.as_str(), "current" | "changed" | "unchanged");
    if success {
        if exit_code != 0
            || report.error.is_some()
            || !report.cleanup_errors.is_empty()
            || report.retained_staging.is_some()
            || (request.action == Action::Status
                && (report.outcome != "current" || report.attempted))
            || (request.action != Action::Status && report.outcome == "current")
            || (report.outcome == "changed" && !report.attempted)
        {
            bail!("receipt installation success report is inconsistent");
        }
    } else if !matches!(
        (report.outcome.as_str(), exit_code),
        ("rejected", 2) | ("failed", 1) | ("failed", 129..=192)
    ) || report.error.is_none()
    {
        bail!("receipt installation failure report is inconsistent");
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request {
            action: Action::Install,
            binary: "sample-tool".into(),
            candidate: Artifact {
                generation: format!("{GENERATIONS}generation-one"),
                receipt_sha256: format!("sha256:{}", "11".repeat(32)),
                source_fingerprint: format!("sha256:{}", "22".repeat(32)),
            },
            destination: format!("{TARGETS}sample/bin"),
            journal: format!("{JOURNALS}sample/sample-tool"),
            previous: None,
            schema: PROTOCOL.into(),
            tool: "sample-tool".into(),
        }
    }
    #[test]
    fn closed_wire_is_checkout_free_and_canonical() {
        let r = request();
        let bytes = policy::canonical(&r).unwrap();
        assert_eq!(bytes, serde_json::to_vec(&r).unwrap());
        assert_eq!(parse_request(&bytes).unwrap(), r);
        let mut value = serde_json::to_value(r).unwrap();
        value["repo_root"] = "/private/source".into();
        assert!(parse_request(&policy::canonical(&value).unwrap()).is_err());
        value.as_object_mut().unwrap().remove("repo_root");
        value.as_object_mut().unwrap().remove("previous");
        assert!(parse_request(&policy::canonical(&value).unwrap()).is_err());
    }
    #[test]
    fn dedicated_namespaces_reject_host_hooks_aliases_and_shared_bins() {
        for path in [
            "/etc/cron.d",
            "/usr/local/bin",
            "/opt/dev-tools-maintenance/../bin",
            "/opt/dev-tools-maintenance/a/../b/bin",
            "/opt/dev-tools-maintenance/a//bin",
        ] {
            let mut r = request();
            r.destination = path.into();
            assert!(parse_request(&policy::canonical(&r).unwrap()).is_err());
        }
        let mut r = request();
        r.journal = "/var/lib/dev-tools-maintenance/journals/other/sample-tool".into();
        assert!(parse_request(&policy::canonical(&r).unwrap()).is_err());
        let mut r = request();
        r.previous = Some(r.candidate.clone());
        assert!(parse_request(&policy::canonical(&r).unwrap()).is_err());
    }
    #[test]
    fn status_scope_has_no_writes_or_predecessor() {
        let mut r = request();
        r.action = Action::Status;
        assert!(resources(&r).values().all(|r| r.access == Access::ReadOnly));
        r.previous = Some(Artifact {
            generation: format!("{GENERATIONS}prior"),
            receipt_sha256: format!("sha256:{}", "33".repeat(32)),
            source_fingerprint: format!("sha256:{}", "44".repeat(32)),
        });
        assert!(parse_request(&policy::canonical(&r).unwrap()).is_err());
    }
    #[test]
    fn output_cannot_claim_success_with_failure_or_wrong_action() {
        let r = request();
        let mut report = Report {
            attempted: true,
            cleanup_errors: vec![],
            error: None,
            outcome: "changed".into(),
            retained_staging: None,
            schema: RESULT_SCHEMA.into(),
        };
        verify_report(&r, &policy::canonical(&report).unwrap(), 0).unwrap();
        assert!(verify_report(&r, &policy::canonical(&report).unwrap(), 1).is_err());
        report.outcome = "current".into();
        assert!(verify_report(&r, &policy::canonical(&report).unwrap(), 0).is_err());
    }
    #[test]
    fn producer_status_golden_has_exact_no_lf_framing() {
        let bytes = include_bytes!("../../tests/fixtures/receipt-install-v1/status-result.json");
        let mut r = request();
        r.action = Action::Status;
        verify_report(&r, bytes, 0).unwrap();
        let mut with_lf = bytes.to_vec();
        with_lf.push(b'\n');
        assert!(verify_report(&r, &with_lf, 0).is_err());
    }
    #[test]
    fn bind_aliases_cannot_merge_scopes_or_write_protected_parents() {
        let protected = BTreeSet::from([(1, 9), (2, 7)]);
        assert!(reject_aliases(
            &[((1, 1), Access::ReadOnly), ((1, 1), Access::ReadWrite)],
            &protected
        )
        .is_err());
        assert!(reject_aliases(&[((1, 9), Access::ReadWrite)], &protected).is_err());
        reject_aliases(
            &[((1, 2), Access::ReadOnly), ((1, 3), Access::ReadWrite)],
            &protected,
        )
        .unwrap();
    }
    fn deployment() -> (ExecutorBinding, ExactPlan, ExecutorReceipt) {
        let r = request();
        let proof = ExecutorReceipt {
            schema: EXECUTOR_SCHEMA.into(),
            protocol: PROTOCOL.into(),
            executable: format!("{EXECUTORS}reviewed/executor"),
            executable_sha256: "55".repeat(32),
            executable_length: 1234,
            source_fingerprint: format!("sha256:{}", "66".repeat(32)),
            build_receipt_sha256: format!("sha256:{}", "77".repeat(32)),
        };
        let binding = ExecutorBinding {
            receipt_path: format!("{EXECUTORS}reviewed/executor-v1.json"),
            receipt_sha256: policy::digest(&policy::canonical(&proof).unwrap()),
            source_fingerprint: proof.source_fingerprint.clone(),
            build_receipt_sha256: proof.build_receipt_sha256.clone(),
        };
        let plan = ExactPlan {
            executable: proof.executable.clone(),
            executable_sha256: proof.executable_sha256.clone(),
            arguments: vec![b"maintenance-v1".to_vec()],
            environment: BTreeMap::new(),
            working_directory: "/".into(),
            resources: resources(&r),
            input: policy::canonical(&r).unwrap(),
            timeout_seconds: 10,
            output_limit: 8192,
        };
        (binding, plan, proof)
    }
    #[test]
    fn real_adapter_requires_exact_command_scope_and_independent_provenance() {
        let (binding, plan, proof) = deployment();
        validate_plan(Some(&binding), &plan).unwrap();
        validate_receipt_bytes(&binding, &plan, &policy::canonical(&proof).unwrap()).unwrap();
        assert!(validate_plan(None, &plan).is_err());
        for changed in [
            "executable",
            "executable_sha256",
            "source_fingerprint",
            "build_receipt_sha256",
            "protocol",
        ] {
            let mut value = serde_json::to_value(&proof).unwrap();
            value[changed] = "different".into();
            // Even a newly pinned record cannot contradict independent fields.
            let bytes = policy::canonical(&value).unwrap();
            let mut other = binding.clone();
            other.receipt_sha256 = policy::digest(&bytes);
            assert!(
                validate_receipt_bytes(&other, &plan, &bytes).is_err(),
                "{changed}"
            );
        }
        let mut value = proof.clone();
        value.executable_length = 0;
        let bytes = policy::canonical(&value).unwrap();
        let mut other = binding.clone();
        other.receipt_sha256 = policy::digest(&bytes);
        assert!(validate_receipt_bytes(&other, &plan, &bytes).is_err());
        for case in 0..7 {
            let mut value = plan.clone();
            match case {
                0 => value.arguments.push(b"--root-shell".to_vec()),
                1 => {
                    value
                        .environment
                        .insert("LD_PRELOAD".into(), "/anything".into());
                }
                2 => value.working_directory = "/tmp".into(),
                3 => value.executable = "/usr/bin/install".into(),
                4 => value.resources.get_mut("candidate").unwrap().access = Access::ReadWrite,
                5 => value.resources.get_mut("destination").unwrap().path = "/etc/cron.d".into(),
                _ => value.input.push(b'\n'),
            }
            assert!(validate_plan(Some(&binding), &value).is_err(), "{case}");
        }
    }
    #[test]
    fn executor_metadata_changes_the_immutable_operation_definition() {
        let (binding, plan, _) = deployment();
        let mut op = policy::Operation {
            protocol: PROTOCOL.into(),
            adapter: Some(binding),
            max_uses: 2,
            plans: BTreeMap::from([("install".into(), plan)]),
        };
        let first = policy::digest(&policy::canonical(&op).unwrap());
        op.adapter.as_mut().unwrap().build_receipt_sha256 = format!("sha256:{}", "88".repeat(32));
        assert_ne!(first, policy::digest(&policy::canonical(&op).unwrap()));
    }
    #[test]
    fn producer_generation_name_fits_without_a_product_specific_branch() {
        let mut r = request();
        r.candidate.generation = format!("{GENERATIONS}example-{}", "11".repeat(32));
        parse_request(&policy::canonical(&r).unwrap()).unwrap();
        r.candidate.generation = format!("{GENERATIONS}{}", "x".repeat(129));
        assert!(parse_request(&policy::canonical(&r).unwrap()).is_err());
    }
    #[test]
    fn producer_install_request_golden_is_byte_identical() {
        let bytes = include_bytes!("../../tests/fixtures/receipt-install-v1/install-request.json");
        let request = parse_request(bytes).unwrap();
        assert_eq!(policy::canonical(&request).unwrap(), bytes);
        assert_eq!(
            policy::digest(bytes),
            "2e06c1950731a734e333f12d9de9d16d77ed5d761d15fbe60e4e2dd1295a8112"
        );
    }
}
