//! Explicit administrative authority; ordinary credential policy is never consulted.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

pub const POLICY_SCHEMA: &str = "dev-auth-privilege-policy-v1";
pub const REQUEST_SCHEMA: &str = "dev-auth-privilege-request-v1";
pub const PLAN_SCHEMA: &str = "dev-auth-privilege-plan-v1";
pub const DOCUMENT_LIMIT: usize = 1024 * 1024;
pub const MAX_OPERATIONS: usize = 64;
pub const MAX_USES: u64 = 10_000;
pub const MAX_ARGUMENT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema: String,
    pub capabilities: BTreeMap<String, Capability>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub users: BTreeSet<u32>,
    pub max_idle_seconds: u64,
    pub max_hard_seconds: u64,
    pub max_uses: u64,
    pub operations: BTreeMap<String, Operation>,
}

/// An operation selects a reviewed native helper protocol and frozen plan variants.
/// This is not a program/argument pattern language. No caller-supplied argv is run.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter: Option<super::receipt_install::ExecutorBinding>,
    pub max_uses: u64,
    pub plans: BTreeMap<String, ExactPlan>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExactPlan {
    pub executable: String,
    pub executable_sha256: String,
    pub arguments: Vec<Vec<u8>>,
    pub environment: BTreeMap<String, String>,
    pub working_directory: String,
    pub resources: BTreeMap<String, Resource>,
    pub input: Vec<u8>,
    pub timeout_seconds: u64,
    pub output_limit: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub path: String,
    pub access: Access,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub capability: String,
    pub owner_uid: u32,
    pub idle_seconds: u64,
    pub hard_seconds: u64,
    pub total_uses: u64,
    pub operations: BTreeMap<String, Selection>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub uses: u64,
    pub plans: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPlan {
    pub schema: String,
    pub policy_sha256: String,
    pub installation_sha256: String,
    pub request: Request,
    pub operations: BTreeMap<String, Operation>,
}

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let bytes = serde_jcs::to_vec(value)?;
    if bytes.len() > DOCUMENT_LIMIT {
        bail!("administrative authority exceeds document bounds");
    }
    Ok(bytes)
}

pub fn parse_policy(bytes: &[u8]) -> Result<Policy> {
    let policy: Policy = parse(bytes)?;
    if policy.schema != POLICY_SCHEMA || policy.capabilities.len() > MAX_OPERATIONS {
        bail!("invalid administrative policy schema or bound");
    }
    for (name, capability) in &policy.capabilities {
        identifier(name)?;
        if capability.users.is_empty()
            || capability.users.len() > 128
            || capability.users.contains(&0)
        {
            bail!("administrative policy requires bounded non-root owners");
        }
        limits(
            capability.max_idle_seconds,
            capability.max_hard_seconds,
            capability.max_uses,
        )?;
        validate_operations(&capability.operations)?;
    }
    Ok(policy)
}

pub fn parse_request(bytes: &[u8]) -> Result<Request> {
    let request: Request = parse(bytes)?;
    if request.schema != REQUEST_SCHEMA || request.owner_uid == 0 {
        bail!("invalid administrative request identity");
    }
    identifier(&request.capability)?;
    limits(
        request.idle_seconds,
        request.hard_seconds,
        request.total_uses,
    )?;
    if request.operations.is_empty() || request.operations.len() > MAX_OPERATIONS {
        bail!("administrative request operation bound is invalid");
    }
    for (name, selection) in &request.operations {
        identifier(name)?;
        if selection.uses == 0
            || selection.uses > MAX_USES
            || selection.plans.is_empty()
            || selection.plans.len() > MAX_OPERATIONS
        {
            bail!("administrative request use or plan bound is invalid");
        }
        for plan in &selection.plans {
            identifier(plan)?;
        }
    }
    Ok(request)
}

pub fn resolve(
    policy_bytes: &[u8],
    request: Request,
    installation_sha256: &str,
) -> Result<ApprovalPlan> {
    let policy = parse_policy(policy_bytes)?;
    let request = parse_request(&canonical(&request)?)?;
    hex_digest(installation_sha256)?;
    let cap = policy
        .capabilities
        .get(&request.capability)
        .context("administrative capability is unavailable")?;
    if !cap.users.contains(&request.owner_uid)
        || request.idle_seconds > cap.max_idle_seconds
        || request.hard_seconds > cap.max_hard_seconds
        || request.total_uses > cap.max_uses
    {
        bail!("administrative request exceeds policy");
    }
    let mut operations = BTreeMap::new();
    for (name, selected) in &request.operations {
        let mut operation = cap
            .operations
            .get(name)
            .context("administrative operation is outside policy")?
            .clone();
        if selected.uses > operation.max_uses
            || selected
                .plans
                .iter()
                .any(|plan| !operation.plans.contains_key(plan))
        {
            bail!("administrative selection exceeds policy");
        }
        operation.max_uses = selected.uses;
        operation
            .plans
            .retain(|name, _| selected.plans.contains(name));
        if operation.plans.values().any(|plan| {
            plan.timeout_seconds > request.idle_seconds
                || plan.timeout_seconds > request.hard_seconds
        }) {
            bail!("operation timeout exceeds the approved lifetime");
        }
        operations.insert(name.clone(), operation);
    }
    Ok(ApprovalPlan {
        schema: PLAN_SCHEMA.into(),
        policy_sha256: digest(policy_bytes),
        installation_sha256: installation_sha256.into(),
        request,
        operations,
    })
}

pub fn verify_plan(
    bytes: &[u8],
    approved_digest: &str,
    policy: &[u8],
    installation: &str,
) -> Result<ApprovalPlan> {
    hex_digest(approved_digest)?;
    let plan: ApprovalPlan = parse(bytes)?;
    if plan.schema != PLAN_SCHEMA || digest(bytes) != approved_digest || canonical(&plan)? != bytes
    {
        bail!("administrative approval digest or canonical identity is invalid");
    }
    let current = resolve(policy, plan.request.clone(), installation)?;
    if current != plan {
        bail!("administrative approval no longer matches current authority");
    }
    Ok(plan)
}

pub fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.is_empty() || bytes.len() > DOCUMENT_LIMIT {
        bail!("administrative document exceeds bounds");
    }
    serde_json::from_slice(bytes).context("invalid administrative authority document")
}

pub fn identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
    {
        bail!("invalid administrative identifier");
    }
    Ok(())
}

pub fn hex_digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("invalid administrative identity digest");
    }
    Ok(())
}

fn limits(idle: u64, hard: u64, uses: u64) -> Result<()> {
    dev_tools_privilege_session::LeaseLimits::from_administrator_policy(
        std::time::Duration::from_secs(idle),
        std::time::Duration::from_secs(hard),
    )
    .map_err(|_| anyhow::anyhow!("administrative duration is outside supported limits"))?;
    if uses == 0 || uses > MAX_USES {
        bail!("administrative use budget is invalid");
    }
    Ok(())
}

pub fn absolute(path: &str) -> Result<()> {
    let path = Path::new(path);
    if !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || path.as_os_str().len() > 4096
    {
        bail!("administrative path is not a bounded absolute authority");
    }
    Ok(())
}

fn validate_operations(operations: &BTreeMap<String, Operation>) -> Result<()> {
    if operations.is_empty() || operations.len() > MAX_OPERATIONS {
        bail!("administrative operation set is invalid");
    }
    for (name, operation) in operations {
        identifier(name)?;
        if operation.max_uses == 0
            || operation.max_uses > MAX_USES
            || operation.plans.is_empty()
            || operation.plans.len() > MAX_OPERATIONS
        {
            bail!("administrative helper protocol or bound is unsupported");
        }
        for (name, plan) in &operation.plans {
            identifier(name)?;
            validate_effect(&operation.protocol, operation.adapter.as_ref(), plan)?;
            absolute(&plan.executable)?;
            if plan.working_directory != "/" {
                absolute(&plan.working_directory)?;
            }
            hex_digest(&plan.executable_sha256)?;
            if plan.arguments.len() > 256
                || plan.arguments.iter().any(|a| a.contains(&0))
                || plan.arguments.iter().map(Vec::len).sum::<usize>() > MAX_ARGUMENT_BYTES
                || plan.input.len() > MAX_ARGUMENT_BYTES
                || plan.timeout_seconds == 0
                || plan.timeout_seconds > 8 * 60 * 60
                || plan.output_limit == 0
                || plan.output_limit > 64 * 1024
            {
                bail!("administrative execution limits are invalid");
            }
            if plan.environment.len() > 64
                || plan.environment.iter().any(|(k, v)| {
                    k.is_empty()
                        || k.len() > 128
                        || !k
                            .bytes()
                            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                        || k.starts_with("LD_")
                        || k.starts_with("DYLD_")
                        || matches!(
                            k.as_str(),
                            "PATH"
                                | "HOME"
                                | "SHELL"
                                | "ENV"
                                | "BASH_ENV"
                                | "PYTHONPATH"
                                | "PERL5OPT"
                                | "RUBYOPT"
                                | "NODE_OPTIONS"
                        )
                        || v.contains('\0')
                        || v.len() > 4096
                })
            {
                bail!("administrative environment is unsafe");
            }
            if plan.resources.is_empty() || plan.resources.len() > MAX_OPERATIONS {
                bail!("administrative resource set is invalid");
            }
            let paths: Vec<_> = plan
                .resources
                .values()
                .map(|r| Path::new(&r.path))
                .collect();
            for (index, path) in paths.iter().enumerate() {
                if paths
                    .iter()
                    .skip(index + 1)
                    .any(|other| path.starts_with(other) || other.starts_with(path))
                {
                    bail!("administrative resources overlap");
                }
            }
            for (name, resource) in &plan.resources {
                identifier(name)?;
                absolute(&resource.path)?;
                if resource.access == Access::ReadWrite
                    && Path::new(&plan.executable).starts_with(&resource.path)
                {
                    bail!("administrative resource can modify its approved helper");
                }
                if [
                    "/sys",
                    "/proc",
                    "/dev",
                    "/run",
                    "/etc/dev-auth",
                    "/usr/local/lib/dev-auth",
                    "/etc/systemd",
                    "/usr/lib/systemd",
                    "/etc/polkit-1",
                    "/usr/share/polkit-1",
                    "/etc/sudoers",
                    "/etc/sudoers.d",
                    "/usr/local/bin/dev-auth",
                ]
                .iter()
                .any(|p| {
                    Path::new(&resource.path).starts_with(p)
                        || Path::new(p).starts_with(&resource.path)
                }) {
                    bail!("administrative resource overlaps enforcement authority");
                }
            }
        }
    }
    Ok(())
}

/// A protocol label is never a reviewed effect definition. Production adapters
/// must have a concrete privileged product contract. The receipt-install ABI
/// derives every native argument and resource; generic execution remains denied.
fn validate_effect(
    protocol: &str,
    adapter: Option<&super::receipt_install::ExecutorBinding>,
    plan: &ExactPlan,
) -> Result<()> {
    if protocol == super::receipt_install::PROTOCOL {
        super::receipt_install::validate_plan(adapter, plan)?;
        return Ok(());
    }
    if adapter.is_some() {
        bail!("administrative adapter evidence belongs to another protocol");
    }
    #[cfg(any(test, feature = "native-privilege-fixture"))]
    if protocol == "dev-auth-native-fixture-v1" {
        if Path::new(&plan.executable).file_name()
            != Some(std::ffi::OsStr::new("dev-auth-privilege-native-fixture"))
            || plan.arguments.len() != 3
            || plan.arguments[0] != b"helper"
            || !matches!(
                plan.arguments[1].as_slice(),
                b"write"
                    | b"core-probe"
                    | b"probe"
                    | b"detached"
                    | b"leader-exit"
                    | b"nested-probe"
                    | b"hold"
                    | b"streams"
                    | b"blocked-output"
                    | b"signal-term"
                    | b"signal-segv"
            )
            || !plan.environment.is_empty()
            || plan.resources.len() != 1
            || (plan.arguments[1] == b"streams" && plan.input != [0, 255, 10, 13, 128])
            || (plan.arguments[1] != b"streams" && !plan.input.is_empty())
        {
            bail!("native qualification helper definition is unsupported");
        }
        let resource = plan
            .resources
            .values()
            .next()
            .context("native fixture resource missing")?;
        let path = Path::new(&resource.path);
        let fixture = path
            .strip_prefix("/var/tmp")
            .ok()
            .and_then(|p| p.components().next());
        if !fixture.is_some_and(|part| {
            part.as_os_str()
                .as_encoded_bytes()
                .starts_with(b"dev-auth-privilege-native-")
        }) || !Path::new(std::str::from_utf8(&plan.arguments[2])?)
            .strip_prefix(path)
            .is_ok_and(|leaf| {
                let mut parts = leaf.components();
                matches!(parts.next(), Some(Component::Normal(_))) && parts.next().is_none()
            })
            || (plan.working_directory != "/" && Path::new(&plan.working_directory) != path)
        {
            bail!("native qualification resource is outside its disposable fixture");
        }
        return Ok(());
    }
    let _ = (protocol, plan);
    bail!("administrative effect adapter is unsupported")
}
