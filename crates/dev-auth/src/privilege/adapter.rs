//! Bind product authority to the shared reusable lifecycle. No native permission
//! is inferred here: the coordinator must validate retained kernel/custody facts.
use super::policy::{self, ApprovalPlan, ExactPlan};
use anyhow::{Context, Result};
use dev_tools_privilege_session as lease;
use sha2::{Digest, Sha256};
use std::num::NonZeroU64;
use std::time::Duration;

pub type Authority = lease::SessionAuthority<()>;

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn decode_id(value: &str) -> Result<[u8; 32]> {
    policy::hex_digest(value)?;
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)?;
    }
    Ok(bytes)
}

pub fn now() -> Duration {
    crate::linux_platform::boot_time_millis()
        .map(Duration::from_millis)
        .unwrap_or(Duration::MAX)
}

pub fn create(plan: &ApprovalPlan, session: &str, approved_at_ms: u64) -> Result<Authority> {
    let binding = lease::AuthorityBinding::new(
        lease::SessionId::from_bytes(decode_id(session)?),
        lease::AudienceId::from_bytes(hash(plan.request.capability.as_bytes())),
        lease::PolicyIdentity::from_bytes(decode_id(&plan.policy_sha256)?),
        lease::InstallationIdentity::from_bytes(decode_id(&plan.installation_sha256)?),
    );
    let grants = plan
        .operations
        .iter()
        .map(|(name, operation)| {
            Ok(lease::OperationGrant::new(
                operation_binding(plan, name)?,
                NonZeroU64::new(operation.max_uses).context("administrative budget is zero")?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Authority::new(
        binding,
        lease::RetainedCaller::new(()),
        lease::LeaseLimits::from_administrator_policy(
            Duration::from_secs(plan.request.idle_seconds),
            Duration::from_secs(plan.request.hard_seconds),
        )?,
        Duration::from_millis(approved_at_ms),
        NonZeroU64::new(plan.request.total_uses).context("administrative total budget is zero")?,
        grants,
    )?)
}

pub fn request(
    authority: &Authority,
    approval: &ApprovalPlan,
    request_id: &str,
    operation: &str,
    plan_id: &str,
) -> Result<lease::OperationRequest> {
    let exact = exact_plan(approval, operation, plan_id)?;
    let mut binding = operation_binding(approval, operation)?;
    binding = lease::OperationBinding::new(
        binding.target(),
        binding.helper(),
        resource_scope(
            exact
                .resources
                .values()
                .map(policy::canonical)
                .collect::<Result<Vec<_>>>()?,
        )?,
    );
    Ok(lease::OperationRequest::new(
        lease::RequestId::from_bytes(decode_id(request_id)?),
        authority.binding(),
        binding,
        lease::OperationPayload::Typed(lease::PayloadDigest::from_bytes(hash(&policy::canonical(
            exact,
        )?))),
    ))
}

pub fn exact_plan<'a>(
    approval: &'a ApprovalPlan,
    operation: &str,
    plan: &str,
) -> Result<&'a ExactPlan> {
    approval
        .operations
        .get(operation)
        .and_then(|o| o.plans.get(plan))
        .context("operation plan is outside the granted audience")
}

fn operation_binding(plan: &ApprovalPlan, name: &str) -> Result<lease::OperationBinding> {
    let operation = plan
        .operations
        .get(name)
        .context("operation is outside the grant")?;
    let mut resources = std::collections::BTreeSet::new();
    for plan in operation.plans.values() {
        for resource in plan.resources.values() {
            resources.insert(policy::canonical(resource)?);
        }
    }
    let helpers = operation
        .plans
        .values()
        .map(|p| (&p.executable, &p.executable_sha256))
        .collect::<Vec<_>>();
    Ok(lease::OperationBinding::new(
        lease::OperationTarget::Typed {
            operation: lease::OperationId::from_bytes(hash(name.as_bytes())),
            definition: lease::DefinitionDigest::from_bytes(hash(&policy::canonical(operation)?)),
        },
        lease::HelperIdentity::from_bytes(hash(&policy::canonical(&helpers)?)),
        resource_scope(resources)?,
    ))
}

fn resource_scope(values: impl IntoIterator<Item = Vec<u8>>) -> Result<lease::ResourceScope> {
    Ok(lease::ResourceScope::new(
        values
            .into_iter()
            .map(|bytes| lease::ResourceId::from_bytes(hash(&bytes))),
    )?)
}
