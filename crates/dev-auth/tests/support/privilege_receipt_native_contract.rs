//! Public protocol fixture inputs, never root authority by themselves.
use anyhow::{bail, Context, Result};
use dev_auth::privilege::{policy, receipt_install as effect};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub schema: String,
    pub case: Case,
    pub dev_auth: PathBuf,
    pub dev_auth_sha256: String,
    pub controller: PathBuf,
    pub controller_sha256: String,
    pub fixture_root: PathBuf,
    pub approval_plan: PathBuf,
    pub approval_sha256: String,
    /// Independently supplied canonical producer receipts, not read from the
    /// installed candidate to establish authority. Root driver verifies them.
    pub receipt_a: Vec<u8>,
    pub receipt_b: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Case {
    Transaction,
    Revoke,
    HardExpiry,
    AliasDenied,
}

pub fn read(path: &Path, owner: u32) -> Result<(Input, policy::ApprovalPlan)> {
    let bytes = dev_auth::privilege::custody::read_document(path, owner, 0o600)?;
    let input: Input = policy::parse(&bytes)?;
    if input.schema != "dev-auth-receipt-install-native-input-v1"
        || !input.dev_auth.is_absolute()
        || !input.controller.is_absolute()
    {
        bail!("invalid real-adapter fixture identity");
    }
    let leaf = input
        .fixture_root
        .strip_prefix("/var/tmp")?
        .components()
        .collect::<Vec<_>>();
    if leaf.len() != 1
        || !leaf[0]
            .as_os_str()
            .as_encoded_bytes()
            .starts_with(b"dev-auth-receipt-native-")
    {
        bail!("real-adapter fixture is not disposable");
    }
    policy::hex_digest(&input.dev_auth_sha256)?;
    policy::hex_digest(&input.controller_sha256)?;
    policy::hex_digest(&input.approval_sha256)?;
    let bytes = fs::read(&input.approval_plan)?;
    if policy::digest(&bytes) != input.approval_sha256 {
        bail!("real-adapter approval changed");
    }
    let approval: policy::ApprovalPlan = policy::parse(&bytes)?;
    if policy::canonical(&approval)? != bytes
        || approval.operations.len() != 1
        || !(10..=180).contains(&approval.request.hard_seconds)
        || approval.request.total_uses < 10
    {
        bail!("real-adapter approval bounds differ");
    }
    if input.case == Case::HardExpiry
        && (approval.request.idle_seconds != approval.request.hard_seconds
            || approval
                .operations
                .get("receipt")
                .and_then(|o| o.plans.get("install-a"))
                .is_none_or(|p| p.timeout_seconds != approval.request.hard_seconds))
    {
        bail!("real hard-expiry case must not expire by an earlier idle deadline");
    }
    let operation = approval
        .operations
        .get("receipt")
        .context("real receipt operation missing")?;
    if operation.protocol != effect::PROTOCOL
        || operation.max_uses < 10
        || operation.plans.len() != 6
    {
        bail!("real-adapter operation is not the finite workflow");
    }
    let a = plan(&approval, "install-a")?;
    let b = plan(&approval, "install-b")?;
    if a.action != effect::Action::Install
        || a.previous.is_some()
        || b.action != effect::Action::Install
        || b.previous.as_ref() != Some(&a.candidate)
        || a.destination != b.destination
        || a.journal != b.journal
        || a.tool != b.tool
        || a.binary != b.binary
    {
        bail!("real replacement approval differs");
    }
    // Each scope is a separately prepared system-owned acceptance target.
    if !a
        .destination
        .starts_with("/opt/dev-tools-maintenance/native-receipt-")
    {
        bail!("real fixture requires an explicit native receipt target");
    }
    for (id, action, candidate, previous) in [
        ("status-a", effect::Action::Status, &a.candidate, None),
        ("status-b", effect::Action::Status, &b.candidate, None),
        (
            "resume-b",
            effect::Action::Resume,
            &b.candidate,
            Some(&a.candidate),
        ),
        (
            "rollback-a",
            effect::Action::Install,
            &a.candidate,
            Some(&b.candidate),
        ),
    ] {
        let actual = plan(&approval, id)?;
        if actual.action != action
            || &actual.candidate != candidate
            || actual.previous.as_ref() != previous
            || actual.destination != a.destination
            || actual.journal != a.journal
            || actual.tool != a.tool
            || actual.binary != a.binary
        {
            bail!("real fixture plan differs from finite workflow");
        }
    }
    for p in operation.plans.values() {
        effect::validate_plan(operation.adapter.as_ref(), p)?;
    }
    for (bytes, artifact) in [
        (&input.receipt_a, &a.candidate),
        (&input.receipt_b, &b.candidate),
    ] {
        if bytes.is_empty()
            || bytes.len() > 16 * 1024
            || format!("sha256:{}", policy::digest(bytes)) != artifact.receipt_sha256
        {
            bail!("independent fixture receipt bytes do not match approval");
        }
        let value: serde_json::Value = serde_json::from_slice(bytes)?;
        if value["schema"] != "syscfg-native-artifact-v1"
            || value["binding"]["tool"] != a.tool
            || value["binding"]["binary"] != a.binary
            || value["binding"]["source_fingerprint"] != artifact.source_fingerprint
        {
            bail!("independent fixture build receipt differs from selected tool/source");
        }
    }
    Ok((input, approval))
}
pub fn plan(approval: &policy::ApprovalPlan, id: &str) -> Result<effect::Request> {
    let operation = approval
        .operations
        .get("receipt")
        .context("receipt operation absent")?;
    effect::validate_plan(
        operation.adapter.as_ref(),
        operation.plans.get(id).context("receipt plan absent")?,
    )
}
