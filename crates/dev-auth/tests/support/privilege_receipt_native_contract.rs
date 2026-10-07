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
    pub artifact_a: ArtifactEvidence,
    pub artifact_b: ArtifactEvidence,
    pub layout: ObservationLayout,
}

/// Operator-supplied, producer-neutral evidence. The opaque producer receipt
/// remains hash-bound to the approved request; its private schema is not ours.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEvidence {
    pub artifact: effect::Artifact,
    pub tool: String,
    pub binary: String,
    pub executable_sha256: String,
    pub executable_bytes: u64,
    pub receipt: Vec<u8>,
}
impl ArtifactEvidence {
    pub fn validate(&self) -> Result<()> {
        policy::hex_digest(&self.executable_sha256)?;
        if self.executable_bytes == 0
            || self.executable_bytes > 256 * 1024 * 1024
            || self.receipt.is_empty()
            || self.receipt.len() > 16 * 1024
            || self.artifact.receipt_sha256 != format!("sha256:{}", policy::digest(&self.receipt))
        {
            bail!("independent artifact evidence is invalid");
        }
        // The journal observation uses JSON value equality, without assigning
        // meaning to the producer's fields or manufacturing producer receipts.
        let receipt: serde_json::Value = serde_json::from_slice(&self.receipt)?;
        if !receipt.is_object() {
            bail!("independent producer receipt must be a JSON object");
        }
        Ok(())
    }
}

/// Read-only fixture observations, confined to already approved resource roots.
/// No producer-specific receipt filename or journal field is built in.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationLayout {
    pub generation_receipt: String,
    pub installed_receipt: String,
    pub journal_file: String,
    pub phase_pointer: String,
    pub receipt_pointer: String,
    pub pending_phase: String,
}
impl ObservationLayout {
    pub fn validate(&self, binary: &str) -> Result<()> {
        for name in [
            &self.generation_receipt,
            &self.installed_receipt,
            &self.journal_file,
        ] {
            if name.is_empty()
                || name.len() > 128
                || matches!(name.as_str(), "." | "..")
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
                || name == binary
            {
                bail!("fixture observation must name a distinct bounded filename");
            }
        }
        for pointer in [&self.phase_pointer, &self.receipt_pointer] {
            if !pointer.starts_with('/')
                || pointer.len() > 256
                || pointer.chars().any(char::is_control)
            {
                bail!("fixture journal pointer is invalid");
            }
            let mut chars = pointer.chars();
            while let Some(ch) = chars.next() {
                if ch == '~' && !matches!(chars.next(), Some('0' | '1')) {
                    bail!("fixture journal pointer escape is invalid");
                }
            }
        }
        if self.phase_pointer == self.receipt_pointer
            || self.pending_phase.is_empty()
            || self.pending_phase.len() > 64
            || self.pending_phase.chars().any(char::is_control)
        {
            bail!("fixture pending observation is invalid");
        }
        Ok(())
    }

    pub fn is_pending(&self, record: &serde_json::Value, receipt: &serde_json::Value) -> bool {
        record
            .pointer(&self.phase_pointer)
            .and_then(serde_json::Value::as_str)
            == Some(self.pending_phase.as_str())
            && record.pointer(&self.receipt_pointer) == Some(receipt)
    }
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
    if input.schema != "dev-auth-receipt-install-native-input-v2"
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
    input.layout.validate(&a.binary)?;
    for (evidence, artifact) in [
        (&input.artifact_a, &a.candidate),
        (&input.artifact_b, &b.candidate),
    ] {
        evidence.validate()?;
        if &evidence.artifact != artifact || evidence.tool != a.tool || evidence.binary != a.binary
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

#[cfg(test)]
mod tests {
    use super::*;
    fn layout() -> ObservationLayout {
        ObservationLayout {
            generation_receipt: "manifest.json".into(),
            installed_receipt: ".sample.receipt.json".into(),
            journal_file: "transaction.json".into(),
            phase_pointer: "/transaction/state".into(),
            receipt_pointer: "/transaction/receipt".into(),
            pending_phase: "prepared".into(),
        }
    }
    #[test]
    fn observation_layout_is_bounded_and_does_not_require_a_producer_schema() {
        let valid = layout();
        valid.validate("sample").unwrap();
        let receipt = serde_json::json!({"public-example": 1});
        let journal = serde_json::json!({"transaction": {"state": "prepared", "receipt": receipt}});
        assert!(valid.is_pending(&journal, &receipt));
        assert!(!valid.is_pending(&journal, &serde_json::json!({"public-example": 2})));
        assert!(!valid.is_pending(&serde_json::json!({}), &receipt));
        assert!(!valid.is_pending(
            &serde_json::json!({"transaction":{"state":"complete","receipt":receipt}}),
            &receipt
        ));
        for name in [
            "",
            ".",
            "..",
            "../receipt",
            "/receipt",
            "sub/receipt",
            "sample",
            "bad\nname",
        ] {
            let mut bad = valid.clone();
            bad.installed_receipt = name.into();
            assert!(bad.validate("sample").is_err(), "{name:?}");
        }
        for pointer in ["", "state", "/bad~2", "/bad~", "/bad\n"] {
            let mut bad = valid.clone();
            bad.phase_pointer = pointer.into();
            assert!(bad.validate("sample").is_err(), "{pointer:?}");
        }
    }
    #[test]
    fn artifact_evidence_preserves_receipt_hash_and_executable_bounds() {
        let receipt = br#"{"format":"independent-public-fixture","version":2}"#.to_vec();
        let valid = ArtifactEvidence {
            artifact: effect::Artifact {
                generation: "/var/lib/dev-tools-maintenance/generations/example-a".into(),
                receipt_sha256: format!("sha256:{}", policy::digest(&receipt)),
                source_fingerprint: format!("sha256:{}", "a".repeat(64)),
            },
            tool: "sample".into(),
            binary: "sample".into(),
            executable_sha256: "b".repeat(64),
            executable_bytes: 42,
            receipt,
        };
        valid.validate().unwrap();
        let mut bad = valid.clone();
        bad.receipt.push(b' ');
        assert!(bad.validate().is_err());
        let mut bad = valid.clone();
        bad.executable_bytes = 0;
        assert!(bad.validate().is_err());
        let mut bad = valid.clone();
        bad.executable_sha256 = "not-a-digest".into();
        assert!(bad.validate().is_err());
        let mut bad = valid;
        bad.receipt = b"invalid json".to_vec();
        bad.artifact.receipt_sha256 = format!("sha256:{}", policy::digest(&bad.receipt));
        assert!(bad.validate().is_err());
    }
}
