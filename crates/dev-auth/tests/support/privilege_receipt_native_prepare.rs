//! Non-root document preparation. Supplied build evidence is never inferred
//! from a user installation and this command publishes no native authority.
use super::privilege_receipt_native_support::contract::{self, Case, Input};
use anyhow::{bail, Context, Result};
use dev_auth::privilege::{custody, policy, receipt_install as effect};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Preparation {
    schema: String,
    case: Case,
    dev_auth: PathBuf,
    dev_auth_sha256: String,
    controller: PathBuf,
    controller_sha256: String,
    fixture_root: PathBuf,
    audience: String,
    executor_receipt: effect::ExecutorReceipt,
    executor_receipt_sha256: String,
    receipt_a: Vec<u8>,
    receipt_b: Vec<u8>,
}
fn load(path: &Path) -> Result<(Preparation, u32)> {
    let uid = nix::unistd::getuid().as_raw();
    if uid == 0 || nix::unistd::geteuid().as_raw() != uid {
        bail!("preparation requires the non-root observer");
    }
    let input: Preparation = policy::parse(&custody::read_document(path, uid, 0o600)?)?;
    if input.schema != "dev-auth-receipt-native-preparation-v1"
        || input.fixture_root.parent() != Some(Path::new("/var/tmp"))
        || !input
            .fixture_root
            .file_name()
            .context("fixture name absent")?
            .as_encoded_bytes()
            .starts_with(b"dev-auth-receipt-native-")
        || !input.audience.starts_with("native-receipt-")
    {
        bail!("explicit disposable receipt fixture required");
    }
    let metadata = fs::symlink_metadata(&input.fixture_root)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
        bail!("existing private observer fixture directory required");
    }
    for (path, expected) in [
        (&input.dev_auth, &input.dev_auth_sha256),
        (&input.controller, &input.controller_sha256),
    ] {
        policy::hex_digest(expected)?;
        if !path.is_absolute() || policy::digest(&fs::read(path)?) != *expected {
            bail!("native fixture image differs from supplied build evidence");
        }
    }
    Ok((input, uid))
}
fn artifact(bytes: &[u8]) -> Result<(effect::Artifact, String, String)> {
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
        bail!("producer receipt bounds invalid");
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    if value["schema"] != "syscfg-native-artifact-v1" {
        bail!("native fixture requires the actual producer receipt");
    }
    let tool = value["binding"]["tool"]
        .as_str()
        .context("tool absent")?
        .to_owned();
    let binary = value["binding"]["binary"]
        .as_str()
        .context("binary absent")?
        .to_owned();
    let source = value["binding"]["source_fingerprint"]
        .as_str()
        .context("source absent")?
        .to_owned();
    let digest = policy::digest(bytes);
    Ok((
        effect::Artifact {
            generation: format!("/var/lib/dev-tools-maintenance/generations/syscfg-{digest}"),
            receipt_sha256: format!("sha256:{digest}"),
            source_fingerprint: source,
        },
        tool,
        binary,
    ))
}
fn documents(input: &Preparation, uid: u32) -> Result<(policy::Policy, policy::Request)> {
    let proof = &input.executor_receipt;
    policy::hex_digest(&input.executor_receipt_sha256)?;
    if proof.schema != effect::EXECUTOR_SCHEMA
        || proof.protocol != effect::PROTOCOL
        || proof.executable_length == 0
        || proof.executable_length > 256 * 1024 * 1024
        || policy::digest(&policy::canonical(proof)?) != input.executor_receipt_sha256
    {
        bail!("independent executor evidence differs");
    }
    let binding = effect::ExecutorBinding {
        receipt_path: Path::new(&proof.executable)
            .parent()
            .context("executor parent absent")?
            .join("executor-v1.json")
            .to_str()
            .context("UTF-8 required")?
            .into(),
        receipt_sha256: input.executor_receipt_sha256.clone(),
        source_fingerprint: proof.source_fingerprint.clone(),
        build_receipt_sha256: proof.build_receipt_sha256.clone(),
    };
    let (a, tool, binary) = artifact(&input.receipt_a)?;
    let (b, other_tool, other_binary) = artifact(&input.receipt_b)?;
    if tool != other_tool || binary != other_binary || a.receipt_sha256 == b.receipt_sha256 {
        bail!("two independent generations of one tool required");
    }
    let lifetime = if input.case == Case::HardExpiry {
        30
    } else {
        180
    };
    let mut plans = BTreeMap::new();
    for (id, action, candidate, previous) in [
        ("install-a", effect::Action::Install, &a, None),
        ("install-b", effect::Action::Install, &b, Some(&a)),
        ("status-a", effect::Action::Status, &a, None),
        ("status-b", effect::Action::Status, &b, None),
        ("resume-b", effect::Action::Resume, &b, Some(&a)),
        ("rollback-a", effect::Action::Install, &a, Some(&b)),
    ] {
        let wire = effect::Request {
            action,
            binary: binary.clone(),
            candidate: candidate.clone(),
            destination: format!("/opt/dev-tools-maintenance/{}/bin", input.audience),
            journal: format!(
                "/var/lib/dev-tools-maintenance/journals/{}/{}",
                input.audience, binary
            ),
            previous: previous.cloned(),
            schema: effect::PROTOCOL.into(),
            tool: tool.clone(),
        };
        let plan = policy::ExactPlan {
            executable: proof.executable.clone(),
            executable_sha256: proof.executable_sha256.clone(),
            arguments: vec![b"maintenance-v1".to_vec()],
            environment: BTreeMap::new(),
            working_directory: "/".into(),
            resources: effect::resources(&wire),
            input: policy::canonical(&wire)?,
            timeout_seconds: lifetime,
            output_limit: 64 * 1024,
        };
        effect::validate_plan(Some(&binding), &plan)?;
        plans.insert(id.into(), plan);
    }
    let operations = BTreeMap::from([(
        "receipt".into(),
        policy::Operation {
            protocol: effect::PROTOCOL.into(),
            adapter: Some(binding),
            max_uses: 16,
            plans,
        },
    )]);
    let request = policy::Request {
        schema: policy::REQUEST_SCHEMA.into(),
        capability: "receipt-native".into(),
        owner_uid: uid,
        idle_seconds: lifetime,
        hard_seconds: lifetime,
        total_uses: 16,
        operations: BTreeMap::from([(
            "receipt".into(),
            policy::Selection {
                uses: 16,
                plans: operations["receipt"].plans.keys().cloned().collect(),
            },
        )]),
    };
    let policy = policy::Policy {
        schema: policy::POLICY_SCHEMA.into(),
        capabilities: BTreeMap::from([(
            "receipt-native".into(),
            policy::Capability {
                users: BTreeSet::from([uid]),
                max_idle_seconds: lifetime,
                max_hard_seconds: lifetime,
                max_uses: 16,
                operations,
            },
        )]),
    };
    policy::parse_policy(&policy::canonical(&policy)?)?;
    policy::parse_request(&policy::canonical(&request)?)?;
    Ok((policy, request))
}
pub fn prepare(path: &Path) -> Result<()> {
    let (input, uid) = load(path)?;
    let (policy, request) = documents(&input, uid)?;
    for (name, bytes) in [
        ("policy.json", policy::canonical(&policy)?),
        ("request.json", policy::canonical(&request)?),
        (
            "executor-v1.json",
            policy::canonical(&input.executor_receipt)?,
        ),
    ] {
        custody::write_new_document(&input.fixture_root.join(name), &bytes, uid)?;
    }
    Ok(())
}
pub fn finish(path: &Path) -> Result<()> {
    let (input, uid) = load(path)?;
    let (policy, request) = documents(&input, uid)?;
    let approval_path = input.fixture_root.join("approval.json");
    let bytes = custody::read_document(&approval_path, uid, 0o600)?;
    let approval: policy::ApprovalPlan = policy::parse(&bytes)?;
    let expected = policy::resolve(
        &policy::canonical(&policy)?,
        request,
        &approval.installation_sha256,
    )?;
    if policy::canonical(&expected)? != bytes {
        bail!("public approval is not the supplied exact fixture authority");
    }
    let final_input = Input {
        schema: "dev-auth-receipt-install-native-input-v1".into(),
        case: input.case,
        dev_auth: input.dev_auth,
        dev_auth_sha256: input.dev_auth_sha256,
        controller: input.controller,
        controller_sha256: input.controller_sha256,
        fixture_root: input.fixture_root.clone(),
        approval_plan: approval_path,
        approval_sha256: policy::digest(&bytes),
        receipt_a: input.receipt_a,
        receipt_b: input.receipt_b,
    };
    let path = input.fixture_root.join("real-input.json");
    custody::write_new_document(&path, &policy::canonical(&final_input)?, uid)?;
    contract::read(&path, uid)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prepared_real_workflow_has_closed_scopes_and_equal_hard_timer() {
        let receipt = |value: &str| {
            serde_json::to_vec(&serde_json::json!({"schema":"syscfg-native-artifact-v1","binding":{"tool":"sample","binary":"sample","source_fingerprint":format!("sha256:{}",value.repeat(64))}})).unwrap()
        };
        let proof = effect::ExecutorReceipt {
            schema: effect::EXECUTOR_SCHEMA.into(),
            protocol: effect::PROTOCOL.into(),
            executable: "/usr/local/lib/dev-tools-maintenance/executors/native/executor".into(),
            executable_sha256: "11".repeat(32),
            executable_length: 1234,
            source_fingerprint: format!("sha256:{}", "22".repeat(32)),
            build_receipt_sha256: format!("sha256:{}", "33".repeat(32)),
        };
        let input = Preparation {
            schema: "dev-auth-receipt-native-preparation-v1".into(),
            case: Case::HardExpiry,
            dev_auth: "/dev-auth".into(),
            dev_auth_sha256: "44".repeat(32),
            controller: "/controller".into(),
            controller_sha256: "55".repeat(32),
            fixture_root: "/var/tmp/dev-auth-receipt-native-source".into(),
            audience: "native-receipt-source".into(),
            executor_receipt_sha256: policy::digest(&policy::canonical(&proof).unwrap()),
            executor_receipt: proof,
            receipt_a: receipt("a"),
            receipt_b: receipt("b"),
        };
        let (policy, request) = documents(&input, 1000).unwrap();
        let approval = policy::resolve(
            &policy::canonical(&policy).unwrap(),
            request,
            &"66".repeat(32),
        )
        .unwrap();
        let op = &approval.operations["receipt"];
        assert_eq!(op.plans.len(), 6);
        assert_eq!(
            op.plans["install-a"].timeout_seconds,
            approval.request.hard_seconds
        );
        assert_eq!(approval.request.idle_seconds, approval.request.hard_seconds);
        assert!(op.plans["status-a"]
            .resources
            .values()
            .all(|r| r.access == policy::Access::ReadOnly));
    }
}
