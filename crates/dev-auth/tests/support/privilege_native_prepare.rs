//! Writes reviewable nonsecret fixture inputs only; never installs or approves.
use super::{
    linux::fixture,
    privilege_native_contract::{Case, Input},
};
use anyhow::{bail, Result};
use dev_auth::privilege::policy;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

fn owner(root: &Path) -> Result<u32> {
    fixture(root)?;
    let uid = unsafe { nix::libc::getuid() };
    let metadata = fs::symlink_metadata(root)?;
    if uid == 0
        || unsafe { nix::libc::geteuid() } != uid
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o700
    {
        bail!("prepare needs an existing private non-root fixture directory");
    }
    Ok(uid)
}
fn write(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(&policy::canonical(value)?)?;
    file.sync_all()?;
    Ok(())
}
pub fn run(case: &str, dev_auth: &Path, executable: &Path, root: &Path) -> Result<()> {
    let uid = owner(root)?;
    let case: Case = serde_json::from_value(serde_json::json!(case))?;
    if !dev_auth.is_absolute() || !executable.is_absolute() {
        bail!("absolute native binaries required");
    }
    let scope = root.join("scope");
    fs::create_dir(&scope)?;
    fs::set_permissions(&scope, fs::Permissions::from_mode(0o700))?;
    let hash = policy::digest(&fs::read(executable)?);
    let (policy, request) = documents(case, uid, executable, &scope, &hash)?;
    policy::parse_policy(&policy::canonical(&policy)?)?;
    policy::parse_request(&policy::canonical(&request)?)?;
    write(&root.join("policy.json"), &policy)?;
    write(&root.join("request.json"), &request)?;
    Ok(())
}
fn documents(
    case: Case,
    uid: u32,
    executable: &Path,
    scope: &Path,
    hash: &str,
) -> Result<(policy::Policy, policy::Request)> {
    let (idle, hard) = match case {
        Case::IdleExpiry | Case::NearIdleAdmission => (2, 12),
        Case::MalformedIpc => (20, 30),
        _ => (15, 15),
    };
    let uses = if case == Case::Exhaustion { 3 } else { 8 };
    let mut plans = BTreeMap::new();
    for (id, action, leaf) in [
        ("write-a", "write", "a"),
        ("write-b", "write", "b"),
        ("probe", "probe", "probe"),
        ("core-probe", "core-probe", "core"),
        ("detached", "detached", "heartbeat"),
        ("leader-exit", "leader-exit", "leader-heartbeat"),
        ("nested-probe", "nested-probe", "nested"),
        ("hold", "hold", "hold"),
        ("streams", "streams", "unused"),
        ("blocked-output", "blocked-output", "output"),
        ("signal-term", "signal-term", "unused"),
        ("signal-segv", "signal-segv", "unused"),
    ] {
        plans.insert(
            id.into(),
            policy::ExactPlan {
                executable: executable
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("fixture path must be UTF-8"))?
                    .into(),
                executable_sha256: hash.into(),
                arguments: vec![
                    b"helper".to_vec(),
                    action.as_bytes().to_vec(),
                    scope.join(leaf).as_os_str().as_encoded_bytes().to_vec(),
                ],
                environment: BTreeMap::new(),
                working_directory: scope.to_str().unwrap().into(),
                resources: BTreeMap::from([(
                    "scope".into(),
                    policy::Resource {
                        path: scope.to_str().unwrap().into(),
                        access: policy::Access::ReadWrite,
                    },
                )]),
                input: if id == "streams" {
                    vec![0, 255, 10, 13, 128]
                } else {
                    Vec::new()
                },
                timeout_seconds: idle,
                output_limit: 64 * 1024,
            },
        );
    }
    let request = policy::Request {
        schema: policy::REQUEST_SCHEMA.into(),
        capability: "native-fixture".into(),
        owner_uid: uid,
        idle_seconds: idle,
        hard_seconds: hard,
        total_uses: uses,
        operations: BTreeMap::from([(
            "fixture".into(),
            policy::Selection {
                uses,
                plans: plans.keys().cloned().collect(),
            },
        )]),
    };
    let policy = policy::Policy {
        schema: policy::POLICY_SCHEMA.into(),
        capabilities: BTreeMap::from([(
            "native-fixture".into(),
            policy::Capability {
                users: BTreeSet::from([uid]),
                max_idle_seconds: idle,
                max_hard_seconds: hard,
                max_uses: uses,
                operations: BTreeMap::from([(
                    "fixture".into(),
                    policy::Operation {
                        protocol: "dev-auth-native-fixture-v1".into(),
                        adapter: None,
                        max_uses: uses,
                        plans,
                    },
                )]),
            },
        )]),
    };
    Ok((policy, request))
}

pub fn input(
    case: &str,
    dev_auth: &Path,
    executable: &Path,
    root: &Path,
    approval: &Path,
) -> Result<()> {
    owner(root)?;
    let case: Case = serde_json::from_value(serde_json::json!(case))?;
    let bytes = fs::read(approval)?;
    let plan: policy::ApprovalPlan = policy::parse(&bytes)?;
    if policy::canonical(&plan)? != bytes {
        bail!("approval must be the canonical public plan output");
    }
    write(
        &root.join("input.json"),
        &Input {
            schema: "dev-auth-privilege-native-input-v1".into(),
            dev_auth: dev_auth.into(),
            fixture_binary: executable.into(),
            fixture_root: root.into(),
            approval_plan: approval.into(),
            approval_sha256: policy::digest(&bytes),
            case,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prepared_subjects_match_the_feature_only_closed_protocol() {
        for case in [
            Case::Reuse,
            Case::IdleExpiry,
            Case::NearIdleAdmission,
            Case::MalformedIpc,
            Case::Exhaustion,
            Case::SignalFidelity,
            Case::CoreCollector,
            Case::CoreCoordinatorDeath,
            Case::CoreBootstrapDeath,
        ] {
            let (policy, request) = documents(
                case,
                1000,
                Path::new("/usr/local/lib/dev-auth-privilege-native-fixture"),
                Path::new("/var/tmp/dev-auth-privilege-native-source/scope"),
                &"a".repeat(64),
            )
            .unwrap();
            let bytes = policy::canonical(&policy).unwrap();
            policy::parse_policy(&bytes).unwrap();
            let plan = policy::resolve(&bytes, request, &"b".repeat(64)).unwrap();
            assert_eq!(plan.operations["fixture"].plans.len(), 12);
            assert_eq!(
                plan.operations["fixture"].protocol,
                "dev-auth-native-fixture-v1"
            );
        }
    }
}
