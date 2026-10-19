#![cfg(unix)]

use dev_auth::smart_binding::{self, source, BindingCodeTrust, BindingIntent, BindingPlanChange};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn target(path: &Path, bytes: &[u8]) {
    private(path, bytes);
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn plan(path: &Path) -> smart_binding::BindingPlan {
    smart_binding::build_binding_plan(
        "agent-binding",
        BindingIntent::structured("bound-agent", "automation", path, ["fixed"])
            .unwrap()
            .with_code_trust(BindingCodeTrust::Mutable),
        smart_binding::resolve_structured_target(path).unwrap(),
        None,
    )
    .unwrap()
}
fn deployment(root: &Path) -> Vec<u8> {
    format!("# retained operator comment\nschema = 'dev-auth-deployment-v3'\nmode = 'user-only'\nchannel = 'stable'\nactivation = 'inactive'\nadministrator_policy = '{}'\nbindings = []\n[[users]]\nname = 'worker'\nconfig = '{}'\n[[credentials]]\nslot = 'database'\nintent = 'preserve'\n", root.join("policy.toml").display(), root.join("user.toml").display()).into_bytes()
}

#[test]
fn selected_raw_plan_digest_and_canonical_bytes_gate_typed_parsing() {
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("agent");
    target(&executable, b"approved public executable");
    let plan = plan(&executable);
    let canonical = smart_binding::canonical_binding_plan(&plan).unwrap();
    let path = root.path().join("plan.json");
    private(&path, &canonical);
    assert_eq!(source::read_plan(&path, &digest(&canonical)).unwrap(), plan);
    assert!(source::read_plan(&path, &"0".repeat(64)).is_err());
    let pretty = serde_json::to_vec_pretty(&plan).unwrap();
    private(&path, &pretty);
    assert!(
        source::read_plan(&path, &digest(&pretty)).is_err(),
        "matching noncanonical raw bytes cannot transfer approval"
    );
    let mut altered = plan.clone();
    altered.actions.pop();
    let encoded = serde_jcs::to_vec(&altered).unwrap();
    private(&path, &encoded);
    assert!(source::read_plan(&path, &digest(&encoded)).is_err());
    let mut legacy = serde_json::to_value(&plan).unwrap();
    legacy["schema"] = "dev-auth-workload-binding-plan-v2".into();
    let encoded = serde_jcs::to_vec(&legacy).unwrap();
    private(&path, &encoded);
    assert!(source::read_plan(&path, &digest(&encoded)).is_err());
}

#[test]
fn user_owned_ancestry_requires_explicit_mutable_intent() {
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("agent");
    target(&executable, b"inspection only");
    let intent =
        BindingIntent::structured("bound-agent", "automation", &executable, ["fixed"]).unwrap();
    assert_eq!(intent.code_trust, BindingCodeTrust::Pinned);
    assert!(smart_binding::build_binding_plan(
        "agent-binding",
        intent,
        smart_binding::resolve_structured_target(&executable).unwrap(),
        None
    )
    .is_err());
    assert_eq!(
        plan(&executable).intent.code_trust,
        BindingCodeTrust::Mutable
    );
    assert_eq!(fs::read(&executable).unwrap(), b"inspection only");
}

#[test]
fn complete_proposals_preserve_source_and_exact_lineage_through_refresh_rollback_removal() {
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("agent");
    target(&executable, b"generation one");
    let initial = plan(&executable);
    let initial_path = root.path().join("initial.json");
    let initial_digest = smart_binding::write_binding_plan(&initial_path, &initial).unwrap();
    let original = deployment(root.path());
    let source_path = root.path().join("deployment.toml");
    private(&source_path, &original);
    let first = root.path().join("proposal-one.toml");
    let first_digest = source::propose(
        &source_path,
        &digest(&original),
        "worker",
        source::SourceChange::Plan {
            plan_path: &initial_path,
            plan_sha256: &initial_digest,
        },
        &first,
    )
    .unwrap();
    assert_eq!(fs::read(&source_path).unwrap(), original);
    let selected = source::read_binding(&first, &first_digest, "worker", "agent-binding").unwrap();
    assert_eq!(selected.receipt.active.generation, 1);
    let unchanged =
        smart_binding::refresh_binding_plan("agent-binding", &selected.receipt, &[]).unwrap();
    assert_eq!(unchanged.change, BindingPlanChange::Unchanged);
    let unchanged_path = root.path().join("unchanged.json");
    let unchanged_digest = smart_binding::write_binding_plan(&unchanged_path, &unchanged).unwrap();
    let same = root.path().join("unchanged.toml");
    source::propose(
        &first,
        &first_digest,
        "worker",
        source::SourceChange::Plan {
            plan_path: &unchanged_path,
            plan_sha256: &unchanged_digest,
        },
        &same,
    )
    .unwrap();
    assert_eq!(fs::read(&same).unwrap(), fs::read(&first).unwrap());
    assert!(source::propose(
        &first,
        &first_digest,
        "worker",
        source::SourceChange::Plan {
            plan_path: &initial_path,
            plan_sha256: &initial_digest
        },
        &root.path().join("stale.toml")
    )
    .is_err());
    target(&executable, b"generation two");
    let refreshed =
        smart_binding::refresh_binding_plan("agent-binding", &selected.receipt, &[]).unwrap();
    assert_eq!(refreshed.change, BindingPlanChange::Refresh);
    let refresh_path = root.path().join("refresh.json");
    let refresh_digest = smart_binding::write_binding_plan(&refresh_path, &refreshed).unwrap();
    let second = root.path().join("proposal-two.toml");
    let second_digest = source::propose(
        &first,
        &first_digest,
        "worker",
        source::SourceChange::Plan {
            plan_path: &refresh_path,
            plan_sha256: &refresh_digest,
        },
        &second,
    )
    .unwrap();
    let selected =
        source::read_binding(&second, &second_digest, "worker", "agent-binding").unwrap();
    assert_eq!(selected.receipt.active.generation, 2);
    assert!(
        smart_binding::rollback_binding_plan("agent-binding", &selected.receipt).is_err(),
        "old target bytes must verify again"
    );
    target(&executable, b"generation one");
    let rollback =
        smart_binding::rollback_binding_plan("agent-binding", &selected.receipt).unwrap();
    assert_eq!(
        source::receipt_from_plan(&rollback)
            .unwrap()
            .active
            .generation,
        3
    );
    let removed = root.path().join("removed.toml");
    source::propose(
        &second,
        &second_digest,
        "worker",
        source::SourceChange::Remove {
            name: "agent-binding",
        },
        &removed,
    )
    .unwrap();
    let proposed = dev_auth::binding_deployment::parse(&fs::read(&removed).unwrap()).unwrap();
    assert!(proposed.bindings.is_empty());
    assert_eq!(proposed.credentials[0].slot, "database");
    assert_eq!(fs::read(&executable).unwrap(), b"generation one");
    assert!(
        source::propose(
            &second,
            &second_digest,
            "worker",
            source::SourceChange::Remove {
                name: "agent-binding"
            },
            &removed
        )
        .is_err(),
        "proposal output is never overwritten"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn adjacent_native_device_and_inode_never_match_retained_executable() {
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("agent");
    target(&executable, b"same bytes");
    let identity = smart_binding::resolve_structured_target(&executable)
        .unwrap()
        .identity()
        .clone();
    for change_device in [true, false] {
        let mut adjacent = identity.clone();
        let selected = if change_device {
            &mut adjacent.device
        } else {
            &mut adjacent.inode
        };
        *selected = Some(selected.unwrap().wrapping_add(1));
        assert!(smart_binding::retain_binding_executable(&adjacent).is_err());
        assert!(smart_binding::snapshot_binding_executable(&adjacent).is_err());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn acknowledged_public_shell_source_is_digest_bound_sealed_nonexecutable_data() {
    use std::io::Read;
    let shell = Path::new("/usr/bin/true");
    let definition = "printf '%s\\n' \"$1\"\n".to_owned();
    assert!(smart_binding::pinned_shell_binding(
        "public-shell",
        "automation",
        shell,
        definition.clone(),
        false,
        &[]
    )
    .is_err());
    let (intent, resolved) = smart_binding::pinned_shell_binding(
        "public-shell",
        "automation",
        shell,
        definition.clone(),
        true,
        &[],
    )
    .unwrap();
    let receipt = smart_binding::BindingReceipt::new(intent, resolved).unwrap();
    let mut source = smart_binding::sealed_shell_source(&receipt)
        .unwrap()
        .unwrap();
    assert_eq!(
        source.metadata().unwrap().permissions().mode() & 0o777,
        0o600
    );
    let mut read = String::new();
    source.read_to_string(&mut read).unwrap();
    assert_eq!(read, definition);
    let seals = rustix::fs::fcntl_get_seals(&source).unwrap();
    assert!(seals.contains(
        rustix::fs::SealFlags::WRITE
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::SEAL
    ));
    assert!(source.set_len(0).is_err());
    let mut command = std::process::Command::new(shell);
    smart_binding::shell::attach_source(&mut command, &receipt, &["literal caller".into()])
        .unwrap();
    let arguments = command.get_args().collect::<Vec<_>>();
    assert!(arguments[0].to_string_lossy().starts_with("/proc/self/fd/"));
    assert_eq!(arguments[1], "literal caller");
    assert!(!arguments
        .iter()
        .any(|argument| argument.to_string_lossy().contains("printf")));
}
