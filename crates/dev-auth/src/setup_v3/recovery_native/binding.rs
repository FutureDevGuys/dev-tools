//! Source fixture for retained V5 binding capture, recovery and inactive restoration.
//! Only the enclosing ignored disposable-container test may invoke this module.
use super::*;
use crate::deployment::DeploymentBinding;
use crate::smart_binding::{
    build_binding_plan, canonical_binding_plan, resolve_structured_target, BindingCodeTrust,
    BindingIntent,
};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

const WORKER: &str = "/usr/local/libexec/dev-auth-fixture-worker";
const PINNED_WORKER: &str = "/usr/local/libexec/dev-auth-pinned-fixture-worker";
const PINNED_RESOURCE: &str = "/usr/local/libexec/dev-auth-pinned-resource";

fn user_worker(account: &nix::unistd::User) -> PathBuf {
    account.dir.join("mutable-worker")
}

pub(super) fn prepare_targets_and_policy(
    account: &nix::unistd::User,
    policy: Vec<u8>,
    config: Vec<u8>,
) -> (Vec<u8>, Vec<u8>) {
    let target = user_worker(account);
    fs::write(&target, fs::read(WORKER).unwrap()).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    nix::unistd::chown(&target, Some(account.uid), Some(account.gid)).unwrap();
    assert_eq!(fs::metadata(&target).unwrap().uid(), account.uid.as_raw());
    publish(
        Path::new(PINNED_WORKER),
        b"#!/bin/sh\nset -eu\nIFS= read -r resource < \"$(/usr/bin/dirname \"$0\")/dev-auth-pinned-resource\"\nprintf 'pinned-path=%s\\npinned-resource=%s\\n' \"$0\" \"$resource\"\nif [ \"${1-}\" = nested ]; then\n  command -v bound-pinned-worker | /usr/bin/grep -q '/tool-bin/bound-pinned-worker$'\n  bound-pinned-worker child\n  printf 'pinned-nested=passed\\n'\nfi\n",
        0o755,
    );
    publish(
        Path::new(PINNED_RESOURCE),
        b"adjacent-root-resource\n",
        0o644,
    );
    let policy = String::from_utf8(policy).unwrap();
    assert!(policy.contains(WORKER));
    let policy = policy
        .replace(WORKER, target.to_str().unwrap())
        .replace(
            "[credentials.providers.primary]",
            &format!("pinned-worker = \"{PINNED_WORKER}\"\n[credentials.providers.primary]"),
        )
        .replace(
            "launchers = [\"worker\"]",
            "launchers = [\"worker\", \"pinned-worker\"]",
        );
    let mut config = String::from_utf8(config).unwrap();
    // This scenario rebinds the shared `worker` launcher to user-owned code.
    // The generic workload fixture also names `short-worker` at that launcher;
    // strong policy requires a separate exact binding for every such workload.
    // The binding scenario does not exercise that second workload.
    let short_worker = "\n[[workloads]]\nname = \"short-worker\"\nprofile = \"worker\"\nlauncher = \"worker\"\nadmission = \"enrolled_noninteractive\"\nduration_seconds = 8\n[workloads.resources.token]\npurposes = [\"read\"]\nprojections = [\"stdin\"]\n";
    assert!(config.contains(short_worker));
    config = config.replace(short_worker, "");
    assert!(config.contains("duration_seconds = 60\n[workloads.resources.token]"));
    config = config.replace(
        "duration_seconds = 60\n[workloads.resources.token]",
        "duration_seconds = 60\ndesktop = { display_name = \"Fixture Worker\", terminal = false }\n[workloads.resources.token]",
    );
    config.push_str(
        "\n[[workloads]]\nname = \"pinned-worker\"\nprofile = \"worker\"\nlauncher = \"pinned-worker\"\nadmission = \"enrolled_noninteractive\"\nduration_seconds = 60\n[workloads.resources.token]\npurposes = [\"read\"]\nprojections = [\"stdin\"]\n",
    );
    (policy.into_bytes(), config.into_bytes())
}

pub(super) fn prepare(account: &nix::unistd::User) -> Vec<DeploymentBinding> {
    let target = user_worker(account);
    let intent = BindingIntent::structured("bound-worker", "worker", &target, Vec::<String>::new())
        .unwrap()
        .with_code_trust(BindingCodeTrust::Mutable)
        .with_desktop_entry(true);
    let plan = build_binding_plan(
        "fixture-binding",
        intent,
        resolve_structured_target(&target).unwrap(),
        None,
    )
    .unwrap();
    let bytes = canonical_binding_plan(&plan).unwrap();
    let path = PathBuf::from("/fixture-input/binding-plan.json");
    publish(&path, &bytes, 0o600);
    let mutable = DeploymentBinding {
        user: account.name.clone(),
        name: plan.name,
        plan: path,
        sha256: sha256_hex(&bytes),
    };
    let pinned_target = Path::new(PINNED_WORKER);
    let pinned_plan = build_binding_plan(
        "fixture-pinned-binding",
        BindingIntent::structured(
            "bound-pinned-worker",
            "pinned-worker",
            pinned_target,
            Vec::<String>::new(),
        )
        .unwrap(),
        resolve_structured_target(pinned_target).unwrap(),
        None,
    )
    .unwrap();
    let pinned_bytes = canonical_binding_plan(&pinned_plan).unwrap();
    let pinned_path = PathBuf::from("/fixture-input/pinned-binding-plan.json");
    publish(&pinned_path, &pinned_bytes, 0o600);
    vec![
        mutable,
        DeploymentBinding {
            user: account.name.clone(),
            name: pinned_plan.name,
            plan: pinned_path,
            sha256: sha256_hex(&pinned_bytes),
        },
    ]
}

pub(super) fn verify_and_restore(account: &nix::unistd::User, executable: &Path) {
    let paths = SetupPaths::strong();
    let installation = crate::setup::read_install_receipt_at(&paths)
        .unwrap()
        .unwrap();
    let path = crate::binding_activation::native_receipt_path(
        InstallMode::Strong,
        &account.dir,
        account.uid.as_raw(),
    )
    .unwrap();
    let (set, _) = crate::binding_activation::read_at(
        &path,
        InstallMode::Strong,
        account.uid.as_raw(),
        &installation,
    )
    .unwrap()
    .unwrap();
    assert_eq!(set.bindings.len(), 2);
    let alias = account.dir.join(".local/bin/bound-worker");
    let pinned_alias = account.dir.join(".local/bin/bound-pinned-worker");
    let desktop = account
        .dir
        .join(".local/share/applications/dev-auth-bound-worker.desktop");
    for link in [&alias, &pinned_alias] {
        assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
        crate::setup::verify_current_workload_alias_link(
            link.file_name().unwrap().to_str().unwrap(),
            &account.dir,
            account.uid.as_raw(),
            Path::new(&installation.executable),
        )
        .unwrap();
    }
    assert!(fs::read_to_string(&desktop)
        .unwrap()
        .contains("bound-worker"));
    let pin = crate::binding_activation::verify_pinned_artifact(
        account.uid.as_raw(),
        "bound-pinned-worker",
        &set.bindings["bound-pinned-worker"],
    )
    .unwrap();
    // Copied bytes, rather than a later root-owned source edit, retain authority.
    fs::write(PINNED_WORKER, b"#!/bin/sh\nexit 19\n").unwrap();
    fs::set_permissions(PINNED_WORKER, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        crate::binding_activation::verify_pinned_artifact(
            account.uid.as_raw(),
            "bound-pinned-worker",
            &set.bindings["bound-pinned-worker"]
        )
        .unwrap(),
        pin
    );
    let accepted = recover(executable);
    assert!(accepted.verified, "{accepted:?}");
    assert_eq!(accepted.changed, Some(false));
    let restored = command(
        executable,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    assert!(restored.status.success());
    let report: serde_json::Value = serde_json::from_slice(&restored.stdout).unwrap();
    assert_eq!(report["verified"], true);
    assert_eq!(report["changed"], true);
    for retired in [&alias, &pinned_alias, &desktop, &path, &pin] {
        assert_eq!(
            fs::symlink_metadata(retired).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }
    assert!(user_worker(account).is_file());
    assert!(
        !crate::setup::verify_at_read_only(&paths)
            .unwrap()
            .transparent_launchers_active
    );
    let restored_again = command(
        executable,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    assert!(restored_again.status.success());
    let report: serde_json::Value = serde_json::from_slice(&restored_again.stdout).unwrap();
    assert_eq!(report["changed"], false);
}
