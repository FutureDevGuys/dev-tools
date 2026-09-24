//! Native strong-mode mutable binding qualification in the disposable image.
use super::*;
use crate::deployment::DeploymentBinding;
use crate::smart_binding::{
    build_binding_plan, canonical_binding_plan, resolve_structured_target, BindingCodeTrust,
    BindingIntent,
};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Duration;

const WORKER: &str = "/usr/local/libexec/dev-auth-fixture-worker";

pub(super) fn prepare(account: &nix::unistd::User) -> DeploymentBinding {
    let target = Path::new(WORKER);
    let intent = BindingIntent::structured("bound-worker", "worker", target, Vec::<String>::new())
        .unwrap()
        .with_code_trust(BindingCodeTrust::Mutable);
    let plan = build_binding_plan(
        "fixture-binding",
        intent,
        resolve_structured_target(target).unwrap(),
        None,
    )
    .unwrap();
    let bytes = canonical_binding_plan(&plan).unwrap();
    let path = PathBuf::from("/fixture-input/binding-plan.json");
    publish(&path, &bytes, 0o600);
    DeploymentBinding {
        user: account.name.clone(),
        name: plan.name,
        plan: path,
        sha256: sha256_hex(&bytes),
    }
}

fn run_bound(account: &nix::unistd::User, alias: &Path, edited: bool) {
    let mut command = Command::new(alias);
    command
        .uid(account.uid.as_raw())
        .gid(account.gid.as_raw())
        .env_clear()
        .env("HOME", &account.dir)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(&account.dir);
    let output = dev_tools_command::run_prepared_bounded_command(
        &mut command,
        Duration::from_secs(40),
        64 * 1024,
    )
    .unwrap();
    assert!(
        output.status.success(),
        "bound workload failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("workload-credential-check=passed"));
    assert_eq!(stdout.contains("strong-binding-edit=passed"), edited);
    assert!(!stdout.contains("fixture-delivered-secret"));
    assert!(!stdout.contains("fixture-service-account"));
}

pub(super) fn exercise(account: &nix::unistd::User, executable: &Path) {
    let alias = account.dir.join(".local/bin/bound-worker");
    assert!(fs::symlink_metadata(&alias)
        .unwrap()
        .file_type()
        .is_symlink());
    let receipt = crate::binding_activation::native_receipt_path(
        InstallMode::Strong,
        &account.dir,
        account.uid.as_raw(),
    )
    .unwrap();
    assert!(receipt.is_file());
    run_bound(account, &alias, false);

    let mut updated = fs::read(WORKER).unwrap();
    updated.extend_from_slice(b"printf 'strong-binding-edit=passed\\n'\n");
    publish(Path::new(WORKER), &updated, 0o755);
    run_bound(account, &alias, true);

    let restoration = command(
        executable,
        &["setup", "restore", "--mode", "strong", "--format", "json"],
    );
    assert!(restoration.status.success());
    let report: serde_json::Value = serde_json::from_slice(&restoration.stdout).unwrap();
    assert_eq!(report["verified"], true);
    assert_eq!(report["changed"], true);
    assert_eq!(
        fs::symlink_metadata(&alias).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        fs::symlink_metadata(&receipt).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert!(Path::new(WORKER).is_file());
    publish(
        Path::new("/fixture/binding-strong-result.json"),
        b"{\"schema\":\"dev-auth-native-strong-binding-v1\",\"passed\":true,\"mutable_edit\":true,\"restored\":true}\n",
        0o644,
    );
}
