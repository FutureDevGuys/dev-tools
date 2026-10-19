#![cfg(test)]

//! Preparation only: genuine native approval is supplied later on the visible
//! container login terminal. No authentication rule or password is synthesized.
use super::*;

pub(super) fn prepare(account: &nix::unistd::User) -> (Vec<u8>, Vec<u8>) {
    let (policy, mut config) = workload::prepare(account);
    let policy = String::from_utf8(policy).unwrap();
    let launcher = "worker = \"/usr/local/libexec/dev-auth-fixture-worker\"";
    assert_eq!(policy.matches(launcher).count(), 1);
    let policy = policy.replace(
        launcher,
        &format!("{launcher}\nbroken = \"/usr/local/libexec/dev-auth-fixture-broken\""),
    );
    assert_eq!(policy.matches("launchers = [\"worker\"]").count(), 1);
    let policy = policy.replace(
        "launchers = [\"worker\"]",
        "launchers = [\"worker\", \"broken\"]",
    );
    config.extend_from_slice(
        br#"
[[workloads]]
name = "broken-worker"
profile = "worker"
launcher = "broken"
admission = "enrolled_noninteractive"
duration_seconds = 60
[workloads.resources.token]
purposes = ["read"]
projections = ["stdin"]
"#,
    );
    publish(
        Path::new("/usr/local/libexec/dev-auth-fixture-broken"),
        b"#!/dev-auth-fixture-missing-interpreter\n",
        0o755,
    );
    let worker = Path::new("/usr/local/libexec/dev-auth-fixture-worker");
    let original = fs::read(worker).unwrap();
    assert!(original.starts_with(b"#!/bin/sh\n"));
    let mut wrapped = br#"#!/bin/sh
if [ "${1-}" = privilege-check ]; then
  [ "$(/usr/local/bin/dev-auth privilege exec -- /usr/bin/id -u)" = 0 ] || exit 92
  case "${2-}" in user|workload) ;; *) exit 93 ;; esac
  printf 'installed-privilege-check=passed\n' > "$HOME/payload-$2"
  exit 0
fi
"#
    .to_vec();
    wrapped.extend_from_slice(&original[b"#!/bin/sh\n".len()..]);
    publish(worker, &wrapped, 0o755);
    (policy.into_bytes(), config)
}

pub(super) fn finish_prepare(account: &nix::unistd::User, executable: &Path) {
    workload::require_credential_operation(account, executable);
    for path in [
        "/etc/dev-auth/administrator-grants-v1.json",
        "/etc/systemd/system/dev-auth-grants.service",
        "/usr/share/polkit-1/actions/org.futuredevguys.dev-auth.privilege.policy",
    ] {
        assert!(
            !Path::new(path).exists(),
            "privilege fixture needs absent authority"
        );
    }
    // Parse the same public closed policy interface used by native acceptance.
    let policy: crate::privilege::grants::policy::Policy =
        serde_json::from_value(serde_json::json!({
            "schema": "dev-auth-administrator-grant-policy-v1", "sudo_program": "/usr/bin/sudo",
            "subjects": [{"account":{"kind":"unix","uid":account.uid.as_raw()},
                "scopes":["user","workload"],"authorities":[{"kind":"administrator"}],
                "maximum_duration_seconds":86400,"allow_delegation":true}],
            "plans":{},"operations":{}
        }))
        .unwrap();
    policy.validate().unwrap();
    publish(
        Path::new("/etc/dev-auth/administrator-grants-v1.json"),
        &serde_json::to_vec(&policy).unwrap(),
        0o644,
    );
    publish(
        Path::new("/etc/systemd/system/dev-auth-grants.service"),
        crate::privilege::grants::assets::SERVICE.as_bytes(),
        0o644,
    );
    publish(
        Path::new("/usr/share/polkit-1/actions/org.futuredevguys.dev-auth.privilege.policy"),
        crate::privilege::grants::assets::POLKIT.as_bytes(),
        0o644,
    );
    assert!(command(
        Path::new("/usr/sbin/usermod"),
        &["--append", "--groups", "wheel", &account.name]
    )
    .status
    .success());
    assert!(command(Path::new("/usr/bin/systemctl"), &["daemon-reload"])
        .status
        .success());
    assert!(command(
        Path::new("/usr/bin/systemctl"),
        &[
            "start",
            "polkit.service",
            "systemd-logind.service",
            "dev-auth-grants.service"
        ]
    )
    .status
    .success());
    // This is a disposable fixture component, not receipt-owned privilege setup.
    // login(1) runs this entry point only after the operator sets a temporary
    // password through native passwd(1), wholly inside the visible terminal.
    let profile = account.dir.join(".bash_profile");
    // This account was created by this fixture with no prior home authority.
    publish(
        &profile,
        b"exec /usr/bin/bash --noprofile --norc /fixture/installed-user.sh\n",
        0o600,
    );
    nix::unistd::chown(&profile, Some(account.uid), Some(account.gid)).unwrap();
    publish(Path::new("/fixture/prepared.json"), b"{\"schema\":\"dev-auth-installed-launch-preparation-v1\",\"prepared\":true,\"signed_release\":false,\"privilege_setup_receipted\":false}\n", 0o644);
}
