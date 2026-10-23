//! Decorate the existing native workload launch with its admitted destinations.
//! This module owns no provider, launcher selection, approval or process runner.
#[cfg(target_os = "linux")]
use crate::policy_v2::ResolvedWorkload;
#[cfg(target_os = "linux")]
use anyhow::{bail, Result};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};

#[cfg(target_os = "linux")]
pub(crate) fn digest(workload: &ResolvedWorkload) -> Result<Option<String>> {
    crate::secret_execution::validate_workload(&workload.secret_projections)?;
    if workload.secret_projections.is_empty() {
        return Ok(None);
    }
    let document = serde_json::json!({
        "schema": "dev-auth-workload-projection-v1",
        "launcher": workload.launcher_path,
        "projections": workload.secret_projections,
    });
    Ok(Some(format!(
        "{:x}",
        Sha256::digest(serde_jcs::to_vec(&document)?)
    )))
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(target_os = "linux")]
pub(crate) struct LaunchIdentity<'a> {
    pub owner_uid: u32,
    pub session_id: &'a str,
    pub workload: &'a str,
}

/// Retain the configured executable before contacting a provider. Pathname
/// replacement cannot select a different consumer while material is fetched.
/// This does not freeze an authorized owner's in-place executable writes.
#[cfg(target_os = "linux")]
pub(crate) fn retained_command(path: &std::path::Path) -> Result<std::process::Command> {
    dev_tools_command::HeldExecutable::open_with_validation(path, |descriptor, _| {
        // The product's ordinary launcher validation disallows writable
        // ancestry, including the sticky-directory exception of the foundation.
        if rustix::fs::fstat(descriptor)?.st_mode & 0o022 != 0 {
            bail!("workload consumer path is writable by another account");
        }
        Ok(())
    })?
    .into_command(path.as_os_str())
}

#[cfg(target_os = "linux")]
#[derive(PartialEq, Eq)]
struct Admission {
    deadline: Option<u64>,
}

#[cfg(target_os = "linux")]
fn admission(
    response: crate::broker_protocol::BrokerResponse,
    workload: &ResolvedWorkload,
    identity: &LaunchIdentity<'_>,
    expected_digest: Option<&str>,
) -> Result<Admission> {
    if let crate::broker_protocol::BrokerResponse::Ready {
        session_id,
        owner_uid,
        execution_uid,
        workload: admitted,
        profile,
        hard_deadline_boot_ms,
        launch_projection_digest,
        ..
    } = response
    {
        if session_id == identity.session_id
            && owner_uid == identity.owner_uid
            && execution_uid == nix::unistd::Uid::effective().as_raw()
            && admitted == identity.workload
            && profile == workload.authority_profile
            && launch_projection_digest.as_deref() == expected_digest
            && launch_projection_digest.as_deref().is_none_or(valid_digest)
            && (expected_digest.is_none() || hard_deadline_boot_ms.is_some())
            && hard_deadline_boot_ms.is_none_or(|deadline| {
                crate::linux_platform::boot_time_millis().is_ok_and(|now| now < deadline)
            })
        {
            return Ok(Admission {
                deadline: hard_deadline_boot_ms,
            });
        }
    }
    bail!("workload projection differs from its admitted identity")
}

/// Acquire every value before invoking the existing final-consumer launch.
/// Recheck both sides of the fetch, including Some-to-None config changes.
#[cfg(target_os = "linux")]
pub(crate) fn run<T>(
    command: std::process::Command,
    workload: &ResolvedWorkload,
    identity: LaunchIdentity<'_>,
    mut request: impl FnMut(
        crate::broker_protocol::BrokerRequest,
    ) -> Result<crate::broker_protocol::BrokerResponse>,
    execute: impl FnOnce(std::process::Command) -> Result<T>,
) -> Result<T> {
    use crate::broker_protocol::{BrokerRequest, BrokerResponse};
    let expected_digest = digest(workload)?;
    let mut request = |operation| {
        request(operation)
            .map_err(|_| anyhow::anyhow!("declared workload projection broker is unavailable"))
    };
    let before = admission(
        request(BrokerRequest::Probe)?,
        workload,
        &identity,
        expected_digest.as_deref(),
    )?;
    if workload.secret_projections.is_empty() {
        return execute(command);
    }
    let mut values = Vec::with_capacity(workload.secret_projections.len());
    for projection in &workload.secret_projections {
        let response = request(BrokerRequest::SecretRead {
            resource: projection.resource.clone(),
            projection: Some(projection.projection()),
        })?;
        let BrokerResponse::SecretMaterial { material } = response else {
            bail!("declared workload projection is unavailable");
        };
        values.push(material);
    }
    let prepared =
        crate::secret_execution::Prepared::new(command, &workload.secret_projections, values)
            .map_err(|_| anyhow::anyhow!("declared workload projection could not be prepared"))?;
    let after = admission(
        request(BrokerRequest::Probe)?,
        workload,
        &identity,
        expected_digest.as_deref(),
    )?;
    if before != after {
        bail!("workload projection admission changed before execution");
    }
    prepared.with_command(execute)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::broker_protocol::{BrokerRequest, BrokerResponse, SensitiveBytes};
    use crate::secret_execution::{Request, Target};
    use std::cell::Cell;
    use std::process::Command;

    fn workload() -> ResolvedWorkload {
        ResolvedWorkload {
            launcher: "native-tool".into(),
            launcher_path: "/usr/bin/true".into(),
            authority_profile: "worker".into(),
            secret_references: Vec::new(),
            secret_projections: vec![Request {
                resource: "token".into(),
                target: Target::Environment("SERVICE_TOKEN".into()),
            }],
            workspace_roots: Vec::new(),
            sandbox: crate::policy_v2::ResolvedSandbox {
                mode: crate::policy_v2::SandboxMode::None,
                adapters: Vec::new(),
            },
            desktop: None,
            admission: Some(crate::policy_v3::Admission::EnrolledNoninteractive),
            duration_seconds: Some(120),
            allow_pinned_shell: false,
        }
    }

    fn identity() -> LaunchIdentity<'static> {
        LaunchIdentity {
            owner_uid: nix::unistd::Uid::effective().as_raw(),
            session_id: "session",
            workload: "native-tool",
        }
    }

    fn ready(workload: &ResolvedWorkload) -> BrokerResponse {
        BrokerResponse::Ready {
            session_id: "session".into(),
            owner_uid: identity().owner_uid,
            execution_uid: identity().owner_uid,
            workload: "native-tool".into(),
            profile: "worker".into(),
            expires_at: "2026-01-01T00:00:00Z".into(),
            hard_deadline_boot_ms: Some(
                crate::linux_platform::boot_time_millis().unwrap() + 60_000,
            ),
            launch_projection_digest: digest(workload).unwrap(),
        }
    }

    fn material(bytes: &[u8]) -> BrokerResponse {
        BrokerResponse::SecretMaterial {
            material: SensitiveBytes::new(bytes.to_vec()).unwrap(),
        }
    }

    #[test]
    fn admitted_mapping_preserves_configured_command_and_native_arguments() {
        let workload = workload();
        let first = ready(&workload);
        let mut last = first.clone();
        if let BrokerResponse::Ready { expires_at, .. } = &mut last {
            *expires_at = "2027-01-01T00:00:00Z".into();
        }
        let mut replies = [first, material(b"synthetic-value"), last].into_iter();
        let mut calls = Vec::new();
        let mut command = Command::new(&workload.launcher_path);
        command
            .args(["", "two words", ";not-shell"])
            .env("SERVICE_TOKEN", "ambient");
        let result = run(
            command,
            &workload,
            identity(),
            |request| {
                calls.push(request);
                Ok(replies.next().unwrap())
            },
            |command| {
                assert_eq!(command.get_program(), "/usr/bin/true");
                assert_eq!(
                    command.get_args().collect::<Vec<_>>(),
                    ["", "two words", ";not-shell"]
                );
                assert_eq!(
                    command
                        .get_envs()
                        .find(|(name, _)| name == &"SERVICE_TOKEN")
                        .unwrap()
                        .1
                        .unwrap(),
                    "synthetic-value"
                );
                Ok(29)
            },
        )
        .unwrap();
        assert_eq!(result, 29);
        assert_eq!(
            calls,
            [
                BrokerRequest::Probe,
                BrokerRequest::SecretRead {
                    resource: "token".into(),
                    projection: Some(crate::logical_authority::Projection::Environment)
                },
                BrokerRequest::Probe
            ]
        );
    }

    #[test]
    fn changed_or_missing_admission_mapping_stops_before_provider_access() {
        for remove_current in [false, true] {
            let mut workload = workload();
            let mut response = ready(&workload);
            if remove_current {
                workload.secret_projections.clear();
            } else if let BrokerResponse::Ready {
                launch_projection_digest,
                ..
            } = &mut response
            {
                *launch_projection_digest = None;
            }
            let calls = Cell::new(0);
            let result = run(
                Command::new("/usr/bin/true"),
                &workload,
                identity(),
                |request| {
                    assert_eq!(request, BrokerRequest::Probe);
                    calls.set(calls.get() + 1);
                    Ok(response.clone())
                },
                |_| -> Result<()> { panic!("must not start") },
            );
            assert!(result.is_err());
            assert_eq!(calls.get(), 1);
        }
    }

    #[test]
    fn partial_material_or_unrepresentable_environment_never_starts_consumer() {
        for nul in [false, true] {
            let mut workload = workload();
            workload.secret_projections.push(Request {
                resource: "secondary".into(),
                target: Target::Environment("SECOND_TOKEN".into()),
            });
            let replies = if nul {
                vec![
                    ready(&workload),
                    material(b"synthetic-secret"),
                    material(b"cannot\0represent"),
                ]
            } else {
                vec![
                    ready(&workload),
                    material(b"synthetic-secret"),
                    BrokerResponse::Denied {
                        code: "denied".into(),
                        message: "synthetic-secret".into(),
                    },
                ]
            };
            let mut replies = replies.into_iter();
            let error = run(
                Command::new("/usr/bin/true"),
                &workload,
                identity(),
                |_| Ok(replies.next().unwrap()),
                |_| -> Result<()> { panic!("must not start") },
            )
            .unwrap_err();
            assert!(!format!("{error:#}").contains("synthetic-secret"));
            assert!(!format!("{error:#}").contains("cannot"));
        }
    }

    #[test]
    fn final_probe_rejects_identity_deadline_and_mapping_changes() {
        let workload = workload();
        for change in 0..10 {
            let first = ready(&workload);
            let mut last = first.clone();
            if let BrokerResponse::Ready {
                session_id,
                owner_uid,
                execution_uid,
                workload,
                profile,
                hard_deadline_boot_ms,
                launch_projection_digest,
                ..
            } = &mut last
            {
                match change {
                    0 => *session_id = "other-session".into(),
                    1 => *owner_uid = owner_uid.wrapping_add(1),
                    2 => *execution_uid = execution_uid.wrapping_add(1),
                    3 => *workload = "other-workload".into(),
                    4 => *profile = "other-profile".into(),
                    5 => *hard_deadline_boot_ms = Some(hard_deadline_boot_ms.unwrap() + 1),
                    6 => *hard_deadline_boot_ms = Some(0),
                    7 => *launch_projection_digest = None,
                    8 => *launch_projection_digest = Some("0".repeat(64)),
                    _ => last = BrokerResponse::NoSession,
                }
            }
            let mut replies = [first, material(b"synthetic-secret"), last].into_iter();
            assert!(run(
                Command::new("/usr/bin/true"),
                &workload,
                identity(),
                |_| Ok(replies.next().unwrap()),
                |_| -> Result<()> { panic!("must not start") }
            )
            .is_err());
        }
    }

    #[test]
    fn empty_legacy_mapping_never_reads_provider() {
        let mut workload = workload();
        workload.secret_projections.clear();
        let calls = Cell::new(0);
        assert_eq!(
            run(
                Command::new("/usr/bin/true"),
                &workload,
                identity(),
                |request| {
                    assert_eq!(request, BrokerRequest::Probe);
                    calls.set(calls.get() + 1);
                    Ok(ready(&workload))
                },
                |_| Ok(7)
            )
            .unwrap(),
            7
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn digest_binds_consumer_and_exact_destination_without_material() {
        let mut workload = workload();
        let initial = digest(&workload).unwrap().unwrap();
        assert!(valid_digest(&initial));
        workload.launcher_path = "/usr/bin/false".into();
        assert_ne!(digest(&workload).unwrap().unwrap(), initial);
        workload = self::workload();
        workload.secret_projections[0].target = Target::Environment("OTHER_TOKEN".into());
        assert_ne!(digest(&workload).unwrap().unwrap(), initial);
        for invalid in [
            "A".repeat(64),
            "g".repeat(64),
            "0".repeat(63),
            "0".repeat(65),
        ] {
            assert!(!valid_digest(&invalid));
        }
    }
}
