use crate::broker_protocol::{BrokerSessionProbe, LocalSessionClaim, RoutingDecision};
use crate::setup::{current_installation, verify_at, InstallMode};
use anyhow::{bail, Result};
use serde::Serialize;

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrokerStatusReport {
    pub schema: &'static str,
    pub mode: InstallMode,
    pub version: String,
    pub source_commit: Option<String>,
    pub root_generation: Option<u64>,
    pub manifest_generation: Option<u64>,
    pub authenticated_release: bool,
    pub product_aliases_ready: bool,
    pub transparent_launchers_active: bool,
    pub policy_ready: bool,
    pub user_config_ready: bool,
    pub policy_resolution_ready: bool,
    pub workload_launchers_ready: bool,
    pub desktop_entries_ready: bool,
    pub launcher_resolution_ready: bool,
    pub signing_configured: bool,
    pub ssh_authentication_configured: bool,
    pub credential_ready: bool,
    pub session_state: &'static str,
    pub broker_state: &'static str,
    pub degraded_same_user_boundary: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExplainReport {
    pub schema: &'static str,
    pub command: String,
    pub local_claim: &'static str,
    pub broker_probe: &'static str,
    pub decision: &'static str,
    pub reason: Option<String>,
}

pub fn broker_status() -> Result<BrokerStatusReport> {
    let (paths, receipt) = current_installation()?;
    let setup = verify_at(&paths)?;
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?;
    let policy_ready = match (receipt.mode, user.as_ref()) {
        (InstallMode::Strong, _) => crate::policy_store::load_system_policy().is_ok(),
        (InstallMode::UserOnly, Some(user)) => crate::policy_store::load_user_policy_at(
            &crate::policy_store::user_policy_path(user),
            user.uid.as_raw(),
        )
        .is_ok(),
        (InstallMode::UserOnly, None) => false,
    };
    let user_config_ready = user.as_ref().is_some_and(|user| {
        crate::policy_store::load_user_config_at(
            &crate::policy_store::user_config_path(user),
            user.uid.as_raw(),
        )
        .is_ok()
    });
    let resolved = match (receipt.mode, user.as_ref()) {
        (InstallMode::Strong, Some(user)) => {
            crate::policy_store::load_resolved_policy_for_uid(user.uid.as_raw()).ok()
        }
        (InstallMode::UserOnly, Some(user)) => {
            crate::policy_store::load_user_only_resolved_policy_for_uid(user.uid.as_raw()).ok()
        }
        (_, None) => None,
    };
    let integrations = match (user.as_ref(), resolved.as_ref()) {
        (Some(user), Some(resolved)) => crate::setup::verify_user_integrations_at(
            &user.dir,
            std::path::Path::new(&receipt.executable),
            &resolved.workloads,
            user.uid.as_raw(),
        )
        .ok(),
        _ => None,
    };
    let signing_configured = resolved.as_ref().is_some_and(|resolved| {
        resolved
            .authority_profiles
            .values()
            .any(|profile| profile.signing && profile.signing_key.is_some())
    });
    let ssh_authentication_configured = resolved.as_ref().is_some_and(|resolved| {
        resolved
            .authority_profiles
            .values()
            .any(|profile| profile.ssh && !profile.ssh_keys.is_empty())
    });
    let launcher_resolution_ready = setup.transparent_launchers_active
        && crate::setup::transparent_launchers_resolve_first_at(
            &paths,
            std::path::Path::new(&receipt.executable),
            std::env::var_os("PATH").as_deref().unwrap_or_default(),
        )?;
    let credential_ready = match receipt.mode {
        InstallMode::Strong => crate::setup::system_service_credential_ready(),
        InstallMode::UserOnly => crate::runtime::user_broker_service_token().is_ok(),
    };
    let (claim, probe) = claim_and_probe(receipt.mode)?;
    Ok(BrokerStatusReport {
        schema: "dev-auth-broker-status-v1",
        mode: receipt.mode,
        version: receipt.version,
        source_commit: receipt.source_commit.clone(),
        root_generation: receipt.root_generation,
        manifest_generation: receipt.manifest_generation,
        authenticated_release: receipt.source_commit.is_some()
            && receipt.root_generation.is_some()
            && receipt.manifest_generation.is_some(),
        product_aliases_ready: setup.product_aliases_ready,
        transparent_launchers_active: setup.transparent_launchers_active,
        policy_ready,
        user_config_ready,
        policy_resolution_ready: resolved.is_some(),
        workload_launchers_ready: integrations
            .as_ref()
            .is_some_and(|report| report.workload_launchers_ready),
        desktop_entries_ready: integrations
            .as_ref()
            .is_some_and(|report| report.desktop_entries_ready),
        launcher_resolution_ready,
        signing_configured,
        ssh_authentication_configured,
        credential_ready,
        session_state: claim_name(&claim),
        broker_state: probe_name(&probe),
        degraded_same_user_boundary: receipt.mode == InstallMode::UserOnly,
    })
}

pub fn explain(command: &str) -> Result<ExplainReport> {
    if !matches!(command, "git" | "gh") {
        bail!("explain supports only git or gh");
    }
    let (_, receipt) = current_installation()?;
    let (claim, probe) = claim_and_probe(receipt.mode)?;
    let decision = crate::broker_protocol::decide_routing(&claim, probe.clone());
    let (decision_name, reason) = match decision {
        RoutingDecision::NativePassthrough => ("native_passthrough", None),
        RoutingDecision::BrokerSession { .. } => ("broker_session", None),
        RoutingDecision::Deny { reason } => ("deny", Some(reason)),
    };
    Ok(ExplainReport {
        schema: "dev-auth-explain-v1",
        command: command.to_owned(),
        local_claim: claim_name(&claim),
        broker_probe: probe_name(&probe),
        decision: decision_name,
        reason,
    })
}

fn claim_and_probe(mode: InstallMode) -> Result<(LocalSessionClaim, BrokerSessionProbe)> {
    #[cfg(target_os = "linux")]
    {
        let value = crate::broker_client::active_claim_and_probe()?;
        if mode == InstallMode::Strong
            && matches!(value.0, LocalSessionClaim::Present { ref marker } if marker.starts_with("user:"))
        {
            bail!("strong installation received a user-only broker hint");
        }
        Ok(value)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok((LocalSessionClaim::Absent, probe_for_mode(mode)))
    }
}

#[cfg(not(target_os = "linux"))]
fn probe_for_mode(mode: InstallMode) -> BrokerSessionProbe {
    match mode {
        InstallMode::Strong => BrokerSessionProbe::Unavailable {
            reason: "strong broker is not supported on this platform".into(),
        },
        InstallMode::UserOnly => BrokerSessionProbe::NoSession,
    }
}

fn claim_name(claim: &LocalSessionClaim) -> &'static str {
    match claim {
        LocalSessionClaim::Absent => "absent",
        LocalSessionClaim::Present { .. } => "present",
    }
}

fn probe_name(probe: &BrokerSessionProbe) -> &'static str {
    match probe {
        BrokerSessionProbe::Verified { .. } => "verified",
        BrokerSessionProbe::NoSession => "no_session",
        BrokerSessionProbe::Invalid { .. } => "invalid",
        BrokerSessionProbe::Unavailable { .. } => "unavailable",
    }
}
