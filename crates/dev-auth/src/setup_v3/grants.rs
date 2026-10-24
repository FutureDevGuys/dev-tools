//! The privilege component of the existing full setup generation. No separate
//! installer, approval record, credential store or restoration journal is used.
use super::*;
pub(super) mod maintenance;
use crate::deployment::SetupPurpose;
use crate::privilege::grants::assets;
use dev_tools_installation::ArtifactIdentity;

mod native;
#[cfg(test)]
mod native_acceptance;

const LIBRARY: &str = "/usr/local/lib/dev-auth/privilege/dev-auth-sudo.so";
const UNIT: &str = "dev-auth-grants.service";
const SERVICE: &str = "/etc/systemd/system/dev-auth-grants.service";
const ACTION: &str = "/usr/share/polkit-1/actions/org.futuredevguys.dev-auth.privilege.policy";
const SUDO_CONF: &str = "/etc/sudo.conf";
const SUDOERS: &str = "/etc/sudoers.d/50-dev-auth-privilege";
const BEGIN: &[u8] = b"# BEGIN receipt-owned dev-auth administrator grants v1\n";
const END: &[u8] = b"# END receipt-owned dev-auth administrator grants v1\n";
const LIBRARY_LIMIT: u64 = GRANT_LIBRARY_LIMIT;

pub(super) fn paths() -> Vec<(String, String, PathBuf)> {
    [
        ("grant_policy", crate::privilege::grants::SYSTEM_POLICY),
        ("grant_library", LIBRARY),
        ("grant_service", SERVICE),
        ("grant_action", ACTION),
        ("grant_sudo_conf", SUDO_CONF),
        ("grant_sudoers", SUDOERS),
    ]
    .into_iter()
    .map(|(kind, path)| (kind.into(), "system".into(), path.into()))
    .collect()
}

fn identity(bytes: &[u8]) -> ArtifactIdentity {
    ArtifactIdentity {
        length: bytes.len() as u64,
        sha256: sha256_hex(bytes),
    }
}

fn bridge_lines(executable: &Path) -> Result<Vec<u8>> {
    let program = executable
        .to_str()
        .context("privilege frontend path is not UTF-8")?;
    if !executable.is_absolute() || program.bytes().any(|b| b.is_ascii_whitespace() || b == 0) {
        bail!("privilege frontend has invalid native configuration syntax");
    }
    Ok(format!("Plugin dev_auth_sudo_audit {LIBRARY} runtime=/run/dev-auth-grants frontend={program}\nPlugin dev_auth_sudo_approval {LIBRARY}\n").into_bytes())
}

pub(super) fn payload(installation: &SetupPlan) -> Result<BTreeMap<String, ArtifactIdentity>> {
    payload_with_library(installation, assets::SUDO_LIBRARY)
}

fn payload_with_library(
    installation: &SetupPlan,
    library: &[u8],
) -> Result<BTreeMap<String, ArtifactIdentity>> {
    if library.is_empty() || library.len() as u64 > LIBRARY_LIMIT {
        bail!("privilege setup requires the source-matched embedded native sudo payload");
    }
    let executable = installation
        .paths
        .data_root
        .join("versions")
        .join(&installation.request.version)
        .join("dev-auth");
    Ok(BTreeMap::from([
        ("library".into(), identity(library)),
        ("service".into(), identity(assets::SERVICE.as_bytes())),
        ("action".into(), identity(assets::POLKIT.as_bytes())),
        ("sudoers".into(), identity(assets::SUDOERS.as_bytes())),
        ("bridge".into(), identity(&bridge_lines(&executable)?)),
    ]))
}

/// Keep unrelated native configuration byte-for-byte. A recognizable marker
/// grants no ownership: removing a block requires its retained expected bytes.
fn render_sudo_conf(
    before: &[u8],
    prior_block: Option<&[u8]>,
    next_block: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if before.len() as u64 > DOCUMENT_LIMIT || before.contains(&0) {
        bail!("native sudo configuration has unsupported content");
    }
    let starts = before
        .windows(BEGIN.len())
        .enumerate()
        .filter_map(|(i, bytes)| (bytes == BEGIN).then_some(i))
        .collect::<Vec<_>>();
    let ends = before
        .windows(END.len())
        .enumerate()
        .filter_map(|(i, bytes)| (bytes == END).then_some(i))
        .collect::<Vec<_>>();
    let mut base = before.to_vec();
    match (starts.as_slice(), ends.as_slice(), prior_block) {
        ([], [], None) => {}
        ([start], [end], Some(expected)) if start < end => {
            let end = end + END.len();
            let start = start
                .checked_sub(usize::from(expected.starts_with(b"\n")))
                .context("owned bridge separator is absent")?;
            if (start > 0 && !expected.starts_with(b"\n") && before[start - 1] != b'\n')
                || &before[start..end] != expected
            {
                bail!("sudo bridge block changed outside retained ownership");
            }
            base.drain(start..end);
        }
        _ => bail!("sudo bridge configuration has absent, foreign or ambiguous ownership"),
    }
    let mut explicit_plugins = false;
    for line in base.split(|byte| *byte == b'\n') {
        let tokens = line
            .split(u8::is_ascii_whitespace)
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        if tokens.first().is_none_or(|first| first.starts_with(b"#")) {
            continue;
        }
        if line.last() == Some(&b'\\') {
            bail!(
                "continued native sudo configuration requires explicit compatibility qualification"
            );
        }
        if tokens.first() == Some(&b"Plugin".as_slice()) {
            explicit_plugins = true;
            if tokens.len() < 3 || tokens[1].starts_with(b"dev_auth_sudo_") {
                bail!("native sudo configuration contains an unowned or malformed plugin");
            }
        }
    }
    if let Some(next) = next_block {
        if !next.starts_with(BEGIN) || !next.ends_with(END) {
            bail!("invalid product bridge block");
        }
        // Installing explicit plugins must preserve Sudo's otherwise implicit
        // sudoers policy and I/O plugins. They belong inside our removable block.
        let mut body = next.to_vec();
        if !explicit_plugins {
            body.splice(
                BEGIN.len()..BEGIN.len(),
                b"Plugin sudoers_policy sudoers.so\nPlugin sudoers_io sudoers.so\n"
                    .iter()
                    .copied(),
            );
        }
        if !base.is_empty() && !base.ends_with(b"\n") {
            body.insert(0, b'\n');
        }
        base.extend(body);
    }
    Ok(base)
}

fn block(executable: &Path, implicit_defaults: bool) -> Result<Vec<u8>> {
    let mut bytes = BEGIN.to_vec();
    if implicit_defaults {
        bytes
            .extend_from_slice(b"Plugin sudoers_policy sudoers.so\nPlugin sudoers_io sudoers.so\n");
    }
    bytes.extend(bridge_lines(executable)?);
    bytes.extend_from_slice(END);
    Ok(bytes)
}

fn check_sudoers_export(bytes: &[u8], owned_group_plugin: bool) -> Result<()> {
    if bytes.len() as u64 > DOCUMENT_LIMIT {
        bail!("native sudo policy exceeds inspection bounds");
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("native sudo policy export is not valid JSON")?;
    let object = value
        .as_object()
        .context("native sudo policy export has no object")?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "Defaults"
                | "User_Aliases"
                | "Host_Aliases"
                | "Runas_Aliases"
                | "Command_Aliases"
                | "User_Specs"
        )
    }) {
        bail!("native sudo policy export has an unsupported schema");
    }
    fn visit(value: &serde_json::Value, owned: bool) -> Result<()> {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(plugin) = map.get("group_plugin") {
                    if !owned || plugin.as_str() != Some(LIBRARY) {
                        bail!("independent sudo group-plugin configuration cannot be replaced");
                    }
                }
                for value in map.values() {
                    visit(value, owned)?;
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    visit(value, owned)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    visit(&value, owned_group_plugin)
}

fn policy(bytes: &[u8]) -> Result<crate::privilege::grants::policy::Policy> {
    let policy: crate::privilege::grants::policy::Policy = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid privilege policy document"))?;
    policy
        .validate()
        .map_err(|_| anyhow::anyhow!("invalid privilege policy authority"))?;
    if policy.sudo_program != std::ffi::OsStr::new("/usr/bin/sudo") {
        bail!("privilege setup requires the qualified native /usr/bin/sudo integration");
    }
    Ok(policy)
}

pub(super) fn validate_policy(bytes: &[u8]) -> Result<()> {
    policy(bytes).map(|_| ())
}

fn retained(plan: &SetupPlanV3) -> Result<RetainedSetupGeneration> {
    let transition = crate::setup_transition::retained_transition(&plan.installation.paths, 0)?
        .context("privilege files require the enclosing retained setup generation")?;
    let generation: RetainedSetupGeneration = serde_json::from_slice(&transition.bytes)?;
    if generation.schema != "dev-auth-retained-setup-generation-v1"
        || generation.plan != *plan
        || generation.plan_sha256 != transition.plan_sha256
        || generation.plan_sha256 != sha256_hex(&serde_jcs::to_vec(plan)?)
    {
        bail!("privilege component differs from its retained setup authority");
    }
    Ok(generation)
}

fn prior<'a>(
    generation: &'a RetainedSetupGeneration,
    kind: &str,
) -> Result<&'a RetainedSetupObject> {
    let (_, _, path) = paths()
        .into_iter()
        .find(|(role, _, _)| role == kind)
        .context("unknown privilege file role")?;
    let expected = generation
        .plan
        .current_paths
        .iter()
        .find(|current| current.kind == kind && current.subject == "system" && current.path == path)
        .context("privilege path is missing from the approved inventory")?;
    let mut objects = generation
        .documents
        .iter()
        .filter(|object| object.current == *expected);
    let object = objects
        .next()
        .context("retained privilege object is absent")?;
    if objects.next().is_some() {
        bail!("retained privilege object is ambiguous");
    }
    match (&object.current.identity, &object.bytes) {
        (None, None) => {}
        (Some(meta), Some(bytes))
            if meta.object_type == "file"
                && meta.owner_uid == 0
                && meta.link_count == 1
                && meta.link_target.is_none()
                && meta.mode & 0o022 == 0
                && bytes.len() as u64 == meta.length
                && meta.length <= LIBRARY_LIMIT
                && sha256_hex(bytes) == meta.sha256 => {}
        _ => bail!("retained privilege object has invalid custody or bytes"),
    }
    Ok(object)
}

fn before_bytes(plan: &SetupPlanV3, kind: &str) -> Result<Option<Vec<u8>>> {
    let digest = sha256_hex(&serde_jcs::to_vec(plan)?);
    if let Some(state) = crate::setup_transition::retained_transition(&plan.installation.paths, 0)?
    {
        let generation: RetainedSetupGeneration = serde_json::from_slice(&state.bytes)?;
        if generation.schema != "dev-auth-retained-setup-generation-v1"
            || generation.plan_sha256 != state.plan_sha256
            || generation.plan_sha256 != sha256_hex(&serde_jcs::to_vec(&generation.plan)?)
        {
            bail!("privilege retention is inconsistent");
        }
        if state.plan_sha256 == digest
            || (state.phase == crate::setup_transition::Phase::Pending
                && generation.plan.intent == plan.intent
                && generation.plan.installation == plan.installation
                && generation.plan.source_documents == plan.source_documents
                && generation.plan.grant_payload == plan.grant_payload)
        {
            return Ok(prior(&generation, kind)?.bytes.clone());
        }
    }
    let current = plan
        .current_paths
        .iter()
        .find(|entry| entry.kind == kind && entry.subject == "system")
        .context("privilege current-state inventory is incomplete")?;
    Ok(capture_retained_object(current)?.bytes)
}

fn previously_owned_block(
    installation: &SetupPlan,
    intent: &DeploymentIntent,
) -> Result<Option<Vec<u8>>> {
    let Some(transition) = crate::setup_transition::retained_transition(&installation.paths, 0)?
    else {
        return Ok(None);
    };
    let generation: RetainedSetupGeneration = serde_json::from_slice(&transition.bytes)?;
    if generation.schema != "dev-auth-retained-setup-generation-v1"
        || generation.plan_sha256 != transition.plan_sha256
        || generation.plan_sha256 != sha256_hex(&serde_jcs::to_vec(&generation.plan)?)
        || generation.plan.installation.paths != installation.paths
    {
        bail!("privilege setup cannot adopt another component's retained generation");
    }
    if terminal_replacement_allowed(transition.phase, || {
        maintenance::verify_terminal_replacement(&generation)
    })? {
        // A completed uninstall owns no integration block for the new plan.
        // Its old block remains retained evidence, never replacement authority.
        return Ok(None);
    }
    if !generation.plan.intent.has_grants() {
        return match transition.phase {
            crate::setup_transition::Phase::Accepted
            | crate::setup_transition::Phase::RestoredInactive => Ok(None),
            crate::setup_transition::Phase::Pending
            | crate::setup_transition::Phase::Restoring
            | crate::setup_transition::Phase::Repairing
            | crate::setup_transition::Phase::Uninstalling
            | crate::setup_transition::Phase::UninstalledInactive => {
                bail!("existing credential setup requires recovery before adding privilege")
            }
        };
    }
    match transition.phase {
        crate::setup_transition::Phase::Pending | crate::setup_transition::Phase::Repairing => {
            if generation.plan.intent != *intent || generation.plan.installation != *installation {
                bail!("another privilege setup requires recovery before replanning");
            }
            Ok(generation.plan.grant_previous_block)
        }
        crate::setup_transition::Phase::Restoring => {
            bail!("privilege restoration must finish before replanning")
        }
        crate::setup_transition::Phase::Uninstalling
        | crate::setup_transition::Phase::UninstalledInactive => {
            bail!("setup maintenance must finish before replanning")
        }
        crate::setup_transition::Phase::RestoredInactive => {
            Ok(generation.plan.grant_previous_block)
        }
        crate::setup_transition::Phase::Accepted => {
            if generation.plan.intent.activation != Activation::Transparent {
                return Ok(None);
            }
            let before = prior(&generation, "grant_sudo_conf")?
                .bytes
                .as_deref()
                .unwrap_or_default();
            let base = render_sudo_conf(
                before,
                generation.plan.grant_previous_block.as_deref(),
                None,
            )?;
            let executable = generation
                .plan
                .installation
                .paths
                .data_root
                .join("versions")
                .join(&generation.plan.installation.request.version)
                .join("dev-auth");
            let next = block(&executable, false)?;
            let after = render_sudo_conf(
                before,
                generation.plan.grant_previous_block.as_deref(),
                Some(&next),
            )?;
            Ok(Some(after[base.len()..].to_vec()))
        }
    }
}

fn terminal_replacement_allowed(
    phase: crate::setup_transition::Phase,
    verify_withdrawn: impl FnOnce() -> Result<()>,
) -> Result<bool> {
    match phase {
        crate::setup_transition::Phase::UninstalledInactive => {
            verify_withdrawn()?;
            Ok(true)
        }
        crate::setup_transition::Phase::Uninstalling => {
            bail!("setup maintenance must finish before replanning")
        }
        _ => Ok(false),
    }
}

pub(super) fn build(
    intent: DeploymentIntent,
    installation: SetupPlan,
    require_privileged: bool,
    read_source: &dyn Fn(&Path, &str, &str) -> Result<OpenedDocument>,
    validate_installation: &dyn Fn(&SetupPlan) -> Result<()>,
) -> Result<SetupPlanV3> {
    let intent_sha256 = sha256_hex(&canonical_deployment_intent(&intent)?);
    if intent.purpose != SetupPurpose::PrivilegeOnly
        || intent.mode != DeploymentMode::Strong
        || installation.request.mode != crate::setup::InstallMode::Strong
        || installation.request.purpose != intent.purpose
        || installation.paths != crate::setup::SetupPaths::strong()
        || (require_privileged && !nix::unistd::geteuid().is_root())
    {
        bail!("privilege setup requires its exact system installation authority");
    }
    validate_installation(&installation)?;
    let invoked = crate::setup::setup_executable_identity(&std::env::current_exe()?)?;
    if invoked
        != (
            installation.source_length,
            installation.source_sha256.clone(),
        )
    {
        bail!("privilege setup planning must run from the exact selected release candidate");
    }
    require_compatible_installation(&installation)?;
    let document = read_source(&intent.administrator_policy, "grant_policy", "system")?;
    policy(&document.bytes)?;
    let grant_payload = payload(&installation)?;
    let grant_previous_block = previously_owned_block(&installation, &intent)?;
    let (current_paths, current_credential_ready, current_broker_state) = current_state_snapshot(
        &installation,
        &intent,
        &[],
        &[],
        Some("dev-auth-administrator-grant-policy-v1"),
    )?;
    validate_existing_component(&installation, &current_paths)?;
    let current_state_sha256 = stored_current_state_digest(
        &current_paths,
        &current_credential_ready,
        &current_broker_state,
    )?;
    let actions = planned_action_contract(&intent);
    let plan = SetupPlanV3 {
        credential_preservation: None,
        grant_previous_block,
        grant_current_state: None,
        grant_payload,
        authority_schema: Some("dev-auth-administrator-grant-policy-v1".into()),
        schema: "dev-auth-setup-plan-v4".into(),
        intent,
        intent_sha256,
        installation,
        source_documents: vec![document.identity],
        accounts: vec![],
        retiring_accounts: vec![],
        current_paths,
        current_credential_ready,
        current_broker_state,
        current_state_sha256,
        actions,
    };
    let before = before_bytes(&plan, "grant_sudo_conf")?.unwrap_or_default();
    render_sudo_conf(&before, plan.grant_previous_block.as_deref(), None)?;
    native::sudo_compatibility(plan.grant_previous_block.is_some())?;
    validate_setup_plan_v3_with_installation_check(&plan, validate_installation)?;
    Ok(plan)
}

pub(super) fn attach(
    plan: &mut SetupPlanV3,
    validate_installation: &dyn Fn(&SetupPlan) -> Result<()>,
) -> Result<()> {
    if plan.intent.purpose != SetupPurpose::Credentials
        || plan.intent.grant_policy.is_none()
        || plan.intent.mode != DeploymentMode::Strong
        || plan.installation.request.mode != crate::setup::InstallMode::Strong
        || plan.installation.paths != crate::setup::SetupPaths::strong()
    {
        bail!("combined privilege setup requires exact strong installation authority");
    }
    validate_installation(&plan.installation)?;
    require_compatible_installation(&plan.installation)?;
    plan.grant_payload = payload(&plan.installation)?;
    plan.grant_previous_block = previously_owned_block(&plan.installation, &plan.intent)?;
    validate_existing_component(&plan.installation, &plan.current_paths)?;
    let before = before_bytes(plan, "grant_sudo_conf")?.unwrap_or_default();
    render_sudo_conf(&before, plan.grant_previous_block.as_deref(), None)?;
    native::sudo_compatibility(plan.grant_previous_block.is_some())?;
    Ok(())
}

fn require_compatible_installation(installation: &SetupPlan) -> Result<()> {
    match read_bounded(&installation.paths.data_root.join("install-v2.json")) {
        Ok(bytes) => {
            let receipt: crate::setup::InstallReceipt = serde_json::from_slice(&bytes)?;
            crate::setup::require_preserving_purpose(
                receipt.purpose,
                installation.request.purpose,
            )?;
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

pub(super) fn require_selected_if_retained(installation: &SetupPlan) -> Result<()> {
    let Some(transition) = crate::setup_transition::retained_transition(&installation.paths, 0)?
    else {
        return Ok(());
    };
    let generation: RetainedSetupGeneration = serde_json::from_slice(&transition.bytes)?;
    if generation.schema != "dev-auth-retained-setup-generation-v1"
        || generation.plan_sha256 != transition.plan_sha256
        || generation.plan_sha256 != sha256_hex(&serde_jcs::to_vec(&generation.plan)?)
    {
        bail!("existing privilege retention is inconsistent");
    }
    if generation.plan.intent.has_grants()
        && transition.phase != crate::setup_transition::Phase::RestoredInactive
    {
        bail!("existing privilege installation requires privilege selection or restoration");
    }
    Ok(())
}

pub(super) fn state() -> Result<String> {
    Ok(serde_jcs::to_string(&native::observe()?)?)
}

pub(super) fn validate(plan: &SetupPlanV3) -> Result<()> {
    validate_component(plan)?;
    if !plan.accounts.is_empty()
        || !plan.retiring_accounts.is_empty()
        || !plan.current_credential_ready.is_empty()
        || plan.source_documents.len() != 1
        || plan.authority_schema.as_deref() != Some("dev-auth-administrator-grant-policy-v1")
    {
        bail!("privilege-only setup contains credential authority");
    }
    Ok(())
}

pub(super) fn validate_component(plan: &SetupPlanV3) -> Result<()> {
    if plan.intent.mode != DeploymentMode::Strong
        || plan.installation.request.mode != crate::setup::InstallMode::Strong
        || !plan.intent.has_grants()
        || plan.installation.request.purpose != plan.intent.purpose
    {
        bail!("privilege setup plan has an incompatible closed authority contract");
    }
    let expected_policy = plan
        .intent
        .grant_policy
        .as_deref()
        .unwrap_or(&plan.intent.administrator_policy);
    let mut policies = plan
        .source_documents
        .iter()
        .filter(|document| document.kind == "grant_policy" && document.subject == "system");
    if policies
        .next()
        .is_none_or(|document| document.path != expected_policy)
        || policies.next().is_some()
    {
        bail!("privilege setup plan lacks its exact policy source");
    }
    let state_bytes = match plan.intent.purpose {
        SetupPurpose::PrivilegeOnly if plan.grant_current_state.is_none() => {
            &plan.current_broker_state
        }
        SetupPurpose::Credentials => plan
            .grant_current_state
            .as_ref()
            .context("combined privilege setup lacks a native service snapshot")?,
        _ => bail!("privilege service snapshot is incompatible with setup purpose"),
    };
    let state: native::State = serde_json::from_str(state_bytes)?;
    if !state.loaded && (!state.stopped || state.enabled) {
        bail!("privilege service snapshot is inconsistent");
    }
    if plan.grant_previous_block.as_ref().is_some_and(|bytes| {
        bytes.len() > 8192
            || bytes.contains(&0)
            || !(bytes.starts_with(BEGIN)
                || bytes
                    .strip_prefix(b"\n")
                    .is_some_and(|body| body.starts_with(BEGIN)))
            || !bytes.ends_with(END)
    }) {
        bail!("retained privilege bridge block has invalid syntax");
    }
    Ok(())
}

pub(super) fn revalidate(
    plan: &SetupPlanV3,
    documents: &[RetainedCandidateDocument],
    validate_installation: &dyn Fn(&SetupPlan) -> Result<()>,
) -> Result<()> {
    if plan.intent.purpose == SetupPurpose::PrivilegeOnly {
        validate(plan)?;
    } else {
        validate_component(plan)?;
    }
    validate_installation(&plan.installation)?;
    require_compatible_installation(&plan.installation)?;
    policy(candidate_bytes(
        documents,
        document_identity(plan, "grant_policy", "system")?,
    )?)?;
    let digest = sha256_hex(&serde_jcs::to_vec(plan)?);
    let known = crate::setup_transition::retained_transition(&plan.installation.paths, 0)?
        .is_some_and(|transition| transition.plan_sha256 == digest);
    if known {
        retained(plan)?;
    } else if previously_owned_block(&plan.installation, &plan.intent)? != plan.grant_previous_block
    {
        bail!("privilege ownership changed after approval");
    }
    Ok(())
}

pub(super) struct DesiredFile {
    kind: &'static str,
    path: &'static str,
    mode: u32,
    bytes: Option<Vec<u8>>,
}

fn desired_files(
    plan: &SetupPlanV3,
    documents: &[RetainedCandidateDocument],
) -> Result<Vec<DesiredFile>> {
    if plan.grant_payload != payload(&plan.installation)? {
        bail!("privilege payload differs from the approved candidate");
    }
    let policy_identity = document_identity(plan, "grant_policy", "system")?;
    let policy_bytes = candidate_bytes(documents, policy_identity)?;
    policy(policy_bytes)?;
    let before = before_bytes(plan, "grant_sudo_conf")?;
    let executable = plan
        .installation
        .paths
        .data_root
        .join("versions")
        .join(&plan.installation.request.version)
        .join("dev-auth");
    let active = plan.intent.activation == Activation::Transparent;
    let bridge = block(&executable, false)?;
    let merged = render_sudo_conf(
        before.as_deref().unwrap_or_default(),
        plan.grant_previous_block.as_deref(),
        active.then_some(bridge.as_slice()),
    )?;
    let conf_mode = plan
        .current_paths
        .iter()
        .find(|entry| entry.kind == "grant_sudo_conf")
        .and_then(|entry| entry.identity.as_ref())
        .map_or(0o644, |identity| identity.mode);
    Ok(vec![
        DesiredFile {
            kind: "grant_library",
            path: LIBRARY,
            mode: 0o644,
            bytes: Some(assets::SUDO_LIBRARY.to_vec()),
        },
        DesiredFile {
            kind: "grant_policy",
            path: crate::privilege::grants::SYSTEM_POLICY,
            mode: 0o600,
            bytes: Some(policy_bytes.to_vec()),
        },
        DesiredFile {
            kind: "grant_action",
            path: ACTION,
            mode: 0o644,
            bytes: Some(assets::POLKIT.as_bytes().to_vec()),
        },
        DesiredFile {
            kind: "grant_service",
            path: SERVICE,
            mode: 0o644,
            bytes: Some(assets::SERVICE.as_bytes().to_vec()),
        },
        DesiredFile {
            kind: "grant_sudoers",
            path: SUDOERS,
            mode: 0o440,
            bytes: active.then(|| assets::SUDOERS.as_bytes().to_vec()),
        },
        DesiredFile {
            kind: "grant_sudo_conf",
            path: SUDO_CONF,
            mode: conf_mode,
            bytes: (active || before.is_some()).then_some(merged),
        },
    ])
}

pub(super) fn verify(plan: &SetupPlanV3, documents: &[RetainedCandidateDocument]) -> Result<()> {
    let files = desired_files(plan, documents)?;
    for file in &files {
        let preparation = dev_tools_installation::DocumentDirectoryPreparation::observe(
            Path::new(file.path)
                .parent()
                .context("privilege path has no parent")?,
            0,
            0o755,
        )?;
        let found = preparation.read_file(
            Path::new(file.path)
                .file_name()
                .context("privilege path has no leaf")?,
            &file.authority(),
        )?;
        if found.as_ref().map(|document| document.bytes.as_slice()) != file.bytes.as_deref() {
            bail!("privilege component does not satisfy its approved file identity");
        }
    }
    let state = native::observe()?;
    if plan.intent.activation == Activation::Transparent {
        if !state.loaded || state.stopped || !state.enabled {
            bail!("privilege coordinator is not active");
        }
        native::sudo_compatibility(true)?;
    } else {
        if !state.stopped || state.enabled {
            bail!("privilege coordinator remains active");
        }
        crate::setup::restoration::require_grant_domain_empty()?;
    }
    Ok(())
}

impl DesiredFile {
    fn authority(&self) -> DocumentAuthority {
        DocumentAuthority {
            owner_uid: 0,
            mode: self.mode,
            limit: if self.kind == "grant_library" {
                LIBRARY_LIMIT
            } else {
                DOCUMENT_LIMIT
            },
        }
    }
}

fn validate_existing_component(
    installation: &SetupPlan,
    current: &[CurrentPathIdentity],
) -> Result<()> {
    let previous = crate::setup_transition::retained_transition(&installation.paths, 0)?
        .map(|transition| serde_json::from_slice::<RetainedSetupGeneration>(&transition.bytes))
        .transpose()?;
    for entry in current
        .iter()
        .filter(|entry| entry.kind.starts_with("grant_"))
    {
        let Some(meta) = &entry.identity else {
            continue;
        };
        if meta.object_type != "file"
            || meta.owner_uid != 0
            || meta.link_count != 1
            || meta.mode & !0o666 != 0
            || meta.mode & 0o022 != 0
            || meta.mode & 0o400 == 0
            || fs::symlink_metadata(&entry.path)?.gid() != 0
        {
            bail!("privilege component has incompatible native file custody");
        }
        if entry.kind == "grant_sudo_conf" {
            continue;
        }
        if entry.kind == "grant_policy" {
            policy(&read_bounded(&entry.path)?)?;
            continue;
        }
        let old = previous
            .as_ref()
            .context("privilege setup cannot overwrite unowned native integration files")?;
        let key = entry
            .kind
            .strip_prefix("grant_")
            .context("invalid privilege role")?;
        let candidate_owned = (entry.kind != "grant_sudoers"
            || old.plan.intent.activation == Activation::Transparent)
            && old.plan.grant_payload.get(key).is_some_and(|identity| {
                identity.length == meta.length && identity.sha256 == meta.sha256
            });
        let before_owned = old.documents.iter().any(|object| {
            object.current.kind == entry.kind
                && object.current.path == entry.path
                && object.current.identity.as_ref() == Some(meta)
        });
        if !candidate_owned && !before_owned {
            bail!("native privilege integration changed outside retained ownership");
        }
    }
    Ok(())
}

struct FileChange<'a> {
    file: &'a DesiredFile,
    before: &'a RetainedSetupObject,
    preparation: dev_tools_installation::DocumentDirectoryPreparation,
}

impl<'a> FileChange<'a> {
    fn new(file: &'a DesiredFile, before: &'a RetainedSetupObject) -> Result<Self> {
        if before.current.path != Path::new(file.path) {
            bail!("privilege file destination is outside retained authority");
        }
        let preparation = dev_tools_installation::DocumentDirectoryPreparation::observe(
            Path::new(file.path)
                .parent()
                .context("privilege file has no parent")?,
            0,
            0o755,
        )?;
        let selected = Self {
            file,
            before,
            preparation,
        };
        selected.observe()?;
        Ok(selected)
    }

    fn before_authority(&self) -> DocumentAuthority {
        let mut authority = self.file.authority();
        if let Some(meta) = &self.before.current.identity {
            authority.mode = meta.mode;
        }
        authority
    }

    fn name(&self) -> Result<&std::ffi::OsStr> {
        Path::new(self.file.path)
            .file_name()
            .context("privilege file has no name")
    }

    fn observe(
        &self,
    ) -> Result<Option<(dev_tools_installation::AtomicDocument, DocumentAuthority)>> {
        let before_authority = self.before_authority();
        if let Ok(Some(document)) = self.preparation.read_file(self.name()?, &before_authority) {
            if self.before.bytes.as_deref() == Some(document.bytes.as_slice()) {
                return Ok(Some((document, before_authority)));
            }
        }
        let authority = self.file.authority();
        let current = self.preparation.read_file(self.name()?, &authority)?;
        if current.as_ref().map(|document| document.bytes.as_slice()) == self.file.bytes.as_deref()
            || (current.is_none() && self.before.bytes.is_none())
        {
            return Ok(current.map(|document| (document, authority)));
        }
        bail!("privilege file changed outside the retained before/candidate pair")
    }

    fn apply(&self) -> Result<bool> {
        let current = self.observe()?;
        if current.is_none() && self.file.bytes.is_none() && self.before.bytes.is_none() {
            return Ok(false);
        }
        let (directory, created) = self.preparation.prepare()?;
        let changed = match (&self.file.bytes, current) {
            (Some(bytes), Some((current, authority))) => directory.replace_file(
                self.name()?,
                bytes,
                &self.file.authority(),
                &authority,
                &current.identity,
            )?,
            (Some(bytes), None) => {
                directory.write_file(self.name()?, bytes, &self.file.authority(), None)?
            }
            (None, Some((current, authority))) => {
                directory.remove_file(self.name()?, &authority, &current.identity)?
            }
            (None, None) => {
                let before = self
                    .before
                    .bytes
                    .as_deref()
                    .context("removed privilege file has no prior identity")?;
                directory.remove_file(self.name()?, &self.before_authority(), &identity(before))?
            }
        };
        Ok(changed || created)
    }

    fn restore(&self) -> Result<bool> {
        let current = self.observe()?;
        let parent = Path::new(self.file.path)
            .parent()
            .context("privilege file has no parent")?;
        let directory = match dev_tools_installation::ExistingDocumentDirectory::open(parent, 0) {
            Ok(directory) => directory,
            Err(error)
                if self.before.bytes.is_none()
                    && error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        match (&self.before.bytes, current) {
            (Some(bytes), Some((current, authority))) => directory.replace_file(
                self.name()?,
                bytes,
                &self.before_authority(),
                &authority,
                &current.identity,
            ),
            (Some(bytes), None) => {
                directory.write_file(self.name()?, bytes, &self.before_authority(), None)
            }
            (None, Some((current, authority))) => {
                directory.remove_file(self.name()?, &authority, &current.identity)
            }
            (None, None) => match &self.file.bytes {
                Some(bytes) => {
                    directory.remove_file(self.name()?, &self.file.authority(), &identity(bytes))
                }
                None => Ok(false),
            },
        }
    }

    fn verify_restored(&self) -> Result<()> {
        let current = self.observe()?;
        if current
            .as_ref()
            .map(|(document, _)| document.bytes.as_slice())
            != self.before.bytes.as_deref()
            || current
                .as_ref()
                .is_some_and(|(_, authority)| authority.mode != self.before_authority().mode)
        {
            bail!("privilege file restoration is incomplete");
        }
        Ok(())
    }
}

pub(super) fn stop(plan: &SetupPlanV3) -> Result<bool> {
    let generation = retained(plan)?;
    let document = prior(&generation, "grant_service")?;
    if let Some(meta) = &document.current.identity {
        let current =
            fs::read(SERVICE).context("owned privilege service definition is unavailable")?;
        if sha256_hex(&current) != meta.sha256 && current != assets::SERVICE.as_bytes() {
            bail!("privilege service shutdown has lost definition ownership");
        }
    } else if fs::symlink_metadata(SERVICE).is_ok() {
        if fs::read(SERVICE)? != assets::SERVICE.as_bytes() {
            bail!("unowned privilege service appeared");
        }
    } else if native::observe()?.loaded {
        bail!("unowned cached privilege service prevents setup");
    }
    if fs::symlink_metadata(SERVICE).is_ok() {
        native::reload()?;
    }
    native::stop()
}

pub(super) fn finish(
    plan: &SetupPlanV3,
    digest: &str,
    documents: &[RetainedCandidateDocument],
    before: String,
    mut actions: Vec<String>,
) -> Result<SetupApplyReportV3> {
    verify_retained_maintenance_policy(plan)?;
    apply_component(plan, documents, &mut actions)?;
    verify_postcondition(plan, digest, documents)?;
    crate::setup_transition::accept(&plan.installation.paths, 0, digest)?;
    Ok(SetupApplyReportV3 {
        schema: "dev-auth-setup-apply-v3".into(),
        changed: before != fingerprint(plan)?,
        verified: true,
        input_required: vec![],
        blocked: vec![],
        next_action: "none".into(),
        actions,
    })
}

pub(super) fn apply_component(
    plan: &SetupPlanV3,
    documents: &[RetainedCandidateDocument],
    actions: &mut Vec<String>,
) -> Result<()> {
    let generation = retained(plan)?;
    let files = desired_files(plan, documents)?;
    let changes = files
        .iter()
        .map(|file| FileChange::new(file, prior(&generation, file.kind)?))
        .collect::<Result<Vec<_>>>()?;
    if !native::observe()?.stopped {
        bail!("privilege files require a stopped coordinator");
    }
    crate::setup::restoration::require_grant_domain_empty()?;
    let own_current_rule = files.iter().zip(&changes).any(|(file, change)| {
        file.kind == "grant_sudoers"
            && change
                .observe()
                .ok()
                .flatten()
                .is_some_and(|(document, _)| document.bytes == assets::SUDOERS.as_bytes())
    });
    native::sudo_compatibility(plan.grant_previous_block.is_some() || own_current_rule)?;
    for change in &changes {
        change.apply()?;
        actions.push(format!("install_{}", change.file.kind));
    }
    drop(changes);
    native::reload()?;
    if plan.intent.activation == Activation::Transparent {
        native::activate()?;
    }
    verify(plan, documents)?;
    Ok(())
}

pub(super) fn fingerprint(plan: &SetupPlanV3) -> Result<String> {
    let mut identities = Vec::new();
    for path in paths().into_iter().map(|(_, _, path)| path).chain([
        installation_receipt_path(plan),
        crate::setup_transition::state_path(&plan.installation.paths),
    ]) {
        let value = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
            Ok(meta) => {
                if !meta.is_file() || meta.file_type().is_symlink() {
                    bail!("privilege state contains an unsupported object");
                }
                let bytes = read_bounded_at_with_empty(
                    &path,
                    LIBRARY_LIMIT,
                    "privilege state",
                    path == Path::new(SUDO_CONF),
                )?;
                Some((meta.mode() & 0o7777, identity(&bytes)))
            }
        };
        identities.push((path, value));
    }
    Ok(sha256_hex(&serde_jcs::to_vec(&(
        identities,
        native::observe()?,
    ))?))
}

pub(super) fn restore(generation: &RetainedSetupGeneration) -> Result<bool> {
    let files = desired_files(&generation.plan, &generation.candidate_documents)?;
    let changes = files
        .iter()
        .map(|file| FileChange::new(file, prior(generation, file.kind)?))
        .collect::<Result<Vec<_>>>()?;
    let mut changed = stop(&generation.plan)?;
    for kind in [
        "grant_sudoers",
        "grant_sudo_conf",
        "grant_service",
        "grant_action",
        "grant_policy",
        "grant_library",
    ] {
        let change = changes
            .iter()
            .find(|change| change.file.kind == kind)
            .context("privilege restoration inventory is incomplete")?;
        changed |= change.restore()?;
    }
    native::reload()?;
    let state = native::observe()?;
    if !state.stopped || state.enabled {
        bail!("restored privilege integration is not inactive");
    }
    for change in &changes {
        change.verify_restored()?;
    }
    Ok(changed)
}

pub(super) fn verify_restored(generation: &RetainedSetupGeneration) -> Result<()> {
    let files = desired_files(&generation.plan, &generation.candidate_documents)?;
    for file in &files {
        FileChange::new(file, prior(generation, file.kind)?)?.verify_restored()?;
    }
    let state = native::observe()?;
    if !state.stopped || state.enabled {
        bail!("privilege restoration has live activation");
    }
    crate::setup::restoration::require_grant_domain_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_uninstalled_planning_requires_fresh_withdrawal_proof() {
        let verified = std::cell::Cell::new(false);
        assert!(terminal_replacement_allowed(
            crate::setup_transition::Phase::UninstalledInactive,
            || {
                verified.set(true);
                Ok(())
            }
        )
        .unwrap());
        assert!(
            verified.get(),
            "returning no previous block must inspect current authority"
        );
        assert!(terminal_replacement_allowed(
            crate::setup_transition::Phase::UninstalledInactive,
            || { bail!("retained sudo or grant enforcement drift") }
        )
        .is_err());
        assert!(
            terminal_replacement_allowed(crate::setup_transition::Phase::Uninstalling, || {
                panic!("incomplete uninstall cannot ask for terminal authority")
            })
            .is_err()
        );
        assert!(
            !terminal_replacement_allowed(crate::setup_transition::Phase::Accepted, || {
                panic!("accepted grant ownership follows the existing branch")
            })
            .unwrap()
        );
    }

    #[test]
    fn terminal_native_base_keeps_unrelated_bytes_and_does_not_restore_previous_grants() {
        let native = b"# unrelated native sudo configuration without newline";
        let old = block(
            Path::new("/usr/local/lib/dev-auth/versions/0.5.0/dev-auth"),
            false,
        )
        .unwrap();
        let old_conf = render_sudo_conf(native, None, Some(&old)).unwrap();
        let retained_old_block = old_conf[native.len()..].to_vec();
        let native_base = render_sudo_conf(&old_conf, Some(&retained_old_block), None).unwrap();
        assert_eq!(native_base, native);
        assert!(
            render_sudo_conf(&old_conf, None, None).is_err(),
            "a no-grants terminal cannot adopt a recognized old block"
        );
        assert_eq!(render_sudo_conf(&native_base, None, None).unwrap(), native);
    }

    #[test]
    fn bridge_removal_restores_an_original_file_without_a_final_newline() {
        let before = b"# native configuration without newline";
        let desired = block(
            Path::new("/usr/local/lib/dev-auth/versions/0.5.0/dev-auth"),
            false,
        )
        .unwrap();
        let after = render_sudo_conf(before, None, Some(&desired)).unwrap();
        let owned = &after[before.len()..];
        assert!(owned.starts_with(b"\n"));
        assert_eq!(render_sudo_conf(&after, Some(owned), None).unwrap(), before);
        check_sudoers_export(
            br#"{"Command_Aliases":{"SAFE":[{"command":"/usr/bin/true"}]},"User_Specs":[]}"#,
            false,
        )
        .unwrap();
    }

    #[test]
    fn sudo_merge_preserves_unrelated_bytes_and_requires_retained_block_ownership() {
        let before = b"# native settings\nPath askpass /usr/bin/native-askpass\n";
        let executable = Path::new("/usr/local/lib/dev-auth/versions/0.5.0/dev-auth");
        let plain = block(executable, false).unwrap();
        let rendered = render_sudo_conf(before, None, Some(&plain)).unwrap();
        assert!(rendered.starts_with(before));
        let owned = block(executable, true).unwrap();
        assert!(rendered.ends_with(&owned));
        assert_eq!(
            render_sudo_conf(&rendered, Some(&owned), None).unwrap(),
            before
        );
        assert!(render_sudo_conf(&rendered, None, None).is_err());
        let mut changed = rendered.clone();
        changed.extend_from_slice(END);
        assert!(render_sudo_conf(&changed, Some(&owned), None).is_err());
    }

    #[test]
    fn explicit_native_plugins_are_unchanged_and_not_duplicated() {
        let before =
            b"Plugin sudoers_policy sudoers.so\nPlugin independent_audit /usr/lib/audit.so\n";
        let own = block(
            Path::new("/usr/local/lib/dev-auth/versions/0.5.0/dev-auth"),
            false,
        )
        .unwrap();
        let rendered = render_sudo_conf(before, None, Some(&own)).unwrap();
        assert_eq!(rendered, [before.as_slice(), own.as_slice()].concat());
        assert_eq!(
            render_sudo_conf(&rendered, Some(&own), Some(&own)).unwrap(),
            rendered
        );
    }

    #[test]
    fn native_group_plugin_cannot_be_silently_replaced() {
        assert!(check_sudoers_export(
            br#"{"Defaults":[{"Options":[{"group_plugin":"/independent.so"}]}]}"#,
            false
        )
        .is_err());
        let owned = serde_json::to_vec(
            &serde_json::json!({"Defaults":[{"Options":[{"group_plugin":LIBRARY}]}]}),
        )
        .unwrap();
        assert!(check_sudoers_export(&owned, false).is_err());
        check_sudoers_export(&owned, true).unwrap();
        check_sudoers_export(br#"{"User_Specs":[]}"#, false).unwrap();
        assert!(check_sudoers_export(br#"{"unknown_defaults":[]}"#, false).is_err());
    }
}
