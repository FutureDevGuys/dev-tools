//! Canonical one-shot authorization transport for strong setup apply.
//!
//! This module turns validated, public setup inputs into one exact native
//! helper invocation. It does not parse setup plans, handle credential values,
//! cache elevation, or expose a general privileged command surface.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Result};
#[cfg(target_os = "linux")]
use dev_tools_privilege::{
    ExactHelperRequest, PrivilegeAuthorizer, PrivilegeOutcome, ProcessTermination, StdioPolicy,
    UnavailableReason, UserInteraction,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupApplyFormat {
    Human,
    Json,
}

impl SetupApplyFormat {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "human" => Ok(Self::Human),
            "json" => Ok(Self::Json),
            _ => bail!("setup apply format must be human or json"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Json => "json",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupApplyCredentialSource {
    Stdin,
    File(PathBuf),
    /// Kept explicit so callers cannot accidentally forward an inherited file
    /// descriptor across the sudo process boundary.
    FileDescriptor(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupApplyCredentialInput {
    slot: String,
    source: SetupApplyCredentialSource,
}

impl SetupApplyCredentialInput {
    pub fn stdin(slot: impl Into<String>) -> Self {
        Self {
            slot: slot.into(),
            source: SetupApplyCredentialSource::Stdin,
        }
    }

    pub fn file(slot: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            slot: slot.into(),
            source: SetupApplyCredentialSource::File(path.into()),
        }
    }

    pub fn file_descriptor(slot: impl Into<String>, descriptor: i32) -> Self {
        Self {
            slot: slot.into(),
            source: SetupApplyCredentialSource::FileDescriptor(descriptor),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrongSetupApplyAuthorization {
    plan: PathBuf,
    sha256: String,
    format: SetupApplyFormat,
    credentials: BTreeMap<String, CanonicalCredentialSource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CanonicalCredentialSource {
    Stdin,
    File(PathBuf),
}

impl StrongSetupApplyAuthorization {
    pub fn new(
        plan: impl Into<PathBuf>,
        sha256: impl AsRef<str>,
        format: &str,
        credentials: impl IntoIterator<Item = SetupApplyCredentialInput>,
    ) -> Result<Self> {
        let plan = plan.into();
        validate_normalized_absolute_path(&plan, "setup plan")?;
        let sha256 = normalize_sha256(sha256.as_ref())?;
        let format = SetupApplyFormat::parse(format)?;
        let mut canonical_credentials = BTreeMap::new();
        let mut stdin_count = 0_usize;
        for credential in credentials {
            if credential.slot.is_empty() || credential.slot.contains('=') {
                bail!("credential slot must be nonempty and unambiguous");
            }
            let source = match credential.source {
                SetupApplyCredentialSource::Stdin => {
                    stdin_count += 1;
                    CanonicalCredentialSource::Stdin
                }
                SetupApplyCredentialSource::File(path) => {
                    validate_normalized_absolute_path(&path, "credential file")?;
                    CanonicalCredentialSource::File(path)
                }
                SetupApplyCredentialSource::FileDescriptor(_) => {
                    bail!("sudo setup authorization does not accept credential file descriptors")
                }
            };
            if canonical_credentials
                .insert(credential.slot, source)
                .is_some()
            {
                bail!("credential input slot was defined more than once");
            }
        }
        if stdin_count > 1 {
            bail!("sudo setup authorization accepts at most one standard-input credential");
        }
        Ok(Self {
            plan,
            sha256,
            format,
            credentials: canonical_credentials,
        })
    }

    pub fn plan(&self) -> &Path {
        &self.plan
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn format(&self) -> SetupApplyFormat {
        self.format
    }

    pub fn native_arguments(&self) -> Vec<OsString> {
        let mut arguments = vec![
            OsString::from("apply-v3"),
            OsString::from("--plan"),
            self.plan.clone().into_os_string(),
            OsString::from("--sha256"),
            OsString::from(&self.sha256),
        ];
        for (slot, source) in &self.credentials {
            match source {
                CanonicalCredentialSource::Stdin => {
                    arguments.push(OsString::from("--credential-stdin"));
                    arguments.push(OsString::from(slot));
                }
                CanonicalCredentialSource::File(path) => {
                    let mut value = OsString::from(slot);
                    value.push("=");
                    value.push(path.as_os_str());
                    arguments.push(OsString::from("--credential-file"));
                    arguments.push(value);
                }
            }
        }
        arguments.push(OsString::from("--format"));
        arguments.push(OsString::from(self.format.as_str()));
        arguments
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(target_os = "linux")]
pub enum StrongSetupApplyAuthorizationOutcome {
    HelperExited(ProcessTermination),
    AuthorizationNotCompleted,
    Unavailable(UnavailableReason),
}

#[cfg(target_os = "linux")]
pub fn authorize_strong_apply_with<A: PrivilegeAuthorizer + ?Sized>(
    authorizer: &A,
    request: &StrongSetupApplyAuthorization,
) -> Result<StrongSetupApplyAuthorizationOutcome> {
    let arguments = request.native_arguments();
    let outcome = authorizer.authorize_and_run_exact_helper(&ExactHelperRequest {
        helper: crate::setup::setup_helper_path(),
        arguments: &arguments,
        deadline: None,
        interaction: UserInteraction::Allowed,
        stdio: StdioPolicy::Inherit,
    })?;
    Ok(match outcome {
        PrivilegeOutcome::Exited(termination) => {
            StrongSetupApplyAuthorizationOutcome::HelperExited(termination)
        }
        PrivilegeOutcome::Denied | PrivilegeOutcome::Cancelled | PrivilegeOutcome::TimedOut => {
            StrongSetupApplyAuthorizationOutcome::AuthorizationNotCompleted
        }
        PrivilegeOutcome::Unavailable(reason) => {
            StrongSetupApplyAuthorizationOutcome::Unavailable(reason)
        }
    })
}

fn normalize_sha256(value: &str) -> Result<String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("setup plan SHA-256 must contain exactly 64 hexadecimal characters");
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_normalized_absolute_path(path: &Path, description: &str) -> Result<()> {
    if !path.is_absolute() {
        bail!("{description} path must be absolute and normalized");
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        if !matches!(
            component,
            Component::RootDir | Component::Prefix(_) | Component::Normal(_)
        ) {
            bail!("{description} path must be absolute and normalized");
        }
        normalized.push(component.as_os_str());
    }
    if normalized.as_os_str() != path.as_os_str() {
        bail!("{description} path must be absolute and normalized");
    }
    Ok(())
}
