//! Closed, test-only inputs. These never create a product authorization route.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Case {
    Reuse,
    Revoke,
    HardExpiry,
    IdleExpiry,
    NearIdleAdmission,
    CoordinatorDeath,
    BootstrapDeath,
    HandoffBootstrapDeath,
    ControllerGateBootstrapDeath,
    GuardianDeath,
    MalformedIpc,
    IdentityDenial,
    PolicyReplaced,
    HelperReplaced,
    ResourceReplaced,
    Busy,
    Replay,
    Exhaustion,
    BlockedIo,
    SetupExclusion,
    CleanupFailure,
    SignalFidelity,
    LeaderExit,
    NestedResourceMount,
    CoreCollector,
    CoreCoordinatorDeath,
    CoreBootstrapDeath,
}
impl Case {
    pub fn name(self) -> String {
        serde_json::to_value(self)
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned()
    }
    pub fn needs_fault_driver(self) -> bool {
        matches!(
            self,
            Self::CoordinatorDeath
                | Self::BootstrapDeath
                | Self::HandoffBootstrapDeath
                | Self::ControllerGateBootstrapDeath
                | Self::NestedResourceMount
                | Self::CoreCollector
                | Self::CoreCoordinatorDeath
                | Self::CoreBootstrapDeath
                | Self::GuardianDeath
                | Self::PolicyReplaced
                | Self::HelperReplaced
                | Self::SetupExclusion
                | Self::CleanupFailure
        )
    }
    pub fn needs_heartbeat(self) -> bool {
        matches!(
            self,
            Self::Revoke
                | Self::CoreCoordinatorDeath
                | Self::CoreBootstrapDeath
                | Self::HardExpiry
                | Self::CoordinatorDeath
                | Self::BootstrapDeath
                | Self::GuardianDeath
                | Self::PolicyReplaced
                | Self::HelperReplaced
                | Self::SetupExclusion
                | Self::CleanupFailure
                | Self::BlockedIo
        )
    }
    pub fn completes_normally(self) -> bool {
        matches!(
            self,
            Self::Reuse
                | Self::MalformedIpc
                | Self::IdentityDenial
                | Self::Busy
                | Self::Replay
                | Self::SignalFidelity
                | Self::LeaderExit
                | Self::NestedResourceMount
                | Self::CoreCollector
        )
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub schema: String,
    pub dev_auth: PathBuf,
    pub fixture_binary: PathBuf,
    pub fixture_root: PathBuf,
    pub approval_plan: PathBuf,
    pub approval_sha256: String,
    pub case: Case,
}
