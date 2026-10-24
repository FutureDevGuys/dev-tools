//! Product-owned administrator grants. Native transports authenticate callers;
//! serialized selectors and observations never carry execution authority.

mod cli_spec;
mod client;
mod model;
mod native_text;
pub mod policy;

pub use cli_spec::{direct_specification, specification, DirectGrantCommand};
pub use client::{control, run_program};
pub use model::{
    parse_duration, Authority, ControlRequest, ControlResult, Execution, Failure, Grant,
    GrantRequest, GrantRequirement, GrantScope, GrantState, OutputCounts, OutputObservation,
    RESULT_SCHEMA,
};

#[cfg(target_os = "linux")]
pub(crate) mod transport;

#[cfg(target_os = "linux")]
mod approval;
#[cfg(target_os = "linux")]
pub mod assets;
#[cfg(target_os = "linux")]
mod execution_io;
#[cfg(target_os = "linux")]
mod graph;
#[cfg(target_os = "linux")]
mod native;
#[cfg(target_os = "linux")]
mod output;
#[cfg(target_os = "linux")]
mod packet;
#[cfg(target_os = "linux")]
pub mod service;
#[cfg(target_os = "linux")]
mod sudo_wire;
#[cfg(target_os = "linux")]
mod tty_agent;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use graph::run_worker as run_plan_worker;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use output::run_worker as run_output_relay;
#[cfg(target_os = "linux")]
pub(crate) use tty_agent::TtyAgent;

/// How long stopped managed work has to end: the fixed grace before SIGKILL
/// and five seconds of cleanup (ADR 0141). The coordinator waits this long
/// before it reports a cleanup failure, so its clients wait longer.
#[cfg(target_os = "linux")]
pub(crate) const STOP_SETTLE: std::time::Duration =
    dev_tools_privilege_session::linux::TERMINATION_GRACE
        .saturating_add(std::time::Duration::from_secs(5));

pub const SYSTEM_SOCKET: &str = "/run/dev-auth-grants/control.sock";
pub const SYSTEM_POLICY: &str = "/etc/dev-auth/administrator-grants-v1.json";

#[cfg(target_os = "linux")]
pub(crate) use client::activate_bootstrap;
