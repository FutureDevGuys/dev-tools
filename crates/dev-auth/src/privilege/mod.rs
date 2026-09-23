//! Product-owned administrator grants. Native transports authenticate callers;
//! serialized selectors and observations never carry execution authority.

mod client;
mod model;
mod native_text;
pub mod policy;

pub use client::control;
pub use model::{
    parse_duration, Authority, ControlRequest, ControlResult, Execution, Failure, Grant,
    GrantRequest, GrantScope, GrantState, RESULT_SCHEMA,
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

pub const SYSTEM_SOCKET: &str = "/run/dev-auth-privilege/control.sock";
pub const SYSTEM_POLICY: &str = "/etc/dev-auth/privilege-policy.json";
