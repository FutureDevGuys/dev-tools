//! A product-owned native sudo plugin, loaded only through root-owned sudo
//! configuration. It never reads user input, handles a password, parses
//! command options, executes a shell, or makes a cached timestamp authoritative.
//! Its only terminal output is one line that explains a refusal.

#![deny(unsafe_op_in_unsafe_fn)]

include!(concat!(env!("OUT_DIR"), "/dev-auth-sudo-abi.rs"));

// SAFETY: one immutable exported build-identity symbol belongs to this helper.
// The outer signed product embeds these exact bytes, not an ambient library.
#[used]
#[no_mangle]
pub static DEV_AUTH_SUDO_BUILD_ID: &str = concat!(
    "dev-auth-sudo-build-v2:",
    env!("CARGO_PKG_VERSION"),
    ":",
    env!("DEV_TOOLS_GIT_COMMIT"),
    ":",
    env!("DEV_TOOLS_BUILD_TARGET"),
    ":",
    env!("DEV_AUTH_SUDO_ABI_ID"),
    ":end"
);

#[cfg(target_os = "linux")]
mod abi;
#[cfg(target_os = "linux")]
mod native;
#[cfg(target_os = "linux")]
#[path = "../../dev-auth/src/privilege/grants/native_text.rs"]
#[allow(dead_code)] // Each component uses the corresponding half of the same codec.
mod native_text;
#[cfg(target_os = "linux")]
#[path = "../../dev-auth/src/privilege/grants/packet.rs"]
mod packet;
#[cfg(target_os = "linux")]
#[path = "../../dev-auth/src/privilege/grants/sudo_wire.rs"]
mod sudo_wire;

#[cfg(target_os = "linux")]
#[path = "../../dev-auth/src/strict_serde.rs"]
mod strict_serde;
