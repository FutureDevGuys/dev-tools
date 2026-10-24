//! Private coordination between receipt-matched components of one product.
//! Message selectors are not authority; the server authenticates native sudo
//! before using its original-account and post-policy command observations.

use serde::{Deserialize, Serialize};
use std::ffi::OsString;

pub(crate) const SUDO_SCHEMA: &str = "dev-auth-sudo-bridge-v1";
pub(crate) const SUDO_HELLO: &[u8; 8] = b"DVSUDO1\0";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Message {
    pub schema: String,
    pub request: Request,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Request {
    Preflight {
        uid: u32,
    },
    Admit {
        #[serde(with = "super::native_text::sequence")]
        command_info: Vec<OsString>,
        #[serde(with = "super::native_text::sequence")]
        arguments: Vec<OsString>,
        #[serde(with = "super::native_text::sequence")]
        environment: Vec<OsString>,
    },
    #[serde(deserialize_with = "crate::strict_serde::empty_variant")]
    Attached,
    #[serde(deserialize_with = "crate::strict_serde::empty_variant")]
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Decision {
    Native,
    Managed,
    Relay,
    Attached,
    Denied,
    Unavailable,
    /// The coordinator drains and admits no new sudo through a grant that
    /// routes this invocation (ADR 0141).
    Draining,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Response {
    pub schema: String,
    pub decision: Decision,
    pub hard_deadline_milliseconds: u64,
    #[serde(default)]
    pub grant: Option<String>,
}
