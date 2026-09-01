use crate::broker_protocol::{BROKER_PROTOCOL_VERSION, MAX_BROKER_FRAME_BYTES};
use crate::linux_admission::SessionRegistration;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlEnvelope {
    pub version: u32,
    pub request_id: String,
    pub request: ControlRequest,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ControlRequest {
    Register {
        session: Box<SessionRegistration>,
    },
    Renew {
        session_id: String,
        expires_at_unix: i64,
    },
    Revoke {
        session_id: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlResponseEnvelope {
    pub version: u32,
    pub request_id: String,
    pub response: ControlResponse,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ControlResponse {
    Accepted,
    Revoked { existed: bool },
    Denied { message: String },
}

pub fn encode_control_request(request: &ControlEnvelope) -> Result<Vec<u8>> {
    validate_control_request(request)?;
    bounded_json(request, "control request")
}

pub fn decode_control_request(input: &[u8]) -> Result<ControlEnvelope> {
    if input.len() > MAX_BROKER_FRAME_BYTES {
        bail!("control request exceeds the frame limit");
    }
    let request = serde_json::from_slice(input).context("parse control request")?;
    validate_control_request(&request)?;
    Ok(request)
}

pub fn encode_control_response(response: &ControlResponseEnvelope) -> Result<Vec<u8>> {
    validate_control_response(response)?;
    bounded_json(response, "control response")
}

pub fn decode_control_response(input: &[u8]) -> Result<ControlResponseEnvelope> {
    if input.len() > MAX_BROKER_FRAME_BYTES {
        bail!("control response exceeds the frame limit");
    }
    let response = serde_json::from_slice(input).context("parse control response")?;
    validate_control_response(&response)?;
    Ok(response)
}

fn validate_control_request(request: &ControlEnvelope) -> Result<()> {
    if request.version != BROKER_PROTOCOL_VERSION {
        bail!("control request protocol version is unsupported");
    }
    validate_control_identifier(&request.request_id, "control request identifier")?;
    match &request.request {
        ControlRequest::Register { session } => {
            validate_control_identifier(&session.session_id, "session identifier")
        }
        ControlRequest::Renew {
            session_id,
            expires_at_unix,
        } => {
            validate_control_identifier(session_id, "session identifier")?;
            if *expires_at_unix <= 0 {
                bail!("session renewal expiry is invalid");
            }
            Ok(())
        }
        ControlRequest::Revoke { session_id } => {
            validate_control_identifier(session_id, "session identifier")
        }
    }
}

fn validate_control_response(response: &ControlResponseEnvelope) -> Result<()> {
    if response.version != BROKER_PROTOCOL_VERSION {
        bail!("control response protocol version is unsupported");
    }
    validate_control_identifier(&response.request_id, "control response identifier")?;
    if let ControlResponse::Denied { message } = &response.response {
        if message.is_empty()
            || message.len() > 512
            || message
                .chars()
                .any(|character| character.is_control() && character != '\t')
        {
            bail!("control denial message is invalid");
        }
    }
    Ok(())
}

fn validate_control_identifier(value: &str, description: &str) -> Result<()> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{description} is invalid");
    }
    Ok(())
}

fn bounded_json<T: Serialize>(value: &T, description: &str) -> Result<Vec<u8>> {
    let output = serde_json::to_vec(value).with_context(|| format!("serialize {description}"))?;
    if output.len() > MAX_BROKER_FRAME_BYTES {
        bail!("{description} exceeds the frame limit");
    }
    Ok(output)
}
