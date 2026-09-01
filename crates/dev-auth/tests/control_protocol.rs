#![cfg(target_os = "linux")]

use dev_auth::broker_protocol::BROKER_PROTOCOL_VERSION;
use dev_auth::control_protocol::{
    decode_control_request, decode_control_response, encode_control_request,
    encode_control_response, ControlEnvelope, ControlRequest, ControlResponse,
    ControlResponseEnvelope,
};
use dev_auth::linux_admission::{SessionAuthorityGrant, SessionRegistration};

fn registration() -> SessionRegistration {
    SessionRegistration {
        session_id: "0123456789abcdef0123456789abcdef".into(),
        owner_uid: 1000,
        workload: "codex".into(),
        profile: "automation".into(),
        authority: SessionAuthorityGrant {
            github: None,
            signing: None,
            ssh: Vec::new(),
        },
        cgroup:
            "/sys/fs/cgroup/dev-auth-workloads.slice/session-0123456789abcdef0123456789abcdef.scope"
                .into(),
        expires_at_unix: 2_000_000_000,
    }
}

#[test]
fn supervisor_control_frames_are_closed_bounded_and_correlated() {
    let request = ControlEnvelope {
        version: BROKER_PROTOCOL_VERSION,
        request_id: "abcdef0123456789abcdef0123456789".into(),
        request: ControlRequest::Register {
            session: Box::new(registration()),
        },
    };
    let encoded = encode_control_request(&request).unwrap();
    let decoded = decode_control_request(&encoded).unwrap();
    assert_eq!(decoded.request_id, request.request_id);
    assert!(matches!(decoded.request, ControlRequest::Register { .. }));

    let response = ControlResponseEnvelope {
        version: BROKER_PROTOCOL_VERSION,
        request_id: request.request_id,
        response: ControlResponse::Accepted,
    };
    let encoded = encode_control_response(&response).unwrap();
    assert_eq!(
        decode_control_response(&encoded).unwrap().response,
        ControlResponse::Accepted
    );

    let mut unknown = serde_json::to_value(&response).unwrap();
    unknown["unknown"] = serde_json::json!(true);
    assert!(decode_control_response(&serde_json::to_vec(&unknown).unwrap()).is_err());
}

#[test]
fn control_protocol_rejects_invalid_identifiers_and_denial_text() {
    let invalid = ControlEnvelope {
        version: BROKER_PROTOCOL_VERSION,
        request_id: "not-an-id".into(),
        request: ControlRequest::Revoke {
            session_id: "0123456789abcdef0123456789abcdef".into(),
        },
    };
    assert!(encode_control_request(&invalid).is_err());

    let invalid = ControlResponseEnvelope {
        version: BROKER_PROTOCOL_VERSION,
        request_id: "abcdef0123456789abcdef0123456789".into(),
        response: ControlResponse::Denied {
            message: "unsafe\nmessage".into(),
        },
    };
    assert!(encode_control_response(&invalid).is_err());
}
