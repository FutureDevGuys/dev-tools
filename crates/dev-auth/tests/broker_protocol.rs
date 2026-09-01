use dev_auth::broker_protocol::{
    decide_routing, decode_request_frame, decode_response_frame, encode_request_frame,
    encode_response_frame, BrokerRequest, BrokerRequestEnvelope, BrokerResponse,
    BrokerResponseEnvelope, BrokerSessionProbe, LocalSessionClaim, RoutingDecision,
    SensitiveString, BROKER_PROTOCOL_VERSION, MAX_BROKER_FRAME_BYTES,
};

#[test]
fn only_explicit_absence_can_route_to_native_tools() {
    assert_eq!(
        decide_routing(&LocalSessionClaim::Absent, BrokerSessionProbe::NoSession),
        RoutingDecision::NativePassthrough
    );

    for decision in [
        decide_routing(
            &LocalSessionClaim::Present {
                marker: "root-owned-session".into(),
            },
            BrokerSessionProbe::NoSession,
        ),
        decide_routing(
            &LocalSessionClaim::Present {
                marker: "root-owned-session".into(),
            },
            BrokerSessionProbe::Invalid {
                reason: "expired session".into(),
            },
        ),
        decide_routing(
            &LocalSessionClaim::Present {
                marker: "root-owned-session".into(),
            },
            BrokerSessionProbe::Unavailable {
                reason: "broker unavailable".into(),
            },
        ),
        decide_routing(
            &LocalSessionClaim::Absent,
            BrokerSessionProbe::Verified {
                session_id: "session".into(),
                workload: "codex".into(),
                profile: "automation".into(),
            },
        ),
    ] {
        assert!(matches!(decision, RoutingDecision::Deny { .. }));
    }
}

#[test]
fn verified_claim_routes_to_broker_session() {
    assert_eq!(
        decide_routing(
            &LocalSessionClaim::Present {
                marker: "root-owned-session".into(),
            },
            BrokerSessionProbe::Verified {
                session_id: "session".into(),
                workload: "codex".into(),
                profile: "automation".into(),
            }
        ),
        RoutingDecision::BrokerSession {
            session_id: "session".into(),
            workload: "codex".into(),
            profile: "automation".into(),
        }
    );
}

#[test]
fn request_frames_are_bounded_versioned_and_closed() {
    let valid = br#"{"version":1,"request_id":"0123456789abcdef0123456789abcdef","request":{"operation":"git_credential","protocol":"https","host":"github.com","owner":"ExampleOrg","repository":"repo"}}"#;
    let decoded = decode_request_frame(valid).unwrap();
    assert_eq!(decoded.version, BROKER_PROTOCOL_VERSION);

    for invalid in [
        br#"{"version":2,"request_id":"0123456789abcdef0123456789abcdef","request":{"operation":"probe"}}"#.as_slice(),
        br#"{"version":1,"request_id":"short","request":{"operation":"probe"}}"#.as_slice(),
        br#"{"version":1,"request_id":"0123456789abcdef0123456789abcdef","unknown":true,"request":{"operation":"probe"}}"#.as_slice(),
        br#"{"version":1,"request_id":"0123456789abcdef0123456789abcdef","request":{"operation":"git_credential","protocol":"http","host":"github.com","owner":"ExampleOrg","repository":"repo"}}"#.as_slice(),
    ] {
        assert!(decode_request_frame(invalid).is_err());
    }

    assert!(decode_request_frame(&vec![b'x'; MAX_BROKER_FRAME_BYTES + 1]).is_err());
}

#[test]
fn secret_responses_are_redacted_but_wire_serializable() {
    let token = "credential-sentinel";
    let sensitive = SensitiveString::new(token.into());
    assert_eq!(format!("{sensitive:?}"), "<redacted>");
    assert_eq!(sensitive.to_string(), "<redacted>");

    let response = BrokerResponseEnvelope {
        version: BROKER_PROTOCOL_VERSION,
        request_id: "0123456789abcdef0123456789abcdef".into(),
        response: BrokerResponse::GhExecutionToken {
            token: sensitive,
            expires_at: "2030-01-01T00:00:00Z".into(),
        },
    };
    let wire = encode_response_frame(&response).unwrap();
    assert!(std::str::from_utf8(&wire).unwrap().contains(token));
    assert!(!format!("{response:?}").contains(token));
}

#[test]
fn broker_protocol_has_no_generic_secret_export_operation() {
    let generic_export = br#"{"version":1,"request_id":"0123456789abcdef0123456789abcdef","request":{"operation":"export_token","owner":"ExampleOrg","repository":"repo"}}"#;
    assert!(decode_request_frame(generic_export).is_err());
}

#[test]
fn request_and_response_round_trip_with_exact_correlation() {
    let request = BrokerRequestEnvelope {
        version: BROKER_PROTOCOL_VERSION,
        request_id: "0123456789abcdef0123456789abcdef".into(),
        request: BrokerRequest::Probe,
    };
    assert_eq!(
        decode_request_frame(&encode_request_frame(&request).unwrap()).unwrap(),
        request
    );

    let response = BrokerResponseEnvelope {
        version: BROKER_PROTOCOL_VERSION,
        request_id: request.request_id.clone(),
        response: BrokerResponse::NoSession,
    };
    assert_eq!(
        decode_response_frame(&encode_response_frame(&response).unwrap()).unwrap(),
        response
    );
}

#[test]
fn responses_reject_malformed_secrets_lifetimes_and_public_diagnostics() {
    let request_id = "0123456789abcdef0123456789abcdef".to_owned();
    for response in [
        BrokerResponse::GhExecutionToken {
            token: SensitiveString::new("token\nleak".into()),
            expires_at: "2026-09-01T00:00:00Z".into(),
        },
        BrokerResponse::GitCredential {
            username: "human-user".into(),
            password: SensitiveString::new("token".into()),
            expires_at: "2026-09-01T00:00:00Z".into(),
        },
        BrokerResponse::Denied {
            code: "Internal Error".into(),
            message: "/secret/internal/path".into(),
        },
        BrokerResponse::Ready {
            session_id: request_id.clone(),
            workload: "codex".into(),
            profile: "automation".into(),
            expires_at: "not-a-time".into(),
        },
    ] {
        assert!(encode_response_frame(&BrokerResponseEnvelope {
            version: BROKER_PROTOCOL_VERSION,
            request_id: request_id.clone(),
            response,
        })
        .is_err());
    }
}
