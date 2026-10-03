use dev_auth::broker_protocol::{
    decide_routing, decode_request_frame, decode_response_frame, encode_request_frame,
    encode_response_frame, BrokerRequest, BrokerRequestEnvelope, BrokerResponse,
    BrokerResponseEnvelope, BrokerSessionProbe, LocalSessionClaim, RoutingDecision,
    SensitiveString, BROKER_PROTOCOL_VERSION, MAX_BROKER_FRAME_BYTES,
};

#[test]
fn provider_validation_has_no_caller_selected_authority_and_returns_only_counts() {
    let request = serde_json::json!({
        "version": BROKER_PROTOCOL_VERSION,
        "request_id": "0123456789abcdef0123456789abcdef",
        "request": {"operation": "validate_providers"}
    });
    let decoded = decode_request_frame(&serde_json::to_vec(&request).unwrap()).unwrap();
    assert_eq!(decoded.request, BrokerRequest::ValidateProviders);
    for field in ["resource", "reference", "slot", "token", "user"] {
        let mut invalid = request.clone();
        invalid["request"][field] = "caller-selected".into();
        assert!(decode_request_frame(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    let response = BrokerResponseEnvelope {
        version: BROKER_PROTOCOL_VERSION,
        request_id: "0123456789abcdef0123456789abcdef".into(),
        response: BrokerResponse::ProviderValidation {
            authentication_checked: 1,
            authentication_total: 2,
            resources_checked: 1,
            resources_total: 2,
            keys_checked: 1,
            keys_failed: 0,
            keys_total: 2,
        },
    };
    let frame = encode_response_frame(&response).unwrap();
    assert_eq!(decode_response_frame(&frame).unwrap(), response);
    let mut invalid = response;
    invalid.response = BrokerResponse::ProviderValidation {
        authentication_checked: 1,
        authentication_total: 2,
        resources_checked: 3,
        resources_total: 2,
        keys_checked: 1,
        keys_failed: 0,
        keys_total: 2,
    };
    assert!(encode_response_frame(&invalid).is_err());
    invalid.response = BrokerResponse::ProviderValidation {
        authentication_checked: 3,
        authentication_total: 2,
        resources_checked: 2,
        resources_total: 2,
        keys_checked: 1,
        keys_failed: 0,
        keys_total: 2,
    };
    assert!(encode_response_frame(&invalid).is_err());
    assert!(decode_response_frame(&serde_json::to_vec(&invalid).unwrap()).is_err());
    for (checked, failed, total) in [(1, 1, 1), (u32::MAX, 1, u32::MAX)] {
        invalid.response = BrokerResponse::ProviderValidation {
            authentication_checked: 1,
            authentication_total: 1,
            resources_checked: 1,
            resources_total: 1,
            keys_checked: checked,
            keys_failed: failed,
            keys_total: total,
        };
        assert!(encode_response_frame(&invalid).is_err());
        assert!(decode_response_frame(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
}

#[test]
fn logical_secret_requests_accept_names_but_not_provider_references() {
    for operation in ["secret_read", "secret_public"] {
        let frame = serde_json::json!({
            "version": BROKER_PROTOCOL_VERSION,
            "request_id": "0123456789abcdef0123456789abcdef",
            "request": {"operation": operation, "resource": "build-token"}
        });
        assert!(decode_request_frame(&serde_json::to_vec(&frame).unwrap()).is_ok());
        for invalid in ["op://vault/item/field", "", "../token"] {
            let mut rejected = frame.clone();
            rejected["request"]["resource"] = invalid.into();
            assert!(decode_request_frame(&serde_json::to_vec(&rejected).unwrap()).is_err());
        }
    }
}

#[test]
fn binary_secret_responses_are_bounded_and_redacted() {
    use base64::Engine;
    let bytes = vec![255u8; 64 * 1024];
    let value = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let frame = serde_json::json!({
        "version": BROKER_PROTOCOL_VERSION,
        "request_id": "0123456789abcdef0123456789abcdef",
        "response": {"status": "secret_material", "material": value}
    });
    let decoded = decode_response_frame(&serde_json::to_vec(&frame).unwrap()).unwrap();
    assert!(!format!("{decoded:?}").contains(&value));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encode_response_frame(&decoded).unwrap())
            .unwrap(),
        frame
    );
    let mut oversized = frame;
    oversized["response"]["material"] = base64::engine::general_purpose::STANDARD
        .encode(vec![0; 64 * 1024 + 1])
        .into();
    assert!(decode_response_frame(&serde_json::to_vec(&oversized).unwrap()).is_err());
}

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
                owner_uid: 1000,
                execution_uid: 991,
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
                owner_uid: 1000,
                execution_uid: 991,
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
fn request_operations_reject_unknown_fields_before_authority_dispatch() {
    for request in [
        serde_json::json!({"operation": "probe"}),
        serde_json::json!({"operation": "gh_execution_token"}),
        serde_json::json!({"operation": "renew_session", "session_id": "0123456789abcdef0123456789abcdef"}),
        serde_json::json!({"operation": "git_credential", "protocol": "https", "host": "github.com", "owner": "ExampleOrg", "repository": "repo"}),
    ] {
        let mut frame = serde_json::json!({"version": BROKER_PROTOCOL_VERSION, "request_id": "0123456789abcdef0123456789abcdef", "request": request});
        let valid = serde_json::to_vec(&frame).unwrap();
        let decoded = decode_request_frame(&valid).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&encode_request_frame(&decoded).unwrap())
                .unwrap(),
            frame
        );
        frame["request"]["purported_scope"] = serde_json::json!({"repository": "narrower"});
        assert!(decode_request_frame(&serde_json::to_vec(&frame).unwrap()).is_err());
    }
}

#[test]
fn request_frames_are_bounded_versioned_and_closed() {
    assert_eq!(BROKER_PROTOCOL_VERSION, 3);
    let valid = br#"{"version":3,"request_id":"0123456789abcdef0123456789abcdef","request":{"operation":"git_credential","protocol":"https","host":"github.com","owner":"ExampleOrg","repository":"repo"}}"#;
    let decoded = decode_request_frame(valid).unwrap();
    assert_eq!(decoded.version, BROKER_PROTOCOL_VERSION);

    for invalid in [
        br#"{"version":1,"request_id":"0123456789abcdef0123456789abcdef","request":{"operation":"probe"}}"#.as_slice(),
        br#"{"version":2,"request_id":"0123456789abcdef0123456789abcdef","request":{"operation":"probe"}}"#.as_slice(),
        br#"{"version":3,"request_id":"short","request":{"operation":"probe"}}"#.as_slice(),
        br#"{"version":3,"request_id":"0123456789abcdef0123456789abcdef","unknown":true,"request":{"operation":"probe"}}"#.as_slice(),
        br#"{"version":3,"request_id":"0123456789abcdef0123456789abcdef","request":{"operation":"git_credential","protocol":"http","host":"github.com","owner":"ExampleOrg","repository":"repo"}}"#.as_slice(),
    ] {
        assert!(decode_request_frame(invalid).is_err());
    }

    assert!(decode_request_frame(&vec![b'x'; MAX_BROKER_FRAME_BYTES + 1]).is_err());
}

#[test]
fn session_lifecycle_requests_are_value_free_and_identifier_bounded() {
    for request in [
        BrokerRequest::ActivateSession {
            session_id: "0123456789abcdef0123456789abcdef".into(),
        },
        BrokerRequest::RenewSession {
            session_id: "0123456789abcdef0123456789abcdef".into(),
        },
        BrokerRequest::EndSession {
            session_id: "0123456789abcdef0123456789abcdef".into(),
        },
    ] {
        let frame = BrokerRequestEnvelope {
            version: BROKER_PROTOCOL_VERSION,
            request_id: "abcdef0123456789abcdef0123456789".into(),
            request: request.clone(),
        };
        let encoded = encode_request_frame(&frame).unwrap();
        assert_eq!(decode_request_frame(&encoded).unwrap().request, request);
    }
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
            hard_deadline_boot_ms: None,
            session_id: request_id.clone(),
            owner_uid: 1000,
            execution_uid: 991,
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
