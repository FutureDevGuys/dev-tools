//! Redirect admission happens before I/O, never after automatic redirection.

use crate::{validate_https_request, HttpsPolicy};
use anyhow::{bail, Context, Result};
use std::time::{Duration, Instant};
use ureq::http::Response;
use url::Url;

type HttpResponse = Response<ureq::Body>;
const MAX_URL_BYTES: usize = 8192;

/// Value-free URL or redirect admission rejection, distinguishable from an
/// operational transport failure through `anyhow::Error::downcast_ref`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpsAdmissionFailure;

impl std::fmt::Display for HttpsAdmissionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HTTPS resource is outside the admitted authority")
    }
}

impl std::error::Error for HttpsAdmissionFailure {}

#[derive(Clone)]
pub(super) struct ResponseLocation(pub String);

/// Header-only location observation. An unsupported HEAD request fails without
/// a GET fallback; a successful location is not artifact authentication.
pub fn probe_https_location(url: &str, policy: &HttpsPolicy) -> Result<String> {
    probe_location_with_send(url, policy, |url, remaining, _| {
        let agent: ureq::Agent = crate::https_single_hop_config(policy, remaining).into();
        head_request(&agent, url)
            .call()
            .context("request HTTPS resource headers")
    })
}

fn head_request(
    agent: &ureq::Agent,
    url: &str,
) -> ureq::RequestBuilder<ureq::typestate::WithoutBody> {
    agent.head(url).header("Accept", "application/octet-stream")
}

fn probe_location_with_send(
    url: &str,
    policy: &HttpsPolicy,
    send: impl FnMut(&str, Duration, bool) -> Result<HttpResponse>,
) -> Result<String> {
    let response = guarded_response(url, policy, 1, send)?;
    if response.status().as_u16() != 200 {
        bail!("HTTPS header request did not identify an available resource");
    }
    response
        .extensions()
        .get::<ResponseLocation>()
        .map(|location| location.0.clone())
        .context("HTTPS response location is unavailable")
}

/// Resolve an inert reference against an absolute HTTPS resource URL without
/// network access. This validates URL syntax, not host admission, authenticity
/// or installation authority; a future request still requires its own policy.
pub fn resolve_https_reference(base: &str, reference: &str) -> Result<String> {
    canonical_https_host(base)?;
    validate_url_text(reference)?;
    let resolved = Url::parse(base)
        .context("parse HTTPS reference base")?
        .join(reference)
        .context("resolve HTTPS reference")?;
    canonical_https_host(resolved.as_str())?;
    Ok(resolved.into())
}

/// Derive a host-policy entry from a trusted local HTTPS URL using the same
/// normalization and validation as the transport. Never use remote URLs to
/// extend an existing allowed-host policy.
pub fn canonical_https_host(input: &str) -> Result<String> {
    validate_url_text(input)?;
    let parsed = Url::parse(input).context("parse HTTPS policy URL")?;
    let uri: ureq::http::Uri = parsed
        .as_str()
        .parse()
        .context("parse normalized HTTPS policy URL")?;
    let host = uri
        .host()
        .context("HTTPS policy URL has no host")?
        .to_owned();
    let policy = HttpsPolicy {
        allowed_hosts: std::collections::BTreeSet::from([host.clone()]),
        max_redirects: 0,
        timeout: Duration::from_secs(1),
        user_agent: "dev-tools-release".into(),
    };
    validate_url(&parsed, &policy, 1)?;
    Ok(host)
}

pub(super) fn guarded_response(
    input: &str,
    policy: &HttpsPolicy,
    limit: u64,
    send: impl FnMut(&str, Duration, bool) -> Result<HttpResponse>,
) -> Result<HttpResponse> {
    guarded_response_with_clock(input, policy, limit, send, Instant::now)
}

fn guarded_response_with_clock(
    input: &str,
    policy: &HttpsPolicy,
    limit: u64,
    mut send: impl FnMut(&str, Duration, bool) -> Result<HttpResponse>,
    mut now: impl FnMut() -> Instant,
) -> Result<HttpResponse> {
    validate_url_text(input)?;
    let mut current = Url::parse(input).map_err(|_| HttpsAdmissionFailure)?;
    let deadline = now()
        .checked_add(policy.timeout)
        .context("HTTPS deadline overflowed")?;
    for hop in 0..=policy.max_redirects {
        validate_url(&current, policy, limit)?;
        let remaining = deadline
            .checked_duration_since(now())
            .filter(|remaining| !remaining.is_zero())
            .context("HTTPS request deadline expired")?;
        let mut response = send(current.as_str(), remaining, hop == 0)?;
        if now() >= deadline {
            bail!("HTTPS request deadline expired");
        }
        if !matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
            response
                .extensions_mut()
                .insert(ResponseLocation(current.into()));
            return Ok(response);
        }
        if hop == policy.max_redirects {
            bail!("HTTPS redirect limit exceeded");
        }
        let mut locations = response.headers().get_all("location").iter();
        let location = locations
            .next()
            .ok_or(HttpsAdmissionFailure)?
            .to_str()
            .map_err(|_| HttpsAdmissionFailure)?;
        if locations.next().is_some() {
            bail!(HttpsAdmissionFailure);
        }
        validate_url_text(location)?;
        current = current.join(location).map_err(|_| HttpsAdmissionFailure)?;
        // This is checked again immediately before send; perform it here as
        // well so invalid metadata is not mistaken for an exhausted deadline.
        validate_url(&current, policy, limit)?;
    }
    bail!("HTTPS redirect policy is invalid")
}

fn validate_url_text(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_URL_BYTES
        || value.contains(['\\', '#'])
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        bail!(HttpsAdmissionFailure);
    }
    Ok(())
}

fn validate_url(url: &Url, policy: &HttpsPolicy, limit: u64) -> Result<()> {
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        bail!(HttpsAdmissionFailure);
    }
    validate_url_text(url.as_str())?;
    validate_https_request(url.as_str(), policy, limit).map_err(|_| HttpsAdmissionFailure.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_location_is_the_admitted_request_not_response_metadata() {
        let response = guarded_response(
            "https://example.test/start",
            &policy(),
            100,
            |_, _, initial| {
                let mut response = if initial {
                    reply(302, Some("/files/feed.zsync"))
                } else {
                    reply(200, None)
                };
                response
                    .extensions_mut()
                    .insert(ResponseLocation("https://untrusted.test/spoof".into()));
                Ok(response)
            },
        )
        .unwrap();
        assert_eq!(
            response.extensions().get::<ResponseLocation>().unwrap().0,
            "https://example.test/files/feed.zsync"
        );
    }

    #[test]
    fn located_metadata_keeps_body_bounds_and_redirect_validator_scope() {
        let response = guarded_response(
            "https://example.test/start",
            &policy(),
            100,
            |_, _, initial| {
                Ok(if initial {
                    reply(302, Some("/feed"))
                } else {
                    Response::builder()
                        .status(200)
                        .header("etag", "\"final\"")
                        .body(ureq::Body::builder().data(b"metadata".to_vec()))
                        .unwrap()
                })
            },
        )
        .unwrap();
        let result = crate::decode_located_resource_response(response, 100, false, false).unwrap();
        assert_eq!(result.final_url, "https://example.test/feed");
        let crate::ConditionalHttpsResponse::Modified {
            response,
            validators,
        } = result.response
        else {
            panic!("modified")
        };
        assert_eq!(response.bytes, b"metadata");
        assert!(response.etag.is_none());
        assert_eq!(validators, crate::HttpsValidators::default());
        for (status, limit, initial) in [(200, 1, true), (206, 100, true), (304, 100, false)] {
            let response =
                guarded_response("https://example.test/feed", &policy(), 100, |_, _, _| {
                    Ok(reply(status, None))
                })
                .unwrap();
            assert!(
                crate::decode_located_resource_response(response, limit, true, initial).is_err()
            );
        }
    }

    #[test]
    fn inert_https_reference_resolution_uses_the_explicit_base() {
        assert_eq!(
            resolve_https_reference(
                "https://example.test/rel/feed.zsync",
                "../assets/app.AppImage?download=1"
            )
            .unwrap(),
            "https://example.test/assets/app.AppImage?download=1"
        );
        assert_eq!(
            resolve_https_reference("https://example.test/feed", "https://other.test/app").unwrap(),
            "https://other.test/app"
        );
        for reference in [
            "",
            "http://other.test/app",
            "https://user@other.test/app",
            "#fragment",
            "file:///not-read",
            "\\other.test\\app",
            "with space",
            "\n/evil",
        ] {
            assert!(resolve_https_reference("https://example.test/feed", reference).is_err());
        }
        assert!(resolve_https_reference("http://example.test/feed", "app").is_err());
    }

    #[test]
    fn header_probe_uses_head_and_the_admitted_final_location() {
        let agent: ureq::Agent =
            crate::https_single_hop_config(&policy(), Duration::from_secs(1)).into();
        assert_eq!(
            head_request(&agent, "https://example.test/start").method_ref(),
            Some(&ureq::http::Method::HEAD)
        );
        let mut requests = Vec::new();
        let location = probe_location_with_send(
            "https://example.test/start",
            &policy(),
            |url, _, initial| {
                requests.push(url.to_owned());
                Ok(if initial {
                    reply(302, Some("/app-42.zip"))
                } else {
                    reply(200, None)
                })
            },
        )
        .unwrap();
        assert_eq!(location, "https://example.test/app-42.zip");
        assert_eq!(requests.len(), 2);
    }

    #[test]
    fn header_probe_never_falls_back_after_unsupported_head() {
        for status in [204, 206, 304, 403, 404, 405, 429, 500, 501] {
            let mut calls = 0;
            assert!(
                probe_location_with_send("https://example.test/file", &policy(), |_, _, _| {
                    calls += 1;
                    Ok(reply(status, None))
                })
                .is_err()
            );
            assert_eq!(calls, 1);
        }
        let mut calls = 0;
        assert!(
            probe_location_with_send("https://example.test/file", &policy(), |_, _, _| {
                calls += 1;
                Ok(reply(302, Some("https://untrusted.test/file")))
            })
            .is_err()
        );
        assert_eq!(calls, 1);
    }

    #[test]
    fn header_probe_does_not_read_response_content() {
        struct Unreadable;
        impl std::io::Read for Unreadable {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("HEAD probe read artifact content")
            }
        }
        let result = probe_location_with_send("https://example.test/app", &policy(), |_, _, _| {
            Ok(Response::builder()
                .status(200)
                .body(ureq::Body::builder().reader(Unreadable))
                .unwrap())
        })
        .unwrap();
        assert_eq!(result, "https://example.test/app");
        assert_eq!(
            crate::https_single_hop_config(&policy(), Duration::from_secs(1))
                .max_response_header_size(),
            64 * 1024
        );
    }

    #[test]
    fn local_host_policy_uses_transport_normalization() {
        assert_eq!(
            canonical_https_host("https://EXAMPLE.com/root").unwrap(),
            "example.com"
        );
        assert_eq!(
            canonical_https_host("https://[2001:0db8:0:0:0:0:0:1]/root").unwrap(),
            "[2001:db8::1]"
        );
        for url in [
            "http://example.com/",
            "https://user@example.com/",
            "https://example.com/#fragment",
        ] {
            assert!(canonical_https_host(url).is_err());
        }
    }
    use crate::HttpsPolicy;
    use std::collections::BTreeSet;
    use std::time::Duration;

    #[test]
    fn conditional_response_requires_the_original_validator() {
        use crate::{decode_conditional_response, ConditionalHttpsResponse};
        let response = || {
            Response::builder()
                .status(304)
                .body(ureq::Body::builder().data("ignored"))
                .unwrap()
        };
        assert!(decode_conditional_response(response(), 64, false).is_err());
        assert!(matches!(
            decode_conditional_response(response(), 64, true).unwrap(),
            ConditionalHttpsResponse::NotModified { .. }
        ));
    }

    #[test]
    fn redirected_response_validators_are_not_retained_for_original_url() {
        use crate::{decode_resource_response, ConditionalHttpsResponse};
        let response = Response::builder()
            .status(200)
            .header("etag", "\"final-resource\"")
            .header("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")
            .body(ureq::Body::builder().data("bytes"))
            .unwrap();
        match decode_resource_response(response, 64, false, false).unwrap() {
            ConditionalHttpsResponse::Modified {
                response,
                validators,
            } => {
                assert!(response.etag.is_none());
                assert!(validators.etag.is_none());
                assert!(validators.last_modified.is_none());
                assert_eq!(response.bytes, b"bytes");
            }
            _ => panic!("redirected 200 is modified, not a cache hit"),
        }
    }

    #[test]
    fn conditional_metadata_is_bounded_and_unambiguous() {
        use crate::{decode_conditional_response, ConditionalHttpsResponse};
        let response = Response::builder()
            .status(200)
            .header("etag", "\"v1\"")
            .header("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")
            .body(ureq::Body::builder().data("bytes"))
            .unwrap();
        match decode_conditional_response(response, 5, false).unwrap() {
            ConditionalHttpsResponse::Modified {
                response,
                validators,
            } => {
                assert_eq!(response.bytes, b"bytes");
                assert_eq!(validators.etag.as_deref(), Some("\"v1\""));
                assert_eq!(
                    validators.last_modified.as_deref(),
                    Some("Wed, 21 Oct 2015 07:28:00 GMT")
                );
            }
            _ => panic!("200 must contain new bytes"),
        }
        for values in [vec!["a".into(), "b".into()], vec!["x".repeat(8193)]] {
            let mut builder = Response::builder().status(304);
            for value in values {
                builder = builder.header("etag", value);
            }
            let response = builder.body(ureq::Body::builder().data("ignored")).unwrap();
            assert!(decode_conditional_response(response, 64, true).is_err());
        }
        for (status, limit) in [(200, 4), (206, 64), (404, 64), (429, 64)] {
            let response = Response::builder()
                .status(status)
                .body(ureq::Body::builder().data("bytes"))
                .unwrap();
            assert!(decode_conditional_response(response, limit, false).is_err());
        }
    }

    fn policy() -> HttpsPolicy {
        HttpsPolicy {
            allowed_hosts: BTreeSet::from(["example.test".into()]),
            max_redirects: 2,
            timeout: Duration::from_secs(2),
            user_agent: "dev-tools-test".into(),
        }
    }

    fn reply(status: u16, location: Option<&str>) -> ureq::http::Response<ureq::Body> {
        let mut builder = ureq::http::Response::builder().status(status);
        if let Some(location) = location {
            builder = builder.header("Location", location);
        }
        builder
            .body(ureq::Body::builder().data(b"body".to_vec()))
            .unwrap()
    }

    #[test]
    fn off_policy_redirect_is_rejected_before_any_second_request() {
        for location in [
            "https://untrusted.test/secret",
            "http://example.test/plain",
            "https://user:password@example.test/file",
        ] {
            let mut requests = Vec::new();
            let result =
                guarded_response("https://example.test/start", &policy(), 100, |url, _, _| {
                    requests.push(url.to_owned());
                    Ok(reply(302, Some(location)))
                });
            assert!(result.is_err());
            assert_eq!(requests, ["https://example.test/start"]);
        }
    }

    #[test]
    fn relative_redirects_resolve_before_the_next_request() {
        let mut requests = Vec::new();
        let response = guarded_response(
            "https://example.test/releases/latest",
            &policy(),
            100,
            |url, remaining, initial| {
                requests.push((url.to_owned(), initial));
                assert!(remaining > Duration::ZERO && remaining <= policy().timeout);
                Ok(if initial {
                    reply(307, Some("../files/tool?download=1"))
                } else {
                    reply(200, None)
                })
            },
        )
        .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            requests,
            [
                ("https://example.test/releases/latest".into(), true),
                ("https://example.test/files/tool?download=1".into(), false)
            ]
        );
    }

    #[test]
    fn redirect_count_bounds_the_number_of_requests() {
        let mut requests = 0;
        let result = guarded_response("https://example.test/start", &policy(), 100, |_, _, _| {
            requests += 1;
            Ok(reply(301, Some("/again")))
        });
        assert!(result.is_err());
        assert_eq!(requests, 3);
    }

    #[test]
    fn malformed_or_oversized_locations_are_terminal() {
        for location in [
            None,
            Some(""),
            Some("https://example.test/#fragment"),
            Some("/bad\\path"),
            Some("/path with spaces"),
        ] {
            let mut calls = 0;
            assert!(
                guarded_response("https://example.test/start", &policy(), 100, |_, _, _| {
                    calls += 1;
                    Ok(reply(302, location))
                })
                .is_err()
            );
            assert_eq!(calls, 1);
        }
        let large = format!("/{}", "a".repeat(8192));
        assert!(
            guarded_response("https://example.test/start", &policy(), 100, |_, _, _| Ok(
                reply(302, Some(&large))
            ))
            .is_err()
        );
    }

    #[test]
    fn non_redirect_status_is_preserved_for_the_caller() {
        for status in [200, 304, 404, 429, 500] {
            let response =
                guarded_response("https://example.test/start", &policy(), 100, |_, _, _| {
                    Ok(reply(status, None))
                })
                .unwrap();
            assert_eq!(response.status().as_u16(), status);
        }
    }

    #[test]
    fn admission_errors_are_typed_and_value_free_without_reclassifying_io() {
        for url in [
            "https://untrusted.test/private-value",
            "https://user:private-value@example.test/file",
        ] {
            let error = guarded_response(url, &policy(), 100, |_, _, _| {
                panic!("inadmissible request reached transport")
            })
            .unwrap_err();
            assert!(error.downcast_ref::<HttpsAdmissionFailure>().is_some());
            assert!(!format!("{error:#}").contains("private-value"));
        }
        let error = guarded_response("https://example.test/file", &policy(), 100, |_, _, _| {
            bail!("fixture transport unavailable")
        })
        .unwrap_err();
        assert!(error.downcast_ref::<HttpsAdmissionFailure>().is_none());
        let error = guarded_response("https://example.test/file", &policy(), 100, |_, _, _| {
            Ok(reply(302, Some("https://untrusted.test/private-value")))
        })
        .unwrap_err();
        assert!(error.downcast_ref::<HttpsAdmissionFailure>().is_some());
        assert!(!format!("{error:#}").contains("private-value"));
    }

    #[test]
    fn invalid_initial_authority_never_reaches_the_transport() {
        for url in [
            "https://untrusted.test/file",
            "https://user:password@example.test/file",
            "https://example.test/file#fragment",
            "http://example.test/file",
        ] {
            assert!(guarded_response(url, &policy(), 100, |_, _, _| panic!(
                "invalid request reached transport"
            ))
            .is_err());
        }
    }

    #[test]
    fn one_deadline_bounds_the_complete_redirect_chain() {
        let start = Instant::now();
        let mut samples = [start, start, start + Duration::from_secs(2)].into_iter();
        let mut calls = 0;
        let result = guarded_response_with_clock(
            "https://example.test/start",
            &policy(),
            100,
            |_, _, _| {
                calls += 1;
                Ok(reply(302, Some("/next")))
            },
            || samples.next().unwrap(),
        );
        assert!(result.is_err());
        assert_eq!(calls, 1, "expiry must not start the next request");
    }

    #[test]
    fn multiple_location_headers_are_not_guessed() {
        let mut response = reply(302, Some("/one"));
        response
            .headers_mut()
            .append("location", "/two".parse().unwrap());
        let mut response = Some(response);
        assert!(
            guarded_response("https://example.test/start", &policy(), 100, |_, _, _| Ok(
                response.take().expect("no second request")
            ))
            .is_err()
        );
    }

    #[test]
    fn real_transport_cannot_bypass_redirect_admission() {
        let config = crate::https_single_hop_config(&policy(), Duration::from_secs(1));
        assert_eq!(config.max_redirects(), 0);
        assert!(config.https_only());
        assert!(!config.http_status_as_error());
    }
}
