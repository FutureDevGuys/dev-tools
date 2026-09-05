//! Redirect admission happens before I/O, never after automatic redirection.

use crate::{validate_https_request, HttpsPolicy};
use anyhow::{bail, Context, Result};
use std::time::{Duration, Instant};
use ureq::http::Response;
use url::Url;

type HttpResponse = Response<ureq::Body>;
const MAX_URL_BYTES: usize = 8192;

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
    let mut current = Url::parse(input).context("parse HTTPS request URL")?;
    let deadline = now()
        .checked_add(policy.timeout)
        .context("HTTPS deadline overflowed")?;
    for hop in 0..=policy.max_redirects {
        validate_url(&current, policy, limit)?;
        let remaining = deadline
            .checked_duration_since(now())
            .filter(|remaining| !remaining.is_zero())
            .context("HTTPS request deadline expired")?;
        let response = send(current.as_str(), remaining, hop == 0)?;
        if now() >= deadline {
            bail!("HTTPS request deadline expired");
        }
        if !matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
            return Ok(response);
        }
        if hop == policy.max_redirects {
            bail!("HTTPS redirect limit exceeded");
        }
        let mut locations = response.headers().get_all("location").iter();
        let location = locations
            .next()
            .context("HTTPS redirect has no location")?
            .to_str()
            .context("HTTPS redirect location is invalid")?;
        if locations.next().is_some() {
            bail!("HTTPS redirect location is ambiguous");
        }
        validate_url_text(location)?;
        current = current
            .join(location)
            .context("resolve HTTPS redirect location")?;
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
        bail!("HTTPS URL is invalid or exceeds its size bound");
    }
    Ok(())
}

fn validate_url(url: &Url, policy: &HttpsPolicy, limit: u64) -> Result<()> {
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        bail!("HTTPS URL contains prohibited authority or fragment data");
    }
    validate_url_text(url.as_str())?;
    validate_https_request(url.as_str(), policy, limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HttpsPolicy;
    use std::collections::BTreeSet;
    use std::time::Duration;

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
