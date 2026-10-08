//! Deliberately small decoder for one closed, bounded native Engine response.
//! No URL routing, redirects, compression, networking, or executable policy.

use super::Failure;

pub(super) fn decode(bytes: &[u8]) -> Result<&[u8], Failure> {
    let boundary = bytes
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .ok_or(Failure::Protocol)?;
    if boundary > 16 * 1024 {
        return Err(Failure::Protocol);
    }
    let header = std::str::from_utf8(&bytes[..boundary]).map_err(|_| Failure::Protocol)?;
    let mut lines = header.split("\r\n");
    let status = lines.next().ok_or(Failure::Protocol)?;
    let mut words = status.splitn(3, ' ');
    if !matches!(words.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(Failure::Protocol);
    }
    let code: u16 = words
        .next()
        .ok_or(Failure::Protocol)?
        .parse()
        .map_err(|_| Failure::Protocol)?;
    // Do not return provider-controlled error messages or follow redirects.
    if code == 401 || code == 403 {
        return Err(Failure::Permission);
    }
    if code != 200 {
        return Err(Failure::Provider);
    }
    let mut length = None;
    let mut content_type = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(Failure::Protocol)?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(Failure::Protocol);
            }
            length = Some(value.parse::<usize>().map_err(|_| Failure::Protocol)?);
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("content-encoding")
        {
            // HTTP/1.0 + Connection: close requests intentionally avoid chunking.
            // Unsupported framing is never interpreted as an empty cache.
            return Err(Failure::Protocol);
        } else if name.eq_ignore_ascii_case("content-type") {
            if content_type || value.split(';').next() != Some("application/json") {
                return Err(Failure::Protocol);
            }
            content_type = true;
        }
    }
    let body = &bytes[boundary + 4..];
    if !content_type || length.is_some_and(|length| length != body.len()) {
        return Err(Failure::Protocol);
    }
    Ok(body)
}

pub(super) fn request(method: &str, path: &str) -> Vec<u8> {
    // HTTP/1.0 makes the response close-delimited even for streamed JSON. There
    // is one request per native socket connection, with no connection reuse.
    format!("{method} {path} HTTP/1.0\r\nHost: docker\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").into_bytes()
}

pub(super) fn query_encode(value: &str) -> String {
    use std::fmt::Write;
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            write!(encoded, "%{byte:02X}").expect("write to string");
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_closed_response_framing() {
        assert_eq!(
            decode(
                b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
            )
            .unwrap(),
            b"{}"
        );
        assert_eq!(
            decode(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{}").unwrap(),
            b"{}"
        );
        for bytes in [
            &b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"[..],
            &b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\n\r\n{}"[..],
            &b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}"[..],
            &b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n{}"[..],
            &b"HTTP/1.0 302 Found\r\nLocation: https://remote.invalid\r\n\r\n"[..],
        ] { assert!(decode(bytes).is_err()); }
    }
}
