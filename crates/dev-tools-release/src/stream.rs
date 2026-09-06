use anyhow::Result;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

/// Value-free categories for the signed artifact streaming boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactTransferErrorKind {
    Authentication,
    InvalidLimit,
    Transport,
    Integrity,
    Storage,
}

/// Downcast from the existing `anyhow::Error` return to distinguish operational
/// failures from failed authentication or content integrity without parsing text.
#[derive(Debug)]
pub struct ArtifactTransferError {
    kind: ArtifactTransferErrorKind,
    context: &'static str,
    source: Option<anyhow::Error>,
}

impl ArtifactTransferError {
    pub fn kind(&self) -> ArtifactTransferErrorKind {
        self.kind
    }
}

impl std::fmt::Display for ArtifactTransferError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.context)
    }
}

impl std::error::Error for ArtifactTransferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|error| error.as_ref())
    }
}

fn failure(kind: ArtifactTransferErrorKind, context: &'static str) -> anyhow::Error {
    ArtifactTransferError {
        kind,
        context,
        source: None,
    }
    .into()
}

fn caused(
    kind: ArtifactTransferErrorKind,
    context: &'static str,
    source: impl Into<anyhow::Error>,
) -> anyhow::Error {
    ArtifactTransferError {
        kind,
        context,
        source: Some(source.into()),
    }
    .into()
}

/// Authenticate metadata, then stream its selected artifact into caller-owned
/// quarantine storage using the shared HTTPS redirect and timeout policy.
///
/// The writer MUST be empty private staging storage, never an active executable
/// or published cache entry. On error it may contain unverified partial bytes;
/// the caller must discard it. Success includes exact signed length, SHA-256 and
/// writer flush, but not filesystem sync, publication, anti-rollback acceptance,
/// installation ownership or execution approval. Those remain caller obligations.
/// A caller-supplied writer that blocks is not bounded by the network timeout.
pub fn fetch_artifact_to_staging(
    metadata: &crate::ReleaseMetadata,
    authority: &crate::ReleaseAuthority,
    policy: &crate::HttpsPolicy,
    limit: u64,
    writer: &mut impl Write,
) -> Result<crate::VerifiedRelease> {
    let verified = crate::verify_release_metadata(metadata, authority).map_err(|error| {
        caused(
            ArtifactTransferErrorKind::Authentication,
            "release authentication failed",
            error,
        )
    })?;
    if limit == 0 || limit > crate::ARTIFACT_LIMIT as u64 || verified.artifact_length > limit {
        return Err(failure(
            ArtifactTransferErrorKind::InvalidLimit,
            "release artifact size bound is invalid",
        ));
    }
    let (response, _, _) = crate::request_https_response(
        &verified.artifact_url,
        policy,
        limit,
        &crate::HttpsValidators::default(),
    )
    .map_err(|error| {
        caused(
            ArtifactTransferErrorKind::Transport,
            "HTTPS artifact request failed",
            error,
        )
    })?;
    stage_response(
        response,
        writer,
        verified.artifact_length,
        &verified.artifact_sha256,
    )?;
    Ok(verified)
}

fn stage_response(
    mut response: ureq::http::Response<ureq::Body>,
    writer: &mut impl Write,
    length: u64,
    digest: &str,
) -> Result<()> {
    if response.status().as_u16() != 200 {
        return Err(failure(
            ArtifactTransferErrorKind::Transport,
            "HTTPS artifact request returned an unsupported status",
        ));
    }
    let mut reader = response.body_mut().with_config().limit(length + 1).reader();
    copy_artifact(&mut reader, writer, length, digest)
}

fn copy_artifact(
    reader: &mut impl Read,
    writer: &mut impl Write,
    length: u64,
    digest: &str,
) -> Result<()> {
    if length == 0 || length > crate::ARTIFACT_LIMIT as u64 {
        return Err(failure(
            ArtifactTransferErrorKind::InvalidLimit,
            "release artifact size bound is invalid",
        ));
    }
    let mut bytes = [0_u8; 64 * 1024];
    let mut remaining = length;
    let mut hash = Sha256::new();
    while remaining > 0 {
        let requested = remaining.min(bytes.len() as u64) as usize;
        let read = match reader.read(&mut bytes[..requested]) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result.map_err(|error| {
                caused(
                    ArtifactTransferErrorKind::Transport,
                    "read staged artifact",
                    error,
                )
            })?,
        };
        if read == 0 {
            return Err(failure(
                ArtifactTransferErrorKind::Integrity,
                "release artifact is shorter than the signed length",
            ));
        }
        writer.write_all(&bytes[..read]).map_err(|error| {
            caused(
                ArtifactTransferErrorKind::Storage,
                "write staged artifact",
                error,
            )
        })?;
        hash.update(&bytes[..read]);
        remaining -= read as u64;
    }
    let mut extra = [0];
    loop {
        match reader.read(&mut extra) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(0) => break,
            Ok(_) => {
                return Err(failure(
                    ArtifactTransferErrorKind::Integrity,
                    "release artifact exceeds the signed length",
                ))
            }
            Err(error) => {
                return Err(caused(
                    ArtifactTransferErrorKind::Transport,
                    "finish staged artifact read",
                    error,
                ))
            }
        }
    }
    if format!("{:x}", hash.finalize()) != digest {
        return Err(failure(
            ArtifactTransferErrorKind::Integrity,
            "release artifact does not match the signed manifest",
        ));
    }
    writer.flush().map_err(|error| {
        caused(
            ArtifactTransferErrorKind::Storage,
            "flush staged artifact",
            error,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    // Run this test executable directly with per-child peak RSS accounting.
    // ARTIFACT_TRANSFER_MODE=buffered|streamed; ARTIFACT_TRANSFER_MIB=1|64|128.
    // Synthetic body-copy evidence only: no TLS, network, filesystem or fsync.
    #[test]
    #[ignore = "isolated process memory comparison"]
    fn transfer_memory_probe() {
        let size = std::env::var("ARTIFACT_TRANSFER_MIB")
            .unwrap()
            .parse::<u64>()
            .unwrap()
            * 1024
            * 1024;
        assert!(size <= crate::ARTIFACT_LIMIT as u64);
        let mode = std::env::var("ARTIFACT_TRANSFER_MODE").unwrap();
        let mut hash = Sha256::new();
        for _ in 0..size / 65536 {
            hash.update([0; 65536]);
        }
        let digest = format!("{:x}", hash.finalize());
        let mut body = ureq::Body::builder().reader(std::io::repeat(0).take(size));
        match mode.as_str() {
            "buffered" => {
                let bytes = crate::read_bounded_body(&mut body, size).unwrap();
                assert_eq!(crate::sha256_hex(&bytes), digest);
                std::io::sink().write_all(&bytes).unwrap();
            }
            "streamed" => {
                copy_artifact(&mut body.as_reader(), &mut std::io::sink(), size, &digest).unwrap()
            }
            _ => panic!("unknown transfer mode"),
        }
        println!("mode={mode} bytes={size} verified=true");
    }

    #[test]
    fn transfer_does_not_require_an_artifact_sized_write() {
        struct BoundedWriter(usize);
        impl Write for BoundedWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                assert!(bytes.len() <= 64 * 1024, "artifact-sized write");
                self.0 += bytes.len();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let bytes = vec![7; 150_000];
        let mut writer = BoundedWriter(0);
        copy_artifact(
            &mut bytes.as_slice(),
            &mut writer,
            bytes.len() as u64,
            &crate::sha256_hex(&bytes),
        )
        .unwrap();
        assert_eq!(writer.0, bytes.len());
    }

    #[test]
    fn transfer_rejects_truncation_excess_and_wrong_digest() {
        let digest = crate::sha256_hex(b"abc");
        for bytes in [b"ab".as_slice(), b"abcd", b"abd"] {
            let mut staged = Vec::new();
            let error = copy_artifact(&mut &*bytes, &mut staged, 3, &digest).unwrap_err();
            assert_eq!(
                error
                    .downcast_ref::<ArtifactTransferError>()
                    .unwrap()
                    .kind(),
                ArtifactTransferErrorKind::Integrity
            );
            assert!(staged.len() <= 3);
        }
        for status in [204, 206, 304, 404, 429, 500] {
            let response = ureq::http::Response::builder()
                .status(status)
                .body(ureq::Body::builder().data(b"abc"))
                .unwrap();
            let mut staged = Vec::new();
            let error = stage_response(response, &mut staged, 3, &digest).unwrap_err();
            assert_eq!(
                error
                    .downcast_ref::<ArtifactTransferError>()
                    .unwrap()
                    .kind(),
                ArtifactTransferErrorKind::Transport
            );
            assert!(staged.is_empty());
        }
        let response = ureq::http::Response::builder()
            .status(200)
            .body(ureq::Body::builder().data(b"abc"))
            .unwrap();
        let mut staged = Vec::new();
        stage_response(response, &mut staged, 3, &digest).unwrap();
        assert_eq!(staged, b"abc");
    }

    #[test]
    fn transfer_propagates_reader_write_and_flush_failures() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("injected read"))
            }
        }
        struct Writer {
            fail_write: bool,
            flushes: usize,
        }
        impl Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.fail_write {
                    Err(std::io::Error::other("injected write"))
                } else {
                    Ok(bytes.len().min(1))
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.flushes += 1;
                Err(std::io::Error::other("injected flush"))
            }
        }
        let digest = crate::sha256_hex(b"abc");
        let classified =
            copy_artifact(&mut FailingReader, &mut Vec::new(), 3, &digest).unwrap_err();
        assert_eq!(
            classified
                .downcast_ref::<ArtifactTransferError>()
                .map(ArtifactTransferError::kind),
            Some(ArtifactTransferErrorKind::Transport)
        );
        assert!(
            copy_artifact(&mut FailingReader, &mut Vec::new(), 3, &digest)
                .unwrap_err()
                .to_string()
                .contains("read staged")
        );
        let mut writer = Writer {
            fail_write: true,
            flushes: 0,
        };
        let error = copy_artifact(&mut b"abc".as_slice(), &mut writer, 3, &digest).unwrap_err();
        assert!(error.to_string().contains("write staged"));
        assert_eq!(
            error
                .downcast_ref::<ArtifactTransferError>()
                .unwrap()
                .kind(),
            ArtifactTransferErrorKind::Storage
        );
        assert_eq!(writer.flushes, 0);
        writer.fail_write = false;
        let error = copy_artifact(&mut b"abc".as_slice(), &mut writer, 3, &digest).unwrap_err();
        assert!(error.to_string().contains("flush staged"));
        assert_eq!(
            error
                .downcast_ref::<ArtifactTransferError>()
                .unwrap()
                .kind(),
            ArtifactTransferErrorKind::Storage
        );
        assert_eq!(writer.flushes, 1);
    }
}
