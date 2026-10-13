//! Explicit, exact-reference 1Password metadata. Never use item JSON here:
//! it contains field values even without --reveal. The vendor documents the
//! fixed `attribute=type` query for both fields and file attachments.
use super::*;
use dev_tools_secret::{SecretMetadataObservation, SecretValueType};

pub(super) fn base_reference(reference: &str) -> std::result::Result<&str, SecretError> {
    crate::validate_op_reference(reference)
        .map_err(|_| secret_error(SecretErrorKind::InvalidReference))?;
    let (base, query) = reference
        .split_once('?')
        .map_or((reference, None), |(base, query)| (base, Some(query)));
    // Only documented value-format selectors can be replaced by the fixed
    // type selector. Unknown or combined queries are never sent to a provider.
    if query.is_some_and(|query| {
        !matches!(
            query,
            "ssh-format=openssh"
                | "attribute=value"
                | "attr=value"
                | "attribute=content"
                | "attr=content"
                | "attribute=otp"
                | "attr=otp"
        )
    }) {
        return Err(secret_error(SecretErrorKind::Unsupported));
    }
    crate::validate_op_reference(base)
        .map_err(|_| secret_error(SecretErrorKind::InvalidReference))?;
    let path = base
        .strip_prefix("op://")
        .ok_or_else(|| secret_error(SecretErrorKind::InvalidReference))?;
    if !path.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b' ')
    }) {
        return Err(secret_error(SecretErrorKind::Unsupported));
    }
    Ok(base)
}

pub(super) fn discover(
    provider: &OnePasswordProvider<'_>,
    reference: &SecretReference,
    operation: SecretOperationContext<'_>,
) -> std::result::Result<SecretMetadataObservation, SecretError> {
    operation.checkpoint()?;
    let reference = base_reference(reference.expose_to_provider())?;
    let guard = program_guard(provider.op_program, "1Password CLI")
        .map_err(|_| secret_error(SecretErrorKind::ProviderUnavailable))?;
    let timeout = operation
        .remaining()?
        .checked_sub(Duration::from_secs(2))
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| secret_error(SecretErrorKind::DeadlineExceeded))?;
    #[cfg(target_os = "linux")]
    let output = run_linux_provider_operation(
        operation,
        &provider.child_executable,
        provider.op_program,
        &guard,
        provider.service_token,
        OnePasswordInvocation::FieldType(reference),
        timeout,
    )?;
    #[cfg(not(target_os = "linux"))]
    let output = run_provider_operation(
        operation,
        provider.op_program,
        &guard,
        provider.service_token,
        OnePasswordInvocation::FieldType(reference),
        timeout,
    )?;
    let stdout = zeroize::Zeroizing::new(output.stdout);
    let _stderr = zeroize::Zeroizing::new(output.stderr);
    operation.checkpoint()?;
    if !output.status.success() {
        // The CLI does not expose a stable typed not-found/permission taxonomy.
        // Failure therefore never establishes that the resource is absent.
        return Err(secret_error(SecretErrorKind::ProviderFailure));
    }
    let observation = parse_type(&stdout)?;
    operation.checkpoint()?;
    Ok(observation)
}

fn parse_type(bytes: &[u8]) -> std::result::Result<SecretMetadataObservation, SecretError> {
    // Borrow the zeroizing capture. Never allocate, retain or publish a native
    // string. Unknown scalar type names can be observed without inventing a
    // provider-independent type; malformed/JSON/empty output fails closed.
    if bytes.is_empty()
        || bytes.len() > 64
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return Err(secret_error(SecretErrorKind::InvalidResponse));
    }
    let value_type = if bytes.eq_ignore_ascii_case(b"STRING") {
        SecretValueType::Text
    } else if bytes.eq_ignore_ascii_case(b"CONCEALED") {
        SecretValueType::Concealed
    } else if bytes.eq_ignore_ascii_case(b"OTP") {
        SecretValueType::OneTimePassword
    } else {
        SecretValueType::Other
    };
    Ok(SecretMetadataObservation { value_type })
}
