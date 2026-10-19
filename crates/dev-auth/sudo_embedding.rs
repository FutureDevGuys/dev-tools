//! Product-owned byte checks shared by helper embedding and source regressions.

#[path = "../dev-auth-sudo/abi_identity.rs"]
mod sudo_abi_identity;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ValidationError {
    UnsupportedTarget,
    IncompatibleElf,
    IdentityMismatch,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedTarget => "sudo helper target not qualified for embedding",
            Self::IncompatibleElf => "sudo helper architecture does not match the product",
            Self::IdentityMismatch => {
                "sudo helper version, target, source or ABI identity does not match"
            }
        })
    }
}

pub(crate) fn validate(
    bytes: &[u8],
    version: &str,
    source_commit: &str,
    target: &str,
) -> Result<(), ValidationError> {
    let machine: u16 = if target.starts_with("x86_64-") {
        62
    } else if target.starts_with("aarch64-") {
        183
    } else {
        return Err(ValidationError::UnsupportedTarget);
    };
    if !(target.contains("linux")
        && bytes.len() >= 64
        && &bytes[..6] == b"\x7fELF\x02\x01"
        && u16::from_le_bytes([bytes[16], bytes[17]]) == 3
        && u16::from_le_bytes([bytes[18], bytes[19]]) == machine)
    {
        return Err(ValidationError::IncompatibleElf);
    }
    let expected = format!(
        "dev-auth-sudo-build-v2:{version}:{source_commit}:{target}:{}:end",
        sudo_abi_identity::identity(),
    );
    if !bytes
        .windows(expected.len())
        .any(|window| window == expected.as_bytes())
    {
        return Err(ValidationError::IdentityMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ValidationError, validate};

    const VERSION: &str = "0.5.3";
    const SOURCE: &str = "0123456789abcdef0123456789abcdef01234567";
    const X86_TARGET: &str = "x86_64-unknown-linux-gnu";
    const ARM_TARGET: &str = "aarch64-unknown-linux-gnu";
    // Independent fixtures pin ADR0115's build-v2 identity and selected APIs.
    const X86_IDENTITY: &str = concat!(
        "dev-auth-sudo-build-v2:0.5.3:",
        "0123456789abcdef0123456789abcdef01234567:",
        "x86_64-unknown-linux-gnu:sudo-plugin-api-1.22:group-api-1.0:end"
    );
    const ARM_IDENTITY: &str = concat!(
        "dev-auth-sudo-build-v2:0.5.3:",
        "0123456789abcdef0123456789abcdef01234567:",
        "aarch64-unknown-linux-gnu:sudo-plugin-api-1.22:group-api-1.0:end"
    );

    fn helper_bytes(machine: u16, identity: &str) -> Vec<u8> {
        // Minimal byte-check fixture, never loaded as a native plugin.
        let mut bytes = vec![0; 64];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes.extend_from_slice(b"\0fixture-prefix\0");
        bytes.extend_from_slice(identity.as_bytes());
        bytes.extend_from_slice(b"\0fixture-suffix\0");
        bytes
    }

    #[test]
    fn exact_build_v2_accepts_both_supported_elf_machines() {
        for (target, machine, identity) in [
            (X86_TARGET, 62, X86_IDENTITY),
            (ARM_TARGET, 183, ARM_IDENTITY),
        ] {
            assert_eq!(
                validate(&helper_bytes(machine, identity), VERSION, SOURCE, target),
                Ok(()),
                "{target}"
            );
        }
    }

    #[test]
    fn legacy_build_v1_cannot_supply_the_required_identity() {
        let identity = concat!(
            "dev-auth-sudo-build-v1:0.5.3:",
            "0123456789abcdef0123456789abcdef01234567:",
            "x86_64-unknown-linux-gnu:end"
        );
        assert_eq!(
            validate(&helper_bytes(62, identity), VERSION, SOURCE, X86_TARGET),
            Err(ValidationError::IdentityMismatch)
        );
    }

    #[test]
    fn every_selected_build_v2_identity_component_must_match() {
        for (name, from, to) in [
            ("version", "0.5.3", "0.5.4"),
            ("source", SOURCE, "ffffffffffffffffffffffffffffffffffffffff"),
            ("target", X86_TARGET, ARM_TARGET),
            ("plugin ABI", "sudo-plugin-api-1.22", "sudo-plugin-api-1.21"),
            ("group ABI", "group-api-1.0", "group-api-1.1"),
            ("terminator", ":end", ":stop"),
        ] {
            let identity = X86_IDENTITY.replace(from, to);
            assert_eq!(
                validate(&helper_bytes(62, &identity), VERSION, SOURCE, X86_TARGET),
                Err(ValidationError::IdentityMismatch),
                "{name}"
            );
        }
    }

    #[test]
    fn missing_identity_is_rejected_even_with_a_compatible_elf_header() {
        assert_eq!(
            validate(&helper_bytes(62, ""), VERSION, SOURCE, X86_TARGET),
            Err(ValidationError::IdentityMismatch)
        );
    }

    #[test]
    fn exact_identity_cannot_override_an_incompatible_elf_header() {
        for (name, offset, replacement) in [
            ("magic", 0, 0),
            ("class", 4, 1),
            ("byte order", 5, 2),
            ("object type", 16, 2),
            ("object type high byte", 17, 1),
            ("machine", 18, 183),
            ("machine high byte", 19, 1),
        ] {
            let mut bytes = helper_bytes(62, X86_IDENTITY);
            bytes[offset] = replacement;
            assert_eq!(
                validate(&bytes, VERSION, SOURCE, X86_TARGET),
                Err(ValidationError::IncompatibleElf),
                "{name}"
            );
        }
        let bytes = helper_bytes(62, X86_IDENTITY);
        for length in 0..64 {
            assert_eq!(
                validate(&bytes[..length], VERSION, SOURCE, X86_TARGET),
                Err(ValidationError::IncompatibleElf),
                "truncated length {length}"
            );
        }
    }

    #[test]
    fn unsupported_architectures_and_non_linux_targets_remain_rejected() {
        let bytes = helper_bytes(62, X86_IDENTITY);
        assert_eq!(
            validate(&bytes, VERSION, SOURCE, "riscv64gc-unknown-linux-gnu"),
            Err(ValidationError::UnsupportedTarget)
        );
        assert_eq!(
            validate(&bytes, VERSION, SOURCE, "x86_64-apple-darwin"),
            Err(ValidationError::IncompatibleElf)
        );
    }
}
