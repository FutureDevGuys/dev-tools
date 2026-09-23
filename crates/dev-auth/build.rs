mod identity {
    include!("../build_info_build.rs");
    pub fn emit() {
        main();
    }
}

fn main() {
    identity::emit();
    println!("cargo:rerun-if-env-changed=DEV_AUTH_SUDO_ARTIFACT");
    let output =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo provides OUT_DIR"))
            .join("dev-auth-sudo.so");
    let Some(artifact) = std::env::var_os("DEV_AUTH_SUDO_ARTIFACT") else {
        std::fs::write(output, []).expect("write absent helper marker");
        return;
    };
    let artifact = std::path::PathBuf::from(artifact);
    assert!(
        artifact.is_absolute(),
        "sudo helper artifact must be absolute"
    );
    println!("cargo:rerun-if-changed={}", artifact.display());
    let metadata =
        std::fs::symlink_metadata(&artifact).expect("read selected sudo helper metadata");
    assert!(
        metadata.is_file() && metadata.len() <= 32 * 1024 * 1024,
        "invalid sudo helper artifact"
    );
    let bytes = std::fs::read(&artifact).expect("read selected sudo helper artifact");
    let target = std::env::var("TARGET").expect("Cargo provides target");
    let machine: u16 = if target.starts_with("x86_64-") {
        62
    } else if target.starts_with("aarch64-") {
        183
    } else {
        panic!("sudo helper target not qualified for embedding");
    };
    assert!(
        target.contains("linux")
            && bytes.len() >= 64
            && &bytes[..6] == b"\x7fELF\x02\x01"
            && u16::from_le_bytes([bytes[16], bytes[17]]) == 3
            && u16::from_le_bytes([bytes[18], bytes[19]]) == machine,
        "sudo helper architecture does not match the product"
    );
    let commit = std::env::var("DEV_TOOLS_GIT_COMMIT").unwrap_or_else(|_| "unknown".into());
    let expected = format!(
        "dev-auth-sudo-build-v1:{}:{commit}:{target}:end",
        std::env::var("CARGO_PKG_VERSION").expect("Cargo provides version")
    );
    assert!(
        bytes
            .windows(expected.len())
            .any(|window| window == expected.as_bytes()),
        "sudo helper version, target or source identity does not match"
    );
    std::fs::write(output, bytes).expect("embed matched sudo helper");
}
