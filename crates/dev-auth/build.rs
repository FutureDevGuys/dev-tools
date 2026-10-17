mod identity {
    include!("../build_info_build.rs");
    pub fn emit() {
        main();
    }
}

mod sudo_embedding;

fn main() {
    identity::emit();
    println!("cargo:rerun-if-env-changed=DEV_AUTH_SUDO_ARTIFACT");
    println!("cargo:rerun-if-changed=sudo_embedding.rs");
    println!("cargo:rerun-if-changed=../dev-auth-sudo/abi_identity.rs");
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
    let commit = std::env::var("DEV_TOOLS_GIT_COMMIT").unwrap_or_else(|_| "unknown".into());
    let version = std::env::var("CARGO_PKG_VERSION").expect("Cargo provides version");
    sudo_embedding::validate(&bytes, &version, &commit, &target)
        .unwrap_or_else(|error| panic!("{error}"));
    std::fs::write(output, bytes).expect("embed matched sudo helper");
}
