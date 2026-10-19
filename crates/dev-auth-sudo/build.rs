mod identity {
    include!("../build_info_build.rs");

    pub fn emit() {
        main();
    }
}

mod abi_identity;

fn main() -> std::io::Result<()> {
    identity::emit();
    println!("cargo:rerun-if-changed=abi_identity.rs");
    println!(
        "cargo:rustc-env=DEV_AUTH_SUDO_ABI_ID={}",
        abi_identity::identity()
    );
    let output = std::path::PathBuf::from(
        std::env::var_os("OUT_DIR").expect("Cargo provides OUT_DIR"), // INVARIANT: Cargo supplies OUT_DIR before invoking a build script.
    )
    .join("dev-auth-sudo-abi.rs");
    std::fs::write(
        output,
        format!(
            "#[cfg(target_os = \"linux\")]\npub(crate) const SUDO_PLUGIN_API_VERSION: u32 = {};\n\
             #[cfg(target_os = \"linux\")]\npub(crate) const SUDO_GROUP_API_VERSION: u32 = {};\n",
            abi_identity::PLUGIN_API_VERSION,
            abi_identity::GROUP_API_VERSION,
        ),
    )?;
    Ok(())
}
