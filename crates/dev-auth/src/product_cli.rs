//! Local common identity output, separate from the retained release verifier API.
use dev_tools_product::{BuildInfo, ProductId};
use std::io::Write;
#[cfg(any(test, not(target_os = "linux")))]
use std::path::Path;

#[cfg(any(test, not(target_os = "linux")))]
pub(super) fn has_version_layout(executable: &Path) -> bool {
    executable
        .parent()
        .and_then(Path::parent)
        .and_then(Path::file_name)
        == Some(std::ffi::OsStr::new("versions"))
}

#[cfg(not(target_os = "linux"))]
pub(super) fn running_has_version_layout() -> std::io::Result<bool> {
    std::env::current_exe().map(|executable| has_version_layout(&executable))
}

pub(super) fn print_version() -> i32 {
    write_output(format!("dev-auth {}\n", env!("CARGO_PKG_VERSION")).as_bytes())
}

pub(super) fn print_build_info() -> i32 {
    let info = ProductId::parse("dev-auth").and_then(|product| {
        BuildInfo::from_build_values(
            product,
            env!("CARGO_PKG_VERSION"),
            option_env!("DEV_TOOLS_GIT_COMMIT"),
            option_env!("DEV_TOOLS_GIT_DIRTY"),
            option_env!("DEV_TOOLS_BUILD_TARGET"),
            option_env!("DEV_TOOLS_BUILD_PROFILE"),
            option_env!("DEV_TOOLS_BUILD_UNIX"),
        )
    });
    let Ok(info) = info else {
        eprintln!("dev-auth: build identity is invalid");
        return 1;
    };
    let Ok(mut bytes) = serde_json::to_vec(&info) else {
        eprintln!("dev-auth: build identity could not be encoded");
        return 1;
    };
    bytes.push(b'\n');
    write_output(&bytes)
}

fn write_output(bytes: &[u8]) -> i32 {
    if std::io::stdout().lock().write_all(bytes).is_err() {
        eprintln!("dev-auth: identity output could not be written");
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_layout_classifier_does_not_infer_a_managed_installation_from_a_name() {
        use super::has_version_layout;
        use std::path::Path;
        assert!(has_version_layout(Path::new(
            "/opt/dev-auth/versions/0.5.0/dev-auth"
        )));
        assert!(!has_version_layout(Path::new("/opt/dev-auth/dev-auth")));
        assert!(!has_version_layout(Path::new("/opt/versions/dev-auth")));
    }
}
