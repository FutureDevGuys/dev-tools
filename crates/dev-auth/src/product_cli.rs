//! Local common identity output, separate from the retained release verifier API.
use dev_tools_product::{BuildInfo, ProductId};
use std::io::Write;

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
