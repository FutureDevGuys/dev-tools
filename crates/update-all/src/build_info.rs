use serde::Serialize;
use std::env;
use std::path::PathBuf;
#[derive(Clone, Debug, Serialize)]
pub struct BuildInfo {
    pub profile: String,
    pub git_commit: String,
    pub git_dirty: bool,
    pub built_unix: u64,
}

pub fn current_build_info() -> BuildInfo {
    BuildInfo {
        profile: option_env!("UPDATE_ALL_BUILD_PROFILE")
            .unwrap_or("unknown")
            .to_string(),
        git_commit: option_env!("UPDATE_ALL_GIT_COMMIT")
            .unwrap_or("unknown")
            .to_string(),
        git_dirty: option_env!("UPDATE_ALL_GIT_DIRTY")
            .map(|v| v == "1")
            .unwrap_or(false),
        built_unix: option_env!("UPDATE_ALL_BUILD_UNIX")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0),
    }
}

pub fn package_support_root() -> PathBuf {
    let home = env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    if cfg!(windows) {
        env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData/Local"))
            .join("update-all/package-authority")
    } else {
        env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"))
            .join("update-all/package-authority")
    }
}
