use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use sync_configs::paths::{is_absolute_for, PathContext, PathPlatform};

#[test]
fn synthetic_windows_absolute_paths_follow_native_root_and_prefix_rules() {
    let cases = [
        (r"C:\config", true),
        ("C:/config", true),
        (r"c:\", true),
        ("Z:/", true),
        (r"\\server\share", true),
        (r"\\server\share\config", true),
        ("//server/share/config", true),
        (r"\\server/share\config", true),
        (r"\\?\C:\config", true),
        (r"\\.\COM1", true),
        (r"C:config", false),
        ("C:", false),
        ("C", false),
        (r"\config", false),
        ("/config", false),
        ("config", false),
        ("", false),
        (r"1:\config", false),
        (r"\\server", false),
        (r"\\server\", false),
        (r"\\\share", false),
        ("//server", false),
        ("///share", false),
        (r"\\server\\share", false),
    ];

    for (raw, expected) in cases {
        assert_eq!(
            is_absolute_for(Path::new(raw), PathPlatform::Windows),
            expected,
            "Windows absolute-path classification for {raw:?}"
        );
    }
}

#[test]
fn synthetic_windows_home_environment_lookup_is_case_insensitive() {
    type HomeCase<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a str);
    let cases: &[HomeCase<'_>] = &[
        (
            "user profile",
            &[("userProfile", r"C:\Users\operator")],
            r"C:\Users\operator",
        ),
        (
            "drive and home path",
            &[("homeDrive", "D:"), ("homePath", r"\Operators\rashino")],
            r"D:\Operators\rashino",
        ),
    ];
    for &(name, environment, expected) in cases {
        let environment: BTreeMap<OsString, OsString> = environment
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value)))
            .collect();
        let context = PathContext::from_environment(
            PathPlatform::Windows,
            PathBuf::from(r"C:\workspace"),
            PathBuf::from(r"C:\Temp"),
            environment,
        );

        assert_eq!(context.home, Some(PathBuf::from(expected)), "{name}");
    }
}

#[test]
fn relative_platform_home_values_are_not_path_authority() {
    for (platform, name, value) in [
        (PathPlatform::Posix, "HOME", "relative-home"),
        (PathPlatform::Windows, "USERPROFILE", "relative-home"),
    ] {
        let environment = BTreeMap::from([(OsString::from(name), OsString::from(value))]);
        let context = PathContext::from_environment(
            platform,
            PathBuf::from("/absolute/workspace"),
            PathBuf::from("/absolute/tmp"),
            environment,
        );

        assert_eq!(context.home, None, "{platform:?} relative home");
    }
}
