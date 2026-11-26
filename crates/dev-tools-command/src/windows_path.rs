//! Product-neutral Windows path-spelling rules.
//!
//! Rules follow Microsoft's "Naming Files, Paths, and Namespaces": a file name
//! must not end in a dot or space, and must not use a reserved DOS device name
//! (CON, PRN, AUX, NUL, COM0-9, LPT0-9, COM/LPT followed by a superscript
//! 1, 2 or 3), with or without an extension.

use std::path::PathBuf;

/// Whether an uppercased file-name stem is a reserved Windows device name.
pub fn is_reserved_device_stem(stem: &str) -> bool {
    matches!(stem, "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|rest| {
                let mut chars = rest.chars();
                matches!(
                    (chars.next(), chars.next()),
                    (Some(c), None) if c.is_ascii_digit() || matches!(c, '\u{b9}' | '\u{b2}' | '\u{b3}')
                )
            })
        })
}

/// Whether one file-name component keeps its meaning when spelled without a
/// verbatim prefix: no trailing dot or space, and no reserved device name.
pub fn is_plain_component(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or_default();
    !name.ends_with(['.', ' '])
        && !is_reserved_device_stem(&stem.trim_end_matches(' ').to_uppercase())
}

/// Return the plain spelling of a verbatim drive path (`\\?\C:\a` -> `C:\a`)
/// when it names the same file, else `None`. UNC and volume paths, a bare
/// drive, and paths with a component the plain form would reinterpret keep
/// their prefix.
pub fn plain_verbatim_disk(text: &str) -> Option<&str> {
    let rest = text.strip_prefix(r"\\?\")?;
    matches!(rest.as_bytes(), [drive, b':', b'\\', ..] if drive.is_ascii_alphabetic())
        .then_some(())?;
    rest[3..]
        .split('\\')
        .all(is_plain_component)
        .then_some(rest)
}

/// Drop the `\\?\` prefix `canonicalize` adds on Windows when the plain form
/// names the same file. Unchanged on other platforms and for non-Unicode paths.
pub fn without_verbatim_prefix(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    if let Some(plain) = path.to_str().and_then(plain_verbatim_disk) {
        return PathBuf::from(plain);
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_device_names_follow_the_documented_list() {
        for reserved in ["CON", "PRN", "AUX", "NUL", "COM0", "COM9", "LPT0", "LPT9"] {
            assert!(is_reserved_device_stem(reserved), "{reserved}");
        }
        for reserved in [
            "COM\u{b9}",
            "COM\u{b2}",
            "COM\u{b3}",
            "LPT\u{b9}",
            "LPT\u{b3}",
        ] {
            assert!(is_reserved_device_stem(reserved), "{reserved}");
        }
        for plain in [
            "COM10",
            "COM",
            "LPT",
            "CONN",
            "COMA",
            "NULL",
            "",
            "COM\u{2074}",
        ] {
            assert!(!is_reserved_device_stem(plain), "{plain}");
        }
    }

    #[test]
    fn components_are_plain_only_without_trailing_dot_space_or_device_stem() {
        for kept in [
            "NUL",
            "nul.txt",
            "com1.txt",
            "Lpt9",
            "name.",
            "name ",
            "com\u{b9}",
            "NUL .x",
        ] {
            assert!(!is_plain_component(kept), "{kept}");
        }
        for plain in ["com10", "a b", "file.txt", "console", ".hidden"] {
            assert!(is_plain_component(plain), "{plain}");
        }
    }

    #[test]
    fn verbatim_disk_paths_simplify_only_when_equivalent() {
        for (raw, expected) in [
            (r"\\?\C:\config\a.yaml", Some(r"C:\config\a.yaml")),
            (r"\\?\C:\", Some(r"C:\")),
            (r"\\?\C:\dir\com10", Some(r"C:\dir\com10")),
            (r"\\?\UNC\server\share\a", None),
            (r"\\?\Volume{1}\a", None),
            (r"\\?\C:", None),
            (r"\\?\C:\dir\NUL.txt", None),
            ("\\\\?\\C:\\dir\\com\u{b9}", None),
            (r"\\?\C:\dir.\a", None),
            (r"\\?\C:\dir\a ", None),
            (r"C:\plain", None),
        ] {
            assert_eq!(plain_verbatim_disk(raw), expected, "{raw}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn path_wrapper_keeps_non_unicode_and_plain_paths() {
        use std::os::windows::ffi::OsStringExt;
        let odd = PathBuf::from(std::ffi::OsString::from_wide(&[
            0x5c, 0x5c, 0x3f, 0x5c, 0x43, 0x3a, 0x5c, 0xd800,
        ]));
        assert_eq!(without_verbatim_prefix(odd.clone()), odd);
        assert_eq!(
            without_verbatim_prefix(PathBuf::from(r"\\?\C:\a")),
            PathBuf::from(r"C:\a")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn path_wrapper_is_identity_off_windows() {
        let path = PathBuf::from(r"\\?\C:\a");
        assert_eq!(without_verbatim_prefix(path.clone()), path);
    }
}
