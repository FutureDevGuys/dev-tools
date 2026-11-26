use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().context("JSON target has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))
}

pub fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut size = 0;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size += read as u64;
    }
    Ok((hasher.finalize().to_hex().to_string(), size))
}

pub fn directory_size(path: &Path) -> u64 {
    walkdir::WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.metadata().ok())
        .filter(|meta| meta.is_file())
        .map(|meta| meta.len())
        .sum()
}

/// Join a slash-separated relative path using the platform separator.
pub fn join_slashed(base: &Path, relative: &str) -> PathBuf {
    base.join(relative.split('/').collect::<PathBuf>())
}

/// Canonicalize, dropping the Windows verbatim prefix that other tools reject.
pub fn canonicalize(path: &Path) -> std::io::Result<PathBuf> {
    path.canonicalize().map(plain_path)
}

#[cfg(not(windows))]
fn plain_path(path: PathBuf) -> PathBuf {
    path
}

// `\\?\X:\...` becomes `X:\...` only where the plain form names the same
// file: no reserved device-name or trailing-dot/space component. Long plain
// paths stay equivalent because std re-adds the prefix when it needs one.
#[cfg(windows)]
fn plain_path(path: PathBuf) -> PathBuf {
    use std::path::Prefix;

    let mut components = path.components();
    let Some(std::path::Component::Prefix(prefix)) = components.next() else {
        return path;
    };
    let Prefix::VerbatimDisk(letter) = prefix.kind() else {
        return path;
    };
    let rest = components.as_path();
    let plain = PathBuf::from(format!("{}:", letter as char)).join(rest);
    if !rest.components().all(plain_component) {
        return path;
    }
    plain
}

#[cfg(windows)]
fn plain_component(component: std::path::Component<'_>) -> bool {
    let std::path::Component::Normal(name) = component else {
        return matches!(component, std::path::Component::RootDir);
    };
    let Some(name) = name.to_str() else {
        return false;
    };
    if name.ends_with(['.', ' ']) {
        return false;
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or(name)
        .trim_end()
        .to_ascii_uppercase();
    let mut chars = stem.chars();
    let numbered = matches!(
        (
            chars.next(),
            chars.next(),
            chars.next(),
            chars.next(),
            chars.next()
        ),
        (
            Some('C'),
            Some('O'),
            Some('M'),
            Some('0'..='9' | '¹' | '²' | '³'),
            None
        ) | (
            Some('L'),
            Some('P'),
            Some('T'),
            Some('0'..='9' | '¹' | '²' | '³'),
            None
        )
    );
    let reserved = numbered
        || matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        );
    !reserved
}

pub fn path_from_home(raw: &Path) -> PathBuf {
    let text = raw.to_string_lossy();
    if text == "~" {
        return crate::config::home_dir();
    }
    if let Some(rest) = text.strip_prefix("~/") {
        return crate::config::home_dir().join(rest);
    }
    raw.to_path_buf()
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    fn plain(text: &str) -> PathBuf {
        plain_path(PathBuf::from(text))
    }

    #[test]
    fn verbatim_disk_paths_are_simplified_only_when_the_plain_form_is_equivalent() {
        assert_eq!(
            plain(r"\\?\C:\Users\a b\cache"),
            Path::new(r"C:\Users\a b\cache")
        );
        assert_eq!(plain(r"\\?\C:\"), Path::new(r"C:\"));
        for kept in [
            r"\\?\UNC\server\share\x",
            r"\\?\C:\dir\NUL",
            r"\\?\C:\dir\com1.txt",
            r"\\?\C:\dir\name.",
            r"\\?\C:\dir\name ",
            r"C:\plain",
        ] {
            assert_eq!(plain(kept), Path::new(kept), "{kept}");
        }
        let long = format!(r"\\?\C:\{}", "a".repeat(260));
        assert_eq!(plain(&long), Path::new(&long[4..]));
        for kept in [r"\\?\C:\com0", r"\\?\C:\LPT²", r"\\?\C:\Lpt9.txt"] {
            assert_eq!(plain(kept), Path::new(kept), "{kept}");
        }
        assert_eq!(plain(r"\\?\C:\com10"), Path::new(r"C:\com10"));
    }
}
