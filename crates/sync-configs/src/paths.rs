use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathPlatform {
    Posix,
    Windows,
}

impl PathPlatform {
    pub const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Posix
        }
    }
}

#[derive(Clone, Debug)]
pub struct PathContext {
    pub platform: PathPlatform,
    pub cwd: PathBuf,
    pub home: Option<PathBuf>,
    pub temp_dir: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
}

impl PathContext {
    pub fn new(
        platform: PathPlatform,
        cwd: PathBuf,
        home: Option<PathBuf>,
        temp_dir: PathBuf,
        environment: BTreeMap<OsString, OsString>,
    ) -> Self {
        Self {
            platform,
            cwd,
            home,
            temp_dir,
            environment,
        }
    }

    pub fn from_current_environment() -> Result<Self, PathError> {
        let environment: BTreeMap<OsString, OsString> = env::vars_os().collect();
        let platform = PathPlatform::current();
        let home =
            match platform {
                PathPlatform::Posix => environment.get(OsStr::new("HOME")).cloned(),
                PathPlatform::Windows => environment
                    .get(OsStr::new("USERPROFILE"))
                    .cloned()
                    .or_else(|| {
                        let drive = environment.get(OsStr::new("HOMEDRIVE"))?;
                        let path = environment.get(OsStr::new("HOMEPATH"))?;
                        let mut joined = drive.clone();
                        joined.push(path);
                        Some(joined)
                    }),
            }
            .map(PathBuf::from);
        Ok(Self {
            platform,
            cwd: env::current_dir().map_err(PathError::CurrentDirectory)?,
            home,
            temp_dir: env::temp_dir(),
            environment,
        })
    }

    fn environment_value(&self, name: &str) -> Option<&OsString> {
        if self.platform == PathPlatform::Windows {
            self.environment.iter().find_map(|(key, value)| {
                key.to_str()
                    .is_some_and(|key| key.eq_ignore_ascii_case(name))
                    .then_some(value)
            })
        } else {
            self.environment.get(OsStr::new(name))
        }
    }
}

#[derive(Debug, Error)]
pub enum PathError {
    #[error("cannot determine the current directory: {0}")]
    CurrentDirectory(std::io::Error),
    #[error("cannot expand current-user home in path because no home directory is available")]
    MissingHome,
    #[error("named-user home expansion is unsupported: {0}")]
    NamedUserHome(String),
}

fn is_variable_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_variable_continue(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn push_literal(output: &mut OsString, raw: &str, start: usize, end: usize) {
    if start < end {
        output.push(&raw[start..end]);
    }
}

fn expand_dollar_variables(raw: &str, context: &PathContext) -> OsString {
    let bytes = raw.as_bytes();
    let mut output = OsString::new();
    let mut literal_start = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'$' {
            index += 1;
            continue;
        }
        let variable = if index + 1 < bytes.len() && bytes[index + 1] == b'{' {
            let Some(close_offset) = raw[index + 2..].find('}') else {
                index += 1;
                continue;
            };
            let close = index + 2 + close_offset;
            let name = &raw[index + 2..close];
            (!name.is_empty()).then_some((name, close + 1))
        } else {
            let start = index + 1;
            if start >= bytes.len() || !is_variable_start(bytes[start]) {
                index += 1;
                continue;
            }
            let mut end = start + 1;
            while end < bytes.len() && is_variable_continue(bytes[end]) {
                end += 1;
            }
            Some((&raw[start..end], end))
        };
        let Some((name, end)) = variable else {
            index += 1;
            continue;
        };
        let Some(value) = context.environment_value(name) else {
            index = end;
            continue;
        };
        push_literal(&mut output, raw, literal_start, index);
        output.push(value);
        literal_start = end;
        index = end;
    }
    push_literal(&mut output, raw, literal_start, raw.len());
    output
}

fn expand_percent_variables(raw: OsString, context: &PathContext) -> OsString {
    let Some(raw) = raw.to_str() else {
        return raw;
    };
    let mut output = OsString::new();
    let mut literal_start = 0;
    let mut index = 0;
    while index < raw.len() {
        let Some(open_offset) = raw[index..].find('%') else {
            break;
        };
        let open = index + open_offset;
        let Some(close_offset) = raw[open + 1..].find('%') else {
            break;
        };
        let close = open + 1 + close_offset;
        let name = &raw[open + 1..close];
        let Some(value) = context.environment_value(name) else {
            index = close + 1;
            continue;
        };
        push_literal(&mut output, raw, literal_start, open);
        output.push(value);
        literal_start = close + 1;
        index = close + 1;
    }
    push_literal(&mut output, raw, literal_start, raw.len());
    output
}

fn expand_environment(raw: &str, context: &PathContext) -> OsString {
    let expanded = expand_dollar_variables(raw, context);
    if context.platform == PathPlatform::Windows {
        expand_percent_variables(expanded, context)
    } else {
        expanded
    }
}

fn windows_separators(path: OsString) -> OsString {
    let Some(path) = path.to_str() else {
        return path;
    };
    OsString::from(path.replace('/', "\\"))
}

fn platform_join(base: &Path, child: &Path, platform: PathPlatform) -> PathBuf {
    if platform != PathPlatform::Windows || cfg!(windows) {
        return base.join(child);
    }
    let Some(base) = base.to_str() else {
        return base.join(child);
    };
    let Some(child) = child.to_str() else {
        return PathBuf::from(base).join(child);
    };
    let base = base.trim_end_matches(['/', '\\']);
    let child = child.trim_start_matches(['/', '\\']);
    PathBuf::from(format!("{base}\\{child}"))
}

fn map_windows_temp(path: OsString, context: &PathContext) -> PathBuf {
    let Some(path) = path.to_str() else {
        return PathBuf::from(path);
    };
    let unix_style = path.replace('\\', "/");
    for prefix in ["/tmp", "/var/tmp"] {
        if unix_style == prefix || unix_style.starts_with(&format!("{prefix}/")) {
            let remainder = unix_style[prefix.len()..].trim_start_matches('/');
            if remainder.is_empty() {
                return context.temp_dir.clone();
            }
            return platform_join(
                &context.temp_dir,
                Path::new(&remainder.replace('/', "\\")),
                PathPlatform::Windows,
            );
        }
    }
    PathBuf::from(windows_separators(OsString::from(path)))
}

pub fn normalize_user_path(raw: &str, context: &PathContext) -> Result<PathBuf, PathError> {
    let expanded = if raw == "~" {
        context
            .home
            .clone()
            .ok_or(PathError::MissingHome)?
            .into_os_string()
    } else if raw.starts_with("~/") || raw.starts_with("~\\") {
        let home = context.home.as_ref().ok_or(PathError::MissingHome)?;
        let suffix = expand_environment(&raw[2..], context);
        let suffix = if context.platform == PathPlatform::Windows {
            windows_separators(suffix)
        } else {
            suffix
        };
        platform_join(home, Path::new(&suffix), context.platform).into_os_string()
    } else if raw.starts_with('~') {
        return Err(PathError::NamedUserHome(raw.to_owned()));
    } else {
        expand_environment(raw, context)
    };

    if context.platform == PathPlatform::Windows {
        Ok(map_windows_temp(expanded, context))
    } else {
        Ok(PathBuf::from(expanded))
    }
}

pub fn is_absolute_for(path: &Path, platform: PathPlatform) -> bool {
    if platform != PathPlatform::Windows || cfg!(windows) {
        return path.is_absolute();
    }
    let Some(path) = path.to_str() else {
        return false;
    };
    let bytes = path.as_bytes();
    path.starts_with(['/', '\\'])
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\'))
}

fn lexical_normalize_posix(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let can_pop_normal_component = result
                    .file_name()
                    .is_some_and(|name| name != OsStr::new(".."));
                if can_pop_normal_component {
                    result.pop();
                } else if !path.is_absolute() {
                    result.push("..");
                }
            }
            other => result.push(other.as_os_str()),
        }
    }
    if result.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        result
    }
}

fn lexical_normalize_windows(path: &Path) -> PathBuf {
    let Some(path) = path.to_str() else {
        return path.to_path_buf();
    };
    let path = path.replace('/', "\\");
    let (prefix, remainder) = if path.starts_with("\\\\") {
        ("\\\\", path.trim_start_matches('\\'))
    } else if path.len() >= 2 && path.as_bytes()[1] == b':' {
        (&path[..2], path[2..].trim_start_matches('\\'))
    } else if path.starts_with('\\') {
        ("\\", path.trim_start_matches('\\'))
    } else {
        ("", path.as_str())
    };
    let rooted = !prefix.is_empty();
    let mut parts: Vec<&str> = Vec::new();
    for part in remainder.split('\\') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|part| *part != "..") => {
                parts.pop();
            }
            ".." if !rooted => parts.push(part),
            ".." => {}
            other => parts.push(other),
        }
    }
    let separator = if prefix.ends_with('\\') || parts.is_empty() {
        ""
    } else {
        "\\"
    };
    PathBuf::from(format!("{prefix}{separator}{}", parts.join("\\")))
}

pub fn lexical_normalize(path: &Path, platform: PathPlatform) -> PathBuf {
    if platform == PathPlatform::Windows && !cfg!(windows) {
        lexical_normalize_windows(path)
    } else {
        lexical_normalize_posix(path)
    }
}

pub fn resolve_against(
    raw: &str,
    base: &Path,
    context: &PathContext,
) -> Result<PathBuf, PathError> {
    let normalized = normalize_user_path(raw, context)?;
    let absolute = if is_absolute_for(&normalized, context.platform) {
        normalized
    } else {
        platform_join(base, &normalized, context.platform)
    };
    Ok(lexical_normalize(&absolute, context.platform))
}

pub fn resolve_config_path(raw: &str, context: &PathContext) -> Result<PathBuf, PathError> {
    resolve_against(raw, &context.cwd, context)
}

pub fn contains_parent_component(raw: &str) -> bool {
    raw.replace('\\', "/").split('/').any(|part| part == "..")
}

pub fn contains_glob(raw: &str) -> bool {
    raw.bytes().any(|byte| matches!(byte, b'*' | b'?' | b'['))
}

pub fn candidate_source_override(path: &Path) -> PathBuf {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return path.to_path_buf();
    };
    if name.contains(".override") {
        return path.to_path_buf();
    }
    let candidate = match (
        path.file_stem().and_then(OsStr::to_str),
        path.extension().and_then(OsStr::to_str),
    ) {
        (Some(stem), Some(extension)) => format!("{stem}.override.{extension}"),
        _ => format!("{name}.override"),
    };
    path.with_file_name(candidate)
}

pub fn manifest_override_path(path: &Path) -> PathBuf {
    let stem = path.file_stem().and_then(OsStr::to_str).unwrap_or_default();
    match path.extension().and_then(OsStr::to_str) {
        Some(extension) => path.with_file_name(format!("{stem}.override.{extension}")),
        None => path.with_file_name(format!("{stem}.override")),
    }
}

pub fn canonical_target_key(path: &Path, context: &PathContext) -> PathBuf {
    let absolute = if is_absolute_for(path, context.platform) {
        path.to_path_buf()
    } else {
        platform_join(&context.cwd, path, context.platform)
    };
    let normalized = lexical_normalize(&absolute, context.platform);
    if context.platform == PathPlatform::Windows {
        normalized
            .to_str()
            .map(|path| PathBuf::from(path.to_lowercase()))
            .unwrap_or(normalized)
    } else {
        normalized
    }
}
