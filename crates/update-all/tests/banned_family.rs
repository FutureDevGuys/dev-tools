// Banned-family test harness for Rust workspaces.
// Reason: Generated test harness intentionally uses indexing, printing, and
// assertions for portability; these lints do not apply to the harness itself.
#![allow(
    clippy::collapsible_if,
    clippy::indexing_slicing,
    clippy::needless_range_loop,
    clippy::print_stderr,
    clippy::panic,
    missing_docs
)]
//
// Copy into any Rust repo as `tests/banned_family.rs` (or any crate's tests/).
//
// What it does:
// - Fails the test if *non-test* Rust code contains banned-family calls.
// - Skips test-only code: `#[cfg(test)]` blocks, `mod tests { ... }`, and
//   test-only directories (`tests/`, `test/`, `benches/`, `examples/`, `fixtures/`).
// - Honors same-line `// INVARIANT:` escapes for `unwrap`/`expect`/`unreachable` families.
// - Use this together with clippy lints (see clippy-lints.toml) to cover
//   broader non-idiomatic patterns.
//
// Defaults:
// - Always scans the workspace root; also scans `crates/` if it exists.
// - You can override scan roots via env var: BANNED_FAMILY_ROOTS="src,crates,apps"
//   (comma-separated, relative to workspace root).
//
// Usage:
// - Run: `cargo test -p <crate> --test banned_family --locked`
// - Works best when your CI runs `cargo test --workspace`.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

enum MatchKind {
    MacroOrCall,
    MacroOnly,
}

const BANNED_PREFIXES: &[(&str, MatchKind)] = &[
    ("unwrap", MatchKind::MacroOrCall),
    ("unwrap_err", MatchKind::MacroOrCall),
    ("unwrap_unchecked", MatchKind::MacroOrCall),
    ("expect", MatchKind::MacroOrCall),
    ("expect_err", MatchKind::MacroOrCall),
    ("panic", MatchKind::MacroOrCall),
    ("todo", MatchKind::MacroOrCall),
    ("unimplemented", MatchKind::MacroOrCall),
    ("unreachable", MatchKind::MacroOrCall),
    ("dbg", MatchKind::MacroOnly),
];

#[test]
fn banned_family_is_absent_in_production_code() {
    let root = workspace_root().expect("workspace root");
    let scan_roots = resolve_scan_roots(&root);
    let mut violations = Vec::new();
    let mut seen_files = HashSet::new();

    for root in scan_roots {
        for path in collect_rust_files(&root) {
            let canonical_path = match fs::canonicalize(&path) {
                Ok(canonical) => canonical,
                Err(err) => {
                    eprintln!("warn: canonicalize failed for {}: {err}", path.display());
                    path.clone()
                }
            };
            if !seen_files.insert(canonical_path) {
                continue;
            }
            let source = fs::read_to_string(&path).expect("read source");
            let sanitized = strip_comments_and_strings(&source);
            let raw_lines: Vec<&str> = source.lines().collect();
            let sanitized_lines: Vec<&str> = sanitized.lines().collect();
            let skip_lines = compute_test_line_mask(&raw_lines, &sanitized_lines);

            let mut unsafe_impl_state = UnsafeImplState::searching();
            for (line_idx, line) in sanitized_lines.iter().enumerate() {
                if skip_lines.get(line_idx).copied().unwrap_or(false) {
                    continue;
                }
                let raw_line = raw_lines.get(line_idx).copied().unwrap_or("");
                let has_invariant = raw_line.contains("// INVARIANT:");
                let line_no = line_idx + 1;
                for (prefix, kind) in BANNED_PREFIXES {
                    if let Some(col) = find_banned_prefix(line, prefix, kind) {
                        if has_invariant && is_invariant_escapable_prefix(prefix) {
                            continue;
                        }
                        violations.push(format!(
                            "{}:{}:{}: banned `{}` family call",
                            path.display(),
                            line_no,
                            col + 1,
                            prefix
                        ));
                    }
                }
                if is_unsafe_impl_send_or_sync_violation(line, raw_line, &mut unsafe_impl_state) {
                    violations.push(format!(
                        "{}:{}:1: banned `unsafe impl Send/Sync`",
                        path.display(),
                        line_no,
                    ));
                }
            }
        }
    }

    if !violations.is_empty() {
        let mut message = String::from("banned-family usage found:\n");
        for violation in violations {
            message.push_str("  ");
            message.push_str(&violation);
            message.push('\n');
        }
        panic!("{}", message);
    }
}

fn workspace_root() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // clone: dir is mutated by pop(); manifest_dir remains as fallback.
    let mut dir = manifest_dir.clone();
    loop {
        let manifest = dir.join("Cargo.toml");
        let has_workspace_manifest = manifest.exists()
            && fs::read_to_string(&manifest)
                .map(|contents| contents.contains("[workspace]"))
                .unwrap_or(false);
        if has_workspace_manifest {
            return Some(dir);
        }
        if !dir.pop() {
            break;
        }
    }
    // Fall back to the crate's own manifest directory. This also covers runs
    // from workspace members where no ancestor Cargo.toml declares [workspace].
    Some(manifest_dir)
}

fn resolve_scan_roots(root: &Path) -> Vec<PathBuf> {
    let canonical_root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    if let Ok(value) = std::env::var("BANNED_FAMILY_ROOTS") {
        let mut roots = Vec::new();
        for part in value.split(',') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            let requested = Path::new(trimmed);
            if requested.is_absolute() {
                continue;
            }
            let candidate = root.join(requested);
            let canonical_candidate = match fs::canonicalize(&candidate) {
                Ok(path) => path,
                Err(_) => continue,
            };
            if !canonical_candidate.starts_with(&canonical_root) {
                continue;
            }
            if canonical_candidate.is_dir() {
                roots.push(canonical_candidate);
            }
        }
        if !roots.is_empty() {
            return roots;
        }
    }

    let mut roots = vec![root.to_path_buf()];
    let crates_dir = root.join("crates");
    if crates_dir.is_dir() {
        roots.push(crates_dir);
    }
    roots
}

fn collect_rust_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut visited_dirs = HashSet::new();
    while let Some(dir) = stack.pop() {
        let canonical_dir = match fs::canonicalize(&dir) {
            Ok(path) => path,
            Err(_) => continue,
        };
        if !visited_dirs.insert(canonical_dir) {
            continue;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let mut sorted_entries = Vec::new();
        for entry in entries {
            match entry {
                Ok(value) => sorted_entries.push(value),
                Err(err) => {
                    eprintln!(
                        "warning: failed to read an entry under {}: {err}",
                        dir.display()
                    );
                }
            }
        }
        sorted_entries.sort_by_key(|entry| entry.path());
        for entry in sorted_entries {
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(value) => value,
                Err(_) => continue,
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                if should_skip_dir(&path) {
                    continue;
                }
                stack.push(path);
            } else if file_type.is_file()
                && path.extension().and_then(|ext| ext.to_str()) == Some("rs")
            {
                if should_skip_file(&path) {
                    continue;
                }
                files.push(path);
            }
        }
    }
    files.sort_unstable();
    files
}

fn should_skip_dir(path: &Path) -> bool {
    path.components().any(|component| {
        let name = component.as_os_str().to_string_lossy();
        matches!(
            name.as_ref(),
            "target" | ".git" | ".local" | "vendor" | "node_modules"
        ) || is_test_only_component(name.as_ref())
    })
}

fn should_skip_file(path: &Path) -> bool {
    if path
        .parent()
        .map(|parent| {
            parent.components().any(|component| {
                let segment = component.as_os_str().to_string_lossy();
                is_test_only_component(segment.as_ref())
            })
        })
        .unwrap_or(false)
    {
        return true;
    }

    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name == "tests.rs" || name.ends_with("_test.rs")
}

fn is_test_only_component(name: &str) -> bool {
    matches!(
        name,
        "test"
            | "tests"
            | "testdata"
            | "bench"
            | "benches"
            | "example"
            | "examples"
            | "fixture"
            | "fixtures"
    )
}

fn is_cfg_test_attr(line: &str) -> bool {
    let trimmed = line.trim();
    let Some(inner) = trimmed.strip_prefix("#[cfg(") else {
        return false;
    };
    let Some(end_idx) = inner.find(")]") else {
        return false;
    };
    has_non_negated_test_token(&inner[..end_idx])
}

fn parse_cfg_test_attribute_at(lines: &[&str], start_idx: usize) -> Option<(String, usize)> {
    let trimmed = lines[start_idx].trim();
    let mut remainder = trimmed.strip_prefix("#[cfg(")?;
    let mut expr = String::new();
    let mut idx = start_idx;
    loop {
        if let Some(end_idx) = remainder.find(")]") {
            let before_end = remainder[..end_idx].trim();
            if !before_end.is_empty() {
                if !expr.is_empty() {
                    expr.push(' ');
                }
                expr.push_str(before_end);
            }
            return Some((expr, idx));
        }

        let chunk = remainder.trim();
        if !chunk.is_empty() {
            if !expr.is_empty() {
                expr.push(' ');
            }
            expr.push_str(chunk);
        }

        idx += 1;
        if idx >= lines.len() {
            return None;
        }
        remainder = lines[idx].trim();
    }
}

fn has_non_negated_test_token(expr: &str) -> bool {
    let compact: String = expr
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    let bytes = compact.as_bytes();
    let mut idx = 0usize;
    let mut in_string = false;
    let mut stack: Vec<(bool, bool)> = Vec::new();

    while idx < bytes.len() {
        let b = bytes[idx];
        if in_string {
            if b == b'\\' && idx + 1 < bytes.len() {
                idx += 2;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            idx += 1;
            continue;
        }

        if b == b'"' {
            in_string = true;
            idx += 1;
            continue;
        }

        if is_ident_char(b) {
            let start = idx;
            idx += 1;
            while idx < bytes.len() && is_ident_char(bytes[idx]) {
                idx += 1;
            }
            let ident = &compact[start..idx];
            if idx < bytes.len() && bytes[idx] == b'(' {
                let is_not = ident == "not";
                let is_any = ident == "any";
                stack.push((is_not, is_any));
                idx += 1;
                continue;
            }
            if ident == "test" {
                let negated = stack.iter().any(|(is_not, _)| *is_not);
                let inside_any = stack.iter().any(|(_, is_any)| *is_any);
                if !negated && !inside_any {
                    return true;
                }
            }
            continue;
        }

        if b == b'(' {
            stack.push((false, false));
        } else if b == b')' {
            stack.pop();
        }
        idx += 1;
    }

    false
}

fn is_tests_module_decl(line: &str) -> bool {
    let trimmed = line.trim_start();
    const TEST_MODULE_PREFIXES: &[&str] = &["mod tests", "pub mod tests", "pub(crate) mod tests"];
    TEST_MODULE_PREFIXES.iter().any(|prefix| {
        if !trimmed.starts_with(prefix) {
            return false;
        }
        let remainder = &trimmed[prefix.len()..];
        match remainder.chars().next() {
            None => true,
            Some('{') | Some(';') => true,
            Some(ch) if ch.is_whitespace() => true,
            Some(_) => false,
        }
    })
}

fn brace_delta(line: &str) -> i32 {
    let mut delta = 0;
    for ch in line.chars() {
        match ch {
            '{' => delta += 1,
            '}' => delta -= 1,
            _ => {}
        }
    }
    delta
}

enum CfgAnnotatedItemState {
    Pending,
    Complete,
    Block(i32),
}

fn cfg_annotated_item_state(line: &str) -> CfgAnnotatedItemState {
    if line.contains('{') {
        let delta = brace_delta(line);
        if delta > 0 {
            return CfgAnnotatedItemState::Block(delta);
        }
        return CfgAnnotatedItemState::Complete;
    }
    if line.contains(';') {
        return CfgAnnotatedItemState::Complete;
    }
    CfgAnnotatedItemState::Pending
}

fn compute_test_line_mask(lines: &[&str], sanitized_lines: &[&str]) -> Vec<bool> {
    let mut mask = vec![false; lines.len()];
    let mut pending_cfg_test = false;
    let mut in_cfg_test_block = false;
    let mut cfg_test_depth: i32 = 0;

    let mut idx = 0usize;
    while idx < lines.len() {
        let line = lines[idx];
        if in_cfg_test_block {
            mask[idx] = true;
            cfg_test_depth += brace_delta(sanitized_lines[idx]);
            if cfg_test_depth <= 0 {
                in_cfg_test_block = false;
                cfg_test_depth = 0;
            }
            idx += 1;
            continue;
        }

        if pending_cfg_test {
            mask[idx] = true;
            let trimmed = line.trim();
            // Keep pending state across blank lines and stacked attributes until
            // the cfg(test)-annotated item (module/use/type/etc.) is observed.
            if trimmed.is_empty() || trimmed.starts_with("#[") {
                idx += 1;
                continue;
            }
            match cfg_annotated_item_state(sanitized_lines[idx]) {
                CfgAnnotatedItemState::Block(delta) => {
                    in_cfg_test_block = true;
                    cfg_test_depth = delta;
                    pending_cfg_test = false;
                }
                CfgAnnotatedItemState::Complete => {
                    pending_cfg_test = false;
                }
                CfgAnnotatedItemState::Pending => {
                    pending_cfg_test = true;
                }
            }
            idx += 1;
            continue;
        }

        if let Some((expr, attr_end_idx)) = parse_cfg_test_attribute_at(lines, idx) {
            if has_non_negated_test_token(&expr) {
                for item in mask.iter_mut().take(attr_end_idx + 1).skip(idx) {
                    *item = true;
                }
                let delta = brace_delta(sanitized_lines[attr_end_idx]);
                let has_trailing_item = sanitized_lines[attr_end_idx]
                    .split_once(")]")
                    .map(|(_, trailing)| !trailing.trim().is_empty())
                    .unwrap_or(false);
                if delta != 0 {
                    in_cfg_test_block = true;
                    cfg_test_depth = delta;
                    pending_cfg_test = false;
                } else if !has_trailing_item {
                    pending_cfg_test = true;
                } else if let Some((_, trailing)) = sanitized_lines[attr_end_idx].split_once(")]") {
                    match cfg_annotated_item_state(trailing) {
                        CfgAnnotatedItemState::Block(inner_delta) => {
                            in_cfg_test_block = true;
                            cfg_test_depth = inner_delta;
                            pending_cfg_test = false;
                        }
                        CfgAnnotatedItemState::Complete => {
                            pending_cfg_test = false;
                        }
                        CfgAnnotatedItemState::Pending => {
                            pending_cfg_test = true;
                        }
                    }
                }
                idx = attr_end_idx + 1;
                continue;
            }
        }

        if is_tests_module_decl(line) {
            mask[idx] = true;
            let delta = brace_delta(sanitized_lines[idx]);
            if delta != 0 {
                in_cfg_test_block = true;
                cfg_test_depth = delta;
            }
        }
        idx += 1;
    }

    mask
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_invariant_escapable_prefix(prefix: &str) -> bool {
    matches!(
        prefix,
        "unwrap" | "unwrap_err" | "unwrap_unchecked" | "expect" | "expect_err" | "unreachable"
    )
}

fn find_banned_prefix(line: &str, prefix: &str, kind: &MatchKind) -> Option<usize> {
    let bytes = line.as_bytes();
    let prefix_bytes = prefix.as_bytes();
    let mut i = 0;
    while i + prefix_bytes.len() <= bytes.len() {
        if &bytes[i..i + prefix_bytes.len()] == prefix_bytes {
            if i > 0 && is_ident_char(bytes[i - 1]) {
                i += 1;
                continue;
            }
            let mut j = i + prefix_bytes.len();
            while j < bytes.len() && is_ident_char(bytes[j]) {
                j += 1;
            }
            match kind {
                MatchKind::MacroOnly => {
                    let mut k = j;
                    while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                        k += 1;
                    }
                    if k < bytes.len() && bytes[k] == b'!' {
                        return Some(i);
                    }
                }
                MatchKind::MacroOrCall => {
                    let mut k = j;
                    while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                        k += 1;
                    }
                    if k < bytes.len() && bytes[k] == b'!' {
                        return Some(i);
                    }
                    if j == i + prefix_bytes.len() {
                        let mut call_idx = j;
                        while call_idx < bytes.len() && bytes[call_idx].is_ascii_whitespace() {
                            call_idx += 1;
                        }
                        if call_idx < bytes.len() && bytes[call_idx] == b'(' {
                            return Some(i);
                        }
                    }
                }
            }
        }
        i += 1;
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnsafeImplPhase {
    Searching,
    SawUnsafe,
    SawUnsafeImpl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnsafeImplState {
    phase: UnsafeImplPhase,
    // Only meaningful when `phase == SawUnsafeImpl`.
    impl_generic_depth: usize,
    // Escape marker discovered on `unsafe impl` line before `Send`/`Sync` appears.
    impl_escape_pending: bool,
}

impl UnsafeImplState {
    fn searching() -> Self {
        Self {
            phase: UnsafeImplPhase::Searching,
            impl_generic_depth: 0,
            impl_escape_pending: false,
        }
    }

    fn set_phase(&mut self, phase: UnsafeImplPhase) {
        self.phase = phase;
        if phase != UnsafeImplPhase::SawUnsafeImpl {
            self.impl_generic_depth = 0;
            self.impl_escape_pending = false;
        }
    }

    fn take_pending_escape(&mut self) -> bool {
        let pending = self.impl_escape_pending;
        self.impl_escape_pending = false;
        pending
    }
}

fn contains_unsafe_impl_send_or_sync(
    line: &str,
    raw_line: &str,
    state: &mut UnsafeImplState,
) -> bool {
    let has_escape_marker = has_unsafe_impl_escape(raw_line);
    let mut i = 0;
    let bytes = line.as_bytes();
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let token = &line[start..i];
            let next_phase = match (state.phase, token) {
                (_, "unsafe") => UnsafeImplPhase::SawUnsafe,
                (UnsafeImplPhase::SawUnsafe, "impl") => {
                    if has_escape_marker {
                        state.impl_escape_pending = true;
                    }
                    UnsafeImplPhase::SawUnsafeImpl
                }
                (UnsafeImplPhase::SawUnsafeImpl, "for") => UnsafeImplPhase::Searching,
                (UnsafeImplPhase::SawUnsafeImpl, "where") => UnsafeImplPhase::Searching,
                (UnsafeImplPhase::SawUnsafeImpl, "Send" | "Sync")
                    if state.impl_generic_depth == 0 =>
                {
                    return true;
                }
                (UnsafeImplPhase::SawUnsafe, _) => UnsafeImplPhase::Searching,
                _ => state.phase,
            };
            state.set_phase(next_phase);
            continue;
        }
        if state.phase == UnsafeImplPhase::SawUnsafeImpl {
            if b == b'<' {
                state.impl_generic_depth += 1;
                i += 1;
                continue;
            }
            if b == b'>' && state.impl_generic_depth > 0 {
                state.impl_generic_depth -= 1;
                i += 1;
                continue;
            }
        }
        if matches!(b, b';' | b'{' | b'}') {
            state.set_phase(UnsafeImplPhase::Searching);
        }
        i += 1;
    }
    false
}

fn is_unsafe_impl_send_or_sync_violation(
    sanitized_line: &str,
    raw_line: &str,
    state: &mut UnsafeImplState,
) -> bool {
    if !contains_unsafe_impl_send_or_sync(sanitized_line, raw_line, state) {
        return false;
    }
    let escaped_on_current_line = has_unsafe_impl_escape(raw_line);
    let escaped_on_impl_line = state.take_pending_escape();
    state.set_phase(UnsafeImplPhase::Searching);
    !escaped_on_current_line && !escaped_on_impl_line
}

fn has_unsafe_impl_escape(raw_line: &str) -> bool {
    let bytes = raw_line.as_bytes();
    let mut i = 0usize;
    let mut in_string = false;
    let mut in_char = false;
    let mut raw_hashes: Option<usize> = None;
    let mut block_comment_depth = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        let next = bytes.get(i + 1).copied().unwrap_or(b'\0');

        if let Some(hashes) = raw_hashes {
            if b == b'"' {
                if hashes == 0 {
                    raw_hashes = None;
                    i += 1;
                    continue;
                }
                let mut matched = 0usize;
                let mut j = i + 1;
                while matched < hashes && j < bytes.len() && bytes[j] == b'#' {
                    matched += 1;
                    j += 1;
                }
                if matched == hashes {
                    raw_hashes = None;
                    i = j;
                    continue;
                }
            }
            i += 1;
            continue;
        }

        if block_comment_depth > 0 {
            if b == b'/' && next == b'*' {
                block_comment_depth += 1;
                i += 2;
                continue;
            }
            if b == b'*' && next == b'/' {
                block_comment_depth -= 1;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        if in_string {
            if b == b'\\' {
                i += usize::from(i + 1 < bytes.len()) + 1;
            } else {
                if b == b'"' {
                    in_string = false;
                }
                i += 1;
            }
            continue;
        }

        if in_char {
            if b == b'\\' {
                i += usize::from(i + 1 < bytes.len()) + 1;
            } else {
                if b == b'\'' {
                    in_char = false;
                }
                i += 1;
            }
            continue;
        }

        if b == b'/' && next == b'/' {
            let comment = &raw_line[i..];
            return comment.contains("// ALLOW:") || comment.contains("// SAFETY:");
        }
        if b == b'/' && next == b'*' {
            block_comment_depth = 1;
            i += 2;
            continue;
        }

        if b == b'r' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] == b'#' {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                raw_hashes = Some(j - (i + 1));
                i = j + 1;
                continue;
            }
        }

        if b == b'"' {
            in_string = true;
            i += 1;
            continue;
        }
        if b == b'\'' {
            in_char = true;
            i += 1;
            continue;
        }
        i += 1;
    }

    false
}

fn strip_comments_and_strings(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut in_line_comment = false;
    let mut block_comment_depth = 0usize;
    let mut in_string = false;
    let mut in_char = false;
    let mut raw_hashes: Option<usize> = None;

    while i < bytes.len() {
        let b = bytes[i];
        let next = bytes.get(i + 1).copied().unwrap_or(b'\0');

        if in_line_comment {
            if b == b'\n' {
                in_line_comment = false;
                out.push(b);
            } else {
                push_placeholder(&mut out, b);
            }
            i += 1;
            continue;
        }

        if block_comment_depth > 0 {
            if b == b'/' && next == b'*' {
                push_placeholder(&mut out, b);
                push_placeholder(&mut out, next);
                block_comment_depth += 1;
                i += 2;
            } else if b == b'*' && next == b'/' {
                push_placeholder(&mut out, b);
                push_placeholder(&mut out, next);
                block_comment_depth -= 1;
                i += 2;
            } else {
                push_placeholder(&mut out, b);
                i += 1;
            }
            continue;
        }

        if let Some(hashes) = raw_hashes {
            if b == b'"' {
                if hashes == 0 {
                    push_placeholder(&mut out, b);
                    raw_hashes = None;
                    i += 1;
                    continue;
                }
                let mut matches = 0;
                let mut j = i + 1;
                while matches < hashes && j < bytes.len() && bytes[j] == b'#' {
                    matches += 1;
                    j += 1;
                }
                if matches == hashes {
                    push_placeholder(&mut out, b);
                    for _ in 0..hashes {
                        push_placeholder(&mut out, b'#');
                    }
                    raw_hashes = None;
                    i = j;
                    continue;
                }
            }
            push_placeholder(&mut out, b);
            i += 1;
            continue;
        }

        if in_string {
            if b == b'\\' {
                push_placeholder(&mut out, b);
                if i + 1 < bytes.len() {
                    push_placeholder(&mut out, bytes[i + 1]);
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            push_placeholder(&mut out, b);
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        if in_char {
            if b == b'\\' {
                push_placeholder(&mut out, b);
                if i + 1 < bytes.len() {
                    push_placeholder(&mut out, bytes[i + 1]);
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            push_placeholder(&mut out, b);
            if b == b'\'' {
                in_char = false;
            }
            i += 1;
            continue;
        }

        if b == b'/' && next == b'/' {
            push_placeholder(&mut out, b);
            push_placeholder(&mut out, next);
            in_line_comment = true;
            i += 2;
            continue;
        }
        if b == b'/' && next == b'*' {
            push_placeholder(&mut out, b);
            push_placeholder(&mut out, next);
            block_comment_depth = 1;
            i += 2;
            continue;
        }

        if b == b'\'' {
            if is_lifetime_start(bytes, i) {
                out.push(b);
            } else {
                push_placeholder(&mut out, b);
                in_char = true;
            }
            i += 1;
            continue;
        }

        if b == b'"' {
            push_placeholder(&mut out, b);
            in_string = true;
            i += 1;
            continue;
        }

        if b == b'r' || (b == b'b' && next == b'r') {
            let mut j = i + 1;
            if b == b'b' {
                j += 1;
            }
            let mut hashes = 0usize;
            while j < bytes.len() && bytes[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                push_placeholder(&mut out, b);
                if b == b'b' {
                    push_placeholder(&mut out, next);
                }
                for _ in 0..hashes {
                    push_placeholder(&mut out, b'#');
                }
                push_placeholder(&mut out, b'"');
                raw_hashes = Some(hashes);
                i = j + 1;
                continue;
            }
        }

        out.push(b);
        i += 1;
    }

    String::from_utf8_lossy(&out).to_string()
}

fn is_lifetime_start(bytes: &[u8], quote_idx: usize) -> bool {
    if quote_idx + 1 >= bytes.len() {
        return false;
    }
    let next = bytes[quote_idx + 1];
    if !(next.is_ascii_alphabetic() || next == b'_') {
        return false;
    }
    if quote_idx + 2 < bytes.len() && bytes[quote_idx + 2] == b'\'' {
        // Character literal like `'x'`.
        return false;
    }
    let Some(prev) = prev_non_whitespace_byte(bytes, quote_idx) else {
        return false;
    };
    matches!(prev, b'&' | b'<' | b',' | b'(' | b':' | b'+' | b'>' | b'=')
}

fn prev_non_whitespace_byte(bytes: &[u8], end_idx: usize) -> Option<u8> {
    if end_idx == 0 {
        return None;
    }
    let mut idx = end_idx;
    while idx > 0 {
        idx -= 1;
        let b = bytes[idx];
        if !b.is_ascii_whitespace() {
            return Some(b);
        }
    }
    None
}

fn push_placeholder(out: &mut Vec<u8>, b: u8) {
    if b == b'\n' {
        out.push(b'\n');
    } else {
        out.push(b' ');
    }
}

#[cfg(test)]
mod tests {
    use super::{
        compute_test_line_mask, contains_unsafe_impl_send_or_sync, find_banned_prefix,
        is_cfg_test_attr, resolve_scan_roots, should_skip_file, strip_comments_and_strings,
        MatchKind,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "banned-family-{label}-{}-{}",
            std::process::id(),
            nanos
        ))
    }

    #[test]
    fn cfg_test_single_line_item_does_not_mask_following_production_code() {
        let lines = vec![
            "#[cfg(test)]",
            "fn test_setup() {}",
            "",
            "fn prod() { panic!(\"bug\"); }",
        ];
        let mask = compute_test_line_mask(&lines, &lines);
        assert_eq!(mask, vec![true, true, false, false]);
    }

    #[test]
    fn cfg_not_test_attr_is_not_treated_as_test_only() {
        assert!(!is_cfg_test_attr("#[cfg(not(test))]"));
    }

    #[test]
    fn cfg_any_test_with_non_test_branch_is_not_treated_as_test_only() {
        assert!(!is_cfg_test_attr("#[cfg(any(test, feature = \"bench\"))]"));
    }

    #[test]
    fn cfg_not_any_test_attr_is_not_treated_as_test_only() {
        assert!(!is_cfg_test_attr(
            "#[cfg(not(any(test, feature = \"bench\")))]"
        ));
    }

    #[test]
    fn cfg_feature_string_named_test_is_not_treated_as_cfg_test() {
        assert!(!is_cfg_test_attr("#[cfg(feature = \"test\")]"));
    }

    #[test]
    fn multiline_cfg_test_attribute_masks_only_test_item() {
        let lines = vec![
            "#[cfg(",
            "    test,",
            ")]",
            "fn helper() { panic!(\"only in tests\"); }",
            "fn prod() { panic!(\"should be scanned\"); }",
        ];
        let mask = compute_test_line_mask(&lines, &lines);
        assert_eq!(mask, vec![true, true, true, true, false]);
    }

    #[test]
    fn multiline_cfg_test_with_trailing_comment_masks_following_item() {
        let raw = [
            "#[cfg(",
            "    test",
            ")] // keep",
            "fn helper() { panic!(\"only in tests\"); }",
            "fn prod() { panic!(\"should be scanned\"); }",
        ];
        let source = raw.join("\n");
        let sanitized_source = strip_comments_and_strings(&source);
        let raw_lines: Vec<&str> = source.lines().collect();
        let sanitized_lines: Vec<&str> = sanitized_source.lines().collect();
        let mask = compute_test_line_mask(&raw_lines, &sanitized_lines);
        assert_eq!(mask, vec![true, true, true, true, false]);
    }

    #[test]
    fn cfg_test_brace_on_next_line_masks_entire_item() {
        let lines = vec![
            "#[cfg(test)]",
            "fn helper()",
            "{",
            "    panic!(\"only in tests\");",
            "}",
            "fn prod() { panic!(\"should be scanned\"); }",
        ];
        let mask = compute_test_line_mask(&lines, &lines);
        assert_eq!(mask, vec![true, true, true, true, true, false]);
    }

    #[test]
    fn lifetime_annotations_do_not_mask_following_code() {
        let source = "fn conn() -> &'static str { value.unwrap() }";
        let sanitized = strip_comments_and_strings(source);
        assert!(sanitized.contains("value.unwrap()"));
    }

    #[test]
    fn find_banned_prefix_detects_unwrap_expect_err_variants() {
        assert_eq!(
            find_banned_prefix("value.unwrap_err()", "unwrap_err", &MatchKind::MacroOrCall),
            Some(6)
        );
        assert_eq!(
            find_banned_prefix(
                "unsafe { value.unwrap_unchecked() }",
                "unwrap_unchecked",
                &MatchKind::MacroOrCall
            ),
            Some(15)
        );
        assert_eq!(
            find_banned_prefix(
                "result.expect_err(\"boom\")",
                "expect_err",
                &MatchKind::MacroOrCall
            ),
            Some(7)
        );
    }

    #[test]
    fn find_banned_prefix_does_not_match_similar_non_banned_names() {
        assert_eq!(
            find_banned_prefix(
                "value.unwrap_or_default()",
                "unwrap",
                &MatchKind::MacroOrCall
            ),
            None
        );
        assert_eq!(
            find_banned_prefix("ctx.expectation()", "expect", &MatchKind::MacroOrCall),
            None
        );
    }

    #[test]
    fn should_skip_file_for_test_helpers_in_tests_dir() {
        assert!(should_skip_file(Path::new("src/tests/helpers.rs")));
        assert!(should_skip_file(Path::new("crates/api/fixtures/setup.rs")));
        assert!(!should_skip_file(Path::new("src/testing.rs")));
    }

    #[test]
    fn tests_module_declaration_line_is_masked() {
        let lines = vec!["mod tests;", "fn prod() { panic!(\"bug\"); }"];
        let mask = compute_test_line_mask(&lines, &lines);
        assert_eq!(mask, vec![true, false]);
    }

    #[test]
    fn resolve_scan_roots_includes_root_and_crates_for_mixed_layout() {
        let root = unique_temp_dir("roots");
        let src_dir = root.join("src");
        let crates_dir = root.join("crates");
        fs::create_dir_all(&src_dir).expect("create root src");
        fs::create_dir_all(&crates_dir).expect("create crates dir");
        fs::write(src_dir.join("lib.rs"), "pub fn root_pkg() {}").expect("write root src");

        let roots = resolve_scan_roots(&root);
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0], root);
        assert_eq!(roots[1], crates_dir);

        fs::remove_dir_all(&root).expect("cleanup temp workspace");
    }

    #[test]
    fn unsafe_impl_send_sync_detection_is_token_aware() {
        let mut state = super::UnsafeImplState::searching();
        assert!(contains_unsafe_impl_send_or_sync(
            "unsafe impl Send for Worker {}",
            "unsafe impl Send for Worker {}",
            &mut state
        ));
        state = super::UnsafeImplState::searching();
        assert!(contains_unsafe_impl_send_or_sync(
            "unsafe impl<T> Sync for Cache<T> {}",
            "unsafe impl<T> Sync for Cache<T> {}",
            &mut state
        ));
        let sanitized = strip_comments_and_strings("let msg = \"unsafe impl Send\";");
        state = super::UnsafeImplState::searching();
        assert!(!contains_unsafe_impl_send_or_sync(
            &sanitized,
            "let msg = \"unsafe impl Send\";",
            &mut state
        ));
        state = super::UnsafeImplState::searching();
        assert!(!contains_unsafe_impl_send_or_sync(
            "impl Send for Worker {}",
            "impl Send for Worker {}",
            &mut state
        ));
    }

    #[test]
    fn unsafe_impl_send_sync_detection_spans_multiple_lines() {
        let mut state = super::UnsafeImplState::searching();
        assert!(!super::is_unsafe_impl_send_or_sync_violation(
            "unsafe impl<T>",
            "unsafe impl<T>",
            &mut state
        ));
        assert!(super::is_unsafe_impl_send_or_sync_violation(
            "Send for Worker<T> {}",
            "Send for Worker<T> {}",
            &mut state
        ));
        assert!(!super::is_unsafe_impl_send_or_sync_violation(
            "let keep_scanning = Send;",
            "let keep_scanning = Send;",
            &mut state
        ));
    }

    #[test]
    fn unsafe_impl_send_sync_detection_ignores_generic_bounds() {
        let mut state = super::UnsafeImplState::searching();
        assert!(!contains_unsafe_impl_send_or_sync(
            "unsafe impl<T: Send + Sync> Service for Worker<T> {}",
            "unsafe impl<T: Send + Sync> Service for Worker<T> {}",
            &mut state
        ));
        state = super::UnsafeImplState::searching();
        assert!(!contains_unsafe_impl_send_or_sync(
            "unsafe impl<T>",
            "unsafe impl<T>",
            &mut state
        ));
        assert!(!contains_unsafe_impl_send_or_sync(
            "Service for Worker<T>",
            "Service for Worker<T>",
            &mut state
        ));
        assert!(!contains_unsafe_impl_send_or_sync(
            "where T: Send + Sync {}",
            "where T: Send + Sync {}",
            &mut state
        ));
    }

    #[test]
    fn unsafe_impl_send_sync_escape_hatches_are_detected() {
        assert!(super::has_unsafe_impl_escape(
            "unsafe impl Send for Worker {} // SAFETY: bounded by internal runtime invariants"
        ));
        assert!(super::has_unsafe_impl_escape(
            "unsafe impl Sync for Cache {} // ALLOW: required for compatibility"
        ));
        assert!(!super::has_unsafe_impl_escape(
            "unsafe impl Send for Worker {}"
        ));
    }

    #[test]
    fn unsafe_impl_escape_on_same_line_is_not_a_violation() {
        let raw = "unsafe impl Send for Worker {} // SAFETY: bounded by runtime invariants";
        let sanitized = strip_comments_and_strings(raw);
        let mut state = super::UnsafeImplState::searching();
        assert!(!super::is_unsafe_impl_send_or_sync_violation(
            &sanitized, raw, &mut state
        ));
    }

    #[test]
    fn unsafe_impl_escape_ignores_string_literal_markers() {
        let raw = "static DOCS: &str = \"// SAFETY: fake\"; unsafe impl Send for Worker {}";
        let sanitized = strip_comments_and_strings(raw);
        let mut state = super::UnsafeImplState::searching();
        assert!(super::is_unsafe_impl_send_or_sync_violation(
            &sanitized, raw, &mut state
        ));
    }

    #[test]
    fn unsafe_impl_escape_ignores_block_comment_markers() {
        let raw = "/* // SAFETY: fake */ unsafe impl Send for Worker {}";
        let sanitized = strip_comments_and_strings(raw);
        let mut state = super::UnsafeImplState::searching();
        assert!(super::is_unsafe_impl_send_or_sync_violation(
            &sanitized, raw, &mut state
        ));
    }

    #[test]
    fn unsafe_impl_escape_on_impl_line_applies_to_multiline_send() {
        let mut state = super::UnsafeImplState::searching();
        let raw_impl_line = "unsafe impl<T> // SAFETY: marker applies to the impl";
        let impl_line = strip_comments_and_strings(raw_impl_line);
        assert!(!super::is_unsafe_impl_send_or_sync_violation(
            &impl_line,
            raw_impl_line,
            &mut state
        ));
        assert_eq!(state.phase, super::UnsafeImplPhase::SawUnsafeImpl);
        assert!(state.impl_escape_pending);
        let raw_send_line = "Send for Worker<T> {}";
        assert!(!super::is_unsafe_impl_send_or_sync_violation(
            raw_send_line,
            raw_send_line,
            &mut state
        ));
    }

    #[test]
    fn nested_block_comments_remain_sanitized() {
        let source = "/* outer /* nested unsafe impl Send */ still comment */\nfn ok() {}";
        let sanitized = strip_comments_and_strings(source);
        assert!(!sanitized.contains("unsafe impl Send"));
    }
}
