//! Thin shell adapters for the shared Rust query engine plus deterministic static
//! renderers used when measured query latency misses the release threshold.

use super::completion_query::{QueryShell, QUERY_PROTOCOL, RESPONSE_PROTOCOL};
use super::help_ir::{CommandNode, CompletionIr, ValueArity, ValueHint};
use std::fmt::Write as _;
use std::path::Path;

pub(crate) const ADAPTER_RENDER_VERSION: u16 = 1;
pub(crate) const WARM_P95_LIMIT_MS: u64 = 100;
pub(crate) const COLD_P95_LIMIT_MS: u64 = 250;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdapterMode {
    QueryEngine,
    Static,
}

pub(crate) const DEFAULT_ADAPTER_MODE: AdapterMode = AdapterMode::QueryEngine;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LatencyAssessment {
    pub(crate) warm_p95_ms: u64,
    pub(crate) cold_p95_ms: u64,
    pub(crate) mode: AdapterMode,
}

pub(crate) fn assess_latency(warm_ms: &[u64], cold_ms: &[u64]) -> Option<LatencyAssessment> {
    let warm_p95_ms = percentile_95(warm_ms)?;
    let cold_p95_ms = percentile_95(cold_ms)?;
    Some(LatencyAssessment {
        warm_p95_ms,
        cold_p95_ms,
        mode: if warm_p95_ms <= WARM_P95_LIMIT_MS && cold_p95_ms <= COLD_P95_LIMIT_MS {
            AdapterMode::QueryEngine
        } else {
            AdapterMode::Static
        },
    })
}

fn percentile_95(values: &[u64]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = ((sorted.len() * 95).saturating_add(99) / 100).saturating_sub(1);
    sorted.get(rank).copied()
}

pub(crate) fn render_adapter(
    shell: QueryShell,
    mode: AdapterMode,
    engine: &Path,
    ir_path: &Path,
    command_name: &str,
    ir: &CompletionIr,
) -> Vec<u8> {
    let rendered = match mode {
        AdapterMode::QueryEngine => render_query_adapter(shell, engine, ir_path, command_name),
        AdapterMode::Static => render_static(shell, command_name, ir),
    };
    normalize_artifact(rendered).into_bytes()
}

pub(crate) fn render_query_adapter(
    shell: QueryShell,
    engine: &Path,
    ir_path: &Path,
    command_name: &str,
) -> String {
    match shell {
        QueryShell::Bash => bash_query_adapter(engine, ir_path, command_name),
        QueryShell::Zsh => zsh_query_adapter(engine, ir_path, command_name),
        QueryShell::Fish => fish_query_adapter(engine, ir_path, command_name),
        QueryShell::Elvish => elvish_query_adapter(engine, ir_path, command_name),
        QueryShell::PowerShell => powershell_query_adapter(engine, ir_path, command_name),
    }
}

pub(crate) fn render_static(shell: QueryShell, command_name: &str, ir: &CompletionIr) -> String {
    match shell {
        QueryShell::Bash => bash_static(command_name, &ir.root),
        QueryShell::Zsh => zsh_static(command_name, &ir.root),
        QueryShell::Fish => fish_static(command_name, &ir.root),
        QueryShell::Elvish => elvish_static(command_name, &ir.root),
        QueryShell::PowerShell => powershell_static(command_name, &ir.root),
    }
}

fn bash_query_adapter(engine: &Path, ir: &Path, command: &str) -> String {
    let engine = bash_quote(&engine.to_string_lossy());
    let ir = bash_quote(&ir.to_string_lossy());
    let function = identifier(command);
    format!(
        r#"# update-all help IR query adapter v1
__uac_hex_{function}() {{
    local h="$1" out="" pair
    while [[ -n "$h" ]]; do
        pair="${{h:0:2}}"; h="${{h:2}}"
        printf -v pair '\\x%s' "$pair"
        printf -v pair '%b' "$pair"
        out+="$pair"
    done
    printf '%s' "$out"
}}
__uac_complete_{function}() {{
    local cur="${{COMP_WORDS[COMP_CWORD]}}" line kind value description directives directive response
    COMPREPLY=()
    response=$(command {engine} {protocol} {ir} bash "$COMP_CWORD" "${{#cur}}" -- "${{COMP_WORDS[@]}}") || return 0
    [[ "${{response%%$'\n'*}}" == {response_protocol} ]] || return 0
    while IFS=$'\t' read -r kind value description directives; do
        [[ "$kind" == c ]] || continue
        value=$(__uac_hex_{function} "$value")
        COMPREPLY+=("$value")
        IFS=',' read -ra __uac_directives <<< "$directives"
        for directive in "${{__uac_directives[@]}}"; do
            [[ "$directive" == nospace ]] && compopt -o nospace 2>/dev/null
        done
    done <<< "${{response#*$'\n'}}"
}}
complete -F __uac_complete_{function} -- {command_q}
"#,
        protocol = bash_quote(QUERY_PROTOCOL),
        response_protocol = bash_quote(RESPONSE_PROTOCOL),
        command_q = bash_quote(command),
    )
}

fn zsh_query_adapter(engine: &Path, ir: &Path, command: &str) -> String {
    let function = identifier(command);
    format!(
        r#"#compdef {command_q}
# update-all help IR query adapter v1
__uac_hex_{function}() {{
    local hex="$1" out="" pair
    while [[ -n "$hex" ]]; do
        pair="${{hex[1,2]}}"; hex="${{hex[3,-1]}}"
        printf -v pair '%b' "\\x$pair"
        out+="$pair"
    done
    print -rn -- "$out"
}}
__uac_complete_{function}() {{
    local response line kind value description directives
    local -a values descriptions
    response=$(command {engine} {protocol} {ir} zsh "$((CURRENT-1))" "${{#PREFIX}}" -- "${{words[@]}}") || return 1
    [[ "${{response%%$'\n'*}}" == {response_protocol} ]] || return 1
    while IFS=$'\t' read -r kind value description directives; do
        [[ "$kind" == c ]] || continue
        value=$(__uac_hex_{function} "$value")
        description=$(__uac_hex_{function} "$description")
        values+=("$value")
        descriptions+=("$description")
    done <<< "${{response#*$'\n'}}"
    if (( ${{#values}} )); then
        compadd -d descriptions -- "${{values[@]}}"
    fi
}}
compdef __uac_complete_{function} {command_q}
"#,
        command_q = zsh_quote(command),
        engine = zsh_quote(&engine.to_string_lossy()),
        protocol = zsh_quote(QUERY_PROTOCOL),
        ir = zsh_quote(&ir.to_string_lossy()),
        response_protocol = zsh_quote(RESPONSE_PROTOCOL),
    )
}

fn fish_query_adapter(engine: &Path, ir: &Path, command: &str) -> String {
    let function = identifier(command);
    format!(
        r#"# update-all help IR query adapter v1
function __uac_hex_{function} --argument-names hex
    string replace -ra '(..)' '\\x$1' -- $hex | string unescape
end
function __uac_complete_{function}
    set -l words (commandline -opc)
    set -a words (commandline -ct)
    set -l index (math (count $words) - 1)
    set -l current $words[-1]
    set -l response (command {engine} {protocol} {ir} fish $index (string length -- $current) -- $words)
    test $status -eq 0; or return
    test "$response[1]" = {response_protocol}; or return
    for line in $response[2..-1]
        set -l fields (string split \t -- $line)
        test "$fields[1]" = c; or continue
        set -l value (__uac_hex_{function} $fields[2])
        set -l description (__uac_hex_{function} $fields[3])
        printf '%s\\t%s\\n' "$value" "$description"
    end
end
complete -c {command_q} -f -a '(__uac_complete_{function})'
"#,
        engine = fish_quote(&engine.to_string_lossy()),
        protocol = fish_quote(QUERY_PROTOCOL),
        ir = fish_quote(&ir.to_string_lossy()),
        response_protocol = fish_quote(RESPONSE_PROTOCOL),
        command_q = fish_quote(command),
    )
}

fn elvish_query_adapter(engine: &Path, ir: &Path, command: &str) -> String {
    let function = identifier(command);
    format!(
        r#"# update-all help IR query adapter v1
fn __uac-hex-{function} [hex] {{
  var out = ''
  var rest = $hex
  while (> (count $rest) 0) {{
    var pair = $rest[0..2]
    set rest = $rest[2..]
    set out = $out(printf "\\x$pair")
  }}
  put $out
}}
set edit:completion:arg-completer[{command_q}] = {{|@words|
  var current = ''
  if (> (count $words) 0) {{ set current = $words[-1] }}
  var index = (- (count $words) 1)
  var response = (slurp < <(external {engine} {protocol} {ir} elvish $index (count $current) -- $@words))
  var lines = (splits '\n' $response)
  if (and (> (count $lines) 0) (eq $lines[0] {response_protocol})) {{
    each $lines[1..] {{|line|
      var fields = (splits '\t' $line)
      if (and (>= (count $fields) 4) (eq $fields[0] c)) {{
        put (edit:complex-candidate &code=(__uac-hex-{function} $fields[1]) &display=(__uac-hex-{function} $fields[2]))
      }}
    }}
  }}
}}
"#,
        command_q = elvish_quote(command),
        engine = elvish_quote(&engine.to_string_lossy()),
        protocol = elvish_quote(QUERY_PROTOCOL),
        ir = elvish_quote(&ir.to_string_lossy()),
        response_protocol = elvish_quote(RESPONSE_PROTOCOL),
    )
}

fn powershell_query_adapter(engine: &Path, ir: &Path, command: &str) -> String {
    format!(
        r#"# update-all help IR query adapter v1
function ConvertFrom-UacHex([string] $Hex) {{
    if ([string]::IsNullOrEmpty($Hex)) {{ return '' }}
    $bytes = [byte[]]::new($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {{ $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16) }}
    return [Text.Encoding]::UTF8.GetString($bytes)
}}
Register-ArgumentCompleter -Native -CommandName {command_q} -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)
    $words = @($commandAst.CommandElements | ForEach-Object {{ $_.Extent.Text }})
    $index = [Math]::Max(0, $words.Count - 1)
    $response = & {engine} {protocol} {ir} powershell $index ([Text.Encoding]::UTF8.GetByteCount($wordToComplete)) -- @words
    if ($LASTEXITCODE -ne 0 -or $response[0] -ne {response_protocol}) {{ return }}
    foreach ($line in $response[1..($response.Count - 1)]) {{
        $fields = $line -split "`t", 4
        if ($fields.Count -ne 4 -or $fields[0] -ne 'c') {{ continue }}
        $value = ConvertFrom-UacHex $fields[1]
        $description = ConvertFrom-UacHex $fields[2]
        [System.Management.Automation.CompletionResult]::new($value, $value, 'ParameterValue', $description)
    }}
}}
"#,
        command_q = powershell_quote(command),
        engine = powershell_quote(&engine.to_string_lossy()),
        protocol = powershell_quote(QUERY_PROTOCOL),
        ir = powershell_quote(&ir.to_string_lossy()),
        response_protocol = powershell_quote(RESPONSE_PROTOCOL),
    )
}

fn bash_static(command: &str, node: &CommandNode) -> String {
    let function = identifier(command);
    let words = static_words(node);
    let mut script = format!("# update-all deterministic static fallback v1\n__uac_static_{function}() {{\n  local cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n  COMPREPLY=( $(compgen -W {} -- \"$cur\") )\n", bash_quote(&words.join(" ")));
    append_bash_value_directives(&mut script, node);
    script.push_str("}\ncomplete -F __uac_static_");
    script.push_str(&function);
    script.push_str(" -- ");
    script.push_str(&bash_quote(command));
    script.push('\n');
    script
}

fn zsh_static(command: &str, node: &CommandNode) -> String {
    let function = identifier(command);
    let mut script = format!("#compdef {}\n# update-all deterministic static fallback v1\n__uac_static_{function}() {{\n  local -a values descriptions\n", zsh_quote(command));
    for (value, description) in static_described_words(node) {
        let _ = writeln!(script, "  values+=({})", zsh_quote(&value));
        let _ = writeln!(
            script,
            "  descriptions+=({})",
            zsh_quote(description.as_deref().unwrap_or(""))
        );
    }
    script.push_str("  compadd -d descriptions -- \"${values[@]}\"\n}\ncompdef __uac_static_");
    script.push_str(&function);
    script.push(' ');
    script.push_str(&zsh_quote(command));
    script.push('\n');
    script
}

fn fish_static(command: &str, node: &CommandNode) -> String {
    let mut script = String::from("# update-all deterministic static fallback v1\n");
    for option in &node.options {
        for spelling in &option.spellings {
            let mut line = format!("complete -c {}", fish_quote(command));
            if let Some(long) = spelling.strip_prefix("--") {
                let _ = write!(line, " -l {}", fish_quote(long));
            } else if let Some(short) = spelling.strip_prefix('-') {
                if short.chars().count() == 1 {
                    let _ = write!(line, " -s {}", fish_quote(short));
                }
            }
            if option.value.arity == ValueArity::Required {
                line.push_str(" -r");
            }
            if let Some(description) = &option.description {
                let _ = write!(line, " -d {}", fish_quote(&description.text));
            }
            if !option.value.choices.is_empty() {
                let _ = write!(line, " -a {}", fish_quote(&option.value.choices.join(" ")));
            }
            line.push('\n');
            script.push_str(&line);
        }
    }
    for child in &node.subcommands {
        if let Some(name) = child.canonical_path.last() {
            let description = child
                .description
                .as_ref()
                .map(|d| d.text.as_str())
                .unwrap_or("");
            let _ = writeln!(
                script,
                "complete -c {} -f -a {} -d {}",
                fish_quote(command),
                fish_quote(name),
                fish_quote(description)
            );
        }
    }
    script
}

fn elvish_static(command: &str, node: &CommandNode) -> String {
    let function = identifier(command);
    let mut script = format!("# update-all deterministic static fallback v1\nset edit:completion:arg-completer[{}] = {{|@words|\n", elvish_quote(command));
    for (value, description) in static_described_words(node) {
        let _ = writeln!(
            script,
            "  put (edit:complex-candidate &code={} &display={})",
            elvish_quote(&value),
            elvish_quote(description.as_deref().unwrap_or(&value))
        );
    }
    script.push_str("}\n");
    let _ = function;
    script
}

fn powershell_static(command: &str, node: &CommandNode) -> String {
    let mut script = format!("# update-all deterministic static fallback v1\nRegister-ArgumentCompleter -Native -CommandName {} -ScriptBlock {{\n  param($wordToComplete, $commandAst, $cursorPosition)\n", powershell_quote(command));
    for (value, description) in static_described_words(node) {
        let description = description.unwrap_or_else(|| value.clone());
        let _ = writeln!(script, "  if ({} -like \"$wordToComplete*\") {{ [System.Management.Automation.CompletionResult]::new({}, {}, 'ParameterValue', {}) }}", powershell_quote(&value), powershell_quote(&value), powershell_quote(&value), powershell_quote(&description));
    }
    script.push_str("}\n");
    script
}

fn append_bash_value_directives(script: &mut String, node: &CommandNode) {
    script.push_str("  case \"${COMP_WORDS[COMP_CWORD-1]}\" in\n");
    for option in &node.options {
        let pattern = option.spellings.join("|");
        match option.value.hint {
            ValueHint::File => {
                let _ = writeln!(
                    script,
                    "    {}) COMPREPLY=( $(compgen -f -- \"$cur\") ); return;;",
                    pattern
                );
            }
            ValueHint::Directory => {
                let _ = writeln!(
                    script,
                    "    {}) COMPREPLY=( $(compgen -d -- \"$cur\") ); return;;",
                    pattern
                );
            }
            _ if !option.value.choices.is_empty() => {
                let _ = writeln!(
                    script,
                    "    {}) COMPREPLY=( $(compgen -W {} -- \"$cur\") ); return;;",
                    pattern,
                    bash_quote(&option.value.choices.join(" "))
                );
            }
            _ => {}
        }
    }
    script.push_str("  esac\n");
}

fn static_words(node: &CommandNode) -> Vec<String> {
    static_described_words(node)
        .into_iter()
        .map(|pair| pair.0)
        .collect()
}

fn static_described_words(node: &CommandNode) -> Vec<(String, Option<String>)> {
    let mut values = Vec::new();
    for option in &node.options {
        for spelling in &option.spellings {
            values.push((
                spelling.clone(),
                option.description.as_ref().map(|d| d.text.clone()),
            ));
        }
    }
    for child in &node.subcommands {
        if let Some(name) = child.canonical_path.last() {
            values.push((
                name.clone(),
                child.description.as_ref().map(|d| d.text.clone()),
            ));
        }
        for alias in &child.aliases {
            values.push((
                alias.clone(),
                child.description.as_ref().map(|d| d.text.clone()),
            ));
        }
    }
    values.sort();
    values.dedup();
    values
}

fn normalize_artifact(mut value: String) -> String {
    value = value.replace("\r\n", "\n").replace('\r', "\n");
    while value.ends_with('\n') {
        value.pop();
    }
    value.push('\n');
    value
}

fn identifier(value: &str) -> String {
    let mut output = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            output.push(ch);
        } else {
            output.push('_');
        }
    }
    if output.is_empty() || output.starts_with(|ch: char| ch.is_ascii_digit()) {
        output.insert(0, '_');
    }
    output
}

fn bash_quote(value: &str) -> String {
    single_quote(value)
}
fn zsh_quote(value: &str) -> String {
    single_quote(value)
}
fn fish_quote(value: &str) -> String {
    single_quote(value)
}
fn elvish_quote(value: &str) -> String {
    single_quote(value)
}
fn single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::completions::help_ir::{parse_help, CompletionIr, EvidenceRef};
    use std::path::PathBuf;

    fn ir() -> CompletionIr {
        let evidence = EvidenceRef {
            digest: "00".repeat(32),
            argv: vec![],
            exit_code: Some(0),
            truncated_stdout: false,
            truncated_stderr: false,
        };
        let mut ir = CompletionIr::new("tool".into(), evidence);
        ir.root = parse_help(b"Usage: tool [OPTIONS] <FILE>\n\nCommands:\n  run  run work\n  stop stop work\n\nOptions:\n  --mode <MODE>  {fast,safe}\n  --output <FILE> output file path\n\nArguments:\n  <FILE> input file path\n", &["tool".into()], 0);
        ir
    }

    #[test]
    fn every_shell_has_query_and_static_adapter() {
        for shell in [
            QueryShell::Bash,
            QueryShell::Zsh,
            QueryShell::Fish,
            QueryShell::Elvish,
            QueryShell::PowerShell,
        ] {
            let query = render_adapter(
                shell,
                AdapterMode::QueryEngine,
                Path::new("/bin/update-all"),
                Path::new("/tmp/a b.ir"),
                "odd'cmd",
                &ir(),
            );
            let static_render = render_adapter(
                shell,
                AdapterMode::Static,
                Path::new("/bin/update-all"),
                Path::new("/tmp/a b.ir"),
                "odd'cmd",
                &ir(),
            );
            assert!(String::from_utf8(query).unwrap().contains(QUERY_PROTOCOL));
            assert!(!static_render.is_empty());
        }
    }

    #[test]
    fn latency_miss_selects_static_without_daemon() {
        let assessment = assess_latency(&[10, 20, 101], &[20, 30, 251]).unwrap();
        assert_eq!(assessment.mode, AdapterMode::Static);
        let passing = assess_latency(&[10; 20], &[20; 20]).unwrap();
        assert_eq!(passing.mode, AdapterMode::QueryEngine);
    }

    #[test]
    fn render_is_deterministic() {
        let first = render_adapter(
            QueryShell::Fish,
            AdapterMode::Static,
            &PathBuf::from("engine"),
            &PathBuf::from("ir"),
            "tool",
            &ir(),
        );
        let second = render_adapter(
            QueryShell::Fish,
            AdapterMode::Static,
            &PathBuf::from("engine"),
            &PathBuf::from("ir"),
            "tool",
            &ir(),
        );
        assert_eq!(first, second);
    }
}
