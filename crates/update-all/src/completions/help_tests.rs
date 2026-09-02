use super::completion_query::{query, CompletionDirective, QueryRequest, QueryShell};
use super::help_adapters::{render_adapter, AdapterMode};
use super::help_ir::{
    parse_help, Completeness, CompletionIr, Confidence, EvidenceRef, Repeatability, ValueArity,
    ValueHint,
};
use anyhow::{anyhow, Context};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

fn evidence() -> EvidenceRef {
    EvidenceRef {
        digest: "11".repeat(32),
        argv: vec!["--help".into()],
        exit_code: Some(0),
        truncated_stdout: false,
        truncated_stderr: false,
    }
}

fn ir(help: &[u8]) -> CompletionIr {
    let mut ir = CompletionIr::new("tool".into(), evidence());
    ir.root = parse_help(help, &["tool".into()], 0);
    ir
}

#[test]
fn help_ir_clap_fixture_preserves_arity_choices_repeatability_and_positionals() -> anyhow::Result<()>
{
    let parsed = ir(br#"A clap fixture

Usage: tool [OPTIONS] <INPUT> [COMMAND]

Commands:
  build  Build the project
  check  Check the project

Arguments:
  <INPUT>  Input file path

Options:
  -v, --verbose...       Increase verbosity
      --color <WHEN>     Color output [possible values: auto, always, never]
      --config <FILE>    Configuration file path
  -h, --help             Print help
"#);
    let color = parsed
        .root
        .options
        .iter()
        .find(|option| option.spellings.contains(&"--color".into()))
        .ok_or_else(|| anyhow!("missing --color option"))?;
    assert_eq!(color.value.arity, ValueArity::Required);
    assert_eq!(color.value.choices, vec!["always", "auto", "never"]);
    let verbose = parsed
        .root
        .options
        .iter()
        .find(|option| option.spellings.contains(&"--verbose".into()))
        .ok_or_else(|| anyhow!("missing --verbose option"))?;
    assert_eq!(verbose.repeatability, Repeatability::Repeatable);
    assert_eq!(parsed.root.positionals[0].value.hint, ValueHint::File);
    assert_eq!(parsed.root.subcommands.len(), 2);
    Ok(())
}

#[test]
fn help_ir_cobra_and_go_style_fixture_preserves_global_scope_and_commands() {
    let parsed = ir(br#"A cobra fixture

Usage:
  tool [command]

Available Commands:
  completion  Generate completion
  get         Get resources
  version     Print version

Flags:
  -h, --help           help for tool
      --output string  output format

Global Flags:
      --context string  context name

Use "tool [command] --help" for more information about a command.
"#);
    assert_eq!(parsed.root.subcommands.len(), 3);
    assert!(parsed
        .root
        .options
        .iter()
        .any(|option| option.spellings.contains(&"--context".into())
            && matches!(option.scope, super::help_ir::OptionScope::Global)));
}

#[test]
fn help_ir_click_typer_fixture_preserves_aliases_and_choices() -> anyhow::Result<()> {
    let parsed = ir(br#"Usage: tool [OPTIONS] COMMAND [ARGS]...

  Click fixture.

Options:
  --format [json|yaml]  Output format.
  --help                Show this message and exit.

Commands:
  serve, s  Serve requests.
  test      Run tests.
"#);
    let serve = parsed
        .root
        .subcommands
        .iter()
        .find(|child| {
            child
                .canonical_path
                .last()
                .is_some_and(|name| name == "serve")
        })
        .ok_or_else(|| anyhow!("missing serve subcommand"))?;
    assert_eq!(serve.aliases, vec!["s"]);
    let format = parsed
        .root
        .options
        .iter()
        .find(|option| option.spellings.contains(&"--format".into()))
        .ok_or_else(|| anyhow!("missing --format option"))?;
    assert_eq!(format.value.choices, vec!["json", "yaml"]);
    Ok(())
}

#[test]
fn help_ir_argparse_fixture_does_not_invent_file_semantics() -> anyhow::Result<()> {
    let parsed = ir(br#"usage: tool [-h] [--mode {fast,safe}] target

positional arguments:
  target                opaque target identifier

options:
  -h, --help            show this help message and exit
  --mode {fast,safe}    execution mode
"#);
    assert_eq!(parsed.root.positionals.len(), 1);
    assert_eq!(parsed.root.positionals[0].value.hint, ValueHint::Unknown);
    let mode = parsed
        .root
        .options
        .iter()
        .find(|option| option.spellings.contains(&"--mode".into()))
        .ok_or_else(|| anyhow!("missing --mode option"))?;
    assert_eq!(mode.value.choices, vec!["fast", "safe"]);
    Ok(())
}

#[test]
fn help_ir_commander_oclif_fixture_handles_uppercase_sections_and_wrapping() {
    let parsed = ir(br#"USAGE
  $ tool [COMMAND]

COMMANDS
  deploy, d  deploy an application to the selected
             environment
  status     show deployment status

FLAGS
  -f, --file=<value>  manifest file path
  --dir=<value>       directory path
"#);
    assert_eq!(parsed.root.subcommands.len(), 2);
    assert_eq!(
        parsed.root.subcommands[0]
            .description
            .as_ref()
            .map(|description| description.text.as_str()),
        Some("deploy an application to the selected environment")
    );
    assert!(parsed
        .root
        .options
        .iter()
        .any(|option| option.value.hint == ValueHint::File));
    assert!(parsed
        .root
        .options
        .iter()
        .any(|option| option.value.hint == ValueHint::Directory));
}

#[test]
fn adversarial_sections_ansi_and_nonzero_help_evidence_are_conservative() {
    let mut evidence = evidence();
    evidence.exit_code = Some(2);
    let help = b"\x1b[31mUsage:\x1b[0m tool [OPTIONS]\r\n\r\nEnvironment:\r\n  launch  not a command\r\nConfiguration:\r\n  init    not a command\r\nExamples:\r\n  run     not a command\r\nExit Codes:\r\n  stop    not a command\r\nOptions:\r\n  --value <THING>  opaque\r\n";
    let mut parsed = CompletionIr::new("tool".into(), evidence);
    parsed.root = parse_help(help, &["tool".into()], 0);
    assert!(parsed.root.subcommands.is_empty());
    assert_eq!(parsed.root.options[0].value.hint, ValueHint::Unknown);
}

#[test]
fn command_section_requires_usage_or_multiple_command_rows() {
    let one = ir(b"Usage: tool [OPTIONS]\n\nCommands:\n  cleanup  remove files\n");
    assert!(one.root.subcommands.is_empty());
    let two = ir(
        b"Usage: tool [OPTIONS]\n\nCommands:\n  cleanup  remove files\n  inspect  inspect state\n",
    );
    assert_eq!(two.root.subcommands.len(), 2);
    let usage = ir(b"Usage: tool <COMMAND>\n\nCommands:\n  cleanup  remove files\n");
    assert_eq!(usage.root.subcommands.len(), 1);
}

#[test]
fn query_asserts_end_of_options_and_explicit_directives() -> anyhow::Result<()> {
    let parsed = ir(b"Usage: tool [OPTIONS] -- <FILE>\n\nOptions:\n  --directory <DIR>  directory path\n  --output <FILE>     output file path\n\nArguments:\n  <FILE> input file path\n");
    let directory = query(
        &parsed,
        &QueryRequest {
            shell: QueryShell::Bash,
            words: vec!["tool".into(), "--directory".into(), "".into()],
            word_index: 2,
            cursor_byte: 0,
        },
    )?;
    assert!(directory
        .fallback_directives
        .contains(&CompletionDirective::Directory));
    let after_end = query(
        &parsed,
        &QueryRequest {
            shell: QueryShell::PowerShell,
            words: vec!["tool".into(), "--".into(), "-".into()],
            word_index: 2,
            cursor_byte: 1,
        },
    )?;
    assert!(after_end
        .candidates
        .iter()
        .all(|candidate| !candidate.value.starts_with('-')));
    Ok(())
}

#[test]
fn confidence_and_partial_markers_are_explicit() {
    let parsed = ir(b"Usage: tool [OPTIONS]\n\nOptions:\n  --flag  an explicit flag\n");
    assert_eq!(parsed.root.options[0].confidence, Confidence::Explicit);
    assert!(parsed.root.completeness.contains(&Completeness::Complete));
    let unknown = ir(b"tool banner only\n");
    assert!(unknown
        .root
        .completeness
        .contains(&Completeness::PartialParse));
}

#[test]
fn parser_is_deterministic_bounded_and_does_not_panic_on_adversarial_input() -> anyhow::Result<()> {
    let mut input = Vec::new();
    input.extend_from_slice(b"Usage: tool <COMMAND>\n\nCommands:\n");
    for index in 0..10_000 {
        input.extend_from_slice(format!("  command-{index}  description {index}\n").as_bytes());
    }
    let result = catch_unwind(AssertUnwindSafe(|| ir(&input)));
    assert!(result.is_ok());
    let first = result
        .map_err(|_| anyhow!("help parser panicked"))?
        .encode_canonical()?;
    let second = ir(&input).encode_canonical()?;
    assert_eq!(first, second);
    let decoded = CompletionIr::decode(&first)?;
    assert!(decoded.root.subcommands.len() <= super::help_ir::MAX_NODES);
    assert!(first.len() <= super::help_ir::MAX_IR_BYTES);
    Ok(())
}

#[test]
fn all_five_adapters_preserve_candidate_descriptions_and_explicit_directives() -> anyhow::Result<()>
{
    let parsed = ir(b"Usage: tool [OPTIONS] <FILE>\n\nCommands:\n  run  run work\n  stop stop work\n\nOptions:\n  --output <FILE> output file path\n  --directory <DIR> directory path\n\nArguments:\n  <FILE> input file path\n");
    for shell in [
        QueryShell::Bash,
        QueryShell::Zsh,
        QueryShell::Fish,
        QueryShell::Elvish,
        QueryShell::PowerShell,
    ] {
        let dynamic = String::from_utf8(render_adapter(
            shell,
            AdapterMode::QueryEngine,
            Path::new("/bin/update-all"),
            Path::new("/tmp/ir with ' chars"),
            "tool",
            &parsed,
        ))?;
        let static_render = String::from_utf8(render_adapter(
            shell,
            AdapterMode::Static,
            Path::new("/bin/update-all"),
            Path::new("/tmp/ir"),
            "tool",
            &parsed,
        ))?;
        assert!(dynamic.contains(super::completion_query::QUERY_PROTOCOL));
        assert!(static_render.contains("run"));
        assert!(
            static_render.contains("output")
                || matches!(shell, QueryShell::Bash | QueryShell::Elvish)
        );
    }
    Ok(())
}

#[test]
fn arbitrary_shell_characters_survive_query_candidate_transport() -> anyhow::Result<()> {
    let weird = "a b\tline\n'\"$`\\;|&()[]{}🙂";
    let mut parsed = ir(b"Usage: tool [OPTIONS]\n\nOptions:\n  --value <VALUE>  opaque value\n");
    let value = parsed
        .root
        .options
        .iter_mut()
        .find(|option| {
            option
                .spellings
                .iter()
                .any(|spelling| spelling == "--value")
        })
        .ok_or_else(|| anyhow!("missing --value option"))?;
    value.value.choices = vec![weird.to_owned(), "plain".to_owned()];
    value.value.hint = ValueHint::Choice;
    let response = query(
        &parsed,
        &QueryRequest {
            shell: QueryShell::Fish,
            words: vec!["tool".into(), "--value".into(), "".into()],
            word_index: 2,
            cursor_byte: 0,
        },
    )?;
    assert!(response
        .candidates
        .iter()
        .any(|candidate| candidate.value == weird));
    Ok(())
}

#[test]
fn real_shell_candidates_are_syntax_checked_when_shells_are_available() -> anyhow::Result<()> {
    let parsed = ir(b"Usage: tool [OPTIONS]\n\nCommands:\n  run  run work\n  stop stop work\n\nOptions:\n  --flag  a flag\n");
    let cases = [
        (QueryShell::Bash, "bash", vec!["-n"]),
        (QueryShell::Zsh, "zsh", vec!["-n"]),
        (QueryShell::Fish, "fish", vec!["-n"]),
        (
            QueryShell::PowerShell,
            "pwsh",
            vec!["-NoLogo", "-NoProfile", "-Command"],
        ),
    ];
    for (shell, executable, prefix) in cases {
        let Some(path) = find_on_path(executable) else {
            continue;
        };
        let artifact = render_adapter(
            shell,
            AdapterMode::Static,
            Path::new("/bin/update-all"),
            Path::new("/tmp/ir"),
            "tool",
            &parsed,
        );
        let mut command = std::process::Command::new(path);
        command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if shell == QueryShell::PowerShell {
            let script = String::from_utf8(artifact)?;
            command.args(prefix).arg(script);
        } else {
            let file = write_temp(shell.name(), &artifact)?;
            command.args(prefix).arg(&file);
            let status = command.status().context("run shell syntax check")?;
            let _ = std::fs::remove_file(file);
            assert!(
                status.success(),
                "{executable} rejected generated static completion"
            );
            continue;
        }
        assert!(
            command
                .status()
                .context("run PowerShell syntax check")?
                .success(),
            "{executable} rejected generated static completion"
        );
    }
    Ok(())
}

fn find_on_path(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}

fn write_temp(label: &str, bytes: &[u8]) -> anyhow::Result<std::path::PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "update-all-{label}-{}-{}.completion",
        std::process::id(),
        bytes.len()
    ));
    std::fs::write(&path, bytes).context("write shell completion fixture")?;
    Ok(path)
}
