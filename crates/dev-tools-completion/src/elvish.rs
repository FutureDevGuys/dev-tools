// Adapted from clap_complete 4.6.9, src/aot/shells/elvish.rs.
// Copyright clap contributors. Licensed under MIT OR Apache-2.0.
// Upstream: https://github.com/clap-rs/clap
// Local changes: render into a String; emit visible option choices after an
// explicit option token, but never after `--`. Retains upstream command-path
// parsing (leading subcommands before the first option), not a full Clap parser.
// Remove when the native option-value regressions pass upstream.

use clap::{Arg, Command};
use clap_complete::generator::utils;

pub(super) fn render(command: &Command, binary: &str) -> String {
    let cases = command_cases(command, binary);
    format!(
        r#"
use builtin;
use str;

set edit:completion:arg-completer[{binary}] = {{|@words|
    fn spaces {{|n|
        if (< $n 0) {{ set n = 0 }}
        builtin:repeat $n ' ' | str:join ''
    }}
    fn cand {{|text desc|
        edit:complex-candidate $text &display=$text' '(spaces (- 14 (wcswidth $text)))$desc
    }}
    var command = '{binary}'
    var ended = $false
    for word $words[1..-1] {{
        if (eq $word '--') {{ set ended = $true }}
    }}
    for word $words[1..-1] {{
        if (str:has-prefix $word '-') {{ break }}
        set command = $command';'$word
    }}
    var previous = ''
    if (> (count $words) 2) {{ set previous = $words[-2] }}
    var completions = [{cases}
    ]
    if (has-key $completions $command) {{ $completions[$command] }}
}}
"#
    )
}

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

fn candidate(name: &str, help: Option<String>) -> String {
    format!(
        "\n            cand {} {}",
        quote(name),
        quote(&help.unwrap_or_else(|| name.to_owned()).replace('\n', " "))
    )
}

fn option_names(argument: &Arg) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(shorts) = argument.get_short_and_visible_aliases() {
        names.extend(shorts.into_iter().map(|name| format!("-{name}")));
    }
    if let Some(longs) = argument.get_long_and_visible_aliases() {
        names.extend(longs.into_iter().map(|name| format!("--{name}")));
    }
    names
}

fn command_cases(command: &Command, path: &str) -> String {
    let mut body = String::from("\n            var offered = $false");
    for argument in command.get_opts() {
        if let Some(values) = argument.get_value_parser().possible_values() {
            let choices = values
                .filter(|value| !value.is_hide_set())
                .map(|value| candidate(value.get_name(), value.get_help().map(ToString::to_string)))
                .collect::<String>();
            if !choices.is_empty() {
                for name in option_names(argument) {
                    body.push_str(&format!(
                        "\n            if (and (not $ended) (eq $previous {})) {{{choices}\n                set offered = $true\n            }}",
                        quote(&name)
                    ));
                }
            }
        }
    }
    body.push_str("\n            if (not $offered) {");
    let flags = utils::flags(command);
    for argument in command.get_opts().chain(flags.iter()) {
        for name in option_names(argument) {
            body.push_str(&candidate(
                &name,
                argument.get_help().map(ToString::to_string),
            ));
        }
    }
    for child in command.get_subcommands() {
        for name in child.get_name_and_visible_aliases() {
            body.push_str(&candidate(name, child.get_about().map(ToString::to_string)));
        }
    }
    body.push_str("\n            }");
    let mut result = format!("\n        &{}= {{{body}\n        }}", quote(path));
    for child in command.get_subcommands() {
        for name in child.get_name_and_visible_aliases() {
            result.push_str(&command_cases(child, &format!("{path};{name}")));
        }
    }
    result
}
