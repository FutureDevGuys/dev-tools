//! Static completion rendering, without discovery, execution or publication.
//!
//! The public adapter deliberately accepts Clap 4 command metadata and the
//! re-exported Clap Complete 4 shell selector. All command names, descriptions,
//! values and other metadata must be trusted product-owned definitions: this is
//! a shell-code generator, not a sanitizer for remote or user-supplied text.
#![forbid(unsafe_code)]

use clap::Command;
pub use clap_complete::Shell;

mod elvish;
mod fish;

/// The registration name is not a plain ASCII command identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidCommandName;

impl std::fmt::Display for InvalidCommandName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("completion requires a plain ASCII command name")
    }
}

impl std::error::Error for InvalidCommandName {}

/// Render a trusted command tree for the real command users type.
///
/// The registration name must start with an ASCII letter or underscore and
/// contain only ASCII letters, digits, underscores or hyphens. Metadata is
/// consumed so generator-specific changes cannot leak into another rendering.
/// No configuration, environment, filesystem or external process is consulted.
/// Invalid Clap definitions may panic in the upstream generator; products should
/// validate their static definitions with `Command::debug_assert` in tests.
pub fn render(
    shell: Shell,
    mut command: Command,
    binary_name: &str,
) -> Result<Vec<u8>, InvalidCommandName> {
    if !binary_name
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !binary_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(InvalidCommandName);
    }
    if shell == Shell::Bash {
        bash_command_paths(&mut command, &binary_name.replace('-', "__"));
    }
    let mut bytes = Vec::new();
    if matches!(shell, Shell::Fish | Shell::Elvish) {
        command.set_bin_name(binary_name);
        command.build();
        bytes = match shell {
            Shell::Fish => fish::render(&command, binary_name),
            _ => elvish::render(&command, binary_name),
        }
        .into_bytes();
    } else {
        clap_complete::generate(shell, &mut command, binary_name, &mut bytes);
    }
    Ok(bytes)
}

// clap_complete 4.6.9 encodes root hyphens differently in Bash transitions and
// child-detail labels. Set internal child paths consistently while retaining
// the real registration name. Remove when native nested tests pass without it.
fn bash_command_paths(command: &mut Command, parent: &str) {
    for child in command.get_subcommands_mut() {
        let path = format!("{parent} {}", child.get_name());
        child.set_bin_name(path.clone());
        bash_command_paths(child, &path);
    }
}
