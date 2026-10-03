//! Consumed command ownership shared by native execution modes.

use super::{Command, HeldCommand};

/// A consumed prepared command, retaining a held executable's borrow when used.
///
/// Construct with `Command::into()` or `HeldCommand::into()`. Consumption prevents
/// the child-only setup from persisting into a subsequent execution.
pub struct OwnedPreparedCommand<'a>(PreparedCommand<'a>);

enum PreparedCommand<'a> {
    Plain(Command),
    Held(HeldCommand<'a>),
}

impl From<Command> for OwnedPreparedCommand<'_> {
    fn from(command: Command) -> Self {
        Self(PreparedCommand::Plain(command))
    }
}

impl<'a> From<HeldCommand<'a>> for OwnedPreparedCommand<'a> {
    fn from(command: HeldCommand<'a>) -> Self {
        Self(PreparedCommand::Held(command))
    }
}

impl OwnedPreparedCommand<'_> {
    pub(super) fn command_mut(&mut self) -> &mut Command {
        match &mut self.0 {
            PreparedCommand::Plain(command) => command,
            PreparedCommand::Held(command) => &mut command.command,
        }
    }
}
