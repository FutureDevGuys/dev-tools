//! Whether a failed system bus call went unanswered. The bus could not
//! deliver it, its destination had no owner or could not be started, or the
//! destination left before it replied. Any other error is the destination's
//! own answer. The service manager and PolicyKit are both such destinations,
//! and both can restart while the coordinator runs.

pub(super) fn unanswered(error: &zbus::Error) -> bool {
    match error {
        zbus::Error::InputOutput(_) | zbus::Error::Connection(..) | zbus::Error::Handshake(_) => {
            true
        }
        zbus::Error::MethodError(name, _, _) => unanswered_reply(name.as_str()),
        zbus::Error::FDO(error) => unanswered_fdo(error),
        _ => false,
    }
}

pub(super) fn unanswered_fdo(error: &zbus::fdo::Error) -> bool {
    match error {
        zbus::fdo::Error::ZBus(error) => unanswered(error),
        error => unanswered_reply(zbus::DBusError::name(error).as_str()),
    }
}

/// Whether an error reply named `name` came from the bus instead of the
/// destination. `Spawn.*` replies are the bus failing to start the
/// destination.
pub(super) fn unanswered_reply(name: &str) -> bool {
    name.strip_prefix("org.freedesktop.DBus.Error.")
        .is_some_and(|name| {
            name.starts_with("Spawn.")
                || matches!(
                    name,
                    "ServiceUnknown"
                        | "NameHasNoOwner"
                        | "NoReply"
                        | "Timeout"
                        | "TimedOut"
                        | "Disconnected"
                        | "NoServer"
                        | "IOError"
                )
        })
}
