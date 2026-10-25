use super::native::Caller;
use super::{Authority, Failure, GrantRequest, GrantScope};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};

pub(super) const ACTION: &str = "org.futuredevguys.dev-auth.privilege.request";

/// The program a command-scoped grant runs, as its approval names it.
pub(super) struct CommandDisclosure<'a> {
    pub path: &'a OsStr,
    pub sha256: &'a str,
    pub device: u64,
    pub inode: u64,
    pub owner: u32,
    pub argv0: &'a OsStr,
    pub arguments: &'a [OsString],
    pub working_directory: &'a OsStr,
    pub environment: &'a [(OsString, OsString)],
}

/// The longest command an approval shows. A longer command is refused,
/// because an approval cannot authorize what it cannot show.
const MAX_DISCLOSED_COMMAND: usize = 4096;

/// The PolicyKit message and details for one grant request.
pub(super) struct Disclosure {
    pub message: String,
    pub details: Vec<(&'static str, String)>,
}

/// Every caller-supplied byte appears escaped inside quotes, so a path or an
/// argument cannot start a line or forge text in the approval message.
fn quoted(value: &OsStr) -> String {
    format!("\"{}\"", escaped(value))
}

/// Printable ASCII stays readable. Every other byte, and the markup
/// characters that agents such as polkit-gnome interpret, become escapes.
fn escaped(value: &OsStr) -> String {
    value
        .as_encoded_bytes()
        .escape_ascii()
        .to_string()
        .replace('&', "\\x26")
        .replace('<', "\\x3c")
        .replace('>', "\\x3e")
}

pub(super) fn disclosure(
    uid: u32,
    pid: u32,
    request: &GrantRequest,
    command: Option<&CommandDisclosure>,
) -> Result<Disclosure, Failure> {
    let scope = match request.scope {
        GrantScope::User => "all processes of this OS account",
        GrantScope::Workload => "this registered workload and its descendants",
        GrantScope::Command => "the process tree of one command",
    };
    let authority = match &request.authority {
        Authority::Administrator => "unrestricted host administrator authority".to_owned(),
        Authority::ExactPlan { sha256 } => format!("executable plan {sha256} (fixed inputs do not confine the programs' administrator effects)"),
        Authority::Typed { operations } => format!("named operations {} (their administrator effects depend on the configured programs)", operations.join(", ")),
    };
    let program = match (request.scope, command) {
        (GrantScope::Command, Some(command)) => {
            let line = std::iter::once(command.argv0)
                .chain(command.arguments.iter().map(OsString::as_os_str))
                .map(quoted)
                .collect::<Vec<_>>()
                .join(" ");
            let environment = if command.environment.is_empty() {
                "none".to_owned()
            } else {
                command
                    .environment
                    .iter()
                    .map(|(name, value)| format!("{}={}", escaped(name), quoted(value)))
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            let shown = format!(
                "Program: {}, sha256 {}, device {}:{} inode {}, owned by uid {}. Command line: {line}. Working directory: {}. Environment: {environment}. Every process in that tree can run any command as root through sudo. No other process can use the grant, and it ends when the command exits. ",
                quoted(command.path),
                command.sha256,
                rustix::fs::major(command.device),
                rustix::fs::minor(command.device),
                command.inode,
                command.owner,
                quoted(command.working_directory),
            );
            if shown.len() > MAX_DISCLOSED_COMMAND {
                return Err(Failure::InvalidRequest);
            }
            shown
        }
        (GrantScope::Command, None) | (_, Some(_)) => return Err(Failure::InvalidRequest),
        _ => String::new(),
    };
    let message = format!(
        "Allow {authority} for {scope} (user {uid}, requesting process {pid}) for {} seconds? {program}Idle cutoff: {}. Use limit: {}. Existing grants are not extended. Unrestricted commands can change the system and disable enforcement.",
        request.duration_seconds,
        request.idle_seconds.map(|seconds| format!("{seconds} seconds")).unwrap_or_else(|| "none".to_owned()),
        request.uses.map(|uses| uses.to_string()).unwrap_or_else(|| "none".to_owned()));
    let mut details = vec![
        (
            "dev-auth.scope",
            match request.scope {
                GrantScope::User => "user",
                GrantScope::Workload => "workload",
                GrantScope::Command => "command",
            }
            .to_owned(),
        ),
        (
            "dev-auth.duration-seconds",
            request.duration_seconds.to_string(),
        ),
    ];
    if let Some(command) = command {
        details.push(("dev-auth.program", escaped(command.path)));
        details.push(("dev-auth.program-sha256", command.sha256.to_owned()));
    }
    Ok(Disclosure { message, details })
}

/// PolicyKit owns the authentication UI and all credential input. The action
/// uses auth_admin, never an *_keep result or a product-managed password cache.
pub(super) async fn approve(
    caller: &Caller,
    request: &GrantRequest,
    nonce: &str,
    control: &std::os::fd::OwnedFd,
    command: Option<&CommandDisclosure<'_>>,
) -> Result<(), Failure> {
    let disclosure = disclosure(caller.peer.uid, caller.peer.pid, request, command)?;
    let connection = zbus::Connection::system()
        .await
        .map_err(|_| Failure::NativeUnavailable)?;
    let properties = subject_properties(caller.peer.pid, caller.start_time, caller.peer.uid)?;
    let mut details = HashMap::<&str, String>::from_iter(disclosure.details);
    details.insert("polkit.message", disclosure.message);
    let cancellation = format!("dev-auth-{nonce}");
    let body = (
        ("unix-process", properties),
        ACTION,
        details,
        1_u32,
        cancellation.as_str(),
    );
    let pending = connection.call_method(
        Some("org.freedesktop.PolicyKit1"),
        "/org/freedesktop/PolicyKit1/Authority",
        Some("org.freedesktop.PolicyKit1.Authority"),
        "CheckAuthorization",
        &body,
    );
    let connection_alive = async {
        while caller.still_present() && super::native::alive(control) {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    };
    let response = tokio::select! {
        response = tokio::time::timeout(std::time::Duration::from_secs(300), pending) => response,
        _ = connection_alive => {
            cancel(&connection, &cancellation).await;
            return Err(Failure::Interrupted);
        }
    };
    let response = match response {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            cancel(&connection, &cancellation).await;
            return Err(transport_failure(&error));
        }
        Err(_) => {
            eprintln!("dev-auth native approval timed out");
            cancel(&connection, &cancellation).await;
            return Err(Failure::ApprovalDenied);
        }
    };
    let (authorized, challenge, details): (bool, bool, HashMap<String, String>) = response
        .body()
        .deserialize()
        .map_err(|_| Failure::ProtocolViolation)?;
    if !authorized || !caller.still_present() {
        eprintln!(
            "dev-auth native approval not granted: authorized={} challenge={} dismissed={} caller_present={}",
            authorized, challenge, details.contains_key("polkit.dismissed"), caller.still_present(),
        );
        return Err(Failure::ApprovalDenied);
    }
    Ok(())
}

/// The outcome of a request whose approval call failed with `error`.
fn transport_failure(error: &zbus::Error) -> Failure {
    match error {
        zbus::Error::MethodError(name, _, _) => {
            eprintln!("dev-auth native approval transport rejected: {name}");
        }
        _ => eprintln!("dev-auth native approval transport unavailable"),
    }
    Failure::ApprovalDenied
}

fn subject_properties(
    pid: u32,
    start_time: u64,
    uid: u32,
) -> Result<HashMap<&'static str, zbus::zvariant::Value<'static>>, Failure> {
    // PolicyKit's unix-process ABI uses uint32 PID but int32 UID. An unsigned
    // UID is ignored by its parser and silently becomes an unspecified owner.
    let uid = i32::try_from(uid).map_err(|_| Failure::AuthorityDenied)?;
    Ok(HashMap::from([
        ("pid", zbus::zvariant::Value::from(pid)),
        ("start-time", zbus::zvariant::Value::from(start_time)),
        ("uid", zbus::zvariant::Value::from(uid)),
    ]))
}

async fn cancel(connection: &zbus::Connection, cancellation: &str) {
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        connection.call_method(
            Some("org.freedesktop.PolicyKit1"),
            "/org/freedesktop/PolicyKit1/Authority",
            Some("org.freedesktop.PolicyKit1.Authority"),
            "CancelCheckAuthorization",
            &(cancellation,),
        ),
    )
    .await;
}

pub(super) async fn account_has_login(uid: u32) -> Result<bool, Failure> {
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        account_has_login_inner(uid),
    )
    .await
    .map_err(|_| Failure::NativeUnavailable)?
}

async fn account_has_login_inner(uid: u32) -> Result<bool, Failure> {
    let connection = zbus::Connection::system()
        .await
        .map_err(|_| Failure::NativeUnavailable)?;
    let response = connection
        .call_method(
            Some("org.freedesktop.login1"),
            "/org/freedesktop/login1",
            Some("org.freedesktop.login1.Manager"),
            "ListSessions",
            &(),
        )
        .await
        .map_err(|_| Failure::NativeUnavailable)?;
    let sessions: Vec<(String, u32, String, String, zbus::zvariant::OwnedObjectPath)> = response
        .body()
        .deserialize()
        .map_err(|_| Failure::ProtocolViolation)?;
    if sessions.len() > 4096 {
        return Err(Failure::NativeUnavailable);
    }
    for (_, owner, _, _, path) in sessions {
        if owner != uid {
            continue;
        }
        let properties = zbus::fdo::PropertiesProxy::builder(&connection)
            .destination("org.freedesktop.login1")
            .map_err(|_| Failure::NativeUnavailable)?
            .path(path)
            .map_err(|_| Failure::NativeUnavailable)?
            .build()
            .await
            .map_err(|_| Failure::NativeUnavailable)?;
        let interface = zbus::names::InterfaceName::try_from("org.freedesktop.login1.Session")
            .map_err(|_| Failure::NativeUnavailable)?;
        let values = properties
            .get_all(interface)
            .await
            .map_err(|_| Failure::NativeUnavailable)?;
        let value = |name: &str| {
            values
                .get(name)
                .and_then(|value| <&str>::try_from(value).ok())
        };
        if interactive_session(value("Class"), value("Type"), value("State")) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn interactive_session(class: Option<&str>, kind: Option<&str>, state: Option<&str>) -> bool {
    matches!(
        class,
        Some("user" | "user-early" | "user-light" | "user-early-light")
    ) && matches!(kind, Some("tty" | "x11" | "wayland" | "mir"))
        && matches!(state, Some("online" | "active"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command_request() -> GrantRequest {
        GrantRequest::command(Authority::Administrator, 7200)
    }

    fn converge(arguments: &[OsString]) -> CommandDisclosure<'_> {
        converge_with(arguments, &[])
    }

    fn converge_with<'a>(
        arguments: &'a [OsString],
        environment: &'a [(OsString, OsString)],
    ) -> CommandDisclosure<'a> {
        CommandDisclosure {
            path: OsStr::new("/usr/local/bin/converge"),
            sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            device: rustix::fs::makedev(259, 3),
            inode: 131_074,
            owner: 0,
            argv0: OsStr::new("converge"),
            arguments,
            working_directory: OsStr::new("/home/account/project"),
            environment,
        }
    }

    #[test]
    fn a_run_approval_names_the_program_its_arguments_and_unrestricted_root() {
        let arguments = [OsString::from("--apply"), OsString::from("host profile")];
        let shown =
            disclosure(1000, 4242, &command_request(), Some(&converge(&arguments))).unwrap();
        for expected in [
            "unrestricted host administrator authority",
            "the process tree of one command",
            "user 1000, requesting process 4242",
            "for 7200 seconds",
            "Program: \"/usr/local/bin/converge\"",
            "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "device 259:3 inode 131074, owned by uid 0",
            "Command line: \"converge\" \"--apply\" \"host profile\".",
            "Working directory: \"/home/account/project\".",
            "can run any command as root through sudo",
            "it ends when the command exits",
        ] {
            assert!(
                shown.message.contains(expected),
                "missing {expected:?}: {}",
                shown.message
            );
        }
        assert!(shown
            .details
            .contains(&("dev-auth.scope", "command".to_owned())));
        assert!(shown
            .details
            .contains(&("dev-auth.program", "/usr/local/bin/converge".to_owned())));
        assert!(shown.details.contains(&(
            "dev-auth.program-sha256",
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_owned()
        )));
    }

    #[test]
    fn a_run_argument_cannot_forge_text_in_the_approval() {
        use std::os::unix::ffi::OsStringExt;
        let forged = [
            OsString::from("x\". Program: \"/usr/bin/true\nApprove"),
            OsString::from_vec(b"\xff\x1b[2J".to_vec()),
        ];
        let shown = disclosure(1000, 4242, &command_request(), Some(&converge(&forged))).unwrap();
        assert!(!shown.message.contains('\n'), "{}", shown.message);
        assert!(!shown.message.contains('\u{1b}'), "{}", shown.message);
        assert!(
            shown
                .message
                .contains(r#""x\". Program: \"/usr/bin/true\nApprove""#),
            "{}",
            shown.message
        );
        assert!(
            shown.message.contains(r#""\xff\x1b[2J""#),
            "{}",
            shown.message
        );
        assert_eq!(shown.message.matches("Program: \"").count(), 1);
    }

    #[test]
    fn a_run_approval_shows_every_environment_variable_the_program_receives() {
        let environment = [
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
            (
                OsString::from("LD_PRELOAD"),
                OsString::from("/home/account/.cache/x.so"),
            ),
        ];
        let shown = disclosure(
            1000,
            4242,
            &command_request(),
            Some(&converge_with(&[], &environment)),
        )
        .unwrap();
        assert!(
            shown.message.contains(
                "Environment: PATH=\"/usr/bin:/bin\" LD_PRELOAD=\"/home/account/.cache/x.so\"."
            ),
            "{}",
            shown.message
        );
        let none = disclosure(1000, 4242, &command_request(), Some(&converge(&[]))).unwrap();
        assert!(
            none.message.contains("Environment: none."),
            "{}",
            none.message
        );
    }

    #[test]
    fn a_run_argument_cannot_inject_markup_into_the_approval() {
        let markup = [
            OsString::from("</b></big><span size=\"1\">"),
            OsString::from("https://host/?a=1&b=2"),
        ];
        let environment = [(OsString::from("A<b>"), OsString::from("&amp;"))];
        let shown = disclosure(
            1000,
            4242,
            &command_request(),
            Some(&converge_with(&markup, &environment)),
        )
        .unwrap();
        for character in ['<', '>', '&'] {
            assert!(
                !shown.message.contains(character),
                "{character}: {}",
                shown.message
            );
        }
        assert!(
            shown.message.contains(r#""https://host/?a=1\x26b=2""#),
            "{}",
            shown.message
        );
    }

    #[test]
    fn a_command_too_long_to_show_cannot_be_approved() {
        let arguments = vec![OsString::from("a".repeat(4096))];
        assert_eq!(
            disclosure(1000, 4242, &command_request(), Some(&converge(&arguments))).err(),
            Some(Failure::InvalidRequest)
        );
    }

    #[test]
    fn only_a_command_grant_discloses_a_program() {
        let user = GrantRequest {
            scope: GrantScope::User,
            ..command_request()
        };
        let shown = disclosure(1000, 4242, &user, None).unwrap();
        assert!(shown.message.contains("all processes of this OS account"));
        assert!(!shown.message.contains("Program:"));
        assert!(disclosure(1000, 4242, &user, Some(&converge(&[]))).is_err());
        assert!(disclosure(1000, 4242, &command_request(), None).is_err());
    }

    #[test]
    fn a_polkit_that_cannot_answer_makes_approval_unavailable_and_the_request_retryable() {
        use zbus::fdo::Error as Reply;
        let polkit = || "org.freedesktop.PolicyKit1".to_owned();
        for (error, why) in [
            (
                zbus::Error::InputOutput(std::sync::Arc::new(
                    std::io::ErrorKind::ConnectionReset.into(),
                )),
                "the bus connection broke",
            ),
            (
                zbus::Error::FDO(Box::new(Reply::NameHasNoOwner(polkit()))),
                "PolicyKit is stopped",
            ),
            (
                zbus::Error::FDO(Box::new(Reply::ServiceUnknown(polkit()))),
                "PolicyKit is not activatable",
            ),
            (
                zbus::Error::FDO(Box::new(Reply::SpawnChildExited(polkit()))),
                "PolicyKit failed to start",
            ),
            (
                zbus::Error::FDO(Box::new(Reply::NoReply(polkit()))),
                "PolicyKit restarted during the approval",
            ),
            (
                zbus::Error::FDO(Box::new(Reply::Disconnected(polkit()))),
                "the bus disconnected",
            ),
        ] {
            let failure = transport_failure(&error);
            assert_eq!(
                serde_json::to_value(failure).unwrap(),
                "approval_unavailable",
                "{why}"
            );
            assert_eq!(failure.exit_code(), 3, "{why}: retryable, like busy");
        }
        for error in [
            zbus::Error::FDO(Box::new(Reply::AccessDenied(polkit()))),
            zbus::Error::FDO(Box::new(Reply::Failed(polkit()))),
            zbus::Error::InvalidReply,
        ] {
            assert_eq!(transport_failure(&error), Failure::ApprovalDenied, "{error}");
        }
    }

    #[test]
    fn process_subject_uses_the_native_polkit_signed_uid_contract() {
        let properties = subject_properties(42, 9876, 1000).unwrap();
        assert!(matches!(
            properties["uid"],
            zbus::zvariant::Value::I32(1000)
        ));
        assert!(subject_properties(42, 9876, u32::MAX).is_err());
    }

    #[test]
    fn lingering_managers_background_and_closing_sessions_do_not_extend_grants() {
        for class in ["user", "user-early", "user-light", "user-early-light"] {
            for kind in ["tty", "x11", "wayland", "mir"] {
                assert!(interactive_session(Some(class), Some(kind), Some("online")));
                assert!(interactive_session(Some(class), Some(kind), Some("active")));
                assert!(!interactive_session(
                    Some(class),
                    Some(kind),
                    Some("closing")
                ));
            }
        }
        for class in [
            "manager",
            "manager-early",
            "background",
            "background-light",
            "greeter",
            "lock-screen",
            "user-incomplete",
            "none",
        ] {
            assert!(!interactive_session(
                Some(class),
                Some("tty"),
                Some("active")
            ));
        }
        assert!(!interactive_session(
            Some("user"),
            Some("unspecified"),
            Some("online")
        ));
        assert!(!interactive_session(None, Some("tty"), Some("active")));
    }
}
