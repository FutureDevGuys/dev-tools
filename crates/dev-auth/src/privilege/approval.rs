use super::native::Caller;
use super::{Authority, Failure, GrantRequest, GrantScope};
use std::collections::HashMap;

pub(super) const ACTION: &str = "org.futuredevguys.dev-auth.privilege.request";

/// PolicyKit owns the authentication UI and all credential input. The action
/// uses auth_admin, never an *_keep result or a product-managed password cache.
pub(super) async fn approve(
    caller: &Caller,
    request: &GrantRequest,
    nonce: &str,
    control: &std::os::fd::OwnedFd,
) -> Result<(), Failure> {
    let connection = zbus::Connection::system()
        .await
        .map_err(|_| Failure::NativeUnavailable)?;
    let properties = subject_properties(caller.peer.pid, caller.start_time, caller.peer.uid)?;
    let scope = match request.scope {
        GrantScope::User => "all processes of this OS account",
        GrantScope::Workload => "this registered workload and its descendants",
    };
    let authority = match &request.authority {
        Authority::Administrator => "unrestricted host administrator authority".to_owned(),
        Authority::ExactPlan { sha256 } => format!("executable plan {sha256} (fixed inputs do not confine the programs' administrator effects)"),
        Authority::Typed { operations } => format!("named operations {} (their administrator effects depend on the configured programs)", operations.join(", ")),
    };
    let mut details = HashMap::<&str, String>::new();
    details.insert("polkit.message", format!(
        "Allow {authority} for {scope} (user {}, requesting process {}) for {} seconds? Idle cutoff: {}. Use limit: {}. Existing grants are not extended. Unrestricted commands can change the system and disable enforcement.",
        caller.peer.uid, caller.peer.pid, request.duration_seconds,
        request.idle_seconds.map(|seconds| format!("{seconds} seconds")).unwrap_or_else(|| "none".to_owned()),
        request.uses.map(|uses| uses.to_string()).unwrap_or_else(|| "none".to_owned())));
    details.insert(
        "dev-auth.scope",
        match request.scope {
            GrantScope::User => "user",
            GrantScope::Workload => "workload",
        }
        .to_owned(),
    );
    details.insert(
        "dev-auth.duration-seconds",
        request.duration_seconds.to_string(),
    );
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
            match &error {
                zbus::Error::MethodError(name, _, _) => {
                    eprintln!("dev-auth native approval transport rejected: {name}");
                }
                _ => eprintln!("dev-auth native approval transport unavailable"),
            }
            cancel(&connection, &cancellation).await;
            return Err(Failure::ApprovalDenied);
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
