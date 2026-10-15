//! Metadata-only enrollment observation. This module has no credential-value API.
use super::CredentialStore;
use futures_util::future::{select, Either};
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;
use zbus::zvariant::OwnedObjectPath;

const BUDGET: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PresenceError {
    Unavailable,
    Unsupported,
    Locked,
    Ambiguous,
}

impl fmt::Display for PresenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "credential enrollment metadata is unavailable",
            Self::Unsupported => "credential enrollment metadata is unsupported",
            Self::Locked => "credential enrollment metadata identifies locked enrollment",
            Self::Ambiguous => "credential enrollment metadata is ambiguous",
        })
    }
}

impl std::error::Error for PresenceError {}

type Result<T> = std::result::Result<T, PresenceError>;

pub(super) fn observe(store: &CredentialStore) -> Result<bool> {
    super::validate_secret_service_session().map_err(|_| PresenceError::Unavailable)?;
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(PresenceError::Unsupported);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| PresenceError::Unavailable)?;
    let bus = format!("/run/user/{}/bus", rustix::process::geteuid().as_raw());
    runtime.block_on(observe_at(Path::new(&bus), store, BUDGET))
}

struct SocketCustody(UnixStream);

impl Drop for SocketCustody {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

pub(super) async fn observe_at(
    bus: &Path,
    store: &CredentialStore,
    budget: Duration,
) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + budget;
    let stream = tokio::time::timeout_at(deadline, tokio::net::UnixStream::connect(bus))
        .await
        .map_err(|_| PresenceError::Unavailable)?
        .map_err(|_| PresenceError::Unavailable)?
        .into_std()
        .map_err(|_| PresenceError::Unavailable)?;
    let custody = SocketCustody(stream.try_clone().map_err(|_| PresenceError::Unavailable)?);
    let result = tokio::time::timeout_at(deadline, async {
        let connection = zbus::connection::Builder::async_io_unix_stream(stream)
            .internal_executor(false)
            .max_queued(8)
            .method_timeout(budget)
            .build()
            .await
            .map_err(|_| PresenceError::Unavailable)?;
        drive(&connection, async {
            let bus = zbus::fdo::DBusProxy::new(&connection)
                .await
                .map_err(|_| PresenceError::Unavailable)?;
            let name = "org.freedesktop.secrets"
                .try_into()
                .map_err(|_| PresenceError::Unsupported)?;
            // Resolve the running unique owner. Calling that unique name cannot
            // activate a service if the owner disappears between observation and call.
            let owner = bus
                .get_name_owner(name)
                .await
                .map_err(|_| PresenceError::Unavailable)?;
            let proxy = zbus::proxy::Builder::<zbus::Proxy<'_>>::new(&connection)
                .destination(owner)
                .map_err(|_| PresenceError::Unsupported)?
                .path("/org/freedesktop/secrets")
                .map_err(|_| PresenceError::Unsupported)?
                .interface("org.freedesktop.Secret.Service")
                .map_err(|_| PresenceError::Unsupported)?
                .cache_properties(zbus::proxy::CacheProperties::No)
                .build()
                .await
                .map_err(|_| PresenceError::Unsupported)?;
            let attributes = HashMap::from([
                ("service", store.service.as_str()),
                ("username", store.account.as_str()),
            ]);
            let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = proxy
                .call("SearchItems", &(attributes,))
                .await
                .map_err(classify_error)?;
            match (unlocked.len(), locked.len()) {
                (0, 0) => Ok(false),
                (1, 0) => Ok(true),
                (0, 1) => Err(PresenceError::Locked),
                _ => Err(PresenceError::Ambiguous),
            }
        })
        .await
    })
    .await
    .map_err(|_| PresenceError::Unavailable)
    .and_then(|result| result);
    let closed = custody.0.shutdown(Shutdown::Both);
    match (result, closed) {
        (result, Ok(())) => result,
        _ => Err(PresenceError::Unavailable),
    }
}

fn classify_error(error: zbus::Error) -> PresenceError {
    match error {
        zbus::Error::MethodError(name, _, _)
            if matches!(
                name.as_str(),
                "org.freedesktop.DBus.Error.UnknownMethod"
                    | "org.freedesktop.DBus.Error.UnknownInterface"
                    | "org.freedesktop.DBus.Error.UnknownObject"
                    | "org.freedesktop.DBus.Error.NotSupported"
            ) =>
        {
            PresenceError::Unsupported
        }
        _ => PresenceError::Unavailable,
    }
}

async fn drive<T>(connection: &zbus::Connection, operation: impl Future<Output = T>) -> T {
    async fn ticks<T>(connection: &zbus::Connection) -> T {
        loop {
            connection.executor().tick().await;
        }
    }
    match select(Box::pin(operation), Box::pin(ticks(connection))).await {
        Either::Left((result, _)) | Either::Right((result, _)) => result,
    }
}
