//! Read existing, unlocked enrollment without entering keyring unlock/migration code.
use super::{CredentialStore, SecretString, OP_SERVICE_TOKEN_LIMIT};
use futures_util::future::{select, Either};
use secret_service::{EncryptionType, SecretService};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::future::Future;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

const READ_BUDGET: Duration = Duration::from_secs(5);

/// Carries no backend messages, item identifiers, or credential values.
#[derive(Debug)]
pub(crate) struct CredentialUnavailable;

impl fmt::Display for CredentialUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("enrolled credential is unavailable without interaction")
    }
}

impl std::error::Error for CredentialUnavailable {}

type Result<T> = std::result::Result<T, CredentialUnavailable>;

pub(super) fn read(
    stores: &BTreeMap<String, CredentialStore>,
) -> Result<BTreeMap<String, SecretString>> {
    super::validate_secret_service_session().map_err(|_| CredentialUnavailable)?;
    // This is a synchronous launch-admission boundary, before the broker or child
    // starts. Never nest a runtime in an existing async caller.
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(CredentialUnavailable);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| CredentialUnavailable)?;
    let bus = format!("/run/user/{}/bus", rustix::process::geteuid().as_raw());
    runtime.block_on(read_at(Path::new(&bus), stores, READ_BUDGET))
}

struct SocketCustody(UnixStream);

impl Drop for SocketCustody {
    fn drop(&mut self) {
        // Also closes outstanding transport work if the owning future is dropped.
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

async fn read_at(
    bus: &Path,
    stores: &BTreeMap<String, CredentialStore>,
    budget: Duration,
) -> Result<BTreeMap<String, SecretString>> {
    let deadline = tokio::time::Instant::now() + budget;
    let stream = tokio::time::timeout_at(deadline, tokio::net::UnixStream::connect(bus))
        .await
        .map_err(|_| CredentialUnavailable)?
        .map_err(|_| CredentialUnavailable)?
        .into_std()
        .map_err(|_| CredentialUnavailable)?;
    let custody = SocketCustody(stream.try_clone().map_err(|_| CredentialUnavailable)?);
    let result = tokio::time::timeout_at(deadline, async {
        let connection = zbus::connection::Builder::async_io_unix_stream(stream)
            .internal_executor(false)
            .max_queued(8)
            .method_timeout(budget)
            .build()
            .await
            .map_err(|_| CredentialUnavailable)?;
        drive(&connection, async {
            // Reject a service that is not currently running. No environment
            // address lookup, collection discovery, unlock, prompt, or migration
            // is used. The standard read methods do not request authentication.
            let bus = zbus::fdo::DBusProxy::new(&connection)
                .await
                .map_err(|_| CredentialUnavailable)?;
            let name = "org.freedesktop.secrets"
                .try_into()
                .map_err(|_| CredentialUnavailable)?;
            if !bus
                .name_has_owner(name)
                .await
                .map_err(|_| CredentialUnavailable)?
            {
                return Err(CredentialUnavailable);
            }
            let service =
                SecretService::connect_with_existing(EncryptionType::Dh, connection.clone())
                    .await
                    .map_err(|_| CredentialUnavailable)?;
            read_service(&service, stores).await
        })
        .await
    })
    .await
    .map_err(|_| CredentialUnavailable)
    .and_then(|result| result);
    // Terminalize the socket before returning, including authentication timeouts.
    // The scoped executor has no independent driver or detached credential task.
    let closed = custody.0.shutdown(Shutdown::Both);
    match (result, closed) {
        (Ok(values), Ok(())) => Ok(values),
        _ => Err(CredentialUnavailable),
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

async fn read_service(
    service: &SecretService<'_>,
    stores: &BTreeMap<String, CredentialStore>,
) -> Result<BTreeMap<String, SecretString>> {
    let mut values = BTreeMap::new();
    for (slot, store) in stores {
        // These are the exact keyring 4.1.6 / zbus-store 1.0.1 enrollment keys.
        let matches = service
            .search_items(HashMap::from([
                ("service", store.service.as_str()),
                ("username", store.account.as_str()),
            ]))
            .await
            .map_err(|_| CredentialUnavailable)?;
        if !matches.locked.is_empty() || matches.unlocked.len() != 1 {
            return Err(CredentialUnavailable);
        }
        let value = matches.unlocked[0]
            .get_secret()
            .await
            .map_err(|_| CredentialUnavailable)?;
        values.insert(slot.clone(), token(value)?);
    }
    Ok(values)
}

fn token(bytes: Vec<u8>) -> Result<SecretString> {
    let bytes = Zeroizing::new(bytes);
    if bytes.is_empty() || bytes.len() > OP_SERVICE_TOKEN_LIMIT as usize {
        return Err(CredentialUnavailable);
    }
    let value = std::str::from_utf8(&bytes).map_err(|_| CredentialUnavailable)?;
    if value.contains(['\n', '\r', '\0']) {
        return Err(CredentialUnavailable);
    }
    Ok(SecretString::new(value.to_owned()))
}

#[cfg(test)]
mod tests;
