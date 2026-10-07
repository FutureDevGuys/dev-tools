//! Originating native login identity. Environment/session-name hints are not used.
use anyhow::{bail, Context, Result};
use std::time::Duration;
use zbus::{
    blocking::{connection::Builder, Connection, Proxy},
    zvariant::OwnedObjectPath,
};

pub struct LoginSession {
    connection: Connection,
    path: OwnedObjectPath,
    owner: u32,
}
impl LoginSession {
    pub fn bind(peer_pid: u32, owner: u32) -> Result<Self> {
        let connection = Builder::system()?
            .method_timeout(Duration::from_secs(2))
            .build()?;
        let manager = Proxy::new(
            &connection,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )?;
        let direct: std::result::Result<OwnedObjectPath, zbus::Error> =
            manager.call("GetSessionByPID", &(peer_pid,));
        let path = match direct {
            Ok(path) => path,
            Err(zbus::Error::MethodError(name, _, _))
                if name.as_str() == "org.freedesktop.login1.NoSessionForPID" =>
            {
                // Desktop applications may be user-manager units rather than
                // members of a login scope. Bind the native user's explicitly
                // reported display session, never a caller-supplied session ID.
                let user_path: OwnedObjectPath = manager.call("GetUser", &(owner,))?;
                let user = Proxy::new(
                    &connection,
                    "org.freedesktop.login1",
                    user_path.as_str(),
                    "org.freedesktop.login1.User",
                )?;
                let uid: u32 = user.get_property("UID")?;
                if uid != owner {
                    bail!("native login owner changed");
                }
                let display: (String, OwnedObjectPath) = user.get_property("Display")?;
                if display.0.is_empty() || display.1.as_str() == "/" {
                    bail!("native approval has no retained active login");
                }
                display.1
            }
            Err(error) => return Err(error.into()),
        };
        drop(manager);
        let result = Self {
            connection,
            path,
            owner,
        };
        result.verify()?;
        Ok(result)
    }
    pub fn retain(path: &str, owner: u32) -> Result<Self> {
        if !path.starts_with("/org/freedesktop/login1/session/") || path.len() > 256 {
            bail!("native login binding is invalid");
        }
        let connection = Builder::system()?
            .method_timeout(Duration::from_secs(2))
            .build()?;
        let result = Self {
            connection,
            path: OwnedObjectPath::try_from(path).context("native login path is invalid")?,
            owner,
        };
        result.verify()?;
        Ok(result)
    }
    pub fn path(&self) -> &str {
        self.path.as_str()
    }
    pub fn verify(&self) -> Result<()> {
        let session = Proxy::new(
            &self.connection,
            "org.freedesktop.login1",
            self.path.as_str(),
            "org.freedesktop.login1.Session",
        )?;
        let user: (u32, OwnedObjectPath) = session.get_property("User")?;
        let active: bool = session.get_property("Active")?;
        let state: String = session.get_property("State")?;
        if user.0 != self.owner || !active || state != "active" {
            bail!("native login authority is no longer active");
        }
        Ok(())
    }
}
