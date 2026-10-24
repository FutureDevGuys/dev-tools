//! Product-owned declarative inputs. Setup publishes these only as a verified,
//! receipt-owned generation; an embedded helper alone grants no authority.

pub const SUDO_LIBRARY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dev-auth-sudo.so"));
pub const SERVICE: &str = include_str!("../../../assets/grants/dev-auth-grants.service");
pub const POLKIT: &str =
    include_str!("../../../assets/grants/org.futuredevguys.dev-auth.privilege.policy");
pub const SUDO_CONFIGURATION: &str = include_str!("../../../assets/grants/sudo.conf");
pub const SUDOERS: &str = include_str!("../../../assets/grants/sudoers");

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn administrator_assets_require_fresh_approval_and_independent_crash_cleanup() {
        assert!(POLKIT.contains(super::super::approval::ACTION));
        assert_eq!(POLKIT.matches(">auth_admin<").count(), 3);
        assert!(!POLKIT.contains("auth_admin_keep"));
        for required in [
            "KillMode=control-group",
            "SendSIGKILL=yes",
            "TimeoutStopSec=5s",
            "RuntimeDirectoryPreserve=yes",
            "Delegate=no",
            "ExitType=main",
            "RemainAfterExit=no",
            "Restart=on-failure",
        ] {
            assert!(SERVICE.lines().any(|line| line == required));
        }
        assert!(!SERVICE.contains("LoadCredential"));
        assert!(!SERVICE.contains("PrivateUsers="));
        assert!(SUDOERS.contains("%:dev-auth-active"));
        assert!(SUDO_CONFIGURATION.contains("dev_auth_sudo_audit"));
        assert!(SUDO_CONFIGURATION.contains("dev_auth_sudo_approval"));
    }
}
