//! Product-owned declarative inputs. Setup publishes these only as a verified,
//! receipt-owned generation; an embedded helper alone grants no authority.

pub const SUDO_LIBRARY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dev-auth-sudo.so"));
pub const SERVICE: &str = include_str!("../../../assets/grants/dev-auth-grants.service");
pub const POLKIT: &str =
    include_str!("../../../assets/grants/org.futuredevguys.dev-auth.privilege.policy");
pub const SUDO_CONFIGURATION: &str = include_str!("../../../assets/grants/sudo.conf");
pub const SUDOERS: &str = include_str!("../../../assets/grants/sudoers");

/// The kill mode and stop timeout, as `systemctl show` prints them, of the
/// unit that setup publishes and of the unit it replaces. Setup observes and
/// stops a coordinator under either (ADR 0141).
pub const TEARDOWNS: [(&str, &str); 2] = [("mixed", "1min 30s"), ("control-group", "5s")];

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn administrator_assets_require_fresh_approval_and_independent_crash_cleanup() {
        assert!(POLKIT.contains(super::super::approval::ACTION));
        assert_eq!(POLKIT.matches(">auth_admin<").count(), 3);
        assert!(!POLKIT.contains("auth_admin_keep"));
        for required in [
            "KillMode=mixed",
            "SendSIGKILL=yes",
            "TimeoutStopSec=90s",
            "OOMPolicy=continue",
            "OOMScoreAdjust=-900",
            "RuntimeDirectoryPreserve=yes",
            "Delegate=no",
            "ExitType=main",
            "RemainAfterExit=no",
            "TasksMax=4096",
            "LimitNOFILE=8192",
        ] {
            assert!(SERVICE.lines().any(|line| line == required), "{required}");
        }
        assert!(!SERVICE.contains("LoadCredential"));
        assert!(!SERVICE.contains("PrivateUsers="));
        assert!(SUDOERS.contains("%:dev-auth-active"));
        assert!(SUDO_CONFIGURATION.contains("dev_auth_sudo_audit"));
        assert!(SUDO_CONFIGURATION.contains("dev_auth_sudo_approval"));
    }

    fn setting(key: &str) -> impl Iterator<Item = &'static str> + '_ {
        SERVICE
            .lines()
            .filter_map(move |line| line.strip_prefix(key)?.strip_prefix('='))
    }

    #[test]
    fn no_other_units_stop_or_restart_stops_the_coordinator() {
        // Each of these stops this unit when the named unit stops or
        // restarts, or, for Conflicts=, when it starts. A package upgrade
        // that restarts PolicyKit would then end every grant.
        for key in [
            "Requires",
            "Requisite",
            "BindsTo",
            "PartOf",
            "StopPropagatedFrom",
            "Conflicts",
        ] {
            assert_eq!(setting(key).next(), None, "{key}= stops the coordinator");
        }
        assert!(setting("Wants").any(|units| units.split(' ').any(|unit| unit == "polkit.service")));
        assert!(setting("After").any(|units| units.split(' ').any(|unit| unit == "polkit.service")));
    }

    #[test]
    fn the_service_manager_restarts_the_coordinator_after_any_exit_it_did_not_order() {
        // A stop that the service manager orders never restarts a unit,
        // whatever Restart= says. Restart=on-failure also skips an exit with
        // status 0, such as the drain after a SIGTERM from `kill -TERM -1`.
        assert_eq!(setting("Restart").collect::<Vec<_>>(), ["always"]);
        assert_eq!(setting("RestartPreventExitStatus").next(), None);
    }

    #[test]
    fn systemd_oomd_never_selects_the_coordinators_own_cgroup() {
        // The preference applies to the unit's cgroup only, so oomd can
        // still select a job's leaf cgroup.
        assert_eq!(
            setting("ManagedOOMPreference").collect::<Vec<_>>(),
            ["omit"]
        );
    }
}
