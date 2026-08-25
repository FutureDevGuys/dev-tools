use crate::updaters::{HostOs, PrivilegeMode};
use crate::util::process::which;
use anyhow::Result;
use is_terminal::IsTerminal;
use std::io;
use std::process::{Command, Stdio};

#[derive(Clone, Debug)]
pub enum PrivilegeDecision {
    Proceed,
    Skip(String),
    Fail(String),
}

pub fn resolve_privilege_decision(
    mode: PrivilegeMode,
    host_os: HostOs,
    task_label: &str,
) -> Result<PrivilegeDecision> {
    match mode {
        PrivilegeMode::Skip => Ok(PrivilegeDecision::Skip(format!(
            "{task_label}: requires elevation; skipped (mode=skip)"
        ))),
        PrivilegeMode::Fail => Ok(PrivilegeDecision::Fail(format!(
            "{task_label}: requires elevation but mode=fail"
        ))),
        PrivilegeMode::PromptTty => prompt_tty_for_privilege(host_os, task_label),
    }
}

fn prompt_tty_for_privilege(host_os: HostOs, task_label: &str) -> Result<PrivilegeDecision> {
    let stdin_is_terminal = io::stdin().is_terminal();
    let stdout_is_terminal = io::stdout().is_terminal();
    let cached_sudo_session =
        matches!(host_os, HostOs::Linux | HostOs::Macos) && noninteractive_sudo_session_available();

    Ok(prompt_tty_for_privilege_with_state(
        host_os,
        task_label,
        stdin_is_terminal,
        stdout_is_terminal,
        cached_sudo_session,
    ))
}

fn prompt_tty_for_privilege_with_state(
    host_os: HostOs,
    task_label: &str,
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
    cached_sudo_session: bool,
) -> PrivilegeDecision {
    if !stdin_is_terminal || !stdout_is_terminal {
        if matches!(host_os, HostOs::Linux | HostOs::Macos) && cached_sudo_session {
            return PrivilegeDecision::Proceed;
        }
        return PrivilegeDecision::Fail(format!(
            "{task_label}: requires elevation but prompt_tty cannot prompt in a non-interactive session; run update-all from an interactive terminal, pre-authenticate sudo, or set privilege_mode=\"skip\" to intentionally skip elevated tasks"
        ));
    }

    // "prompt_tty" means we allow OS-native elevation prompting in TTY sessions.
    // We avoid custom stdin prompts here to keep dashboard/TTY state stable.
    match host_os {
        HostOs::Linux | HostOs::Macos => PrivilegeDecision::Proceed,
        HostOs::Windows => PrivilegeDecision::Proceed,
        HostOs::Unknown => PrivilegeDecision::Proceed,
    }
}

fn noninteractive_sudo_session_available() -> bool {
    if which("sudo").is_none() {
        return false;
    }
    Command::new("sudo")
        .arg("-n")
        .arg("-v")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_tty_fails_noninteractive_without_cached_sudo() {
        let decision =
            prompt_tty_for_privilege_with_state(HostOs::Linux, "Yay", false, false, false);

        match decision {
            PrivilegeDecision::Fail(message) => {
                assert!(message.contains("Yay"), "{message}");
                assert!(message.contains("non-interactive session"), "{message}");
            }
            other => panic!("expected fail decision, got {other:?}"),
        }
    }

    #[test]
    fn prompt_tty_uses_cached_sudo_in_noninteractive_unix_session() {
        let decision =
            prompt_tty_for_privilege_with_state(HostOs::Linux, "Yay", false, false, true);

        assert!(matches!(decision, PrivilegeDecision::Proceed));
    }

    #[test]
    fn explicit_skip_mode_remains_skip() {
        let decision =
            resolve_privilege_decision(PrivilegeMode::Skip, HostOs::Linux, "Yay").unwrap();

        match decision {
            PrivilegeDecision::Skip(message) => {
                assert!(message.contains("mode=skip"), "{message}");
            }
            other => panic!("expected skip decision, got {other:?}"),
        }
    }
}
