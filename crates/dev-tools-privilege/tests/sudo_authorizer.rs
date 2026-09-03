#![cfg(unix)]

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use dev_tools_privilege::{
    ExactHelperRequest, PrivilegeAuthorizer, PrivilegeOutcome, ProcessTermination, StdioPolicy,
    SudoAuthorizer, UnavailableReason, UserInteraction,
};

static PROCESS_TEST_LOCK: Mutex<()> = Mutex::new(());

fn process_test_guard() -> MutexGuard<'static, ()> {
    PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn exact_helper_preserves_native_arguments_and_clears_the_environment() {
    let _guard = process_test_guard();
    let root = tempfile::tempdir().unwrap();
    let authorizer_program = root.path().join("sudo");
    let helper = root.path().join("helper");
    let output = root.path().join("output");
    let injected = root.path().join("must-not-exist");
    executable(
        &authorizer_program,
        r#"#!/usr/bin/bash
set -eu
test "$1" = --
shift
exec "$@"
"#,
    );
    executable(
        &helper,
        r#"#!/usr/bin/bash
output=$1
shift
{
  printf 'argc=%s\n' "$#"
  for argument in "$@"; do printf 'arg=%s\n' "$argument"; done
  printf 'op=%s\n' "${OP_SERVICE_ACCOUNT_TOKEN-unset}"
} >"$output"
exit 23
"#,
    );
    let arguments = vec![
        output.clone().into_os_string(),
        OsString::from("two words"),
        OsString::from(format!("$(touch {})", injected.display())),
    ];
    let authorizer = SudoAuthorizer::new(&authorizer_program).unwrap();
    let outcome = authorizer
        .authorize_and_run_exact_helper(&ExactHelperRequest {
            helper: &helper,
            arguments: &arguments,
            deadline: None,
            interaction: UserInteraction::Allowed,
            stdio: StdioPolicy::Inherit,
        })
        .unwrap();

    assert_eq!(
        outcome,
        PrivilegeOutcome::Exited(ProcessTermination {
            code: Some(23),
            signal: None,
        })
    );
    assert_eq!(
        fs::read_to_string(output).unwrap(),
        format!(
            "argc=2\narg=two words\narg=$(touch {})\nop=unset\n",
            injected.display()
        )
    );
    assert!(!injected.exists());
}

#[test]
fn noninteractive_authorization_adds_only_the_native_no_prompt_flag() {
    let _guard = process_test_guard();
    let root = tempfile::tempdir().unwrap();
    let authorizer_program = root.path().join("sudo");
    let helper = root.path().join("helper");
    let output = root.path().join("output");
    executable(
        &authorizer_program,
        r#"#!/usr/bin/bash
set -eu
test "$1" = -n
test "$2" = --
shift 2
exec "$@"
"#,
    );
    executable(&helper, "#!/usr/bin/bash\nprintf '%s\\n' \"$@\" >\"$1\"\n");
    let arguments = vec![
        output.clone().into_os_string(),
        OsString::from("literal value"),
    ];
    let authorizer = SudoAuthorizer::new(&authorizer_program).unwrap();
    let outcome = authorizer
        .authorize_and_run_exact_helper(&ExactHelperRequest {
            helper: &helper,
            arguments: &arguments,
            deadline: None,
            interaction: UserInteraction::Forbidden,
            stdio: StdioPolicy::Null,
        })
        .unwrap();
    assert_eq!(
        outcome,
        PrivilegeOutcome::Exited(ProcessTermination {
            code: Some(0),
            signal: None,
        })
    );
}

#[test]
fn sudo_deadlines_reject_before_authorization_and_signals_remain_raw() {
    let _guard = process_test_guard();
    let root = tempfile::tempdir().unwrap();
    let authorizer_program = root.path().join("sudo");
    executable(
        &authorizer_program,
        r#"#!/usr/bin/bash
set -eu
if test "$1" = -n; then
  shift
else
  test "$1" = --
fi
test "$1" = --
shift
exec "$@"
"#,
    );
    let authorizer = SudoAuthorizer::new(&authorizer_program).unwrap();
    let deadline_error = authorizer.authorize_and_run_exact_helper(&ExactHelperRequest {
        helper: Path::new("/usr/bin/sleep"),
        arguments: &[OsString::from("10")],
        deadline: Some(Duration::from_millis(20)),
        interaction: UserInteraction::Forbidden,
        stdio: StdioPolicy::Null,
    });
    assert!(deadline_error.is_err());

    let helper = root.path().join("cancel");
    executable(&helper, "#!/usr/bin/bash\nkill -TERM $$\n");
    let signalled = authorizer
        .authorize_and_run_exact_helper(&ExactHelperRequest {
            helper: &helper,
            arguments: &[],
            deadline: None,
            interaction: UserInteraction::Allowed,
            stdio: StdioPolicy::Inherit,
        })
        .unwrap();
    assert_eq!(
        signalled,
        PrivilegeOutcome::Exited(ProcessTermination {
            code: None,
            signal: Some(15),
        })
    );
}

#[test]
fn unsafe_or_ambiguous_requests_fail_before_authorization() {
    let _guard = process_test_guard();
    let root = tempfile::tempdir().unwrap();
    let helper = root.path().join("helper");
    let alias = root.path().join("alias");
    let real_parent = root.path().join("real-parent");
    let linked_parent = root.path().join("linked-parent");
    let linked_parent_helper = real_parent.join("helper");
    executable(&helper, "#!/usr/bin/bash\nexit 0\n");
    symlink(&helper, &alias).unwrap();
    fs::create_dir(&real_parent).unwrap();
    executable(&linked_parent_helper, "#!/usr/bin/bash\nexit 0\n");
    symlink(&real_parent, &linked_parent).unwrap();
    let authorizer = SudoAuthorizer::new("/usr/bin/env").unwrap();

    for request in [
        ExactHelperRequest {
            helper: Path::new("relative-helper"),
            arguments: &[],
            deadline: None,
            interaction: UserInteraction::Allowed,
            stdio: StdioPolicy::Inherit,
        },
        ExactHelperRequest {
            helper: &alias,
            arguments: &[],
            deadline: None,
            interaction: UserInteraction::Allowed,
            stdio: StdioPolicy::Inherit,
        },
        ExactHelperRequest {
            helper: &linked_parent.join("helper"),
            arguments: &[],
            deadline: None,
            interaction: UserInteraction::Allowed,
            stdio: StdioPolicy::Inherit,
        },
        ExactHelperRequest {
            helper: &helper,
            arguments: &[],
            deadline: Some(Duration::ZERO),
            interaction: UserInteraction::Forbidden,
            stdio: StdioPolicy::Null,
        },
        ExactHelperRequest {
            helper: &helper,
            arguments: &[],
            deadline: None,
            interaction: UserInteraction::Allowed,
            stdio: StdioPolicy::Null,
        },
    ] {
        assert!(authorizer.authorize_and_run_exact_helper(&request).is_err());
    }
}

#[test]
fn vanished_authorization_program_is_unavailable_without_running_the_helper() {
    let _guard = process_test_guard();
    let root = tempfile::tempdir().unwrap();
    let authorizer_program = root.path().join("sudo");
    let helper = root.path().join("helper");
    let marker = root.path().join("marker");
    executable(&authorizer_program, "#!/usr/bin/bash\nexec \"$@\"\n");
    executable(
        &helper,
        &format!("#!/usr/bin/bash\ntouch '{}'\n", marker.display()),
    );
    let authorizer = SudoAuthorizer::new(&authorizer_program).unwrap();
    fs::remove_file(authorizer_program).unwrap();
    let outcome = authorizer
        .authorize_and_run_exact_helper(&ExactHelperRequest {
            helper: &helper,
            arguments: &[],
            deadline: None,
            interaction: UserInteraction::Allowed,
            stdio: StdioPolicy::Inherit,
        })
        .unwrap();
    assert_eq!(
        outcome,
        PrivilegeOutcome::Unavailable(UnavailableReason::AuthorizationProgram)
    );
    assert!(!marker.exists());
}
