//! Layouts follow sudo_plugin.h API 1.22 and group API 1.0. Sudo owns all
//! borrowed arrays/strings for the callback duration. The plugin copies bounded
//! native observations and retains no foreign pointer or conversation function.

use crate::native::{self, STATE};
use std::ffi::{CStr, OsString};
use std::io;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::os::unix::ffi::OsStringExt;

const API: c_uint = (1 << 16) | 22;
const DENIAL: &[u8] = b"Dev Auth managed administrator admission denied; inspect the grant or explicitly leave managed routing.\0";
type Strings = *const *mut c_char;
type ErrorText = *mut *const c_char;
type Conversation =
    Option<unsafe extern "C" fn(c_int, *const c_void, *mut c_void, *mut c_void) -> c_int>;
type Print = Option<unsafe extern "C" fn(c_int, *const c_char, ...) -> c_int>;
type Open = unsafe extern "C" fn(
    c_uint,
    Conversation,
    Print,
    Strings,
    Strings,
    c_int,
    Strings,
    Strings,
    Strings,
    ErrorText,
) -> c_int;
type Hook = Option<unsafe extern "C" fn(c_int, *mut c_void)>;
type Event = Option<unsafe extern "C" fn() -> *mut c_void>;
type AuditEvent =
    unsafe extern "C" fn(*const c_char, c_uint, *const c_char, Strings, ErrorText) -> c_int;

#[repr(C)]
pub struct AuditPlugin {
    pub kind: c_uint,
    pub version: c_uint,
    pub open: Option<Open>,
    pub close: Option<unsafe extern "C" fn(c_int, c_int)>,
    pub accept: Option<
        unsafe extern "C" fn(*const c_char, c_uint, Strings, Strings, Strings, ErrorText) -> c_int,
    >,
    pub reject: Option<AuditEvent>,
    pub error: Option<AuditEvent>,
    pub show_version: Option<unsafe extern "C" fn(c_int) -> c_int>,
    pub register_hooks: Hook,
    pub deregister_hooks: Hook,
    pub event_alloc: Event,
}

#[repr(C)]
pub struct ApprovalPlugin {
    pub kind: c_uint,
    pub version: c_uint,
    pub open: Option<Open>,
    pub close: Option<unsafe extern "C" fn()>,
    pub check: Option<unsafe extern "C" fn(Strings, Strings, Strings, ErrorText) -> c_int>,
    pub show_version: Option<unsafe extern "C" fn(c_int) -> c_int>,
}

#[repr(C)]
pub struct GroupPlugin {
    pub version: c_uint,
    pub init: Option<unsafe extern "C" fn(c_int, Print, Strings) -> c_int>,
    pub cleanup: Option<unsafe extern "C" fn()>,
    pub query: Option<
        unsafe extern "C" fn(*const c_char, *const c_char, *const nix::libc::passwd) -> c_int,
    >,
}

// SAFETY: these symbols have the exact writable plugin-record layout expected
// by native sudo. They exist once in this cdylib. Sudo initializes event_alloc
// before callbacks; callbacks never mutate or alias these exported records.
#[no_mangle]
pub static mut dev_auth_sudo_audit: AuditPlugin = AuditPlugin {
    kind: 3,
    version: API,
    open: Some(audit_open),
    close: Some(audit_close),
    accept: Some(audit_accept),
    reject: Some(audit_event),
    error: Some(audit_event),
    show_version: Some(show_version),
    register_hooks: None,
    deregister_hooks: None,
    event_alloc: None,
};
#[no_mangle]
pub static mut dev_auth_sudo_approval: ApprovalPlugin = ApprovalPlugin {
    kind: 4,
    version: API,
    open: Some(approval_open),
    close: None,
    check: Some(approval_check),
    show_version: Some(show_version),
};
#[no_mangle]
pub static mut group_plugin: GroupPlugin = GroupPlugin {
    version: 1 << 16,
    init: Some(group_init),
    cleanup: Some(group_cleanup),
    query: Some(group_query),
};

fn guarded(error: ErrorText, operation: impl FnOnce() -> io::Result<c_int>) -> c_int {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
    match outcome {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            // SAFETY: sudo supplies a writable error pointer when non-null;
            // the fixed NUL-terminated string has static lifetime.
            if !error.is_null() {
                unsafe {
                    *error = DENIAL.as_ptr().cast();
                }
            }
            -1
        }
        Err(payload) => {
            // A panic payload may have an arbitrary destructor. Do not permit
            // secondary unwinding to cross the non-unwinding native ABI.
            std::mem::forget(payload);
            if !error.is_null() {
                unsafe {
                    *error = DENIAL.as_ptr().cast();
                }
            }
            -1
        }
    }
}

/// # Safety
/// `values` is null or points to a native sudo-owned NUL-terminated array of
/// live NUL-terminated strings for the full callback. No pointer is retained.
unsafe fn copy_strings(values: Strings) -> io::Result<Vec<OsString>> {
    if values.is_null() {
        return Ok(Vec::new());
    }
    let mut copied = Vec::new();
    let mut total = 0_usize;
    for index in 0..=1024 {
        // SAFETY: the native API guarantees the complete array through its
        // terminating NULL; we stop at NULL and never dereference beyond it.
        let value = unsafe { *values.add(index) };
        if value.is_null() {
            return Ok(copied);
        }
        if index == 1024 {
            return Err(native::invalid());
        }
        let value = unsafe { CStr::from_ptr(value) }.to_bytes();
        total = total.checked_add(value.len()).ok_or_else(native::invalid)?;
        if total > 60 * 1024 {
            return Err(native::invalid());
        }
        copied.push(OsString::from_vec(value.to_vec()));
    }
    Err(native::invalid())
}

unsafe extern "C" fn audit_open(
    version: c_uint,
    _conversation: Conversation,
    _print: Print,
    _settings: Strings,
    user_info: Strings,
    _optind: c_int,
    argv: Strings,
    environment: Strings,
    options: Strings,
    error: ErrorText,
) -> c_int {
    guarded(error, || {
        if version >> 16 != 1 || version & 0xffff < 22 {
            return Err(native::invalid());
        }
        // SAFETY: these arrays have the native callback's borrowed lifetime.
        let user_info = unsafe { copy_strings(user_info)? };
        let options = unsafe { copy_strings(options)? };
        let state = native::initialize(&user_info, &options)?;
        if state.relay {
            // SAFETY: sudo retains its original unparsed argv/environment for
            // the callback. The replacement frontend has no retained privilege.
            return Err(native::relay(
                &state,
                &user_info,
                unsafe { copy_strings(argv)? },
                unsafe { copy_strings(environment)? },
            ));
        }
        let mut current = STATE.lock().map_err(|_| native::invalid())?;
        if current.is_some() {
            return Err(native::invalid());
        }
        *current = Some(state);
        Ok(1)
    })
}

unsafe extern "C" fn audit_close(_kind: c_int, _status: c_int) {
    let _ = guarded(std::ptr::null_mut(), || {
        if let Some(mut state) = STATE.lock().map_err(|_| native::invalid())?.take() {
            if let Some(client) = &mut state.client {
                client.finish();
            }
        }
        Ok(1)
    });
}

unsafe extern "C" fn approval_open(
    version: c_uint,
    _conversation: Conversation,
    _print: Print,
    _settings: Strings,
    _user_info: Strings,
    _optind: c_int,
    _argv: Strings,
    _environment: Strings,
    _options: Strings,
    error: ErrorText,
) -> c_int {
    guarded(error, || {
        if version >> 16 != 1 || version & 0xffff < 22 {
            return Err(native::invalid());
        }
        Ok(1)
    })
}

unsafe extern "C" fn approval_check(
    info: Strings,
    argv: Strings,
    environment: Strings,
    error: ErrorText,
) -> c_int {
    guarded(error, || {
        let mut current = STATE.lock().map_err(|_| native::invalid())?;
        let state = current.as_mut().ok_or_else(native::invalid)?;
        if let Some(client) = &mut state.client {
            if state.admitted {
                return Err(native::invalid());
            }
            // SAFETY: sudo retains the final post-policy arrays for this call.
            client.admit(
                unsafe { copy_strings(info)? },
                unsafe { copy_strings(argv)? },
                unsafe { copy_strings(environment)? },
            )?;
            state.admitted = true;
        }
        Ok(1)
    })
}

unsafe extern "C" fn audit_accept(
    _plugin: *const c_char,
    kind: c_uint,
    _info: Strings,
    _argv: Strings,
    _environment: Strings,
    error: ErrorText,
) -> c_int {
    guarded(error, || {
        let current = STATE.lock().map_err(|_| native::invalid())?;
        let state = current.as_ref().ok_or_else(native::invalid)?;
        if matches!(kind, 0 | 4) && state.client.is_some() && !state.admitted {
            return Err(native::invalid());
        }
        Ok(1)
    })
}

unsafe extern "C" fn audit_event(
    _plugin: *const c_char,
    _kind: c_uint,
    _message: *const c_char,
    _info: Strings,
    _error: ErrorText,
) -> c_int {
    1
}
unsafe extern "C" fn show_version(_verbose: c_int) -> c_int {
    1
}
unsafe extern "C" fn group_init(version: c_int, _print: Print, _argv: Strings) -> c_int {
    if version >> 16 == 1 {
        1
    } else {
        -1
    }
}

extern "C" fn group_cleanup() {
    // Sudoers invokes this callback unconditionally before command execution.
    // The audit plugin, not the group provider, owns the invocation state; it
    // must remain available for final admission and the front-end audit.
}

unsafe extern "C" fn group_query(
    user: *const c_char,
    group: *const c_char,
    pwd: *const nix::libc::passwd,
) -> c_int {
    let result = guarded(std::ptr::null_mut(), || {
        if user.is_null() || group.is_null() {
            return Ok(0);
        }
        // SAFETY: user/group are NUL-terminated native arguments. pwd is null
        // or a borrowed native passwd valid for this callback. No data escapes.
        if unsafe { CStr::from_ptr(group) }.to_bytes() != b"dev-auth-active" {
            return Ok(0);
        }
        let current = STATE.lock().map_err(|_| native::invalid())?;
        let Some(state) = current.as_ref() else {
            return Ok(0);
        };
        if state.client.is_none()
            || unsafe { CStr::from_ptr(user) }.to_bytes() != state.user
            || (!pwd.is_null() && unsafe { (*pwd).pw_uid } != state.uid)
        {
            return Ok(0);
        }
        // Keep the conditional native no-password route selected for this
        // invocation even if the grant expires now. Final approval then denies;
        // returning false could enter a cached/native authentication fallback.
        Ok(1)
    });
    if result == 1 {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_group_lifecycle_supplies_required_cleanup() {
        // SAFETY: no unit test or Rust callback writes this static record. The
        // native loader is absent here, and the copied callback lives forever.
        let cleanup = unsafe { std::ptr::addr_of!(group_plugin.cleanup).read() }
            .expect("sudoers invokes the group cleanup callback unconditionally");
        // SAFETY: this callback takes no arguments and owns no foreign state.
        unsafe { cleanup() };
    }

    #[test]
    fn native_boundary_errors_never_become_plugin_disable_success() {
        let mut error = std::ptr::null();
        assert_eq!(guarded(&mut error, || Err(native::invalid())), -1);
        assert_eq!(unsafe { CStr::from_ptr(error) }.to_bytes_with_nul(), DENIAL);
        assert_eq!(
            unsafe {
                approval_open(
                    0,
                    None,
                    None,
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    &mut error,
                )
            },
            -1
        );
    }
    #[test]
    fn copying_native_arrays_preserves_non_unicode_values_and_has_a_bound() {
        let value = std::ffi::CString::new([b'a', 255]).unwrap();
        let values = [value.as_ptr().cast_mut(), std::ptr::null_mut()];
        assert_eq!(
            unsafe { copy_strings(values.as_ptr()) }.unwrap(),
            vec![OsString::from_vec(vec![b'a', 255])]
        );
        let oversized = std::ffi::CString::new(vec![b'a'; 60 * 1024 + 1]).unwrap();
        let values = [oversized.as_ptr().cast_mut(), std::ptr::null_mut()];
        assert!(unsafe { copy_strings(values.as_ptr()) }.is_err());
    }

    #[test]
    #[ignore = "explicit native ABI acceptance requires the installed upstream sudo_plugin.h and C compiler"]
    fn native_sudo_header_matches_plugin_layout() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("sudo-abi");
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/sudo_abi.c");
        let built = std::process::Command::new("/usr/bin/cc")
            .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2"])
            .arg(source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let output = std::process::Command::new(executable).output().unwrap();
        assert!(output.status.success());
        let expected = [
            std::mem::size_of::<AuditPlugin>(),
            std::mem::offset_of!(AuditPlugin, open),
            std::mem::offset_of!(AuditPlugin, accept),
            std::mem::offset_of!(AuditPlugin, event_alloc),
            std::mem::size_of::<ApprovalPlugin>(),
            std::mem::offset_of!(ApprovalPlugin, check),
            std::mem::size_of::<GroupPlugin>(),
            std::mem::offset_of!(GroupPlugin, query),
            std::mem::size_of::<Conversation>(),
        ];
        let actual: Vec<usize> = std::str::from_utf8(&output.stdout)
            .unwrap()
            .split_whitespace()
            .map(|value| value.parse().unwrap())
            .collect();
        assert_eq!(actual, expected);
    }
}
