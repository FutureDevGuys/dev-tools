//! Requests the cancellable loginwindow restart dialog, never an immediate reboot.
//!
//! Apple recommends kAEShowRestartDialog for programmatic restart requests:
//! https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/Lifecycle.html
//! https://developer.apple.com/library/archive/qa/qa1134/_index.html
//! Success establishes only that the event was sent, not user confirmation or a
//! completed restart. There is no privilege escalation or fallback on failure.

// The narrow native boundary is documented at every unsafe call.
#![allow(unsafe_code)]

use anyhow::{bail, Result};
use std::ffi::{c_long, c_void};

const TYPE_NULL: u32 = u32::from_be_bytes(*b"null");
const TYPE_PROCESS_SERIAL_NUMBER: u32 = u32::from_be_bytes(*b"psn ");
const CORE_EVENT_CLASS: u32 = u32::from_be_bytes(*b"aevt");
const SHOW_RESTART_DIALOG: u32 = u32::from_be_bytes(*b"rrst");
const NO_REPLY: i32 = 1;
// AppleEvents.h: return errAEEventWouldRequireUserConsent instead of asking
// for new Automation permission. Native AppleEvents do not bypass OS policy.
const DO_NOT_PROMPT_FOR_USER_CONSENT: i32 = 0x0002_0000;
const SEND_MODE: i32 = NO_REPLY | DO_NOT_PROMPT_FOR_USER_CONSENT;
// Apple event ticks are 1/60 second. Never request an unlimited reply timeout.
const SEND_TIMEOUT_TICKS: c_long = 600;

// AEDataModel.h uses two-byte packing, including on 64-bit macOS. The handle
// stays opaque and is released only by AEDisposeDesc; never dereference it or
// form a Rust reference to this potentially unaligned packed field.
#[repr(C, packed(2))]
struct AEDesc {
    descriptor_type: u32,
    data_handle: *mut c_void,
}

#[repr(C)]
struct ProcessSerialNumber {
    high: u32,
    low: u32,
}

// SAFETY: These declarations match AEDataModel.h and AEMach.h in CoreServices:
// OSErr/return IDs are signed 16-bit; OSStatus, send mode and transaction IDs
// are signed 32-bit; Size and timeout use the platform's signed long. Calls
// borrow descriptors synchronously, do not retain our stack pointers, and have
// no Rust callbacks or cross-language unwinding. This module is macOS-only.
#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn AECreateDesc(
        descriptor_type: u32,
        data: *const c_void,
        size: c_long,
        result: *mut AEDesc,
    ) -> i16;
    fn AECreateAppleEvent(
        event_class: u32,
        event_id: u32,
        target: *const AEDesc,
        return_id: i16,
        transaction_id: i32,
        result: *mut AEDesc,
    ) -> i16;
    fn AESendMessage(
        event: *const AEDesc,
        reply: *mut AEDesc,
        send_mode: i32,
        timeout_ticks: c_long,
    ) -> i32;
    fn AEDisposeDesc(descriptor: *mut AEDesc) -> i16;
}

struct OwnedDesc(AEDesc);

impl OwnedDesc {
    fn null() -> Self {
        Self(AEDesc {
            descriptor_type: TYPE_NULL,
            data_handle: std::ptr::null_mut(),
        })
    }
}

impl Drop for OwnedDesc {
    fn drop(&mut self) {
        // SAFETY: This uniquely owned descriptor is either a valid null
        // descriptor or was initialized by AppleEvents. Creation failures leave
        // null descriptors. No pointer survives disposal; the platform owns the
        // allocation. Disposing a null descriptor is allowed. Cleanup errors
        // cannot authorize retrying the already-sent restart request.
        let _ = unsafe { AEDisposeDesc(&raw mut self.0) };
    }
}

fn check_status(operation: &str, status: i32) -> Result<()> {
    if status != 0 {
        bail!("macOS restart dialog request failed or is uncertain during {operation} (OSStatus {status}); restart manually if needed; no retry or permission prompt was attempted");
    }
    Ok(())
}

pub(super) fn request() -> Result<()> {
    // Apple's system process address targets loginwindow in the current
    // session, without launching a scripting application or using an interpreter.
    let system = ProcessSerialNumber { high: 0, low: 1 };
    let mut target = OwnedDesc::null();
    let mut event = OwnedDesc::null();
    let mut reply = OwnedDesc::null();

    // SAFETY: `system` is an initialized eight-byte native PSN, alive throughout
    // the call. AECreateDesc copies it and initializes the exclusive output.
    let status = unsafe {
        AECreateDesc(
            TYPE_PROCESS_SERIAL_NUMBER,
            (&raw const system).cast(),
            8,
            &raw mut target.0,
        )
    };
    check_status("address creation", i32::from(status))?;

    // SAFETY: target is a successfully created descriptor. Output is exclusive
    // and initialized; the API copies the target and retains no Rust pointer.
    let status = unsafe {
        AECreateAppleEvent(
            CORE_EVENT_CLASS,
            SHOW_RESTART_DIALOG,
            &raw const target.0,
            -1,
            0,
            &raw mut event.0,
        )
    };
    check_status("event creation", i32::from(status))?;

    if crate::util::cancel::is_cancel_requested() {
        return Err(crate::Cancelled.into());
    }

    // SAFETY: event is valid and immutable during the call; reply is an
    // exclusive initialized descriptor. No callbacks or retained Rust pointers.
    // NO_REPLY deliberately reports submission only. The finite timeout is not
    // a promise that loginwindow has displayed or the user accepted its dialog.
    let status = unsafe {
        AESendMessage(
            &raw const event.0,
            &raw mut reply.0,
            SEND_MODE,
            SEND_TIMEOUT_TICKS,
        )
    };
    check_status("event submission", status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_restart_descriptor_abi_matches_platform_headers() {
        assert_eq!(std::mem::size_of::<ProcessSerialNumber>(), 8);
        assert_eq!(std::mem::align_of::<AEDesc>(), 2);
        assert_eq!(std::mem::offset_of!(AEDesc, data_handle), 4);
        assert_eq!(
            std::mem::size_of::<AEDesc>(),
            4 + std::mem::size_of::<*mut c_void>()
        );
    }

    #[test]
    fn macos_restart_requests_only_a_dialog_without_permission_prompt() {
        assert_eq!(SHOW_RESTART_DIALOG, u32::from_be_bytes(*b"rrst"));
        assert_ne!(SHOW_RESTART_DIALOG, u32::from_be_bytes(*b"rest"));
        assert_eq!(SEND_MODE, 0x0002_0001);
        assert_eq!(SEND_TIMEOUT_TICKS, 600);
        assert!(check_status("test", 0).is_ok());
        assert!(check_status("test", -1744).is_err());
    }
}
