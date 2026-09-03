//! Process-lifetime cooperative interruption for convergence.
//!
//! The first Ctrl-C received while a convergence is running requests orderly
//! cancellation. Repeated signals coalesce while owned work is being cleaned
//! up. The transition to `Finalizing` is the linearization point: a signal
//! observed before it produces exit 130 and interrupted run metadata; signals
//! received after it are ignored so terminal publication cannot be rewritten.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::OnceLock;

use thiserror::Error;

const IDLE: u8 = 0;
const RUNNING: u8 = 1;
const CANCEL_REQUESTED: u8 = 2;
const FINALIZING: u8 = 3;

static LIFECYCLE: AtomicU8 = AtomicU8::new(IDLE);
static CANCELLED: AtomicBool = AtomicBool::new(false);
static HANDLER: OnceLock<Result<(), ()>> = OnceLock::new();

fn request_cancellation() {
    if LIFECYCLE
        .compare_exchange(
            RUNNING,
            CANCEL_REQUESTED,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
        || LIFECYCLE.load(Ordering::Acquire) == CANCEL_REQUESTED
    {
        CANCELLED.store(true, Ordering::Release);
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum InterruptSetupError {
    #[error("cannot install the process interruption handler")]
    HandlerUnavailable,
    #[error("another in-process convergence is already active")]
    AlreadyActive,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("convergence interrupted")]
pub struct Interrupted;

pub struct RunGuard;

impl RunGuard {
    pub fn begin() -> Result<Self, InterruptSetupError> {
        let installed =
            HANDLER.get_or_init(|| ctrlc::set_handler(request_cancellation).map_err(|_| ()));
        if installed.is_err() {
            return Err(InterruptSetupError::HandlerUnavailable);
        }

        LIFECYCLE
            .compare_exchange(IDLE, RUNNING, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| InterruptSetupError::AlreadyActive)?;
        Ok(Self)
    }

    /// Freeze the terminal outcome. The returned value is authoritative for
    /// the run's exit code and terminal metadata.
    pub fn begin_finalization(&mut self) -> bool {
        loop {
            match LIFECYCLE.load(Ordering::Acquire) {
                RUNNING => {
                    if LIFECYCLE
                        .compare_exchange(RUNNING, FINALIZING, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        return false;
                    }
                }
                CANCEL_REQUESTED => {
                    if LIFECYCLE
                        .compare_exchange(
                            CANCEL_REQUESTED,
                            FINALIZING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                FINALIZING => {
                    return CANCELLED.load(Ordering::Acquire);
                }
                _ => return CANCELLED.load(Ordering::Acquire),
            }
        }
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        CANCELLED.store(false, Ordering::Release);
        // Publish IDLE only after the prior run's cancellation state is clear.
        // A new guard cannot then begin between these stores and have its own
        // cancellation request erased by the previous guard's drop.
        LIFECYCLE.store(IDLE, Ordering::Release);
    }
}

pub fn check() -> Result<(), Interrupted> {
    if CANCELLED.load(Ordering::Acquire) {
        Err(Interrupted)
    } else {
        Ok(())
    }
}

pub(crate) fn cancellation_flag() -> &'static AtomicBool {
    &CANCELLED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_repeated_and_late_cancellation_have_stable_outcomes() {
        let mut guard = RunGuard::begin().expect("begin");
        request_cancellation();
        request_cancellation();
        assert!(check().is_err());
        assert!(guard.begin_finalization());
        drop(guard);

        let mut guard = RunGuard::begin().expect("begin next run");
        assert!(!guard.begin_finalization());
        request_cancellation();
        assert!(check().is_ok(), "late signals must not rewrite the outcome");
    }

    #[test]
    fn rejected_overlapping_run_does_not_clear_active_cancellation() {
        let guard = RunGuard::begin().expect("begin active run");
        request_cancellation();

        let error = match RunGuard::begin() {
            Ok(_) => panic!("overlapping run must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error, InterruptSetupError::AlreadyActive);
        assert!(
            check().is_err(),
            "a rejected overlapping run cleared active cancellation"
        );
        drop(guard);
    }
}
