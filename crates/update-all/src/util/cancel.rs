use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static CANCEL_REQUESTED: AtomicBool = AtomicBool::new(false);
static SIGNAL_CANCEL_SUPPRESSIONS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
pub struct SignalCancelSuppression;

impl Drop for SignalCancelSuppression {
    fn drop(&mut self) {
        SIGNAL_CANCEL_SUPPRESSIONS.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn request_cancel() {
    if SIGNAL_CANCEL_SUPPRESSIONS.load(Ordering::SeqCst) > 0 {
        return;
    }
    CANCEL_REQUESTED.store(true, Ordering::SeqCst);
}

pub fn is_cancel_requested() -> bool {
    CANCEL_REQUESTED.load(Ordering::SeqCst)
}

pub fn suppress_signal_cancel() -> SignalCancelSuppression {
    SIGNAL_CANCEL_SUPPRESSIONS.fetch_add(1, Ordering::SeqCst);
    SignalCancelSuppression
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset() {
        CANCEL_REQUESTED.store(false, Ordering::SeqCst);
        SIGNAL_CANCEL_SUPPRESSIONS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn signal_cancel_suppression_ignores_cancel_until_guard_drops() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset();

        {
            let _guard = suppress_signal_cancel();
            request_cancel();
            assert!(!is_cancel_requested());
        }

        request_cancel();
        assert!(is_cancel_requested());
        reset();
    }

    #[test]
    fn signal_cancel_suppression_is_nested() {
        let _lock = TEST_LOCK.lock().unwrap();
        reset();

        let outer = suppress_signal_cancel();
        {
            let _inner = suppress_signal_cancel();
            request_cancel();
            assert!(!is_cancel_requested());
        }
        request_cancel();
        assert!(!is_cancel_requested());
        drop(outer);

        request_cancel();
        assert!(is_cancel_requested());
        reset();
    }
}
