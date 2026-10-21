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
    use std::process::{Command, Stdio};
    use std::sync::Mutex;
    use std::time::Duration;
    use wait_timeout::ChildExt;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    // These tests mutate production-global cancellation and suppression state.
    // A test-local mutex cannot protect unrelated captures or suppression guards.
    fn run_in_isolated_process(test_name: &str) -> bool {
        const CHILD_TEST: &str = "UPDATE_ALL_CANCEL_TEST_CHILD";
        if std::env::var(CHILD_TEST).as_deref() == Ok(test_name) {
            return false;
        }

        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", test_name, "--test-threads=1", "--color=never"])
            .env(CHILD_TEST, test_name)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn isolated cancellation test");
        let status = child.wait_timeout(Duration::from_secs(10));
        if !matches!(&status, Ok(Some(_))) {
            let _ = child.kill();
        }
        let output = child
            .wait_with_output()
            .expect("reap isolated cancellation test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            matches!(&status, Ok(Some(status)) if status.success()),
            "isolated cancellation test {test_name} failed or timed out: {status:?}\n{stdout}\n{stderr}"
        );
        assert!(
            stdout.contains(&format!("test {test_name} ... ok")),
            "isolated cancellation test did not execute its exact target: {stdout}\n{stderr}"
        );
        true
    }

    fn reset() {
        CANCEL_REQUESTED.store(false, Ordering::SeqCst);
        SIGNAL_CANCEL_SUPPRESSIONS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn signal_cancel_suppression_ignores_cancel_until_guard_drops() {
        if run_in_isolated_process(
            "util::cancel::tests::signal_cancel_suppression_ignores_cancel_until_guard_drops",
        ) {
            return;
        }
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
        if run_in_isolated_process("util::cancel::tests::signal_cancel_suppression_is_nested") {
            return;
        }
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
