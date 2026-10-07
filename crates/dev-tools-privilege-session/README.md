# Reusable bounded authority foundations

This focused Rust crate supplies a non-cloneable lease lifecycle, immutable operation/plan/resource binding, conserved shared/per-operation uses, replay protection and one-in-flight reusable admission. Completion permits later transactions; expiry, revocation and authority loss close admission. Gate failures do not refund authority or permit blind retries. Cleanup failures remain sticky.

The standard convenience values remain thirty minutes idle and two hours hard; explicit policy is still capped at eight hours. No convenience value grants permission. Trusted useful activity can reset idle expiry within the original hard deadline; polling and status cannot.

The Linux module provides root-custodied held cgroup directories, kernel peer pidfds, fresh gated child placement, cgroup.kill, populated=0 and retained child joins. These are explicit native mechanisms, not a complete administrator authorization service. Products must own policy/helper custody, native approval, independent hard-deadline/coordinator-death enforcement and payload restrictions. It does not contain unrestricted root merely because a process is in a cgroup.

Source/synthetic tests and opt-in disposable-systemd fixtures are separate. Native installation, complete product containment and signed-release acceptance cannot be inferred from the local lifecycle tests. Delegation is not implemented. See ADRs 0004 and 0094 and the product qualification record.
