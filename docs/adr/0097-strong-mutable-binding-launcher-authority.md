---
authority: canonical
owner: dev-auth
---

# ADR 0097: Strong mutable binding launcher authority

status: proposed
verification: pending

## Decision

An explicitly mutable binding may name a user-owned executable in a strong workload only when the configured administrator policy, digest-bound binding plan, root-custodied installed binding set and receipt-owned public alias all select the same native owner, workload and canonical launcher. Setup checks native same-user path custody before mutation. The authenticated root dispatcher, admitted non-root supervisor, gated child and sandbox child repeat that selection at their own boundaries. A normal strong workload with no matching active mutable binding keeps its root-owned launcher rule. Removing or changing the binding closes the user-owned route rather than falling back to the path alone.

The full setup transaction carries its validated exact mutable launcher selections into administrator-policy reconciliation. That reconciler rechecks each selected executable's native owner and verifies every selected path is in the same administrator policy; unselected trusted launchers and all native tools, providers and sandbox adapters remain root-owned. Direct policy installation or update supplies no binding selection and therefore retains the root-owned trusted-launcher rule. This closes the planning-versus-installation mismatch without granting a policy-only route to user-owned code.

The binding approves later edits at that location; it does not claim immutable pinned bytes. Native cgroup, broker/session identity, privilege-coordinator, sandbox, stream and terminal authority remain independent and unchanged. The root dispatcher reads only a product-owned binding receipt and checks the owner account's exact installed alias; it never accepts a caller-supplied executable path, PID, environment hint or copied receipt as authorization. Rechecking at each boundary prevents an earlier successful plan or alias lookup from substituting for current native custody.

Binding lookup recognizes two installed caller shapes, not an arbitrary executable: the version-layout runtime under its existing receipt validation, and the exact dedicated root dispatcher after its independent launcher/sidecar verification. This lets the dispatcher check a strong binding before it starts the versioned transient workload without treating a copied launcher path or environment variable as installed authority.

## Remaining gate

Source checks prove that root-owned launchers still pass, unreceipted user-owned launchers still fail, and a user-owned target in a strong setup plan requires an exact account/workload binding rather than merely sharing an approved path. User-only mutable binding fixtures continue to pass. A disposable rootful systemd fixture passes the positive strong route, initial and repeat accepted recovery, later mutable edit visibility, nested launch and inactive owned restoration. The same headless image invokes the receipt-owned desktop entry through native `gio launch`, a transient systemd service invokes the published alias under the selected account, and native Git invokes that alias as an editor child; each reaches the admitted workload's synthetic credential check. These do not prove a graphical desktop session, a durable real-world service, or other editors. Remaining interruption, sandbox adapter, terminal/signal, signed distribution and installed-host gates remain open. A disposable unsigned fixture does not establish supported release authority.
