# Bounded administrator lease lifecycle

This independently versioned Rust foundation implements the local lease lifecycle in ADR 0004 without external dependencies. It has no native backend, authorizer, daemon, timer, command runner, credential input, or network behavior. It is not yet a usable administrator-session facility.

The trusted product coordinator owns the non-cloneable lifecycle, validates native caller/workload identity and policy before each admission, and supplies monotonic timestamps from one native clock with the required suspension semantics. Standard limits are 30 minutes idle and two hours hard. Administrator policy may explicitly select limits up to eight hours hard. Polling does not extend either deadline; accepted activity only resets idle expiry. Use exhaustion rejects a new operation without killing the last approved operation.

Expiry, clock regression, or explicit revocation enters `Stopping`, which rejects all admissions but does not claim that native work stopped. The coordinator cancels and joins its retained execution boundary before reporting complete cleanup. Failed cleanup remains nonterminal, and a later successful retry retains the failure history. There is no transition back to active and no serialization or cloning of the live use budget.

Identity-bound lease registries, conserved delegation, executable DAGs, native containment, and product CLI integration remain required before any platform supports administrator sessions. Fake-clock contract tests prove only this local state machine, never operating-system enforcement.
