---
authority: canonical
owner: dev-tools
---

# ADR 0037: Dev Auth local doctor and explicit execution results

status: proposed
verification: pending

## Context

General-purpose callers need a local readiness observation and an explicit launch interface that cannot accidentally prompt. Execution metadata cannot replace native child streams or falsely establish that a workload started. Protected credential metadata may be inaccessible to a legitimate diagnostic caller; that is not evidence of absent enrollment or failed provider authentication.

## Decision

Dev Auth adds local `doctor [--json]` using the retained common observational v1 schema with additive product details. Doctor does not connect to a broker, access a native credential store, launch helpers or contact a provider. Credential observations distinguish presence, absence, unsafe custody, inaccessible metadata and no required slots. Provider use remains untested by this operation. Existing `status --broker` retains its explicit broker probe and gains the same credential observation vocabulary.

The explicit `workload launch` interface accepts native arguments after `--`, a noninteractive control and an optional separate result destination. Its parser is shared with static completion. Noninteractive execution cannot enter an approval dialog or a potentially interactive credential-store read. This control does not itself authorize admission; native identity and administrator policy remain independent gates.

The separate `dev-auth-execution-result-v1` document contains fixed value-free execution observations, not output, caller arguments, secrets or authority. `started=false` establishes no execution; null preserves uncertainty after an execution boundary that cannot positively report workload startup. Child output remains on its native streams, and successful result finalization preserves the backend exit or signal status. Failure to finalize the result is an operational failure, not evidence that execution did not occur.

The initial Unix destination is an absolute new file beneath a caller-owned mode-0700 directory, opened relative to a retained directory descriptor with exclusive creation and no final-symlink following. Existing entries and symlinked ancestors are rejected; the file is mode 0600. An interrupted write can leave an incomplete document, which is not a result or authorization receipt. This does not isolate the destination from a hostile process with the same native identity. Unsupported native custody adapters fail before execution.

## Compatibility and incomplete integration

Legacy workload aliases retain their default interactive behavior. The existing verified nested exec-replacement path cannot finalize a result document and rejects that combination before execution until an owned child lifecycle replaces that limitation. Enrollment-authorized outer admission, provider checks, native non-Linux custody and signed-release acceptance remain delivery work. This record does not claim those capabilities from parser or component tests and does not change enrollment, policy or broker-protocol authority.

## Verification

Public CLI tests cover local JSON, value-free failure output, native trailing arguments, invalid-input no-mutation and result destination custody. Disposable installed copies exercise doctor under syscall tracing with no network, child execution or managed writes. Full product tests and strict native/target builds accompany the slice; native platform and signed-release acceptance remain independent gates documented in the product acceptance inventory.
