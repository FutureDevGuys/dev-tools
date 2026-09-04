# Provider-neutral secret operations

`dev-tools-secret` is the shared Rust contract for provider-neutral secret operations. Products compile it and their selected provider adapters into standalone binaries; they do not call a sibling product or discover ambient provider credentials.

The crate distinguishes logical names from opaque provider-native references and distinguishes exportable reads, public material, metadata, and operation-only signing. Secret bytes are bounded, cannot be cloned, formatted, or serialized, and are zeroized on drop. Fixed error categories reveal no provider output, reference, or value.

Every provider call receives one process-local absolute deadline and cancellation signal. A multi-stage adapter retains that context in its trusted coordinator across authentication, discovery, network requests, and final publication so no stage resets the authority window. The context is not transportable authority: when an adapter uses a child process, the parent derives a bounded child timeout from the remaining budget, retains cancellation, and owns terminalization. The product remains responsible for policy, logical-name resolution, audit records, and safe child-process projection.

Dev Auth uses 1Password as its first adapter. Its enrolled service-account token remains broker-only and reaches the retained provider child through a sealed private transport. Direct `op` remains a human command and does not inherit Dev Auth automation authority. Additional providers use the same interface only after their custody and live-operation contracts are accepted.
