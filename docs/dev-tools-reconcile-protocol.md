# Typed external reconciliation

`dev-tools-reconcile-protocol` owns the fixed `dev-tools-reconcile-result-v1` wire contract shared by independently installed Dev Tools products and configuration clients. Results expose only `changed`, `verified`, `deferred`, sorted credential-slot identifiers, one public next-action token, and sorted public diagnostic tokens. The crate validates and canonically hashes the contract and publishes its strict JSON Schema.

The protocol is not an orchestration language. It contains no shell string, arbitrary command template, installation path, privilege escalation, service operation, credential value, or product-specific desired state. A product owns its own plan, apply, receipt, and verification semantics; a client such as sync-configs owns private plan custody, fixed argv invocation, timeout handling, and presentation.
