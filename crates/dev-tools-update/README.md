# dev-tools-update

`dev-tools-update` is the product-neutral orchestration boundary for the common standalone update contract. It decides cache freshness, network eligibility, managed-installation transitions, and stable result categories while product adapters retain layout, setup, health, presentation, and authorization policy.

The crate does not perform arbitrary process execution, contain product-name branches, invoke sibling products, or choose privileged effects. Authenticated release discovery and storage adapters must construct candidates from `dev-tools-release` verification results.

Status and check assess freshness against the caller-supplied evaluation time. Evidence older than the configured maximum age, or dated after that evaluation time, produces `unknown` rather than a current/stale claim; exactly the maximum age remains fresh. A successful refresh call alone does not override this assessment. Adapters must use a consistent timestamp horizon when recording refreshed evidence. Explicit offline application may still reuse authenticated cached artifact bytes after discovery evidence expires; that permission does not establish currentness.
