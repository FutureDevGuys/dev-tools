# dev-tools-update

`dev-tools-update` is the product-neutral orchestration boundary for the common standalone update contract. It decides cache freshness, network eligibility, managed-installation transitions, and stable result categories while product adapters retain layout, setup, health, presentation, and authorization policy.

The crate does not perform arbitrary process execution, contain product-name branches, invoke sibling products, or choose privileged effects. Authenticated release discovery and storage adapters must construct candidates from `dev-tools-release` verification results.
