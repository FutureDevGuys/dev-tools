# dev-tools-product

`dev-tools-product` defines product-neutral identity, build-information, operation-result, and exit-category contracts shared by independently released Dev Tools products.

The crate contains no product registry, release discovery, installation layout, network client, command runner, or product policy. Each product compiles this crate into its own executable and supplies its own identity and operation adapter.

The JSON documents in `schema/` are observational schemas: consumers must require the declared major schema and required fields while tolerating additive fields. Authority-bearing inputs belong to their owning protocol crates and continue to deny unknown fields.
