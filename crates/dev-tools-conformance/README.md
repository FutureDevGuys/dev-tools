# dev-tools-conformance

`dev-tools-conformance` is the test-only executable harness for the common standalone product contract. It owns the explicit public-product inventory and checks product binaries through their public command-line interfaces; it is not linked into released products.

The harness runs subjects by absolute path with a cleared environment, private synthetic platform roots, closed standard input, bounded output, and a fixed timeout. Its fixtures contain no private downstream paths or policy. Network-capable checks require an explicit transport boundary and are never part of the local status or doctor checks.

During staged rollout, the inventory distinguishes current products from planned products and records whether each product has reached inventory, common build-info, or full conformance. The harness itself is exercised against a native fixture. A product becomes conformant only at the full stage, when its real release binary is in the executable matrix and every common check is mandatory.
