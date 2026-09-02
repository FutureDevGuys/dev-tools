# Shared command execution

`dev-tools-command` is the product-neutral authority for ordered executable discovery, native `PATH` composition, and bounded execution of an exact caller-selected program inside Dev Tools. It preserves platform search semantics, requires executable files, compares command locations through canonical parent directories, uses the operating system's path-list encoding rather than constructing path strings manually, and captures explicitly bounded output without pipe backpressure.

The crate does not choose which commands are trusted, install launchers, mutate shell configuration, interpret output, or grant credentials. Products retain those policy decisions and must supply the exact executable, arguments, environment, working directory, timeout, and output limit for bounded execution. Dev Cache uses the shared discovery surface for its owned intercept audit, while dev-auth uses the shared path composer for its session-private workload tool plane.
