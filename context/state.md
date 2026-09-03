# Active work

- Publish and accept the prepared Update All 0.1.6 generation 7 and Python sync-configs 0.1.13 generation 13 after the operation-only Dev Auth v0.3.8 publisher is live; do not use raw release keys or ambient human GitHub credentials.
- Integrate the native Rust sync-configs 0.2.0 branch onto a clean Dev Tools `main`, then publish and accept that native release before retiring the Python zipapp path.
- Add an enforceable manifest capability precondition atomically with the Rust Syscfg cutover so permissive 0.1.11 clients fail before authentication, hooks, or writes.
- Extend the one-target release contract and run native WSL, Windows, and macOS acceptance before advertising those Rust targets as supported; Linux x86-64 remains the only accepted release target meanwhile.
