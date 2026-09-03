# Active work

- Wait for the operation-only Dev Auth v0.3.9 setup and publisher to pass live acceptance and reach authoritative `main`, then integrate this native cutover without using raw keys or ambient human GitHub credentials.
- Rebuild, publish, install, and accept Update All 0.1.6 generation 7 and native sync-configs 0.2.0 generation 14 from the final merged source; the earlier `acd45e4` Update All artifact and Python sync-configs 0.1.13 release artifact are superseded and must not be published.
- Run the current Syscfg manifest through the installed native client twice and require the second pass to perform no configuration mutations or unnecessary authentication.
- Extend the one-target release contract, add receipt-backed Windows installation plus audited ACL/process custody, and run native WSL, Windows, and macOS acceptance before advertising those Rust targets as supported; Linux x86-64 remains the only accepted release target meanwhile.
