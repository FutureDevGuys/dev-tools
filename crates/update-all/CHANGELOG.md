# UpdateAll changelog

## 0.1.17

- On Linux, interactive tasks declaring sudo use share the startup terminal and authentication. Native input stays with the foreground command while stdout, stderr, custom result footers, and reports remain captured. Direct sudo launches cannot request another password or replay protected effects. Explicit external windows keep separate authentication.
- Open logs at the end in browse mode. In Less, `q` returns and `F` follows new output.
- On Linux, give the viewer its own foreground process group. Viewer interrupts do not cancel updates; a signal sent to UpdateAll still cancels the run and cleans up the viewer.
- Show deferred and unconfirmed observations separately from process completion in the dashboard, final summary, and run history.
- Read explicitly configured generic product result documents without product-specific branches. Keep available versions separate from observed installed versions.
- Keep missing post-timeout inventory unknown and preserve observed partial results. Command deadlines and retry policy are unchanged.
- Show command diagnostics outside package-change tables and name failures after the selected task instead of its wrapper executable.
- Accept npm tilde version ranges without treating them as local filesystem dependencies.

Run report consumers must tolerate the additional `deferred` and `unconfirmed` row values and optional task presentation metadata. The task lifecycle vocabulary is unchanged.

Linux terminal tests do not establish non-Linux interrupt isolation. Signed release and installed acceptance remain separate from source tests.
