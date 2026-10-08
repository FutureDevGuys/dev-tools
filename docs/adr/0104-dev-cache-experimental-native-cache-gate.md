---
authority: canonical
owner: dev-cache
---

# ADR 0104: Default-off experimental native cache

status: proposed
verification: pending

## Decision

This supersedes only ADR 0099's unconditional command availability. Native Docker acceptance is NOT RUN, so the product-owned `experimental-container-cache` Cargo feature defaults off. Default/stable builds exclude the native adapter module and CLI variant, omit the command from help and generated completions, and reject explicit preview/apply invocations with exit 2 before configuration reads or provider contact. No environment variable, runtime flag, configuration field or trust override enables it. The Linux-only socket dependency is optional under the same feature; existing GC cancellation remains independent.

Explicit experimental source builds retain ADR 0099's protocol, locality and mutation boundaries and tests unchanged. Their help labels the capability experimental and unqualified. The common `build-info --json` document adds the product-owned observational field `native_container_cache`, with values `disabled` or `experimental-unqualified`. The existing extensible common schema permits this field; shared and signed release schemas are unchanged. Disabled is an availability state, not qualification evidence.

Release Admin's fixed, cleared-environment default-feature recipe remains unchanged. It gains no feature-selection input or experimental release lane. Stable construction must not enable this feature through `--all-features` or any other build customization. Enabling stable native-cache support requires a separately reviewed successor decision with exact-candidate native acceptance evidence for each claimed engine, privilege domain and storage backend.

## Compatibility and verification

There is no native-scope state to migrate. Default builds reject the previously exposed experimental command; previously pruned cache remains engine-owned and cannot be restored by this guard. Existing filesystem GC, intercepts and routing remain independent and can be qualified without exposing this unqualified capability. This guard does not establish full product conformance or waive signed-distribution, installed-artifact, rollback, performance or other product release gates.

Both feature configurations require source tests and warnings-denied Clippy. Default tests check help and all five completion outputs, truthful build information, and zero connections to explicit and ambient synthetic sockets for both preview and apply, even with attempted environment opt-ins. The feature-enabled lane retains adversarial native protocol and locality tests. Generated completion checks do not establish native five-shell acceptance. Fake sockets, unit tests and compilation do not replace the [disposable native Docker acceptance](../dev-cache-native-cache.md#disposable-native-acceptance), which remains NOT RUN.
