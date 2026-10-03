---
authority: canonical
owner: dev-cache
---

# ADR 0093: Read-only cache-root intercept fallback

status: proposed
verification: pending

## Decision

An installed intercept whose selected cache root becomes read-only before native tool delegation runs the previously resolved original tool once, without Dev Cache environment injection or cache bookkeeping. Compiler-name intercepts bypass ccache entirely in this case. Cargo and Rustup-Cargo retain their native paths. This fallback is limited to an underlying operating-system read-only-filesystem error during routing preparation; volume identity changes, missing roots, unsafe ownership, permission denials, configuration errors and other failures retain their existing fail-closed behavior.

Once the native tool has run, an EROFS failure recording completed cache use does not replay it or replace its exit status. The cache remains unhealthy, and diagnostic commands remain read-only. Dev Cache does not remount, repair, adopt or redirect the failed filesystem, and it does not treat read-only operation as successful cache routing. The operator must repair or replace failing storage through the operating system's native process before routing resumes.

## Verification

Source tests distinguish EROFS from permission and volume-identity failures. Native acceptance must exercise candidate Cargo and compiler-name intercepts against an actually read-only configured root and confirm one original-tool invocation, unchanged exit status and no cache-root mutation. Installation of this change requires a new signed release; an unsigned development candidate is not an installed repair.
