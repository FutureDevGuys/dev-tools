---
authority: canonical
owner: dev-tools
---

# update-all architecture decisions

Read the applicable records before changing `update-all` configuration,
scheduling, package-manager reconciliation, or run artifacts.

| ADR | Decision | Status | Verification |
| --- | --- | --- | --- |
| [0001](0001-ordering-versus-health-dependencies.md) | Ordering versus health dependencies | accepted | verified |
| [0002](0002-npm-lifecycle-script-attribution-and-recovery.md) | NPM lifecycle-script attribution and recovery | accepted | verified |
| [0003](0003-structured-failure-evidence.md) | Structured failure evidence | accepted | verified |
| [0004](0004-attributable-aur-failure-containment.md) | Attributable AUR failure containment | superseded | pending |
| [0005](0005-verified-repository-retirement.md) | Verified repository-retirement recovery | proposed | pending |

`proposed` plus `verification: pending` means code and automated gates exist,
but the record's runtime acceptance has not passed. `accepted` requires
`verification: verified`. A superseded proposal may remain pending when a later
record replaces it before runtime acceptance. A material change to an accepted
decision requires a new numbered record with `status: superseded` and a link
from the old record to its replacement; accepted records are not silently
rewritten.
