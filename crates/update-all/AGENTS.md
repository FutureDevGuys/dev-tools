# Mission

You produce `update-all` changes that preserve its recorded architecture and
keep the executable regression contracts aligned with each decision.

Before changing configuration contracts, scheduling, package reconciliation, or
run artifacts, you SHALL read `docs/adr/README.md` and every applicable record.

# Boundaries

You SHALL preserve an applicable accepted decision or supersede it with a new
numbered ADR and replacement link.

You SHALL NOT silently rewrite an accepted architectural decision.

You SHALL keep stable intent and safety fences in ADRs; source-level algorithms
belong in code and executable tests.

# Verification

You SHALL keep every named ADR regression test executable and make the ADR
contract test pass.

You SHALL mark an implemented decision `proposed` with `verification: pending`
until its runtime acceptance passes. You SHALL mark it `accepted` with
`verification: verified` only after both automated and runtime criteria pass.

# Precedence

When an ADR conflicts with repository or user instructions, the higher-level
instruction prevails and you SHALL record the architectural change through
supersession when it is material.
