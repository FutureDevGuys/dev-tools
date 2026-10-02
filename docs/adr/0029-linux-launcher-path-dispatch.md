---
authority: canonical
owner: dev-tools
---

# ADR 0029: Linux launcher path dispatch

status: proposed
verification: pending

An exported zsh `ARGV0` can replace a launched program's argv[0], and zsh may remove that environment variable before executing the child. Checking the child's environment is therefore insufficient. Linux public launcher dispatch uses the kernel-provided `AT_EXECFN` invocation path to recover the actual invoked basename, independently of rewritten argv[0]. This preserves symlink launchers such as git and gh without resolving away their names through current_exe.

The pathname selects a route only; it never grants authority. Every existing receipt, executable, workload, broker and policy check still applies. Core executable calls that explicitly select the existing provider-exec or setup-helper internal entrypoints retain those entrypoints' descriptor/plan checks. Descriptor execution retains its existing explicit argv[0] contract because its kernel filename is a descriptor path rather than a public alias. Unknown executable names (including validated setup candidates and workload aliases) and other platforms retain their current dispatch pending native qualification. This change fixes transparent public frontend routing; it does not claim ARGV0 recovery for arbitrary workload aliases.

The workload environment filter removes ARGV0 before launching admitted children, preventing inherited contamination of nested zsh commands. This does not modify the user's shell or persistent settings.

Public CLI tests compare ordinary and rewritten invocations for git, gh, core names with invalid, uninstalled and other frontend override values, including real zsh when installed. They assert equal output/status and no switch to a foreign frontend; they do not claim successful installed Git authorization in a fixture without receipts. Existing private helper tests and native signed installed acceptance remain separate gates. No signed release version or existing artifact is reissued by this source change.

Kernel interface reference: https://man7.org/linux/man-pages/man3/getauxval.3.html (`AT_EXECFN` is the pathname used to execute the program).
