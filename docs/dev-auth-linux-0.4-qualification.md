# Dev Auth 0.4.0 Linux qualification

This evidence covers the signed Linux x86-64 release and its bounded native workload and setup contracts. It does not claim completion of general administrator sessions, continuation bindings, the full common update interface or native support on other platforms.

## Released identity

The immutable [dev-auth/v0.4.0 release](https://github.com/FutureDevGuys/dev-tools/releases/tag/dev-auth%2Fv0.4.0) is bound to clean source `a4b7de65dd42777e1b22e6d7d435bedb38a42177`. Two independent native `release-admin set build` invocations produced byte-identical release directories. Native set verification and the retained 0.3.11 verifier both authenticated the successor.

| Field | Value |
| --- | --- |
| Product / target | `dev-auth` / `linux-x86_64` |
| Product version / manifest generation | `0.4.0` / `24` |
| Root generation | `1` |
| Artifact length | `22633448` bytes |
| Artifact SHA-256 | `47e990721bf263b1e4e0f6ba6e607bc7ae0389a3d4bdae4065338fb53ad480d8` |
| Manifest SHA-256 | `8fa3c3838ceea39c97b9e17a779c89eb01651d0705883faa3fd0019413e7bc38` |
| Root document SHA-256 | `6ce83859ed938fd24716061ec998e5721bb49f7471524e6a6b37cc85b2f79f72` |

The native publisher verified the automation-signed tag against the declared source and signing identity, published the exact three assets, anonymously downloaded them and checked each length and digest. Release construction, signing, publication and privileged installation used separate authority boundaries; no routine private signing key was exported.

A subsequent native publication of the same set returned `verified=true` and `changed=false` through the installed 0.4.0 broker.

## Installed migration and operations

The host acceptance upgraded the existing signed 0.3.11 strong installation to the exact artifact above using a digest-bound full setup plan. It preserved the existing enrollment, retained prior-generation authority and legacy configuration, installed the reviewed v3 policy/configuration, and passed full verification. A newly generated equivalent plan applied and verified with no changes.

The installed general-purpose workload authenticated the enrolled provider, checked four declared resources and five operation-key uses, accessed the scoped GitHub repository, created and verified an automation-signed Git commit, proved SSH authentication signing, and reproduced the exact release-manifest signature. An attempted raw read of an operation-only signing key returned `resource_denied` with no resource output. The workload exited successfully and its native service was removed.

The live check also exposed a diagnostic-only defect in 0.4.0: `doctor` uses legacy-only preliminary readiness readers and can report `policy_ready=false` for working v3 authority. Full setup verification, explicit configuration validation and the credential operations above are separate evidence. The 0.4.1 source correction selects the active schema and matching configuration path; its public installed-CLI regression also rejects fallback to a retained v2 configuration when the selected v3 document is missing.

## Executable evidence

The optimized four-crate test run (`dev-auth`, `dev-tools-command`, `dev-tools-installation` and `release-admin`) completed 49 suites with 799 passing tests, no failures and 51 explicitly ignored native or opt-in tests. The standalone optimized CLI suite completed 62 tests with two ignored. All-target Clippy for those crates, formatting and the selected Windows GNU compile check also passed. Windows compilation is not native runtime acceptance.

Separate disposable-systemd runs exercised the ignored native cases. Each rootful container had no host mounts or network, private PID/cgroup/IPC/UTS namespaces, bounded resources and only synthetic encrypted enrollment. The signed candidate and retained signed 0.3.11 artifact were copied without stripping or alteration.

- `native_disposable_signed_fresh_install_workload_and_restore` exercised public signature verification, plan/apply/verify, a second plan/apply no-op, real set-ID dispatch and non-root broker admission, provider validation, logical read and stdin projection, then public initial restoration and unchanged retry.
- Its expiry, revocation, dispatcher-death and broker-death cases required both the worker and its detached TERM-ignoring descendant to terminate within twenty seconds, followed by removal of the workload unit and release of setup exclusion.
- `native_disposable_signed_legacy_upgrade_and_restore` exercised public installation and unchanged repeat of authenticated 0.3.11, upgrade and unchanged repeat of signed 0.4.0, an enrolled native credential operation, then public restoration of the exact prior policy, configuration and installation while preserving enrollment. Restoration left integrations inactive and repeated unchanged.

The qualification harness includes two test-input corrections relative to the immutable artifact source: explicit `--channel stable` arguments and distinct native Git, gh, SSH and ssh-keygen paths for the retained V2 policy. Both corrections affect only the fixture. The qualified production artifact remains the exact source-bound release above.

These runs establish the exercised Linux signed setup, workload containment and restoration paths. They do not substitute for power-loss testing, every interrupted setup phase, overnight refresh, arbitrary distribution-wide service overrides or independent non-Linux custody and process acceptance. The broader inventory remains in [executable acceptance](dev-auth-acceptance.md).
