# Threat model

Dev Tools treats update metadata, downloaded artifacts, external catalogs, subprocess output, prompts, and filesystem paths as untrusted inputs. It must fail closed on invalid signatures, hash or length mismatch, rollback, equivocation, revoked keys, unsupported protocols, unsafe redirects, and truncated or oversized responses.

Run journals and logs use owner-only directories, bounded capture, and configurable argument redaction. They do not persist complete environment snapshots or secret values. External catalogs cannot silently replace built-ins or one another. A failed authoritative journal write aborts the run; frontend detachment switches visibly to complete plain output without discarding events.

Please report suspected vulnerabilities privately as described in [SECURITY.md](../SECURITY.md).
