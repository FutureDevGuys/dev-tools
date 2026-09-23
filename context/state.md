# Active work

- The current Linux `/storage` ext4 filesystem still rejects writes after an unrecovered `/dev/sda` media error, aborted ext4 journal and one ordinary remount attempt. Dev Cache 0.1.10 keeps intercepted tools usable without that cache, but native storage repair/replacement remains outside Dev Cache and is required to restore cache writes.
- GitHub's release-list and tag endpoints omit the three assets of published `dev-cache/v0.1.10` even though the release-ID and asset endpoints expose them. This blocks ordinary latest-release discovery on other hosts and the publisher's idempotence check. The current Linux host reached signed 0.1.10 through Update All's exact authenticated root/manifest URL override; resolve the provider discrepancy or release-discovery fallback before claiming ordinary distribution convergence.
- Qualify native Windows, WSL and macOS stable-volume recovery before claiming those runtime targets supported.
