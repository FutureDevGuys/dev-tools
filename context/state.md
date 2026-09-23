# Active work

- The current Linux `/storage` ext4 filesystem is kernel-remounted read-only after an unrecovered `/dev/sda` media error and aborted journal. Dev Cache cannot repair the mounted filesystem or resume caching until native storage repair/replacement; qualify and release the narrowly scoped original-tool fallback in ADR 0093 without presenting it as disk repair.
- Qualify native Windows, WSL and macOS stable-volume recovery before claiming those runtime targets supported.
