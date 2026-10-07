# Protocol conformance vectors

These fixed, nonsecret protocol bytes are checked into this repository so building/testing Dev Auth never reads another checkout. The standalone installer owner and Dev Auth consumer agreed these canonical no-newline vectors on2026-10-06. They identify no deployed authority.

- install-request.json SHA256 2e06c1950731a734e333f12d9de9d16d77ed5d761d15fbe60e4e2dd1295a8112
- status-result.json SHA256 fea1d61967c0d4fbf743983563295384d6364afe7c84e62f7b8e28967f882819

The generation identifier is a synthetic public example. Conformance depends only on the public ABI and these checked-in vectors. No downstream implementation or repository is required.
