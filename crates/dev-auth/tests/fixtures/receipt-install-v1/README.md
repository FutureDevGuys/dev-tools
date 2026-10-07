# Protocol conformance vectors

These fixed, nonsecret protocol bytes are checked into this repository so building/testing Dev Auth never reads another checkout. The standalone installer owner and Dev Auth consumer agreed these canonical no-newline vectors on2026-10-06. They identify no deployed authority.

- install-request.json SHA256 d2fd196d43d7f39595e89a91887230c0c2cc5f92f51b8bc1bfc7057bf8bd9c39
- status-result.json SHA256 fea1d61967c0d4fbf743983563295384d6364afe7c84e62f7b8e28967f882819

The owning producer patch is based on public Syscfg628d775295077db0a6d42f4b197bbd8b776b1bfb. Future implementations conform to the public ABI; that product's source is not a test/runtime dependency.
