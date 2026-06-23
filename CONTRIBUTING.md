# Contributing

Thanks for your interest in the BloxTools Studio plugin. This is pure Luau built
with [rojo](https://rojo.space), plus a small Node-based crypto proof suite.

## Prerequisites

- **Node.js ≥ 20** (for the crypto test suite — uses only Node built-ins, no
  dependencies to install).
- **[rojo](https://rojo.space) ≥ 7** to build the plugin `.rbxm`. The easiest way
  is [rokit](https://github.com/rojo-rbx/rokit), which pins the exact version
  from [`rokit.toml`](rokit.toml):
  ```bash
  rokit install
  ```
  (You can also install rojo by any means you like; `rokit.toml` records the
  version CI uses.)
- **Optional: the [Luau CLI](https://github.com/luau-lang/luau)** to execute the
  actual Luau crypto against the NIST vectors locally. Without it, that one test
  skips and the Luau side rests on the line-correspondent mirror + the Studio
  test plan.

## Clone and build

```bash
git clone https://github.com/bloxtoolsio/bloxtools-plugin
cd bloxtools-plugin
rokit install
rojo build default.project.json -o BloxToolsPlugin.rbxm
```

Install the resulting `BloxToolsPlugin.rbxm` into your Studio plugins folder (see
[README.md](README.md#install)) and restart Studio.

> `*.rbxm` is gitignored — it is a build/release artifact, never committed. CI
> builds it on every push and attaches it to GitHub releases on tag.

## Run the crypto proof suite

```bash
npm test
```

This runs `node --test` over `test/`, which:

- proves the Node mirror (`tools/aes-gcm-mirror.mjs`) is byte-identical to
  WebCrypto (`node:crypto`) on NIST CAVP AES-256-GCM vectors and randomized
  inputs;
- checks SHA-256 and base64 against `node:crypto` / `Buffer`;
- asserts the Luau and the mirror carry identical cryptographic constant streams
  (a transcription-typo guard);
- when a `luau` binary is on `PATH` (or `LUAU_BIN` is set), executes the **actual
  Luau** modules in `src/Crypto/` against the same vectors via
  `tools/luau-vectors.luau`.

If you change anything in `src/Crypto/`, you **must** keep
`tools/aes-gcm-mirror.mjs` line-correspondent with it (same functions, same
order, same constants) — the suite enforces the constant streams match, and a
human review confirms the logic does.

### Regenerating the Luau vectors

`tools/vectors.luau` is generated from `test/plugin-crypto.vectors.json`. If you
change the vectors, regenerate and commit:

```bash
npm run gen-vectors      # = node tools/gen-vectors-luau.mjs
```

The test suite fails if `tools/vectors.luau` is out of sync.

## In-Studio acceptance checks

The Studio wiring (toolbar, docks, HTTP, jump-to-line, settings persistence,
Pro+ gating) can't run in CI — there is no Roblox runtime. Those are verified by
hand following [PLUGIN_TESTPLAN.md](PLUGIN_TESTPLAN.md).

## Pull request flow

1. Fork and branch from `main`.
2. Make your change. Keep crypto changes mirror-synced (see above).
3. Run `npm test` — it must be green (the Luau-CLI test may show as skipped if you
   don't have `luau` installed; that's fine).
4. If you touched Studio wiring, walk the relevant section of
   `PLUGIN_TESTPLAN.md` and note what you verified in the PR.
5. Open a PR with a clear description. CI will build the `.rbxm` and run the test
   suite.

## Reporting security issues

Do **not** open a public issue for anything that could leak a key, token, or
source. Follow [SECURITY.md](SECURITY.md).

## License

By contributing you agree your contributions are licensed under the project's
[MIT License](LICENSE).
