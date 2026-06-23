# Trust — read this before installing

A plugin that asks to upload your game's source code deserves suspicion.
The Roblox plugin ecosystem has a real malware history and no code signing,
so this document doesn't ask you to trust us — it shows you how to check.

## The permission footprint

When you first use the plugin, Roblox Studio will prompt you to allow HTTP
requests **for this plugin, to exactly ONE domain**: the backend URL you
yourself configured in Settings. That is the plugin's entire permission
surface.

- **One domain.** If Studio ever prompts for a second domain you didn't
  configure, deny it and report it.
- **NO Script Injection.** This plugin never requests the Script Injection
  permission — it reads `Script.Source` (which needs no special permission in
  Studio) and never writes to any script. **If any version of this plugin asks
  for Script Injection, refuse the prompt, uninstall it, and report it.** A
  build that asks for it is not our build.
- No file system access, no extra services, no telemetry about you. The
  plugin makes requests only when you press a button or have the Errors dock
  open (a 30-second refresh of your own error list).

## The zero-knowledge claim — audit it, don't believe it

Claim: **the BloxTools backend only ever receives ciphertext; your source and
your key never leave your machine.**

How to check it yourself:

1. **Sniff the traffic.** Point the plugin's Backend URL at a local proxy
   (mitmproxy, Fiddler, Charles — or just run the open-source backend locally
   and log bodies). Press *Upload source now*. What you will see, per script:

   ```json
   { "instancePath": "ServerScriptService.Combat",
     "iv": "<16 base64 chars>",
     "ciphertext": "<base64 noise, ~4/3 the source length>",
     "plainBytes": 18234 }
   ```

   plus one `keyFingerprint` field per request — the first 8 hex characters of
   SHA-256 of the key, which identifies the key without revealing anything
   about it. What you will NOT see, anywhere, ever: your source text, your
   project key, or anything decryptable without the key.

2. **Check the crypto.** It's AES-256-GCM, vendored in readable, commented
   Luau at `src/Crypto/` (no dependencies, nothing obfuscated, encrypt-only —
   there is deliberately no decrypt path in the plugin). The same algorithm
   is mirrored line-for-line in `tools/aes-gcm-mirror.mjs`, and the repository
   test suite proves the mirror byte-identical to WebCrypto
   (`node:crypto`) on NIST CAVP test vectors and randomized inputs:

   ```bash
   npm test   # see test/plugin-crypto-roundtrip.test.js
   ```

   A transcription-typo guard in that suite also asserts the Luau and the
   mirror carry identical cryptographic constant tables. And because the
   crypto uses no Roblox globals, you can execute the ACTUAL Luau files
   against the NIST vectors with the open-source
   [Luau CLI](https://github.com/luau-lang/luau):

   ```bash
   luau tools/luau-vectors.luau   # also runs inside `npm test` when luau is on PATH
   ```

3. **Check where the key lives.** Grep the plugin source for the key's
   journey: it is pasted once, validated, stored via Studio's per-user plugin
   settings (plaintext **on your own disk** — it's your key, on your machine),
   and used only as input to `AesGcm.encrypt`. The only derived value that
   leaves: the 8-hex-char fingerprint. Decryption happens only where YOU
   supply the key: in your browser (the dashboard) or on your own machine
   (the [BloxTools MCP server](https://github.com/bloxtoolsio/bloxtools-mcp),
   which reads the key from local env and never sends it anywhere).

What this model does NOT defend against, stated honestly: anyone with access
to your machine and your Studio profile can read the stored key and token from
plugin settings, and the BloxTools operator could ship a *different*, malicious
plugin build. The second one is what the next section is for.

## Verifying a release

Every release publishes:

- a git tag in this repository,
- the built `BloxToolsPlugin.rbxm`,
- the SHA-256 hash of that file in the release notes.

To verify the Creator Store build (or any `.rbxm` you were handed):

```bash
# 1. Hash the file you have
sha256sum BloxToolsPlugin.rbxm          # macOS: shasum -a 256

# 2. Compare against the hash in the GitHub release notes for that version.

# 3. Or rebuild it yourself from the tag and diff the hashes:
git checkout <release-tag>
rojo build default.project.json -o /tmp/BloxToolsPlugin.rbxm
sha256sum /tmp/BloxToolsPlugin.rbxm
```

If the hashes differ from the published ones, do not install it, and report it
(see [SECURITY.md](SECURITY.md)).

Rojo builds are deterministic for identical inputs; if your locally built hash
differs from the published one for the same tag and the same rojo version,
treat that as a red flag and raise an issue.

## Reporting

For ordinary bugs or questions, open an issue in this repository. For
security-sensitive findings (a build asking for Script Injection, a mismatched
release hash, a second domain prompt, or anything that looks like it could leak
your key or source), please follow the private reporting process in
[SECURITY.md](SECURITY.md) rather than filing a public issue.
