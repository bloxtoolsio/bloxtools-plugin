# BloxTools Studio Plugin

A Roblox Studio plugin for [BloxTools](https://bloxtools.io) — error monitoring
for Roblox experiences — with two features:

1. **Encrypted source upload.** After you publish, press **Upload source now**:
   the plugin enumerates every `Script` / `LocalScript` / `ModuleScript` in the
   place, encrypts each one **on your machine** with a key only you hold
   (AES-256-GCM), and uploads only ciphertext. Decryption happens only where
   you hold the key: the BloxTools dashboard decrypts in your browser, and the
   [BloxTools MCP server](https://github.com/bloxtoolsio/bloxtools-mcp) decrypts
   locally so your AI agent can read the source lines around a crash. BloxTools'
   servers can never read your code — see [TRUST.md](TRUST.md) for the full,
   auditable claim.
2. **Error inspector dock.** A live list of your experience's open error groups,
   right inside Studio. Click one and Studio opens the offending script at the
   offending line.

> The Studio inspector and source-upload features are a **Pro+** feature: they
> use a personal access token, and a Free account is gated with an in-plugin
> upgrade prompt. The plugin itself is open source and free to build and read.

## Why trust it?

A plugin that uploads your game's source deserves suspicion, and the Roblox
plugin ecosystem has no code signing. So the design is **zero-knowledge** and
**auditable**, not "trust us":

- The plugin encrypts client-side with a key **you** generate in the dashboard
  and paste into Settings. The key never leaves your machine; only an 8-hex-char
  fingerprint of it ever goes on the wire.
- The crypto is vendored as readable, commented, dependency-free Luau in
  [`src/Crypto/`](src/Crypto) (encrypt-only — there is deliberately no decrypt
  path in the plugin).
- That Luau cipher is mirrored line-for-line in
  [`tools/aes-gcm-mirror.mjs`](tools/aes-gcm-mirror.mjs), and the test suite
  proves the mirror byte-identical to WebCrypto on NIST CAVP vectors — and runs
  the **actual Luau** against those same vectors when the
  [Luau CLI](https://github.com/luau-lang/luau) is available.
- The plugin requests **exactly one** permission: HTTP access to the single
  backend domain you configure. It never requests Script Injection.

Read [TRUST.md](TRUST.md) for how to verify all of this yourself, including how
to check a release `.rbxm` against its published SHA-256.

## Install

### Option A — download the release `.rbxm` (recommended)

1. Download `BloxToolsPlugin.rbxm` from the
   [latest GitHub release](https://github.com/bloxtoolsio/bloxtools-plugin/releases).
2. (Recommended) verify its SHA-256 against the hash in the release notes — see
   [TRUST.md](TRUST.md#verifying-a-release).
3. Install it:
   - **Windows:** copy `BloxToolsPlugin.rbxm` into `%LOCALAPPDATA%\Roblox\Plugins`
   - **macOS:** copy it into `~/Documents/Roblox/Plugins`
   - Or, in Studio: **Plugins** tab → **Plugins Folder**, and drop the file there.
4. Restart Studio; a **BloxTools** toolbar appears under the Plugins tab.

### Option B — build from source (for the skeptical)

Requires [rojo](https://rojo.space) (≥ 7). If you use
[rokit](https://github.com/rojo-rbx/rokit), `rokit install` reads the pinned
version from [`rokit.toml`](rokit.toml):

```bash
git clone https://github.com/bloxtoolsio/bloxtools-plugin
cd bloxtools-plugin
rokit install            # installs the pinned rojo (or install rojo yourself)
rojo build default.project.json -o BloxToolsPlugin.rbxm
```

Then install `BloxToolsPlugin.rbxm` exactly as in Option A, step 3.

## Connect

1. Install the plugin (above) and create a BloxTools account at
   <https://bloxtools.io>.
2. In the dashboard, copy your **access token** (`blxt_…`) and your
   **project key** (encrypts your source). Both are provisioned for you — no
   scopes to pick, nothing to mint by hand.
3. In Studio, open **BloxTools → Settings** and fill in:
   - **Access token** — paste the `blxt_…` token. The plugin shows only its last
     4 characters afterwards.
   - **Project key (encrypts your source)** — paste it. The plugin shows the
     key's *fingerprint* (8 hex chars); confirm it matches the dashboard. The
     key is never displayed again and never leaves your machine.
   - **Game** — press *Load my games* and click the game this place belongs to.
   - **Backend URL** — pre-filled to the hosted production backend. Leave it as
     is; only change it if you self-host.
4. Publish your place, then press **Upload source now** (see *Use* below). The
   first request makes Studio ask permission for the plugin to call the backend
   domain — exactly one domain, the only permission it ever requests. **If any
   version of this plugin asks for Script Injection, refuse it and report it**
   (see [TRUST.md](TRUST.md)).

Settings persist via Studio's per-user plugin settings, as plaintext on your own
disk. That is deliberate: the key is *yours*, held on *your* machine — treat that
file like you treat the key.

## Use

The plugin runs in **edit sessions only**; during playtests it deliberately
no-ops (a playtest is a throwaway copy stamped `PlaceVersion 0`).

- **Upload source:** publish your place (File → Publish), then open the
  **Errors** dock and press **Upload source now**. There is no publish event in
  the Studio plugin API, so upload is an explicit button rather than an
  unreliable hook — the dock shows the place version it is uploading so you can
  tell at a glance you published first. Re-uploading the same version replaces it.
- **Inspect errors:** open **BloxTools → Errors**. The dock lists open error
  groups (count, message, top frame), refreshes every 30 s while open, and on
  demand. Click a group: Studio opens the script at the crash line. If the script
  no longer exists at that path (renamed, deleted, older version) the dock says
  so instead of guessing.

## What it never does

- Never generates or transmits your project key (only a SHA-256 fingerprint).
- Never uploads plaintext source — ciphertext only ([TRUST.md](TRUST.md) shows
  you how to confirm it on the wire).
- Never touches your game's runtime ingest key; uploads authenticate with your
  scoped access token only.
- Never requests Script Injection or any permission beyond HTTP access to the
  single backend domain you configured.

## Repository layout

```
default.project.json     rojo project → builds BloxToolsPlugin.rbxm
rokit.toml               pinned rojo toolchain (rokit/aftman-compatible)
src/
  Main.server.luau       Studio wiring (toolbar, docks, HTTP, editor jumps)
  Settings.luau          settings model: validation, masking, persistence
  Uploader.luau          enumerate → encrypt → chunked upload
  Inspector/
    Inspector.luau       error-list fetching + frame location logic
    PathResolver.luau    GetFullName() path → live Instance (dot-safe)
  Crypto/
    AesGcm.luau          AES-256-GCM, pure Luau, clean-room, commented
    Sha256.luau          SHA-256 (key fingerprint, IV derivation)
    Base64.luau          strict RFC 4648 base64
tools/
  aes-gcm-mirror.mjs     line-correspondent Node mirror of src/Crypto —
                         tested against WebCrypto + NIST vectors in CI
  luau-vectors.luau      runs the ACTUAL Luau crypto against the NIST vectors
                         under the open-source Luau CLI
  vectors.luau           generated Luau form of the NIST vectors
  gen-vectors-luau.mjs   generator for vectors.luau (sync-checked in CI)
test/                    the Node crypto proof suite (`npm test`)
PLUGIN_TESTPLAN.md       the in-Studio acceptance test plan
TRUST.md                 permission footprint + how to audit the
                         zero-knowledge claim + release verification
```

The crypto is vendored, not imported: Studio plugins have no crypto API and no
package manager we would ask you to trust. Read it — it's ~300 commented lines —
and read [TRUST.md](TRUST.md) for how the repository proves the Luau matches the
tested mirror.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup, how to run the crypto
proof suite (`npm test`), and the PR flow. The in-Studio acceptance checks live
in [PLUGIN_TESTPLAN.md](PLUGIN_TESTPLAN.md).

## Related

- [bloxtools-mcp](https://github.com/bloxtoolsio/bloxtools-mcp) — the MCP server
  that lets an AI agent read decrypted source around a crash, locally.
- [bloxtools.io](https://bloxtools.io) — dashboard, accounts, and tokens.

## License

MIT — see [LICENSE](LICENSE).
