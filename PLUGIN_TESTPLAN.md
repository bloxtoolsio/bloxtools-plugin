# BloxTools Studio Plugin — live test plan

Execute verbatim in Roblox Studio. There is no Roblox runtime in CI, so this
plan is the plugin's acceptance test: the crypto already has executable proof
(`npm test` → `test/plugin-crypto-roundtrip.test.js`, mirror vs WebCrypto on
NIST vectors, plus `test/plugin-crypto-luau.test.js`, which executes the
ACTUAL Luau cipher against those vectors under the Luau CLI when available),
and THIS plan verifies the Studio wiring and the remaining Luau modules live. Every numbered check lists exact pass criteria across up to three
checkpoints: Studio, backend/DB, dashboard.

Total time: ~25 minutes.

## 0. Prerequisites

1. A reachable BloxTools backend. Either the hosted backend (point the plugin's
   Backend URL at it) or a self-hosted instance with the source-context feature
   enabled. The default URL in the plugin is `http://localhost:3000` for a local
   install; production deployments use their own URL.
2. A BloxTools game with the SDK installed in a **published** test place
   (`game.PlaceVersion ≥ 1`; an unpublished place uploads as v0 — works, but
   P6 needs real versions).
3. A PAT minted with **both** `read` and `upload` scopes (dashboard →
   Settings → API tokens). Note its last 4 characters. NOTE: minting a
   PAT requires a **Pro+** account — a Free account cannot mint one (the gate
   tests below cover the Free path). The token begins `blxt_…`.
4. A project key generated in the dashboard (shown once) — copy both the key
   and the fingerprint the dashboard displays.
5. The plugin built and installed locally:
   `rojo build default.project.json -o BloxToolsPlugin.rbxm`, copy into
   your Studio plugins folder, restart Studio. PASS: a **BloxTools** toolbar with
   **Errors** and **Settings** buttons appears, and the dock/widget titles read
   **"BloxTools — Errors"** / **"BloxTools — Settings"** (no "BugHub" anywhere).
6. For the ciphertext spot-check (P2), read access to wherever your backend
   stores artifacts (e.g. a SQL console). Optional if you instead sniff the
   upload traffic with a proxy, as described in TRUST.md.

## Setup walk (exercises the Settings widget; do once)

Open **BloxTools → Settings**:

- Backend URL `http://localhost:3000` → Save. PASS: "Saved."
- Paste a malformed token (e.g. `abc`) → Save. PASS: error names the `blxt_`
  format; nothing stored.
- Paste the real PAT → Save. PASS: box clears; "Stored: blxt_…XXXX" shows the
  correct last 4. The full token is visible nowhere.
- Paste a truncated project key (delete one char) → Save. PASS: length error,
  nothing stored. Paste the real key → Save. PASS: box clears; the displayed
  fingerprint EQUALS the fingerprint the dashboard showed (8 hex chars).
- Press *Load my games* → click your test game. PASS: "Selected: <name>".
- First HTTP call: Studio prompts to allow this plugin to call
  `localhost:3000` — and that is the ONLY domain ever prompted for. PASS.

## P1 — publish upload

1. File → Publish to Roblox. Note the new place version (`game.PlaceVersion`
   in the command bar).
2. Open **BloxTools → Errors**, press **Upload source now**.

PASS: progress runs enumerate → encrypt N/N → upload chunk 1/1; final line
reads `Done (place vV): S scripts, S encrypted, S accepted, 0 skipped…` where
V is the version from step 1 and S ≈ the place's script count; backend log
shows `POST /api/games/<id>/source → 202`. The BloxTools SDK's own scripts
(`ServerScriptService.BloxTools`, `ReplicatedStorage.BloxTools`) are NOT counted
(check S against a manual count). Nothing in Studio Output contains source
text, the key, or the token.

## P2 — ciphertext-only spot-check (the zero-knowledge check)

Run (against your backend's artifact store):

```sql
SELECT instance_path, place_version, length(ciphertext) AS ct_len, iv,
       key_fingerprint, left(ciphertext, 60) AS ct_head
FROM source_artifacts WHERE game_id = '<game uuid>'
ORDER BY instance_path LIMIT 20;
```

PASS: one row per script; `iv` is 16 base64 chars; `key_fingerprint` matches
the dashboard's; `ct_head` is base64 noise. Decode one to be sure:
`SELECT convert_from(decode(ciphertext,'base64')::bytea,'LATIN1') …` must be
unreadable garbage — no `local`, no `function`, no recognizable identifiers
anywhere in any row. Also: `SELECT * FROM source_artifacts WHERE ciphertext
LIKE '%local %'` returns 0 rows.

## P3 — decrypt round-trip via the dashboard

1. In Play (Server view) command bar, throw an error from a known script
   line, e.g. add `error("boom")` at a known line in a test script, publish,
   upload (P1 again), then trigger it.
2. Open the error group in the dashboard, expand the crashing frame, enter
   the project key.

PASS: the dashboard renders the REAL source lines around the crash, matching
the script in Studio character-for-character (this proves Luau-encrypt →
WebCrypto-decrypt across implementations — the cross-language seam).

## P4 — wrong key

In the dashboard, enter a wrong-but-valid-shaped key (generate a second key).

PASS: clean "different key than the one this upload used" state driven by the
fingerprint mismatch — no decrypt attempt, no junk render, no console errors.
In the PLUGIN: paste that second key in Settings → its fingerprint differs
from the dashboard's original; re-paste the correct key and the fingerprints
match again.

## P5 — jump-to-line

1. With the error from P3 listed in the **Errors** dock (press Refresh),
   click the group.

PASS: Studio opens the correct script in the editor with the cursor on the
crash line (status: `Opened <path> at line N.`).

2. Not-found state: rename the crashing script, press Refresh, click the
   group again. PASS: status reads "Not found in this place … (renamed/
   deleted, or from another version)" — no error, no wrong script opened.
   Rename it back.

3. Dot-ambiguity (PathResolver): create a Folder literally named `A.B` in
   ServerScriptService containing a Script `S`; in the command bar verify
   `require`-free resolution by triggering an error from it and clicking the
   group. PASS: the right script opens despite the dot in the folder name.

## P6 — re-publish / nearestVersion

1. Note the current artifact rows' `place_version` (= V).
2. Edit one script (add a comment), File → Publish (→ V+1), **Upload source
   now**.

PASS: `SELECT DISTINCT place_version FROM source_artifacts WHERE game_id=…`
shows V and V+1; row count per version equal; the edited script's V+1
ciphertext differs from its V ciphertext. In the dashboard, open an OLD error
event (recorded at V) — PASS: it decrypts via the `nearestVersion` fallback
and labels the source as from the older version. Upload again at V+1 without
changes — PASS: re-upload replaces rows (same count, no duplicates;
`accepted` = S, upsert on (game, version, path)).

## P7 — settings persistence + masked PAT

1. Close Studio entirely; reopen the place.

PASS: Settings still shows the backend URL, `Stored: blxt_…XXXX` (correct
last 4, full token nowhere), the key fingerprint, and the selected game —
without re-entering anything. The Errors dock still refreshes and Upload
still works (stored values are live, not just displayed).

2. Open the plugin settings file on disk (Studio's per-user plugin settings
   JSON) and confirm what's documented: the key and PAT ARE there in
   plaintext — machine-local, accepted model per TRUST.md — and nowhere
   else on the system.

## Sweep (after P1–P7)

- Studio Output for the whole session contains zero occurrences of: the
  project key, any `blxt_` token, or any script source text.
- The 30 s auto-refresh ran only while the Errors dock was open (close it,
  watch the backend log go quiet).
- Studio prompted for exactly ONE HTTP domain over the entire session and
  never for Script Injection.

## P8 — Pro+ gating (needs a FREE test account)

The plugin is a **Pro+** feature: every call uses a PAT, and the backend 403s
every PAT route for a Free account (`plan_required`) except `token-info`, which
still answers with `plan:'free'` so the plugin can render a precise upgrade note.

Set a throwaway test account to `free` via SQL and mint/keep a `blxt_…` PAT for
it (or reuse a Pro PAT then downgrade that account to `free` — the PAT keeps
validating but every route now 403s `plan_required`). Configure the plugin with
that token + a game.

1. **Proactive banner.** Restart Studio (or re-save the token). PASS: the
   Settings widget shows a persistent banner directly under the *Access token*
   label reading **"Studio plugin is a Pro+ feature — upgrade in the
   dashboard."** (no button pressed yet). The Inspector dock status shows the
   same line and the upload button reads **"Upload (Pro+)"** (greyed, not the
   blue "Upload source now").
2. **Reactive — load games.** Settings → *Load my games*. PASS: status reads the
   Pro+ upgrade line (NOT a raw "HTTP 403"); no game list renders.
3. **Reactive — refresh errors.** Open **Errors**, press **Refresh**. PASS: the
   dock status reads the Pro+ upgrade line, not "Refresh failed: HTTP 403".
4. **Reactive — upload.** Press the upload button. PASS: status reads the Pro+
   upgrade line, not "Upload failed".
5. **Upgrade clears it.** Set the account back to `pro` via SQL, re-save the
   token (or restart Studio). PASS: the banner disappears, the upload button
   returns to blue "Upload source now", and *Load my games* / *Refresh* /
   *Upload* all work normally (per P1–P7).

> Backstop: the machine-readable signal is `body.error.code == "plan_required"`
> (rendered by the backend's central error handler as
> `{ error: { code, message, details:{feature,requiredPlan,plan} } }`). The plugin
> keys ONLY on that code — never on the human message — and reads the proactive
> plan from `token-info`'s `plan` field.

## P9 — BugHub_* → BloxTools_* setting-key migration (legacy rebrand)

This verifies an existing install that saved settings under the legacy
`BugHub_*` keys is silently migrated on first load of the rebranded plugin.

1. Simulate a legacy install: in the Studio command bar, with the (old or new)
   plugin's settings object, seed legacy keys, e.g.
   `plugin:SetSetting("BugHub_BackendUrl", "http://localhost:3000")`,
   `plugin:SetSetting("BugHub_Pat", "blxt_<yourtoken>")`,
   `plugin:SetSetting("BugHub_ProjectKey", "<44-char-key>")`,
   `plugin:SetSetting("BugHub_GameId", "<gameuuid>")`,
   `plugin:SetSetting("BugHub_GameName", "<name>")` — and clear the matching
   `BloxTools_*` keys (`SetSetting(key, nil)`).
2. Reload the plugin (reinstall the rebuilt `.rbxm` / restart Studio).

PASS: Output shows `[BloxTools] migrated N setting(s) from the legacy BugHub_*
keys to BloxTools_*.`; the Settings widget shows the backend URL, the masked
`blxt_…XXXX` PAT, the key fingerprint, and the selected game **without
re-entering anything**. Verify the migration cleared the old keys and never
clobbered a new value:
   - `print(plugin:GetSetting("BugHub_Pat"))` → `nil` (legacy key retired).
   - `print(plugin:GetSetting("BloxTools_Pat"))` → the `blxt_…` token (migrated).
3. **Idempotent / no-clobber.** Reload again. PASS: no second "migrated" line
   (count 0); values unchanged. Then set BOTH a legacy and a NEW value for one
   key (e.g. `BugHub_GameName="old"`, `BloxTools_GameName="new"`) and reload —
   PASS: `BloxTools_GameName` stays `"new"` (the migration never overwrites a
   value already saved under the new key) and `BugHub_GameName` is cleared.

## P10 — built-artifact load check

1. Build the artifact: `rojo build default.project.json -o
   BloxToolsPlugin.rbxm`. PASS: the command succeeds and writes
   `BloxToolsPlugin.rbxm`.
2. Install `BloxToolsPlugin.rbxm` into the Studio plugins folder, restart Studio.

PASS: the plugin loads with no script errors in Output; the toolbar is
**BloxTools** with **Errors** + **Settings**; widget titles read "BloxTools — …".
Run the *Setup walk* + P1 once against the built artifact to confirm the
build is functionally identical to a source build (token validates as
`blxt_…`, upload skips only `ServerScriptService.BloxTools` /
`ReplicatedStorage.BloxTools`, and — for a Pro account — errors load and upload
succeeds).
