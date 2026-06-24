--[[
	BloxTools Studio Plugin — Settings

	Pure-logic settings model (DI-style): validation,
	masking, and persistence policy live here; the actual `plugin:GetSetting` /
	`plugin:SetSetting` calls are injected so this module is reviewable and
	reasoned about without a live `plugin` object.

	WHAT IS STORED, AND WHERE (documented, accepted model):
	  Values persist via `plugin:SetSetting`, which Roblox Studio writes as
	  PLAINTEXT JSON on the OPERATOR'S OWN DISK (per-user plugin settings).
	  That is the accepted trust model for a customer-held-key design: the
	  key and PAT never leave the operator's machine except as, respectively,
	  a fingerprint and an Authorization header. They are NEVER sent to
	  BloxTools's servers, never logged, and never shown in full in the UI after
	  entry (PAT is masked to its last 4; the key is shown only as its
	  fingerprint).

	Setting keys (all strings):
	  BloxTools_BackendUrl  defaults to the hosted production backend
	                        (https://bloxtools-backend-production.up.railway.app);
	                        remains user-editable for self-hosted deployments)
	  BloxTools_Pat         "blxt_…" personal access token (read+upload scopes)
	  BloxTools_ProjectKey  44-char base64 project key (PASTED, never minted here
	                        — Luau has no CSPRNG; the dashboard generates it)
	  BloxTools_GameId      BloxTools game uuid (from the game picker)
	  BloxTools_GameName    display name cached for the UI

	An earlier rebrand renamed these from the legacy BugHub_* keys; a one-time
	migration shim in Main.server.luau copies any existing BugHub_* value to the
	new key on first load so saved installs don't lose their URL/token/key/game.

	opts for Settings.new:
	  crypto  { Sha256, Base64 } from src/Crypto
	  get     function(key) -> value?   (plugin:GetSetting)
	  set     function(key, value)      (plugin:SetSetting)
]]

local Settings = {}
Settings.__index = Settings

local DEFAULT_BACKEND_URL = "https://bloxtools-backend-production.up.railway.app"

local KEYS = {
	backendUrl = "BloxTools_BackendUrl",
	pat = "BloxTools_Pat",
	projectKey = "BloxTools_ProjectKey",
	gameId = "BloxTools_GameId",
	gameName = "BloxTools_GameName",
}

-- Legacy BugHub_* setting keys, in 1:1 order with KEYS above. The migration shim
-- (Main.server.luau) reads these once on load and copies any value into the new
-- BloxTools_* key, then clears the old one. Exported so the shim and any test can
-- reference the exact pairing without re-stating the strings.
local LEGACY_KEYS = {
	backendUrl = "BugHub_BackendUrl",
	pat = "BugHub_Pat",
	projectKey = "BugHub_ProjectKey",
	gameId = "BugHub_GameId",
	gameName = "BugHub_GameName",
}

function Settings.new(opts)
	return setmetatable({
		crypto = opts.crypto,
		get = opts.get,
		set = opts.set,
	}, Settings)
end

-- ── Validation (pure; exercised by the mirror-side reasoning + live gate) ────

--[[
	Validate a pasted project key. The dashboard mints 32 random bytes and
	shows them once as 44-char '='-padded base64; anything else is a paste
	error. Returns ok, keyBytesOrMessage. NEVER echoes the pasted value in
	the message (it might be a key with a stray character).
]]
function Settings.validateProjectKey(crypto, pasted)
	if type(pasted) ~= "string" then
		return false, "Paste the project key from your BloxTools dashboard."
	end
	local trimmed = pasted:gsub("^%s+", ""):gsub("%s+$", "")
	if #trimmed ~= 44 then
		return false, ("Project keys are exactly 44 characters of base64 (got %d)."):format(#trimmed)
	end
	local bytes = crypto.Base64.decode(trimmed)
	if bytes == nil or #bytes ~= 32 then
		return false, "That is not valid base64 for a 32-byte key. Re-copy it from the dashboard."
	end
	return true, { keyB64 = trimmed, keyBytes = bytes }
end

--[[
	keyFingerprint: first 8 hex of sha256(RAW key bytes) — pinned wire field.
	Shown in the settings UI so the user can compare it against the dashboard
	("does the plugin hold the same key the dash expects?") without either
	side ever displaying the key itself.
	(Mirrored as [MIRROR §4.1] keyFingerprint in tools/aes-gcm-mirror.mjs.)
]]
function Settings.fingerprintOf(crypto, keyBytes)
	return string.sub(crypto.Sha256.hex(keyBytes), 1, 8)
end

--[[
	Masked PAT for display: "blxt_…abcd" (last-4 idiom, matching the dash).
	The full token is never rendered after entry.
]]
function Settings.maskPat(pat)
	if type(pat) ~= "string" or #pat < 8 then
		return "(not set)"
	end
	return "blxt_…" .. string.sub(pat, -4)
end

function Settings.looksLikePat(pat)
	return type(pat) == "string" and string.sub(pat, 1, 5) == "blxt_" and #pat >= 12
end

-- Normalize a backend URL: trim, strip trailing slashes, require http(s).
function Settings.normalizeUrl(url)
	if type(url) ~= "string" then
		return nil
	end
	local trimmed = url:gsub("^%s+", ""):gsub("%s+$", ""):gsub("/+$", "")
	if trimmed == "" then
		return nil
	end
	if not (trimmed:match("^https?://")) then
		return nil
	end
	return trimmed
end

-- ── Persistence (thin wrappers over the injected get/set) ────────────────────

function Settings:backendUrl()
	return Settings.normalizeUrl(self.get(KEYS.backendUrl)) or DEFAULT_BACKEND_URL
end

function Settings:setBackendUrl(url)
	local normalized = Settings.normalizeUrl(url)
	if not normalized then
		return false, "Backend URL must start with http:// or https://"
	end
	self.set(KEYS.backendUrl, normalized)
	return true, normalized
end

function Settings:pat()
	local v = self.get(KEYS.pat)
	if Settings.looksLikePat(v) then
		return v
	end
	return nil
end

function Settings:setPat(pat)
	if not Settings.looksLikePat(pat) then
		return false, "Tokens start with blxt_ — mint one under Settings → API tokens in the dashboard."
	end
	self.set(KEYS.pat, pat)
	return true
end

-- Returns keyB64, keyBytes, fingerprint — or nil if no valid key is stored.
function Settings:projectKey()
	local stored = self.get(KEYS.projectKey)
	local ok, result = Settings.validateProjectKey(self.crypto, stored)
	if not ok then
		return nil
	end
	return result.keyB64, result.keyBytes, Settings.fingerprintOf(self.crypto, result.keyBytes)
end

function Settings:setProjectKey(pasted)
	local ok, result = Settings.validateProjectKey(self.crypto, pasted)
	if not ok then
		return false, result -- result is the user-facing message
	end
	self.set(KEYS.projectKey, result.keyB64)
	return true, Settings.fingerprintOf(self.crypto, result.keyBytes)
end

function Settings:game()
	local id = self.get(KEYS.gameId)
	if type(id) ~= "string" or id == "" then
		return nil
	end
	return id, self.get(KEYS.gameName)
end

function Settings:setGame(id, name)
	self.set(KEYS.gameId, id)
	self.set(KEYS.gameName, name)
end

-- ── One-time BugHub_* → BloxTools_* setting-key migration (legacy rebrand) ────

--[[
	migrateLegacyKeys: for each setting, if the NEW BloxTools_* key is empty but
	the legacy BugHub_* key holds a value, copy the value into the new key and
	clear the old one. Pure over the injected get/set, so it is exercised the same
	way as every other persistence path. Idempotent: a second run sees the new
	keys already populated (or the legacy keys already cleared) and does nothing.
	Never clobbers a value the operator has already saved under the new key.

	Returns the number of keys migrated (for a one-line status / test assertion).
	Values are never logged here (a PAT/key could be among them).
]]
function Settings:migrateLegacyKeys()
	local migrated = 0
	for field, newKey in KEYS do
		local legacyKey = LEGACY_KEYS[field]
		if legacyKey then
			local newVal = self.get(newKey)
			local oldVal = self.get(legacyKey)
			local newEmpty = (newVal == nil or newVal == "")
			local oldHasValue = (oldVal ~= nil and oldVal ~= "")
			if newEmpty and oldHasValue then
				self.set(newKey, oldVal)
				migrated += 1
			end
			-- Always retire the legacy key once we've had a chance to migrate it,
			-- so a stale BugHub_* value can never resurface or linger on disk.
			if oldVal ~= nil then
				self.set(legacyKey, nil)
			end
		end
	end
	return migrated
end

-- Exposed so Main.server.luau's shim and any review/test can reference the exact
-- key strings without re-stating them.
Settings.KEYS = KEYS
Settings.LEGACY_KEYS = LEGACY_KEYS

return Settings
