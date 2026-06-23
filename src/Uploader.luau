--[[
	BloxTools Studio Plugin — Uploader

	Enumerates every Script / LocalScript / ModuleScript under the configured
	containers, AES-256-GCM-encrypts each Source with the customer-held project
	key, and POSTs the ciphertext to the backend in capped chunks using an
	`upload`-scope personal access token.

	ZERO-KNOWLEDGE INVARIANTS (do not weaken):
	  - The project key NEVER leaves this process: it is not logged, not sent
	    in any request, and appears in no error message. Only its FINGERPRINT
	    (first 8 hex of sha256(raw key)) goes on the wire.
	  - Plaintext source is never logged and never sent — only ciphertext.
	  - The PAT appears only in the Authorization header, never in logs.
	  - This module never touches the game's INGEST key (that key belongs to
	    the runtime SDK, not the plugin); upload auth is the PAT, full stop.

	DI-style (all I/O is injected), so everything but
	the actual HTTP calls is exercisable as pure logic. Crypto modules are
	injected too (they are Roblox-global-free; see src/Crypto/).

	opts for Uploader.new:
	  crypto      { AesGcm, Sha256, Base64 }  (the modules in src/Crypto)
	  keyB64      44-char base64 project key (validated here: must decode to
	              exactly 32 bytes; the plugin NEVER mints keys — no CSPRNG)
	  patToken    "blxt_…" upload-scope PAT
	  baseUrl     e.g. "http://localhost:3000" (trailing "/" stripped)
	  gameId      BloxTools game id (uuid from the settings game picker)
	  request     function(requestOptions) -> { Success, StatusCode, Body }
	  jsonEncode  function(table) -> string
	  jsonDecode  function(string) -> table  (for the {accepted, skipped} reply)
	  guid        function() -> string   (HttpService:GenerateGUID(false))
	  clock       function() -> number   (os.clock)
	  getSource   function(instance) -> string  (function(s) return s.Source end;
	              injected so enumeration logic needs no live Instances in review)
	  wait        function(seconds)      (task.wait; no-op in reasoning/tests)
	  warn        function(message)
]]

local Uploader = {}
Uploader.__index = Uploader

-- Pinned caps (matched by the backend, which enforces the same numbers with
-- 413/400 + `skipped`). The plugin pre-chunks so a normal publish never
-- trips them server-side.
local MAX_ARTIFACTS_PER_REQUEST = 2000
local MAX_CIPHERTEXT_BYTES = 256 * 1024 -- raw ciphertext+tag bytes, per artifact
local MAX_REQUEST_BYTES = 18 * 1024 * 1024 -- ≤20 MiB pinned; headroom for JSON framing

local SCRIPT_CLASSES = { Script = true, LocalScript = true, ModuleScript = true }

-- SDK subtrees are skipped: the BloxTools SDK is published BloxTools code, not
-- customer source. The plugin's own scripts live in the plugin tree, NOT under
-- `game`, so enumeration never sees them in the first place.
-- These must match the SDK's install paths EXACTLY: the SDK tree installs at
-- these instance paths, so its own scripts are skipped (not uploaded as customer
-- source).
local SKIP_PREFIXES = {
	"ServerScriptService.BloxTools",
	"ReplicatedStorage.BloxTools",
}

local function bytesOf(s)
	local out = table.create(#s)
	for i = 1, #s do
		out[i] = string.byte(s, i)
	end
	return out
end

function Uploader.isSkippedPath(path)
	for _, prefix in SKIP_PREFIXES do
		if path == prefix or string.sub(path, 1, #prefix + 1) == prefix .. "." then
			return true
		end
	end
	return false
end

--[[
	Detect the backend's `plan_required` 403 in a failed upload response. The
	backend renders an error as { error = { code = "plan_required", … } }.
	ALL PAT use is a Pro+ feature, so a Free account's POST /source 403s with
	this code — distinct from a wrong-scope/wrong-game 403 — and the UI shows the
	"Pro+ feature — upgrade" prompt rather than a raw upload error. Keys only on
	the machine-readable code; decode failures return false (treat as a real error).
]]
function Uploader.responseIsPlanRequired(res, jsonDecode)
	if type(res) ~= "table" or tonumber(res.StatusCode) ~= 403 then
		return false
	end
	if type(res.Body) ~= "string" or not jsonDecode then
		return false
	end
	local ok, decoded = pcall(jsonDecode, res.Body)
	return ok
		and type(decoded) == "table"
		and type(decoded.error) == "table"
		and decoded.error.code == "plan_required"
end

function Uploader.new(opts)
	local keyBytes = opts.crypto.Base64.decode(opts.keyB64 or "")
	if keyBytes == nil or #keyBytes ~= 32 then
		-- Deliberately does not echo the pasted value (it might be a key).
		error("Uploader: project key must be 44-char base64 of exactly 32 bytes")
	end
	return setmetatable({
		crypto = opts.crypto,
		keyB64 = opts.keyB64,
		keyBytes = keyBytes,
		-- keyFingerprint: first 8 hex of sha256(raw key bytes) — pinned wire
		-- field; lets the dashboard detect "wrong key" without seeing the key.
		-- (Mirrored as [MIRROR §4.1] keyFingerprint in tools/aes-gcm-mirror.mjs.)
		keyFingerprint = string.sub(opts.crypto.Sha256.hex(keyBytes), 1, 8),
		patToken = opts.patToken,
		baseUrl = tostring(opts.baseUrl or ""):gsub("/+$", ""),
		gameId = opts.gameId,
		request = opts.request,
		jsonEncode = opts.jsonEncode,
		jsonDecode = opts.jsonDecode,
		guid = opts.guid,
		clock = opts.clock,
		getSource = opts.getSource or function(inst)
			return inst.Source
		end,
		wait = opts.wait or function() end,
		warn = opts.warn or function() end,
	}, Uploader)
end

--[[
	IV DERIVATION (pinned recipe — matched by the dashboard/MCP decrypt side;
	mirrored as [MIRROR §4.2] ivFromSeed in tools/aes-gcm-mirror.mjs):

	    iv = first 12 bytes of sha256(
	        projectKeyB64 .. instancePath .. placeVersion .. os.clock() .. GUID
	    )

	WHY THIS IS SOUND — uniqueness, not secrecy: GCM is catastrophically
	broken by IV *reuse* under the same key (it leaks the XOR of plaintexts
	and enables tag forgery), but the IV itself needs only to be UNIQUE per
	(key, message). It does not need to be secret or unpredictable — it is
	transmitted in the clear right next to the ciphertext by design.

	Luau has no CSPRNG, so instead of pretending to have random bytes we hash
	together everything that distinguishes this one encryption from every
	other one ever performed with this key:
	  - instancePath   differs across scripts in one upload
	  - placeVersion   differs across publishes
	  - os.clock()     high-resolution time, differs within a session
	  - GenerateGUID   128 bits of Roblox-engine randomness — the load-bearing
	                   uniqueness term. NEVER derive an IV without it.
	  - projectKeyB64  domain-separates projects sharing a backend
	A collision needs a GUID collision AND an identical clock reading on the
	same path+version — negligible against GCM's 2^-32 multi-IV bound.
]]
function Uploader:deriveIv(instancePath, placeVersion)
	local seed = self.keyB64
		.. instancePath
		.. tostring(placeVersion)
		.. tostring(self.clock())
		.. self.guid()
	local digest = self.crypto.Sha256.digest(bytesOf(seed))
	local iv = table.create(12)
	for i = 1, 12 do
		iv[i] = digest[i]
	end
	return iv
end

--[[
	Enumerate candidate scripts under the given container instances.
	Returns an array of { path = GetFullName(), source = string }.
	Sources are read here once; unreadable Sources (pcall fails) are skipped
	with a warning that names the PATH ONLY (never the content).
]]
function Uploader:enumerate(containers)
	local found = {}
	for _, container in containers do
		for _, inst in container:GetDescendants() do
			if SCRIPT_CLASSES[inst.ClassName] then
				local path = inst:GetFullName()
				if not Uploader.isSkippedPath(path) then
					local ok, source = pcall(self.getSource, inst)
					if ok and type(source) == "string" then
						found[#found + 1] = { path = path, source = source }
					else
						self.warn(("[BloxTools] could not read Source of %s — skipped"):format(path))
					end
				end
			end
		end
	end
	return found
end

--[[
	Encrypt one enumerated script into a wire artifact (pinned shape):
	  { instancePath, iv (base64, 16 chars), ciphertext (base64 of ct||tag),
	    plainBytes }
	Returns nil, reason when the artifact exceeds the per-artifact cap (the
	server would mark it `skipped` anyway; skipping locally saves the bytes).
]]
function Uploader:buildArtifact(entry, placeVersion)
	local plainBytes = #entry.source
	if plainBytes + 16 > MAX_CIPHERTEXT_BYTES then
		return nil, "over 256 KiB"
	end
	local iv = self:deriveIv(entry.path, placeVersion)
	-- ct||tag — WebCrypto-native layout (subtle.decrypt consumes it as-is).
	local ct = self.crypto.AesGcm.encrypt(self.keyBytes, iv, bytesOf(entry.source))
	return {
		instancePath = entry.path,
		iv = self.crypto.Base64.encode(iv),
		ciphertext = self.crypto.Base64.encode(ct),
		plainBytes = plainBytes,
	}
end

--[[
	Pure chunking per the pinned caps: ≤2000 artifacts per request and ≤20 MiB
	per request body (we budget 18 MiB of artifact payload to leave framing
	headroom). Returns an array of artifact arrays.
]]
function Uploader.chunkArtifacts(artifacts)
	local chunks = {}
	local chunk = {}
	local chunkBytes = 0
	for _, a in artifacts do
		-- Rough wire cost of one artifact: its strings plus JSON framing.
		local cost = #a.ciphertext + #a.iv + #a.instancePath + 80
		if #chunk > 0 and (#chunk >= MAX_ARTIFACTS_PER_REQUEST or chunkBytes + cost > MAX_REQUEST_BYTES) then
			chunks[#chunks + 1] = chunk
			chunk = {}
			chunkBytes = 0
		end
		chunk[#chunk + 1] = a
		chunkBytes += cost
	end
	if #chunk > 0 then
		chunks[#chunks + 1] = chunk
	end
	return chunks
end

-- POST one chunk with retry (3 attempts, 1s/2s backoff). Transport-style
-- policy: transport errors / 429 / 5xx retry; other 4xx fail immediately
-- (a token or payload problem will not fix itself). Returns ok, info.
function Uploader:postChunk(artifacts, placeVersion, maxAttempts)
	maxAttempts = maxAttempts or 3
	local url = ("%s/api/games/%s/source"):format(self.baseUrl, self.gameId)
	local body = self.jsonEncode({
		placeVersion = placeVersion,
		keyFingerprint = self.keyFingerprint,
		artifacts = artifacts,
	})
	local lastDetail = "?"
	for attempt = 1, maxAttempts do
		local ok, res = pcall(self.request, {
			Url = url,
			Method = "POST",
			Headers = {
				["Content-Type"] = "application/json",
				-- The PAT travels ONLY here. Never logged, never persisted by
				-- this module.
				["Authorization"] = "Bearer " .. self.patToken,
			},
			Body = body,
		})
		if ok and res and res.Success then
			return true, res
		end
		if not ok then
			lastDetail = "request error: " .. tostring(res)
		elseif res then
			lastDetail = ("HTTP %s"):format(tostring(res.StatusCode))
			local status = tonumber(res.StatusCode)
			if status and status ~= 429 and status < 500 then
				-- Body deliberately not echoed beyond a short prefix: it is
				-- backend JSON, but keep log surface minimal on principle.
				self.warn(("[BloxTools] upload rejected (%s) — check the token's `upload` scope, the game id, and the backend URL"):format(lastDetail))
				return false, res
			end
		end
		if attempt < maxAttempts then
			self.wait(2 ^ (attempt - 1)) -- 1s, 2s
		end
	end
	self.warn(("[BloxTools] upload chunk failed after %d attempt(s) (%s)"):format(maxAttempts, lastDetail))
	return false
end

--[[
	The full flow: enumerate → encrypt → chunk → POST.
	onProgress(state) is called with:
	  { phase = "enumerate"|"encrypt"|"upload"|"done",
	    done = n, total = n, detail = string? }
	Returns a summary table:
	  { scripts, encrypted, skippedLocal, chunks, chunksFailed,
	    accepted, skippedServer, ok }
]]
function Uploader:run(containers, placeVersion, onProgress)
	onProgress = onProgress or function() end

	onProgress({ phase = "enumerate", done = 0, total = 0 })
	local entries = self:enumerate(containers)

	local artifacts = {}
	local skippedLocal = 0
	for i, entry in entries do
		local artifact, reason = self:buildArtifact(entry, placeVersion)
		if artifact then
			artifacts[#artifacts + 1] = artifact
		else
			skippedLocal += 1
			self.warn(("[BloxTools] %s skipped (%s)"):format(entry.path, reason))
		end
		onProgress({ phase = "encrypt", done = i, total = #entries })
	end

	local chunks = Uploader.chunkArtifacts(artifacts)
	local accepted = 0
	local skippedServer = 0
	local chunksFailed = 0
	local planGated = false
	for i, chunk in chunks do
		onProgress({ phase = "upload", done = i - 1, total = #chunks })
		local ok, res = self:postChunk(chunk, placeVersion)
		if not ok and Uploader.responseIsPlanRequired(res, self.jsonDecode) then
			-- Free account → Pro+ gate. The PAT itself is refused for this
			-- account; no point retrying the remaining chunks. Surface it so
			-- the caller can show the upgrade prompt instead of a raw failure.
			planGated = true
		end
		if ok then
			-- Response shape (pinned): { ok, accepted, skipped }.
			local parsed = nil
			if res and type(res.Body) == "string" and self.jsonDecode then
				local okDecode, decoded = pcall(self.jsonDecode, res.Body)
				if okDecode and type(decoded) == "table" then
					parsed = decoded
				end
			end
			accepted += (parsed and tonumber(parsed.accepted)) or #chunk
			skippedServer += (parsed and tonumber(parsed.skipped)) or 0
		else
			chunksFailed += 1
		end
		onProgress({ phase = "upload", done = i, total = #chunks })
	end

	local summary = {
		scripts = #entries,
		encrypted = #artifacts,
		skippedLocal = skippedLocal,
		chunks = #chunks,
		chunksFailed = chunksFailed,
		accepted = accepted,
		skippedServer = skippedServer,
		planGated = planGated,
		ok = chunksFailed == 0,
	}
	onProgress({ phase = "done", done = #chunks, total = #chunks })
	return summary
end

return Uploader
