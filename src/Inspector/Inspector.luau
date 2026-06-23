--[[
	BloxTools Studio Plugin — Inspector (logic)

	The error-inspector dock's brain, DI-style: fetching and parsing live
	error groups for the configured game, picking the frame to jump to, and
	resolving it to a live script. All I/O (HTTP, the DataModel root, the
	script editor) is injected, so this module is pure logic reviewable
	without Studio; Main.server.luau owns the actual widgets and services.

	API surface consumed (read-scope PAT — GETs only; a read PAT can never
	mutate anything, enforced server-side by patGuard):
	  GET /api/games/:gameId/errors?status=open&sort=recent
	      → { errors: [ { id, message, count, status, topPath, topFn,
	                      lastSeen, placeVersion, surface, … } ] }
	  GET /api/games/:gameId/errors/:id/events?limit=1
	      → { events: [ { frames: [{path,line,fn,kind}], placeVersion, … } ] }

	The group row carries the top frame's PATH but no line number; line
	numbers live on sampled events. So a click does one extra GET for the
	group's newest event and uses its first resolvable frame.

	opts for Inspector.new:
	  resolver  PathResolver (src/Inspector/PathResolver.luau)
	  request   function(requestOptions) -> { Success, StatusCode, Body }
	  jsonDecode function(string) -> table
	  patToken  "blxt_…" (read scope; only ever placed in the Authorization
	            header — never logged)
	  baseUrl   normalized backend base URL
	  gameId    configured game uuid
	  root      instance whose children are top-level path segments (`game`
	            in production; any instance in review)
	  warn      function(message)
]]

local Inspector = {}
Inspector.__index = Inspector

function Inspector.new(opts)
	return setmetatable({
		resolver = opts.resolver,
		request = opts.request,
		jsonDecode = opts.jsonDecode,
		patToken = opts.patToken,
		baseUrl = opts.baseUrl,
		gameId = opts.gameId,
		root = opts.root,
		warn = opts.warn or function() end,
	}, Inspector)
end

-- The Pro+ upgrade copy — shown whenever the backend gates a PAT route behind a
-- plan (ALL PAT use is a Pro+ feature, so a Free account 403s every route except
-- token-info). Pinned to the dashboard's upgrade story, not a raw HTTP error.
Inspector.PRO_GATE_MESSAGE = "Studio plugin is a Pro+ feature — upgrade in the dashboard."

--[[
	Detect the backend's `plan_required` 403 in a decoded response body. The
	backend's central error handler renders an error as:
	  { error = { code = "plan_required", message = …, details = {feature,…} } }
	We key ONLY on the machine-readable code, never on the human message.
]]
function Inspector.isPlanRequired(decodedBody)
	return type(decodedBody) == "table"
		and type(decodedBody.error) == "table"
		and decodedBody.error.code == "plan_required"
end

-- One authorized GET. Returns decodedTable | nil, errorMessage, planGated?
--   planGated == true → the failure is a Pro+ plan gate (plan_required 403);
--   callers render PRO_GATE_MESSAGE instead of a raw error.
function Inspector:getJson(path)
	local ok, res = pcall(self.request, {
		Url = self.baseUrl .. path,
		Method = "GET",
		Headers = {
			-- The PAT travels ONLY here; never logged, never persisted by
			-- this module.
			["Authorization"] = "Bearer " .. self.patToken,
		},
	})
	if not ok then
		return nil, "request failed — is the backend reachable and HTTP access approved?"
	end
	if not res or not res.Success then
		local status = res and tostring(res.StatusCode) or "?"
		-- A 403 may be the Pro+ plan gate. Decode the body and check the
		-- machine-readable code before falling back to the generic scope hint.
		if status == "403" then
			local okDecode, decoded = pcall(self.jsonDecode, res and res.Body)
			if okDecode and Inspector.isPlanRequired(decoded) then
				return nil, Inspector.PRO_GATE_MESSAGE, true
			end
		end
		if status == "401" or status == "403" then
			return nil, "rejected (HTTP " .. status .. ") — check the token and its read scope"
		end
		return nil, "backend error (HTTP " .. status .. ")"
	end
	local okDecode, decoded = pcall(self.jsonDecode, res.Body)
	if not okDecode or type(decoded) ~= "table" then
		return nil, "unexpected response from the backend"
	end
	return decoded
end

--[[
	Fetch the current PAT's plan via GET /api/account/token-info (this route is
	EXEMPT from the PAT-on-free 403, so it still answers for a Free
	account → we can render the precise "you're on Free — upgrade" banner instead
	of an opaque error). Returns plan ("free"|"pro"|"studio") | nil, errorMessage.
	token-info shape: { kind, name, scopes, tokenLast4, plan, features }.
]]
function Inspector:fetchPlan()
	local decoded, err = self:getJson("/api/account/token-info")
	if not decoded then
		return nil, err
	end
	if type(decoded.plan) ~= "string" then
		return nil, "backend did not report a plan"
	end
	return decoded.plan
end

--[[
	Fetch open error groups, newest activity first. Returns an array of
	display-ready rows (or nil, message):
	  { id, message, count, topPath, topFn, lastSeen, surface }
]]
function Inspector:fetchGroups()
	local decoded, err, planGated = self:getJson(("/api/games/%s/errors?status=open&sort=recent"):format(self.gameId))
	if not decoded then
		return nil, err, planGated
	end
	local groups = {}
	for _, g in (decoded.errors or {}) do
		groups[#groups + 1] = {
			id = g.id,
			message = tostring(g.message or "?"),
			count = tonumber(g.count) or 0,
			topPath = g.topPath, -- may be nil (no parsable frames)
			topFn = g.topFn,
			lastSeen = g.lastSeen,
			surface = g.surface,
		}
	end
	return groups
end

--[[
	For a clicked group: fetch its newest sampled event and pick the frame to
	jump to — the first frame whose path resolves to a live script under
	`root`. Falls back to the group's topPath at line 1 when the group has no
	sampled events (counted-only groups exist by design — sampling caps).

	Returns one of:
	  { kind = "hit",      instance = Instance, line = n, path = s }
	  { kind = "notfound", path = s, reason = "deleted"|"noframes" }
]]
function Inspector:locate(group)
	local frames = {}
	local decoded = self:getJson(("/api/games/%s/errors/%s/events?limit=1"):format(self.gameId, group.id))
	if decoded and type(decoded.events) == "table" and decoded.events[1] then
		frames = decoded.events[1].frames or {}
	end
	-- Try event frames innermost-first; each may be from an older place
	-- version (renamed/deleted scripts) — resolver returns nil, we move on.
	for _, frame in frames do
		if type(frame) == "table" and type(frame.path) == "string" then
			local inst = self.resolver.resolve(self.root, frame.path)
			if inst then
				return {
					kind = "hit",
					instance = inst,
					line = math.max(1, tonumber(frame.line) or 1),
					path = frame.path,
				}
			end
		end
	end
	-- No event frames resolved; try the group's aggregate top path, line 1.
	if type(group.topPath) == "string" and group.topPath ~= "" then
		local inst = self.resolver.resolve(self.root, group.topPath)
		if inst then
			return { kind = "hit", instance = inst, line = 1, path = group.topPath }
		end
		return { kind = "notfound", path = group.topPath, reason = "deleted" }
	end
	return { kind = "notfound", path = "?", reason = "noframes" }
end

-- Game picker support: list the account's games via the read PAT.
-- Returns array of { id, name } or nil, message.
function Inspector:fetchGames()
	local decoded, err, planGated = self:getJson("/api/games")
	if not decoded then
		return nil, err, planGated
	end
	local games = {}
	for _, g in (decoded.games or {}) do
		games[#games + 1] = { id = g.id, name = tostring(g.name or g.id) }
	end
	return games
end

return Inspector
