--[[
	BloxTools Studio Plugin — Main (Studio wiring)

	The ONLY file that touches Roblox plugin APIs. Everything with logic in
	it lives in sibling modules (Settings, Uploader, Inspector, Crypto/) and
	receives its I/O from here by injection, so those modules are reviewable
	— and, for the crypto, executably testable via the Node mirror — without
	a Studio runtime. This file is verified live per PLUGIN_TESTPLAN.md.

	Every Roblox plugin API call below that CANNOT be exercised outside
	Studio is marked [STUDIO-VERIFY] with the assumption being made; the
	in-Studio test plan (PLUGIN_TESTPLAN.md) walks them.

	MANUAL UPLOAD TRIGGER (pinned decision): there is NO reliable
	publish-completed event in the plugin API surface — nothing documented
	fires when File → Publish succeeds, and approximating one by polling
	game.PlaceVersion on Heartbeat would be exactly the kind of fakery this
	project refuses. So source upload is an explicit dock button:
	"Upload source now", pressed by the operator right after publishing.
	The dock shows the place version being uploaded so a stale pre-publish
	upload is visible immediately.

	ZERO-KNOWLEDGE INVARIANTS (wiring-level):
	  - project key + PAT live in plugin settings only (operator-local
	    plaintext on disk — documented, accepted model; see Settings.luau);
	  - neither is ever printed, warned, or sent anywhere except: key →
	    nowhere (only its fingerprint goes on the wire), PAT → Authorization
	    header only;
	  - plaintext source is read once per upload, encrypted in-process, and
	    only ciphertext leaves; nothing is logged but instance PATHS.
]]

if not plugin then
	-- Defensive: this Script only makes sense as a Studio plugin.
	return
end

-- [STUDIO-VERIFY] RunService:IsEdit() is true in the edit DataModel and false
-- in play-test sessions. The plugin is an EDIT-session tool: a play session is
-- a throwaway copy of the game running a separate plugin instance — uploading
-- from it would stamp PlaceVersion 0 (the backend rejects that, but as a
-- confusing failure) and jump-to-line would open scripts whose edits vanish on
-- Stop. No-op outside edit mode.
local RunService = game:GetService("RunService")
if not RunService:IsEdit() then
	return
end

local HttpService = game:GetService("HttpService")
-- [STUDIO-VERIFY] ScriptEditorService exists and is plugin-accessible; used
-- for OpenScriptDocumentAsync / FindScriptDocument / ForceSetSelectionAsync.
local ScriptEditorService = game:GetService("ScriptEditorService")

local root = script.Parent
local SettingsModel = require(root.Settings)
local Uploader = require(root.Uploader)
local Inspector = require(root.Inspector.Inspector)
local PathResolver = require(root.Inspector.PathResolver)
local crypto = {
	AesGcm = require(root.Crypto.AesGcm),
	Sha256 = require(root.Crypto.Sha256),
	Base64 = require(root.Crypto.Base64),
}

-- [STUDIO-VERIFY] plugin:GetSetting/SetSetting(key) persist per-user,
-- per-plugin values as plaintext JSON on the operator's disk.
local settingsModel = SettingsModel.new({
	crypto = crypto,
	get = function(key)
		return plugin:GetSetting(key)
	end,
	set = function(key, value)
		plugin:SetSetting(key, value)
	end,
})

-- One-time BugHub_* → BloxTools_* setting-key migration (legacy rebrand). Existing
-- installs saved their URL/token/project-key/game under the legacy BugHub_* keys;
-- copy any such value into the new BloxTools_* key and clear the old one so the
-- operator doesn't have to re-enter anything. Idempotent + value-safe (never
-- clobbers a value already saved under the new key; logs nothing — values may be
-- a PAT/project key). [STUDIO-VERIFY] runs against the real plugin settings store.
do
	local okMigrate, migratedOrErr = pcall(function()
		return settingsModel:migrateLegacyKeys()
	end)
	if okMigrate and type(migratedOrErr) == "number" and migratedOrErr > 0 then
		warn(("[BloxTools] migrated %d setting(s) from the legacy BugHub_* keys to BloxTools_*."):format(migratedOrErr))
	end
end

local pluginAlive = true
-- [STUDIO-VERIFY] plugin.Unloading fires when the plugin is deactivated,
-- uninstalled, or Studio closes; used to stop the poll loop.
plugin.Unloading:Connect(function()
	pluginAlive = false
end)

-- HttpService:RequestAsync wrapper injected into Uploader/Inspector.
-- [STUDIO-VERIFY] In a plugin, the FIRST RequestAsync to a new domain makes
-- Studio prompt the user to allow HTTP access for THIS plugin to THAT domain
-- (one domain = one prompt; see plugin/TRUST.md). RequestAsync returns
-- { Success, StatusCode, StatusMessage, Headers, Body } and raises on
-- transport errors (callers pcall it).
local function httpRequest(options)
	return HttpService:RequestAsync(options)
end

local function jsonEncode(value)
	return HttpService:JSONEncode(value)
end

local function jsonDecode(value)
	return HttpService:JSONDecode(value)
end

-- ─────────────────────────────────────────────────────────────────────────────
-- UI helpers (plain Instances; no external UI libs)
-- ─────────────────────────────────────────────────────────────────────────────

local COLORS = {
	bg = Color3.fromRGB(46, 46, 46),
	row = Color3.fromRGB(56, 56, 56),
	rowHover = Color3.fromRGB(66, 66, 66),
	text = Color3.fromRGB(230, 230, 230),
	dim = Color3.fromRGB(160, 160, 160),
	accent = Color3.fromRGB(0, 162, 255),
	bad = Color3.fromRGB(240, 110, 100),
	good = Color3.fromRGB(120, 200, 130),
}

local function mk(className, props, parent)
	local inst = Instance.new(className)
	for k, v in props do
		inst[k] = v
	end
	inst.Parent = parent
	return inst
end

local function mkLabel(parent, text, height, color)
	return mk("TextLabel", {
		Text = text,
		Size = UDim2.new(1, -16, 0, height or 18),
		BackgroundTransparency = 1,
		TextColor3 = color or COLORS.text,
		TextXAlignment = Enum.TextXAlignment.Left,
		TextTruncate = Enum.TextTruncate.AtEnd,
		Font = Enum.Font.SourceSans,
		TextSize = 16,
	}, parent)
end

local function mkButton(parent, text, width)
	return mk("TextButton", {
		Text = text,
		Size = UDim2.new(0, width or 130, 0, 26),
		BackgroundColor3 = COLORS.row,
		TextColor3 = COLORS.text,
		Font = Enum.Font.SourceSansSemibold,
		TextSize = 15,
		AutoButtonColor = true,
		BorderSizePixel = 0,
	}, parent)
end

local function mkTextBox(parent, placeholder)
	return mk("TextBox", {
		PlaceholderText = placeholder,
		Text = "",
		ClearTextOnFocus = false,
		Size = UDim2.new(1, -16, 0, 26),
		BackgroundColor3 = COLORS.row,
		TextColor3 = COLORS.text,
		PlaceholderColor3 = COLORS.dim,
		Font = Enum.Font.Code,
		TextSize = 14,
		TextXAlignment = Enum.TextXAlignment.Left,
		BorderSizePixel = 0,
	}, parent)
end

local function mkListFrame(parent)
	local frame = mk("ScrollingFrame", {
		Size = UDim2.new(1, 0, 1, -70),
		Position = UDim2.new(0, 0, 0, 70),
		BackgroundTransparency = 1,
		ScrollBarThickness = 6,
		CanvasSize = UDim2.new(0, 0, 0, 0),
		AutomaticCanvasSize = Enum.AutomaticSize.Y,
		BorderSizePixel = 0,
	}, parent)
	mk("UIListLayout", {
		Padding = UDim.new(0, 4),
		SortOrder = Enum.SortOrder.LayoutOrder,
	}, frame)
	mk("UIPadding", {
		PaddingLeft = UDim.new(0, 8),
		PaddingRight = UDim.new(0, 8),
		PaddingTop = UDim.new(0, 4),
	}, frame)
	return frame
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Toolbar + widgets
-- ─────────────────────────────────────────────────────────────────────────────

-- [STUDIO-VERIFY] plugin:CreateToolbar(name) and
-- toolbar:CreateButton(buttonId, tooltip, iconAssetId, text) — assumed
-- 4-arg form with empty icon falling back to the text label.
local toolbar = plugin:CreateToolbar("BloxTools")
local inspectorButton = toolbar:CreateButton("BloxToolsErrors", "Live error groups — click to jump to the line", "", "Errors")
local settingsButton = toolbar:CreateButton("BloxToolsSettings", "Backend URL, access token, project key, game", "", "Settings")

-- [STUDIO-VERIFY] DockWidgetPluginGuiInfo.new(initialDockState, initEnabled,
-- overrideEnabledRestore, floatWidth, floatHeight, minWidth, minHeight) and
-- plugin:CreateDockWidgetPluginGui(id, info). Widget restores its previous
-- enabled/dock state across sessions when overrideEnabledRestore = false.
local inspectorWidget = plugin:CreateDockWidgetPluginGui(
	"BloxToolsErrors",
	DockWidgetPluginGuiInfo.new(Enum.InitialDockState.Right, false, false, 340, 480, 280, 240)
)
inspectorWidget.Title = "BloxTools — Errors"

local settingsWidget = plugin:CreateDockWidgetPluginGui(
	"BloxToolsSettings",
	DockWidgetPluginGuiInfo.new(Enum.InitialDockState.Float, false, false, 360, 460, 320, 380)
)
settingsWidget.Title = "BloxTools — Settings"

inspectorButton.Click:Connect(function()
	inspectorWidget.Enabled = not inspectorWidget.Enabled
end)
settingsButton.Click:Connect(function()
	settingsWidget.Enabled = not settingsWidget.Enabled
end)

-- ─────────────────────────────────────────────────────────────────────────────
-- Settings widget
-- ─────────────────────────────────────────────────────────────────────────────

local settingsRoot = mk("Frame", {
	Size = UDim2.new(1, 0, 1, 0),
	BackgroundColor3 = COLORS.bg,
	BorderSizePixel = 0,
}, settingsWidget)
mk("UIListLayout", { Padding = UDim.new(0, 6), SortOrder = Enum.SortOrder.LayoutOrder }, settingsRoot)
mk("UIPadding", { PaddingLeft = UDim.new(0, 8), PaddingRight = UDim.new(0, 8), PaddingTop = UDim.new(0, 8) }, settingsRoot)

local settingsStatus -- forward-declared; bottom status label
-- forward-declared; defined after the Inspector dock exists (it updates dock +
-- upload UI too). Probes GET /api/account/token-info and renders the Pro+ state.
local refreshPlanState

-- The persistent Pro+ upgrade copy (matches Inspector.PRO_GATE_MESSAGE).
local PRO_GATE_MESSAGE = "Studio plugin is a Pro+ feature — upgrade in the dashboard."

local function setSettingsStatus(text, color)
	settingsStatus.Text = text
	settingsStatus.TextColor3 = color or COLORS.dim
end

-- Backend URL
mkLabel(settingsRoot, "Backend URL", 18, COLORS.dim)
local urlBox = mkTextBox(settingsRoot, "http://localhost:3000")
urlBox.Text = settingsModel:backendUrl()

-- Access token (masked after save; the box never re-displays a stored token)
mkLabel(settingsRoot, "Access token (blxt_…, read + upload scopes)", 18, COLORS.dim)

-- Pro+ gating banner — anchored right under the access-token label because the
-- token IS the gate (ALL PAT use is a Pro+ feature). Populated by refreshPlanState()
-- from GET /api/account/token-info; hidden until we know the plan. On a Free
-- account it shows the persistent upgrade prompt; on Pro/Studio it stays hidden.
local proBanner = mkLabel(settingsRoot, "", 32, COLORS.bad)
proBanner.TextWrapped = true
proBanner.Visible = false

local patState = mkLabel(settingsRoot, "Stored: " .. SettingsModel.maskPat(settingsModel:pat()), 16, COLORS.dim)
local patBox = mkTextBox(settingsRoot, "paste a new token to replace")

-- Project key (never re-displayed; only its fingerprint is shown)
mkLabel(settingsRoot, "Project key (44-char base64 from the dashboard)", 18, COLORS.dim)
local _, _, storedFp = settingsModel:projectKey()
local keyState = mkLabel(
	settingsRoot,
	storedFp and ("Stored: key with fingerprint " .. storedFp .. " — compare with the dashboard") or "Stored: (none)",
	16,
	COLORS.dim
)
local keyBox = mkTextBox(settingsRoot, "paste the key to replace (shown once in the dash)")

local saveButton = mkButton(settingsRoot, "Save settings", 140)

-- Game picker
mkLabel(settingsRoot, "Game", 18, COLORS.dim)
local gameId, gameName = settingsModel:game()
local gameState = mkLabel(settingsRoot, gameId and ("Selected: " .. tostring(gameName)) or "Selected: (none)", 16, COLORS.dim)
local loadGamesButton = mkButton(settingsRoot, "Load my games", 140)
local gamesList = mk("Frame", {
	Size = UDim2.new(1, -16, 0, 0),
	AutomaticSize = Enum.AutomaticSize.Y,
	BackgroundTransparency = 1,
}, settingsRoot)
mk("UIListLayout", { Padding = UDim.new(0, 3), SortOrder = Enum.SortOrder.LayoutOrder }, gamesList)

settingsStatus = mkLabel(settingsRoot, "", 32, COLORS.dim)
settingsStatus.TextWrapped = true

local function makeInspectorClient()
	local pat = settingsModel:pat()
	local gid = settingsModel:game()
	if not pat then
		return nil, "Set an access token first (Settings)."
	end
	return Inspector.new({
		resolver = PathResolver,
		request = httpRequest,
		jsonDecode = jsonDecode,
		patToken = pat,
		baseUrl = settingsModel:backendUrl(),
		gameId = gid, -- nil is fine for fetchGames (not used there)
		root = game,
		warn = warn,
	})
end

saveButton.MouseButton1Click:Connect(function()
	local okUrl, urlOrMsg = settingsModel:setBackendUrl(urlBox.Text)
	if not okUrl then
		setSettingsStatus(urlOrMsg, COLORS.bad)
		return
	end
	urlBox.Text = urlOrMsg

	if patBox.Text ~= "" then
		local okPat, msg = settingsModel:setPat(patBox.Text)
		if not okPat then
			setSettingsStatus(msg, COLORS.bad)
			return
		end
		patBox.Text = "" -- never leave the full token sitting in a TextBox
		patState.Text = "Stored: " .. SettingsModel.maskPat(settingsModel:pat())
	end

	if keyBox.Text ~= "" then
		local okKey, fpOrMsg = settingsModel:setProjectKey(keyBox.Text)
		if not okKey then
			setSettingsStatus(fpOrMsg, COLORS.bad)
			return
		end
		keyBox.Text = "" -- never leave the key sitting in a TextBox
		keyState.Text = "Stored: key with fingerprint " .. fpOrMsg .. " — compare with the dashboard"
	end

	setSettingsStatus("Saved.", COLORS.good)
	-- A new token may belong to a different account/plan — re-probe the banner.
	if refreshPlanState then
		refreshPlanState()
	end
end)

loadGamesButton.MouseButton1Click:Connect(function()
	for _, child in gamesList:GetChildren() do
		if child:IsA("TextButton") then
			child:Destroy()
		end
	end
	local client, err = makeInspectorClient()
	if not client then
		setSettingsStatus(err, COLORS.bad)
		return
	end
	setSettingsStatus("Loading games…")
	task.spawn(function()
		local games, fetchErr, planGated = client:fetchGames()
		if not games then
			if planGated then
				-- The PAT works but the account is on Free → Pro+ gate, not a real error.
				setSettingsStatus(PRO_GATE_MESSAGE, COLORS.bad)
				if refreshPlanState then
					refreshPlanState()
				end
				return
			end
			setSettingsStatus("Could not load games: " .. tostring(fetchErr), COLORS.bad)
			return
		end
		if #games == 0 then
			setSettingsStatus("No games on this account yet — create one in the dashboard.", COLORS.bad)
			return
		end
		for i, g in games do
			local b = mkButton(gamesList, g.name, 0)
			b.Size = UDim2.new(1, 0, 0, 24)
			b.LayoutOrder = i
			b.MouseButton1Click:Connect(function()
				settingsModel:setGame(g.id, g.name)
				gameState.Text = "Selected: " .. g.name
				setSettingsStatus("Game selected.", COLORS.good)
			end)
		end
		setSettingsStatus(("%d game(s) — click one to select."):format(#games))
	end)
end)

-- ─────────────────────────────────────────────────────────────────────────────
-- Inspector dock (error list, jump-to-line, Upload source now)
-- ─────────────────────────────────────────────────────────────────────────────

local inspectorRoot = mk("Frame", {
	Size = UDim2.new(1, 0, 1, 0),
	BackgroundColor3 = COLORS.bg,
	BorderSizePixel = 0,
}, inspectorWidget)

local topBar = mk("Frame", {
	Size = UDim2.new(1, 0, 0, 34),
	BackgroundTransparency = 1,
}, inspectorRoot)
mk("UIListLayout", {
	FillDirection = Enum.FillDirection.Horizontal,
	Padding = UDim.new(0, 6),
	VerticalAlignment = Enum.VerticalAlignment.Center,
	SortOrder = Enum.SortOrder.LayoutOrder,
}, topBar)
mk("UIPadding", { PaddingLeft = UDim.new(0, 8) }, topBar)

local uploadButton = mkButton(topBar, "Upload source now", 150)
uploadButton.BackgroundColor3 = COLORS.accent
local refreshButton = mkButton(topBar, "Refresh", 80)

local inspectorStatus = mk("TextLabel", {
	Text = "Open the dock and press Refresh.",
	Size = UDim2.new(1, -16, 0, 30),
	Position = UDim2.new(0, 8, 0, 36),
	BackgroundTransparency = 1,
	TextColor3 = COLORS.dim,
	TextXAlignment = Enum.TextXAlignment.Left,
	TextWrapped = true,
	Font = Enum.Font.SourceSans,
	TextSize = 14,
}, inspectorRoot)

local listFrame = mkListFrame(inspectorRoot)

local function setInspectorStatus(text, color)
	inspectorStatus.Text = text
	inspectorStatus.TextColor3 = color or COLORS.dim
end

-- ── Pro+ plan state (proactive banner) ───────────────────────────────────────

-- Render the Pro+ gated state across all three surfaces (Settings banner,
-- Inspector dock status, upload button). gated == true → Free account.
local function applyPlanState(gated)
	if gated then
		proBanner.Text = PRO_GATE_MESSAGE
		proBanner.Visible = true
		setInspectorStatus(PRO_GATE_MESSAGE, COLORS.bad)
		uploadButton.Text = "Upload (Pro+)"
		uploadButton.BackgroundColor3 = COLORS.row
	else
		proBanner.Visible = false
		uploadButton.Text = "Upload source now"
		uploadButton.BackgroundColor3 = COLORS.accent
	end
end

-- Probe GET /api/account/token-info (the one PAT route exempt from the Pro+ 403, so
-- it answers even for Free) and render the Pro+ banner if plan == 'free'. Quietly
-- no-ops when there's no token yet (nothing to gate on) or the backend is
-- unreachable (don't show a misleading Pro+ note for a transient network error).
-- Defined as a forward-declared upvalue so the connect points above can call it.
refreshPlanState = function()
	local pat = settingsModel:pat()
	if not pat then
		applyPlanState(false) -- no token → no gate to show yet
		return
	end
	local client = makeInspectorClient()
	if not client then
		return
	end
	task.spawn(function()
		local plan, err = client:fetchPlan()
		if not plan then
			-- planGated would only come back if token-info itself were gated, but
			-- the backend exempts it; a real error here (network/older backend) → leave
			-- the banner as-is rather than asserting a plan we couldn't read.
			if err == Inspector.PRO_GATE_MESSAGE then
				applyPlanState(true)
			end
			return
		end
		applyPlanState(plan == "free")
	end)
end

-- Click handler for one group row: locate the frame, open + select the line.
local function jumpToGroup(client, group)
	setInspectorStatus("Locating " .. group.message)
	local located = client:locate(group)
	if located.kind == "notfound" then
		if located.reason == "noframes" then
			setInspectorStatus("This group has no parsable stack frames to jump to.", COLORS.bad)
		else
			setInspectorStatus(
				("Not found in this place: %s (renamed/deleted, or from another version)."):format(located.path),
				COLORS.bad
			)
		end
		return
	end
	-- [STUDIO-VERIFY] ScriptEditorService:OpenScriptDocumentAsync(script)
	-- returns (success: boolean, err: string) rather than throwing — pcall
	-- guards both behaviors. Must be called from a plugin context.
	local opened, openErr = false, nil
	local okCall, callErr = pcall(function()
		opened, openErr = ScriptEditorService:OpenScriptDocumentAsync(located.instance)
	end)
	if not okCall then
		opened, openErr = false, callErr
	end
	if not opened then
		setInspectorStatus("Could not open " .. located.path .. ": " .. tostring(openErr), COLORS.bad)
		return
	end
	-- [STUDIO-VERIFY] ScriptEditorService:FindScriptDocument(script) returns
	-- the open ScriptDocument, and ScriptDocument:ForceSetSelectionAsync(
	-- cursorLine, cursorChar, anchorLine?, anchorChar?) moves the editor
	-- cursor (selection-jump is the achievable UX; persistent gutter marks
	-- are not in the plugin API — DESIGN/ROADMAP note).
	local doc = ScriptEditorService:FindScriptDocument(located.instance)
	if doc then
		pcall(function()
			doc:ForceSetSelectionAsync(located.line, 1)
		end)
	end
	setInspectorStatus(("Opened %s at line %d."):format(located.path, located.line), COLORS.good)
end

local refreshing = false
local function refreshInspector()
	if refreshing then
		return
	end
	local client, err = makeInspectorClient()
	if not client then
		setInspectorStatus(err, COLORS.bad)
		return
	end
	if not client.gameId then
		setInspectorStatus("Pick a game in Settings first.", COLORS.bad)
		return
	end
	refreshing = true
	setInspectorStatus("Refreshing…")
	task.spawn(function()
		local groups, fetchErr, planGated = client:fetchGroups()
		refreshing = false
		if not groups then
			if planGated then
				-- Free account → Pro+ gate. Show the upgrade prompt, not a raw error.
				setInspectorStatus(PRO_GATE_MESSAGE, COLORS.bad)
				if refreshPlanState then
					refreshPlanState()
				end
				return
			end
			setInspectorStatus("Refresh failed: " .. tostring(fetchErr), COLORS.bad)
			return
		end
		for _, child in listFrame:GetChildren() do
			if child:IsA("TextButton") then
				child:Destroy()
			end
		end
		if #groups == 0 then
			setInspectorStatus("No open error groups. Quiet is good.", COLORS.good)
			return
		end
		for i, group in groups do
			local row = mk("TextButton", {
				Text = "",
				Size = UDim2.new(1, 0, 0, 44),
				BackgroundColor3 = COLORS.row,
				BorderSizePixel = 0,
				AutoButtonColor = true,
				LayoutOrder = i,
			}, listFrame)
			local msg = mkLabel(row, ("[%d×] %s"):format(group.count, group.message), 20)
			msg.Position = UDim2.new(0, 8, 0, 2)
			msg.TextSize = 15
			local where = mkLabel(
				row,
				group.topPath and (tostring(group.topPath) .. (group.topFn and (" · " .. group.topFn) or "")) or "(no frame)",
				16,
				COLORS.dim
			)
			where.Position = UDim2.new(0, 8, 0, 22)
			where.TextSize = 13
			row.MouseButton1Click:Connect(function()
				task.spawn(jumpToGroup, client, group)
			end)
		end
		setInspectorStatus(("%d open group(s). Click one to jump to the line."):format(#groups))
	end)
end

refreshButton.MouseButton1Click:Connect(refreshInspector)

-- Refresh when the dock is opened, then every 30s WHILE it stays open
-- (manual refresh always available). No polling while closed.
inspectorWidget:GetPropertyChangedSignal("Enabled"):Connect(function()
	if inspectorWidget.Enabled then
		refreshPlanState()
		refreshInspector()
	end
end)
task.spawn(function()
	while pluginAlive do
		task.wait(30)
		if pluginAlive and inspectorWidget.Enabled then
			refreshInspector()
		end
	end
end)

-- ── Upload source now ────────────────────────────────────────────────────────

-- Containers walked for scripts. game:GetDescendants() on the DataModel
-- itself can throw on permission-restricted services, so each top-level
-- service is walked individually under pcall and unreadable ones skipped.
-- [STUDIO-VERIFY] confirm the walk reaches all script containers in a real
-- place and that restricted services fail soft (pcall) rather than hard.
local function uploadContainers()
	local containers = {}
	for _, child in game:GetChildren() do
		local ok = pcall(function()
			return #child:GetDescendants()
		end)
		if ok then
			containers[#containers + 1] = child
		end
	end
	return containers
end

local uploading = false
uploadButton.MouseButton1Click:Connect(function()
	if uploading then
		return
	end
	local keyB64 = settingsModel:projectKey()
	local pat = settingsModel:pat()
	local gid = settingsModel:game()
	if not keyB64 then
		setInspectorStatus("Paste your project key in Settings first.", COLORS.bad)
		return
	end
	if not pat then
		setInspectorStatus("Set an access token (upload scope) in Settings first.", COLORS.bad)
		return
	end
	if not gid then
		setInspectorStatus("Pick a game in Settings first.", COLORS.bad)
		return
	end

	-- [STUDIO-VERIFY] game.PlaceVersion is the live published version (0 in
	-- an unpublished place). The operator presses this button right AFTER
	-- File → Publish, so PlaceVersion already reflects the new version —
	-- shown in the progress text so a stale upload is visible.
	local placeVersion = game.PlaceVersion

	uploading = true
	uploadButton.Text = "Uploading…"
	task.spawn(function()
		local okRun, summaryOrErr = pcall(function()
			local uploader = Uploader.new({
				crypto = crypto,
				keyB64 = keyB64,
				patToken = pat,
				baseUrl = settingsModel:backendUrl(),
				gameId = gid,
				request = httpRequest,
				jsonEncode = jsonEncode,
				jsonDecode = jsonDecode,
				-- [STUDIO-VERIFY] GenerateGUID(false) → bare GUID string; the
				-- load-bearing uniqueness term of IV derivation (Uploader.deriveIv).
				guid = function()
					return HttpService:GenerateGUID(false)
				end,
				clock = os.clock,
				wait = task.wait,
				warn = warn,
			})
			return uploader:run(uploadContainers(), placeVersion, function(state)
				if state.phase == "enumerate" then
					setInspectorStatus(("Enumerating scripts… (place v%d)"):format(placeVersion))
				elseif state.phase == "encrypt" then
					setInspectorStatus(("Encrypting %d/%d… (place v%d)"):format(state.done, state.total, placeVersion))
				elseif state.phase == "upload" then
					setInspectorStatus(("Uploading chunk %d/%d… (place v%d)"):format(state.done, state.total, placeVersion))
				end
			end)
		end)
		uploading = false
		uploadButton.Text = "Upload source now"
		if not okRun then
			-- Error strings from Uploader.new name no secrets (key paste
			-- errors deliberately do not echo the pasted value).
			setInspectorStatus("Upload failed: " .. tostring(summaryOrErr), COLORS.bad)
			return
		end
		local s = summaryOrErr
		if s.planGated then
			-- The backend refused the PAT for this account (Free → Pro+ gate).
			setInspectorStatus(PRO_GATE_MESSAGE, COLORS.bad)
			if refreshPlanState then
				refreshPlanState()
			end
			return
		end
		local report = ("Done (place v%d): %d scripts, %d encrypted, %d accepted, %d skipped (server), %d skipped (size)."):format(
			placeVersion,
			s.scripts,
			s.encrypted,
			s.accepted,
			s.skippedServer,
			s.skippedLocal
		)
		if s.chunksFailed > 0 then
			setInspectorStatus(report .. (" %d chunk(s) FAILED — see Output, then retry."):format(s.chunksFailed), COLORS.bad)
		else
			setInspectorStatus(report, COLORS.good)
		end
	end)
end)

-- ── Proactive Pro+ banner on load ────────────────────────────────────────────
-- Probe the plan once at startup so a Free account sees the persistent
-- "Studio plugin is a Pro+ feature — upgrade in the dashboard" banner in Settings
-- (and the matching dock/upload state) BEFORE pressing anything — not just as a
-- reactive 403. No-ops silently if no token is configured yet.
refreshPlanState()
