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

-- Dark UI palette.
local COLORS = {
	bg = Color3.fromRGB(11, 11, 13), -- canvas
	surface = Color3.fromRGB(20, 20, 23), -- cards / inputs
	field = Color3.fromRGB(20, 20, 23),
	row = Color3.fromRGB(24, 24, 27), -- list rows
	rowHover = Color3.fromRGB(34, 34, 38),
	stroke = Color3.fromRGB(40, 40, 45), -- hairline borders
	strokeStrong = Color3.fromRGB(60, 60, 66),
	ink = Color3.fromRGB(250, 250, 250), -- headings, input text, grid
	text = Color3.fromRGB(214, 214, 220), -- body
	dim = Color3.fromRGB(140, 140, 146), -- captions / eyebrows
	dim2 = Color3.fromRGB(96, 96, 102), -- placeholders
	white = Color3.fromRGB(255, 255, 255), -- primary button fill
	accent = Color3.fromRGB(96, 165, 250), -- focus / selection
	bad = Color3.fromRGB(242, 116, 109),
	good = Color3.fromRGB(63, 185, 80),
}

-- Maps a UI role to a built-in font. (Roblox can't load custom fonts in a
-- distributed plugin, so these are the closest built-ins: Gotham, RobotoMono.)
local function brandFont(_role, builtin, _weight)
	return Font.fromEnum(builtin)
end

local function mk(className, props, parent)
	local inst = Instance.new(className)
	for k, v in props do
		inst[k] = v
	end
	inst.Parent = parent
	return inst
end

-- Rounded corners / borders — tiny wrappers so every surface is styled the same.
local function corner(inst, radius)
	mk("UICorner", { CornerRadius = UDim.new(0, radius or 6) }, inst)
	return inst
end

-- Fully-rounded "pill" (scale radius → rounds to any height the caller sets).
local function pill(inst)
	mk("UICorner", { CornerRadius = UDim.new(1, 0) }, inst)
	return inst
end

local function stroke(inst, color, thickness, transparency)
	mk("UIStroke", {
		Color = color or COLORS.stroke,
		Thickness = thickness or 1,
		Transparency = transparency or 0,
		ApplyStrokeMode = Enum.ApplyStrokeMode.Border,
	}, inst)
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
		FontFace = brandFont("body", Enum.Font.Gotham),
		TextSize = 15,
	}, parent)
end

-- Secondary pill button (fill + hairline border). mkPrimaryButton overrides it.
local function mkButton(parent, text, width)
	local btn = mk("TextButton", {
		Text = text,
		Size = UDim2.new(0, width or 130, 0, 32),
		BackgroundColor3 = COLORS.surface,
		TextColor3 = COLORS.text,
		FontFace = brandFont("bodyMedium", Enum.Font.GothamMedium, Enum.FontWeight.Medium),
		TextSize = 14,
		AutoButtonColor = true,
		BorderSizePixel = 0,
	}, parent)
	pill(btn)
	stroke(btn, COLORS.strokeStrong, 1, 0)
	return btn
end

-- Per-input border tracking, so Save can flag an invalid field red until edited.
local fieldRing = setmetatable({}, { __mode = "k" }) -- TextBox -> UIStroke
local fieldInvalid = setmetatable({}, { __mode = "k" }) -- TextBox -> true

-- Rounded mono input with an accent focus ring. The TextBox is inset inside a
-- clipping frame instead of using UIPadding, because Roblox ignores UIPadding
-- for cursor-follow scrolling while editing (text would overflow the margins).
local function mkTextBox(parent, placeholder)
	local box = mk("Frame", {
		Size = UDim2.new(1, 0, 0, 34),
		BackgroundColor3 = COLORS.field,
		BorderSizePixel = 0,
	}, parent)
	corner(box, 8)
	local ring = stroke(box, COLORS.strokeStrong, 1, 0)
	-- Inset clip region = the input's true text area, so editing stays in bounds.
	local clip = mk("Frame", {
		Size = UDim2.new(1, -24, 1, 0),
		Position = UDim2.new(0, 12, 0, 0),
		BackgroundTransparency = 1,
		ClipsDescendants = true,
	}, box)
	local input = mk("TextBox", {
		PlaceholderText = placeholder,
		Text = "",
		ClearTextOnFocus = false,
		Size = UDim2.new(1, 0, 1, 0),
		BackgroundTransparency = 1,
		TextColor3 = COLORS.ink,
		PlaceholderColor3 = COLORS.dim2,
		FontFace = brandFont("mono", Enum.Font.RobotoMono),
		TextSize = 13,
		TextXAlignment = Enum.TextXAlignment.Left,
		BorderSizePixel = 0,
	}, clip)
	fieldRing[input] = ring
	local function applyRing()
		if input:IsFocused() then
			ring.Color, ring.Thickness = COLORS.ink, 1.5
		elseif fieldInvalid[input] then
			ring.Color, ring.Thickness = COLORS.bad, 1.5
		else
			ring.Color, ring.Thickness = COLORS.strokeStrong, 1
		end
	end
	input.Focused:Connect(applyRing)
	input.FocusLost:Connect(applyRing)
	input:GetPropertyChangedSignal("Text"):Connect(function()
		if fieldInvalid[input] then
			fieldInvalid[input] = nil
			applyRing()
		end
	end)
	return input
end

-- Flag a field's border red (cleared when the user edits it).
local function markFieldInvalid(input)
	fieldInvalid[input] = true
	local ring = fieldRing[input]
	if ring then
		ring.Color, ring.Thickness = COLORS.bad, 1.5
	end
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

-- Small uppercase mono label used as a section eyebrow.
local function mkEyebrow(parent, text)
	return mk("TextLabel", {
		Text = string.upper(text),
		Size = UDim2.new(1, 0, 0, 14),
		BackgroundTransparency = 1,
		TextColor3 = COLORS.dim,
		TextXAlignment = Enum.TextXAlignment.Left,
		FontFace = brandFont("mono", Enum.Font.RobotoMono),
		TextSize = 12,
	}, parent)
end

-- A rounded card with an eyebrow title and a vertical stack of fields.
local function mkSection(parent, eyebrow)
	local card = mk("Frame", {
		Size = UDim2.new(1, 0, 0, 0),
		AutomaticSize = Enum.AutomaticSize.Y,
		BackgroundColor3 = COLORS.surface,
		BorderSizePixel = 0,
	}, parent)
	corner(card, 14)
	stroke(card, COLORS.stroke, 1, 0)
	mk("UIPadding", {
		PaddingTop = UDim.new(0, 14),
		PaddingBottom = UDim.new(0, 14),
		PaddingLeft = UDim.new(0, 14),
		PaddingRight = UDim.new(0, 14),
	}, card)
	mk("UIListLayout", {
		Padding = UDim.new(0, 8),
		SortOrder = Enum.SortOrder.LayoutOrder,
		HorizontalAlignment = Enum.HorizontalAlignment.Left,
	}, card)
	if eyebrow then
		mkEyebrow(card, eyebrow).LayoutOrder = -100
	end
	return card
end

-- Field caption above an input.
local function mkFieldLabel(parent, text)
	return mk("TextLabel", {
		Text = text,
		Size = UDim2.new(1, 0, 0, 0),
		AutomaticSize = Enum.AutomaticSize.Y,
		BackgroundTransparency = 1,
		TextColor3 = COLORS.text,
		TextXAlignment = Enum.TextXAlignment.Left,
		FontFace = brandFont("bodyMedium", Enum.Font.GothamMedium, Enum.FontWeight.Medium),
		TextSize = 14,
		TextWrapped = true,
	}, parent)
end

-- Smaller, fainter helper line under a caption.
local function mkHelp(parent, text)
	return mk("TextLabel", {
		Text = text,
		Size = UDim2.new(1, 0, 0, 0),
		AutomaticSize = Enum.AutomaticSize.Y,
		BackgroundTransparency = 1,
		TextColor3 = COLORS.dim,
		TextXAlignment = Enum.TextXAlignment.Left,
		FontFace = brandFont("body", Enum.Font.Gotham),
		TextSize = 12,
		TextWrapped = true,
	}, parent)
end

-- A status / value line. `mono` renders values (tokens, fingerprints) in mono.
local function mkInfoLabel(parent, text, color, mono)
	return mk("TextLabel", {
		Text = text,
		Size = UDim2.new(1, 0, 0, 0),
		AutomaticSize = Enum.AutomaticSize.Y,
		BackgroundTransparency = 1,
		TextColor3 = color or COLORS.dim,
		TextXAlignment = Enum.TextXAlignment.Left,
		FontFace = mono and brandFont("mono", Enum.Font.RobotoMono)
			or brandFont("body", Enum.Font.Gotham),
		TextSize = 13,
		TextWrapped = true,
	}, parent)
end

-- Primary pill: solid white fill, dark text, no border.
local function mkPrimaryButton(parent, text, width)
	local btn = mkButton(parent, text, width)
	btn.BackgroundColor3 = COLORS.white
	btn.TextColor3 = COLORS.bg
	btn.FontFace = brandFont("bodyMedium", Enum.Font.GothamBold, Enum.FontWeight.SemiBold)
	local edge = btn:FindFirstChildOfClass("UIStroke")
	if edge then
		edge.Transparency = 1
	end
	return btn
end

-- Faint grid drawn behind the content (ZIndex 0) as ambient texture.
local function paintGrid(parent)
	local layer = mk("Frame", {
		Size = UDim2.new(1, 0, 1, 0),
		BackgroundTransparency = 1,
		ClipsDescendants = true,
		ZIndex = 0,
	}, parent)
	local W, H, cell = 760, 1600, 30
	for x = 0, W, cell do
		mk("Frame", {
			Size = UDim2.new(0, 1, 0, H),
			Position = UDim2.new(0, x, 0, 0),
			BackgroundColor3 = COLORS.ink,
			BackgroundTransparency = 0.955,
			BorderSizePixel = 0,
			ZIndex = 0,
		}, layer)
	end
	for y = 0, H, cell do
		mk("Frame", {
			Size = UDim2.new(0, W, 0, 1),
			Position = UDim2.new(0, 0, 0, y),
			BackgroundColor3 = COLORS.ink,
			BackgroundTransparency = 0.955,
			BorderSizePixel = 0,
			ZIndex = 0,
		}, layer)
	end
	return layer
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Brand assets (logo + toolbar icon)
-- ─────────────────────────────────────────────────────────────────────────────
--
-- Pass an Image id to render it directly, or a Decal id to render it via
-- rbxthumb. (To convert a Decal id to its Image id, run in the Command Bar:
-- print(game:GetObjects("rbxassetid://<DECAL_ID>")[1].Texture))
local function assetImage(imageId, decalId)
	if imageId ~= "" then
		return "rbxassetid://" .. imageId
	elseif decalId ~= "" then
		return "rbxthumb://type=Asset&id=" .. decalId .. "&w=420&h=420"
	end
	return ""
end

local LOGO_IMAGE = assetImage("", "102132691217053") -- (imageId, decalId)
local ICON_IMAGE = assetImage("", "") -- toolbar icon; falls back to the logo
local TOOLBAR_ICON = ICON_IMAGE ~= "" and ICON_IMAGE or LOGO_IMAGE

-- ─────────────────────────────────────────────────────────────────────────────
-- Toolbar + widgets
-- ─────────────────────────────────────────────────────────────────────────────

-- One toolbar button toggles ONE combined dock widget; Errors and Settings live
-- inside it as tabs (rather than two separate docks/buttons).
local toolbar = plugin:CreateToolbar("BloxTools")
local toggleButton = toolbar:CreateButton("BloxToolsMain", "BloxTools — errors & settings", TOOLBAR_ICON, "BloxTools")

local mainWidget = plugin:CreateDockWidgetPluginGui(
	"BloxToolsMain",
	DockWidgetPluginGuiInfo.new(Enum.InitialDockState.Right, false, false, 360, 540, 300, 380)
)
mainWidget.Title = "BloxTools"
toggleButton.Click:Connect(function()
	mainWidget.Enabled = not mainWidget.Enabled
end)

-- Forward-declared so the tab bar (built now) can drive the refresh logic that is
-- defined further down with the Errors panel.
local refreshPlanState
local refreshInspector
local activeTab = "settings"

-- ── Shell: bg + grid + shared header + tab bar + content views ────────────────
local mainRoot = mk("Frame", {
	Size = UDim2.new(1, 0, 1, 0),
	BackgroundColor3 = COLORS.bg,
	BorderSizePixel = 0,
}, mainWidget)
paintGrid(mainRoot)

-- Shared header: logo + two-tone wordmark + mono eyebrow.
local header = mk("Frame", {
	Size = UDim2.new(1, -32, 0, 38),
	Position = UDim2.new(0, 16, 0, 14),
	BackgroundTransparency = 1,
}, mainRoot)
local hasLogo = LOGO_IMAGE ~= ""
mk("ImageLabel", {
	Image = LOGO_IMAGE,
	Visible = hasLogo,
	Size = UDim2.new(0, 38, 0, 38),
	Position = UDim2.new(0, 0, 0.5, 0),
	AnchorPoint = Vector2.new(0, 0.5),
	BackgroundTransparency = 1,
	ScaleType = Enum.ScaleType.Fit,
}, header)
local titleX = hasLogo and 48 or 0
local titleCol = mk("Frame", {
	Size = UDim2.new(1, -titleX, 1, 0),
	Position = UDim2.new(0, titleX, 0, 0),
	BackgroundTransparency = 1,
}, header)
mk("UIListLayout", {
	Padding = UDim.new(0, 3),
	SortOrder = Enum.SortOrder.LayoutOrder,
	VerticalAlignment = Enum.VerticalAlignment.Center,
}, titleCol)
mk("TextLabel", {
	RichText = true,
	Text = 'Blox<font color="#8A8A8E">Tools</font>',
	Size = UDim2.new(1, 0, 0, 24),
	BackgroundTransparency = 1,
	TextColor3 = COLORS.ink,
	TextXAlignment = Enum.TextXAlignment.Left,
	FontFace = brandFont("display", Enum.Font.GothamBold, Enum.FontWeight.Bold),
	TextSize = 22,
}, titleCol)
mkEyebrow(titleCol, "Ship with confidence")

-- ── Tab bar: underline navigation ────────────────────────────────────────────
local tabBar = mk("Frame", {
	Size = UDim2.new(1, -32, 0, 24),
	Position = UDim2.new(0, 16, 0, 60),
	BackgroundTransparency = 1,
}, mainRoot)
mk("UIListLayout", {
	FillDirection = Enum.FillDirection.Horizontal,
	Padding = UDim.new(0, 22),
	SortOrder = Enum.SortOrder.LayoutOrder,
}, tabBar)
local function mkTab(text, order)
	-- Auto-width so the underline spans the label.
	local t = mk("TextButton", {
		Text = text,
		Size = UDim2.new(0, 0, 1, 0),
		AutomaticSize = Enum.AutomaticSize.X,
		BackgroundTransparency = 1,
		TextColor3 = COLORS.dim,
		TextXAlignment = Enum.TextXAlignment.Left,
		FontFace = brandFont("display", Enum.Font.GothamBold, Enum.FontWeight.Bold),
		TextSize = 15,
		AutoButtonColor = false,
		BorderSizePixel = 0,
		LayoutOrder = order,
	}, tabBar)
	local underline = mk("Frame", {
		Name = "Underline",
		Size = UDim2.new(1, 0, 0, 2), -- full width of the (text-hugging) tab
		Position = UDim2.new(0, 0, 1, 0),
		AnchorPoint = Vector2.new(0, 1),
		BackgroundColor3 = COLORS.ink, -- monochrome (white), not the blue accent
		BorderSizePixel = 0,
		Visible = false,
	}, t)
	corner(underline, 1)
	return t
end
local errorsTab = mkTab("Errors", 1)
local settingsTab = mkTab("Settings", 2)

-- Hairline separating the navigation from the panel below.
mk("Frame", {
	Size = UDim2.new(1, 0, 0, 1),
	Position = UDim2.new(0, 0, 0, 90),
	BackgroundColor3 = COLORS.stroke,
	BorderSizePixel = 0,
}, mainRoot)

-- ── Content views (one visible at a time) ─────────────────────────────────────
local contentArea = mk("Frame", {
	Size = UDim2.new(1, 0, 1, -98),
	Position = UDim2.new(0, 0, 0, 98),
	BackgroundTransparency = 1,
}, mainRoot)
local errorsView = mk("Frame", {
	Size = UDim2.new(1, 0, 1, 0),
	BackgroundTransparency = 1,
}, contentArea)
local settingsView = mk("Frame", {
	Size = UDim2.new(1, 0, 1, 0),
	BackgroundTransparency = 1,
}, contentArea)

local function selectTab(which)
	activeTab = which
	local onErrors = which == "errors"
	errorsView.Visible = onErrors
	settingsView.Visible = not onErrors
	errorsTab.TextColor3 = onErrors and COLORS.ink or COLORS.dim
	settingsTab.TextColor3 = onErrors and COLORS.dim or COLORS.ink
	errorsTab.Underline.Visible = onErrors
	settingsTab.Underline.Visible = not onErrors
	if onErrors and refreshInspector then
		if refreshPlanState then
			refreshPlanState()
		end
		refreshInspector()
	end
end
errorsTab.MouseButton1Click:Connect(function()
	selectTab("errors")
end)
settingsTab.MouseButton1Click:Connect(function()
	selectTab("settings")
end)
selectTab("settings") -- initial tab

-- Refresh the Errors panel whenever the widget is (re)opened on that tab.
mainWidget:GetPropertyChangedSignal("Enabled"):Connect(function()
	if mainWidget.Enabled and activeTab == "errors" and refreshInspector then
		if refreshPlanState then
			refreshPlanState()
		end
		refreshInspector()
	end
end)

-- ─────────────────────────────────────────────────────────────────────────────
-- Settings panel (the settingsView tab of the shared widget)
-- ─────────────────────────────────────────────────────────────────────────────

-- Scrollable content column.
local settingsScroll = mk("ScrollingFrame", {
	Size = UDim2.new(1, 0, 1, 0),
	BackgroundTransparency = 1,
	BorderSizePixel = 0,
	ScrollBarThickness = 6,
	ScrollBarImageColor3 = COLORS.strokeStrong,
	CanvasSize = UDim2.new(0, 0, 0, 0),
	AutomaticCanvasSize = Enum.AutomaticSize.Y,
}, settingsView)
mk("UIListLayout", { Padding = UDim.new(0, 14), SortOrder = Enum.SortOrder.LayoutOrder }, settingsScroll)
mk("UIPadding", {
	PaddingLeft = UDim.new(0, 16),
	PaddingRight = UDim.new(0, 16),
	PaddingTop = UDim.new(0, 4),
	PaddingBottom = UDim.new(0, 16),
}, settingsScroll)

local settingsStatus -- forward-declared; bottom status label

-- The persistent Pro+ upgrade copy (matches Inspector.PRO_GATE_MESSAGE).
local PRO_GATE_MESSAGE = "Studio plugin is a Pro+ feature — upgrade in the dashboard."

local function setSettingsStatus(text, color)
	settingsStatus.Text = text
	settingsStatus.TextColor3 = color or COLORS.dim
end

-- ── Connection ────────────────────────────────────────────────────────────────
local connSection = mkSection(settingsScroll, "Connection")
connSection.LayoutOrder = 1
mkFieldLabel(connSection, "Backend URL")
local urlBox = mkTextBox(connSection, "https://api.bloxtools.io")
urlBox.Text = settingsModel:backendUrl()

-- ── Credentials ───────────────────────────────────────────────────────────────
local credSection = mkSection(settingsScroll, "Credentials")
credSection.LayoutOrder = 2

mkFieldLabel(credSection, "Access token")

-- Pro+ gating banner — the token IS the gate (all PAT use is Pro+). Populated by
-- refreshPlanState() from GET /api/account/token-info; hidden until we know the
-- plan. Free → persistent upgrade prompt; Pro/Studio → stays hidden.
local proBanner = mkInfoLabel(credSection, "", COLORS.bad)
proBanner.FontFace = brandFont("bodyMedium", Enum.Font.GothamMedium, Enum.FontWeight.Medium)
proBanner.Visible = false

local existingPat = settingsModel:pat()
local patState = mkInfoLabel(
	credSection,
	existingPat and ("Saved · " .. SettingsModel.maskPat(existingPat)) or "No token saved",
	nil,
	true
)
local patBox = mkTextBox(credSection, "blxt_…")

mkFieldLabel(credSection, "Project key")
local _, _, storedFp = settingsModel:projectKey()
local keyState = mkInfoLabel(
	credSection,
	storedFp and ("Saved · fingerprint " .. storedFp) or "No key saved",
	nil,
	true
)
local keyBox = mkTextBox(credSection, "Paste to replace")

-- Primary action: persists Backend URL + token + project key together.
local saveButton = mkPrimaryButton(credSection, "Save settings", 0)
saveButton.Size = UDim2.new(1, 0, 0, 36)

-- ── Game ────────────────────────────────────────────────────────────────────────
local gameSection = mkSection(settingsScroll, nil) -- custom header row below
gameSection.LayoutOrder = 3

-- Header row: "GAME" eyebrow on the left, a subtle "Load games" action on the right.
local gameHeader = mk("Frame", {
	Size = UDim2.new(1, 0, 0, 18),
	BackgroundTransparency = 1,
	LayoutOrder = -100,
}, gameSection)
local gameEyebrow = mkEyebrow(gameHeader, "Games")
gameEyebrow.Size = UDim2.new(1, -80, 1, 0)
local loadGamesButton = mk("TextButton", {
	Text = "Load games",
	Size = UDim2.new(0, 0, 1, 0),
	AutomaticSize = Enum.AutomaticSize.X,
	Position = UDim2.new(1, 0, 0.5, 0),
	AnchorPoint = Vector2.new(1, 0.5),
	BackgroundTransparency = 1,
	TextColor3 = COLORS.text,
	FontFace = brandFont("bodyMedium", Enum.Font.GothamMedium, Enum.FontWeight.Medium),
	TextSize = 13,
	AutoButtonColor = false,
	BorderSizePixel = 0,
}, gameHeader)
mk("Frame", { -- white underline (link affordance)
	Size = UDim2.new(1, 0, 0, 1),
	Position = UDim2.new(0, 0, 1, -1),
	AnchorPoint = Vector2.new(0, 1),
	BackgroundColor3 = COLORS.ink,
	BorderSizePixel = 0,
}, loadGamesButton)
loadGamesButton.MouseEnter:Connect(function()
	loadGamesButton.TextColor3 = COLORS.ink
end)
loadGamesButton.MouseLeave:Connect(function()
	loadGamesButton.TextColor3 = COLORS.text
end)

local gameId, gameName = settingsModel:game()
local gameState = mkInfoLabel(gameSection, gameId and ("Selected · " .. tostring(gameName)) or "No game selected")
local gamesList = mk("Frame", {
	Size = UDim2.new(1, 0, 0, 0),
	AutomaticSize = Enum.AutomaticSize.Y,
	BackgroundTransparency = 1,
}, gameSection)
mk("UIListLayout", { Padding = UDim.new(0, 6), SortOrder = Enum.SortOrder.LayoutOrder }, gamesList)

-- ── Footer status line ───────────────────────────────────────────────────────
settingsStatus = mkInfoLabel(settingsScroll, "", nil, true)
settingsStatus.LayoutOrder = 4

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
		markFieldInvalid(urlBox)
		setSettingsStatus(urlOrMsg, COLORS.bad)
		return
	end
	urlBox.Text = urlOrMsg

	if patBox.Text ~= "" then
		local okPat, msg = settingsModel:setPat(patBox.Text)
		if not okPat then
			markFieldInvalid(patBox)
			setSettingsStatus(msg, COLORS.bad)
			return
		end
		patBox.Text = "" -- never leave the full token sitting in a TextBox
		patState.Text = "Saved · " .. SettingsModel.maskPat(settingsModel:pat())
	end

	if keyBox.Text ~= "" then
		local okKey, fpOrMsg = settingsModel:setProjectKey(keyBox.Text)
		if not okKey then
			markFieldInvalid(keyBox)
				setSettingsStatus(fpOrMsg, COLORS.bad)
			return
		end
		keyBox.Text = "" -- never leave the key sitting in a TextBox
		keyState.Text = "Saved · fingerprint " .. fpOrMsg
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
		local selectedGameId = settingsModel:game()
		local rows = {}
		-- List rows are flat rectangles (not pills) so they read as choices, not
		-- actions. The selected row gets a brighter fill, accent border + marker.
		local function paintRow(row, sel)
			local edge = row:FindFirstChildOfClass("UIStroke")
			row.BackgroundColor3 = sel and COLORS.rowHover or COLORS.surface
			if edge then
				edge.Color = sel and COLORS.ink or COLORS.stroke
				edge.Thickness = sel and 1.5 or 1
			end
			local nameLabel = row:FindFirstChild("Name")
			if nameLabel then
				nameLabel.TextColor3 = sel and COLORS.ink or COLORS.dim
			end
		end
		for i, g in games do
			local row = mk("TextButton", {
				Text = "",
				Size = UDim2.new(1, 0, 0, 30),
				BackgroundColor3 = COLORS.surface,
				AutoButtonColor = true,
				BorderSizePixel = 0,
				LayoutOrder = i,
			}, gamesList)
			corner(row, 8)
			stroke(row, COLORS.stroke, 1, 0)
			mk("TextLabel", {
				Name = "Name",
				Text = g.name,
				Size = UDim2.new(1, -24, 1, 0),
				Position = UDim2.new(0, 12, 0, 0),
				BackgroundTransparency = 1,
				TextColor3 = COLORS.dim,
				TextXAlignment = Enum.TextXAlignment.Left,
				TextTruncate = Enum.TextTruncate.AtEnd,
				FontFace = brandFont("body", Enum.Font.Gotham),
				TextSize = 14,
			}, row)
			rows[#rows + 1] = row
			paintRow(row, g.id == selectedGameId)
			row.MouseButton1Click:Connect(function()
				settingsModel:setGame(g.id, g.name)
				selectedGameId = g.id
				for _, rb in rows do
					paintRow(rb, false)
				end
				paintRow(row, true)
				gameState.Text = "Selected · " .. g.name
				setSettingsStatus("Now tracking " .. g.name .. ".", COLORS.good)
			end)
		end
		-- Show the count in the section heading rather than underneath.
		gameEyebrow.Text = (#games == 1) and "1 GAME" or (#games .. " GAMES")
		setSettingsStatus("Click a game to select.")
	end)
end)

-- ─────────────────────────────────────────────────────────────────────────────
-- Errors panel (the errorsView tab of the shared widget)
-- ─────────────────────────────────────────────────────────────────────────────

-- Action row (Upload / Refresh).
local topBar = mk("Frame", {
	Size = UDim2.new(1, -32, 0, 32),
	Position = UDim2.new(0, 16, 0, 6),
	BackgroundTransparency = 1,
}, errorsView)
mk("UIListLayout", {
	FillDirection = Enum.FillDirection.Horizontal,
	Padding = UDim.new(0, 8),
	VerticalAlignment = Enum.VerticalAlignment.Center,
	SortOrder = Enum.SortOrder.LayoutOrder,
}, topBar)

local uploadButton = mkPrimaryButton(topBar, "Upload source now", 158)
local refreshButton = mkButton(topBar, "Refresh", 84)

local inspectorStatus = mk("TextLabel", {
	Text = "Press Refresh to load open error groups.",
	Size = UDim2.new(1, -32, 0, 28),
	Position = UDim2.new(0, 16, 0, 46),
	BackgroundTransparency = 1,
	TextColor3 = COLORS.dim,
	TextXAlignment = Enum.TextXAlignment.Left,
	TextWrapped = true,
	FontFace = brandFont("body", Enum.Font.Gotham),
	TextSize = 13,
}, errorsView)

local listFrame = mkListFrame(errorsView)
listFrame.Position = UDim2.new(0, 8, 0, 82)
listFrame.Size = UDim2.new(1, -8, 1, -90)

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
		uploadButton.BackgroundColor3 = COLORS.surface -- muted: not an available action
		uploadButton.TextColor3 = COLORS.dim2
	else
		proBanner.Visible = false
		uploadButton.Text = "Upload source now"
		uploadButton.BackgroundColor3 = COLORS.white -- primary CTA restored
		uploadButton.TextColor3 = COLORS.bg
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
function refreshInspector()
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
				Size = UDim2.new(1, 0, 0, 48),
				BackgroundColor3 = COLORS.surface,
				BorderSizePixel = 0,
				AutoButtonColor = true,
				ClipsDescendants = true,
				LayoutOrder = i,
			}, listFrame)
			corner(row, 10)
			stroke(row, COLORS.stroke, 1, 0)
			-- Count badge on the left for quick scanning.
			local badge = mk("TextLabel", {
				Text = tostring(group.count) .. "×",
				Size = UDim2.new(0, 44, 0, 18),
				Position = UDim2.new(0, 10, 0, 8),
				BackgroundColor3 = COLORS.rowHover,
				TextColor3 = COLORS.text,
				FontFace = brandFont("mono", Enum.Font.RobotoMono),
				TextSize = 12,
				TextXAlignment = Enum.TextXAlignment.Center,
				TextTruncate = Enum.TextTruncate.AtEnd,
				BorderSizePixel = 0,
			}, row)
			corner(badge, 6)
			local msg = mkLabel(row, group.message, 18)
			msg.Position = UDim2.new(0, 62, 0, 6)
			msg.Size = UDim2.new(1, -70, 0, 18)
			msg.TextSize = 14
			local where = mkLabel(
				row,
				group.topPath and (tostring(group.topPath) .. (group.topFn and (" · " .. group.topFn) or "")) or "(no frame)",
				14,
				COLORS.dim
			)
			where.Position = UDim2.new(0, 62, 0, 26)
			where.Size = UDim2.new(1, -70, 0, 14)
			where.TextSize = 12
			row.MouseButton1Click:Connect(function()
				task.spawn(jumpToGroup, client, group)
			end)
		end
		setInspectorStatus(("%d open group(s). Click one to jump to the line."):format(#groups))
	end)
end

refreshButton.MouseButton1Click:Connect(refreshInspector)

-- Poll every 30s while the widget is open AND the Errors tab is active. The
-- refresh-on-open / refresh-on-tab-switch is wired in the shell (selectTab and
-- the widget Enabled signal). No polling while closed or on the Settings tab.
task.spawn(function()
	while pluginAlive do
		task.wait(30)
		if pluginAlive and mainWidget.Enabled and activeTab == "errors" then
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
	if placeVersion < 1 then
		-- game.PlaceVersion is 0 in an unpublished place / Studio playtest. A v0
		-- source upload is rejected by the backend (it must pin a real version),
		-- so stop here with a clear message instead of a confusing failure.
		setInspectorStatus("Place version is 0 — Publish to Roblox first, then upload.", COLORS.bad)
		return
	end

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
