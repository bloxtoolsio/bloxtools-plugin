--[[
	BloxTools Studio Plugin — PathResolver

	Resolves an `instancePath` string (as produced by Instance:GetFullName(),
	e.g. "ServerScriptService.Combat.Hitreg") back to a live Instance under a
	given root (the DataModel in production; any instance in review).

	THE DOT-AMBIGUITY PROBLEM, handled honestly: GetFullName() joins ancestor
	NAMES with "." but instance names may themselves CONTAIN dots, so the
	string does not always split uniquely. We resolve with backtracking:
	at each level, try the LONGEST joined run of remaining segments first as
	one child name, then shorter runs. The first complete match wins. Paths
	recorded from a different place version (renamed/deleted scripts) resolve
	to nil — the dock shows a not-found state instead of guessing.
]]

local PathResolver = {}

local function split(path)
	local segments = {}
	for seg in string.gmatch(path, "[^%.]+") do
		segments[#segments + 1] = seg
	end
	return segments
end

local function resolveFrom(node, segments, i)
	if i > #segments then
		return node
	end
	-- Longest-first: a child literally named "A.B" must beat child "A" with
	-- grandchild "B" only when the latter doesn't complete; either way one
	-- full-path match is returned.
	for j = #segments, i, -1 do
		local name = table.concat(segments, ".", i, j)
		local child = node:FindFirstChild(name)
		if child then
			local hit = resolveFrom(child, segments, j + 1)
			if hit then
				return hit
			end
		end
	end
	return nil
end

--[[
	root: the instance whose CHILDREN are the first path segment — for paths
	from GetFullName() that is the DataModel (`game`), since full names start
	at the service ("ServerScriptService.…").
	Returns the Instance or nil.
]]
function PathResolver.resolve(root, instancePath)
	if type(instancePath) ~= "string" or instancePath == "" then
		return nil
	end
	local segments = split(instancePath)
	if #segments == 0 then
		return nil
	end
	return resolveFrom(root, segments, 1)
end

return PathResolver
