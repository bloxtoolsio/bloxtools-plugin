--[[
	BloxTools Studio Plugin — Base64 (RFC 4648), pure Luau

	Used for: decoding the pasted project key (44-char, '='-padded base64 of
	32 random bytes) and encoding IVs + ciphertext for the JSON wire format.

	PORTABILITY CONTRACT: no Roblox globals — only `math`, `string`, `table`.
	Line-correspondent with tools/aes-gcm-mirror.mjs [MIRROR §3],
	which `npm test` verifies against Node's Buffer base64 on randomized
	inputs. Change both files together, or neither.

	API:
	  Base64.encode(bytes) -> string            (always '='-padded)
	  Base64.decode(s)     -> bytes or nil      (STRICT; nil on any deviation)
]]

local Base64 = {}

-- [MIRROR §3.1] Standard RFC 4648 alphabet with '=' padding (what the
-- dashboard's btoa/atob and the wire contract use).
local B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

-- [MIRROR §3.2] Encode a byte array to base64 (always padded).
function Base64.encode(bytes)
	local out = {}
	local n = #bytes
	for i = 0, n - 1, 3 do
		local b0 = bytes[i + 1]
		local b1 = 0
		if i + 1 < n then
			b1 = bytes[i + 2]
		end
		local b2 = 0
		if i + 2 < n then
			b2 = bytes[i + 3]
		end
		local triple = b0 * 65536 + b1 * 256 + b2
		out[#out + 1] = string.sub(B64_ALPHABET, math.floor(triple / 262144) % 64 + 1, math.floor(triple / 262144) % 64 + 1)
		out[#out + 1] = string.sub(B64_ALPHABET, math.floor(triple / 4096) % 64 + 1, math.floor(triple / 4096) % 64 + 1)
		if i + 1 < n then
			out[#out + 1] = string.sub(B64_ALPHABET, math.floor(triple / 64) % 64 + 1, math.floor(triple / 64) % 64 + 1)
		else
			out[#out + 1] = "="
		end
		if i + 2 < n then
			out[#out + 1] = string.sub(B64_ALPHABET, triple % 64 + 1, triple % 64 + 1)
		else
			out[#out + 1] = "="
		end
	end
	return table.concat(out)
end

-- [MIRROR §3.3] Decode base64 to a byte array. STRICT: length must be a
-- multiple of 4, only canonical alphabet characters, '=' only as 1–2 trailing
-- pad chars. Returns nil on any violation (the settings UI turns that into
-- a "not a valid key" message rather than guessing).
function Base64.decode(s)
	if type(s) ~= "string" or #s % 4 ~= 0 or #s == 0 then
		return nil
	end
	local pad = 0
	if string.sub(s, -2) == "==" then
		pad = 2
	elseif string.sub(s, -1) == "=" then
		pad = 1
	end
	local out = {}
	for i = 0, #s - 1, 4 do
		local triple = 0
		local chars = 4
		for j = 0, 3 do
			local ch = string.sub(s, i + j + 1, i + j + 1)
			if ch == "=" then
				-- '=' is only legal in the final group, only in the last 1–2 slots
				if i + 4 < #s or j < 4 - pad then
					return nil
				end
				chars = chars - 1
				triple = triple * 64
			else
				local v = string.find(B64_ALPHABET, ch, 1, true)
				if v == nil then
					return nil
				end
				triple = triple * 64 + (v - 1)
			end
		end
		out[#out + 1] = math.floor(triple / 65536) % 256
		if chars >= 3 then
			out[#out + 1] = math.floor(triple / 256) % 256
		end
		if chars >= 4 then
			out[#out + 1] = triple % 256
		end
	end
	return out
end

return Base64
