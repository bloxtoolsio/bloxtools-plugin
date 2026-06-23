--[[
	BloxTools Studio Plugin — Luau-side vector harness

	Runs the ACTUAL Luau crypto (src/Crypto/*.luau — the very files
	rojo packs into the plugin) against the NIST CAVP vectors, plus
	SHA-256/base64 known answers.

	This closes the central gap in the proof chain: the Node test suite
	proves the line-correspondent MIRROR equals WebCrypto; this harness
	proves the LUAU TEXT ITSELF produces the NIST-expected bytes, using the
	open-source Luau CLI (https://github.com/luau-lang/luau) — no Roblox
	required, because Crypto/ uses no Roblox globals (the portability
	contract). `npm test` executes this automatically when a `luau` binary
	is found (test/plugin-crypto-luau.test.js), and skips otherwise.

	Run standalone from anywhere:
	  luau tools/luau-vectors.luau

	Vectors come from ./vectors.luau — GENERATED from
	test/plugin-crypto.vectors.json (the Luau CLI has no file I/O, so the
	JSON is re-expressed as a module; `npm test` asserts the two stay in
	sync). Errors (nonzero exit) on any mismatch; prints PASS lines
	otherwise.
]]

local AesGcm = require("../src/Crypto/AesGcm")
local Sha256 = require("../src/Crypto/Sha256")
local Base64 = require("../src/Crypto/Base64")
local vectors = require("./vectors")

local function hexToBytes(hex)
	local out = {}
	for byteHex in hex:gmatch("%x%x") do
		out[#out + 1] = tonumber(byteHex, 16)
	end
	return out
end

local function bytesToHex(bytes)
	local parts = {}
	for i, b in bytes do
		parts[i] = string.format("%02x", b)
	end
	return table.concat(parts)
end

local function stringToBytes(s)
	local out = {}
	for i = 1, #s do
		out[i] = string.byte(s, i)
	end
	return out
end

assert(#vectors >= 12, "expected a meaningful vector set, got " .. #vectors)

-- ── 1. AES-256-GCM: Luau encrypt vs NIST expectations ────────────────────────

for _, v in vectors do
	assert(v.aad == "", v.name .. ": AAD must be empty (pinned envelope)")
	local got = bytesToHex(AesGcm.encrypt(hexToBytes(v.key), hexToBytes(v.iv), hexToBytes(v.plaintext)))
	local want = v.ct .. v.tag
	if got ~= want then
		error(("FAIL %s\n  want %s\n  got  %s"):format(v.name, want, got))
	end
	print("PASS AesGcm.luau === NIST: " .. v.name)
end

-- ── 2. SHA-256 known answers (FIPS-180-4) ────────────────────────────────────

local shaCases = {
	{ "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
	{ "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
	{
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
	},
	{ string.rep("a", 1000), "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3" },
}
for _, case in shaCases do
	local got = Sha256.hex(stringToBytes(case[1]))
	assert(got == case[2], "FAIL sha256(" .. #case[1] .. " bytes): got " .. got)
end
print("PASS Sha256.luau === FIPS-180-4 known answers (4 cases)")

-- ── 3. Base64 round-trips + strict-decode rejections ─────────────────────────

for _, len in { 0, 1, 2, 3, 31, 32, 33, 100 } do
	local bytes = {}
	for i = 1, len do
		bytes[i] = (i * 37 + len) % 256
	end
	local decoded = Base64.decode(Base64.encode(bytes))
	assert(len == 0 or decoded ~= nil, "decode returned nil at len=" .. len)
	assert(bytesToHex(decoded or {}) == bytesToHex(bytes), "FAIL base64 round-trip len=" .. len)
end
for _, bad in { "abc", "ab=c", "a===", "====", "ab!d", "AAAA=AAA", "AA==AA==" } do
	assert(Base64.decode(bad) == nil, "FAIL strict decode accepted " .. bad)
end
print("PASS Base64.luau round-trips + strict rejections")

-- ── 4. The pinned compositions, in Luau ──────────────────────────────────────

-- keyFingerprint = first 8 hex of sha256(raw key bytes): 8 lowercase hex chars.
local key = hexToBytes(vectors[1].key)
local fp = string.sub(Sha256.hex(key), 1, 8)
assert(#fp == 8 and fp:match("^%x+$"), "fingerprint shape")
-- ivFromSeed = first 12 bytes of sha256(seed string bytes).
local seed = stringToBytes("keyB64" .. "ServerScriptService.Combat" .. "43" .. "12.345" .. "{guid}")
local digest = Sha256.digest(seed)
assert(#digest == 32, "sha256 digest is 32 bytes")
print("PASS composition shapes (fingerprint slice, 12-byte IV slice)")

print(("\nALL LUAU-SIDE CHECKS PASSED (%d NIST vectors + SHA-256 + base64)"):format(#vectors))
