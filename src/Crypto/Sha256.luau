--[[
	BloxTools Studio Plugin — SHA-256, pure Luau

	Clean-room from FIPS-180-4. Used for exactly two things in this plugin:
	  1. the project-key FINGERPRINT (first 8 hex chars of sha256(raw key)),
	     shown in settings and sent on the wire so the dashboard can detect
	     a wrong key without ever seeing the key itself;
	  2. deriving per-artifact GCM IVs from a unique seed string (see
	     Uploader.deriveIv — GCM needs IV uniqueness, not secrecy).

	PORTABILITY CONTRACT: no Roblox globals — only `bit32`, `math`, `table`,
	`string`. Line-correspondent with tools/aes-gcm-mirror.mjs
	[MIRROR §2], which `npm test` verifies against node:crypto on known
	digests and randomized inputs. Change both files together, or neither.

	API:
	  Sha256.digest(bytes) -> 32-byte array     (bytes = table of ints 0-255)
	  Sha256.hex(bytes)    -> 64-char lowercase hex string
]]

local Sha256 = {}

-- [MIRROR §2.1] Round constants: fractional parts of the cube roots of the
-- first 64 primes (FIPS-180-4 §4.2.2). Fixed public constants.
local SHA256_K = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

-- [MIRROR §2.2] rotr: rotate a 32-bit word right by n (1 ≤ n ≤ 31).
-- (The mirror spells out the shift/or expression JS needs; bit32.rrotate is
-- its exact built-in equivalent.)
local function rotr(x, n)
	return bit32.rrotate(x, n)
end

-- [MIRROR §2.3] SHA-256 over a byte array (FIPS-180-4 §6.2). Returns the
-- 32-byte digest as a byte array. Streaming is unnecessary — inputs here are
-- script sources and small seed strings.
function Sha256.digest(bytes)
	local n = #bytes
	-- Initial hash values: fractional parts of the square roots of the first
	-- eight primes (FIPS-180-4 §5.3.3).
	local h0 = 0x6a09e667
	local h1 = 0xbb67ae85
	local h2 = 0x3c6ef372
	local h3 = 0xa54ff53a
	local h4 = 0x510e527f
	local h5 = 0x9b05688c
	local h6 = 0x1f83d9ab
	local h7 = 0x5be0cd19

	-- Padding (§5.1.1): append 0x80, then zeros until length ≡ 56 (mod 64),
	-- then the message length in BITS as a 64-bit big-endian integer.
	local padded = table.create(n + 72)
	for i = 1, n do
		padded[i] = bytes[i]
	end
	padded[#padded + 1] = 0x80
	while #padded % 64 ~= 56 do
		padded[#padded + 1] = 0x00
	end
	local bits = n * 8
	local hi = math.floor(bits / 4294967296)
	local lo = bits % 4294967296
	padded[#padded + 1] = bit32.band(bit32.rshift(hi, 24), 0xff)
	padded[#padded + 1] = bit32.band(bit32.rshift(hi, 16), 0xff)
	padded[#padded + 1] = bit32.band(bit32.rshift(hi, 8), 0xff)
	padded[#padded + 1] = bit32.band(hi, 0xff)
	padded[#padded + 1] = bit32.band(bit32.rshift(lo, 24), 0xff)
	padded[#padded + 1] = bit32.band(bit32.rshift(lo, 16), 0xff)
	padded[#padded + 1] = bit32.band(bit32.rshift(lo, 8), 0xff)
	padded[#padded + 1] = bit32.band(lo, 0xff)

	local w = table.create(64)
	for off = 0, #padded - 1, 64 do
		-- Message schedule (§6.2.2 step 1)
		for t = 0, 15 do
			local i = off + t * 4
			w[t + 1] = bit32.bor(
				bit32.lshift(padded[i + 1], 24),
				bit32.lshift(padded[i + 2], 16),
				bit32.lshift(padded[i + 3], 8),
				padded[i + 4]
			)
		end
		for t = 16, 63 do
			local s0 = bit32.bxor(rotr(w[t - 14], 7), rotr(w[t - 14], 18), bit32.rshift(w[t - 14], 3))
			local s1 = bit32.bxor(rotr(w[t - 1], 17), rotr(w[t - 1], 19), bit32.rshift(w[t - 1], 10))
			w[t + 1] = (w[t - 15] + s0 + w[t - 6] + s1) % 4294967296
		end
		-- Compression (§6.2.2 steps 2–4). Additions are mod 2^32; intermediate
		-- sums stay exact (well under 2^53) before reduction.
		local a = h0
		local b = h1
		local c = h2
		local d = h3
		local e = h4
		local f = h5
		local g = h6
		local h = h7
		for t = 0, 63 do
			local S1 = bit32.bxor(rotr(e, 6), rotr(e, 11), rotr(e, 25))
			local ch = bit32.bxor(bit32.band(e, f), bit32.band(bit32.bnot(e), g))
			local temp1 = (h + S1 + ch + SHA256_K[t + 1] + w[t + 1]) % 4294967296
			local S0 = bit32.bxor(rotr(a, 2), rotr(a, 13), rotr(a, 22))
			local maj = bit32.bxor(bit32.band(a, b), bit32.band(a, c), bit32.band(b, c))
			local temp2 = (S0 + maj) % 4294967296
			h = g
			g = f
			f = e
			e = (d + temp1) % 4294967296
			d = c
			c = b
			b = a
			a = (temp1 + temp2) % 4294967296
		end
		h0 = (h0 + a) % 4294967296
		h1 = (h1 + b) % 4294967296
		h2 = (h2 + c) % 4294967296
		h3 = (h3 + d) % 4294967296
		h4 = (h4 + e) % 4294967296
		h5 = (h5 + f) % 4294967296
		h6 = (h6 + g) % 4294967296
		h7 = (h7 + h) % 4294967296
	end

	local out = table.create(32)
	for _, word in { h0, h1, h2, h3, h4, h5, h6, h7 } do
		out[#out + 1] = bit32.band(bit32.rshift(word, 24), 0xff)
		out[#out + 1] = bit32.band(bit32.rshift(word, 16), 0xff)
		out[#out + 1] = bit32.band(bit32.rshift(word, 8), 0xff)
		out[#out + 1] = bit32.band(word, 0xff)
	end
	return out
end

-- [MIRROR §2.4] Hex form of the digest (lowercase), used for the key
-- fingerprint shown in the settings UI and sent on the wire.
function Sha256.hex(bytes)
	local d = Sha256.digest(bytes)
	local parts = table.create(32)
	for i = 1, 32 do
		parts[i] = string.format("%02x", d[i])
	end
	return table.concat(parts)
end

return Sha256
