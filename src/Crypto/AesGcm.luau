--[[
	BloxTools Studio Plugin — AES-256-GCM (encrypt-only), pure Luau

	WHY THIS EXISTS: Roblox Studio plugins have no crypto API, so the cipher
	is vendored here, clean-room, from the public specifications:
	FIPS-197 (AES) and NIST SP 800-38D (GCM). Correctness over speed —
	publish-time encryption of a few hundred scripts is the only workload
	(~tens of ms per script is fine; publishing is rare).

	PORTABILITY CONTRACT: this module uses NO Roblox globals — only `bit32`,
	`math`, `table`, `string` and plain Lua. That keeps it line-correspondent
	with its executable Node mirror, tools/aes-gcm-mirror.mjs
	[MIRROR §1], which the repo's test suite verifies byte-for-byte against
	WebCrypto (node:crypto) on NIST CAVP vectors and randomized inputs.
	If you change ANYTHING here, make the same change in the mirror and run
	`npm test` — the two files must stay in lock-step, same functions, same
	order, same constants, same comments. The only systematic differences:
	Luau tables are 1-based (JS arrays are 0-based) and `bit32.*` replaces
	JS bitwise operators.

	ENCRYPT-ONLY BY DESIGN: the plugin encrypts script source and uploads it;
	it never decrypts anything (decryption happens in the customer's browser,
	WebCrypto, with the customer-held key). So no decrypt path ships at all —
	smaller audit surface, nothing to misuse.

	API:  AesGcm.encrypt(keyBytes, ivBytes, plaintextBytes) -> bytes
	  keyBytes       table of 32 ints 0-255 (the raw project key)
	  ivBytes        table of 12 ints 0-255 (96-bit IV; see Uploader.deriveIv
	                 for how IVs are derived — uniqueness, not secrecy)
	  plaintextBytes table of ints 0-255, any length (the script source)
	  returns        table of (#plaintext + 16) ints: ciphertext with the
	                 16-byte GCM tag APPENDED — WebCrypto-native layout, so
	                 the dashboard calls subtle.decrypt on it directly.

	NO require-time side effects: everything below is table/function literals.
]]

local AesGcm = {}

-- [MIRROR §1.1] The AES S-box (FIPS-197 §5.1.1, Fig. 7). A fixed public
-- constant — written as a literal so nothing is computed at load time.
local SBOX = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

-- [MIRROR §1.2] Round constants for key expansion (FIPS-197 §5.2). AES-256
-- consumes Rcon[1..7] (60 words / Nk=8 → i/Nk runs 1..7); never overflows GF.
local RCON = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40 }

-- [MIRROR §1.3] xtime: multiply by x (i.e. ·2) in GF(2^8) modulo the AES
-- polynomial x^8 + x^4 + x^3 + x + 1 (0x11b). Building block for MixColumns;
-- ·3 is computed inline as xtime(a) ^ a.
local function xtime(b)
	b = bit32.lshift(b, 1)
	if bit32.band(b, 0x100) ~= 0 then
		b = bit32.bxor(b, 0x11b)
	end
	return bit32.band(b, 0xff)
end

-- [MIRROR §1.4] AES-256 key expansion (FIPS-197 §5.2). Takes the 32-byte key,
-- returns the flat 240-byte round-key schedule (15 round keys of 16 bytes).
-- Word w (0-based 8..59) lives at byte offset 4w. For Nk = 8:
--   w % 8 == 0 → temp = SubWord(RotWord(prev)) ^ Rcon[w/8]
--   w % 8 == 4 → temp = SubWord(prev)           (the AES-256-only extra step)
--   otherwise  → temp = prev
--   word[w] = word[w - 8] ^ temp
local function expandKey(key)
	if #key ~= 32 then
		error("AesGcm: key must be exactly 32 bytes (AES-256)")
	end
	local rk = table.create(240)
	for i = 1, 32 do
		rk[i] = key[i] -- round keys 0..1 are the key itself (words 0..7)
	end
	for w = 8, 59 do
		local p = w * 4 + 1 -- byte offset (1-based) of the word being produced
		local t0 = rk[p - 4]
		local t1 = rk[p - 3]
		local t2 = rk[p - 2]
		local t3 = rk[p - 1]
		if w % 8 == 0 then
			-- RotWord (rotate left one byte) then SubWord, then Rcon into byte 0.
			local r = t0
			t0 = bit32.bxor(SBOX[t1 + 1], RCON[w / 8])
			t1 = SBOX[t2 + 1]
			t2 = SBOX[t3 + 1]
			t3 = SBOX[r + 1]
		elseif w % 8 == 4 then
			-- SubWord only — the extra substitution AES-256 adds mid-stride.
			t0 = SBOX[t0 + 1]
			t1 = SBOX[t1 + 1]
			t2 = SBOX[t2 + 1]
			t3 = SBOX[t3 + 1]
		end
		local b = p - 32 -- the word Nk (= 8 words = 32 bytes) earlier
		rk[p] = bit32.bxor(rk[b], t0)
		rk[p + 1] = bit32.bxor(rk[b + 1], t1)
		rk[p + 2] = bit32.bxor(rk[b + 2], t2)
		rk[p + 3] = bit32.bxor(rk[b + 3], t3)
	end
	return rk
end

-- [MIRROR §1.5] Encrypt one 16-byte block (FIPS-197 §5.1). State is kept as a
-- flat 16-byte array in COLUMN-MAJOR order: state[row][col] = s[4*col + row]
-- (exactly how blocks arrive off the wire, so no transposition is needed).
-- 14 rounds for AES-256; MixColumns is skipped in the last round per spec.
local function encryptBlock(rk, input)
	local s = table.create(16)
	for i = 1, 16 do
		s[i] = bit32.bxor(input[i], rk[i]) -- initial AddRoundKey (round key 0)
	end
	for round = 1, 14 do
		-- SubBytes: byte-wise S-box substitution.
		for i = 1, 16 do
			s[i] = SBOX[s[i] + 1]
		end
		-- ShiftRows: row r (flat indices r, r+4, r+8, r+12 zero-based) rotates
		-- LEFT by r. Written as explicit swaps so both implementations are
		-- identical (indices here are the 1-based equivalents of the mirror's).
		local t = s[2]
		s[2] = s[6]
		s[6] = s[10]
		s[10] = s[14]
		s[14] = t -- row 1: left by 1
		t = s[3]
		s[3] = s[11]
		s[11] = t
		t = s[7]
		s[7] = s[15]
		s[15] = t -- row 2: left by 2 (two swaps)
		t = s[16]
		s[16] = s[12]
		s[12] = s[8]
		s[8] = s[4]
		s[4] = t -- row 3: left by 3 == right by 1
		-- MixColumns (FIPS-197 §5.1.3): per column [a0..a3],
		--   b0 = 2·a0 ^ 3·a1 ^ a2 ^ a3   (and rotations thereof), in GF(2^8).
		if round < 14 then
			for c = 1, 13, 4 do
				local a0 = s[c]
				local a1 = s[c + 1]
				local a2 = s[c + 2]
				local a3 = s[c + 3]
				s[c] = bit32.bxor(xtime(a0), bit32.bxor(xtime(a1), a1), a2, a3)
				s[c + 1] = bit32.bxor(a0, xtime(a1), bit32.bxor(xtime(a2), a2), a3)
				s[c + 2] = bit32.bxor(a0, a1, xtime(a2), bit32.bxor(xtime(a3), a3))
				s[c + 3] = bit32.bxor(bit32.bxor(xtime(a0), a0), a1, a2, xtime(a3))
			end
		end
		-- AddRoundKey with this round's 16 bytes of schedule.
		local o = round * 16
		for i = 1, 16 do
			s[i] = bit32.bxor(s[i], rk[o + i])
		end
	end
	return s
end

-- [MIRROR §1.6] GF(2^128) multiplication for GHASH (SP 800-38D §6.3,
-- Algorithm 1 — the bitwise right-shift method; no precomputed tables, ~128
-- iterations per block: slow and simple, which is the point).
-- A 128-bit element is four big-endian 32-bit words [w0,w1,w2,w3]; w0 holds
-- the polynomial's most significant bits, and bit 0 (MSB of w0) is the
-- coefficient of x^0 per GCM's reflected bit convention.
local function gf128Mul(x, y)
	local z0 = 0
	local z1 = 0
	local z2 = 0
	local z3 = 0
	local v0 = y[1]
	local v1 = y[2]
	local v2 = y[3]
	local v3 = y[4]
	for i = 0, 127 do
		-- bit i of x, MSB-first across the four words
		local xb = bit32.band(bit32.rshift(x[math.floor(i / 32) + 1], 31 - (i % 32)), 1)
		if xb ~= 0 then
			z0 = bit32.bxor(z0, v0)
			z1 = bit32.bxor(z1, v1)
			z2 = bit32.bxor(z2, v2)
			z3 = bit32.bxor(z3, v3)
		end
		local lsb = bit32.band(v3, 1)
		-- V = V >> 1 across word boundaries (carry each word's LSB rightward)
		v3 = bit32.bor(bit32.rshift(v3, 1), bit32.lshift(v2, 31))
		v2 = bit32.bor(bit32.rshift(v2, 1), bit32.lshift(v1, 31))
		v1 = bit32.bor(bit32.rshift(v1, 1), bit32.lshift(v0, 31))
		v0 = bit32.rshift(v0, 1)
		if lsb ~= 0 then
			-- Reduce by R = 11100001 || 0^120 (x^128 ≡ x^7 + x^2 + x + 1)
			v0 = bit32.bxor(v0, 0xe1000000)
		end
	end
	return { z0, z1, z2, z3 }
end

-- [MIRROR §1.7] Read a 16-byte block (zero-padded past `len`) as four
-- big-endian 32-bit words, starting at 0-based byte offset `off`.
local function blockToWords(bytes, off, len)
	local w = { 0, 0, 0, 0 }
	for i = 0, 15 do
		local idx = off + i
		local b = 0
		if idx < len then
			b = bytes[idx + 1]
		end
		local wi = math.floor(i / 4) + 1
		w[wi] = bit32.bor(bit32.lshift(w[wi], 8), b)
	end
	return w
end

-- [MIRROR §1.8] GHASH absorb: Y = (Y ⊕ block) · H  (SP 800-38D §6.4).
local function ghashBlock(y, blockWords, h)
	return gf128Mul({
		bit32.bxor(y[1], blockWords[1]),
		bit32.bxor(y[2], blockWords[2]),
		bit32.bxor(y[3], blockWords[3]),
		bit32.bxor(y[4], blockWords[4]),
	}, h)
end

-- [MIRROR §1.9] AES-256-GCM encrypt (SP 800-38D §7.1), specialized to this
-- plugin's pinned envelope:
--   - 96-bit (12-byte) IV only — so J0 = IV || 0x00000001, no GHASH of the IV
--   - AAD is always empty (integrity comes from the GCM tag alone)
--   - output is ciphertext with the 16-byte tag APPENDED — the exact layout
--     WebCrypto's subtle.encrypt produces / subtle.decrypt consumes, so the
--     dashboard decrypts the wire bytes with zero re-framing.
-- Returns a fresh byte array of length #plaintext + 16. Encrypt-only by
-- design: the plugin never decrypts anything, so no decrypt path is shipped.
function AesGcm.encrypt(key, iv, plaintext)
	if #iv ~= 12 then
		error("AesGcm: iv must be exactly 12 bytes (96-bit GCM IV)")
	end
	local rk = expandKey(key) -- also validates key length
	local n = #plaintext

	-- H = E_K(0^128): the GHASH subkey (SP 800-38D §6.4, step 1)
	local zero = table.create(16, 0)
	local h = blockToWords(encryptBlock(rk, zero), 0, 16)

	-- J0 = IV || 0x00000001 (96-bit IV fast path, §7.1 step 2)
	local j0 = table.create(16)
	for i = 1, 12 do
		j0[i] = iv[i]
	end
	j0[13] = 0x00
	j0[14] = 0x00
	j0[15] = 0x00
	j0[16] = 0x01

	-- CTR-mode encryption with counters inc32(J0), inc32²(J0), … (§6.5).
	-- inc32 wraps only the last 32 bits of the counter block.
	local out = table.create(n + 16)
	local ctr = table.clone(j0)
	for off = 0, n - 1, 16 do
		-- inc32(ctr): big-endian increment of the last 4 bytes, carry stops there
		for i = 16, 13, -1 do
			ctr[i] = bit32.band(ctr[i] + 1, 0xff)
			if ctr[i] ~= 0 then
				break
			end
		end
		local ks = encryptBlock(rk, ctr)
		local blockLen = math.min(16, n - off)
		for i = 0, blockLen - 1 do
			out[off + i + 1] = bit32.bxor(plaintext[off + i + 1], ks[i + 1])
		end
	end

	-- S = GHASH_H(C ∥ pad ∥ len64(AAD)=0 ∥ len64(C))  — AAD empty by contract
	local y = { 0, 0, 0, 0 }
	for off = 0, n - 1, 16 do
		y = ghashBlock(y, blockToWords(out, off, n), h)
	end
	local bits = n * 8 -- exact in doubles for any plausible script size
	local lenBlock = { 0, 0, math.floor(bits / 4294967296), bits % 4294967296 }
	y = ghashBlock(y, lenBlock, h)

	-- T = E_K(J0) ⊕ S, appended after the ciphertext (WebCrypto layout)
	local ekj0 = encryptBlock(rk, j0)
	for i = 0, 3 do
		local w = y[i + 1]
		out[n + i * 4 + 1] = bit32.band(bit32.bxor(ekj0[i * 4 + 1], bit32.rshift(w, 24)), 0xff)
		out[n + i * 4 + 2] = bit32.band(bit32.bxor(ekj0[i * 4 + 2], bit32.rshift(w, 16)), 0xff)
		out[n + i * 4 + 3] = bit32.band(bit32.bxor(ekj0[i * 4 + 3], bit32.rshift(w, 8)), 0xff)
		out[n + i * 4 + 4] = bit32.band(bit32.bxor(ekj0[i * 4 + 4], w), 0xff)
	end
	return out
end

return AesGcm
