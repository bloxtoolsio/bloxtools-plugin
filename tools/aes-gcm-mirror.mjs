/*
  BloxTools Studio Plugin — crypto mirror (Node, dependency-free)

  THIS FILE IS A LINE-CORRESPONDENT MIRROR of the plugin's pure-Luau crypto:

    [MIRROR §1]  src/Crypto/AesGcm.luau   — AES-256 block cipher + GCM
    [MIRROR §2]  src/Crypto/Sha256.luau   — SHA-256
    [MIRROR §3]  src/Crypto/Base64.luau   — base64 encode/decode
    [MIRROR §4]  compositions (key fingerprint, IV-from-seed) that correspond
                 to call sites in Settings.luau / Uploader.luau

  Why a mirror exists: Roblox Studio plugins have no crypto API, so the cipher
  is vendored in pure Luau — but this repo has no Luau runtime to test it.
  This file keeps the SAME functions, in the SAME order, with the SAME
  constants, structure and comments as the Luau, and node:crypto's WebCrypto
  is the judge: test/plugin-crypto-roundtrip.test.js asserts this mirror's
  output equals `subtle.encrypt` byte-for-byte on NIST CAVP vectors
  (test/plugin-crypto.vectors.json) plus randomized inputs. The Luau side is
  additionally executed directly against the same vectors under the
  open-source Luau CLI when one is available (tools/luau-vectors.luau
  via test/plugin-crypto-luau.test.js), then validated by
  line-correspondence review and the live Studio gate.

  Systematic, intentional differences from the Luau (and nothing else):
    - JS arrays are 0-based; Luau tables are 1-based. Loop bounds and index
      arithmetic differ by exactly that offset.
    - `bit32.band/bxor/lshift/rshift/rrotate` become `& ^ << >>>` with a
      trailing `>>> 0` to normalize to unsigned 32-bit (matching bit32).
    - `local function` becomes `function`; `--` comments become `//`.
  All hex constants appear in identical order in both files; the test suite
  extracts and diffs the literal streams to catch transcription typos.

  Clean-room sources: FIPS-197 (AES), NIST SP 800-38D (GCM), FIPS-180-4
  (SHA-256), RFC 4648 (base64). Correctness over speed: publish-time
  encryption of a few hundred scripts is the only workload.
*/

// ─────────────────────────────────────────────────────────────────────────────
// [MIRROR §1] AesGcm — mirrors src/Crypto/AesGcm.luau
// ─────────────────────────────────────────────────────────────────────────────

// [MIRROR §1.1] The AES S-box (FIPS-197 §5.1.1, Fig. 7). A fixed public
// constant — written as a literal so nothing is computed at load time.
const SBOX = [
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
];

// [MIRROR §1.2] Round constants for key expansion (FIPS-197 §5.2). AES-256
// consumes Rcon[1..7] (60 words / Nk=8 → i/Nk runs 1..7); never overflows GF.
const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

// [MIRROR §1.3] xtime: multiply by x (i.e. ·2) in GF(2^8) modulo the AES
// polynomial x^8 + x^4 + x^3 + x + 1 (0x11b). Building block for MixColumns;
// ·3 is computed inline as xtime(a) ^ a.
function xtime(b) {
  b = (b << 1) >>> 0;
  if ((b & 0x100) !== 0) {
    b = (b ^ 0x11b) >>> 0;
  }
  return (b & 0xff) >>> 0;
}

// [MIRROR §1.4] AES-256 key expansion (FIPS-197 §5.2). Takes the 32-byte key,
// returns the flat 240-byte round-key schedule (15 round keys of 16 bytes).
// Word w (0-based 8..59) lives at byte offset 4w. For Nk = 8:
//   w % 8 == 0 → temp = SubWord(RotWord(prev)) ^ Rcon[w/8]
//   w % 8 == 4 → temp = SubWord(prev)           (the AES-256-only extra step)
//   otherwise  → temp = prev
//   word[w] = word[w - 8] ^ temp
function expandKey(key) {
  if (key.length !== 32) {
    throw new Error("AesGcm: key must be exactly 32 bytes (AES-256)");
  }
  const rk = key.slice(); // round keys 0..1 are the key itself (words 0..7)
  for (let w = 8; w <= 59; w++) {
    const p = w * 4; // byte offset (0-based) of the word being produced
    let t0 = rk[p - 4];
    let t1 = rk[p - 3];
    let t2 = rk[p - 2];
    let t3 = rk[p - 1];
    if (w % 8 === 0) {
      // RotWord (rotate left one byte) then SubWord, then Rcon into byte 0.
      const r = t0;
      t0 = (SBOX[t1] ^ RCON[w / 8 - 1]) >>> 0;
      t1 = SBOX[t2];
      t2 = SBOX[t3];
      t3 = SBOX[r];
    } else if (w % 8 === 4) {
      // SubWord only — the extra substitution AES-256 adds mid-stride.
      t0 = SBOX[t0];
      t1 = SBOX[t1];
      t2 = SBOX[t2];
      t3 = SBOX[t3];
    }
    const b = p - 32; // the word Nk (= 8 words = 32 bytes) earlier
    rk[p] = (rk[b] ^ t0) >>> 0;
    rk[p + 1] = (rk[b + 1] ^ t1) >>> 0;
    rk[p + 2] = (rk[b + 2] ^ t2) >>> 0;
    rk[p + 3] = (rk[b + 3] ^ t3) >>> 0;
  }
  return rk;
}

// [MIRROR §1.5] Encrypt one 16-byte block (FIPS-197 §5.1). State is kept as a
// flat 16-byte array in COLUMN-MAJOR order: state[row][col] = s[4*col + row]
// (exactly how blocks arrive off the wire, so no transposition is needed).
// 14 rounds for AES-256; MixColumns is skipped in the last round per spec.
function encryptBlock(rk, input) {
  const s = new Array(16);
  for (let i = 0; i <= 15; i++) {
    s[i] = (input[i] ^ rk[i]) >>> 0; // initial AddRoundKey (round key 0)
  }
  for (let round = 1; round <= 14; round++) {
    // SubBytes: byte-wise S-box substitution.
    for (let i = 0; i <= 15; i++) {
      s[i] = SBOX[s[i]];
    }
    // ShiftRows: row r (flat indices r, r+4, r+8, r+12) rotates LEFT by r.
    // Written as explicit swaps so both implementations are identical.
    let t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t; // row 1: left by 1
    t = s[2];
    s[2] = s[10];
    s[10] = t;
    t = s[6];
    s[6] = s[14];
    s[14] = t; // row 2: left by 2 (two swaps)
    t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t; // row 3: left by 3 == right by 1
    // MixColumns (FIPS-197 §5.1.3): per column [a0..a3],
    //   b0 = 2·a0 ^ 3·a1 ^ a2 ^ a3   (and rotations thereof), in GF(2^8).
    if (round < 14) {
      for (let c = 0; c <= 12; c += 4) {
        const a0 = s[c];
        const a1 = s[c + 1];
        const a2 = s[c + 2];
        const a3 = s[c + 3];
        s[c] = (xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3) >>> 0;
        s[c + 1] = (a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3) >>> 0;
        s[c + 2] = (a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)) >>> 0;
        s[c + 3] = ((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3)) >>> 0;
      }
    }
    // AddRoundKey with this round's 16 bytes of schedule.
    const o = round * 16;
    for (let i = 0; i <= 15; i++) {
      s[i] = (s[i] ^ rk[o + i]) >>> 0;
    }
  }
  return s;
}

// [MIRROR §1.6] GF(2^128) multiplication for GHASH (SP 800-38D §6.3,
// Algorithm 1 — the bitwise right-shift method; no precomputed tables, ~128
// iterations per block: slow and simple, which is the point).
// A 128-bit element is four big-endian 32-bit words [w0,w1,w2,w3]; w0 holds
// the polynomial's most significant bits, and bit 0 (MSB of w0) is the
// coefficient of x^0 per GCM's reflected bit convention.
function gf128Mul(x, y) {
  let z0 = 0;
  let z1 = 0;
  let z2 = 0;
  let z3 = 0;
  let v0 = y[0];
  let v1 = y[1];
  let v2 = y[2];
  let v3 = y[3];
  for (let i = 0; i <= 127; i++) {
    // bit i of x, MSB-first across the four words
    const xb = ((x[Math.floor(i / 32)] >>> (31 - (i % 32))) & 1) >>> 0;
    if (xb !== 0) {
      z0 = (z0 ^ v0) >>> 0;
      z1 = (z1 ^ v1) >>> 0;
      z2 = (z2 ^ v2) >>> 0;
      z3 = (z3 ^ v3) >>> 0;
    }
    const lsb = (v3 & 1) >>> 0;
    // V = V >> 1 across word boundaries (carry each word's LSB rightward)
    v3 = ((v3 >>> 1) | ((v2 << 31) >>> 0)) >>> 0;
    v2 = ((v2 >>> 1) | ((v1 << 31) >>> 0)) >>> 0;
    v1 = ((v1 >>> 1) | ((v0 << 31) >>> 0)) >>> 0;
    v0 = (v0 >>> 1) >>> 0;
    if (lsb !== 0) {
      // Reduce by R = 11100001 || 0^120 (x^128 ≡ x^7 + x^2 + x + 1)
      v0 = (v0 ^ 0xe1000000) >>> 0;
    }
  }
  return [z0, z1, z2, z3];
}

// [MIRROR §1.7] Read a 16-byte block (zero-padded past `len`) as four
// big-endian 32-bit words, starting at 0-based byte offset `off`.
function blockToWords(bytes, off, len) {
  const w = [0, 0, 0, 0];
  for (let i = 0; i <= 15; i++) {
    const idx = off + i;
    const b = idx < len ? bytes[idx] : 0;
    const wi = Math.floor(i / 4);
    w[wi] = ((w[wi] << 8) | b) >>> 0;
  }
  return w;
}

// [MIRROR §1.8] GHASH absorb: Y = (Y ⊕ block) · H  (SP 800-38D §6.4).
function ghashBlock(y, blockWords, h) {
  return gf128Mul(
    [(y[0] ^ blockWords[0]) >>> 0, (y[1] ^ blockWords[1]) >>> 0, (y[2] ^ blockWords[2]) >>> 0, (y[3] ^ blockWords[3]) >>> 0],
    h
  );
}

// [MIRROR §1.9] AES-256-GCM encrypt (SP 800-38D §7.1), specialized to this
// plugin's pinned envelope:
//   - 96-bit (12-byte) IV only — so J0 = IV || 0x00000001, no GHASH of the IV
//   - AAD is always empty (integrity comes from the GCM tag alone)
//   - output is ciphertext with the 16-byte tag APPENDED — the exact layout
//     WebCrypto's subtle.encrypt produces / subtle.decrypt consumes, so the
//     dashboard decrypts the wire bytes with zero re-framing.
// Returns a fresh byte array of length #plaintext + 16. Encrypt-only by
// design: the plugin never decrypts anything, so no decrypt path is shipped.
function encrypt(key, iv, plaintext) {
  if (iv.length !== 12) {
    throw new Error("AesGcm: iv must be exactly 12 bytes (96-bit GCM IV)");
  }
  const rk = expandKey(key); // also validates key length
  const n = plaintext.length;

  // H = E_K(0^128): the GHASH subkey (SP 800-38D §6.4, step 1)
  const zero = new Array(16).fill(0);
  const h = blockToWords(encryptBlock(rk, zero), 0, 16);

  // J0 = IV || 0x00000001 (96-bit IV fast path, §7.1 step 2)
  const j0 = new Array(16);
  for (let i = 0; i <= 11; i++) {
    j0[i] = iv[i];
  }
  j0[12] = 0x00;
  j0[13] = 0x00;
  j0[14] = 0x00;
  j0[15] = 0x01;

  // CTR-mode encryption with counters inc32(J0), inc32²(J0), … (§6.5).
  // inc32 wraps only the last 32 bits of the counter block.
  const out = new Array(n + 16);
  const ctr = j0.slice();
  for (let off = 0; off < n; off += 16) {
    // inc32(ctr): big-endian increment of bytes 12..15, carry stops there
    for (let i = 15; i >= 12; i--) {
      ctr[i] = (ctr[i] + 1) & 0xff;
      if (ctr[i] !== 0) {
        break;
      }
    }
    const ks = encryptBlock(rk, ctr);
    const blockLen = Math.min(16, n - off);
    for (let i = 0; i <= blockLen - 1; i++) {
      out[off + i] = (plaintext[off + i] ^ ks[i]) >>> 0;
    }
  }

  // S = GHASH_H(C ∥ pad ∥ len64(AAD)=0 ∥ len64(C))  — AAD empty by contract
  let y = [0, 0, 0, 0];
  for (let off = 0; off < n; off += 16) {
    y = ghashBlock(y, blockToWords(out, off, n), h);
  }
  const bits = n * 8; // exact in doubles for any plausible script size
  const lenBlock = [0, 0, Math.floor(bits / 4294967296) >>> 0, bits % 4294967296 >>> 0];
  y = ghashBlock(y, lenBlock, h);

  // T = E_K(J0) ⊕ S, appended after the ciphertext (WebCrypto layout)
  const ekj0 = encryptBlock(rk, j0);
  for (let i = 0; i <= 3; i++) {
    const w = y[i];
    out[n + i * 4] = ((ekj0[i * 4] ^ (w >>> 24)) & 0xff) >>> 0;
    out[n + i * 4 + 1] = ((ekj0[i * 4 + 1] ^ (w >>> 16)) & 0xff) >>> 0;
    out[n + i * 4 + 2] = ((ekj0[i * 4 + 2] ^ (w >>> 8)) & 0xff) >>> 0;
    out[n + i * 4 + 3] = ((ekj0[i * 4 + 3] ^ w) & 0xff) >>> 0;
  }
  return out;
}

export const AesGcm = { encrypt };

// ─────────────────────────────────────────────────────────────────────────────
// [MIRROR §2] Sha256 — mirrors src/Crypto/Sha256.luau
// ─────────────────────────────────────────────────────────────────────────────

// [MIRROR §2.1] Round constants: fractional parts of the cube roots of the
// first 64 primes (FIPS-180-4 §4.2.2). Fixed public constants.
const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// [MIRROR §2.2] rotr: rotate a 32-bit word right by n (1 ≤ n ≤ 31).
// (Luau uses bit32.rrotate; this expression is its exact JS equivalent.)
function rotr(x, n) {
  return ((x >>> n) | ((x << (32 - n)) >>> 0)) >>> 0;
}

// [MIRROR §2.3] SHA-256 over a byte array (FIPS-180-4 §6.2). Returns the
// 32-byte digest as a byte array. Streaming is unnecessary — inputs here are
// script sources and small seed strings.
function digest(bytes) {
  const n = bytes.length;
  // Initial hash values: fractional parts of the square roots of the first
  // eight primes (FIPS-180-4 §5.3.3).
  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  // Padding (§5.1.1): append 0x80, then zeros until length ≡ 56 (mod 64),
  // then the message length in BITS as a 64-bit big-endian integer.
  const padded = bytes.slice();
  padded.push(0x80);
  while (padded.length % 64 !== 56) {
    padded.push(0x00);
  }
  const bits = n * 8;
  const hi = Math.floor(bits / 4294967296) >>> 0;
  const lo = bits % 4294967296 >>> 0;
  padded.push((hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff);
  padded.push((lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);

  const w = new Array(64);
  for (let off = 0; off < padded.length; off += 64) {
    // Message schedule (§6.2.2 step 1)
    for (let t = 0; t <= 15; t++) {
      const i = off + t * 4;
      w[t] = ((padded[i] << 24) | (padded[i + 1] << 16) | (padded[i + 2] << 8) | padded[i + 3]) >>> 0;
    }
    for (let t = 16; t <= 63; t++) {
      const s0 = (rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3)) >>> 0;
      const s1 = (rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10)) >>> 0;
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) % 4294967296;
    }
    // Compression (§6.2.2 steps 2–4). Additions are mod 2^32; intermediate
    // sums stay exact (well under 2^53) before reduction.
    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;
    for (let t = 0; t <= 63; t++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ ((~e >>> 0) & g)) >>> 0;
      const temp1 = (h + S1 + ch + SHA256_K[t] + w[t]) % 4294967296;
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (S0 + maj) % 4294967296;
      h = g;
      g = f;
      f = e;
      e = (d + temp1) % 4294967296;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) % 4294967296;
    }
    h0 = (h0 + a) % 4294967296;
    h1 = (h1 + b) % 4294967296;
    h2 = (h2 + c) % 4294967296;
    h3 = (h3 + d) % 4294967296;
    h4 = (h4 + e) % 4294967296;
    h5 = (h5 + f) % 4294967296;
    h6 = (h6 + g) % 4294967296;
    h7 = (h7 + h) % 4294967296;
  }

  const out = [];
  for (const word of [h0, h1, h2, h3, h4, h5, h6, h7]) {
    out.push((word >>> 24) & 0xff, (word >>> 16) & 0xff, (word >>> 8) & 0xff, word & 0xff);
  }
  return out;
}

// [MIRROR §2.4] Hex form of the digest (lowercase), used for the key
// fingerprint shown in the settings UI and sent on the wire.
function hex(bytes) {
  const d = digest(bytes);
  let s = "";
  for (let i = 0; i <= 31; i++) {
    s += d[i].toString(16).padStart(2, "0");
  }
  return s;
}

export const Sha256 = { digest, hex };

// ─────────────────────────────────────────────────────────────────────────────
// [MIRROR §3] Base64 — mirrors src/Crypto/Base64.luau
// ─────────────────────────────────────────────────────────────────────────────

// [MIRROR §3.1] Standard RFC 4648 alphabet with '=' padding (what the
// dashboard's btoa/atob and the wire contract use).
const B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// [MIRROR §3.2] Encode a byte array to base64 (always padded).
function b64encode(bytes) {
  const out = [];
  const n = bytes.length;
  for (let i = 0; i < n; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < n ? bytes[i + 1] : 0;
    const b2 = i + 2 < n ? bytes[i + 2] : 0;
    const triple = b0 * 65536 + b1 * 256 + b2;
    out.push(B64_ALPHABET[Math.floor(triple / 262144) % 64]);
    out.push(B64_ALPHABET[Math.floor(triple / 4096) % 64]);
    out.push(i + 1 < n ? B64_ALPHABET[Math.floor(triple / 64) % 64] : "=");
    out.push(i + 2 < n ? B64_ALPHABET[triple % 64] : "=");
  }
  return out.join("");
}

// [MIRROR §3.3] Decode base64 to a byte array. STRICT: length must be a
// multiple of 4, only canonical alphabet characters, '=' only as 1–2 trailing
// pad chars. Returns null on any violation (the settings UI turns that into
// a "not a valid key" message rather than guessing).
function b64decode(s) {
  if (typeof s !== "string" || s.length % 4 !== 0 || s.length === 0) {
    return null;
  }
  let pad = 0;
  if (s.endsWith("==")) {
    pad = 2;
  } else if (s.endsWith("=")) {
    pad = 1;
  }
  const out = [];
  for (let i = 0; i < s.length; i += 4) {
    let triple = 0;
    let chars = 4;
    for (let j = 0; j <= 3; j++) {
      const ch = s[i + j];
      if (ch === "=") {
        // '=' is only legal in the final group, only in the last 1–2 slots
        if (i + 4 < s.length || j < 4 - pad) {
          return null;
        }
        chars = chars - 1;
        triple = triple * 64;
      } else {
        const v = B64_ALPHABET.indexOf(ch);
        if (v < 0) {
          return null;
        }
        triple = triple * 64 + v;
      }
    }
    out.push(Math.floor(triple / 65536) % 256);
    if (chars >= 3) {
      out.push(Math.floor(triple / 256) % 256);
    }
    if (chars >= 4) {
      out.push(triple % 256);
    }
  }
  return out;
}

export const Base64 = { encode: b64encode, decode: b64decode };

// ─────────────────────────────────────────────────────────────────────────────
// [MIRROR §4] Compositions — correspond to call sites in Settings.luau and
// Uploader.luau (not separate Luau modules; mirrored here so the Node test
// suite and a manual cross-language audit can exercise the exact recipes).
// ─────────────────────────────────────────────────────────────────────────────

// [MIRROR §4.1] keyFingerprint: first 8 hex chars of sha256(raw key bytes).
// Pinned wire field — lets the dashboard say "wrong key" deterministically
// without ever seeing the key. Corresponds to Settings.luau `fingerprint`.
export function keyFingerprint(keyBytes) {
  return Sha256.hex(keyBytes).slice(0, 8);
}

// [MIRROR §4.2] ivFromSeed: first 12 bytes of sha256(seed bytes). The seed
// string is built by Uploader.luau `deriveIv` as
//   projectKeyB64 .. instancePath .. placeVersion .. os.clock() .. GUID
// GCM needs IV UNIQUENESS, not secrecy — see the rationale comment at the
// derivation site in Uploader.luau. Corresponds to Uploader.luau `deriveIv`.
export function ivFromSeed(seedBytes) {
  return Sha256.digest(seedBytes).slice(0, 12);
}

// [MIRROR §4.3] utf8/byte helpers used by tests and the seam audit.
export function stringToBytes(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) {
    out.push(s.charCodeAt(i) & 0xff); // byte strings only (Luau strings are bytes)
  }
  return out;
}
