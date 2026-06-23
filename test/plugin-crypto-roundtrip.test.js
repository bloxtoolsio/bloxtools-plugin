/*
  Studio plugin crypto — executable proof chain.

  WHAT THIS PROVES, AND WHAT IT DOESN'T:

  The plugin's AES-256-GCM / SHA-256 / base64 live in pure Luau under
  src/Crypto/ — and this repo has NO Luau runtime. So the cipher is
  ALSO written as a single dependency-free Node mirror,
  tools/aes-gcm-mirror.mjs, kept line-correspondent with the Luau
  (same functions, same order, same constants, same comments).

  This suite re-implements NOTHING. It proves, using only node:crypto as the
  judge:
    1. mirror AES-256-GCM === NIST CAVP vectors checked in at
       test/plugin-crypto.vectors.json (key/iv/pt → ct||tag, byte-for-byte);
    2. mirror AES-256-GCM === WebCrypto subtle.encrypt on those vectors AND
       on randomized keys/ivs/plaintexts across length edge cases — and
       WebCrypto subtle.decrypt round-trips the mirror's output (this is the
       exact call the dashboard makes, so the cross-implementation seam is
       exercised here, not just field names);
    3. mirror SHA-256 === node:crypto sha256 (fingerprints + IV derivation);
    4. mirror base64 === Buffer base64, and strict decode rejects garbage;
    5. the pinned envelope compositions: keyFingerprint = first 8 hex of
       sha256(raw key), ivFromSeed = first 12 bytes of sha256(seed);
    6. the Luau and the mirror contain IDENTICAL hex-constant streams
       (S-box, Rcon, GCM reduction constant, SHA-256 K table, masks) —
       a mechanical guard against transcription typos between the files.

  What this file alone cannot prove: that the Luau text *executes*
  identically. That gap is closed by test/plugin-crypto-luau.test.js, which
  runs the ACTUAL Luau modules against the same NIST vectors under the
  open-source Luau CLI whenever a `luau` binary is available (and otherwise
  falls back to line-correspondence + the live Studio gate,
  PLUGIN_TESTPLAN.md).
*/

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto, createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
  AesGcm,
  Sha256,
  Base64,
  keyFingerprint,
  ivFromSeed,
  stringToBytes,
} from '../tools/aes-gcm-mirror.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const hexToBytes = (hex) => (hex ? hex.match(/../g).map((h) => parseInt(h, 16)) : []);
const bytesToHex = (bytes) => bytes.map((b) => b.toString(16).padStart(2, '0')).join('');

const { vectors } = JSON.parse(
  readFileSync(path.join(here, 'plugin-crypto.vectors.json'), 'utf8'),
);

async function importGcmKey(keyBytes, usages) {
  return webcrypto.subtle.importKey('raw', Uint8Array.from(keyBytes), 'AES-GCM', false, usages);
}

// ── 1+2a. NIST CAVP vectors: mirror vs checked-in expectations vs WebCrypto ──

test('NIST vectors are present and well-formed', () => {
  assert.ok(vectors.length >= 12, `expected a meaningful vector set, got ${vectors.length}`);
  for (const v of vectors) {
    assert.equal(v.key.length, 64, `${v.name}: 32-byte key`);
    assert.equal(v.iv.length, 24, `${v.name}: 12-byte IV`);
    assert.equal(v.aad, '', `${v.name}: AAD must be empty (pinned envelope)`);
    assert.equal(v.tag.length, 32, `${v.name}: 16-byte tag`);
  }
  // Edge coverage: at least one empty plaintext and one non-block-aligned one.
  assert.ok(vectors.some((v) => v.plaintext.length === 0), 'has empty-plaintext vector');
  assert.ok(vectors.some((v) => (v.plaintext.length / 2) % 16 !== 0), 'has partial-block vector');
});

for (const v of vectors) {
  test(`mirror matches NIST vector + WebCrypto agrees: ${v.name}`, async () => {
    const key = hexToBytes(v.key);
    const iv = hexToBytes(v.iv);
    const pt = hexToBytes(v.plaintext);

    // Mirror output must equal the NIST expectation: ciphertext || tag.
    const mine = AesGcm.encrypt(key, iv, pt);
    assert.equal(bytesToHex(mine), v.ct + v.tag, 'mirror === NIST ct||tag');

    // WebCrypto, encrypting the same inputs, must produce identical bytes
    // (AES-GCM is deterministic given key+iv) — mirror vs webcrypto.
    const k = await importGcmKey(key, ['encrypt', 'decrypt']);
    const wc = new Uint8Array(
      await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv: Uint8Array.from(iv) }, k, Uint8Array.from(pt)),
    );
    assert.equal(bytesToHex([...wc]), bytesToHex(mine), 'webcrypto === mirror');

    // And WebCrypto must DECRYPT the mirror's output back to the plaintext —
    // the exact subtle.decrypt(iv, ct||tag) call the dashboard performs.
    const back = new Uint8Array(
      await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: Uint8Array.from(iv) }, k, Uint8Array.from(mine)),
    );
    assert.equal(bytesToHex([...back]), v.plaintext, 'webcrypto decrypts mirror output');
  });
}

// ── 2b. Randomized cross-implementation round-trips ──────────────────────────

test('randomized: mirror encrypt === WebCrypto encrypt, and decrypt round-trips', async () => {
  // Length edge cases: empty, sub-block, block boundaries, multi-block,
  // and a realistically sized script source.
  const lengths = [0, 1, 15, 16, 17, 31, 32, 33, 255, 256, 1000, 4096, 50_000];
  for (const len of lengths) {
    const key = [...randomBytes(32)];
    const iv = [...randomBytes(12)];
    const pt = [...randomBytes(len)];

    const mine = AesGcm.encrypt(key, iv, pt);
    assert.equal(mine.length, len + 16, `len=${len}: output is pt+16 bytes`);

    const k = await importGcmKey(key, ['encrypt', 'decrypt']);
    const wc = new Uint8Array(
      await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv: Uint8Array.from(iv) }, k, Uint8Array.from(pt)),
    );
    assert.equal(
      bytesToHex([...wc]),
      bytesToHex(mine),
      `len=${len}: mirror === webcrypto (key=${bytesToHex(key)} iv=${bytesToHex(iv)})`,
    );

    const back = new Uint8Array(
      await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: Uint8Array.from(iv) }, k, Uint8Array.from(mine)),
    );
    assert.equal(bytesToHex([...back]), bytesToHex(pt), `len=${len}: round-trip`);
  }
});

test('tampering any ciphertext byte makes WebCrypto reject the tag', async () => {
  const key = [...randomBytes(32)];
  const iv = [...randomBytes(12)];
  const pt = stringToBytes('local secret = "do not leak"');
  const ct = AesGcm.encrypt(key, iv, pt);
  ct[3] = (ct[3] + 1) & 0xff;
  const k = await importGcmKey(key, ['decrypt']);
  await assert.rejects(
    webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: Uint8Array.from(iv) }, k, Uint8Array.from(ct)),
    'corrupted ciphertext must fail authentication',
  );
});

test('input validation: bad key / iv lengths throw', () => {
  assert.throws(() => AesGcm.encrypt([...randomBytes(16)], [...randomBytes(12)], []), /32 bytes/);
  assert.throws(() => AesGcm.encrypt([...randomBytes(32)], [...randomBytes(16)], []), /12 bytes/);
});

// ── 3. SHA-256 mirror vs node:crypto ─────────────────────────────────────────

test('sha256 mirror matches node:crypto across padding boundaries', () => {
  // FIPS-180-4 known answer first.
  assert.equal(
    Sha256.hex(stringToBytes('abc')),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  );
  // Lengths straddling the 55/56/64-byte padding edges + larger inputs.
  for (const len of [0, 1, 31, 55, 56, 57, 63, 64, 65, 127, 128, 1000, 10_000]) {
    const input = [...randomBytes(len)];
    const want = createHash('sha256').update(Uint8Array.from(input)).digest('hex');
    assert.equal(Sha256.hex(input), want, `sha256 len=${len}`);
    assert.equal(bytesToHex(Sha256.digest(input)), want, `digest() agrees with hex(), len=${len}`);
  }
});

// ── 4. Base64 mirror vs Buffer ───────────────────────────────────────────────

test('base64 encode matches Buffer for all length residues', () => {
  for (const len of [0, 1, 2, 3, 4, 5, 31, 32, 33, 256, 1000]) {
    const input = [...randomBytes(len)];
    assert.equal(Base64.encode(input), Buffer.from(input).toString('base64'), `encode len=${len}`);
  }
});

test('base64 strict decode: round-trips valid input, rejects garbage', () => {
  for (const len of [1, 2, 3, 31, 32, 33, 256]) {
    const input = [...randomBytes(len)];
    const encoded = Buffer.from(input).toString('base64');
    assert.deepEqual(Base64.decode(encoded), input, `decode len=${len}`);
  }
  for (const bad of ['', 'abc', 'ab=c', 'a===', '====', 'ab!d', 'AAAA=AAA', 'AA==AA==']) {
    assert.equal(Base64.decode(bad), null, `must reject ${JSON.stringify(bad)}`);
  }
});

// ── 5. Pinned envelope compositions ──────────────────────────────────────────

test('keyFingerprint = first 8 hex of sha256(raw key bytes) — pinned wire field', () => {
  const key = [...randomBytes(32)];
  const want = createHash('sha256').update(Uint8Array.from(key)).digest('hex').slice(0, 8);
  assert.equal(keyFingerprint(key), want);
  assert.equal(keyFingerprint(key).length, 8);
});

test('ivFromSeed = first 12 bytes of sha256(seed) — pinned IV derivation', () => {
  const seed = stringToBytes('keyB64' + 'ServerScriptService.Combat' + '43' + '12.345' + '{guid}');
  const want = createHash('sha256').update(Uint8Array.from(seed)).digest().subarray(0, 12);
  assert.equal(bytesToHex(ivFromSeed(seed)), bytesToHex([...want]));
  assert.equal(ivFromSeed(seed).length, 12);
});

test('the full plugin pipeline shape: encrypt with derived IV, decrypt like the dash', async () => {
  // Simulates exactly what Uploader.luau does per artifact, then what the
  // dashboard does with the stored row: subtle.decrypt(iv, ct||tag).
  const keyBytes = [...randomBytes(32)];
  const keyB64 = Buffer.from(keyBytes).toString('base64');
  assert.equal(keyB64.length, 44, 'project keys are 44-char padded base64');
  assert.deepEqual(Base64.decode(keyB64), keyBytes, 'plugin-side key paste decode');

  const source = 'local Combat = {}\nfunction Combat.applyDamage(h)\n\treturn h.Damage\nend\nreturn Combat\n';
  const seed = keyB64 + 'ServerScriptService.Combat' + '43' + '7.231' + 'e2ca4f7b-….guid';
  const iv = ivFromSeed(stringToBytes(seed));
  const ct = AesGcm.encrypt(keyBytes, iv, stringToBytes(source));

  // Wire fields per the pinned contract.
  const wire = {
    instancePath: 'ServerScriptService.Combat',
    iv: Base64.encode(iv),
    ciphertext: Base64.encode(ct),
    plainBytes: source.length,
  };
  assert.equal(wire.iv.length, 16, 'iv is 16 base64 chars (12 bytes)');

  const k = await importGcmKey(keyBytes, ['decrypt']);
  const back = new Uint8Array(
    await webcrypto.subtle.decrypt(
      { name: 'AES-GCM', iv: Uint8Array.from(Buffer.from(wire.iv, 'base64')) },
      k,
      Uint8Array.from(Buffer.from(wire.ciphertext, 'base64')),
    ),
  );
  assert.equal(Buffer.from(back).toString('utf8'), source, 'dash-side decrypt recovers the source');
});

// ── 6. Luau ↔ mirror transcription guard: identical hex-constant streams ─────

test('Luau files and mirror sections carry identical hex-constant streams', () => {
  // The riskiest failure mode of the mirror scheme is a transcription typo
  // in a constant table (S-box, Rcon, SHA-256 K, masks). Both files write
  // every cryptographic constant in hex, in the same order — so extracting
  // the 0x… literal streams (code AND comments, which are mirrored verbatim
  // where they contain constants) and diffing them catches that class of
  // error mechanically. Logic transcription is covered by a manual
  // line-correspondence review + the live Studio gate.
  const mirror = readFileSync(path.join(here, '..', 'tools', 'aes-gcm-mirror.mjs'), 'utf8');
  // Slice on the unique section BANNER lines (the file header also mentions
  // the section tags, so match the "// [MIRROR §N] Name" form specifically).
  const sections = {
    'AesGcm.luau': mirror.slice(mirror.indexOf('// [MIRROR §1] AesGcm'), mirror.indexOf('// [MIRROR §2] Sha256')),
    'Sha256.luau': mirror.slice(mirror.indexOf('// [MIRROR §2] Sha256'), mirror.indexOf('// [MIRROR §3] Base64')),
    'Base64.luau': mirror.slice(mirror.indexOf('// [MIRROR §3] Base64'), mirror.indexOf('// [MIRROR §4] Compositions')),
  };
  for (const [name, body] of Object.entries(sections)) {
    assert.ok(body.length > 0, `mirror section for ${name} found`);
  }
  const hexStream = (s) => (s.match(/0x[0-9a-fA-F]+/g) || []).map((h) => h.toLowerCase());
  for (const [luauFile, mirrorSection] of Object.entries(sections)) {
    const luau = readFileSync(path.join(here, '..', 'src', 'Crypto', luauFile), 'utf8');
    // Compare from the first section marker so Luau header prose (which the
    // mirror compresses into its own header) is excluded on both sides.
    const luauBody = luau.slice(luau.indexOf('-- [MIRROR'));
    assert.deepEqual(
      hexStream(luauBody),
      hexStream(mirrorSection),
      `${luauFile} hex-constant stream must equal its mirror section`,
    );
  }
});
