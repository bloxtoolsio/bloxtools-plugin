/*
  Studio plugin crypto — Luau-side execution.

  test/plugin-crypto-roundtrip.test.js proves the Node MIRROR of the plugin
  crypto equals WebCrypto on NIST vectors. This file goes one step further
  when it can: it executes the ACTUAL Luau modules (src/Crypto/*.luau)
  against the same NIST vectors using the open-source Luau CLI
  (https://github.com/luau-lang/luau) — possible because Crypto/ uses no
  Roblox globals (the portability contract).

  - Always: asserts tools/vectors.luau (the vectors re-expressed as a
    Luau module, since the Luau CLI has no file I/O) is in sync with
    test/plugin-crypto.vectors.json.
  - When a `luau` binary is available (LUAU_BIN env var, or `luau` on PATH):
    runs tools/luau-vectors.luau and asserts it exits 0 with every
    vector passing. Skips with an explicit message otherwise — in that case
    the Luau side rests on line-correspondence with the tested mirror plus
    the live Studio gate (PLUGIN_TESTPLAN.md).

  No new dependencies: node built-ins only.
*/

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { delimiter } from 'node:path';

import { generate } from '../tools/gen-vectors-luau.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(here, '..');
const harness = path.join(repoRoot, 'tools', 'luau-vectors.luau');

test('vectors.luau is in sync with plugin-crypto.vectors.json', () => {
  const committed = readFileSync(path.join(repoRoot, 'tools', 'vectors.luau'), 'utf8');
  assert.equal(
    committed,
    generate(),
    'tools/vectors.luau is stale — regenerate: node tools/gen-vectors-luau.mjs',
  );
});

function findLuau() {
  if (process.env.LUAU_BIN && existsSync(process.env.LUAU_BIN)) {
    return process.env.LUAU_BIN;
  }
  for (const dir of (process.env.PATH || '').split(delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, 'luau');
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

const luauBin = findLuau();

test(
  'the ACTUAL Luau crypto passes the NIST vectors under the Luau CLI',
  { skip: luauBin ? false : 'no `luau` binary found (set LUAU_BIN or add to PATH) — Luau side rests on the tested mirror + the Studio gate' },
  () => {
    const run = spawnSync(luauBin, [harness], {
      cwd: repoRoot,
      encoding: 'utf8',
      timeout: 60_000,
    });
    assert.equal(
      run.status,
      0,
      `luau harness failed (exit ${run.status}):\n${run.stdout}\n${run.stderr}`,
    );
    assert.match(run.stdout, /ALL LUAU-SIDE CHECKS PASSED/);
    // One PASS line per NIST vector — none silently skipped.
    const { vectors } = JSON.parse(
      readFileSync(path.join(here, 'plugin-crypto.vectors.json'), 'utf8'),
    );
    for (const v of vectors) {
      assert.ok(run.stdout.includes(`PASS AesGcm.luau === NIST: ${v.name}`), `vector ran: ${v.name}`);
    }
  },
);
