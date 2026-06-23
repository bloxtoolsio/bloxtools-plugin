/*
  Generates tools/vectors.luau — the NIST CAVP vectors from
  test/plugin-crypto.vectors.json re-expressed as a Luau module, so the
  Luau-side harness (tools/luau-vectors.luau) can run under the
  open-source Luau CLI, which has no file I/O.

  test/plugin-crypto-luau.test.js asserts the committed vectors.luau is
  byte-identical to this generator's output (sync guard). Regenerate with:

    node tools/gen-vectors-luau.mjs

  Dependency-free (node built-ins only).
*/

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const jsonPath = path.join(here, '..', 'test', 'plugin-crypto.vectors.json');
const outPath = path.join(here, 'vectors.luau');

export function generate() {
  const { vectors } = JSON.parse(readFileSync(jsonPath, 'utf8'));
  const fields = ['name', 'key', 'iv', 'plaintext', 'aad', 'ct', 'tag'];
  const rows = vectors.map((v) => {
    const parts = fields.map((f) => {
      const value = v[f];
      if (typeof value !== 'string' || /[\\"]/.test(value)) {
        throw new Error(`unexpected vector field ${f}: ${JSON.stringify(value)}`);
      }
      return `${f} = "${value}"`;
    });
    return `\t{ ${parts.join(', ')} },`;
  });
  return [
    '-- GENERATED FILE — DO NOT EDIT.',
    '-- Source of truth: test/plugin-crypto.vectors.json (NIST CAVP AES-256-GCM).',
    '-- Regenerate: node tools/gen-vectors-luau.mjs',
    '-- Sync is asserted by test/plugin-crypto-luau.test.js in `npm test`.',
    'return {',
    ...rows,
    '}',
    '',
  ].join('\n');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  writeFileSync(outPath, generate());
  console.log(`wrote ${outPath}`);
}
