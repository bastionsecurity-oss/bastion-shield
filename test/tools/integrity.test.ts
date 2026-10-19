// Tests for tools/integrity.ts: dist/rulesets/integrity.json hashes every file
// under rulesets/ (rulesets, transparency maps, meta.json), never itself, with
// sorted package-relative paths, and leaves the hashed files unchanged.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { computeIntegrity, INTEGRITY_FILE, writeIntegrity, type IntegrityManifest } from '../../tools/integrity.ts';

const hex = (s: string | Uint8Array): string => createHash('sha256').update(s).digest('hex');

async function fixture(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'bastion-integrity-'));
  await mkdir(join(dir, 'rulesets', 'net'), { recursive: true });
  await mkdir(join(dir, 'rulesets', 'filters'), { recursive: true });
  await mkdir(join(dir, 'cosmetic'), { recursive: true });
  await writeFile(join(dir, 'rulesets', 'net', 'easylist.json'), '[\n{"id":1}\n]\n');
  await writeFile(join(dir, 'rulesets', 'net', 'easylist.regex.json'), '[]\n');
  await writeFile(join(dir, 'rulesets', 'filters', 'easylist.json'), '[\nnull,\n["||ads.example^"]\n]\n');
  await writeFile(join(dir, 'rulesets', 'meta.json'), '{"builtAt":"2026-10-18T10:00:00.000Z"}\n');
  await writeFile(join(dir, 'cosmetic', 'meta.json'), '{}\n');
  return dir;
}

test('computeIntegrity hashes every file under rulesets/ with sorted relative paths', async () => {
  const dir = await fixture();
  try {
    const m = await computeIntegrity(dir, '2026-10-18T10:00:00.000Z');
    assert.equal(m.algorithm, 'sha256');
    assert.equal(m.builtAt, '2026-10-18T10:00:00.000Z');
    assert.deepEqual(Object.keys(m.files), ['rulesets/filters/easylist.json', 'rulesets/meta.json', 'rulesets/net/easylist.json', 'rulesets/net/easylist.regex.json']);
    assert.equal(m.files['rulesets/net/easylist.json'], hex('[\n{"id":1}\n]\n'));
    for (const v of Object.values(m.files)) assert.match(v, /^[0-9a-f]{64}$/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('writeIntegrity writes the manifest, excludes itself on a rerun and changes nothing else', async () => {
  const dir = await fixture();
  try {
    const before = await readFile(join(dir, 'rulesets', 'net', 'easylist.json'));
    await writeIntegrity(dir, 'a');
    const second = await writeIntegrity(dir, 'b');
    const onDisk = JSON.parse(await readFile(join(dir, ...INTEGRITY_FILE.split('/')), 'utf8')) as IntegrityManifest;
    assert.deepEqual(onDisk, second);
    assert.equal(onDisk.builtAt, 'b');
    assert.equal(INTEGRITY_FILE in onDisk.files, false);
    assert.deepEqual(await readFile(join(dir, 'rulesets', 'net', 'easylist.json')), before);
    // A modified ruleset shows up as a different hash.
    await writeFile(join(dir, 'rulesets', 'net', 'easylist.json'), '[]\n');
    const after = await computeIntegrity(dir, 'c');
    assert.notEqual(after.files['rulesets/net/easylist.json'], second.files['rulesets/net/easylist.json']);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
