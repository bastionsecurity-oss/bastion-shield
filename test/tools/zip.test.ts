// Tests for tools/lib/zip.ts: CRC-32 vector, round trip, determinism, and
// the Edge package variant in tools/package.ts.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { crc32, createZip, readZip } from '../../tools/lib/zip.ts';
import { edgeVariant } from '../../tools/package.ts';

test('crc32 check value', () => {
  assert.equal(crc32(Buffer.from('123456789')), 0xcbf43926);
  assert.equal(crc32(new Uint8Array(0)), 0);
});

test('zip round trip with stored and deflated entries', () => {
  const big = Buffer.from('a'.repeat(10_000));
  const tiny = Buffer.from([1, 2, 3]);
  const zip = createZip([
    { name: 'manifest.json', data: Buffer.from('{"a":1}') },
    { name: 'dir/big.txt', data: big },
    { name: 'dir/tiny.bin', data: tiny },
    { name: 'ümlaut.txt', data: Buffer.from('x') },
  ]);
  const files = readZip(zip);
  assert.equal(files.size, 4);
  assert.ok(files.get('dir/big.txt')!.equals(big));
  assert.ok(files.get('dir/tiny.bin')!.equals(tiny));
  assert.equal(files.get('ümlaut.txt')!.toString(), 'x');
  assert.ok(zip.length < 2000, 'repetitive data is deflated');
});

test('zip output is deterministic', () => {
  const entries = [{ name: 'a.txt', data: Buffer.from('hello') }];
  assert.ok(createZip(entries).equals(createZip(entries)));
});

test('zip rejects unsafe or duplicate names', () => {
  assert.throws(() => createZip([{ name: '../x', data: Buffer.alloc(1) }]), /invalid/);
  assert.throws(() => createZip([{ name: '/x', data: Buffer.alloc(1) }]), /invalid/);
  assert.throws(() => createZip([{ name: 'a', data: Buffer.alloc(1) }, { name: 'a', data: Buffer.alloc(1) }]), /duplicate/);
});

test('edge variant moves rulesets to the root and rewrites the manifest', () => {
  const manifest = {
    version: '1.0',
    declarative_net_request: {
      rule_resources: [
        { id: 'easylist', enabled: true, path: 'rulesets/net/easylist.json' },
        { id: 'easylist.regex', enabled: true, path: 'rulesets/net/easylist.regex.json' },
      ],
    },
  };
  const entries = [
    { name: 'manifest.json', data: Buffer.from(JSON.stringify(manifest)) },
    { name: 'rulesets/net/easylist.json', data: Buffer.from('[]') },
    { name: 'rulesets/net/easylist.regex.json', data: Buffer.from('[]') },
    { name: 'rulesets/filters/easylist.json', data: Buffer.from('[null]') },
  ];
  const out = edgeVariant(entries, manifest);
  const names = out.entries.map((e) => e.name).sort();
  assert.deepEqual(names, ['easylist.json', 'easylist.regex.json', 'manifest.json', 'rulesets/filters/easylist.json']);
  const m = JSON.parse(out.entries.find((e) => e.name === 'manifest.json')!.data.toString());
  assert.deepEqual(m.declarative_net_request.rule_resources.map((r: { path: string }) => r.path), ['easylist.json', 'easylist.regex.json']);
  assert.equal(manifest.declarative_net_request.rule_resources[0].path, 'rulesets/net/easylist.json', 'input manifest untouched');
});

test('package filter: no build report, source maps or reserved _ directories', async () => {
  const { shipped } = await import('../../tools/package.ts');
  assert.equal(shipped('build-report.json'), false);
  assert.equal(shipped('background.js.map'), false);
  assert.equal(shipped('_metadata/generated_indexed_rulesets/_ruleset1'), false);
  assert.equal(shipped('_locales/de/messages.json'), true);
  assert.equal(shipped('rulesets/net/easylist.json'), true);
});
