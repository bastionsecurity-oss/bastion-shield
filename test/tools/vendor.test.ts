// Tests for tools/vendor.ts: path mapping from VENDOR.json patterns and the
// tar reader (ustar names, pax path overrides, GitHub's global commit header).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mapVendorPath, readTar, vendorDirOf } from '../../tools/vendor.ts';

test('vendorDirOf', () => {
  assert.equal(vendorDirOf('ublock'), 'ublock');
  assert.equal(vendorDirOf('braveResources'), 'brave-resources');
});

test('mapVendorPath', () => {
  const ubo = ['src/js/resources/*.js', 'src/js/redirect-resources.js', 'src/web_accessible_resources/*', 'src/js/urlskip.js'];
  assert.equal(mapVendorPath('src/js/resources/set-constant.js', ubo), 'resources/set-constant.js');
  assert.equal(mapVendorPath('src/js/resources/sub/x.js', ubo), null, '* does not cross directories');
  assert.equal(mapVendorPath('src/js/resources/readme.md', ubo), null);
  assert.equal(mapVendorPath('src/js/redirect-resources.js', ubo), 'redirect-resources.js');
  assert.equal(mapVendorPath('src/web_accessible_resources/noop.js', ubo), 'web_accessible_resources/noop.js');
  assert.equal(mapVendorPath('src/js/other.js', ubo), null);
  assert.equal(mapVendorPath('LICENSE.txt', ubo), 'LICENSE.txt', 'root licence always kept');
  assert.equal(mapVendorPath('metadata.json', ['resources/*', 'metadata.json']), 'metadata.json');
  assert.equal(mapVendorPath('brave-lists/debounce.json', ['brave-lists/debounce.json']), 'debounce.json');
});

function tarEntry(name: string, data: Buffer, type = '0'): Buffer {
  const h = Buffer.alloc(512);
  h.write(name.slice(0, 100), 0, 'utf8');
  h.write('0000644\0', 100);
  h.write('0000000\0', 108);
  h.write('0000000\0', 116);
  h.write(data.length.toString(8).padStart(11, '0') + '\0', 124);
  h.write('00000000000\0', 136);
  h.write(type, 156);
  h.write('ustar\0', 257);
  h.write('00', 263);
  // Checksum: spaces while summing, then octal.
  h.fill(0x20, 148, 156);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  const pad = Buffer.alloc((512 - (data.length % 512)) % 512);
  return Buffer.concat([h, data, pad]);
}

function pax(records: Record<string, string>): Buffer {
  let out = '';
  for (const [k, v] of Object.entries(records)) {
    const body = ` ${k}=${v}\n`;
    let len = body.length + 1;
    while (String(len).length + body.length !== len) len = String(len).length + body.length;
    out += `${len}${body}`;
  }
  return Buffer.from(out);
}

test('readTar: files, pax path override, global comment', () => {
  const long = `repo-abc/${'d/'.repeat(60)}file.js`;
  const tar = Buffer.concat([
    tarEntry('pax_global_header', pax({ comment: 'a'.repeat(40) }), 'g'),
    tarEntry('repo-abc/', Buffer.alloc(0), '5'),
    tarEntry('repo-abc/LICENSE', Buffer.from('GPL')),
    tarEntry('PaxHeaders/x', pax({ path: long }), 'x'),
    tarEntry('repo-abc/truncated-name', Buffer.from('long one')),
    Buffer.alloc(1024),
  ]);
  const r = readTar(tar);
  assert.equal(r.globalComment, 'a'.repeat(40));
  assert.deepEqual([...r.files.keys()], ['repo-abc/LICENSE', long]);
  assert.equal(r.files.get(long)!.toString(), 'long one');
});
