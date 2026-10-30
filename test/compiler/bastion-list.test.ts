// Site fixes in Bastion's own list (filters/bastion.txt), checked against the
// upstream filters they correct: compile both, resolve the host's cosmetics
// the way the service worker does and check what ends up on the page.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { compileList } from '../../src/compiler/index.ts';
import { resolveHostCosmetic } from '../../src/background/cosmetic.ts';
import type { CosmeticHostEntry } from '../../src/shared/types.ts';
import { opts } from './helpers.ts';

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..', '..');
const bastion = fs.readFileSync(path.join(repoRoot, 'filters', 'bastion.txt'), 'utf8');

/** Host entries for `host` from each list, tagged with the list's bit. */
function hostEntries(host: string, lists: string[]): CosmeticHostEntry[] {
  const out: CosmeticHostEntry[] = [];
  lists.forEach((text, i) => {
    const compiled = compileList(text, opts({ trusted: true }));
    for (const s of compiled.specific) if (s.hosts.includes(host)) out.push([s.kind, s.payload, 1 << i] as CosmeticHostEntry);
  });
  return out;
}

test('20min.ch: the in-feed ad row is collapsed, not removed from the teaser grid', () => {
  // uBlock filters (uAssets#32708) and AdGuard French hide it with display:none.
  const upstream = [
    '20min.ch##section aside:has(> div > div > div[data-ad-unit-id])',
    '20min.ch,lessentiel.lu##section[class*="ad-content-wrapper"] > div[class] > aside:has(> div[class] > div[class] > div[data-ad-unit-id])',
    '20min.ch##div[type="ad"]',
  ].join('\n');
  const r = resolveHostCosmetic([hostEntries('20min.ch', [bastion, upstream])], 0b11, ['20min.ch']);
  assert.deepEqual(r.hide, ['div[type="ad"]']);
  assert.equal(r.styles.length, 1);
  assert.match(r.styles[0], /^section aside:has\(> div > div > div\[data-ad-unit-id\]\) \{ visibility: hidden !important; height: 0 !important;/);
  assert.doesNotMatch(r.styles[0], /display/);
});
