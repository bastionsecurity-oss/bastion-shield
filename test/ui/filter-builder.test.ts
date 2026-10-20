// Tests for the «Eigene Filter» guided builder and .txt import / export
// (src/ui/dashboard/filter-builder.ts).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { appendLine, buildFilter, exportText, hasFilter, importedFilters, mergeFilters } from '../../src/ui/dashboard/filter-builder.ts';

const ok = (filter: string) => ({ ok: true, filter });

test('block a domain', () => {
  assert.deepEqual(buildFilter({ action: 'block-domain', target: 'ads.example.com' }), ok('||ads.example.com^'));
  assert.deepEqual(buildFilter({ action: 'block-domain', target: ' https://www.Example.com/page?x ' }), ok('||example.com^'));
  assert.deepEqual(buildFilter({ action: 'block-domain', target: 'not a domain' }), { ok: false, error: 'domain' });
});

test('turn off filtering on a site', () => {
  assert.deepEqual(buildFilter({ action: 'allow-site', target: 'example.com' }), ok('@@||example.com^$document'));
  assert.deepEqual(buildFilter({ action: 'allow-site', target: '' }), { ok: false, error: 'domain' });
});

test('block a script: URL, path, domain, optional site', () => {
  assert.deepEqual(buildFilter({ action: 'block-script', target: 'https://cdn.example.com/js/t.js?v=3#x' }), ok('||cdn.example.com/js/t.js$script'));
  assert.deepEqual(buildFilter({ action: 'block-script', target: 'example.com/tracker.js' }), ok('||example.com/tracker.js$script'));
  assert.deepEqual(buildFilter({ action: 'block-script', target: 'example.com' }), ok('||example.com^$script'));
  assert.deepEqual(buildFilter({ action: 'block-script', target: 'example.com/t.js', site: 'news.org' }), ok('||example.com/t.js$script,domain=news.org'));
  assert.deepEqual(buildFilter({ action: 'block-script', target: 'example.com/t.js', site: 'nope' }), { ok: false, error: 'site' });
  assert.deepEqual(buildFilter({ action: 'block-script', target: 'two words' }), { ok: false, error: 'script' });
});

test('hide an element, everywhere or on one site', () => {
  assert.deepEqual(buildFilter({ action: 'hide-element', target: '.newsletter-popup' }), ok('##.newsletter-popup'));
  assert.deepEqual(buildFilter({ action: 'hide-element', target: '#ad', site: 'www.example.com' }), ok('example.com###ad'));
  assert.deepEqual(buildFilter({ action: 'hide-element', target: '+js(nowebrtc)' }), { ok: false, error: 'selector' });
  assert.deepEqual(buildFilter({ action: 'hide-element', target: '' }), { ok: false, error: 'selector' });
});

test('appendLine and hasFilter', () => {
  assert.equal(appendLine('', '||a.com^'), '||a.com^');
  assert.equal(appendLine('||a.com^\n\n', '||b.com^'), '||a.com^\n||b.com^');
  assert.ok(hasFilter('! c\r\n  ||a.com^  \n', '||a.com^'));
  assert.ok(!hasFilter('||a.com^$script', '||a.com^'));
});

test('export round-trips through import without duplicating the header', () => {
  const text = '||a.com^\n##.ad';
  const file = exportText(`${text}\n\n`, new Date('2026-10-19T08:00:00Z'));
  assert.match(file, /^! Title: .*\n! Exported: 2026-10-19T08:00:00.000Z\n\n\|\|a\.com\^\n##\.ad\n$/);
  const back = mergeFilters('', importedFilters(file) ?? '');
  assert.deepEqual(back, { text, added: 2, skipped: 0 });
  assert.deepEqual(mergeFilters(text, importedFilters(file) ?? ''), { text, added: 0, skipped: 2 });
});

test('import merges new filters and skips known ones', () => {
  const r = mergeFilters('||a.com^\n', '﻿! from a friend\r\n||a.com^\r\n||b.com^\r\nexample.com##.x\r\n');
  assert.equal(r.text, '||a.com^\n\n! from a friend\n||b.com^\nexample.com##.x');
  assert.equal(r.added, 2);
  assert.equal(r.skipped, 1);
});

test('import accepts a full Bastion backup and refuses other JSON or binary', () => {
  const backup = JSON.stringify({ format: 'bastion-shield-backup', version: 1, customFilters: '||x.com^' });
  assert.equal(importedFilters(backup), '||x.com^');
  assert.equal(importedFilters('{"foo":1}'), null);
  assert.equal(importedFilters('PK\u0003\u0004\u0000'), null);
  assert.equal(importedFilters('||ok.com^'), '||ok.com^');
});
