// Tests for the «Eigene Filter» logic (src/ui/dashboard/filters-core.ts):
// the 1 MB limit shared with the service worker, the counter parts, the
// number of unapplied changes, line reasons and the live check.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { MAX_CUSTOM_FILTERS_BYTES } from '../../src/background/store.ts';
import { changeCount, checkFilters, looksBinary, fmtLimit, fmtSize, lineCount, MAX_CUSTOM_CHARS, misspeltOption, reasonFor, suggestOption, tooBig } from '../../src/ui/dashboard/filters-core.ts';

const NBSP = ' ';

test('one limit: 1 MB (1’000’000 characters) in the editor and the service worker', () => {
  assert.equal(MAX_CUSTOM_CHARS, 1_000_000);
  assert.equal(MAX_CUSTOM_FILTERS_BYTES, MAX_CUSTOM_CHARS);
  assert.equal(tooBig('a'.repeat(MAX_CUSTOM_CHARS)), false);
  assert.equal(tooBig('a'.repeat(MAX_CUSTOM_CHARS + 1)), true);
});

test('size and limit read like the artboard («38 KB von 1 MB»), number glued to the unit', () => {
  assert.equal(fmtSize(38_000), `38${NBSP}KB`);
  assert.equal(fmtSize(37_001), `38${NBSP}KB`);
  assert.equal(fmtSize(0), `0${NBSP}KB`);
  assert.equal(fmtSize(1_300_000), `1.3${NBSP}MB`);
  assert.equal(fmtSize(1_300_000, 'fr-CH', { kb: 'Ko', mb: 'Mo' }), `1,3${NBSP}Mo`);
  assert.equal(fmtLimit(), `1${NBSP}MB`);
});

test('line count: empty editor has none, a trailing newline starts a line', () => {
  assert.equal(lineCount(''), 0);
  assert.equal(lineCount('a'), 1);
  assert.equal(lineCount('a\n'), 2);
  assert.equal(lineCount('a\nb\nc'), 3);
});

test('changes: edited, added and removed lines; moving a line is no change', () => {
  assert.equal(changeCount('a\nb', 'a\nb'), 0);
  assert.equal(changeCount('a\nb\nc', 'a\nB\nc'), 1);
  assert.equal(changeCount('a', 'a\nb\nc\nd'), 3);
  assert.equal(changeCount('a\nb\nc', 'a'), 2);
  assert.equal(changeCount('a\nb', 'b\na'), 1, 'reordered text still differs from the saved text');
});

test('misspelt options get a suggestion', () => {
  assert.equal(suggestOption('documnet'), 'document');
  assert.equal(suggestOption('scirpt'), 'script');
  assert.equal(suggestOption('thrid-party'), 'third-party');
  assert.equal(suggestOption('xyzzy'), null);
  assert.equal(misspeltOption('@@||postfinance.ch^$documnet'), 'documnet');
  assert.equal(misspeltOption('||example.com^$script'), null);
  assert.equal(misspeltOption('example.com##.ad$x'), null, 'cosmetic filters have no options');
  assert.equal(misspeltOption('! comment $documnet'), null);
});

test('every compiler code gets a plain-language reason key that exists in all locales', () => {
  const codes = [
    'unknown-option:documnet',
    'unknown-option:qqqqq',
    'unsupported-option:webrtc',
    'invalid-selector:invalid-selector',
    'unsupported:generic-procedural',
    'invalid-domain',
    'invalid-regex',
    'pattern-too-short',
    'pattern-too-long',
    'unknown-redirect-resource:foo',
    'invalid-scriptlet',
    'duplicate-option',
    'unsupported:html-filtering',
    'never-matches',
    'invalid-filter',
  ];
  const keys = new Set(codes.map((c) => reasonFor(c).key));
  assert.ok(keys.size >= 12, 'codes map to distinct reasons');
  assert.deepEqual(reasonFor('unknown-option:documnet'), { key: 'cfErrOptionSuggest', subs: ['documnet', 'document'] });
  for (const lang of ['de', 'en', 'fr', 'it']) {
    const m = JSON.parse(readFileSync(new URL(`../../src/_locales/${lang}/messages.json`, import.meta.url), 'utf8')) as Record<string, { message: string }>;
    for (const k of keys) {
      assert.ok(m[k]?.message, `${lang}: ${k}`);
      assert.ok(!m[k].message.includes('·'), `${lang}: ${k} has no middle dot`);
    }
    assert.match(m.cfTooLarge.message, /\$P1\$.*\$P2\$/, `${lang}: cfTooLarge names size and limit`);
    assert.ok(!/2 MB|2 Mo/.test(m.cfTooLarge.message + m.cfTooLargeText.message), `${lang}: no 2 MB left`);
  }
});

test('live check flags invalid lines with their line number', () => {
  const r = checkFilters(['! comment', 'watson.ch##[.native-ad', '@@||postfinance.ch^$documnet', '||ads.example.com^', 'example.com##.banner'].join('\n'), null);
  assert.deepEqual(
    r.errors.map((e) => [e.line, reasonFor(e.reason).key]),
    [
      [2, 'cfErrSelector'],
      [3, 'cfErrOptionSuggest'],
    ],
  );
  assert.ok(r.network >= 1);
  assert.equal(r.cosmetic, 1);
});

test('binary files are not filter lists', () => {
  assert.equal(looksBinary('PK\u0003\u0004\u0014\u0000 xl/workbook.xml'), true);
  assert.equal(looksBinary('||ads.example^\n\tindented\r\n'), false);
});
