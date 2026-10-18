// Unit tests for src/content/tokens.ts (cosmetic content-script helpers).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  collectTokens,
  deAmpTarget,
  frameContext,
  hasQueuedAncestor,
  isAmpHtml,
  MAX_TOKEN_LENGTH,
  SURVEY,
  surveyTokens,
  throttleDelay,
} from '../../src/content/tokens.ts';
import type { ParentLink } from '../../src/content/tokens.ts';

test('frameContext: http(s) frames report their own URL', () => {
  assert.deepEqual(frameContext('https://www.example.com/a?b#c', 'https://www.example.com', [], true), {
    url: 'https://www.example.com/a?b#c',
    topUrl: 'https://www.example.com/a?b#c',
  });
  // Subframe: topUrl is the top origin from ancestorOrigins (last entry).
  assert.deepEqual(
    frameContext('https://ads.example.net/frame', 'https://ads.example.net', ['https://mid.example.org', 'https://news.example.com'], false),
    { url: 'https://ads.example.net/frame', topUrl: 'https://news.example.com/' },
  );
});

test('frameContext: about:blank, srcdoc, blob and data frames inherit a context', () => {
  // about:blank inherits its creator's origin.
  assert.deepEqual(frameContext('about:blank', 'https://news.example.com', ['https://news.example.com'], false), {
    url: 'https://news.example.com/',
    topUrl: 'https://news.example.com/',
  });
  // Sandboxed srcdoc: opaque origin, fall back to the parent.
  assert.deepEqual(frameContext('about:srcdoc', 'null', ['https://shop.example.org', 'https://top.example.com'], false), {
    url: 'https://shop.example.org/',
    topUrl: 'https://top.example.com/',
  });
  assert.equal(frameContext('blob:https://app.example.com/1234', 'https://app.example.com', ['https://app.example.com'], false).url, 'https://app.example.com/');
  assert.equal(frameContext('data:text/html,hi', 'null', ['https://x.example'], false).url, 'https://x.example/');
  // Nothing usable: report the raw href and let the SW decide.
  assert.deepEqual(frameContext('about:blank', 'null', [], true), { url: 'about:blank', topUrl: 'about:blank' });
  assert.deepEqual(frameContext('about:blank', 'null', null, false), { url: 'about:blank', topUrl: 'about:blank' });
  // Opaque ancestors are skipped for topUrl.
  assert.equal(frameContext('https://a.example/', 'https://a.example', ['null'], false).topUrl, 'https://a.example/');
});

test('collectTokens extracts ids and classes once', () => {
  const seen = new Set<string>();
  const out: string[] = [];
  assert.equal(collectTokens('main', ' ad-banner  sidebar\tad-banner\nfoo ', seen, out), 4);
  assert.deepEqual(out, ['#main', '.ad-banner', '.sidebar', '.foo']);
  assert.equal(collectTokens('main', 'foo bar', seen, out), 1);
  assert.deepEqual(out.slice(4), ['.bar']);
  assert.equal(collectTokens(null, null, seen, out), 0);
  assert.equal(collectTokens('', '', seen, out), 0);
  assert.equal(collectTokens('   ', '   ', seen, out), 0);
});

test('collectTokens keeps raw (unescaped) values and skips oversized or spaced ids', () => {
  const seen = new Set<string>();
  const out: string[] = [];
  collectTokens('a:b', 'x.y', seen, out);
  assert.deepEqual(out, ['#a:b', '.x.y']);
  out.length = 0;
  collectTokens('two words', 'x'.repeat(MAX_TOKEN_LENGTH + 1) + ' ok', seen, out);
  assert.deepEqual(out, ['.ok']);
  out.length = 0;
  collectTokens('i'.repeat(MAX_TOKEN_LENGTH), null, seen, out);
  assert.equal(out.length, 1);
});

test('throttleDelay', () => {
  assert.equal(throttleDelay(1000, 950, 100), 50);
  assert.equal(throttleDelay(1000, 900, 100), 0);
  assert.equal(throttleDelay(1000, -Infinity, 100), 0);
  assert.equal(SURVEY.INTERVAL_TOP, 100);
  assert.equal(SURVEY.INTERVAL_SUB, 250);
  assert.equal(SURVEY.MAX_EMPTY_FLUSHES, 20);
  assert.equal(SURVEY.IDLE_STOP_MS, 30_000);
  assert.equal(SURVEY.SLICE_MS, 4);
});

test('deAmpTarget redirects to a different http(s) canonical only', () => {
  const amp = 'https://www.example.com/amp/story.html';
  assert.equal(deAmpTarget('https://www.example.com/story.html', amp, ''), 'https://www.example.com/story.html');
  assert.equal(deAmpTarget('/story.html', amp, ''), 'https://www.example.com/story.html');
  assert.equal(deAmpTarget(amp, amp, ''), null);
  assert.equal(deAmpTarget(amp + '#top', amp, ''), null);
  assert.equal(deAmpTarget('https://www.example.com/amp/story.html/', amp, ''), null);
  assert.equal(deAmpTarget('javascript:alert(1)', amp, ''), null);
  assert.equal(deAmpTarget('ftp://example.com/x', amp, ''), null);
  assert.equal(deAmpTarget('http://www.example.com/story.html', amp, ''), null, 'no https -> http downgrade');
  assert.equal(deAmpTarget('http://www.example.com/story.html', 'http://www.example.com/amp', ''), 'http://www.example.com/story.html');
  // Coming from the canonical page means it sent us here: do not bounce back.
  assert.equal(deAmpTarget('https://www.example.com/story.html', amp, 'https://www.example.com/story.html'), null);
  assert.equal(deAmpTarget('https://www.example.com/story.html', amp, 'https://www.google.com/'), 'https://www.example.com/story.html');
  assert.equal(deAmpTarget('::::', 'not a url', ''), null);
});

test('isAmpHtml recognises amp and the lightning attribute, not amp4ads', () => {
  const attrs = (names: string[]) => (n: string) => names.includes(n);
  assert.equal(isAmpHtml(attrs(['amp'])), true);
  assert.equal(isAmpHtml(attrs(['⚡', 'lang'])), true);
  assert.equal(isAmpHtml(attrs(['⚡4ads'])), false);
  assert.equal(isAmpHtml(attrs(['amp4email'])), false);
  assert.equal(isAmpHtml(attrs([])), false);
});

/** A page-like stream of (id, class) pairs: few distinct class strings, many repeats. */
function elementStream(n: number): [string | null, string | null][] {
  const classes = ['card', 'card ad-slot', ' card  teaser	', 'nav-item', 'nav-item active', '', 'x'.repeat(MAX_TOKEN_LENGTH + 1) + ' ok', 'a b c d', 'ad-slot card'];
  const out: [string | null, string | null][] = [];
  let s = 7;
  for (let i = 0; i < n; i++) {
    s = (Math.imul(s, 1103515245) + 12345) >>> 0;
    const cls = s % 11 === 0 ? null : classes[s % classes.length];
    const id = s % 5 === 0 ? `el-${i % 97}` : s % 7 === 0 ? 'has space' : null;
    out.push([id, cls]);
  }
  return out;
}

test('surveyTokens gives exactly the collectTokens output while skipping repeated class strings', () => {
  const stream = elementStream(5000);
  const seenA = new Set<string>();
  const outA: string[] = [];
  const addedA: number[] = [];
  for (const [id, cls] of stream) addedA.push(collectTokens(id, cls, seenA, outA));

  const seenB = new Set<string>();
  const seenClass = new Set<string>();
  const outB: string[] = [];
  const addedB: number[] = [];
  for (const [id, cls] of stream) addedB.push(surveyTokens(id, cls, seenB, seenClass, outB));

  assert.deepEqual(outB, outA, 'same tokens, same order');
  assert.deepEqual(addedB, addedA, 'same per-element new-token counts (idle timer)');
  assert.deepEqual([...seenB].sort(), [...seenA].sort());
  assert.ok(seenClass.size <= 9, `distinct class strings only (${seenClass.size})`);
  assert.ok(!seenClass.has(''), 'empty class strings are not memoised');
});

test('surveyTokens stays correct when the class-string memo is full', () => {
  const seen = new Set<string>();
  const seenClass = new Set<string>();
  for (let i = 0; i < SURVEY.MAX_SEEN_CLASS_STRINGS; i++) seenClass.add(`filler-${i}`);
  const out: string[] = [];
  assert.equal(surveyTokens(null, 'fresh one', seen, seenClass, out), 2);
  assert.equal(seenClass.size, SURVEY.MAX_SEEN_CLASS_STRINGS, 'the memo does not grow past its bound');
  assert.equal(surveyTokens(null, 'fresh one', seen, seenClass, out), 0);
  assert.equal(surveyTokens('id1', 'fresh one two', seen, seenClass, out), 2);
  assert.deepEqual(out, ['.fresh', '.one', '#id1', '.two']);
  // A memoised string whose element also has a new id still reports the id.
  const s2 = new Set<string>();
  const m2 = new Set<string>();
  const o2: string[] = [];
  surveyTokens(null, 'k', s2, m2, o2);
  assert.equal(surveyTokens('new-id', 'k', s2, m2, o2), 1);
  assert.deepEqual(o2, ['.k', '#new-id']);
});

test('hasQueuedAncestor finds still-queued ancestors only, within the depth bound', () => {
  const node = (parent: ParentLink | null): ParentLink => ({ parentElement: parent });
  const root = node(null);
  const mid = node(root);
  const leaf = node(mid);
  const other = node(null);
  assert.equal(hasQueuedAncestor(leaf, new Set<ParentLink>(), 64), false);
  assert.equal(hasQueuedAncestor(leaf, new Set([root]), 64), true);
  assert.equal(hasQueuedAncestor(leaf, new Set([mid]), 64), true);
  assert.equal(hasQueuedAncestor(leaf, new Set([other]), 64), false);
  // The element itself does not count as its own ancestor.
  assert.equal(hasQueuedAncestor(mid, new Set([mid]), 64), false);
  // Depth bound: a deep chain stops looking (and then scans, the safe side).
  let deep = root;
  for (let i = 0; i < 100; i++) deep = node(deep);
  assert.equal(hasQueuedAncestor(deep, new Set([root]), 64), false);
  assert.equal(hasQueuedAncestor(deep, new Set([root]), 200), true);
});
