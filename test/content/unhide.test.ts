// Unit tests for Brave's Standard-mode un-hiding heuristic (content/unhide.ts)
// on a tiny fake DOM. The real-DOM behaviour is covered by
// test/e2e/specs/04c-unhide.spec.ts.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { firstPartyTest, isSubtreeFirstParty, showsSignificantText, UnhideQueues } from '../../src/content/unhide.ts';
import type { WalkNode } from '../../src/content/unhide.ts';

// ---------------------------------------------------------------------------
// Fake DOM
// ---------------------------------------------------------------------------

class FakeNode implements WalkNode {
  nodeType: number;
  firstChild: FakeNode | null = null;
  nextSibling: FakeNode | null = null;
  parentNode: FakeNode | null = null;
  tag: string;
  attrs: Record<string, string>;
  text: string;
  constructor(nodeType: number, tag = '', attrs: Record<string, string> = {}, text = '') {
    this.nodeType = nodeType;
    this.tag = tag;
    this.attrs = attrs;
    this.text = text;
  }
  getAttribute(name: string): string | null {
    return this.nodeType === 1 && Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name] : null;
  }
  get innerText(): string {
    if (this.nodeType === 3) return this.text;
    let out = '';
    for (let c = this.firstChild; c !== null; c = c.nextSibling) out += c.innerText;
    return out;
  }
  getElementsByTagName(name: string): FakeNode[] {
    const out: FakeNode[] = [];
    const walk = (n: FakeNode): void => {
      for (let c = n.firstChild; c !== null; c = c.nextSibling) {
        if (c.nodeType === 1 && c.tag === name) out.push(c);
        walk(c);
      }
    };
    walk(this);
    return out;
  }
}

function el(tag: string, attrs: Record<string, string> = {}, ...children: (FakeNode | string)[]): FakeNode {
  const n = new FakeNode(1, tag, attrs);
  let prev: FakeNode | null = null;
  for (const ch of children) {
    const c = typeof ch === 'string' ? new FakeNode(3, '', {}, ch) : ch;
    c.parentNode = n;
    if (prev === null) n.firstChild = c;
    else prev.nextSibling = c;
    prev = c;
  }
  return n;
}

/** Wrap nodes as siblings under a parent (for "the walk stays in the subtree" checks). */
function siblings(...nodes: FakeNode[]): FakeNode {
  return el('section', {}, ...nodes);
}

const fp = firstPartyTest('20min.ch', 'https://www.20min.ch/story/x');

// ---------------------------------------------------------------------------
// First-party URLs
// ---------------------------------------------------------------------------

test('first-party URLs: relative, same site, subdomains (Brave isFirstPartyUrl)', () => {
  assert.equal(fp('/img/a.jpg'), true);
  assert.equal(fp('img/a.jpg'), true);
  assert.equal(fp('data:image/gif;base64,R0lGOD'), true, 'not //, http:// or https://: relative for Brave');
  assert.equal(fp('https://www.20min.ch/a.png'), true);
  assert.equal(fp('https://media.20min.ch/a.png'), true);
  assert.equal(fp('//cdn.20min.ch/a.png'), true);
  assert.equal(fp('https://20min.ch./a.png'), true, 'trailing dot');
  assert.equal(fp('https://securepubads.g.doubleclick.net/x'), false);
  assert.equal(fp('https://not20min.ch/a.png'), false);
  assert.equal(fp('https://20min.ch.evil.example/a.png'), false);
  assert.equal(fp('http://[bad/'), false, 'unparseable absolute URL');
  const ip = firstPartyTest('127.0.0.1', 'http://127.0.0.1/');
  assert.equal(ip('http://127.0.0.1:8080/x'), true);
  assert.equal(ip('http://127.0.0.2/x'), false);
});

// ---------------------------------------------------------------------------
// First-party subtrees
// ---------------------------------------------------------------------------

test('subtree: no remote resources at all counts as first party (empty ad slot)', () => {
  assert.equal(isSubtreeFirstParty(el('div', { class: 'ad' }), fp), true);
  assert.equal(isSubtreeFirstParty(el('div', { class: 'ad' }, 'Werbung'), fp), true);
});

test('subtree: a first-party src anywhere makes it first party, even after a third-party one', () => {
  const t = el('div', {}, el('img', { src: 'https://ads.example.net/a.gif' }), el('a', {}, el('img', { src: '/teaser.jpg' })));
  assert.equal(isSubtreeFirstParty(t, fp), true);
});

test('subtree: a third-party src, url() or // in style, or an empty srcdoc make it third party', () => {
  assert.equal(isSubtreeFirstParty(el('div', {}, el('iframe', { src: 'https://ads.example.net/frame' })), fp), false);
  assert.equal(isSubtreeFirstParty(el('div', { style: 'background:url(x.png)' }), fp), false);
  assert.equal(isSubtreeFirstParty(el('div', {}, el('span', { style: 'background-image: //x' })), fp), false);
  assert.equal(isSubtreeFirstParty(el('div', {}, el('iframe', { srcdoc: '  ' })), fp), false);
  assert.equal(isSubtreeFirstParty(el('div', {}, el('iframe', { srcdoc: '<p>x</p>' })), fp), true);
});

test('subtree: known ad ids are third party at once, before a first-party src later on', () => {
  for (const id of ['google_ads_iframe_/123/x_0', 'div-gpt-ad-1234', 'adfox_42']) {
    const t = el('div', {}, el('div', { id }), el('img', { src: '/own.jpg' }));
    assert.equal(isSubtreeFirstParty(t, fp), false, id);
  }
  // Document order: the first-party src comes first and decides.
  assert.equal(isSubtreeFirstParty(el('div', {}, el('img', { src: '/own.jpg' }), el('div', { id: 'div-gpt-ad-1' })), fp), true);
  assert.equal(isSubtreeFirstParty(el('div', { id: 'div-gpt-ad-1' }), fp), false, 'the root itself');
});

test("subtree: only the root's own subtree is walked (Brave also walks its following siblings)", () => {
  const ad = el('div', { class: 'ad' }, el('iframe', { src: 'https://ads.example.net/f' }));
  siblings(ad, el('img', { src: '/own.jpg' }));
  assert.equal(isSubtreeFirstParty(ad, fp), false);
  const empty = el('div', { class: 'ad' });
  siblings(empty, el('iframe', { src: 'https://ads.example.net/f' }));
  assert.equal(isSubtreeFirstParty(empty, fp), true);
  const deep = el('div', {}, el('p', {}, el('span', {}, 'x')), el('p', {}, el('img', { src: 'https://ads.example.net/a' })));
  siblings(deep, el('img', { src: '/own.jpg' }));
  assert.equal(isSubtreeFirstParty(deep, fp), false, 'climbing back up stops at the root');
});

test('subtree: a node budget keeps the walk bounded (third party when exceeded)', () => {
  const kids = Array.from({ length: 50 }, () => el('span'));
  const big = el('div', {}, ...kids);
  assert.equal(isSubtreeFirstParty(big, fp, 1000), true);
  assert.equal(isSubtreeFirstParty(big, fp, 10), false);
});

// ---------------------------------------------------------------------------
// Significant text
// ---------------------------------------------------------------------------

test('text: at least 30 characters and 5 words (Brave minAdTextChars / minAdTextWords)', () => {
  assert.equal(showsSignificantText(el('div', {}, 'Anzeige')), false);
  assert.equal(showsSignificantText(el('div', {}, 'Bastion e2e test element')), false, '24 characters');
  assert.equal(showsSignificantText(el('div', {}, 'Supercalifragilisticexpialidocious-word')), false, 'one long word');
  assert.equal(showsSignificantText(el('div', {}, 'one two three four fivefivefivefive')), true);
  assert.equal(showsSignificantText(el('div', {}, 'one two three four\nfivefivefivefivefive')), false, 'Brave splits on spaces only');
  assert.equal(showsSignificantText(el('div', {}, '   Zürich: Tram fällt heute aus, weil   ')), true);
});

test('text: script and style contents do not count', () => {
  const t = el('div', {}, 'Ad', el('script', {}, 'var a = 1; var b = 2; var c = 3; var d = 4;'), el('style', {}, '.a { color: red } .b { color: blue }'));
  assert.equal(showsSignificantText(t), false);
  const real = el('div', {}, el('h2', {}, 'Der Bundesrat will die Regeln für E-Trottinette verschärfen'), el('script', {}, 'x()'));
  assert.equal(showsSignificantText(real), true);
});

test('text: nodes without innerText are not significant', () => {
  assert.equal(showsSignificantText({ getElementsByTagName: () => [] }), false);
});

// ---------------------------------------------------------------------------
// Queues
// ---------------------------------------------------------------------------

test('queues: three passes, first queue first, at most the work size per pump', () => {
  const q = new UnhideQueues();
  assert.equal(q.add(['.a', '.b', '.c', '.a', '', 42 as unknown as string]), 3);
  assert.equal(q.add(['.a']), 0, 'a selector is queued once per frame');
  const w1 = q.next(2)!;
  assert.deepEqual(w1, { queue: 0, selectors: ['.a', '.b'] });
  q.settle(w1, new Set(['.b']));
  const w2 = q.next(2)!;
  assert.deepEqual(w2, { queue: 0, selectors: ['.c'] }, 'queue 0 drains before queue 1');
  q.settle(w2, new Set());
  q.add(['.d']);
  const w3 = q.next(5)!;
  assert.deepEqual(w3, { queue: 0, selectors: ['.d'] }, 'new selectors jump ahead');
  q.settle(w3, new Set(['.d']));
  const w4 = q.next(5)!;
  assert.deepEqual(w4, { queue: 1, selectors: ['.a', '.c'] });
  q.settle(w4, new Set());
  const w5 = q.next(5)!;
  assert.deepEqual(w5, { queue: 2, selectors: ['.a', '.c'] });
  q.settle(w5, new Set(['.c']));
  assert.equal(q.pending, 0, 'after the third pass the rest stays hidden');
  assert.equal(q.next(), null);
  assert.equal(q.add(['.a', '.b']), 0, 'settled selectors are never queued again');
});
