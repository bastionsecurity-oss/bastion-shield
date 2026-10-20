// Unit tests for the procedural engine: argument parsing (procedural-args.ts)
// and selector evaluation (procedural-engine.ts) on a tiny fake DOM. The
// real-DOM behaviour is covered by test/fixtures/procedural.html in e2e.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isSafeStyle,
  parseAttrArg,
  parseAttrList,
  parseCssArg,
  parseMinTextLength,
  parseUpward,
  regexFromString,
  textArg,
  unquote,
} from '../../src/content/procedural-args.ts';
import { cssForFilter, normalizeAction, PSelector } from '../../src/content/procedural-engine.ts';
import type { ProceduralFilter } from '../../src/shared/types.ts';

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

test('unquote follows uBO rules', () => {
  assert.equal(unquote('"abc"'), 'abc');
  assert.equal(unquote("'a\"b'"), 'a"b');
  assert.equal(unquote('"a\\"b"'), 'a"b');
  assert.equal(unquote('"a\\\\b"'), 'a\\b');
  assert.equal(unquote('"a\\nb"'), 'a\\nb', 'other escapes stay');
  assert.equal(unquote('abc'), 'abc');
  assert.equal(unquote('"abc'), '"abc', 'unterminated');
  assert.equal(unquote('"a"b'), '"a"b', 'trailing text: not one token');
  assert.equal(unquote('"'), '"');
  assert.equal(unquote(''), '');
});

test('regexFromString: literals, regexes, flags and invalid input', () => {
  assert.equal(regexFromString('Sponsored')!.test('xx Sponsored yy'), true);
  assert.equal(regexFromString('a.b')!.test('axb'), false, 'literal dot');
  assert.equal(regexFromString('a.b', true)!.test('a.b'), true);
  assert.equal(regexFromString('a.b', true)!.test('xa.b'), false);
  assert.equal(regexFromString('/^ad\\d+$/')!.test('ad42'), true);
  assert.equal(regexFromString('/anzeige/i')!.test('ANZEIGE'), true);
  assert.equal(regexFromString('/x/g')!.test('/x/g'), true, 'g is not an allowed flag: literal');
  assert.equal(regexFromString('/(unclosed/'), null);
  assert.equal(regexFromString('')!.test('anything'), true);
});

test('parseAttrArg covers uBO forms', () => {
  assert.deepEqual(parseAttrArg('data-ad'), { attr: 'data-ad', value: '' });
  assert.deepEqual(parseAttrArg('data-ad=top'), { attr: 'data-ad', value: 'top' });
  assert.deepEqual(parseAttrArg('"data-ad"="/^top/"'), { attr: 'data-ad', value: '/^top/' });
  assert.deepEqual(parseAttrArg("'/^data-/'"), { attr: '/^data-/', value: '' });
  assert.deepEqual(parseAttrArg('"class=ad"'), { attr: 'class', value: 'ad' }, 'one quoted token is split');
  assert.deepEqual(parseAttrArg('tagName=SECTION'), { attr: 'tagName', value: 'SECTION' });
  assert.deepEqual(parseAttrArg({ attr: 'x', value: 'y' }), { attr: 'x', value: 'y' });
  assert.equal(parseAttrArg(''), null);
  assert.equal(parseAttrArg('"a"x'), null);
  assert.equal(parseAttrArg('a="b'), null);
  assert.equal(parseAttrArg('=x'), null);
  assert.equal(parseAttrArg(42), null);
});

test('parseCssArg: names, pseudo prefixes, literal and regex values', () => {
  const a = parseCssArg('position: fixed', null)!;
  assert.equal(a.name, 'position');
  assert.equal(a.pseudo, null);
  assert.equal(a.re.test('fixed'), true);
  assert.equal(a.re.test('fixedx'), false, 'literal values match the whole value');
  const b = parseCssArg('content: /AD/', '::before')!;
  assert.equal(b.pseudo, '::before');
  assert.equal(b.re.test('"AD"'), true);
  const c = parseCssArg('after, content: /^"x"$/i', null)!;
  assert.equal(c.pseudo, '::after');
  assert.equal(c.re.test('"X"'), true);
  const d = parseCssArg('background-image: url("a.png")', null)!;
  assert.equal(d.re.test('url("a.png")'), true, 'special characters are escaped');
  const e = parseCssArg({ name: 'z-index', value: ['^9+$', 'i'] }, null)!;
  assert.equal(e.re.test('999'), true);
  assert.equal(parseCssArg('no-colon', null), null);
  assert.equal(parseCssArg(': x', null), null);
  assert.equal(parseCssArg('a: /(/', null), null);
});

test('small argument parsers', () => {
  assert.deepEqual(parseAttrList('class, data-x ,,id'), ['class', 'data-x', 'id']);
  assert.deepEqual(parseAttrList(''), []);
  assert.deepEqual(parseAttrList(['a', 1, '']), ['a']);
  assert.equal(parseUpward(2), 2);
  assert.equal(parseUpward('3'), 3);
  assert.equal(parseUpward('.box'), '.box');
  assert.equal(parseUpward(0), null);
  assert.equal(parseUpward(256), null);
  assert.equal(parseUpward('0'), null);
  assert.equal(parseUpward(1.5), null);
  assert.equal(parseUpward(''), null);
  assert.equal(parseMinTextLength(40), 40);
  assert.equal(parseMinTextLength(' 12 '), 12);
  assert.equal(parseMinTextLength('x'), null);
  assert.equal(parseMinTextLength(-1), null);
  assert.equal(textArg('"quoted"'), 'quoted');
  assert.equal(textArg(5), null);
});

test('isSafeStyle blocks resource loads and rule escapes', () => {
  assert.equal(isSafeStyle('opacity: 0.5 !important'), true);
  assert.equal(isSafeStyle('height: 0 !important; visibility: hidden'), true);
  assert.equal(isSafeStyle('background: url(https://evil.example/x)'), false);
  assert.equal(isSafeStyle('background-image: image-set("a.png" 1x)'), false);
  assert.equal(isSafeStyle('color: red } body { display: none'), false);
  assert.equal(isSafeStyle('color: red /* x */'), false);
  assert.equal(isSafeStyle('content: "\\41"'), false);
  assert.equal(isSafeStyle(''), false);
  assert.equal(isSafeStyle(undefined), false);
});

test('normalizeAction and cssForFilter', () => {
  assert.deepEqual(normalizeAction(undefined), { op: 'hide' });
  assert.deepEqual(normalizeAction(['style', 'opacity: 0']), { op: 'style', style: 'opacity: 0' });
  assert.equal(normalizeAction(['style', 'background: url(x)']), null);
  assert.deepEqual(normalizeAction(['remove']), { op: 'remove' });
  assert.equal(normalizeAction(['remove-attr', '']), null);
  assert.equal((normalizeAction(['remove-attr', 'data-track']) as { re: RegExp }).re.test('data-track'), true);
  assert.equal((normalizeAction(['remove-class', '/^ad-/']) as { re: RegExp }).re.test('ad-x'), true);
  assert.equal(normalizeAction(['explode']), null);
  assert.equal(normalizeAction('remove'), null);

  const ok = () => true;
  const f = (o: Partial<ProceduralFilter>): ProceduralFilter => ({ raw: 'r', selector: '', tasks: [], ...o });
  assert.equal(cssForFilter(f({ selector: '.ad' }), { op: 'hide' }, ok), '.ad{display:none!important}');
  assert.equal(cssForFilter(f({ selector: '.ad' }), { op: 'style', style: 'opacity:0' }, ok), '.ad{opacity:0}');
  assert.equal(cssForFilter(f({ selector: '.ad' }), { op: 'remove' }, ok), null);
  assert.equal(cssForFilter(f({ selector: '' }), { op: 'hide' }, ok), null);
  assert.equal(
    cssForFilter(f({ selector: '.ad', tasks: [['matches-media', '(max-width: 600px)']] }), { op: 'hide' }, ok),
    '@media (max-width: 600px){.ad{display:none!important}}',
  );
  assert.equal(
    cssForFilter(f({ selector: '', tasks: [['matches-media', '(min-width: 1px)'], ['spath', ' .x > .y']] }), { op: 'hide' }, ok),
    '@media (min-width: 1px){.x > .y{display:none!important}}',
  );
  assert.equal(cssForFilter(f({ selector: '.ad', tasks: [['matches-media', 'x{}']] }), { op: 'hide' }, ok), null);
  assert.equal(cssForFilter(f({ selector: '.ad', tasks: [['matches-media', 'junk']] }), { op: 'hide' }, () => false), null);
  assert.equal(cssForFilter(f({ selector: '.ad', tasks: [['has-text', 'x']] }), { op: 'hide' }, ok), null);
});

// ---------------------------------------------------------------------------
// Evaluation on a fake DOM (only what the tested tasks touch)
// ---------------------------------------------------------------------------

class FakeEl {
  readonly nodeType = 1;
  readonly localName: string;
  readonly classes: Set<string>;
  readonly attrs = new Map<string, string>();
  readonly children: FakeEl[] = [];
  parentElement: FakeEl | null = null;
  private ownText: string;
  [k: string]: unknown;

  constructor(tag: string, opts: { cls?: string; text?: string; attrs?: Record<string, string> } = {}, kids: FakeEl[] = []) {
    this.localName = tag;
    this.classes = new Set((opts.cls ?? '').split(' ').filter(Boolean));
    this.ownText = opts.text ?? '';
    for (const [k, v] of Object.entries(opts.attrs ?? {})) this.attrs.set(k, v);
    if (opts.cls) this.attrs.set('class', opts.cls);
    for (const k of kids) {
      k.parentElement = this;
      this.children.push(k);
    }
  }
  get tagName(): string {
    return this.localName.toUpperCase();
  }
  get textContent(): string {
    return this.ownText + this.children.map((c) => c.textContent).join('');
  }
  getAttributeNames(): string[] {
    return [...this.attrs.keys()];
  }
  getAttribute(n: string): string | null {
    return this.attrs.get(n) ?? null;
  }
  /** Supports "tag", ".class" and "tag.class" only. */
  matches(sel: string): boolean {
    const m = /^([a-z]*)(?:\.([\w-]+))?$/.exec(sel.trim());
    if (m === null) throw new Error('unsupported selector in fake DOM: ' + sel);
    return (m[1] === '' || m[1] === this.localName) && (m[2] === undefined || this.classes.has(m[2]));
  }
  querySelectorAll(sel: string): FakeEl[] {
    const out: FakeEl[] = [];
    const walk = (e: FakeEl): void => {
      for (const c of e.children) {
        if (c.matches(sel)) out.push(c);
        walk(c);
      }
    };
    walk(this);
    return out;
  }
  closest(sel: string): FakeEl | null {
    let e: FakeEl | null = this;
    while (e !== null && !e.matches(sel)) e = e.parentElement;
    return e;
  }
  contains(o: FakeEl): boolean {
    for (let e: FakeEl | null = o; e !== null; e = e.parentElement) if (e === this) return true;
    return false;
  }
}

const el = (tag: string, opts?: ConstructorParameters<typeof FakeEl>[1], kids?: FakeEl[]) => new FakeEl(tag, opts, kids);

function run(filter: Partial<ProceduralFilter>, root: FakeEl): FakeEl[] {
  const ps = new PSelector(null, { raw: 'test', selector: '', tasks: [], ...filter });
  return ps.exec(root as unknown as Element) as unknown as FakeEl[];
}

test('has-text and min-text-length', () => {
  const a = el('div', { cls: 'card', text: 'Sponsored post' });
  const b = el('div', { cls: 'card', text: 'Regular post' });
  const root = el('body', {}, [a, b]);
  assert.deepEqual(run({ selector: '.card', tasks: [['has-text', 'Sponsored']] }, root), [a]);
  assert.deepEqual(run({ selector: '.card', tasks: [['has-text', '/^regular/i']] }, root), [b]);
  assert.deepEqual(run({ selector: '.card', tasks: [['has-text', '"Regular"']] }, root), [b], 'quoted text is unquoted');
  assert.deepEqual(run({ selector: '.card', tasks: [['has-text', '/(/']] }, root), [], 'invalid regex matches nothing');
  assert.deepEqual(run({ selector: '.card', tasks: [['min-text-length', 13]] }, root), [a]);
});

test('has / if / if-not / not with nested procedural selectors', () => {
  const p1 = el('div', { cls: 'item' }, [el('span', { cls: 'label', text: 'Promoted' })]);
  const p2 = el('div', { cls: 'item' }, [el('span', { cls: 'label', text: 'News' })]);
  const p3 = el('div', { cls: 'item', text: 'no label' });
  const root = el('body', {}, [p1, p2, p3]);
  const inner = { raw: '', selector: '.label', tasks: [['has-text', 'Promoted']] };
  assert.deepEqual(run({ selector: '.item', tasks: [['has', inner as ProceduralFilter]] }, root), [p1]);
  assert.deepEqual(run({ selector: '.item', tasks: [['if', inner as ProceduralFilter]] }, root), [p1]);
  assert.deepEqual(run({ selector: '.item', tasks: [['if-not', inner as ProceduralFilter]] }, root), [p2, p3]);
  assert.deepEqual(run({ selector: '.item', tasks: [['if-not', '.label' as unknown as ProceduralFilter]] }, root), [p3], 'string argument = plain selector');
  const self = { raw: '', selector: '', tasks: [['has-text', 'News']] };
  assert.deepEqual(run({ selector: '.item', tasks: [['not', self as ProceduralFilter]] }, root), [p1, p3]);
});

test('matches-attr and matches-prop', () => {
  const a = el('div', { cls: 'slot', attrs: { 'data-ad-slot': 'top-1' } });
  const b = el('div', { cls: 'slot', attrs: { 'data-ad-slot': 'side' } });
  const c = el('section', { cls: 'slot', attrs: { 'data-x': 'y' } });
  const root = el('body', {}, [a, b, c]);
  assert.deepEqual(run({ selector: '.slot', tasks: [['matches-attr', '"data-ad-slot"="/^top/"']] }, root), [a]);
  assert.deepEqual(run({ selector: '.slot', tasks: [['matches-attr', '/^data-/']] }, root), [a, b, c]);
  assert.deepEqual(run({ selector: '.slot', tasks: [['matches-attr', 'data-ad-slot=side']] }, root), [b]);
  assert.deepEqual(run({ selector: '.slot', tasks: [['matches-attr', '"broken']] }, root), []);
  assert.deepEqual(run({ selector: '.slot', tasks: [['matches-prop', 'tagName=SECTION']] }, root), [c]);
  assert.deepEqual(run({ selector: '.slot', tasks: [['matches-prop', 'localName']] }, root), [a, b, c]);
  assert.deepEqual(run({ selector: '.slot', tasks: [['matches-prop', 'nothere']] }, root), []);
  assert.deepEqual(run({ selector: '.slot', tasks: [['matches-prop', 'parentElement.localName=body']] }, root), [a, b, c]);
});

test('upward by count and by selector', () => {
  const target = el('span', { cls: 'target' });
  const parent = el('div', { cls: 'p' }, [target]);
  const gp = el('div', { cls: 'box' }, [parent]);
  const root = el('body', {}, [gp]);
  assert.deepEqual(run({ selector: '.target', tasks: [['upward', 2]] }, root), [gp]);
  assert.deepEqual(run({ selector: '.target', tasks: [['upward', '1']] }, root), [parent]);
  assert.deepEqual(run({ selector: '.target', tasks: [['upward', '.box']] }, root), [gp]);
  assert.deepEqual(run({ selector: '.target', tasks: [['upward', 9]] }, root), [], 'beyond the root');
  assert.deepEqual(run({ selector: '.target', tasks: [['upward', 0]] }, root), [], 'invalid count');
});

test('spath continues the search below matched nodes', () => {
  const ad = el('div', { cls: 'ad' });
  const wrap = el('div', { cls: 'wrap', text: 'Sponsored' }, [ad]);
  const other = el('div', { cls: 'wrap', text: 'plain' }, [el('div', { cls: 'ad' })]);
  const root = el('body', {}, [wrap, other]);
  assert.deepEqual(run({ selector: '.wrap', tasks: [['has-text', 'Sponsored'], ['spath', ' .ad']] }, root), [ad]);
});

test('unknown operators and malformed tasks match nothing', () => {
  const a = el('div', { cls: 'card', text: 'x' });
  const root = el('body', {}, [a]);
  assert.deepEqual(run({ selector: '.card', tasks: [['no-such-op', 'x'] as unknown as ['has-text', string]] }, root), []);
  assert.deepEqual(run({ selector: '.card', tasks: ['garbage' as unknown as ['has-text', string]] }, root), []);
  assert.deepEqual(run({ selector: '.card' }, root), [a], 'no tasks: the selector alone');
});

test('PSelector.test is used for :has() semantics on the node itself', () => {
  const a = el('div', { text: 'Keep' });
  const ps = new PSelector(null, { raw: '', selector: '', tasks: [['has-text', 'Keep']] });
  assert.equal(ps.test(a as unknown as Element), true);
  const ps2 = new PSelector(null, { raw: '', selector: '', tasks: [['has-text', 'Drop']] });
  assert.equal(ps2.test(a as unknown as Element), false);
});
