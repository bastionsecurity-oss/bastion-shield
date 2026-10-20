// Bastion Shield — procedural cosmetic filtering engine.
//
// A TypeScript port of uBlock Origin Lite's css-procedural-api.js (GPL-3.0,
// Copyright Raymond Hill) with the same operator semantics, per-filter time
// budget and un-hide behaviour, adapted to Bastion's ProceduralFilter format
// (shared/types.ts) and hardened against malformed input: every argument is
// parsed by procedural-args.ts, an invalid argument makes its filter match
// nothing, and no exception leaves a filter evaluation.
//
// Hiding uses one attribute per style (`bastion-hide-<random>` for the
// default display:none, `bastion-style-<random>` for :style()) plus one rule
// per attribute in a constructed stylesheet. The Bastion prefix keeps the
// effect inspectable in DevTools (transparency principle).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/*! Procedural filtering engine: port of uBlock Origin Lite css-procedural-api.js, Copyright (C) Raymond Hill, GPL-3.0-or-later. Modified by Bastion Security GmbH. */

import type { ProceduralFilter } from '../shared/types.ts';
import type { CssArg } from './procedural-args.ts';
import {
  isSafeStyle,
  parseAttrArg,
  parseAttrList,
  parseCssArg,
  parseMinTextLength,
  parseUpward,
  regexFromString,
  textArg,
} from './procedural-args.ts';

/** Receives "something changed, re-evaluate" signals from observing tasks. */
export interface EngineHost {
  domChanged(): void;
}

type Root = Element | Document;

const NON_VISUAL = new Set(['head', 'link', 'meta', 'script', 'style']);

function textOf(n: Node): string {
  return n.textContent ?? '';
}

/** Base task: transposes nothing (also the behaviour of unknown operators). */
class PTask {
  begin(): void {}
  end(_out: Element[]): void {}
  destroy(): void {}
  transpose(_node: Element, _out: Element[]): void {}
}

class HasTextTask extends PTask {
  private re: RegExp | null;
  constructor(arg: unknown) {
    super();
    const t = textArg(arg);
    this.re = t === null ? null : regexFromString(t);
  }
  transpose(node: Element, out: Element[]): void {
    if (this.re !== null && this.re.test(textOf(node))) out.push(node);
  }
}

class IfTask extends PTask {
  private inner: PSelector;
  private target: boolean;
  constructor(host: EngineHost | null, arg: unknown, target: boolean) {
    super();
    this.inner = new PSelector(host, typeof arg === 'string' ? { selector: arg, tasks: [] } : arg);
    this.target = target;
  }
  transpose(node: Element, out: Element[]): void {
    if (this.inner.test(node) === this.target) out.push(node);
  }
  destroy(): void {
    this.inner.destroy();
  }
}

class MatchesAttrTask extends PTask {
  private reAttr: RegExp | null = null;
  private reValue: RegExp | null = null;
  constructor(arg: unknown) {
    super();
    const a = parseAttrArg(arg);
    if (a === null) return;
    this.reAttr = regexFromString(a.attr, true);
    this.reValue = regexFromString(a.value, true);
  }
  transpose(node: Element, out: Element[]): void {
    const ra = this.reAttr;
    const rv = this.reValue;
    if (ra === null || rv === null || typeof node.getAttributeNames !== 'function') return;
    for (const name of node.getAttributeNames()) {
      if (!ra.test(name)) continue;
      if (!rv.test(node.getAttribute(name) ?? '')) continue;
      out.push(node);
      return;
    }
  }
}

class MatchesCssTask extends PTask {
  private a: CssArg | null;
  constructor(arg: unknown, pseudoDefault: string | null) {
    super();
    this.a = parseCssArg(arg, pseudoDefault);
  }
  transpose(node: Element, out: Element[]): void {
    const a = this.a;
    if (a === null) return;
    const style = getComputedStyle(node, a.pseudo);
    if (style === null) return;
    let v = style.getPropertyValue(a.name);
    if (v === '') {
      // camelCase names ("zIndex") only resolve as named properties.
      const alt = (style as unknown as Record<string, unknown>)[a.name];
      if (typeof alt === 'string') v = alt;
    }
    if (a.re.test(v)) out.push(node);
  }
}

class MatchesMediaTask extends PTask {
  private mql: MediaQueryList | null = null;
  private onChange: (() => void) | null = null;
  constructor(host: EngineHost | null, arg: unknown) {
    super();
    const q = textArg(arg);
    if (q === null || q === '') return;
    try {
      this.mql = matchMedia(q);
    } catch {
      return;
    }
    if (this.mql.media === 'not all' || host === null) return;
    this.onChange = () => host.domChanged();
    this.mql.addEventListener('change', this.onChange);
  }
  transpose(node: Element, out: Element[]): void {
    if (this.mql !== null && this.mql.matches) out.push(node);
  }
  destroy(): void {
    if (this.mql !== null && this.onChange !== null) this.mql.removeEventListener('change', this.onChange);
  }
}

let navigationHooked = false;

class MatchesPathTask extends PTask {
  private re: RegExp | null;
  constructor(host: EngineHost | null, arg: unknown) {
    super();
    const t = textArg(arg);
    this.re = t === null ? null : regexFromString(t.replace(/\P{ASCII}/gu, (c) => encodeURIComponent(c)));
    if (navigationHooked || host === null) return;
    navigationHooked = true;
    // Same-document navigations (SPA route changes) do not mutate the DOM by
    // themselves; re-evaluate when the URL changes.
    try {
      const nav = (self as unknown as { navigation?: EventTarget }).navigation;
      if (nav !== undefined && typeof nav.addEventListener === 'function') {
        nav.addEventListener('navigate', () => host.domChanged());
      } else {
        self.addEventListener('popstate', () => host.domChanged());
        self.addEventListener('hashchange', () => host.domChanged());
      }
    } catch {
      // ignore
    }
  }
  transpose(node: Element, out: Element[]): void {
    if (this.re !== null && this.re.test(location.pathname + location.search)) out.push(node);
  }
}

class MatchesPropTask extends PTask {
  private props: string[] = [];
  private reValue: RegExp | null = null;
  private valid = false;
  constructor(arg: unknown) {
    super();
    const a = parseAttrArg(arg);
    if (a === null) return;
    this.props = a.attr.split('.');
    if (a.value !== '') {
      this.reValue = regexFromString(a.value, true);
      if (this.reValue === null) return;
    }
    this.valid = true;
  }
  transpose(node: Element, out: Element[]): void {
    if (!this.valid) return;
    let value: unknown = node;
    for (const prop of this.props) {
      if (value === undefined || value === null) return;
      value = (value as Record<string, unknown>)[prop];
    }
    if (this.reValue === null) {
      if (value === undefined) return;
    } else if (!this.reValue.test(String(value))) {
      return;
    }
    out.push(node);
  }
}

class MinTextLengthTask extends PTask {
  private min: number | null;
  constructor(arg: unknown) {
    super();
    this.min = parseMinTextLength(arg);
  }
  transpose(node: Element, out: Element[]): void {
    if (this.min !== null && textOf(node).length >= this.min) out.push(node);
  }
}

/** :others() — everything visible except the targets, their ancestors and their descendants. */
class OthersTask extends PTask {
  private targets = new Set<Element>();
  begin(): void {
    this.targets.clear();
  }
  end(out: Element[]): void {
    const toKeep = new Set(this.targets);
    const toDiscard = new Set<Element>();
    const doc = typeof document !== 'undefined' ? document : null;
    const body = doc?.body ?? null;
    const head = doc?.head ?? null;
    for (const keep of this.targets) {
      let k: Element | null = keep;
      while (k !== null && k !== body && k !== head) {
        toKeep.add(k);
        toDiscard.delete(k);
        let d = k.previousElementSibling;
        while (d !== null) {
          if (!NON_VISUAL.has(d.localName) && !toKeep.has(d)) toDiscard.add(d);
          d = d.previousElementSibling;
        }
        d = k.nextElementSibling;
        while (d !== null) {
          if (!NON_VISUAL.has(d.localName) && !toKeep.has(d)) toDiscard.add(d);
          d = d.nextElementSibling;
        }
        k = k.parentElement;
      }
    }
    for (const d of toDiscard) out.push(d);
    this.targets.clear();
  }
  transpose(candidate: Element): void {
    for (const target of this.targets) {
      if (target.contains(candidate)) return;
      if (candidate.contains(target)) this.targets.delete(target);
    }
    this.targets.add(candidate);
  }
}

type ShadowRootGetter = (el: Element) => ShadowRoot | null;
let shadowRootGetter: ShadowRootGetter | null = null;

function openOrClosedShadowRoot(el: Element): ShadowRoot | null {
  if (shadowRootGetter === null) {
    // chrome.dom.openOrClosedShadowRoot (content scripts only) also reaches closed roots.
    const dom = (globalThis as unknown as { chrome?: { dom?: { openOrClosedShadowRoot?: ShadowRootGetter } } }).chrome?.dom;
    const f = dom?.openOrClosedShadowRoot;
    shadowRootGetter =
      typeof f === 'function'
        ? (e) => {
            try {
              return f.call(dom, e) ?? null;
            } catch {
              return e.shadowRoot;
            }
          }
        : (e) => e.shadowRoot;
  }
  return shadowRootGetter(el);
}

class ShadowTask extends PTask {
  private selector: string;
  constructor(arg: unknown) {
    super();
    this.selector = typeof arg === 'string' ? arg : '';
  }
  transpose(node: Element, out: Element[]): void {
    if (this.selector === '') return;
    const root = openOrClosedShadowRoot(node);
    if (root === null) return;
    const nodes = root.querySelectorAll(this.selector);
    for (let i = 0; i < nodes.length; i++) out.push(nodes[i]);
  }
}

/** Siblings of `node` matching a selector that starts with "+", "~" or ":" (uBO's nth-child trick). */
export function siblingQsa(node: Element, selector: string): ArrayLike<Element> {
  const parent = node.parentElement;
  if (parent === null) return [];
  let pos = 1;
  let n: Element | null = node;
  for (;;) {
    n = n.previousElementSibling;
    if (n === null) break;
    pos += 1;
  }
  return parent.querySelectorAll(`:scope > :nth-child(${pos})${selector}`);
}

// https://github.com/AdguardTeam/ExtendedCss/issues/31#issuecomment-302391277
class SpathTask extends PTask {
  private spath: string;
  private nth: boolean;
  constructor(arg: unknown) {
    super();
    let s = typeof arg === 'string' ? arg : '';
    this.nth = /^(?:\s*[+~]|:)/.test(s);
    if (!this.nth && /^\s*>/.test(s)) s = `:scope ${s.trim()}`;
    this.spath = s;
  }
  transpose(node: Element, out: Element[]): void {
    if (this.spath.trim() === '') return;
    const nodes = this.nth ? siblingQsa(node, this.spath) : node.querySelectorAll(this.spath);
    for (let i = 0; i < nodes.length; i++) out.push(nodes[i]);
  }
}

class UpwardTask extends PTask {
  private arg: number | string | null;
  constructor(arg: unknown) {
    super();
    this.arg = parseUpward(arg);
  }
  transpose(node: Element, out: Element[]): void {
    const a = this.arg;
    if (a === null) return;
    let n: Element | null = node;
    if (typeof a === 'string') {
      const parent = n.parentElement;
      if (parent === null) return;
      n = parent.closest(a);
      if (n === null) return;
    } else {
      for (let i = a; i > 0; i--) {
        n = n.parentElement;
        if (n === null) return;
      }
    }
    out.push(n);
  }
}

class WatchAttrTask extends PTask {
  private host: EngineHost | null;
  private observer: MutationObserver | null = null;
  private observed = new WeakSet<Element>();
  private options: MutationObserverInit;
  constructor(host: EngineHost | null, arg: unknown) {
    super();
    this.host = host;
    this.options = { attributes: true, subtree: true };
    const attrs = parseAttrList(arg);
    if (attrs.length !== 0) this.options.attributeFilter = attrs;
  }
  transpose(node: Element, out: Element[]): void {
    out.push(node);
    const host = this.host;
    if (host === null || this.observed.has(node)) return;
    if (this.observer === null) this.observer = new MutationObserver(() => host.domChanged());
    this.observer.observe(node, this.options);
    this.observed.add(node);
  }
  destroy(): void {
    if (this.observer !== null) {
      this.observer.takeRecords();
      this.observer.disconnect();
      this.observer = null;
    }
  }
}

class XpathTask extends PTask {
  private xpe: XPathExpression | null = null;
  private xpr: XPathResult | null = null;
  constructor(arg: unknown) {
    super();
    const t = textArg(arg);
    if (t === null || t === '') return;
    try {
      this.xpe = document.createExpression(t, null);
    } catch {
      this.xpe = null;
    }
  }
  transpose(node: Element, out: Element[]): void {
    if (this.xpe === null) return;
    this.xpr = this.xpe.evaluate(node, XPathResult.UNORDERED_NODE_SNAPSHOT_TYPE, this.xpr);
    let j = this.xpr.snapshotLength;
    while (j--) {
      const n = this.xpr.snapshotItem(j);
      if (n !== null && n.nodeType === 1) out.push(n as Element);
    }
  }
}

function createTask(host: EngineHost | null, task: unknown): PTask {
  if (!Array.isArray(task) || typeof task[0] !== 'string') return new PTask();
  const arg: unknown = task[1];
  switch (task[0]) {
    case 'has':
    case 'if':
      return new IfTask(host, arg, true);
    case 'if-not':
    case 'not':
      return new IfTask(host, arg, false);
    case 'has-text':
      return new HasTextTask(arg);
    case 'matches-attr':
      return new MatchesAttrTask(arg);
    case 'matches-css':
      return new MatchesCssTask(arg, null);
    case 'matches-css-before':
      return new MatchesCssTask(arg, '::before');
    case 'matches-css-after':
      return new MatchesCssTask(arg, '::after');
    case 'matches-media':
      return new MatchesMediaTask(host, arg);
    case 'matches-path':
      return new MatchesPathTask(host, arg);
    case 'matches-prop':
      return new MatchesPropTask(arg);
    case 'min-text-length':
      return new MinTextLengthTask(arg);
    case 'others':
      return new OthersTask();
    case 'shadow':
      return new ShadowTask(arg);
    case 'spath':
      return new SpathTask(arg);
    case 'upward':
      return new UpwardTask(arg);
    case 'watch-attr':
      return new WatchAttrTask(host, arg);
    case 'xpath':
      return new XpathTask(arg);
    default:
      return new PTask();
  }
}

export class PSelector {
  readonly selector: string;
  readonly tasks: PTask[] = [];

  constructor(host: EngineHost | null, o: unknown) {
    const f = (o !== null && typeof o === 'object' ? o : {}) as { selector?: unknown; tasks?: unknown };
    this.selector = typeof f.selector === 'string' ? f.selector : '';
    if (!Array.isArray(f.tasks)) return;
    for (const t of f.tasks) this.tasks.push(createTask(host, t));
  }

  prime(input?: Root): Element[] {
    const root = input ?? document;
    if (this.selector === '') return [root as Element];
    if (input !== undefined && input.nodeType === 1) {
      const c0 = this.selector.charCodeAt(0);
      if (c0 === 0x2b /* + */ || c0 === 0x7e /* ~ */) {
        return Array.from(siblingQsa(input as Element, this.selector));
      }
      if (c0 === 0x3e /* > */) return Array.from(input.querySelectorAll(`:scope ${this.selector}`));
    }
    return Array.from(root.querySelectorAll(this.selector));
  }

  exec(input?: Root): Element[] {
    let nodes = this.prime(input);
    for (const task of this.tasks) {
      if (nodes.length === 0) break;
      const transposed: Element[] = [];
      task.begin();
      for (const node of nodes) task.transpose(node, transposed);
      task.end(transposed);
      nodes = transposed;
    }
    return nodes;
  }

  /** True when at least one primed node survives every task (used by :has/:if/:not). */
  test(input: Root): boolean {
    const nodes = this.prime(input);
    for (const node of nodes) {
      let output: Element[] = [node];
      for (const task of this.tasks) {
        const transposed: Element[] = [];
        task.begin();
        for (const n of output) task.transpose(n, transposed);
        task.end(transposed);
        output = transposed;
        if (output.length === 0) break;
      }
      if (output.length !== 0) return true;
    }
    return false;
  }

  destroy(): void {
    for (const task of this.tasks) task.destroy();
  }
}

export type Action =
  | { op: 'hide' }
  | { op: 'style'; style: string }
  | { op: 'remove' }
  | { op: 'remove-attr'; re: RegExp }
  | { op: 'remove-class'; re: RegExp };

/** Validate ProceduralFilter.action; null = invalid (the filter is dropped). */
export function normalizeAction(action: unknown): Action | null {
  if (action === undefined || action === null) return { op: 'hide' };
  if (!Array.isArray(action) || typeof action[0] !== 'string') return null;
  switch (action[0]) {
    case 'style':
      return isSafeStyle(action[1]) ? { op: 'style', style: action[1] } : null;
    case 'remove':
      return { op: 'remove' };
    case 'remove-attr':
    case 'remove-class': {
      const t = textArg(action[1]);
      if (t === null || t === '') return null;
      const re = regexFromString(t, true);
      if (re === null) return null;
      return action[0] === 'remove-attr' ? { op: 'remove-attr', re } : { op: 'remove-class', re };
    }
    default:
      return null;
  }
}

/**
 * CSS for filters that need no script: a plain selector, or uBO's "cssable"
 * shape `:matches-media(q)` optionally followed by one :spath(), with a hide
 * or :style() action. null = evaluate procedurally.
 */
export function cssForFilter(f: ProceduralFilter, action: Action, mediaValid: (q: string) => boolean): string | null {
  if (action.op !== 'hide' && action.op !== 'style') return null;
  const decl = action.op === 'hide' ? 'display:none!important' : action.style;
  const tasks = Array.isArray(f.tasks) ? f.tasks : [];
  if (tasks.length === 0) {
    const sel = f.selector.trim();
    return sel === '' ? null : `${sel}{${decl}}`;
  }
  if (tasks.length > 2 || !Array.isArray(tasks[0]) || tasks[0][0] !== 'matches-media') return null;
  let sel = f.selector;
  if (tasks.length === 2) {
    const t1 = tasks[1];
    if (!Array.isArray(t1) || t1[0] !== 'spath' || typeof t1[1] !== 'string') return null;
    sel += t1[1];
  }
  sel = sel.trim();
  const q = textArg(tasks[0][1]);
  if (sel === '' || q === null || q === '' || /[{};]/.test(q) || !mediaValid(q)) return null;
  return `@media ${q}{${sel}{${decl}}}`;
}

export class PSelectorRoot extends PSelector {
  readonly raw: string;
  readonly action: Action;
  /** uBO's budget: ms of evaluation time; refilled 50 ms every 2 s, capped at 200. */
  budget = 200;
  lastAllowanceTime = 0;

  constructor(host: EngineHost | null, o: ProceduralFilter, raw: string, action: Action) {
    super(host, o);
    this.raw = raw;
    this.action = action;
  }
  prime(input?: Root): Element[] {
    try {
      return super.prime(input);
    } catch {
      return [];
    }
  }
  exec(input?: Root): Element[] {
    try {
      return super.exec(input);
    } catch {
      return [];
    }
  }
}

const COMMIT_THROTTLE_MS = 100;

function randomToken(): string {
  const a = new Uint32Array(2);
  crypto.getRandomValues(a);
  return a[0].toString(36) + a[1].toString(36);
}

/** The per-frame runtime: owns the filters, the stylesheet and the DOM observer. */
export class ProceduralFilterer implements EngineHost {
  private readonly doc: Document;
  private readonly roots = new Map<string, PSelectorRoot>();
  /** Filters that were turned into plain CSS. */
  private readonly cssDone = new Set<string>();
  /** style text -> attribute name */
  private readonly tokens = new Map<string, string>();
  private styled = new Set<Element>();
  private sheet: CSSStyleSheet | null = null;
  private styleEl: HTMLStyleElement | null = null;
  /** Shadow roots that adopted our sheet (document styles do not reach into shadow trees). */
  private shadowRoots = new WeakSet<ShadowRoot>();
  private observer: MutationObserver | null = null;
  private timer = 0;
  private raf = 0;
  private lastCommit = -Infinity;

  constructor(doc: Document) {
    this.doc = doc;
  }

  apply(list: unknown): void {
    if (!Array.isArray(list)) return;
    let added = false;
    for (const f of list) {
      try {
        if (this.add(f)) added = true;
      } catch {
        // drop this filter only
      }
    }
    if (!added) return;
    this.observe();
    this.commit();
  }

  private add(f: unknown): boolean {
    if (f === null || typeof f !== 'object') return false;
    const o = f as ProceduralFilter;
    if (typeof o.selector !== 'string') return false;
    const raw = typeof o.raw === 'string' && o.raw !== '' ? o.raw : JSON.stringify(o);
    if (this.roots.has(raw) || this.cssDone.has(raw)) return false;
    const action = normalizeAction(o.action);
    if (action === null) return false;
    const css = cssForFilter(o, action, (q) => {
      try {
        return matchMedia(q).media !== 'not all';
      } catch {
        return false;
      }
    });
    if (css !== null && this.insertRule(css)) {
      this.cssDone.add(raw);
      return false;
    }
    if (action.op === 'hide' || action.op === 'style') {
      if (this.tokenFor(action) === null) return false;
    }
    this.roots.set(raw, new PSelectorRoot(this, o, raw, action));
    return true;
  }

  private ensureSheet(): void {
    if (this.sheet !== null || this.styleEl !== null) return;
    try {
      const sheet = new CSSStyleSheet();
      const list = this.doc.adoptedStyleSheets;
      if (typeof list.push === 'function') list.push(sheet);
      else this.doc.adoptedStyleSheets = [...list, sheet];
      this.sheet = sheet;
      return;
    } catch {
      // fall back to <style>
    }
    const el = this.doc.createElement('style');
    (this.doc.head ?? this.doc.documentElement)?.appendChild(el);
    this.styleEl = el;
  }

  /** Pages may reset document.adoptedStyleSheets or remove our <style>; put it back. */
  private reattach(): void {
    try {
      if (this.sheet !== null) {
        const list = this.doc.adoptedStyleSheets;
        if (!list.includes(this.sheet)) {
          if (typeof list.push === 'function') list.push(this.sheet);
          else this.doc.adoptedStyleSheets = [...list, this.sheet];
        }
      } else if (this.styleEl !== null && !this.styleEl.isConnected) {
        (this.doc.head ?? this.doc.documentElement)?.appendChild(this.styleEl);
      }
    } catch {
      // ignore
    }
  }

  /** Make our hide/style rules apply to an element living in a shadow tree. */
  private coverShadowRoot(node: Element): void {
    if (this.sheet === null) return;
    const root = node.getRootNode();
    // Elements in the document (the common case) need nothing.
    if (root === this.doc || root.nodeType !== 11 /* DOCUMENT_FRAGMENT_NODE */) return;
    const sr = root as ShadowRoot;
    try {
      const list = sr.adoptedStyleSheets;
      if (this.shadowRoots.has(sr) && list.includes(this.sheet)) return;
      if (!list.includes(this.sheet)) {
        if (typeof list.push === 'function') list.push(this.sheet);
        else sr.adoptedStyleSheets = [...list, this.sheet];
      }
      this.shadowRoots.add(sr);
    } catch {
      // ignore
    }
  }

  private insertRule(css: string): boolean {
    try {
      this.ensureSheet();
      if (this.sheet !== null) {
        this.sheet.insertRule(css, this.sheet.cssRules.length);
        return true;
      }
      if (this.styleEl !== null) {
        this.styleEl.appendChild(this.doc.createTextNode(css + '\n'));
        return true;
      }
    } catch {
      // invalid selector / declaration: not CSS-able
    }
    return false;
  }

  private tokenFor(action: Action): string | null {
    const decl = action.op === 'style' ? action.style : 'display:none!important';
    const known = this.tokens.get(decl);
    if (known !== undefined) return known;
    const attr = (action.op === 'style' ? 'bastion-style-' : 'bastion-hide-') + randomToken();
    if (!this.insertRule(`[${attr}]{${decl}}`)) return null;
    this.tokens.set(decl, attr);
    return attr;
  }

  private observe(): void {
    if (this.observer !== null) return;
    try {
      this.observer = new MutationObserver((records) => {
        for (const m of records) {
          for (let i = 0; i < m.addedNodes.length; i++) {
            if (m.addedNodes[i].nodeType === 1) return this.domChanged();
          }
          for (let i = 0; i < m.removedNodes.length; i++) {
            if (m.removedNodes[i].nodeType === 1) return this.domChanged();
          }
        }
      });
      this.observer.observe(this.doc, { childList: true, subtree: true });
    } catch {
      this.observer = null;
    }
    if (this.doc.readyState === 'loading') {
      this.doc.addEventListener('DOMContentLoaded', () => this.domChanged(), { once: true });
    }
  }

  domChanged(): void {
    if (this.timer !== 0 || this.raf !== 0) return;
    const wait = Math.max(0, this.lastCommit + COMMIT_THROTTLE_MS - performance.now());
    this.timer = setTimeout(() => {
      this.timer = 0;
      this.raf = requestAnimationFrame(() => {
        this.raf = 0;
        this.commit();
      });
    }, wait) as unknown as number;
  }

  commit(): void {
    if (this.timer !== 0) {
      clearTimeout(this.timer);
      this.timer = 0;
    }
    if (this.raf !== 0) {
      cancelAnimationFrame(this.raf);
      this.raf = 0;
    }
    this.lastCommit = performance.now();
    this.reattach();

    // https://github.com/uBlockOrigin/uBlock-issues/issues/341
    //   Unhide nodes which no longer match any procedural selector.
    const toUnstyle = this.styled;
    this.styled = new Set();

    let t0 = Date.now();
    for (const root of this.roots.values()) {
      const allowance = Math.floor((t0 - root.lastAllowanceTime) / 2000);
      if (allowance >= 1) {
        root.budget = Math.min(200, root.budget + allowance * 50);
        root.lastAllowanceTime = t0;
      }
      if (root.budget <= 0) continue;
      const nodes = root.exec();
      const t1 = Date.now();
      root.budget += t0 - t1;
      // A filter that keeps eating the page's time is switched off for good.
      if (root.budget < -500) root.budget = -0x7fffffff;
      t0 = t1;
      if (nodes.length !== 0) this.process(nodes, root.action);
    }
    this.unprocess(toUnstyle);
  }

  private process(nodes: Element[], action: Action): void {
    switch (action.op) {
      case 'hide':
      case 'style': {
        const token = this.tokenFor(action);
        if (token === null) return;
        for (const node of nodes) {
          if (node.nodeType !== 1) continue;
          try {
            node.setAttribute(token, '');
            this.styled.add(node);
            this.coverShadowRoot(node);
          } catch {
            // ignore exotic nodes
          }
        }
        return;
      }
      case 'remove':
        for (const node of nodes) {
          if (node.nodeType !== 1) continue;
          try {
            node.remove();
            node.textContent = '';
          } catch {
            // ignore
          }
        }
        return;
      case 'remove-attr':
        for (const node of nodes) {
          if (node.nodeType !== 1) continue;
          try {
            for (const name of node.getAttributeNames()) {
              if (action.re.test(name)) node.removeAttribute(name);
            }
          } catch {
            // ignore
          }
        }
        return;
      case 'remove-class':
        for (const node of nodes) {
          if (node.nodeType !== 1) continue;
          try {
            const cl = node.classList;
            for (const name of Array.from(cl)) {
              if (action.re.test(name)) cl.remove(name);
            }
          } catch {
            // ignore
          }
        }
        return;
    }
  }

  private unprocess(nodes: Set<Element>): void {
    if (nodes.size === 0) return;
    const attrs = Array.from(this.tokens.values());
    for (const node of nodes) {
      if (this.styled.has(node)) continue;
      for (const a of attrs) {
        try {
          node.removeAttribute(a);
        } catch {
          // ignore
        }
      }
    }
  }
}
