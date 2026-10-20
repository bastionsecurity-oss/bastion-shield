// Bastion filter compiler — cosmetic selector analysis: decides whether a
// selector is plain CSS, a plain selector with a :style() declaration, or a
// procedural filter, and compiles procedural (uBO `#?#` / ABP `:-abp-*`)
// selectors into the ProceduralFilter shape run by content/procedural.ts.
// The task layout follows uBO's ExtSelectorCompiler.astCompile so the engine
// can mirror uBO's well-tested semantics (selector, then tasks, spath for
// plain CSS between operators, optional final action).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ProceduralFilter, ProceduralTask } from '../shared/types.ts';
import { isValidCssTokens, serializeTokens, tokenizeSelector, isValidCss } from './selector.ts';
import type { SelToken } from './selector.ts';

/** Operators that always make a selector procedural. */
const PROCEDURAL_OPS = new Set([
  'has-text', 'if', 'if-not', 'matches-attr', 'matches-css', 'matches-css-after', 'matches-css-before',
  'matches-media', 'matches-path', 'matches-prop', 'min-text-length', 'others', 'shadow', 'upward',
  'watch-attr', 'xpath',
]);
const ACTION_OPS = new Set(['remove', 'remove-attr', 'remove-class', 'style']);
/** uBO operator aliases. "-abp-*" ones are only accepted with the #?# separator. */
const OP_ALIASES: ReadonlyMap<string, string> = new Map([
  ['-abp-has', 'has'],
  ['-abp-contains', 'has-text'],
  ['contains', 'has-text'],
  ['nth-ancestor', 'upward'],
  ['watch-attrs', 'watch-attr'],
]);

export type SelectorAnalysis =
  | { kind: 'css'; selector: string; tokens: SelToken[] }
  | { kind: 'style'; selector: string; style: string }
  | { kind: 'procedural'; filter: ProceduralFilter }
  | { kind: 'invalid'; reason: string };

type Role = 'css' | 'procedural' | 'action' | 'invalid';

interface Ctx {
  asProcedural: boolean;
}

function normalizedName(name: string): string {
  return OP_ALIASES.get(name) ?? name;
}

function roleOf(tok: Extract<SelToken, { t: 'pseudo' }>, ctx: Ctx): Role {
  if (tok.element) return 'css';
  const raw = tok.name;
  if (raw.startsWith('-abp-')) {
    if (!ctx.asProcedural || !OP_ALIASES.has(raw)) return 'invalid';
  }
  const name = normalizedName(raw);
  if (ACTION_OPS.has(name)) return 'action';
  if (PROCEDURAL_OPS.has(name)) return 'procedural';
  if (name === 'has') {
    if (tok.arg === null) return 'invalid';
    return argIsProcedural(tok.arg, ctx) || hasPseudoNamed(tok.arg, 'has') ? 'procedural' : 'css';
  }
  if (name === 'not') {
    if (tok.arg === null) return 'invalid';
    return argIsProcedural(tok.arg, ctx) ? 'procedural' : 'css';
  }
  return 'css';
}

function argIsProcedural(arg: string, ctx: Ctx): boolean {
  const tokens = tokenizeSelector(arg);
  if (tokens === null) return false;
  for (const tok of tokens) {
    if (tok.t !== 'pseudo') continue;
    const role = roleOf(tok, ctx);
    if (role === 'procedural' || role === 'action') return true;
  }
  return false;
}

function hasPseudoNamed(arg: string, name: string): boolean {
  const tokens = tokenizeSelector(arg);
  if (tokens === null) return false;
  for (const tok of tokens) {
    if (tok.t !== 'pseudo') continue;
    if (normalizedName(tok.name) === name) return true;
    if (tok.arg !== null && hasPseudoNamed(tok.arg, name)) return true;
  }
  return false;
}

/** uBO's unquoteString: strip one level of quotes, keeping other escapes. Null if junk follows. */
function unquote(s: string): string | null {
  const t = s.trim();
  if (t === '') return '';
  const q = t.charCodeAt(0);
  if (q !== 0x22 && q !== 0x27) return t;
  let out = '';
  let i = 1;
  for (; i < t.length; i++) {
    const c = t.charCodeAt(i);
    if (c === q) break;
    if (c === 0x5c && i + 1 < t.length) {
      const d = t.charCodeAt(i + 1);
      if (d !== 0x5c && d !== q) out += '\\';
      out += t[i + 1];
      i += 1;
      continue;
    }
    out += t[i];
  }
  if (i >= t.length || i !== t.length - 1) return null;
  return out;
}

const reBadStyle = /image-set\(|url\(|\/\s*\/|\\|\/\*|[{}]/i;

function compileStyle(arg: string | null): string | null {
  if (arg === null) return null;
  const s = arg.trim();
  if (s === '' || reBadStyle.test(s)) return null;
  // At least one "property: value" declaration. Malformed extra declarations
  // are tolerated (uBO's CSS parser accepts them; the browser drops them
  // without affecting the rest of the rule).
  const decls = s.split(';').map((d) => d.trim()).filter((d) => d !== '');
  if (!decls.some((d) => /^-{0,2}[a-zA-Z][\w-]*\s*:\s*\S/.test(d))) return null;
  // Unbalanced quotes or parentheses could swallow the closing brace.
  if ((s.match(/"/g) ?? []).length % 2 !== 0 || (s.match(/'/g) ?? []).length % 2 !== 0) return null;
  if ((s.match(/\(/g) ?? []).length !== (s.match(/\)/g) ?? []).length) return null;
  return s;
}

function compileText(arg: string | null): string | null {
  if (arg === null) return null;
  const s = unquote(arg);
  if (s === null || s === '') return null;
  return s;
}

function compileTask(tok: Extract<SelToken, { t: 'pseudo' }>, ctx: Ctx): ProceduralTask | null {
  const name = normalizedName(tok.name);
  const arg = tok.arg;
  switch (name) {
    case 'has':
    case 'not': {
      if (arg === null) return null;
      const nested = compileNested(arg, ctx, true);
      return nested === null ? null : [name, nested];
    }
    case 'if':
    case 'if-not': {
      if (arg === null) return null;
      const nested = compileNested(arg, ctx, true);
      return nested === null ? null : [name, nested];
    }
    case 'has-text': {
      const t = compileText(arg);
      return t === null ? null : ['has-text', t];
    }
    case 'matches-path': {
      const t = compileText(arg);
      return t === null ? null : ['matches-path', t];
    }
    case 'xpath': {
      const t = compileText(arg);
      return t === null ? null : ['xpath', t];
    }
    case 'matches-attr':
    case 'matches-prop': {
      if (arg === null || arg.trim() === '') return null;
      return [name, arg.trim()];
    }
    case 'matches-css':
    case 'matches-css-before':
    case 'matches-css-after': {
      if (arg === null || !arg.includes(':')) return null;
      return [name, arg.trim()];
    }
    case 'matches-media': {
      if (arg === null || arg.trim() === '' || /[{};]/.test(arg)) return null;
      return ['matches-media', arg.trim()];
    }
    case 'min-text-length': {
      if (arg === null || !/^\s*\d+\s*$/.test(arg)) return null;
      const v = parseInt(arg, 10);
      if (!Number.isFinite(v) || v >= 0x7fffffff) return null;
      return ['min-text-length', v];
    }
    case 'others':
      return arg === null || arg.trim() === '' ? ['others'] : null;
    case 'shadow': {
      if (arg === null || !isValidCss(arg.trim())) return null;
      return ['shadow', arg.trim()];
    }
    case 'upward': {
      if (arg === null) return null;
      const a = arg.trim();
      if (/^\d+$/.test(a)) {
        const v = parseInt(a, 10);
        return v >= 1 && v < 256 ? ['upward', v] : null;
      }
      return a !== '' && isValidCss(a) ? ['upward', a] : null;
    }
    case 'watch-attr': {
      const a = arg === null ? '' : arg.trim();
      return ['watch-attr', a.split(/\s*,\s*/).filter((x) => x !== '').join(',')];
    }
    default:
      return null;
  }
}

function compileAction(tok: Extract<SelToken, { t: 'pseudo' }>): ProceduralFilter['action'] | null {
  const name = tok.name;
  switch (name) {
    case 'remove':
      return tok.arg === null || tok.arg.trim() === '' ? ['remove'] : null;
    case 'remove-attr':
    case 'remove-class': {
      const t = compileText(tok.arg);
      return t === null ? null : [name, t];
    }
    case 'style': {
      const s = compileStyle(tok.arg);
      return s === null ? null : ['style', s];
    }
    default:
      return null;
  }
}

/**
 * Serialize a prelude the way uBO does: a leading selector starts with its
 * combinator ("> .a"), an spath after an operator keeps a separating space
 * (" > .a", " .a"), and a trailing combinator gets an implied "*".
 */
function serializePrelude(tokens: readonly SelToken[], leading: boolean): string {
  let out = '';
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    if (tok.t === 'comb') {
      if (i === 0 && leading) out += tok.c === ' ' ? '' : `${tok.c} `;
      else out += tok.c === ' ' ? ' ' : ` ${tok.c} `;
      continue;
    }
    if (tok.t === 'comma') {
      out += ', ';
      continue;
    }
    if (tok.t === 'ws') {
      out += ' ';
      continue;
    }
    out += tok.text;
  }
  const last = tokens[tokens.length - 1];
  if (last !== undefined && last.t === 'comb') out += '*';
  return out.trimEnd();
}

function compileNested(arg: string, ctx: Ctx, relative: boolean): ProceduralFilter | null {
  const tokens = tokenizeSelector(arg.trim());
  if (tokens === null || tokens.length === 0) return null;
  const pf = compileTokens(tokens, ctx, { relative, noAction: true });
  if (pf === null) return null;
  // uBO strips a leading ":scope" from :has() arguments.
  pf.selector = pf.selector.replace(/^\s*:scope\s*/, '');
  return pf;
}

interface CompileOpts {
  relative: boolean;
  noAction: boolean;
}

function compileTokens(tokens: SelToken[], ctx: Ctx, opts: CompileOpts): ProceduralFilter | null {
  const raw = serializeTokens(tokens);
  let selector = '';
  const tasks: ProceduralTask[] = [];
  let action: ProceduralFilter['action'];
  let prelude: SelToken[] = [];
  let sawProcedural = false;
  const flush = (): boolean => {
    if (prelude.length === 0) return true;
    const leading = tasks.length === 0 && !sawProcedural;
    const text = serializePrelude(prelude, leading);
    const forCheck = prelude[prelude.length - 1].t === 'comb'
      ? [...prelude, { t: 'simple', kind: 'universal', text: '*', name: '*' } as SelToken]
      : prelude;
    if (!isValidCssTokens(forCheck, { relative: leading ? opts.relative : true })) return false;
    if (leading) selector = text;
    else tasks.push(['spath', text]);
    prelude = [];
    return true;
  };
  for (const tok of tokens) {
    if (action !== undefined) return null; // nothing may follow an action operator
    if (tok.t === 'comma') {
      // A leading selector list is the subject of every operator that
      // follows ("a, b:others()" keeps both, as in uBO). A comma after an
      // operator has no defined meaning.
      if (sawProcedural) return null;
      prelude.push(tok);
      continue;
    }
    if (tok.t === 'pseudo') {
      const role = roleOf(tok, ctx);
      if (role === 'invalid') return null;
      if (role === 'action') {
        if (opts.noAction) return null;
        if (!flush()) return null;
        const a = compileAction(tok);
        if (a === null) return null;
        action = a;
        sawProcedural = true;
        continue;
      }
      if (role === 'procedural') {
        if (!flush()) return null;
        const task = compileTask(tok, ctx);
        if (task === null) return null;
        tasks.push(task);
        sawProcedural = true;
        continue;
      }
    }
    prelude.push(tok);
  }
  if (!flush()) return null;
  const out: ProceduralFilter = { raw, selector, tasks };
  if (action !== undefined) out.action = action;
  return out;
}

// AdGuard's attribute-style extended syntax: [-ext-has="…"] / [-ext-contains="…"]
const reExtendedSyntax = /\[-(?:abp|ext)-([a-z-]+)=(['"])(.+?)\2\]/g;
const reStyleInjection = /^(.+?)\s*\{([^}]+)\}$/;

/** Analyze a cosmetic filter body. `asProcedural` is true for the #?# separator. */
export function analyzeSelector(body: string, asProcedural: boolean): SelectorAnalysis {
  let raw = body.trim();
  if (raw === '') return { kind: 'invalid', reason: 'empty-selector' };
  // uBO accepts AdGuard/EasyList "selector { style }" in any cosmetic filter.
  if (raw.charCodeAt(raw.length - 1) === 0x7d /* } */) {
    const m = reStyleInjection.exec(raw);
    if (m === null) return { kind: 'invalid', reason: 'invalid-selector' };
    const sel = m[1].trim();
    const style = m[2].trim();
    if (/^\s*remove:\s*true[; ]*$/.test(style)) raw = `${sel}:remove()`;
    else if (/display\s*:\s*none\s*!important;?$/.test(style)) raw = sel;
    else raw = `${sel}:style(${style})`;
  }
  if (asProcedural && raw.includes(':-abp-')) {
    // uBO rewrites ABP's two standard operators before parsing; any other
    // :-abp-* operator stays and is rejected below.
    raw = raw.replace(/:-abp-(has|contains)\(/g, (_m, op: string) => (op === 'has' ? ':has(' : ':has-text('));
  }
  if (asProcedural && raw.includes('[-')) {
    raw = raw.replace(reExtendedSyntax, (m0, op: string, _q: string, arg: string) => {
      if (op === 'has') return `:has(${arg})`;
      if (op === 'contains') return `:has-text(${arg})`;
      return m0;
    });
  }
  if (/^[+>~]/.test(raw)) return { kind: 'invalid', reason: 'relative-selector' };
  const tokens = tokenizeSelector(raw);
  if (tokens === null || tokens.length === 0) return { kind: 'invalid', reason: 'invalid-selector' };
  const ctx: Ctx = { asProcedural };
  let special = false;
  for (const tok of tokens) {
    if (tok.t !== 'pseudo') continue;
    const role = roleOf(tok, ctx);
    if (role === 'invalid') return { kind: 'invalid', reason: 'unsupported-pseudo' };
    if (role !== 'css') special = true;
  }
  if (!special) {
    if (!isValidCssTokens(tokens)) return { kind: 'invalid', reason: 'invalid-selector' };
    return { kind: 'css', selector: serializeTokens(tokens), tokens };
  }
  const pf = compileTokens(tokens, ctx, { relative: false, noAction: false });
  if (pf === null) return { kind: 'invalid', reason: 'invalid-procedural' };
  if (pf.tasks.length === 0 && pf.action !== undefined && pf.action[0] === 'style' && pf.selector !== '') {
    return { kind: 'style', selector: pf.selector, style: pf.action[1] };
  }
  if (pf.tasks.length === 0 && pf.action === undefined) {
    return { kind: 'css', selector: pf.selector, tokens };
  }
  return { kind: 'procedural', filter: pf };
}

/**
 * Parse a uBO procedural / ABP `#?#` selector into a ProceduralFilter.
 * Returns null for invalid selectors and for plain CSS (which is not
 * procedural and should be injected as a stylesheet instead).
 */
export function parseProceduralSelector(selector: string): ProceduralFilter | null {
  const a = analyzeSelector(selector, true);
  if (a.kind === 'procedural') return a.filter;
  if (a.kind === 'style') return { raw: `${a.selector}:style(${a.style})`, selector: a.selector, tasks: [], action: ['style', a.style] };
  return null;
}
