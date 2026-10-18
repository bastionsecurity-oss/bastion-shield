// Bastion filter compiler — a small CSS selector scanner. It tokenizes a
// selector into simple selectors, pseudo-classes (with their raw argument),
// combinators and commas, and validates plain CSS conservatively: one invalid
// selector in a grouped `sel1, sel2 {…}` rule disables the whole rule in the
// browser, so anything we are not sure Chromium accepts is rejected.
//
// SPDX-License-Identifier: GPL-3.0-or-later

export type SelToken =
  | { t: 'ws' }
  | { t: 'comb'; c: ' ' | '>' | '+' | '~' }
  | { t: 'comma' }
  | { t: 'simple'; kind: 'type' | 'universal' | 'id' | 'class' | 'attr'; text: string; name: string }
  | { t: 'pseudo'; text: string; name: string; element: boolean; arg: string | null };

/** Pseudo-classes Chromium understands (uBO's list plus a few standard ones). */
const KNOWN_PSEUDO_CLASSES = new Set([
  'active', 'any-link', 'autofill', 'blank', 'checked', 'current', 'default', 'defined', 'dir',
  'disabled', 'empty', 'enabled', 'first', 'first-child', 'first-of-type', 'fullscreen', 'future',
  'focus', 'focus-visible', 'focus-within', 'has', 'host', 'host-context', 'hover', 'indeterminate',
  'in-range', 'invalid', 'is', 'lang', 'last-child', 'last-of-type', 'left', 'link', 'local-link',
  'modal', 'not', 'nth-child', 'nth-col', 'nth-last-child', 'nth-last-col', 'nth-last-of-type',
  'nth-of-type', 'only-child', 'only-of-type', 'optional', 'out-of-range', 'past',
  'picture-in-picture', 'placeholder-shown', 'paused', 'playing', 'popover-open', 'read-only',
  'read-write', 'required', 'right', 'root', 'scope', 'state', 'target', 'target-within',
  'user-invalid', 'user-valid', 'valid', 'visited', 'where', 'open', 'closed', 'muted',
]);
const PSEUDO_CLASSES_WITH_ARGS = new Set([
  'dir', 'has', 'host-context', 'is', 'lang', 'not', 'nth-child', 'nth-col', 'nth-last-child',
  'nth-last-col', 'nth-last-of-type', 'nth-of-type', 'state', 'where',
]);
const PSEUDO_CLASSES_OPTIONAL_ARGS = new Set(['host']);
const KNOWN_PSEUDO_ELEMENTS = new Set([
  'after', 'backdrop', 'before', 'cue', 'cue-region', 'first-letter', 'first-line',
  'file-selector-button', 'grammar-error', 'marker', 'part', 'placeholder', 'selection', 'slotted',
  'spelling-error', 'target-text', 'highlight',
]);
const PSEUDO_ELEMENTS_WITH_ARGS = new Set(['part', 'slotted', 'highlight']);
/** CSS2 pseudo-elements that may be written with a single colon. */
const LEGACY_PSEUDO_ELEMENTS = new Set(['before', 'after', 'first-line', 'first-letter']);

const isWs = (c: number): boolean => c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0c || c === 0x0d;
const isIdentStart = (c: number): boolean =>
  (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x5f || c >= 0x80;
const isIdentChar = (c: number): boolean => isIdentStart(c) || (c >= 0x30 && c <= 0x39) || c === 0x2d;
const isHexCode = (c: number): boolean =>
  (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66);

/** Read a CSS identifier at s[i]; returns end index (=== i when none). Escapes are kept. */
function readIdent(s: string, i: number): number {
  const n = s.length;
  let j = i;
  if (s.charCodeAt(j) === 0x2d /* - */) {
    j += 1;
    if (s.charCodeAt(j) === 0x2d) j += 1; // custom-ident "--x"
  }
  const first = j;
  while (j < n) {
    const c = s.charCodeAt(j);
    if (c === 0x5c /* \ */) {
      if (j + 1 >= n || s.charCodeAt(j + 1) === 0x0a) return i;
      if (isHexCode(s.charCodeAt(j + 1))) {
        let k = j + 1;
        while (k < n && k < j + 7 && isHexCode(s.charCodeAt(k))) k += 1;
        if (k < n && isWs(s.charCodeAt(k))) k += 1;
        j = k;
      } else {
        j += 2;
      }
      continue;
    }
    if (j === first ? isIdentStart(c) : isIdentChar(c)) {
      j += 1;
      continue;
    }
    break;
  }
  if (j === first) return i;
  return j;
}

/** Decode CSS escapes in an identifier ("foo\:bar" -> "foo:bar"). */
export function unescapeIdent(s: string): string {
  if (s.indexOf('\\') === -1) return s;
  return s.replace(/\\([0-9a-fA-F]{1,6}\s?|[\s\S])/g, (_m, esc: string) => {
    if (/^[0-9a-fA-F]/.test(esc)) {
      const cp = parseInt(esc.trim(), 16);
      if (cp === 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return '\ufffd';
      return String.fromCodePoint(cp);
    }
    return esc;
  });
}

/** Index after the quoted string starting at s[i] (a quote), or -1. */
function skipString(s: string, i: number): number {
  const q = s.charCodeAt(i);
  const n = s.length;
  let j = i + 1;
  while (j < n) {
    const c = s.charCodeAt(j);
    if (c === 0x5c) {
      j += 2;
      continue;
    }
    if (c === q) return j + 1;
    if (c === 0x0a) return -1;
    j += 1;
  }
  return -1;
}

/** Index of the ")" matching the "(" at s[i], honouring strings, escapes and brackets; -1 if unbalanced. */
export function matchParen(s: string, i: number): number {
  const n = s.length;
  let depth = 0;
  let j = i;
  while (j < n) {
    const c = s.charCodeAt(j);
    if (c === 0x5c) {
      j += 2;
      continue;
    }
    if (c === 0x22 || c === 0x27) {
      const e = skipString(s, j);
      if (e === -1) return -1;
      j = e;
      continue;
    }
    if (c === 0x28) depth += 1;
    else if (c === 0x29) {
      depth -= 1;
      if (depth === 0) return j;
    }
    j += 1;
  }
  return -1;
}

const reAttrBody =
  /^\s*(?:[A-Za-z_*][\w-]*\|)?(-?[A-Za-z_][\w-]*|-?(?:\\.|[A-Za-z_])(?:\\.|[\w-])*)\s*(?:([~|^$*]?=)\s*("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|-?(?:\\.|[A-Za-z_\u00a0-\uffff])(?:\\.|[\w\u00a0-\uffff-])*)\s*(?:([iIsS])\s*)?)?$/;

/** Tokenize a selector; null when it is not something we can parse. */
export function tokenizeSelector(s: string): SelToken[] | null {
  const out: SelToken[] = [];
  const n = s.length;
  let i = 0;
  while (i < n) {
    const c = s.charCodeAt(i);
    if (isWs(c)) {
      while (i < n && isWs(s.charCodeAt(i))) i += 1;
      out.push({ t: 'ws' });
      continue;
    }
    if (c === 0x3e || c === 0x2b || c === 0x7e) {
      out.push({ t: 'comb', c: s[i] as '>' | '+' | '~' });
      i += 1;
      continue;
    }
    if (c === 0x2c) {
      out.push({ t: 'comma' });
      i += 1;
      continue;
    }
    if (c === 0x23 /* # */ || c === 0x2e /* . */) {
      const e = readIdent(s, i + 1);
      if (e === i + 1) return null;
      const name = s.slice(i + 1, e);
      if (/^-?\d/.test(name)) return null;
      out.push({ t: 'simple', kind: c === 0x23 ? 'id' : 'class', text: s.slice(i, e), name: unescapeIdent(name) });
      i = e;
      continue;
    }
    if (c === 0x5b /* [ */) {
      let j = i + 1;
      while (j < n) {
        const d = s.charCodeAt(j);
        if (d === 0x5c) {
          j += 2;
          continue;
        }
        if (d === 0x22 || d === 0x27) {
          const e = skipString(s, j);
          if (e === -1) return null;
          j = e;
          continue;
        }
        if (d === 0x5d || d === 0x5b) break;
        j += 1;
      }
      if (j >= n || s.charCodeAt(j) !== 0x5d) return null;
      const body = s.slice(i + 1, j);
      const m = reAttrBody.exec(body);
      if (m === null) return null;
      out.push({ t: 'simple', kind: 'attr', text: s.slice(i, j + 1), name: m[1] });
      i = j + 1;
      continue;
    }
    if (c === 0x3a /* : */) {
      const element = s.charCodeAt(i + 1) === 0x3a;
      const start = element ? i + 2 : i + 1;
      const e = readIdent(s, start);
      if (e === start) return null;
      const name = s.slice(start, e).toLowerCase();
      let arg: string | null = null;
      let end = e;
      if (s.charCodeAt(e) === 0x28 /* ( */) {
        const close = matchParen(s, e);
        if (close === -1) return null;
        arg = s.slice(e + 1, close);
        end = close + 1;
      }
      out.push({ t: 'pseudo', text: s.slice(i, end), name, element, arg });
      i = end;
      continue;
    }
    if (c === 0x2a /* * */) {
      out.push({ t: 'simple', kind: 'universal', text: '*', name: '*' });
      i += 1;
      continue;
    }
    if (isIdentStart(c) || c === 0x2d || c === 0x5c) {
      const e = readIdent(s, i);
      if (e === i) return null;
      const text = s.slice(i, e);
      out.push({ t: 'simple', kind: 'type', text, name: text.toLowerCase() });
      i = e;
      continue;
    }
    return null;
  }
  return normalizeWhitespace(out);
}

/** Turn whitespace into descendant combinators where it is one, drop it elsewhere. */
function normalizeWhitespace(tokens: SelToken[]): SelToken[] {
  const out: SelToken[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    if (tok.t !== 'ws') {
      out.push(tok);
      continue;
    }
    const prev = out[out.length - 1];
    const next = tokens[i + 1];
    if (prev === undefined || next === undefined) continue;
    if (prev.t === 'comb' || prev.t === 'comma') continue;
    if (next.t === 'comb' || next.t === 'comma' || next.t === 'ws') continue;
    out.push({ t: 'comb', c: ' ' });
  }
  return out;
}

/** Serialize tokens back to a canonical selector string. */
export function serializeTokens(tokens: readonly SelToken[]): string {
  let out = '';
  for (const tok of tokens) {
    switch (tok.t) {
      case 'comb':
        out += tok.c === ' ' ? ' ' : ` ${tok.c} `;
        break;
      case 'comma':
        out += ', ';
        break;
      case 'ws':
        out += ' ';
        break;
      default:
        out += tok.text;
    }
  }
  return out.trim();
}

/** Split tokens at top-level commas. */
export function splitSelectorList(tokens: readonly SelToken[]): SelToken[][] {
  const out: SelToken[][] = [[]];
  for (const tok of tokens) {
    if (tok.t === 'comma') out.push([]);
    else out[out.length - 1].push(tok);
  }
  return out;
}

const reNth = /^\s*(?:odd|even|[+-]?\d*n(?:\s*[+-]\s*\d+)?|[+-]?\d+)(?:\s+of\s+(.+))?\s*$/i;

export interface ValidateOptions {
  /** Allow a leading combinator (relative selectors inside :has()). */
  relative?: boolean;
  /** Inside :has(): no nested :has() and no pseudo-elements. */
  inHas?: boolean;
}

/** Validate a token list as plain CSS a Chromium stylesheet will accept. */
export function isValidCssTokens(tokens: readonly SelToken[], opts: ValidateOptions = {}): boolean {
  if (tokens.length === 0) return false;
  for (const complex of splitSelectorList(tokens)) {
    if (complex.length === 0) return false;
    for (let i = 0; i < complex.length; i++) {
      const tok = complex[i];
      if (tok.t === 'comb') {
        if (i === 0 && !opts.relative) return false;
        if (i === complex.length - 1) return false;
        if (complex[i + 1].t === 'comb') return false;
        continue;
      }
      if (tok.t === 'simple') {
        // A type or universal selector must start its compound.
        if ((tok.kind === 'type' || tok.kind === 'universal') && i > 0 && complex[i - 1].t !== 'comb') return false;
        continue;
      }
      if (tok.t === 'pseudo') {
        if (!isValidPseudo(tok, opts)) return false;
      }
    }
  }
  return true;
}

function isValidPseudo(tok: Extract<SelToken, { t: 'pseudo' }>, opts: ValidateOptions): boolean {
  const { name, arg } = tok;
  const element = tok.element || (LEGACY_PSEUDO_ELEMENTS.has(name) && arg === null);
  if (name.startsWith('-')) {
    // Vendor prefixes: only -webkit- exists in Chromium.
    if (!name.startsWith('-webkit-')) return false;
    if (opts.inHas && element) return false;
    return arg === null || arg.trim() !== '';
  }
  if (element) {
    if (opts.inHas) return false;
    if (!KNOWN_PSEUDO_ELEMENTS.has(name)) return false;
    if (PSEUDO_ELEMENTS_WITH_ARGS.has(name)) return arg !== null && arg.trim() !== '';
    return arg === null;
  }
  if (!KNOWN_PSEUDO_CLASSES.has(name)) return false;
  if (PSEUDO_CLASSES_WITH_ARGS.has(name)) {
    if (arg === null || arg.trim() === '') return false;
  } else if (!PSEUDO_CLASSES_OPTIONAL_ARGS.has(name)) {
    return arg === null;
  }
  if (arg === null) return true;
  switch (name) {
    case 'not':
    case 'is':
    case 'where':
    case 'host':
    case 'host-context': {
      const inner = tokenizeSelector(arg);
      return inner !== null && isValidCssTokens(inner, { inHas: opts.inHas });
    }
    case 'has': {
      if (opts.inHas) return false;
      const inner = tokenizeSelector(arg);
      return inner !== null && isValidCssTokens(inner, { relative: true, inHas: true });
    }
    case 'nth-child':
    case 'nth-last-child':
    case 'nth-of-type':
    case 'nth-last-of-type':
    case 'nth-col':
    case 'nth-last-col': {
      const m = reNth.exec(arg);
      if (m === null) return false;
      if (m[1] !== undefined) {
        if (!name.endsWith('-child')) return false;
        const inner = tokenizeSelector(m[1]);
        return inner !== null && isValidCssTokens(inner, { inHas: opts.inHas });
      }
      return true;
    }
    case 'lang':
    case 'dir':
    case 'state':
      return /^\s*[\w-]+(?:\s*,\s*[\w-]+)*\s*$/.test(arg);
    default:
      return true;
  }
}

/** Convenience: is this string a valid plain CSS selector (list)? */
export function isValidCss(selector: string, opts: ValidateOptions = {}): boolean {
  const tokens = tokenizeSelector(selector);
  return tokens !== null && isValidCssTokens(tokens, opts);
}

/**
 * The first "#id" / ".class" token a selector requires (ARCHITECTURE §5.1):
 * from the leading compound, else from the subject (last) compound, never
 * from inside functional pseudo-classes. Null for highly generic selectors
 * and selector lists.
 */
export function genericTokenOf(tokens: readonly SelToken[]): string | null {
  if (tokens.some((t) => t.t === 'comma')) return null;
  const compounds: SelToken[][] = [[]];
  for (const tok of tokens) {
    if (tok.t === 'comb') compounds.push([]);
    else compounds[compounds.length - 1].push(tok);
  }
  const pick = (compound: readonly SelToken[]): string | null => {
    for (const tok of compound) {
      if (tok.t === 'simple' && (tok.kind === 'id' || tok.kind === 'class')) {
        if (tok.name === '') continue;
        return (tok.kind === 'id' ? '#' : '.') + tok.name;
      }
    }
    return null;
  };
  return pick(compounds[0]) ?? (compounds.length > 1 ? pick(compounds[compounds.length - 1]) : null);
}
