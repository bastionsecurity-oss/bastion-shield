// Bastion Shield — argument parsing for procedural cosmetic operators.
//
// The compiler stores procedural tasks as `[operator, argument]` with the
// argument as filter text (see ProceduralTask in shared/types.ts). The
// helpers here turn that text into what the engine needs, with uBO's exact
// semantics (static-filtering-parser.js: unquoteString, compileText,
// compileMatchAttrArgument, compileCSSDeclaration, compileAttrList,
// compileUpwardArgument, compileStyleProperties). They also accept uBO's
// pre-compiled object forms ({attr, value}, {name, pseudo, value}) so the
// engine works with either compiler output. Pure: unit-tested under Node.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/*! Procedural argument parsing: follows uBlock Origin static-filtering-parser.js, Copyright (C) Raymond Hill, GPL-3.0-or-later. Modified by Bastion Security GmbH. */

const RE_LITERAL = /^\/(.+)\/([imu]*)$/;
const RE_SPECIALS = /[.*+?^${}()|[\]\\]/g;

export function escapeRegex(s: string): string {
  return s.replace(RE_SPECIALS, '\\$&');
}

/**
 * Remove one level of surrounding quotes ('…' or "…") with uBO's escape
 * rules (backslash escapes only the quote and the backslash). A string that
 * is not entirely one quoted token is returned unchanged.
 */
export function unquote(s: string): string {
  if (s.length < 2) return s;
  const q = s.charCodeAt(0);
  if (q !== 0x22 && q !== 0x27) return s;
  let out = '';
  for (let i = 1; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c === q) return i === s.length - 1 ? out : s;
    if (c === 0x5c /* \ */) {
      i++;
      if (i === s.length) return s;
      c = s.charCodeAt(i);
      if (c !== 0x5c && c !== q) out += '\\';
    }
    out += String.fromCharCode(c);
  }
  return s; // unterminated
}

/**
 * uBO regexFromString: "/source/flags" is a regex (flags limited to i, m, u),
 * anything else is literal text — a substring match, or a whole-string
 * match when `exact`. "" matches everything. Invalid regexes yield null
 * (the filter then never matches) instead of throwing.
 */
export function regexFromString(s: string, exact = false): RegExp | null {
  if (s === '') return /^/;
  const m = RE_LITERAL.exec(s);
  try {
    if (m !== null) return new RegExp(m[1], m[2] || undefined);
    const src = escapeRegex(s);
    return new RegExp(exact ? `^${src}$` : src);
  } catch {
    return null;
  }
}

export interface AttrArg {
  attr: string;
  value: string;
}

/** `name`, `name=value`, `"name"="value"`, or {attr, value}. Used by :matches-attr and :matches-prop. */
export function parseAttrArg(arg: unknown): AttrArg | null {
  if (arg !== null && typeof arg === 'object') {
    const o = arg as { attr?: unknown; value?: unknown };
    if (typeof o.attr !== 'string' || o.attr === '') return null;
    return { attr: o.attr, value: typeof o.value === 'string' ? o.value : '' };
  }
  if (typeof arg !== 'string') return null;
  const s = arg.trim();
  if (s === '') return null;
  let attr: string;
  let value = '';
  const c0 = s.charCodeAt(0);
  if (c0 === 0x22 || c0 === 0x27) {
    // Quoted attribute name: find its closing quote, honouring escapes.
    let end = -1;
    for (let i = 1; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c === 0x5c) {
        i++;
        continue;
      }
      if (c === c0) {
        end = i;
        break;
      }
    }
    if (end === -1) return null;
    const head = unquote(s.slice(0, end + 1));
    const rest = s.slice(end + 1);
    if (rest === '') {
      // The whole argument was one quoted token: split its content (uBO does the same).
      const pos = head.indexOf('=');
      attr = pos === -1 ? head : head.slice(0, pos);
      value = pos === -1 ? '' : head.slice(pos + 1);
      return attr === '' ? null : { attr, value };
    }
    if (rest.charCodeAt(0) !== 0x3d /* = */) return null;
    attr = head;
    value = rest.slice(1);
  } else {
    const pos = s.indexOf('=');
    if (pos === -1) {
      attr = s;
    } else {
      attr = s.slice(0, pos);
      value = s.slice(pos + 1);
    }
  }
  if (attr === '') return null;
  if (value !== '') {
    const v0 = value.charCodeAt(0);
    if (v0 === 0x22 || v0 === 0x27) {
      const u = unquote(value);
      if (u === value) return null; // malformed quoting
      value = u;
    }
  }
  return { attr, value };
}

export interface CssArg {
  /** CSS property name as written ("background-image", "--x", "zIndex"). */
  name: string;
  /** Pseudo-element for getComputedStyle ("::before"), or null. */
  pseudo: string | null;
  re: RegExp;
}

/**
 * `[pseudo, ]name: value` where value is "/regex/flags" or literal text
 * matched against the whole computed value, or uBO's compiled
 * {name, pseudo, value: source | [source, flags]}.
 */
export function parseCssArg(arg: unknown, pseudoDefault: string | null): CssArg | null {
  if (arg !== null && typeof arg === 'object') {
    const o = arg as { name?: unknown; pseudo?: unknown; value?: unknown };
    if (typeof o.name !== 'string' || o.name === '') return null;
    let src: unknown = o.value;
    let flags: string | undefined;
    if (Array.isArray(src)) {
      flags = typeof src[1] === 'string' ? src[1] : undefined;
      src = src[0];
    }
    if (typeof src !== 'string') return null;
    try {
      const pseudo = typeof o.pseudo === 'string' && o.pseudo !== '' ? `::${o.pseudo}` : pseudoDefault;
      return { name: o.name, pseudo, re: new RegExp(src, flags) };
    } catch {
      return null;
    }
  }
  if (typeof arg !== 'string') return null;
  let s = arg.trim();
  let pseudo = pseudoDefault;
  const pm = /^([a-z-]+)\s*,/.exec(s);
  if (pm !== null) {
    pseudo = `::${pm[1]}`;
    s = s.slice(pm[0].length).trim();
  }
  const pos = s.indexOf(':');
  if (pos <= 0) return null;
  const name = s.slice(0, pos).trim();
  const value = s.slice(pos + 1).trim();
  if (name === '') return null;
  const m = /^\/(.+)\/([imu]+)?$/.exec(value);
  try {
    const re = m !== null ? new RegExp(m[1], m[2]) : new RegExp(`^${escapeRegex(value)}$`);
    return { name, pseudo, re };
  } catch {
    return null;
  }
}

/** Comma-separated attribute names for :watch-attr ("" or [] = all attributes). */
export function parseAttrList(arg: unknown): string[] {
  if (Array.isArray(arg)) return arg.filter((a): a is string => typeof a === 'string' && a !== '');
  if (typeof arg !== 'string') return [];
  return arg
    .split(',')
    .map((a) => a.trim())
    .filter((a) => a !== '');
}

/** :upward(n) with 1 <= n < 256, or :upward(selector). null = invalid. */
export function parseUpward(arg: unknown): number | string | null {
  if (typeof arg === 'number') return Number.isInteger(arg) && arg >= 1 && arg < 256 ? arg : null;
  if (typeof arg !== 'string') return null;
  const s = arg.trim();
  if (s === '') return null;
  if (/^\d+$/.test(s)) {
    const n = parseInt(s, 10);
    return n >= 1 && n < 256 ? n : null;
  }
  return s;
}

/** :min-text-length(n). */
export function parseMinTextLength(arg: unknown): number | null {
  if (typeof arg === 'number') return Number.isInteger(arg) && arg >= 0 ? arg : null;
  if (typeof arg === 'string' && /^\s*\d+\s*$/.test(arg)) return parseInt(arg, 10);
  return null;
}

/** Text arguments (:has-text, :matches-path, :xpath, :remove-attr, :remove-class) may arrive quoted. */
export function textArg(arg: unknown): string | null {
  if (typeof arg !== 'string') return null;
  return unquote(arg);
}

/**
 * :style() declarations. Same blocklist as uBO (no url(), image-set(),
 * comments, backslashes, "//") plus braces and "<" so a declaration can
 * never close our rule and inject another one.
 */
export function isSafeStyle(s: unknown): s is string {
  if (typeof s !== 'string' || s.trim() === '') return false;
  return !/image-set\(|url\(|\/\s*\/|\\|\/\*|[{}<]/i.test(s);
}
