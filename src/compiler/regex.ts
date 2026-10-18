// Bastion filter compiler — regular-expression helpers for DNR regexFilter.
// Chromium evaluates regexFilter with RE2, which has no lookaround, no
// backreferences and no atomic/possessive constructs, and requires ASCII
// source. Filter lists are written for JavaScript's engine, so we check every
// regex here, translate the few JS-only escapes that have a trivial RE2
// spelling, and turn regexes that are plain literals into urlFilter patterns
// (which do not count against the 1,000 regex-rule budget).
//
// SPDX-License-Identifier: GPL-3.0-or-later

const MAX_RE2_REPEAT = 1000;

const isHex = (c: number): boolean =>
  (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66);
const isDigit = (c: number): boolean => c >= 0x30 && c <= 0x39;
const isAlpha = (c: number): boolean => (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);

// Escapes with the same meaning in JS (non-unicode mode) and RE2.
const SAME_LETTER_ESCAPES = new Set(['d', 'D', 'w', 'W', 's', 'S', 'b', 'B', 't', 'n', 'v', 'f', 'r']);

/**
 * Translate a JavaScript regex source (as written in a filter, no flags other
 * than `i`) into an equivalent RE2 source. Returns null when the regex uses a
 * construct RE2 cannot express (lookaround, backreference, atomic group,
 * possessive quantifier, oversized repetition) or contains non-ASCII.
 */
export function toRe2(source: string): string | null {
  const n = source.length;
  if (n === 0) return null;
  let out = '';
  let inClass = false;
  let i = 0;
  while (i < n) {
    const c = source.charCodeAt(i);
    if (c > 0x7e || (c < 0x20 && c !== 0x09)) return null;
    if (c === 0x5c /* \ */) {
      if (i + 1 >= n) return null;
      const d = source.charCodeAt(i + 1);
      const ch = source[i + 1];
      if (d > 0x7e) return null;
      if (!inClass && isDigit(d) && d !== 0x30) return null; // \1..\9 backreference
      if (d === 0x30 /* \0 */) {
        if (i + 2 < n && isDigit(source.charCodeAt(i + 2))) return null; // legacy octal
        out += '\\x00';
        i += 2;
        continue;
      }
      if (ch === 'k' && source[i + 2] === '<') return null; // named backreference
      if (ch === 'x') {
        if (i + 3 < n + 1 && isHex(source.charCodeAt(i + 2)) && isHex(source.charCodeAt(i + 3))) {
          out += source.slice(i, i + 4);
          i += 4;
          continue;
        }
        out += 'x'; // JS: identity escape
        i += 2;
        continue;
      }
      if (ch === 'u') {
        if (
          i + 5 < n + 1 &&
          isHex(source.charCodeAt(i + 2)) && isHex(source.charCodeAt(i + 3)) &&
          isHex(source.charCodeAt(i + 4)) && isHex(source.charCodeAt(i + 5))
        ) {
          out += `\\x{${source.slice(i + 2, i + 6)}}`;
          i += 6;
          continue;
        }
        out += 'u';
        i += 2;
        continue;
      }
      if (ch === 'c') return null; // control escapes: not worth translating
      if (isAlpha(d)) {
        if (inClass && ch === 'b') {
          out += '\\x08'; // backspace inside a class in JS
          i += 2;
          continue;
        }
        if (SAME_LETTER_ESCAPES.has(ch)) {
          out += source.slice(i, i + 2);
        } else {
          // JS identity escape of a letter ("\e" = "e"); RE2 would read many of
          // these (\A, \z, \C, \Q, \p ...) as something else.
          out += ch;
        }
        i += 2;
        continue;
      }
      // Escaped punctuation/space is a literal in both engines.
      out += source.slice(i, i + 2);
      i += 2;
      continue;
    }
    if (inClass) {
      if (c === 0x5d /* ] */) {
        inClass = false;
        out += ']';
      } else if (c === 0x5b /* [ */) {
        out += '\\['; // RE2 would try to read "[:alpha:]" style classes
      } else {
        out += source[i];
      }
      i += 1;
      continue;
    }
    switch (c) {
      case 0x5b /* [ */: {
        if (source.startsWith('[^]', i)) {
          out += '[\\s\\S]';
          i += 3;
          continue;
        }
        // "[]" matches nothing in JS but starts a class containing "]" in RE2.
        if (source.charCodeAt(i + 1) === 0x5d) return null;
        if (source.charCodeAt(i + 1) === 0x5e && source.charCodeAt(i + 2) === 0x5d) return null;
        inClass = true;
        if (source.charCodeAt(i + 1) === 0x5e /* ^ */) {
          out += '[^';
          i += 2;
        } else {
          out += '[';
          i += 1;
        }
        continue;
      }
      case 0x28 /* ( */: {
        if (source.charCodeAt(i + 1) === 0x3f /* ? */) {
          const e = source[i + 2];
          if (e === '=' || e === '!' || e === '>') return null; // lookahead, atomic
          if (e === '<') {
            const f = source[i + 3];
            if (f === '=' || f === '!') return null; // lookbehind
            out += '(?P<';
            i += 3;
            continue;
          }
        }
        out += '(';
        i += 1;
        continue;
      }
      case 0x2a /* * */:
      case 0x2b /* + */:
      case 0x3f /* ? */: {
        out += source[i];
        i += 1;
        // A quantifier followed by "+" is possessive in some engines (and a
        // syntax error in JS); "?" after a quantifier is plain laziness.
        if (source.charCodeAt(i) === 0x2b && c !== 0x3f) return null;
        continue;
      }
      case 0x7b /* { */: {
        const m = /^\{(\d+)(?:,(\d*))?\}/.exec(source.slice(i, i + 24));
        if (m !== null) {
          const lo = parseInt(m[1], 10);
          const hi = m[2] !== undefined && m[2] !== '' ? parseInt(m[2], 10) : lo;
          if (lo > MAX_RE2_REPEAT || hi > MAX_RE2_REPEAT) return null;
          out += m[0];
          i += m[0].length;
          if (source.charCodeAt(i) === 0x2b) return null;
          continue;
        }
        out += '\\{'; // JS treats a non-quantifier brace as a literal
        i += 1;
        continue;
      }
      case 0x7d /* } */:
        out += '\\}';
        i += 1;
        continue;
      default:
        out += source[i];
        i += 1;
    }
  }
  if (inClass) return null;
  return out;
}

/** True if the JS regex source is usable as a DNR regexFilter (RE2 + ASCII). */
export function isRe2Compatible(source: string): boolean {
  try {
    void new RegExp(source);
  } catch {
    return false;
  }
  return toRe2(source) !== null;
}

// Characters that are literal in a regex and plain in a urlFilter.
const reUrlLiteralChar = /[A-Za-z0-9/\-_=&:;,~@!'"<>#%]/;
// Escaped punctuation that stays literal in a urlFilter ("*", "^" and "|" are
// urlFilter syntax and cannot be expressed).
const reUrlEscapable = /[/.\-?=&:;,~@!'"<>#%_+()[\]{}$]/;

/**
 * If a regex source is just a literal (optionally anchored with ^ and $),
 * return the equivalent urlFilter ("^https://x/" -> "|https://x/"). The match
 * is a substring match in both cases, so semantics are preserved.
 */
export function regexToUrlFilter(source: string): string | null {
  const n = source.length;
  if (n === 0) return null;
  let i = 0;
  let out = '';
  if (source.charCodeAt(0) === 0x5e /* ^ */) {
    out = '|';
    i = 1;
  }
  let body = 0;
  while (i < n) {
    const ch = source[i];
    if (ch === '\\') {
      if (i + 1 >= n) return null;
      const d = source[i + 1];
      if (!reUrlEscapable.test(d)) return null;
      out += d;
      body += 1;
      i += 2;
      continue;
    }
    if (ch === '$' && i === n - 1) {
      out += '|';
      i += 1;
      continue;
    }
    if (!reUrlLiteralChar.test(ch)) return null;
    out += ch;
    body += 1;
    i += 1;
  }
  if (body < 2) return null;
  return out;
}
