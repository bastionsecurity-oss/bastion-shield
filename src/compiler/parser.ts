// Bastion filter compiler — line classification and network-filter parsing.
// Mirrors the decisions of uBlock Origin's AstFilterParser
// (static-filtering-parser.js) where they affect the result, but uses plain
// character scans instead of an AST: lists are maintained against uBO, so
// parity matters more than any particular grammar.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { normalizeHostname, normalizeHostOrEntity, reHostnameAscii, isEntity } from './hostname.ts';

// ---------------------------------------------------------------------------
// Lines
// ---------------------------------------------------------------------------

export interface SourceLine {
  /** 1-based line number of the first physical line. */
  line: number;
  text: string;
}

/**
 * Split list text into trimmed logical lines, joining uBO-style continuation
 * lines ("… \" followed by a line indented with four spaces).
 */
export function splitLines(text: string): SourceLine[] {
  const raw = text.split('\n');
  const out: SourceLine[] = [];
  for (let i = 0; i < raw.length; i++) {
    let line = raw[i];
    if (line.length !== 0 && line.charCodeAt(line.length - 1) === 0x0d) line = line.slice(0, -1);
    const start = i + 1;
    if (line.endsWith(' \\')) {
      while (line.endsWith(' \\') && i + 1 < raw.length && raw[i + 1].startsWith('    ')) {
        let next = raw[i + 1];
        if (next.endsWith('\r')) next = next.slice(0, -1);
        line = line.slice(0, -2).trim() + next.trim();
        i += 1;
      }
    }
    const t = line.trim();
    if (t.length === 0) continue;
    out.push({ line: start, text: t });
  }
  return out;
}

export type LineKind = 'comment' | 'network' | 'extended';

export interface ExtAnchor {
  /** Index of the anchor in the line. */
  index: number;
  /** The anchor itself: "##", "#@#", "#?#", "#@?#", "#$#", "#@$#", "#$?#", "#@$?#", "#%#", "#@%#". */
  anchor: string;
}

const reCommentLine = /^(?:!|#\s|####|\[adblock)/i;

/** Find the first cosmetic anchor (uBO: /(#@?(?:\$\?|\$|%|\?)?#).{1,2}/). */
export function findExtAnchor(line: string): ExtAnchor | null {
  let i = line.indexOf('#');
  const n = line.length;
  while (i !== -1 && i < n - 1) {
    let j = i + 1;
    if (line.charCodeAt(j) === 0x40 /* @ */) j += 1;
    const c = line.charCodeAt(j);
    if (c === 0x24 /* $ */) {
      j += 1;
      if (line.charCodeAt(j) === 0x3f /* ? */) j += 1;
    } else if (c === 0x25 /* % */ || c === 0x3f /* ? */) {
      j += 1;
    }
    if (line.charCodeAt(j) === 0x23 /* # */ && j + 1 < n) {
      return { index: i, anchor: line.slice(i, j + 1) };
    }
    i = line.indexOf('#', i + 1);
  }
  return null;
}

export function classifyLine(line: string): { kind: LineKind; ext?: ExtAnchor } {
  const c0 = line.charCodeAt(0);
  if (c0 === 0x21 /* ! */) return { kind: 'comment' };
  if ((c0 === 0x23 /* # */ || c0 === 0x5b /* [ */) && reCommentLine.test(line)) return { kind: 'comment' };
  const ext = line.indexOf('#') !== -1 ? findExtAnchor(line) : null;
  if (ext !== null) return { kind: 'extended', ext };
  if (c0 === 0x23) return { kind: 'comment' };
  return { kind: 'network' };
}

// ---------------------------------------------------------------------------
// Domain lists ($domain=a|~b, a.com,~b.com##…)
// ---------------------------------------------------------------------------

export type DomainKind = 'host' | 'entity' | 'regex' | 'wildcard' | 'other';

export interface DomainEntry {
  /** Normalized value: hostname, "label.*", "/regex/", "*", or the raw advanced form. */
  value: string;
  negated: boolean;
  kind: DomainKind;
}

export interface DomainListMode {
  negation: boolean;
  entity: boolean;
  regex: boolean;
  /** Cosmetic lists: "*" alone, "host>>" ancestors and "host/path" forms. */
  advanced: boolean;
}

export const NET_DOMAIN_MODE: DomainListMode = { negation: true, entity: true, regex: true, advanced: false };
export const DENYALLOW_MODE: DomainListMode = { negation: false, entity: false, regex: false, advanced: false };
export const EXT_DOMAIN_MODE: DomainListMode = { negation: true, entity: true, regex: true, advanced: true };

/** Index just past the closing unescaped "/" of a regex starting at `start` ("/"), or -1. */
function endOfRegexLiteral(s: string, start: number): number {
  for (let i = start + 1; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x5c /* \ */) {
      i += 1;
      continue;
    }
    if (c === 0x2f /* / */) return i + 1;
  }
  return -1;
}

/**
 * Parse a separator-delimited domain list. Returns null on a syntax error
 * (empty entry, bad hostname, negation where not allowed, ...), which makes
 * uBO reject the whole filter.
 */
export function parseDomainList(s: string, sep: string, mode: DomainListMode): DomainEntry[] | null {
  const out: DomainEntry[] = [];
  const n = s.length;
  if (n === 0) return null;
  const sepCode = sep.charCodeAt(0);
  let i = 0;
  while (i <= n) {
    if (i === n) {
      // trailing separator → empty entry
      return out.length === 0 ? null : s.charCodeAt(n - 1) === sepCode ? null : out;
    }
    let negated = false;
    let beg = i;
    if (s.charCodeAt(beg) === 0x7e /* ~ */) {
      if (!mode.negation) return null;
      negated = true;
      beg += 1;
    }
    let end: number;
    let isRegex = false;
    if (s.charCodeAt(beg) === 0x2f /* / */ && mode.regex) {
      end = endOfRegexLiteral(s, beg);
      if (end === -1 || (end < n && s.charCodeAt(end) !== sepCode)) {
        // Not a regex after all (e.g. a path); fall back to a plain scan.
        end = s.indexOf(sep, beg);
        if (end === -1) end = n;
      } else {
        isRegex = end - beg > 2;
      }
    } else {
      end = s.indexOf(sep, beg);
      if (end === -1) end = n;
    }
    const raw = s.slice(beg, end);
    if (raw.length === 0) return null;
    let entry: DomainEntry | null = null;
    if (isRegex) {
      const src = raw.slice(1, -1).replace(/\\\|/g, '|');
      try {
        entry = { value: `/${new RegExp(src).source}/`, negated, kind: 'regex' };
      } catch {
        return null;
      }
    } else if (raw === '*') {
      if (!mode.advanced) return null;
      entry = { value: '*', negated, kind: 'wildcard' };
    } else if (isEntity(raw)) {
      if (!mode.entity) return null;
      const v = normalizeHostOrEntity(raw, true);
      if (v === null) return null;
      entry = { value: v, negated, kind: 'entity' };
    } else if (mode.advanced && (raw.includes('>>') || raw.includes('/'))) {
      entry = { value: raw, negated, kind: 'other' };
    } else {
      const v = reHostnameAscii.test(raw) ? raw : normalizeHostname(raw);
      if (v === null) return null;
      entry = { value: v, negated, kind: 'host' };
    }
    out.push(entry);
    if (end >= n) return out;
    i = end + 1;
    if (i === n) return null; // dangling separator
  }
  return out;
}

// ---------------------------------------------------------------------------
// Network filters
// ---------------------------------------------------------------------------

/** Option aliases -> canonical names (uBO nodeTypeFromOptionName synonyms). */
export const OPTION_ALIASES: ReadonlyMap<string, string> = new Map([
  ['1p', '1p'], ['first-party', '1p'],
  ['3p', '3p'], ['third-party', '3p'],
  ['strict1p', 'strict1p'], ['strict-first-party', 'strict1p'],
  ['strict3p', 'strict3p'], ['strict-third-party', 'strict3p'],
  ['all', 'all'],
  ['badfilter', 'badfilter'],
  ['cname', 'cname'],
  ['csp', 'csp'],
  ['css', 'css'], ['stylesheet', 'css'],
  ['denyallow', 'denyallow'],
  ['doc', 'doc'], ['document', 'doc'],
  ['ehide', 'ehide'], ['elemhide', 'ehide'],
  ['empty', 'empty'],
  ['font', 'font'],
  ['frame', 'frame'], ['subdocument', 'frame'],
  ['from', 'from'], ['domain', 'from'],
  ['genericblock', 'genericblock'],
  ['ghide', 'ghide'], ['generichide', 'ghide'],
  ['image', 'image'],
  ['important', 'important'],
  ['inline-font', 'inline-font'],
  ['inline-script', 'inline-script'],
  ['ipaddress', 'ipaddress'],
  ['match-case', 'match-case'],
  ['media', 'media'],
  ['method', 'method'],
  ['mp4', 'mp4'],
  ['_', '_'],
  ['object', 'object'], ['object-subrequest', 'object'],
  ['other', 'other'],
  ['permissions', 'permissions'],
  ['ping', 'ping'], ['beacon', 'ping'],
  ['popunder', 'popunder'],
  ['popup', 'popup'],
  ['reason', 'reason'],
  ['redirect', 'redirect'], ['rewrite', 'redirect'],
  ['redirect-rule', 'redirect-rule'],
  ['removeparam', 'removeparam'], ['queryprune', 'removeparam'],
  ['replace', 'replace'],
  ['requestheader', 'requestheader'],
  ['header', 'header'], ['responseheader', 'header'],
  ['script', 'script'],
  ['shide', 'shide'], ['specifichide', 'shide'],
  ['to', 'to'],
  ['top', 'top'],
  ['urlskip', 'urlskip'],
  ['uritransform', 'uritransform'], ['urltransform', 'uritransform'],
  ['xhr', 'xhr'], ['xmlhttprequest', 'xhr'],
  ['webrtc', 'webrtc'],
  ['websocket', 'websocket'],
]);

export interface NetOption {
  /** Canonical option name (see OPTION_ALIASES), or the unknown raw name. */
  name: string;
  /** Name as written (for messages). */
  rawName: string;
  negated: boolean;
  /** Option value, null when there is no "=". */
  value: string | null;
  known: boolean;
}

export type PatternKind = 'any' | 'hostname' | 'plain' | 'generic' | 'regex';

export interface ParsedNetFilter {
  raw: string;
  exception: boolean;
  kind: PatternKind;
  /** Normalized pattern without anchors (regex: the normalized source). */
  pattern: string;
  hnAnchor: boolean;
  leftAnchor: boolean;
  rightAnchor: boolean;
  /** `||host^` / hosts-file form where the trailing separator is implied. */
  rightSeparator: boolean;
  options: NetOption[];
  hasOptions: boolean;
  /** The line was a hosts-file entry ("0.0.0.0 host"). */
  hostsEntry: boolean;
}

export type NetParseResult =
  | { ok: true; filter: ParsedNetFilter }
  | { ok: false; reason: string; ignore?: boolean };

const isTokenCharCode = (c: number): boolean =>
  c === 0x25 || (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
const isWordCharCode = (c: number): boolean =>
  (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x5f;
const isOptNameCharCode = (c: number): boolean =>
  (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x7a) || c === 0x5f || c === 0x2d;

/** Does a known option name start at s[j+1] (after "$"), uBO-style word boundary? */
function isOptionsAnchorAt(s: string, j: number): boolean {
  const n = s.length;
  let k = j + 1;
  if (s.charCodeAt(k) === 0x7e /* ~ */) k += 1;
  let e = k;
  while (e < n && isOptNameCharCode(s.charCodeAt(e))) e += 1;
  for (let p = e; p > k; p--) {
    if (p < e && s.charCodeAt(p) !== 0x2d /* - */) continue;
    if (!isWordCharCode(s.charCodeAt(p - 1))) continue;
    if (p === e && p < n && isWordCharCode(s.charCodeAt(p))) continue;
    if (OPTION_ALIASES.has(s.slice(k, p))) return true;
  }
  return false;
}

/** Position of the "$" that starts the options, s.length if none, -1 for "$$" HTML filters. */
function indexOfOptionsAnchor(s: string): number {
  let j = s.lastIndexOf('$');
  if (j === -1) return s.length;
  let html = false;
  for (;;) {
    if (j > 0 && s.charCodeAt(j - 1) === 0x24) html = true;
    if (isOptionsAnchorAt(s, j)) return j > 0 && s.charCodeAt(j - 1) === 0x24 ? -1 : j;
    if (j === 0) break;
    j = s.lastIndexOf('$', j - 1);
    if (j === -1) break;
  }
  if (html) return -1;
  // uBO treats "$" as part of the pattern when the first option is unknown
  // ("/x.$foo=1,script" never matches anything). When the tail is clearly an
  // option list with a known option in it, report the unknown option instead.
  const last = s.lastIndexOf('$');
  if (last !== -1 && reOptionListTail.test(s.slice(last + 1))) {
    const names = s.slice(last + 1).split(',').map((o) => o.replace(/^~/, '').replace(/=.*$/, ''));
    if (names.some((nm) => OPTION_ALIASES.has(nm))) return last;
  }
  return s.length;
}

const reOptionListTail = /^~?[a-z][a-z0-9_-]*(?:=[^,]*)?(?:,~?[a-z][a-z0-9_-]*(?:=[^,]*)?)+$/;

const reNetOptionComma = /,(?:~?[13a-z-]+(?:=.*?)?|_+)(?:,|$)/;

/** Remove the escaping backslash in "\," (keeping escaped backslashes intact). */
function unescapeSeparator(s: string, sep: string): string {
  if (s.indexOf('\\' + sep) === -1) return s;
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '\\' && i + 1 < s.length) {
      if (s[i + 1] === sep) {
        out += sep;
        i += 1;
        continue;
      }
      out += c + s[i + 1];
      i += 1;
      continue;
    }
    out += c;
  }
  return out;
}

/** Tokenize the options part ("script,domain=a|b,csp=…"). */
export function parseNetOptions(s: string): NetOption[] | null {
  const out: NetOption[] = [];
  const n = s.length;
  let i = 0;
  if (n === 0) return null;
  while (i < n) {
    let k = i;
    let negated = false;
    if (s.charCodeAt(k) === 0x7e) {
      negated = true;
      k += 1;
    }
    let e = k;
    while (e < n && isOptNameCharCode(s.charCodeAt(e))) e += 1;
    if (e === k) return null;
    const rawName = s.slice(k, e);
    const canonical = OPTION_ALIASES.get(rawName) ?? (/^_+$/.test(rawName) ? '_' : undefined);
    const name = canonical ?? rawName;
    let value: string | null = null;
    let next: number;
    if (s.charCodeAt(e) === 0x3d /* = */) {
      const vstart = e + 1;
      const q = s.charCodeAt(vstart);
      let done = false;
      next = n;
      if (q === 0x22 || q === 0x27 || q === 0x60) {
        // Quoted value: the closing quote must be followed by "," or the end.
        let j = vstart + 1;
        while (j < n) {
          const c = s.charCodeAt(j);
          if (c === 0x5c) {
            j += 2;
            continue;
          }
          if (c === q) break;
          j += 1;
        }
        if (j < n && (j + 1 === n || s.charCodeAt(j + 1) === 0x2c)) {
          value = unescapeSeparator(s.slice(vstart + 1, j), String.fromCharCode(q));
          next = j + 1;
          done = true;
        }
      }
      if (!done) {
        const m = reNetOptionComma.exec(s.slice(vstart));
        const vend = m === null ? n : vstart + m.index;
        value = unescapeSeparator(s.slice(vstart, vend), ',');
        next = vend;
      }
      if (value === '' || value === null) return null;
    } else {
      next = e;
    }
    out.push({ name, rawName, negated, value, known: canonical !== undefined });
    if (next >= n) break;
    if (s.charCodeAt(next) !== 0x2c /* , */) return null;
    i = next + 1;
    if (i === n) return null; // dangling ","
  }
  return out;
}

/** uBO's `||hostname^` fast path: like reHostnameAscii but the last label may be one character (IPs). */
const reHnAnchoredHostname = /^(?:[\da-z][\da-z_-]*\.)*[\da-z_-]*[\da-z]$/;
const reHostsSink = /^[\w%.:[\]-]+\s+/;
const reHostsRedirect = /(?:0\.0\.0\.0|broadcasthost|local|localhost(?:\.localdomain)?|ip6-\w+)(?:[^\w.-]|$)/;
const reInlineComment = /\s+#.*$/;
const reHasWhitespace = /\s/;
const reHasInvalidChar = /[\x00-\x1F\x7F-\x9F\xAD\u061C\u200B-\u200F\u2028\u2029\uFEFF\uFFF9-\uFFFC]/;
const reHasNonAscii = /[^\x00-\x7f]/;
const reHostnamePatternPart = /^[^\x00-\x24\x26-\x29\x2B\x2C\x2F\x3A-\x40\x5B-\x5E\x60\x7B-\x7F]+/;
const rePointlessLeadingWildcards = /^(\*+)[^%0-9A-Za-z\u{a0}-\u{10FFFF}]/u;
const rePointlessTrailingSeparator = /\*(\^\**)$/;
const rePointlessTrailingWildcards = /(?:[^%0-9A-Za-z]|[%0-9A-Za-z]{7,})(\*+)$/;
const reHasPatternSpecialChars = /[*^]/;

/**
 * Lower-case (unless `keepCase`), punycode the hostname part and
 * percent-encode remaining non-ASCII, as DNR requires ASCII urlFilters.
 */
function normalizePattern(pattern: string, keepCase: boolean): string | null {
  if (reHasInvalidChar.test(pattern)) return null;
  let normal = keepCase ? pattern : pattern.toLowerCase();
  if (!reHasNonAscii.test(normal)) return normal;
  const m = reHostnamePatternPart.exec(normal);
  if (m !== null) {
    const hn = m[0].replace(/[^.]+/g, (label) => {
      if (!reHasNonAscii.test(label)) return label;
      const lower = label.toLowerCase();
      // A leading "-" stops the URL parser from punycoding; uBO prepends "*"
      // as a sacrificial character for the same reason.
      const probe = lower.charCodeAt(0) === 0x2d ? `x${lower}` : lower;
      const n = normalizeHostname(probe);
      if (n === null) return label;
      return lower.charCodeAt(0) === 0x2d ? n.slice(1) : n;
    });
    normal = hn + normal.slice(m[0].length);
  }
  if (!reHasNonAscii.test(normal)) return normal;
  try {
    normal = normal.replace(/[^\x00-\x7f]/gu, (ch) => {
      const enc = encodeURIComponent(ch);
      return keepCase ? enc : enc.toLowerCase();
    });
  } catch {
    return null;
  }
  return normal;
}

/**
 * Parse one network filter line (already classified as network).
 * `ok: false, ignore: true` marks lines uBO silently skips (hosts-file
 * localhost entries and the like).
 */
export function parseNetworkFilter(line: string): NetParseResult {
  let s = line;
  const hasWhitespace = reHasWhitespace.test(s);
  if (hasWhitespace && reInlineComment.test(s)) {
    s = s.replace(reInlineComment, '');
    if (s.length === 0) return { ok: false, reason: 'comment', ignore: true };
  }
  let exception = false;
  let beg = 0;
  if (s.startsWith('@@')) {
    exception = true;
    beg = 2;
  }
  const anchor = indexOfOptionsAnchor(s);
  if (anchor === -1) return { ok: false, reason: 'html-filtering' };
  if (anchor < beg) return { ok: false, reason: 'invalid-filter' };
  let options: NetOption[] = [];
  const hasOptions = anchor < s.length;
  if (hasOptions) {
    const parsed = parseNetOptions(s.slice(anchor + 1));
    if (parsed === null) return { ok: false, reason: 'invalid-option-syntax' };
    options = parsed;
  }
  let pattern = s.slice(beg, anchor);
  const matchCase = options.some((o) => o.name === 'match-case');

  const filter: ParsedNetFilter = {
    raw: line,
    exception,
    kind: 'any',
    pattern: '*',
    hnAnchor: false,
    leftAnchor: false,
    rightAnchor: false,
    rightSeparator: false,
    options,
    hasOptions,
    hostsEntry: false,
  };

  if (pattern.length === 0) return { ok: true, filter };

  // Hosts-file entry: "0.0.0.0 example.com"
  if (hasWhitespace && !exception && !hasOptions) {
    const m = reHostsSink.exec(pattern);
    if (m !== null) {
      const host = pattern.slice(m[0].length).toLowerCase();
      if (reHostsRedirect.test(host) || !reHostnameAscii.test(host)) {
        return { ok: false, reason: 'hosts-ignored', ignore: true };
      }
      filter.kind = 'hostname';
      filter.pattern = host;
      filter.hnAnchor = true;
      filter.rightSeparator = true;
      filter.hostsEntry = true;
      return { ok: true, filter };
    }
  }

  // Regex: /.../
  if (pattern.length > 2 && pattern.charCodeAt(0) === 0x2f && pattern.charCodeAt(pattern.length - 1) === 0x2f) {
    try {
      filter.pattern = new RegExp(pattern.slice(1, -1)).source;
    } catch {
      return { ok: false, reason: 'invalid-regex' };
    }
    filter.kind = 'regex';
    return { ok: true, filter };
  }

  const hasWildcard = pattern.includes('*');
  // Left anchors: "||" / "|" count only when followed by a token character.
  if (pattern.charCodeAt(0) === 0x7c /* | */) {
    if (pattern.charCodeAt(1) === 0x7c) {
      if (isTokenCharCode(pattern.charCodeAt(2) || 0) || reHasNonAscii.test(pattern[2] ?? '')) filter.hnAnchor = true;
      pattern = pattern.slice(2);
    } else {
      if (isTokenCharCode(pattern.charCodeAt(1) || 0)) filter.leftAnchor = true;
      pattern = pattern.slice(1);
    }
  }
  // Right anchor, unless "*|".
  if (pattern.length !== 0 && pattern.charCodeAt(pattern.length - 1) === 0x7c) {
    if (pattern.charCodeAt(pattern.length - 2) !== 0x2a) filter.rightAnchor = true;
    pattern = pattern.slice(0, -1);
  }
  if (hasWildcard) {
    const m = rePointlessLeadingWildcards.exec(pattern);
    if (m !== null) pattern = pattern.slice(m[1].length);
  }
  {
    const m = rePointlessTrailingSeparator.exec(pattern);
    if (m !== null) pattern = pattern.slice(0, -m[1].length);
  }
  if (hasWildcard) {
    const m = rePointlessTrailingWildcards.exec(pattern);
    if (m !== null) {
      const len = m[1].length;
      // Keep one "*" when dropping it would make the pattern look like a regex.
      const needWildcard = pattern.charCodeAt(0) === 0x2f && pattern.charCodeAt(pattern.length - len - 1) === 0x2f;
      pattern = pattern.slice(0, pattern.length - len + (needWildcard ? 1 : 0));
    }
  }
  if (reHasWhitespace.test(pattern)) return { ok: false, reason: 'invalid-pattern' };
  let normal = normalizePattern(pattern, matchCase);
  if (normal === null) return { ok: false, reason: 'invalid-pattern' };
  // "|http:" and "|http://" are the same anchor; uBO normalizes to the latter.
  if (filter.leftAnchor && !filter.rightAnchor && /^https?:$/i.test(normal)) normal += '//';
  const lower = matchCase ? normal.toLowerCase() : normal;

  if (normal === '' || normal === '*') {
    filter.kind = 'any';
    filter.pattern = '*';
  } else if (
    filter.hnAnchor &&
    !hasWildcard &&
    !filter.rightAnchor &&
    lower.endsWith('^') &&
    lower.indexOf('^') === lower.length - 1 &&
    reHnAnchoredHostname.test(lower.slice(0, -1))
  ) {
    // "||example.com^" (and "||1.2.3.4^"): a hostname filter.
    filter.kind = 'hostname';
    filter.pattern = lower.slice(0, -1);
    filter.rightSeparator = true;
  } else if (reHostnameAscii.test(lower)) {
    // uBO quirk kept for parity: a lower-case ASCII "||example.com" without
    // options takes uBO's fast "plain pattern" path (urlFilter), while the
    // same pattern with options, or a bare "example.com", is a hostname.
    if (filter.hnAnchor && !exception && !hasOptions && /^\|\|[0-9a-z%&,\-./:;=?_]+$/.test(s.slice(beg))) {
      filter.kind = 'plain';
      filter.pattern = lower;
    } else {
      filter.kind = 'hostname';
      filter.pattern = lower;
    }
  } else if (reHasPatternSpecialChars.test(normal)) {
    filter.kind = 'generic';
    filter.pattern = normal;
  } else {
    filter.kind = 'plain';
    filter.pattern = normal;
  }
  return { ok: true, filter };
}

/**
 * Parse one hosts-file line ("0.0.0.0 a.com b.com", "a.com"). Returns the
 * normalized hostnames (possibly empty for comments/localhost entries) or
 * null when the line is not a hosts entry.
 */
export function parseHostsLine(line: string): string[] | null {
  let s = line;
  const hash = s.indexOf('#');
  if (hash !== -1) s = s.slice(0, hash);
  s = s.trim();
  if (s === '') return [];
  const parts = s.split(/\s+/);
  let hosts = parts;
  // First token is an address when followed by hostnames.
  if (parts.length > 1 && /^(?:[\d.]+|[\da-f:]+|\[[\da-f:]+\])$/i.test(parts[0])) hosts = parts.slice(1);
  const out: string[] = [];
  for (const h of hosts) {
    if (reHostsRedirect.test(h) && /^(?:0\.0\.0\.0|broadcasthost|local|localhost(?:\.localdomain)?|ip6-\w+)$/.test(h)) continue;
    const n = normalizeHostname(h);
    if (n === null) return null;
    if (n === 'localhost' || n === 'local' || n === 'broadcasthost' || n === '0.0.0.0') continue;
    out.push(n);
  }
  return out;
}
