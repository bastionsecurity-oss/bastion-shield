// Bastion Shield service worker — Brave debounce rules (vendor/brave-lists/
// debounce.json, MPL-2.0 data) converted to DNR regexSubstitution redirects
// to pages/bounce.html (ARCHITECTURE §4.6, §9). bounce.html decodes the
// fragment (percent-encoding, or base64 behind a "b64:" prefix), checks for an
// http(s) URL and calls location.replace.
//
// Supported actions:
//   - "redirect": the target is a query parameter; only values that start
//     with an http(s) scheme (raw or percent-encoded) are captured, because
//     Brave refuses anything else too. With `prepend_scheme` Brave instead
//     wants a scheme-less value, so we capture values that do not start with
//     "ht" and prepend the scheme.
//   - "base64,redirect": as above, base64 values that encode "http…".
//   - "regex-path" / "regex-path-template": Brave's path regex, rewritten so
//     it cannot run into the query or fragment, captures concatenated (or put
//     into the template).
// Skipped with a reason: non-empty `exclude` lists (RE2 has no negative
// lookahead), unknown prefs, and closed query patterns (a pattern without a
// trailing `*` can never carry a query parameter). The de-AMP rules (pref
// brave.de_amp.enabled) follow settings.privacy.deAmp.
//
// When an include pattern names a fixed host ("*://*.example.com/*" or
// "https://t.example.com/*"), the redirect carries it as
// pages/bounce.html?from=<host>#<target>, so the page can refuse targets on
// the tracker's own registrable domain (Brave only debounces cross-site).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { DnrRule } from '../compiler/types.ts';
import { DEBOUNCE_PRIORITY } from './rules.ts';
import { isPlainObject } from './util.ts';

export interface BraveDebounceRule {
  include: string[];
  exclude?: string[];
  action: string;
  param: string;
  prepend_scheme?: string;
  pref?: string;
  redirect_url_template?: string;
}

export interface DebounceConversion {
  rules: DnrRule[];
  skipped: { pattern: string; reason: string }[];
}

export interface DebounceOptions {
  /** settings.privacy.deAmp: enables the rules gated on Brave's de-AMP pref. */
  deAmp?: boolean;
}

const DE_AMP_PREF = 'brave.de_amp.enabled';

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Glob segment to RE2: `*` becomes `wildcard`, everything else is literal. */
function globToRegex(s: string, wildcard: string): string {
  return s.split('*').map(escapeRegex).join(wildcard);
}

interface PatternParts {
  /** ^scheme://host(:port)? */
  origin: string;
  /** Path glob (starting with "/"). */
  path: string;
}

function splitPattern(pattern: string): PatternParts | { error: string } {
  const m = /^(\*|https?):\/\/([^/]+)(\/.*)$/.exec(pattern);
  if (!m) return { error: 'unsupported pattern syntax' };
  const [, scheme, host, path] = m;
  const schemeRe = scheme === '*' ? 'https?' : scheme;
  let hostRe: string;
  if (host === '*') hostRe = '[^/?#]+';
  else if (host.startsWith('*.')) {
    const rest = host.slice(2);
    if (rest.includes('*') || !/^[a-z0-9.-]+$/.test(rest)) return { error: 'unsupported host pattern' };
    hostRe = `(?:[^/?#]*\\.)?${escapeRegex(rest)}`;
  } else {
    if (host.includes('*') || !/^[a-z0-9.-]+$/.test(host)) return { error: 'unsupported host pattern' };
    hostRe = escapeRegex(host);
  }
  return { origin: `^${schemeRe}://${hostRe}(?::[0-9]+)?`, path };
}

/**
 * The fixed host of an include pattern ("*.example.com" → "example.com",
 * "t.example.com" → "t.example.com"), or null when the host is a wildcard.
 */
export function patternFixedHost(pattern: string): string | null {
  const m = /^(?:\*|https?):\/\/([^/]+)\//.exec(pattern);
  if (!m) return null;
  let host = m[1].toLowerCase().replace(/:\d+$/, '');
  if (host.startsWith('*.')) host = host.slice(2);
  if (host.includes('*') || !/^[a-z0-9.-]+$/.test(host) || !host.includes('.')) return null;
  if (host.startsWith('.') || host.endsWith('.') || host.includes('..')) return null;
  return host;
}

/** pages/bounce.html redirect target: `?from=<host>` when the pattern has a fixed host. */
export function bounceSubstitution(bounceUrl: string, pattern: string, target: string): string {
  const from = patternFixedHost(pattern);
  return from ? `${bounceUrl}?from=${from}#${target}` : `${bounceUrl}#${target}`;
}

/**
 * Translate one Chrome-style match pattern (as used by Brave's debounce list)
 * into the regex prefix that must match before a query parameter.
 */
export function matchPatternPrefix(pattern: string): { prefix: string; queryOpen: boolean } | { error: string } {
  const parts = splitPattern(pattern);
  if ('error' in parts) return parts;
  const { origin, path } = parts;
  if (!path.endsWith('*')) return { error: 'closed path cannot carry a query parameter' };
  const open = path.replace(/\*+$/, '');
  const q = open.indexOf('?');
  let pathRe: string;
  let queryOpen: boolean;
  if (q === -1) {
    // The remaining `*` may span the rest of the path; the query must follow.
    pathRe = `${globToRegex(open, '[^?#]*')}[^?#]*\\?`;
    queryOpen = true;
  } else {
    const pathPart = open.slice(0, q);
    const queryPart = open.slice(q + 1);
    pathRe = `${globToRegex(pathPart, '[^?#]*')}\\?${globToRegex(queryPart, '[^#]*')}`;
    queryOpen = queryPart === '' || queryPart.endsWith('&');
  }
  return { prefix: `${origin}${pathRe}`, queryOpen };
}

export type DebounceValue = 'url' | 'base64' | 'schemeless';

/** Capture for the parameter value. */
const VALUE_RE: Record<DebounceValue, string> = {
  // An http(s) URL, raw or with a percent-encoded colon.
  url: '([hH][tT][tT][pP][sS]?(?::|%3[aA])[^&#]*)',
  // base64("http") = "aHR0cA", base64("https") = "aHR0cHM"; base64url and %3D padding allowed.
  base64: '(aHR0c[A-Za-z0-9+/_%=-]*)',
  // prepend_scheme rules: a value that does not already start with a scheme.
  schemeless: '((?:[^hH&#]|[hH][^tT&#])[^&#]*)',
};

/**
 * Full regexFilter for "pattern + query parameter `param`". Capture group 1
 * is the raw parameter value.
 */
export function debounceRegex(pattern: string, param: string, kind: DebounceValue = 'url'): { regex: string } | { error: string } {
  if (!/^[A-Za-z0-9_.\-[\]]+$/.test(param)) return { error: 'unsupported parameter name' };
  const p = matchPatternPrefix(pattern);
  if ('error' in p) return p;
  // Lazy so the first occurrence of the parameter wins, as in Brave
  // (net::GetValueForKeyInQuery); `&`/`?` anchoring prevents "xurl=" matching "url=".
  const before = p.queryOpen ? '(?:[^#]*?&)??' : '[^#]*?&';
  return { regex: `${p.prefix}${before}${escapeRegex(param)}=${VALUE_RE[kind]}` };
}

/**
 * Rewrite a Brave path regex ("^/c/s/(.*)$", applied to the URL path only)
 * so it can run on the full URL: `.` and negated classes no longer match `?`
 * or `#`, and an optional query/fragment may follow. Returns the body and the
 * number of capture groups, or an error for constructs we do not rewrite.
 */
export function pathRegexToUrlPart(pathRegex: string): { body: string; groups: number } | { error: string } {
  if (!pathRegex.startsWith('^/') || !pathRegex.endsWith('$') || pathRegex.endsWith('\\$')) return { error: 'path regex must be anchored' };
  const src = pathRegex.slice(1, -1);
  let out = '';
  let groups = 0;
  let inClass = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '\\') {
      if (i + 1 >= src.length) return { error: 'dangling escape' };
      if (!inClass && /[1-9]/.test(src[i + 1])) return { error: 'backreference' };
      out += c + src[i + 1];
      i++;
      continue;
    }
    if (inClass) {
      if (c === ']') inClass = false;
      out += c;
      continue;
    }
    if (c === '[') {
      inClass = true;
      if (src[i + 1] === '^') {
        out += '[^?#';
        i++;
      } else {
        out += '[';
      }
      if (src[i + 1] === ']') return { error: 'unsupported character class' };
      continue;
    }
    if (c === '.') {
      out += '[^?#]';
      continue;
    }
    if (c === '^' || c === '$' || c === '|') return { error: 'unsupported anchor or alternation' };
    if (c === '(') {
      if (src[i + 1] === '?') {
        if (src[i + 2] !== ':') return { error: 'unsupported group' };
      } else {
        groups++;
      }
    }
    out += c;
  }
  if (inClass) return { error: 'unterminated character class' };
  if (groups < 1 || groups > 9) return { error: 'needs 1 to 9 capture groups' };
  return { body: `${out}(?:[?#].*)?$`, groups };
}

/** Escape text for use in a DNR regexSubstitution (backslash is the only special). */
function substitutionLiteral(s: string): string {
  return s.replace(/\\/g, '\\\\');
}

function captures(n: number): string {
  let s = '';
  for (let i = 1; i <= n; i++) s += `\\${i}`;
  return s;
}

function rule(regexFilter: string, substitution: string): DnrRule {
  return {
    priority: DEBOUNCE_PRIORITY,
    action: { type: 'redirect', redirect: { regexSubstitution: substitution } },
    condition: {
      regexFilter,
      // Parameter names and paths are case-sensitive in Brave's matcher.
      isUrlFilterCaseSensitive: true,
      resourceTypes: ['main_frame'],
      requestMethods: ['get'],
    },
  };
}

/** Convert the Brave list. `bounceUrl` is chrome.runtime.getURL('pages/bounce.html'). */
export function convertDebounceRules(data: unknown, bounceUrl: string, opts: DebounceOptions = {}): DebounceConversion {
  const rules: DnrRule[] = [];
  const skipped: DebounceConversion['skipped'] = [];
  if (!Array.isArray(data)) return { rules, skipped };
  const seen = new Set<string>();
  const add = (regex: string, substitution: string) => {
    const key = `${regex}\u0000${substitution}`;
    if (seen.has(key)) return;
    seen.add(key);
    rules.push(rule(regex, substitution));
  };
  for (const raw of data) {
    if (!isPlainObject(raw) || !Array.isArray(raw.include)) continue;
    const r = raw as unknown as BraveDebounceRule;
    const includes = r.include.filter((x): x is string => typeof x === 'string');
    const skipAll = (reason: string) => {
      for (const pattern of includes) skipped.push({ pattern, reason });
    };
    if (typeof r.param !== 'string' || r.param === '') {
      skipAll('missing parameter');
      continue;
    }
    if (Array.isArray(r.exclude) && r.exclude.length > 0) {
      skipAll('exclude patterns not expressible');
      continue;
    }
    if (r.pref) {
      if (r.pref !== DE_AMP_PREF) {
        skipAll(`unknown preference ${r.pref}`);
        continue;
      }
      if (!opts.deAmp) continue; // de-AMP switched off: not a conversion problem
    }
    const scheme = r.prepend_scheme === 'http' || r.prepend_scheme === 'https' ? `${r.prepend_scheme}://` : '';
    if (r.prepend_scheme && !scheme) {
      skipAll(`unsupported prepend_scheme ${r.prepend_scheme}`);
      continue;
    }

    if (r.action === 'redirect' || r.action === 'base64,redirect') {
      const kind: DebounceValue = r.action === 'base64,redirect' ? 'base64' : scheme ? 'schemeless' : 'url';
      if (kind === 'base64' && scheme) {
        skipAll('base64 with prepend_scheme not expressible');
        continue;
      }
      const target = kind === 'base64' ? 'b64:\\1' : `${scheme}\\1`;
      for (const pattern of includes) {
        const res = debounceRegex(pattern, r.param, kind);
        if ('error' in res) skipped.push({ pattern, reason: res.error });
        else add(res.regex, bounceSubstitution(bounceUrl, pattern, target));
      }
      continue;
    }

    if (r.action === 'regex-path' || r.action === 'regex-path-template') {
      const part = pathRegexToUrlPart(r.param);
      if ('error' in part) {
        skipAll(part.error);
        continue;
      }
      let target: string;
      if (r.action === 'regex-path-template') {
        const tpl = typeof r.redirect_url_template === 'string' ? r.redirect_url_template : '';
        if (!/^https?:\/\//.test(tpl)) {
          skipAll('template must be an http(s) URL');
          continue;
        }
        // Brave requires every $N to be used exactly as the groups exist.
        const used = new Set(Array.from(tpl.matchAll(/\$([1-9])/g), (m) => Number(m[1])));
        if (used.size !== part.groups || Array.from(used).some((n) => n > part.groups)) {
          skipAll('template placeholders do not match capture groups');
          continue;
        }
        target = substitutionLiteral(tpl).replace(/\$([1-9])/g, '\\$1');
      } else {
        // Brave concatenates the captures (then unescapes; bounce.html decodes).
        target = `${scheme}${captures(part.groups)}`;
      }
      for (const pattern of includes) {
        const parts = splitPattern(pattern);
        if ('error' in parts) {
          skipped.push({ pattern, reason: parts.error });
          continue;
        }
        add(`${parts.origin}${part.body}`, bounceSubstitution(bounceUrl, pattern, target));
      }
      continue;
    }

    skipAll(`action "${String(r.action)}" not expressible`);
  }
  return { rules, skipped };
}
