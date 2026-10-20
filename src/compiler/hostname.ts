// Bastion filter compiler — hostname normalization for filter options and
// cosmetic/scriptlet host lists. DNR only accepts lower-case ASCII (punycode)
// hostnames, and the cosmetic shards are keyed by the same form, so every
// hostname that leaves the compiler goes through here.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/** uBO's "plain ASCII hostname" test: the fast path that needs no normalization. */
export const reHostnameAscii = /^(?:[\da-z][\da-z_-]*\.)*[\da-z][\da-z-]*[\da-z]$/;

// Characters that can never appear in a hostname (uBO's reBadHostnameChars).
// `*`, `%`, `-`, `.`, `:`, `_`, `[`, `]` and non-ASCII are left to the URL parser.
const reBadHostnameChars = /[\x00-\x24\x26-\x29\x2b\x2c\x2f\x3b-\x40\x5c\x5e\x60\x7b-\x7f]/;
const reIPv6 = /^\[[0-9a-f:.]+\]$/;
const reHasNonAscii = /[^\x00-\x7f]/;

let punycoder: URL | null = null;

/**
 * Normalize one hostname: lower-case, punycode, strip a trailing dot.
 * Returns null when the value is not a usable hostname. IP literals are kept.
 * Wildcards are not accepted here (see normalizeHostOrEntity).
 */
export function normalizeHostname(raw: string): string | null {
  if (raw.length === 0 || raw.length > 253) return null;
  if (reHostnameAscii.test(raw)) return raw;
  let h = raw.toLowerCase();
  if (h.endsWith('.')) h = h.slice(0, -1);
  if (h.length === 0) return null;
  if (reHostnameAscii.test(h)) return h;
  if (reIPv6.test(h)) return h;
  if (h.includes('*')) return null;
  if (reBadHostnameChars.test(h)) return null;
  // Single-character labels ("x.com" is fine, but "a" alone fails the regex
  // above) and non-ASCII names end up here; the WHATWG URL parser is the
  // authority for IDNA, exactly as the browser computes it.
  try {
    if (punycoder === null) punycoder = new URL('http://bastion.invalid/');
    punycoder.hostname = '_';
    punycoder.hostname = h;
    const out = punycoder.hostname;
    if (out === '_' || out === '' || out.startsWith('.') || out.endsWith('.')) return null;
    if (out.includes('..') || reHasNonAscii.test(out)) return null;
    if (/[^\da-z._-]/.test(out) && !reIPv6.test(out)) return null;
    return out;
  } catch {
    return null;
  }
}

/** True for "label.*" style entities (uBO). */
export function isEntity(h: string): boolean {
  return h.length > 2 && h.charCodeAt(h.length - 1) === 0x2a /* * */ && h.charCodeAt(h.length - 2) === 0x2e /* . */;
}

/**
 * Normalize a hostname or an entity ("google.*"). Returns null if invalid.
 * "*" alone is returned as-is when allowed by the caller (generic marker).
 */
export function normalizeHostOrEntity(raw: string, allowEntity: boolean): string | null {
  if (isEntity(raw)) {
    if (!allowEntity) return null;
    const base = raw.slice(0, -2);
    if (base.includes('*')) return null;
    const n = normalizeHostname(base);
    return n === null ? null : `${n}.*`;
  }
  return normalizeHostname(raw);
}

/** Parent domains of a hostname, nearest first ("a.b.c" -> ["b.c", "c"]). */
export function parentDomains(h: string): string[] {
  const out: string[] = [];
  let pos = h.indexOf('.');
  while (pos !== -1) {
    out.push(h.slice(pos + 1));
    pos = h.indexOf('.', pos + 1);
  }
  return out;
}

/** True if `h` equals `parent` or is a subdomain of it. */
export function isSameOrSubdomain(h: string, parent: string): boolean {
  if (h === parent) return true;
  return h.length > parent.length && h.endsWith(parent) && h.charCodeAt(h.length - parent.length - 1) === 0x2e;
}

/**
 * Remove hostnames already covered by a parent in the same list (DNR domain
 * conditions match subdomains). Returns a sorted, deduplicated array.
 */
export function pruneSubdomains(hosts: readonly string[]): string[] {
  const set = new Set(hosts);
  if (set.size > 1) {
    for (const h of set) {
      let pos = h.indexOf('.');
      while (pos !== -1) {
        if (set.has(h.slice(pos + 1))) {
          set.delete(h);
          break;
        }
        pos = h.indexOf('.', pos + 1);
      }
    }
  }
  return Array.from(set).sort();
}

/** True if `h` or one of its parents is in `set`. */
export function coveredBy(h: string, set: ReadonlySet<string>): boolean {
  if (set.has(h)) return true;
  let pos = h.indexOf('.');
  while (pos !== -1) {
    if (set.has(h.slice(pos + 1))) return true;
    pos = h.indexOf('.', pos + 1);
  }
  return false;
}

/**
 * Domain-set intersection where every entry also stands for its subdomains:
 * {a.com} ∩ {x.a.com, b.com} = {x.a.com}.
 */
export function intersectDomains(a: readonly string[], b: readonly string[]): string[] {
  const out = new Set<string>();
  for (const x of a) {
    for (const y of b) {
      if (isSameOrSubdomain(y, x)) out.add(y);
      else if (isSameOrSubdomain(x, y)) out.add(x);
    }
  }
  return Array.from(out).sort();
}
