// Bastion Shield — decoding of the debounce target carried in the fragment
// of pages/bounce.html (ARCHITECTURE §4.6). Pure and DOM-free so it can be
// unit tested. Accepts a percent-encoded URL (possibly encoded several times)
// or "b64:<base64 / base64url>" and returns a safe http(s) URL or null.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { registrableDomain } from '../shared/hash.ts';

const MAX_INPUT = 8192;
const MAX_DECODE_ROUNDS = 4;

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    // Malformed escapes: decode what can be decoded, leave the rest.
    return s.replace(/%[0-9a-f]{2}/gi, (m) => {
      try {
        return decodeURIComponent(m);
      } catch {
        return m;
      }
    });
  }
}

function fromBase64(s: string): string | null {
  let b = s.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b)) return null;
  b = b.replace(/=+$/, '');
  if (b.length % 4 === 1) return null;
  b += '='.repeat((4 - (b.length % 4)) % 4);
  try {
    const bin = atob(b);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } catch {
    return null;
  }
}

/** A navigable target: absolute http(s), a hostname, and no embedded credentials. */
export function parseTarget(s: string): URL | null {
  const v = s.trim();
  if (!/^https?:\/\//i.test(v)) return null;
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (!u.hostname) return null;
  // user:pass@host is a classic phishing disguise; a tracker never needs it.
  if (u.username || u.password) return null;
  return u;
}

/**
 * Decode the raw fragment (with or without the leading '#'). Returns null for
 * anything that is not a plain http(s) URL after decoding.
 */
export function decodeBounceTarget(raw: string): URL | null {
  if (typeof raw !== 'string') return null;
  let s = raw.startsWith('#') ? raw.slice(1) : raw;
  if (!s || s.length > MAX_INPUT) return null;

  if (s.startsWith('b64:')) {
    // The captured query value may itself be percent-encoded (%3D padding etc.).
    const decoded = fromBase64(safeDecode(s.slice(4)));
    if (decoded === null) return null;
    s = decoded;
  }

  for (let i = 0; i <= MAX_DECODE_ROUNDS; i++) {
    const u = parseTarget(s);
    if (u) return u;
    const next = safeDecode(s);
    if (next === s) break;
    s = next;
  }
  return null;
}

/**
 * Host of the bouncing tracker from the optional `?from=<host>` parameter that
 * the debounce rule appends. Accepts a hostname or a URL; returns the
 * lower-case hostname, or null when absent or malformed.
 */
export function parseFromHost(search: string): string | null {
  let raw: string | null;
  try {
    raw = new URLSearchParams(search).get('from');
  } catch {
    return null;
  }
  if (!raw) return null;
  const v = raw.trim().toLowerCase();
  if (!v || v.length > 253) return null;
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//.test(v) ? v : `https://${v}`);
    if ((u.protocol !== 'http:' && u.protocol !== 'https:') || !u.hostname) return null;
    return u.hostname;
  } catch {
    return null;
  }
}

/**
 * True when the decoded target lives on the same site (registrable domain) as
 * the bouncing host. Debouncing only skips cross-site hops (Brave semantics);
 * a same-site "bounce" is not followed automatically.
 */
export function isSameSiteBounce(target: URL, fromHost: string | null): boolean {
  if (!fromHost) return false;
  return registrableDomain(target.hostname) === registrableDomain(fromHost);
}
