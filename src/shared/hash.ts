// Hashing and hostname helpers shared by the build tools, the service worker
// and the content scripts. Keep these dependency-free and deterministic: the
// build shards data with them and the runtime must find it again.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { COSMETIC_SHARDS } from './constants.ts';

/** 32-bit FNV-1a over UTF-16 code units. */
export function fnv1a32(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** Cosmetic shard index for a hostKey (hostname or entity "label.*"). */
export function shardOf(hostKey: string, shards: number = COSMETIC_SHARDS): number {
  return fnv1a32(hostKey) % shards;
}

/** "007" style file name stem for a shard index. */
export function shardName(n: number): string {
  return String(n).padStart(3, '0');
}

/** Lower-case, strip trailing dot and a leading "www." — the key for per-site settings. */
export function siteKeyOf(hostname: string): string {
  let h = hostname.toLowerCase();
  if (h.endsWith('.')) h = h.slice(0, -1);
  if (h.startsWith('www.') && h.indexOf('.', 4) !== -1) h = h.slice(4);
  return h;
}

/** True for IPv4 literals and bracketed or bare IPv6 literals. */
export function isIpAddress(hostname: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return true;
  return hostname.includes(':') || (hostname.startsWith('[') && hostname.endsWith(']'));
}

/**
 * Hostname and its parent domains, most specific first, stopping at two
 * labels: "a.b.example.co.uk" -> ["a.b.example.co.uk", "b.example.co.uk",
 * "example.co.uk", "co.uk"]. Single-label hosts return themselves. IP
 * addresses return themselves only.
 */
export function hostnameCandidates(hostname: string): string[] {
  const h = hostname.toLowerCase();
  if (h === '' || isIpAddress(h)) return h === '' ? [] : [h];
  const out = [h];
  let pos = h.indexOf('.');
  while (pos !== -1) {
    const rest = h.slice(pos + 1);
    if (rest.indexOf('.') === -1) break; // never emit a bare TLD
    out.push(rest);
    pos = h.indexOf('.', pos + 1);
  }
  return out;
}

/**
 * Entity candidates ("google.*" style) for a hostname, without a public
 * suffix list: for every hostname candidate, strip the last one and the last
 * two labels and append ".*". "www.google.co.uk" -> ["www.google.co.*",
 * "www.google.*", "google.co.*", "google.*"]. Deduplicated, specific first.
 */
export function entityCandidates(hostname: string): string[] {
  const h = hostname.toLowerCase();
  if (h === '' || isIpAddress(h)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const cand of hostnameCandidates(h)) {
    const labels = cand.split('.');
    for (let strip = 1; strip <= 2; strip++) {
      if (labels.length - strip < 1) break;
      const e = labels.slice(0, labels.length - strip).join('.') + '.*';
      if (!seen.has(e)) {
        seen.add(e);
        out.push(e);
      }
    }
  }
  return out;
}

/**
 * Rough registrable-domain approximation for first/third-party decisions in
 * the UI and logs (the browser does the authoritative eTLD+1 check for DNR).
 * Treats well-known two-label public suffixes (co.uk, com.au, ...) correctly.
 */
const TWO_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'org.nz', 'co.jp', 'ne.jp', 'or.jp', 'co.kr', 'co.in', 'co.za',
  'com.br', 'com.mx', 'com.ar', 'com.tr', 'com.cn', 'com.hk', 'com.sg', 'com.tw',
  'github.io', 'gitlab.io', 'pages.dev', 'vercel.app', 'netlify.app', 'web.app',
  'firebaseapp.com', 'azurewebsites.net', 'cloudfront.net', 'herokuapp.com', 'blogspot.com',
]);
export function registrableDomain(hostname: string): string {
  const h = siteKeyOf(hostname);
  if (isIpAddress(h)) return h;
  const labels = h.split('.');
  if (labels.length <= 2) return h;
  const last2 = labels.slice(-2).join('.');
  if (TWO_LABEL_SUFFIXES.has(last2)) return labels.slice(-3).join('.');
  return last2;
}

/** Chrome match pattern covering a hostname and all its subdomains. */
export function matchPatternFor(hostname: string): string {
  if (isIpAddress(hostname)) return `*://${hostname}/*`;
  return `*://*.${hostname}/*`;
}
