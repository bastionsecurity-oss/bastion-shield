// Bastion Shield — the logic behind «Website-Ausnahmen» (views/sites.ts),
// free of DOM so node:test can cover it: the limits the service worker
// enforces (background/sites.ts: 10'000 sites, 253 characters per host),
// host validation that names the fix, the import parser with its count of
// skipped lines, search and the one-line summary of a site's settings.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BlockingMode, FingerprintLevel, SiteSettings, SitesMap } from '../../shared/types.ts';

/** As MAX_SITES in background/sites.ts. */
export const MAX_SITES = 10_000;
/** Longest host name (DNS). */
export const MAX_HOST = 253;
/** Counters appear from 80 % of a limit (AGENTS.md «Inputs»). */
export const NEAR = 0.8;

export function nearLimit(n: number, max: number): boolean {
  return n >= Math.ceil(max * NEAR);
}

export type HostProblem = 'empty' | 'long' | 'chars' | 'tld' | 'scheme';
export type HostCheck = { ok: true; host: string } | { ok: false; problem: HostProblem };

/**
 * Validate and normalise a host typed or pasted by the user (also a full
 * URL), like common.ts normaliseHost, but say what is wrong so the error
 * under the field can name the fix.
 */
export function checkHost(input: string): HostCheck {
  let s = input.trim().toLowerCase();
  if (!s) return { ok: false, problem: 'empty' };
  if (!/^[a-z][a-z0-9+.-]*:\/\//.test(s)) s = `https://${s}`;
  let host: string;
  try {
    const u = new URL(s);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return { ok: false, problem: 'scheme' };
    host = u.hostname;
  } catch {
    return { ok: false, problem: 'chars' };
  }
  if (host.endsWith('.')) host = host.slice(0, -1);
  if (host.startsWith('www.') && host.indexOf('.', 4) !== -1) host = host.slice(4);
  if (host.length > MAX_HOST) return { ok: false, problem: 'long' };
  if (!/^[a-z0-9.-]+$/.test(host) && !/^\[[0-9a-f:.]+\]$/.test(host)) return { ok: false, problem: 'chars' };
  if (!host.includes('.') && host !== 'localhost') return { ok: false, problem: 'tld' };
  if (/\.\.|^[.-]|-$/.test(host)) return { ok: false, problem: 'chars' };
  return { ok: true, host };
}

const MODES: BlockingMode[] = ['standard', 'aggressive'];
const FP: FingerprintLevel[] = ['off', 'standard', 'strict'];

function cleanEntry(v: unknown): SiteSettings | null {
  if (!v || typeof v !== 'object') return null;
  const o = v as Record<string, unknown>;
  const out: SiteSettings = {};
  if (typeof o.enabled === 'boolean') out.enabled = o.enabled;
  if (typeof o.mode === 'string' && (MODES as string[]).includes(o.mode)) out.mode = o.mode as BlockingMode;
  if (typeof o.blockScripts === 'boolean') out.blockScripts = o.blockScripts;
  if (typeof o.fingerprinting === 'string' && (FP as string[]).includes(o.fingerprinting)) out.fingerprinting = o.fingerprinting as FingerprintLevel;
  return out;
}

export interface SitesImport {
  sites: SitesMap;
  /** Entries or lines that are not a valid host (skipped). */
  invalid: number;
}

/** Accepts our export, a full backup, a plain {host: settings} map, or one hostname per line. */
export function parseSitesImport(text: string): SitesImport | null {
  const out: SitesMap = {};
  let invalid = 0;
  let data: unknown = null;
  try {
    data = JSON.parse(text);
  } catch {
    data = null;
  }
  if (data && typeof data === 'object' && !Array.isArray(data)) {
    const d = data as Record<string, unknown>;
    const map = (d.sites && typeof d.sites === 'object' ? d.sites : d) as Record<string, unknown>;
    for (const [k, v] of Object.entries(map)) {
      const c = checkHost(k);
      const entry = cleanEntry(v);
      if (c.ok && entry) out[c.host] = entry;
      else invalid += 1;
    }
  } else if (data === null) {
    for (const line of text.split(/\r?\n/)) {
      const s = line.trim();
      if (!s || s.startsWith('#') || s.startsWith('!')) continue;
      const c = checkHost(s);
      if (c.ok) out[c.host] = { enabled: false };
      else invalid += 1;
    }
  }
  return Object.keys(out).length ? { sites: out, invalid } : null;
}

/** Hosts matching a search: a part of the name; «bank» finds «e-banking.zkb.ch». */
export function searchHosts(hosts: readonly string[], query: string): string[] {
  const q = query.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '');
  return q ? hosts.filter((h) => h.includes(q)) : [...hosts];
}

export type SummaryPart = { key: 'off' } | { key: 'mode'; mode: BlockingMode } | { key: 'scripts' } | { key: 'fp'; level: FingerprintLevel };

/** What a row says in one line (expanded popup): «Schutz aus», «Aggressiv - Skripte blockiert». */
export function summaryParts(s: SiteSettings, defaultMode: BlockingMode): SummaryPart[] {
  const parts: SummaryPart[] = [];
  // With protection off the default mode says nothing; an explicit one still does.
  if (s.enabled !== false || s.mode) parts.push({ key: 'mode', mode: s.mode ?? defaultMode });
  if (s.enabled === false) parts.push({ key: 'off' });
  if (s.blockScripts) parts.push({ key: 'scripts' });
  if (s.fingerprinting) parts.push({ key: 'fp', level: s.fingerprinting });
  return parts;
}
