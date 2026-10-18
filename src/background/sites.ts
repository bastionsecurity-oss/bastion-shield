// Bastion Shield service worker — per-site settings (ARCHITECTURE §10).
// Site keys are lower-case punycode hostnames without a leading "www.". A
// setting on "example.com" also applies to its subdomains (DNR domain lists
// and our match patterns both cover subdomains), so lookups walk the parents.
// `layerScopes` turns nested site overrides into include/exclude groups that
// DNR conditions and content-script match patterns can express exactly.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { hostnameCandidates, isIpAddress, matchPatternFor, siteKeyOf } from '../shared/hash.ts';
import type { BlockingMode, FingerprintLevel, ManagedPolicy, Settings, SiteSettings, SitesMap } from '../shared/types.ts';
import { isPlainObject, parseUrl } from './util.ts';

const MODES: readonly BlockingMode[] = ['standard', 'aggressive'];
const FP_LEVELS: readonly FingerprintLevel[] = ['off', 'standard', 'strict'];
const MAX_SITES = 10_000;

/** Hosts that are never filterable: browser stores block extension scripts. */
const STORE_HOSTS = new Set(['chromewebstore.google.com', 'microsoftedge.microsoft.com']);

/**
 * Normalize user/admin input ("https://www.Example.com/path", "*.example.com",
 * "bücher.ch", "example.com:8080") to a site key, or null when it is not a
 * usable hostname.
 */
export function normalizeSiteKey(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  let s = input.trim().toLowerCase();
  if (s === '') return null;
  // Strip a scheme, path, query or fragment if a URL was pasted.
  const scheme = /^[a-z][a-z0-9+.-]*:\/\//.exec(s);
  if (scheme) s = s.slice(scheme[0].length);
  s = s.replace(/[/?#].*$/, '');
  // Drop user info.
  const at = s.lastIndexOf('@');
  if (at !== -1) s = s.slice(at + 1);
  // Wildcards: "*.example.com" and "||example.com^" mean "example.com and below".
  s = s.replace(/^\|\|/, '').replace(/\^$/, '');
  while (s.startsWith('*.')) s = s.slice(2);
  if (s.startsWith('.')) s = s.slice(1);
  if (s === '' || s.includes('*')) return null;
  // IPv6 literal.
  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    if (end === -1) return null;
    const v6 = s.slice(0, end + 1);
    return /^\[[0-9a-f:.]+\]$/.test(v6) ? v6 : null;
  }
  // Strip port.
  s = s.replace(/:\d*$/, '');
  if (s.endsWith('.')) s = s.slice(0, -1);
  if (s === '') return null;
  // Let the WHATWG URL parser do IDNA/punycode and reject garbage.
  let host: string;
  try {
    host = new URL(`http://${s}/`).hostname;
  } catch {
    return null;
  }
  if (!/^[a-z0-9.-]+$/.test(host) || host.length > 253) return null;
  if (host.startsWith('.') || host.endsWith('.') || host.includes('..')) return null;
  if (host.split('.').some((label) => label.length === 0 || label.length > 63)) return null;
  return siteKeyOf(host);
}

/** Site key for an http(s) page URL, or null for anything else. */
export function siteKeyFromUrl(url: string | undefined | null): string | null {
  const u = parseUrl(url);
  if (!u || (u.protocol !== 'http:' && u.protocol !== 'https:')) return null;
  if (u.hostname === '') return null;
  return siteKeyOf(u.hostname);
}

/** True when Bastion can act on this page (http/https, not a browser store). */
export function isFilterableUrl(url: string | undefined | null): boolean {
  const u = parseUrl(url);
  if (!u || (u.protocol !== 'http:' && u.protocol !== 'https:')) return false;
  const host = u.hostname.toLowerCase();
  if (STORE_HOSTS.has(host)) return false;
  if (host === 'chrome.google.com' && u.pathname.startsWith('/webstore')) return false;
  return true;
}

/** True when `host` is `parent` or one of its subdomains. */
export function isSameOrSubdomain(host: string, parent: string): boolean {
  return host === parent || (host.length > parent.length && host.endsWith(parent) && host[host.length - parent.length - 1] === '.');
}

/** Valid value for DNR *Domains condition arrays (ASCII hostname or IPv4). */
export function isDnrDomain(s: string): boolean {
  if (s.length === 0 || s.length > 253) return false;
  if (!/^[a-z0-9.-]+$/.test(s)) return false;
  return !s.startsWith('.') && !s.endsWith('.') && !s.includes('..');
}

export function sanitizeSiteSettings(raw: unknown): SiteSettings | null {
  if (!isPlainObject(raw)) return null;
  const out: SiteSettings = {};
  if (typeof raw.enabled === 'boolean') out.enabled = raw.enabled;
  if (typeof raw.mode === 'string' && (MODES as readonly string[]).includes(raw.mode)) out.mode = raw.mode as BlockingMode;
  if (typeof raw.blockScripts === 'boolean') out.blockScripts = raw.blockScripts;
  if (typeof raw.fingerprinting === 'string' && (FP_LEVELS as readonly string[]).includes(raw.fingerprinting)) {
    out.fingerprinting = raw.fingerprinting as FingerprintLevel;
  }
  return Object.keys(out).length > 0 ? out : null;
}

/** Validate a stored or imported SitesMap; unknown fields and bad keys are dropped. */
export function sanitizeSites(raw: unknown): SitesMap {
  const out: SitesMap = {};
  if (!isPlainObject(raw)) return out;
  let n = 0;
  for (const [key, value] of Object.entries(raw)) {
    if (n >= MAX_SITES) break;
    const site = normalizeSiteKey(key);
    if (!site) continue;
    const s = sanitizeSiteSettings(value);
    if (!s) continue;
    out[site] = { ...out[site], ...s };
    n++;
  }
  return out;
}

/**
 * Apply a patch to one site. `null` in the patch clears a field; the entry is
 * removed when no field remains. Returns a new map.
 */
export function patchSite(sites: SitesMap, site: string, patch: Record<string, unknown>): SitesMap {
  const next: SitesMap = { ...sites };
  const cur: SiteSettings = { ...(next[site] ?? {}) };
  for (const field of ['enabled', 'mode', 'blockScripts', 'fingerprinting'] as const) {
    if (!(field in patch)) continue;
    const v = patch[field];
    if (v === null || v === undefined) {
      delete cur[field];
      continue;
    }
    const valid = sanitizeSiteSettings({ [field]: v });
    if (valid && field in valid) (cur as Record<string, unknown>)[field] = (valid as Record<string, unknown>)[field];
  }
  if (Object.keys(cur).length === 0) delete next[site];
  else next[site] = cur;
  return next;
}

export interface ManagedSites {
  disabled: Set<string>;
  aggressive: Set<string>;
}

export function managedSites(managed: ManagedPolicy): ManagedSites {
  const disabled = new Set<string>();
  const aggressive = new Set<string>();
  for (const h of managed.disabledSites ?? []) {
    const k = normalizeSiteKey(h);
    if (k) disabled.add(k);
  }
  for (const h of managed.aggressiveSites ?? []) {
    const k = normalizeSiteKey(h);
    if (k) aggressive.add(k);
  }
  return { disabled, aggressive };
}

/** True when `site` or one of its parents is in `set`. */
export function coveredBy(site: string, set: ReadonlySet<string>): boolean {
  if (set.size === 0) return false;
  return hostnameCandidates(site).some((c) => set.has(c));
}

/** User sites with the policy's forced values on top. */
export function effectiveSites(user: SitesMap, managed: ManagedPolicy, m: ManagedSites = managedSites(managed)): SitesMap {
  const out: SitesMap = {};
  for (const [k, v] of Object.entries(user)) out[k] = { ...v };
  for (const k of m.disabled) out[k] = { ...out[k], enabled: false };
  for (const k of m.aggressive) out[k] = { ...out[k], mode: 'aggressive' };
  // aggressiveSites includes subdomains: a user (or imported) mode on a
  // descendant must not punch a Standard-mode hole into the policy.
  if (m.aggressive.size > 0) {
    for (const [k, v] of Object.entries(out)) {
      if (v.mode !== undefined && v.mode !== 'aggressive' && hostnameCandidates(k).slice(1).some((c) => m.aggressive.has(c))) {
        out[k] = { ...v, mode: 'aggressive' };
      }
    }
  }
  // disabledSites includes subdomains as well: a user `enabled: true` below a
  // policy-disabled host must not switch protection back on there.
  if (m.disabled.size > 0) {
    for (const [k, v] of Object.entries(out)) {
      if (v.enabled === true && hostnameCandidates(k).slice(1).some((c) => m.disabled.has(c))) {
        const copy = { ...v };
        delete copy.enabled;
        if (Object.keys(copy).length === 0) delete out[k];
        else out[k] = copy;
      }
    }
  }
  // A site the user switched off while the policy forbids per-site toggles
  // must not stay off (the admin decides where protection is off).
  if (managed.allowUserSiteToggle === false) {
    for (const [k, v] of Object.entries(out)) {
      if (v.enabled === false && !m.disabled.has(k)) {
        const copy = { ...v };
        delete copy.enabled;
        if (Object.keys(copy).length === 0) delete out[k];
        else out[k] = copy;
      }
    }
  }
  return out;
}

/**
 * A whole user map coming from the UI or a backup: fields the policy owns
 * keep the user's current value (`prev`), so a policy overlay can never be
 * copied into the user's own data (and stick after the admin removes it).
 * Owned: `enabled` of disabledSites hosts (of every host when
 * allowUserSiteToggle is false) and `mode` of aggressiveSites hosts.
 */
export function keepPolicyOwnedFields(next: SitesMap, prev: SitesMap, managed: ManagedPolicy, m: ManagedSites = managedSites(managed)): SitesMap {
  const out: SitesMap = {};
  for (const [k, v] of Object.entries(next)) out[k] = { ...v };
  const restore = (k: string, field: 'enabled' | 'mode'): void => {
    const was = prev[k]?.[field];
    const cur = out[k];
    if (was === undefined) {
      if (cur) delete cur[field];
      return;
    }
    out[k] = { ...cur, [field]: was };
  };
  for (const k of m.disabled) restore(k, 'enabled');
  for (const k of m.aggressive) restore(k, 'mode');
  if (managed.allowUserSiteToggle === false) {
    for (const k of new Set([...Object.keys(out), ...Object.keys(prev)])) restore(k, 'enabled');
  }
  for (const [k, v] of Object.entries(out)) if (Object.keys(v).length === 0) delete out[k];
  return out;
}

export type ResolvedSite = Required<Pick<SiteSettings, 'enabled' | 'mode' | 'blockScripts' | 'fingerprinting'>>;

/** Effective settings for a hostname: each field from the nearest site key that sets it. */
export function resolveSite(hostname: string, sites: SitesMap, settings: Settings): ResolvedSite {
  const out: Partial<ResolvedSite> = {};
  const key = siteKeyOf(hostname);
  for (const cand of hostnameCandidates(key)) {
    const s = sites[cand];
    if (!s) continue;
    if (out.enabled === undefined && s.enabled !== undefined) out.enabled = s.enabled;
    if (out.mode === undefined && s.mode !== undefined) out.mode = s.mode;
    if (out.blockScripts === undefined && s.blockScripts !== undefined) out.blockScripts = s.blockScripts;
    if (out.fingerprinting === undefined && s.fingerprinting !== undefined) out.fingerprinting = s.fingerprinting;
  }
  return {
    enabled: out.enabled ?? true,
    mode: out.mode ?? settings.defaultMode,
    blockScripts: out.blockScripts ?? false,
    fingerprinting: out.fingerprinting ?? settings.privacy.fingerprinting,
  };
}

/** Nearest strict ancestor of `site` contained in `keys` (or null). */
function nearestAncestor(site: string, keys: ReadonlyMap<string, unknown> | ReadonlySet<string>): string | null {
  const cands = hostnameCandidates(site);
  for (let i = 1; i < cands.length; i++) if (keys.has(cands[i])) return cands[i];
  return null;
}

/**
 * One include/exclude group. `include === null` is the root group (every
 * host). A host belongs to the group when it is (a subdomain of) an `include`
 * entry and not (a subdomain of) an `exclude` entry.
 */
export interface ScopeGroup<V> {
  value: V;
  /** -1 for the root group; nesting depth of the boundary sites otherwise. */
  depth: number;
  include: string[] | null;
  exclude: string[];
}

/**
 * Turn explicit per-site values into groups that partition all hostnames by
 * effective value, using only "domain or subdomain" includes and excludes
 * (the semantics of DNR requestDomains/excludedRequestDomains and of
 * `*://*.host/*` match patterns, where exclusion always wins).
 *
 * A boundary is an explicit site whose value differs from what it would
 * inherit. Boundaries of equal value and depth share a group; each group
 * excludes the next-deeper boundaries below its members, which are covered by
 * their own groups. This is exact for any nesting depth.
 */
export function layerScopes<V>(explicit: ReadonlyMap<string, V>, rootValue: V, keyOf: (v: V) => string = (v) => JSON.stringify(v)): ScopeGroup<V>[] {
  const keys = Array.from(explicit.keys()).sort((a, b) => a.split('.').length - b.split('.').length || (a < b ? -1 : a > b ? 1 : 0));
  const boundaryDepth = new Map<string, number>();
  for (const k of keys) {
    const v = explicit.get(k) as V;
    const parent = nearestAncestor(k, explicit);
    const inherited = parent === null ? rootValue : (explicit.get(parent) as V);
    if (keyOf(v) === keyOf(inherited)) continue;
    const pb = nearestAncestor(k, boundaryDepth);
    boundaryDepth.set(k, pb === null ? 0 : (boundaryDepth.get(pb) as number) + 1);
  }
  const root: ScopeGroup<V> = { value: rootValue, depth: -1, include: null, exclude: [] };
  const groups = new Map<string, ScopeGroup<V>>();
  const groupOf = (site: string): ScopeGroup<V> => {
    const v = explicit.get(site) as V;
    const depth = boundaryDepth.get(site) as number;
    const gk = `${depth}\u0000${keyOf(v)}`;
    let g = groups.get(gk);
    if (!g) {
      g = { value: v, depth, include: [], exclude: [] };
      groups.set(gk, g);
    }
    return g;
  };
  for (const b of boundaryDepth.keys()) {
    groupOf(b).include!.push(b);
    const pb = nearestAncestor(b, boundaryDepth);
    if (pb === null) root.exclude.push(b);
    else groupOf(pb).exclude.push(b);
  }
  const out = [root, ...groups.values()];
  for (const g of out) {
    g.include?.sort();
    g.exclude.sort();
  }
  out.sort((a, b) => a.depth - b.depth || keyOf(a.value).localeCompare(keyOf(b.value)));
  return out;
}

/** Explicit values of one field across sites. */
export function explicitField<K extends keyof SiteSettings>(sites: SitesMap, field: K): Map<string, NonNullable<SiteSettings[K]>> {
  const out = new Map<string, NonNullable<SiteSettings[K]>>();
  for (const [k, v] of Object.entries(sites)) {
    const value = v[field];
    if (value !== undefined && value !== null) out.set(k, value as NonNullable<SiteSettings[K]>);
  }
  return out;
}

/** Effective value at every explicit key of `fields`, resolved through parents. */
export function explicitResolved(sites: SitesMap, settings: Settings, fields: (keyof SiteSettings)[]): Map<string, ResolvedSite> {
  const out = new Map<string, ResolvedSite>();
  for (const [k, v] of Object.entries(sites)) {
    if (!fields.some((f) => v[f] !== undefined)) continue;
    out.set(k, resolveSite(k, sites, settings));
  }
  return out;
}

/** Match pattern for a site key, covering its subdomains. */
export function sitePattern(site: string): string {
  return matchPatternFor(site);
}

/** Sites whose protection is off (explicitly or via a parent). */
export function isSiteDisabled(hostname: string, sites: SitesMap, settings: Settings): boolean {
  return !resolveSite(hostname, sites, settings).enabled;
}

export function isIpOrLocal(site: string): boolean {
  return isIpAddress(site) || !site.includes('.');
}
