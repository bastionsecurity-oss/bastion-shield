// Bastion Shield service worker — desired content-script registrations
// (ARCHITECTURE §5.2, §6, §9) and the diff against what Chrome has
// registered. Pure: apply.ts performs the chrome.scripting calls.
//
// The set is small and bounded (review PERF-1/PERF-2): Chrome matches every
// registered pattern in every frame and keeps the parsed patterns in every
// renderer, so nothing here scales with the size of the filter lists:
//   bs-cosmetic     content/cosmetic.js
//   bs-gh-all       highly generic CSS of every enabled list (one registration)
//   sl-main/-isolated  one scriptlet bundle per world: [core, data files of
//                   the enabled lists, end]; hostnames are matched in-script
//   bs-privacy*     MAIN-world privacy script, one per fingerprinting level
//                   (+ main/fpmeter.js after it while the nerd mode
//                   fingerprinting meter is on)
//   bs-nerd-clip    nerd mode: MAIN-world clipboard guard
//   bs-nerd-relay   nerd mode: ISOLATED relay for clipguard/fpmeter
//
// Every script is excluded where protection is off. Nested overrides (a
// subdomain switched back on below a disabled site, or a different
// fingerprinting level below a parent) are expressed with extra
// registrations whose `matches` cover only the re-included hosts, using the
// groups from layerScopes (excludeMatches always wins in Chrome).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { CosmeticMeta, FingerprintLevel, ScriptletIndex, Settings, SitesMap } from '../shared/types.ts';
import { explicitField, explicitResolved, isDnrDomain, isSameOrSubdomain, layerScopes, sitePattern } from './sites.ts';
import type { ScopeGroup } from './sites.ts';
import { uniqueSorted } from './util.ts';

export const COSMETIC_SCRIPT_ID = 'bs-cosmetic';
export const COSMETIC_SCRIPT_FILE = 'content/cosmetic.js';
export const PROCEDURAL_SCRIPT_FILE = 'content/procedural.js';
export const PRIVACY_SCRIPT_FILE = 'main/privacy.js';
export const GENERIC_HIGH_ID_PREFIX = 'bs-gh-';
/** The single generic-high CSS registration. */
export const GENERIC_HIGH_ID = `${GENERIC_HIGH_ID_PREFIX}all`;
export const SCRIPTLET_ID_PREFIX = 'sl-';
export const PRIVACY_ID_PREFIX = 'bs-privacy';
export const FPMETER_SCRIPT_FILE = 'main/fpmeter.js';
export const CLIPGUARD_SCRIPT_FILE = 'main/clipguard.js';
export const NERD_RELAY_SCRIPT_FILE = 'content/nerd-relay.js';
export const CLIPGUARD_ID = 'bs-nerd-clip';
export const NERD_RELAY_ID = 'bs-nerd-relay';
const ALL_URLS = '<all_urls>';

export interface DesiredScript {
  id: string;
  js?: string[];
  css?: string[];
  matches: string[];
  excludeMatches?: string[];
  world: 'MAIN' | 'ISOLATED';
  runAt: 'document_start';
  allFrames: boolean;
  matchOriginAsFallback: boolean;
  persistAcrossSessions: boolean;
}

export interface RegistrationInputs {
  settings: Settings;
  sites: SitesMap;
  enabledListIds: ReadonlySet<string>;
  cosmeticMeta: CosmeticMeta | null;
  scriptletIndex: ScriptletIndex | null;
  /** SEED_SETS files, in set order. */
  seedFiles: string[];
  /** Hosts where custom filters say generichide/elemhide (no generic-high CSS there). */
  extraGenericHideHosts?: readonly string[];
  /**
   * Enabled first-party-protected lists. Their highly generic CSS is not
   * registered: the SW serves it per frame, so Standard mode can un-hide it
   * (cosmetic.ts softHighGeneric).
   */
  softListIds?: ReadonlySet<string>;
}

/** Dist paths are relative to the extension root; tolerate "dist/" or "/" prefixes in metadata. */
export function packagePath(p: string): string {
  let s = p.replace(/\\/g, '/');
  while (s.startsWith('/')) s = s.slice(1);
  if (s.startsWith('dist/')) s = s.slice(5);
  return s;
}

/** Host of a "*://*.host/*" / "*://host/*" style pattern, or null for anything else. */
function patternHost(pattern: string): { host: string; subdomains: boolean } | null {
  const m = /^(?:\*|https?|wss?):\/\/(\*\.)?([^/*]+)\/\*$/.exec(pattern);
  if (!m) return null;
  return { host: m[2].toLowerCase(), subdomains: m[1] !== undefined };
}

/**
 * Patterns matching the intersection of `base` and "these sites and their
 * subdomains". When a base pattern cannot be analysed the site patterns are
 * used instead: over-matching only costs a little work, because scriptlet
 * shards and the cosmetic script check the hostname themselves.
 */
export function intersectPatterns(base: readonly string[], sites: readonly string[]): string[] {
  const out = new Set<string>();
  for (const b of base) {
    if (b === ALL_URLS || b === '*://*/*') {
      for (const s of sites) out.add(sitePattern(s));
      continue;
    }
    const bh = patternHost(b);
    if (!bh) {
      for (const s of sites) out.add(sitePattern(s));
      continue;
    }
    for (const s of sites) {
      if (isSameOrSubdomain(bh.host, s)) out.add(b);
      else if (bh.subdomains && isSameOrSubdomain(s, bh.host)) out.add(sitePattern(s));
    }
  }
  return Array.from(out).sort();
}

function patterns(sites: readonly string[]): string[] {
  return sites.map(sitePattern);
}

/**
 * Sites that can intersect `base`: excluding anything else would only grow
 * excludeMatches, and make an unrelated site toggle rewrite the
 * registration (review SW-5).
 */
export function relevantSites(base: readonly string[], sites: readonly string[]): string[] {
  const hosts: { host: string; subdomains: boolean }[] = [];
  for (const b of base) {
    const bh = b === ALL_URLS || b === '*://*/*' ? null : patternHost(b);
    if (!bh) return [...sites];
    hosts.push(bh);
  }
  return sites.filter((s) => hosts.some((bh) => isSameOrSubdomain(bh.host, s) || (bh.subdomains && isSameOrSubdomain(s, bh.host))));
}

/** Hostname usable in a `*://*.host/*` match pattern. */
function isPatternHost(h: unknown): h is string {
  return typeof h === 'string' && (isDnrDomain(h) || /^\[[0-9a-f:.]+\]$/.test(h));
}

/** Groups where protection is on: the root plus re-enabled subtrees. */
function enabledGroups(sites: SitesMap): ScopeGroup<boolean>[] {
  return layerScopes(explicitField(sites, 'enabled'), true).filter((g) => g.value === true);
}

/**
 * Expand one base registration into the registrations needed so it runs
 * exactly where protection is on. `extraExclude` is excluded everywhere.
 */
export function scopeToEnabled(base: DesiredScript, groups: readonly ScopeGroup<boolean>[], extraExclude: readonly string[] = []): DesiredScript[] {
  const out: DesiredScript[] = [];
  const baseExclude = [...(base.excludeMatches ?? []), ...extraExclude];
  let n = 0;
  for (const g of groups) {
    if (g.include === null) {
      out.push(withExclude({ ...base }, [...baseExclude, ...patterns(relevantSites(base.matches, g.exclude))]));
      continue;
    }
    const matches = intersectPatterns(base.matches, g.include);
    if (matches.length === 0) continue;
    n++;
    out.push(withExclude({ ...base, id: `${base.id}~${n}`, matches }, [...baseExclude, ...patterns(relevantSites(matches, g.exclude))]));
  }
  return out;
}

function withExclude(s: DesiredScript, exclude: string[]): DesiredScript {
  const ex = uniqueSorted(exclude);
  if (ex.length > 0) s.excludeMatches = ex;
  else delete s.excludeMatches;
  return s;
}

function cosmeticScript(): DesiredScript {
  return {
    id: COSMETIC_SCRIPT_ID,
    js: [COSMETIC_SCRIPT_FILE],
    matches: [ALL_URLS],
    world: 'ISOLATED',
    runAt: 'document_start',
    allFrames: true,
    matchOriginAsFallback: true,
    persistAcrossSessions: true,
  };
}

/** Privacy cfg file for a level; the build emits main/cfg-<off|standard|strict>-gpc<0|1>.js. */
export function privacyCfgFile(level: FingerprintLevel, gpc: boolean): string {
  return `main/cfg-${level}-gpc${gpc ? 1 : 0}.js`;
}

/**
 * MAIN-world privacy registrations: one per group of hosts sharing an
 * effective fingerprinting level, so that every host gets exactly one cfg
 * file. Sites with protection off get nothing. Sites with fingerprinting off
 * still get the script while GPC is on (cfg-off-gpc1 only sets
 * navigator.globalPrivacyControl, matching the Sec-GPC header they receive).
 *
 * With `fpMeter` (nerd mode fingerprinting meter) main/fpmeter.js is listed
 * right after privacy.js, so in every frame the meter runs second and wraps
 * privacy's proxies: page calls are counted once and privacy's internal
 * calls not at all (fpmeter.ts). Groups that need no privacy script then
 * get a registration with the meter alone.
 */
export function privacyScripts(settings: Settings, sites: SitesMap, seedFiles: readonly string[], fpMeter = false): DesiredScript[] {
  type Value = FingerprintLevel | 'disabled';
  const explicit = new Map<string, Value>();
  for (const [k, r] of explicitResolved(sites, settings, ['enabled', 'fingerprinting'])) {
    explicit.set(k, r.enabled ? r.fingerprinting : 'disabled');
  }
  const groups = layerScopes<Value>(explicit, settings.privacy.fingerprinting);
  const gpc = settings.privacy.gpc;
  const out: DesiredScript[] = [];
  let n = 0;
  for (const g of groups) {
    if (g.value === 'disabled') continue;
    const privacy = !(g.value === 'off' && !gpc);
    if (!privacy && !fpMeter) continue;
    const id = g.include === null ? PRIVACY_ID_PREFIX : `${PRIVACY_ID_PREFIX}-${++n}`;
    const js = privacy ? [...seedFiles, privacyCfgFile(g.value, settings.privacy.gpc), PRIVACY_SCRIPT_FILE] : [];
    if (fpMeter) js.push(FPMETER_SCRIPT_FILE);
    const s: DesiredScript = {
      id,
      js,
      matches: g.include === null ? [ALL_URLS] : patterns(g.include),
      world: 'MAIN',
      runAt: 'document_start',
      allFrames: true,
      matchOriginAsFallback: true,
      persistAcrossSessions: true,
    };
    out.push(withExclude(s, patterns(g.exclude)));
  }
  return out;
}

/**
 * The MAIN-world clipboard guard (ClickFix protection, a privacy default
 * independent of nerd mode) and the ISOLATED relay that both it and the nerd
 * mode fingerprinting meter (which rides on the privacy registrations) report
 * to. Like the cosmetic script they run wherever protection is on.
 */
export function nerdScripts(settings: Settings, groups: readonly ScopeGroup<boolean>[]): DesiredScript[] {
  const n = settings.nerd;
  const clip = settings.privacy.clipboardGuard;
  const meter = n.enabled && n.fingerprintMeter;
  if (!clip && !meter) return [];
  const base = (id: string, file: string, world: 'MAIN' | 'ISOLATED'): DesiredScript => ({
    id,
    js: [file],
    matches: [ALL_URLS],
    world,
    runAt: 'document_start',
    allFrames: true,
    matchOriginAsFallback: true,
    persistAcrossSessions: true,
  });
  const out: DesiredScript[] = [];
  if (clip) out.push(...scopeToEnabled(base(CLIPGUARD_ID, CLIPGUARD_SCRIPT_FILE, 'MAIN'), groups));
  out.push(...scopeToEnabled(base(NERD_RELAY_ID, NERD_RELAY_SCRIPT_FILE, 'ISOLATED'), groups));
  return out;
}

/** The complete desired set of registrations. */
export function computeRegistrations(inputs: RegistrationInputs): DesiredScript[] {
  const { settings, sites, enabledListIds, cosmeticMeta, scriptletIndex } = inputs;
  const groups = enabledGroups(sites);
  const out: DesiredScript[] = [];

  out.push(...scopeToEnabled(cosmeticScript(), groups));
  const soft = inputs.softListIds;
  const staticIds = soft && soft.size > 0 ? new Set(Array.from(enabledListIds).filter((id) => !soft.has(id))) : enabledListIds;
  const gh = genericHighScript(cosmeticMeta, staticIds, inputs.extraGenericHideHosts ?? []);
  if (gh) out.push(...scopeToEnabled(gh.base, groups, gh.exclude));
  for (const s of scriptletScripts(scriptletIndex, enabledListIds)) out.push(...scopeToEnabled(s, groups));
  const nerdOn = settings.nerd.enabled;
  out.push(...privacyScripts(settings, sites, inputs.seedFiles, nerdOn && settings.nerd.fingerprintMeter));
  out.push(...nerdScripts(settings, groups));
  return out;
}

/**
 * Hosts where no list's generic-high CSS may be injected statically: the
 * union over enabled lists (plus generichide hosts of any list and of custom
 * filters). The SW serves a filtered copy there (cosmetic.ts).
 */
export function genericHighExcludedUnion(meta: CosmeticMeta, enabledListIds: ReadonlySet<string>, extra: readonly string[] = []): string[] {
  const out = new Set<string>();
  const addAll = (hosts: unknown) => {
    if (!Array.isArray(hosts)) return;
    for (const h of hosts) if (isPatternHost(h)) out.add(h);
  };
  addAll(meta.genericHideHosts);
  for (const listId of Object.keys(meta.genericHighExcludedHosts ?? {})) {
    if (enabledListIds.has(listId) && meta.genericHighCss?.[listId]) addAll(meta.genericHighExcludedHosts[listId]);
  }
  addAll(extra);
  return Array.from(out).sort();
}

/**
 * One registration for the highly generic CSS of every enabled list (sorted
 * by list id). Entities ("google.*") and bare labels cannot be match patterns
 * (one bad pattern would fail the registration) and are left out.
 */
function genericHighScript(
  meta: CosmeticMeta | null,
  enabledListIds: ReadonlySet<string>,
  extra: readonly string[],
): { base: DesiredScript; exclude: string[] } | null {
  if (!meta || !meta.genericHighCss) return null;
  const css: string[] = [];
  for (const listId of Object.keys(meta.genericHighCss).sort()) {
    const file = meta.genericHighCss[listId];
    if (typeof file === 'string' && file !== '' && enabledListIds.has(listId)) css.push(packagePath(file));
  }
  if (css.length === 0) return null;
  return {
    base: {
      id: GENERIC_HIGH_ID,
      css,
      matches: [ALL_URLS],
      world: 'ISOLATED',
      runAt: 'document_start',
      allFrames: true,
      matchOriginAsFallback: true,
      persistAcrossSessions: true,
    },
    exclude: patterns(genericHighExcludedUnion(meta, enabledListIds, extra)),
  };
}

/**
 * One bundle registration per world: [core, data, end]. The data is the
 * merged file of the usual list set when all of its lists are enabled (plus
 * the files of further enabled lists), else the enabled lists' own files.
 */
function scriptletScripts(index: ScriptletIndex | null, enabledListIds: ReadonlySet<string>): DesiredScript[] {
  if (!index || !Array.isArray(index.bundles) || !Array.isArray(index.registrations)) return [];
  const out: DesiredScript[] = [];
  for (const b of index.bundles) {
    if (!b || (b.world !== 'MAIN' && b.world !== 'ISOLATED') || typeof b.core !== 'string' || typeof b.end !== 'string') continue;
    const merged = (Array.isArray(index.merged) ? index.merged : []).find(
      (m) => m && m.world === b.world && typeof m.file === 'string' && Array.isArray(m.lists) && m.lists.length > 0 && m.lists.every((l) => enabledListIds.has(l)),
    );
    const inMerged = new Set(merged?.lists ?? []);
    const data = index.registrations
      .filter((r) => r && r.world === b.world && typeof r.id === 'string' && typeof r.file === 'string' && enabledListIds.has(r.listId) && !inMerged.has(r.listId))
      .sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0))
      .map((r) => packagePath(r.file));
    if (merged) data.unshift(packagePath(merged.file));
    if (data.length === 0) continue;
    out.push({
      id: `${SCRIPTLET_ID_PREFIX}${b.world.toLowerCase()}`,
      js: [packagePath(b.core), ...data, packagePath(b.end)],
      matches: [ALL_URLS],
      world: b.world,
      runAt: 'document_start',
      allFrames: true,
      matchOriginAsFallback: true,
      persistAcrossSessions: true,
    });
  }
  return out;
}

/** Totals over a registration set (budget checks: review PERF-1/PERF-2). */
export function registrationStats(list: readonly { matches?: readonly string[]; excludeMatches?: readonly string[] }[]): {
  registrations: number;
  matches: number;
  excludeMatches: number;
  patterns: number;
} {
  let matches = 0;
  let excludeMatches = 0;
  for (const r of list) {
    matches += r.matches?.length ?? 0;
    excludeMatches += r.excludeMatches?.length ?? 0;
  }
  return { registrations: list.length, matches, excludeMatches, patterns: matches + excludeMatches };
}

/** Shape returned by chrome.scripting.getRegisteredContentScripts (subset). */
export interface RegisteredScript {
  id: string;
  js?: string[];
  css?: string[];
  matches?: string[];
  excludeMatches?: string[];
  world?: string;
  runAt?: string;
  allFrames?: boolean;
  matchOriginAsFallback?: boolean;
  persistAcrossSessions?: boolean;
}

export interface RegistrationDiff {
  unregister: string[];
  /**
   * Patterns or files changed: updateContentScripts, one call and one
   * broadcast to the renderers (a site or list toggle). File lists are only
   * updated in place when the kind (js / css) stays the same, because an
   * update cannot remove a field.
   */
  update: DesiredScript[];
  /** New, or world/timing/kind changed: (re-)register. */
  register: DesiredScript[];
}

function sameList(a: readonly string[] | undefined, b: readonly string[] | undefined, ordered: boolean): boolean {
  const x = a ?? [];
  const y = b ?? [];
  if (x.length !== y.length) return false;
  if (ordered) return x.every((v, i) => v === y[i]);
  const sx = [...x].sort();
  const sy = [...y].sort();
  return sx.every((v, i) => v === sy[i]);
}

export function diffRegistrations(current: readonly RegisteredScript[], desired: readonly DesiredScript[]): RegistrationDiff {
  const cur = new Map(current.map((c) => [c.id, c]));
  const want = new Set(desired.map((d) => d.id));
  const diff: RegistrationDiff = { unregister: [], update: [], register: [] };
  for (const c of current) if (!want.has(c.id)) diff.unregister.push(c.id);
  for (const d of desired) {
    const c = cur.get(d.id);
    if (!c) {
      diff.register.push(d);
      continue;
    }
    const has = (x: readonly string[] | undefined) => x !== undefined && x.length > 0;
    // updateContentScripts keeps fields it is not given, and apply.ts omits
    // empty excludeMatches: clearing them (the last disabled site switched
    // back on) needs a re-registration.
    const structural =
      has(c.js) !== has(d.js) ||
      has(c.css) !== has(d.css) ||
      (has(c.excludeMatches) && !has(d.excludeMatches)) ||
      (c.world ?? 'ISOLATED') !== d.world ||
      (c.runAt ?? 'document_idle') !== d.runAt ||
      (c.allFrames ?? false) !== d.allFrames ||
      (c.matchOriginAsFallback ?? false) !== d.matchOriginAsFallback ||
      (c.persistAcrossSessions ?? true) !== d.persistAcrossSessions;
    if (structural) {
      diff.unregister.push(d.id);
      diff.register.push(d);
      continue;
    }
    if (
      !sameList(c.js, d.js, true) ||
      !sameList(c.css, d.css, true) ||
      !sameList(c.matches, d.matches, false) ||
      !sameList(c.excludeMatches, d.excludeMatches, false)
    ) {
      diff.update.push(d);
    }
  }
  return diff;
}
