// Bastion Shield service worker — cosmetic filtering on request of the
// content script (ARCHITECTURE §5.2). For each frame we look up the frame's
// hostname, its parents and entity forms in the sharded specific data, keep
// entries of enabled lists, apply exceptions and flags, and inject the result
// with scripting.insertCSS (USER origin, so page styles cannot override it).
// Generic selectors are looked up by class/id token as the page reveals them.
//
// The data-processing functions are pure and exported for tests; the
// CosmeticService class gets its I/O (shard loading, insertCSS) injected.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { entityCandidates, hostnameCandidates, registrableDomain, shardName, shardOf } from '../shared/hash.ts';
import type {
  BlockingMode,
  CosmeticHostEntry,
  CosmeticMeta,
  CosmeticShard,
  GenericIndex,
  MsgCosmeticFrame,
  MsgCosmeticFrameResponse,
  MsgCosmeticTokens,
  MsgCosmeticTokensResponse,
} from '../shared/types.ts';
import type { GenericCosmetic, SpecificCosmetic } from '../compiler/types.ts';
import * as log from './log.ts';
import { Lru, webHostOf } from './util.ts';

export const CSS_GROUP_SIZE = 1000;
export const SHARD_CACHE_SIZE = 64;
const HOST_CACHE_SIZE = 256;
const MAX_TOKENS_PER_MESSAGE = 2000;

/** Hostname, parents (down to two labels) and entity forms, most specific first (§5.2.2.1). */
export function hostKeyCandidates(hostname: string): string[] {
  const h = hostname.toLowerCase().replace(/\.$/, '');
  if (h === '') return [];
  return [...hostnameCandidates(h), ...entityCandidates(h)];
}

/** Custom (user/admin) and imported-list cosmetic filters compiled at runtime. */
export interface CustomCosmetic {
  specific: SpecificCosmetic[];
  generic: GenericCosmetic[];
}

export const EMPTY_CUSTOM: CustomCosmetic = { specific: [], generic: [] };

/**
 * Host and token indexes of a CustomCosmetic. Imported lists put tens of
 * thousands of filters here, so frames and token batches look entries up
 * instead of scanning them. Built once per compiled set (the arrays are never
 * changed after compileAllCustom) and kept with it.
 */
interface CustomIndex {
  /** Host or entity key -> indexes into `specific`, ascending. */
  specificByHost: Map<string, number[]>;
  /** Token -> indexes into `generic`, ascending. */
  genericByToken: Map<string, number[]>;
  /** Indexes of the highly generic entries (no token), ascending. */
  untokened: number[];
}

const customIndexes = new WeakMap<CustomCosmetic, CustomIndex>();

function customIndex(custom: CustomCosmetic): CustomIndex {
  const hit = customIndexes.get(custom);
  if (hit) return hit;
  const ix: CustomIndex = { specificByHost: new Map(), genericByToken: new Map(), untokened: [] };
  const add = (m: Map<string, number[]>, key: string, i: number): void => {
    const list = m.get(key);
    if (!list) m.set(key, [i]);
    else if (list[list.length - 1] !== i) list.push(i);
  };
  custom.specific.forEach((s, i) => {
    for (const h of s.hosts) add(ix.specificByHost, h, i);
  });
  custom.generic.forEach((g, i) => {
    if (g.token === null) ix.untokened.push(i);
    else add(ix.genericByToken, g.token, i);
  });
  customIndexes.set(custom, ix);
  return ix;
}

/** Indexes listed under any of `keys`, ascending and once each (the filters' own order). */
function indexHits(map: ReadonlyMap<string, readonly number[]>, keys: Iterable<string>): number[] {
  const out = new Set<number>();
  for (const k of keys) {
    const list = map.get(k);
    if (list) for (const i of list) out.add(i);
  }
  return Array.from(out).sort((a, b) => a - b);
}

/** Whether the custom filters have keyed generic selectors (the frame then reports its tokens). */
export function customHasTokens(custom: CustomCosmetic): boolean {
  return customIndex(custom).genericByToken.size > 0;
}

/** Everything we know about one hostname after merging all sources. */
export interface HostCosmetic {
  /** Hide selectors of at least one always-apply list or a custom filter. */
  hide: string[];
  /** Hide selectors only first-party-protected lists have: un-hidden by the Standard-mode heuristic (§5.2.8). */
  soft: string[];
  styles: string[];
  procedural: string[];
  /** Selectors excepted on this host (#@#sel); also apply to generic data. */
  exceptions: Set<string>;
  flags: Set<string>;
  /** generichide/elemhide absent. */
  genericAllowed: boolean;
}

interface Collected {
  hide: Set<string>;
  /** Hide selectors from an always-apply list or a custom filter. */
  hard: Set<string>;
  styles: Set<string>;
  procedural: Set<string>;
  exceptions: Set<string>;
  procExceptions: Set<string>;
  flags: Set<string>;
}

function newCollected(): Collected {
  return { hide: new Set(), hard: new Set(), styles: new Set(), procedural: new Set(), exceptions: new Set(), procExceptions: new Set(), flags: new Set() };
}

function addEntry(c: Collected, kind: number, payload: string, hard: boolean): void {
  switch (kind) {
    case 0:
      c.hide.add(payload);
      if (hard) c.hard.add(payload);
      break;
    case 1:
      c.exceptions.add(payload);
      break;
    case 2:
      c.procedural.add(payload);
      break;
    case 3:
      c.styles.add(payload);
      break;
    case 4:
      c.flags.add(payload);
      break;
    case 5:
      c.procExceptions.add(payload);
      break;
    default:
      break;
  }
}

/** Matches when any candidate is in `hosts`. */
function anyIn(candidates: readonly string[], hosts: readonly string[] | ReadonlySet<string>): boolean {
  const set = hosts instanceof Set ? hosts : new Set(hosts as readonly string[]);
  for (const c of candidates) if (set.has(c)) return true;
  return false;
}

/** Selector text of a procedural filter, for matching #@# procedural exceptions. */
function proceduralSelectorText(payload: string): string[] {
  try {
    const f = JSON.parse(payload) as { raw?: unknown };
    if (typeof f.raw !== 'string') return [];
    const raw = f.raw;
    const out = [raw];
    for (const sep of ['#?#', '##']) {
      const i = raw.indexOf(sep);
      if (i !== -1) out.push(raw.slice(i + sep.length));
    }
    return out;
  } catch {
    return [];
  }
}

/**
 * Merge shard entries (already looked up for every candidate key) and custom
 * filters into the cosmetic state of one host, applying list masks,
 * exceptions (kind 1 removes kind 0/3 with the same text, kind 5 removes
 * kind 2) and flags (generichide, specifichide, elemhide). Hide selectors
 * that only lists in `softMask` (enabled first-party-protected lists) have
 * go to `soft`; custom filters are always hard.
 */
export function resolveHostCosmetic(
  entriesPerKey: readonly (readonly CosmeticHostEntry[] | undefined)[],
  enabledMask: number,
  candidates: readonly string[],
  custom: CustomCosmetic = EMPTY_CUSTOM,
  softMask = 0,
): HostCosmetic {
  const hardMask = (enabledMask & ~softMask) >>> 0;
  const c = newCollected();
  for (const entries of entriesPerKey) {
    if (!entries) continue;
    for (const e of entries) {
      if (!Array.isArray(e) || e.length < 3) continue;
      const [kind, payload, mask] = e;
      if (typeof payload !== 'string' || ((mask >>> 0) & (enabledMask >>> 0)) === 0) continue;
      addEntry(c, kind, payload, ((mask >>> 0) & hardMask) !== 0);
    }
  }
  for (const i of indexHits(customIndex(custom).specificByHost, candidates)) {
    const s = custom.specific[i];
    if (s.excludedHosts.length > 0 && anyIn(candidates, s.excludedHosts)) continue;
    addEntry(c, s.kind, s.payload, true);
  }
  const elemhide = c.flags.has('elemhide');
  const specificAllowed = !(elemhide || c.flags.has('specifichide'));
  const genericAllowed = !(elemhide || c.flags.has('generichide'));
  const all = specificAllowed ? Array.from(c.hide).filter((s) => !c.exceptions.has(s)) : [];
  const hide = all.filter((s) => c.hard.has(s));
  const soft = all.filter((s) => !c.hard.has(s));
  const styles = specificAllowed ? Array.from(c.styles).filter((s) => !c.exceptions.has(s)) : [];
  const procedural = specificAllowed
    ? Array.from(c.procedural).filter((p) => !proceduralSelectorText(p).some((t) => c.procExceptions.has(t)))
    : [];
  return { hide, soft, styles, procedural, exceptions: c.exceptions, flags: c.flags, genericAllowed };
}

/** `sel1,\nsel2{display:none!important}` in groups of `groupSize` selectors (§5.2.2.6). */
export function buildHideCss(selectors: readonly string[], groupSize = CSS_GROUP_SIZE): string {
  const parts: string[] = [];
  for (let i = 0; i < selectors.length; i += groupSize) {
    parts.push(`${selectors.slice(i, i + groupSize).join(',\n')}{display:none!important}`);
  }
  return parts.join('\n');
}

/** CSS for specific hiding plus :style() rules. */
export function buildHostCss(host: HostCosmetic, extraHide: readonly string[] = []): string {
  const hide = extraHide.length > 0 ? Array.from(new Set([...host.hide, ...extraHide])) : host.hide;
  const parts: string[] = [];
  const h = buildHideCss(hide);
  if (h) parts.push(h);
  for (const s of host.styles) parts.push(s);
  return parts.join('\n');
}

/** Selector lists of the lowly generic index by token. */
export interface GenericLookup {
  get(token: string): [string, number][] | undefined;
}

const GENERIC_HEAD = '{"tokens":{\n';
const GENERIC_CACHE_SIZE = 20_000;

function lookupFromIndex(g: GenericIndex): GenericLookup | null {
  const tokens = g && typeof g.tokens === 'object' && g.tokens !== null ? g.tokens : null;
  if (!tokens) return null;
  return { get: (t) => (Object.prototype.hasOwnProperty.call(tokens, t) ? tokens[t] : undefined) };
}

/**
 * Binary search for `key` in lines `"token":[[...]]` (optionally followed by
 * a comma), sorted by token, every line ending with "\n". Raw newlines only
 * occur between lines: JSON escapes them inside strings.
 */
function findGenericLine(s: string, key: string): [string, number][] | null {
  let lo = 0;
  let hi = s.length;
  while (lo < hi) {
    const a = s.lastIndexOf('\n', ((lo + hi) >>> 1) - 1) + 1;
    const e = s.indexOf('\n', a);
    if (e === -1 || s.charCodeAt(a) !== 34) return null;
    let j = a + 1;
    let escaped = false;
    while (j < e && s.charCodeAt(j) !== 34) {
      if (s.charCodeAt(j) === 92) {
        j++;
        escaped = true;
      }
      j++;
    }
    if (j >= e) return null;
    const k = escaped ? (JSON.parse(s.slice(a, j + 1)) as string) : s.slice(a + 1, j);
    if (k === key) {
      const v = JSON.parse(s.slice(j + 2, s.charCodeAt(e - 1) === 44 ? e - 1 : e)) as unknown;
      return Array.isArray(v) ? (v as [string, number][]) : null;
    }
    if (k < key) lo = e + 1;
    else hi = a;
  }
  return null;
}

/**
 * Lookup over the text of cosmetic/generic.json (review PERF-5). The build
 * writes one token per line, sorted, so the service worker keeps the text
 * and binary-searches it: no JSON.parse of the whole 2 MB index after every
 * worker start, only the selector lists of tokens a page actually uses.
 * Text in any other layout is parsed once (older builds, tests).
 */
export function genericLookupFromText(text: string): GenericLookup | null {
  if (!text.startsWith(GENERIC_HEAD)) {
    try {
      return lookupFromIndex(JSON.parse(text) as GenericIndex);
    } catch {
      return null;
    }
  }
  const end = text.lastIndexOf('\n}}');
  if (end < GENERIC_HEAD.length - 1) return null;
  const body = text.slice(GENERIC_HEAD.length, end + 1);
  if (body.length <= 1) return { get: () => undefined };
  const cache = new Map<string, [string, number][] | null>();
  return {
    get(token) {
      if (typeof token !== 'string') return undefined;
      const hit = cache.get(token);
      if (hit !== undefined) return hit ?? undefined;
      let v: [string, number][] | null = null;
      try {
        v = findGenericLine(body, token);
      } catch {
        v = null;
      }
      if (cache.size >= GENERIC_CACHE_SIZE) cache.clear();
      cache.set(token, v);
      return v ?? undefined;
    },
  };
}

/**
 * Generic (token-keyed) selectors for newly seen class/id tokens: enabled
 * lists only, minus the host's exceptions, plus custom generic filters.
 */
export function genericSelectorsForTokens(
  index: GenericIndex | GenericLookup | null,
  tokens: readonly string[],
  enabledMask: number,
  host: Pick<HostCosmetic, 'exceptions'>,
  candidates: readonly string[],
  custom: CustomCosmetic = EMPTY_CUSTOM,
): string[] {
  const { hard, soft } = splitGenericSelectors(index, tokens, enabledMask, host, candidates, custom, 0);
  return hard.concat(soft);
}

/** genericSelectorsForTokens, split like resolveHostCosmetic: `soft` holds the selectors only `softMask` lists have. */
export function splitGenericSelectors(
  index: GenericIndex | GenericLookup | null,
  tokens: readonly string[],
  enabledMask: number,
  host: Pick<HostCosmetic, 'exceptions'>,
  candidates: readonly string[],
  custom: CustomCosmetic,
  softMask: number,
): { hard: string[]; soft: string[] } {
  const out = new Set<string>();
  const hard = new Set<string>();
  const hardMask = (enabledMask & ~softMask) >>> 0;
  const wanted = new Set(tokens);
  const lookup = index === null || typeof index !== 'object' ? null : 'tokens' in index ? lookupFromIndex(index) : index;
  if (lookup) {
    for (const t of wanted) {
      const list = lookup.get(t);
      if (!Array.isArray(list)) continue;
      for (const item of list) {
        if (!Array.isArray(item)) continue;
        const [sel, mask] = item;
        if (typeof sel !== 'string' || ((mask >>> 0) & (enabledMask >>> 0)) === 0) continue;
        if (host.exceptions.has(sel)) continue;
        out.add(sel);
        if (((mask >>> 0) & hardMask) !== 0) hard.add(sel);
      }
    }
  }
  for (const i of indexHits(customIndex(custom).genericByToken, wanted)) {
    const g = custom.generic[i];
    if (host.exceptions.has(g.selector)) continue;
    if (g.excludedHosts.length > 0 && anyIn(candidates, g.excludedHosts)) continue;
    out.add(g.selector);
    hard.add(g.selector);
  }
  const all = Array.from(out);
  return { hard: all.filter((s) => hard.has(s)), soft: all.filter((s) => !hard.has(s)) };
}

/** Custom highly generic selectors (no token): injected with the frame CSS. */
export function customHighlyGeneric(custom: CustomCosmetic, host: Pick<HostCosmetic, 'exceptions'>, candidates: readonly string[]): string[] {
  const out: string[] = [];
  for (const i of customIndex(custom).untokened) {
    const g = custom.generic[i];
    if (host.exceptions.has(g.selector)) continue;
    if (g.excludedHosts.length > 0 && anyIn(candidates, g.excludedHosts)) continue;
    out.push(g.selector);
  }
  return out;
}

/**
 * Hosts where the single generic-high registration (bs-gh-all) does not
 * inject: generichide hosts of any list plus the excluded hosts of every
 * enabled list with generic-high CSS. Must match registrations.ts
 * (genericHighExcludedUnion, without the custom-filter hosts: generic hiding
 * is off there anyway).
 */
export function genericHighExcludedSet(meta: CosmeticMeta | null, enabledListIds: ReadonlySet<string>): Set<string> {
  const out = new Set<string>();
  if (!meta) return out;
  const addAll = (hosts: unknown) => {
    if (Array.isArray(hosts)) for (const h of hosts) if (typeof h === 'string') out.add(h);
  };
  addAll(meta.genericHideHosts);
  for (const [listId, hosts] of Object.entries(meta.genericHighExcludedHosts ?? {})) {
    if (enabledListIds.has(listId) && meta.genericHighCss?.[listId]) addAll(hosts);
  }
  return out;
}

/**
 * On hosts where the generic-high CSS is not registered (one of the frame's
 * hostname candidates is in the excluded set), the SW injects a copy of the
 * highly generic selectors of EVERY enabled list without the host's excepted
 * selectors — but only when generic hiding is allowed on the host (§5.2.4).
 * The registration is shared by all lists, so a host excluded because of one
 * list's exception misses every list's CSS.
 */
export function genericHighCopies(
  meta: CosmeticMeta | null,
  selectorsByList: Record<string, string[]> | null,
  enabledListIds: ReadonlySet<string>,
  hostCandidates: readonly string[],
  host: Pick<HostCosmetic, 'exceptions' | 'genericAllowed'>,
  excluded: ReadonlySet<string> = genericHighExcludedSet(meta, enabledListIds),
): string[] {
  if (!meta || !selectorsByList || !host.genericAllowed) return [];
  if (!anyIn(hostCandidates, excluded)) return [];
  const out: string[] = [];
  for (const listId of Object.keys(meta.genericHighCss ?? {}).sort()) {
    if (!enabledListIds.has(listId) || !meta.genericHighCss[listId]) continue;
    for (const sel of selectorsByList[listId] ?? []) if (!host.exceptions.has(sel)) out.push(sel);
  }
  return out;
}

/**
 * Highly generic selectors of the enabled first-party-protected lists, minus
 * the host's exceptions. They are not registered statically (bs-gh-all holds
 * the always-apply lists only), so the SW serves them with every frame:
 * soft in Standard mode, as CSS otherwise (§5.2.4, §5.2.8).
 */
export function softHighGeneric(
  selectorsByList: Record<string, string[]> | null,
  softListIds: ReadonlySet<string>,
  host: Pick<HostCosmetic, 'exceptions' | 'genericAllowed'>,
): string[] {
  if (!selectorsByList || !host.genericAllowed) return [];
  const out = new Set<string>();
  for (const listId of Array.from(softListIds).sort()) {
    for (const sel of selectorsByList[listId] ?? []) if (typeof sel === 'string' && !host.exceptions.has(sel)) out.add(sel);
  }
  return Array.from(out);
}

/** Brave's vetted search engines (cosmetic_filters_js_handler.cc). */
const SEARCH_ENGINES = new Set(['duckduckgo', 'qwant', 'bing', 'startpage', 'google', 'yandex', 'ecosia', 'brave']);

/** True when the label before the public suffix of the host's registrable domain is a vetted search engine. */
export function isVettedSearchEngine(hostname: string): boolean {
  const site = registrableDomain(hostname);
  const i = site.indexOf('.');
  return i > 0 && SEARCH_ENGINES.has(site.slice(0, i));
}

/**
 * How a frame treats soft selectors (Brave's enabled_1st_party_cf_):
 *   - 'hard': hidden like every other selector: Aggressive mode, frames on
 *     another host than the top page (Brave: cross-origin to the main
 *     frame) and youtube.com, which Brave always filters aggressively;
 *   - 'drop': Standard mode on a vetted search engine: not applied at all;
 *   - 'soft': Standard mode: hidden, then checked by the content script.
 */
export function softPolicy(frameHost: string, topHost: string | null, mode: BlockingMode): 'hard' | 'soft' | 'drop' {
  if (mode === 'aggressive') return 'hard';
  const f = frameHost.toLowerCase();
  if (topHost !== null && topHost.toLowerCase() !== f) return 'hard';
  if (registrableDomain(f) === 'youtube.com') return 'hard';
  if (isVettedSearchEngine(f)) return 'drop';
  return 'soft';
}

// ---------------------------------------------------------------------------
// Service (runtime)
// ---------------------------------------------------------------------------

export interface CosmeticConfig {
  enabledMask: number;
  enabledListIds: ReadonlySet<string>;
  /** Bits of the enabled first-party-protected lists (catalog `firstPartyProtected`). */
  softMask: number;
  /** Ids of the enabled first-party-protected lists. */
  softListIds: ReadonlySet<string>;
  /** Blocking mode of the page whose top-level hostname is given. */
  modeOf(topHostname: string): BlockingMode;
  deAmp: boolean;
  custom: CustomCosmetic;
  /** Protection off for the page whose top-level hostname is given. */
  isOff(topHostname: string): boolean;
}

export interface CosmeticTarget {
  tabId: number;
  frameId: number;
  documentId?: string;
}

export interface CosmeticDeps {
  loadMeta(): Promise<CosmeticMeta | null>;
  loadShard(name: string): Promise<CosmeticShard | null>;
  loadGeneric(): Promise<GenericIndex | GenericLookup | null>;
  loadGenericHigh(meta: CosmeticMeta): Promise<Record<string, string[]> | null>;
  config(): CosmeticConfig;
  insertCss(target: CosmeticTarget, css: string): Promise<void>;
}

export interface FrameSender {
  tabId: number;
  frameId: number;
  documentId?: string;
  /** sender.url (the frame's URL as the browser sees it). */
  url?: string;
  /** sender.origin. */
  origin?: string;
  /** sender.tab.url (top-level page). */
  tabUrl?: string;
}

interface HostResult {
  host: HostCosmetic;
  /** CSS of the hard selectors and :style() rules. */
  css: string;
  /** Soft specific selectors plus the soft highly generic ones. */
  soft: string[];
  /** css plus the soft selectors, built on first use. */
  hardCss?: string;
}

/** Enabled lists whose highly generic CSS is registered statically (bs-gh-all). */
function staticListIds(cfg: CosmeticConfig): Set<string> {
  const out = new Set<string>();
  for (const id of cfg.enabledListIds) if (!cfg.softListIds.has(id)) out.add(id);
  return out;
}

export class CosmeticService {
  private readonly deps: CosmeticDeps;
  private readonly shards = new Lru<string, CosmeticShard | null>(SHARD_CACHE_SIZE);
  private readonly hostCache = new Lru<string, HostResult>(HOST_CACHE_SIZE);
  /** genericHighExcludedSet for the enabled lists it was built for. */
  private excluded: { meta: CosmeticMeta; lists: string; set: Set<string> } | null = null;
  private pendingShards = new Map<string, Promise<CosmeticShard | null>>();

  constructor(deps: CosmeticDeps) {
    this.deps = deps;
  }

  /** Call after any configuration change (lists, custom filters, sites). */
  invalidate(): void {
    this.hostCache.clear();
    this.excluded = null;
  }

  private excludedSet(meta: CosmeticMeta, enabledListIds: ReadonlySet<string>): Set<string> {
    const lists = Array.from(enabledListIds).sort().join(',');
    if (this.excluded && this.excluded.meta === meta && this.excluded.lists === lists) return this.excluded.set;
    const set = genericHighExcludedSet(meta, enabledListIds);
    this.excluded = { meta, lists, set };
    return set;
  }

  private shard(name: string): Promise<CosmeticShard | null> {
    if (this.shards.has(name)) return Promise.resolve(this.shards.get(name) ?? null);
    let p = this.pendingShards.get(name);
    if (!p) {
      p = this.deps
        .loadShard(name)
        .catch(() => null)
        .then((s) => {
          this.shards.set(name, s);
          this.pendingShards.delete(name);
          return s;
        });
      this.pendingShards.set(name, p);
    }
    return p;
  }

  /** Frame hostname: the frame URL, else the sender origin (about:blank inherits), else the top page. */
  static frameHostname(msgUrl: string | undefined, sender: FrameSender, topUrl?: string): string | null {
    return webHostOf(msgUrl) ?? webHostOf(sender.url) ?? webHostOf(sender.origin) ?? webHostOf(topUrl) ?? webHostOf(sender.tabUrl);
  }

  private async hostResult(hostname: string, cfg: CosmeticConfig): Promise<HostResult> {
    const cached = this.hostCache.get(hostname);
    if (cached) return cached;
    const candidates = hostKeyCandidates(hostname);
    const meta = await this.deps.loadMeta();
    const shardCount = meta?.shards && meta.shards > 0 ? meta.shards : 256;
    const shardNames = candidates.map((k) => shardName(shardOf(k, shardCount)));
    const loaded = await Promise.all(Array.from(new Set(shardNames)).map(async (n) => [n, await this.shard(n)] as const));
    const byName = new Map(loaded);
    const entriesPerKey = candidates.map((k, i) => {
      const s = byName.get(shardNames[i]);
      const hosts = s?.hosts;
      return hosts && Object.prototype.hasOwnProperty.call(hosts, k) ? hosts[k] : undefined;
    });
    const host = resolveHostCosmetic(entriesPerKey, cfg.enabledMask, candidates, cfg.custom, cfg.softMask);
    let extra: string[] = [];
    let softHigh: string[] = [];
    if (host.genericAllowed) {
      extra = customHighlyGeneric(cfg.custom, host, candidates);
      if (meta) {
        const statics = staticListIds(cfg);
        const excluded = this.excludedSet(meta, statics);
        const parents = hostnameCandidates(hostname);
        if (excluded.size > 0 && anyIn(parents, excluded)) {
          const selectors = await this.deps.loadGenericHigh(meta);
          extra = extra.concat(genericHighCopies(meta, selectors, statics, parents, host, excluded));
        }
        if (cfg.softListIds.size > 0) softHigh = softHighGeneric(await this.deps.loadGenericHigh(meta), cfg.softListIds, host);
      }
    }
    const soft = softHigh.length === 0 ? host.soft : Array.from(new Set([...host.soft, ...softHigh]));
    const result: HostResult = { host, css: buildHostCss(host, extra), soft };
    this.hostCache.set(hostname, result);
    return result;
  }

  private target(sender: FrameSender): CosmeticTarget {
    return sender.documentId ? { tabId: sender.tabId, frameId: sender.frameId, documentId: sender.documentId } : { tabId: sender.tabId, frameId: sender.frameId };
  }

  /** Frame CSS for a soft policy: soft selectors join the CSS only when they are hidden like the rest. */
  private static frameCss(r: HostResult, policy: 'hard' | 'soft' | 'drop'): string {
    if (policy !== 'hard' || r.soft.length === 0) return r.css;
    if (r.hardCss === undefined) r.hardCss = [r.css, buildHideCss(r.soft)].filter((c) => c !== '').join('\n');
    return r.hardCss;
  }

  async onFrame(msg: MsgCosmeticFrame, sender: FrameSender): Promise<MsgCosmeticFrameResponse> {
    const cfg = this.deps.config();
    const empty: MsgCosmeticFrameResponse = { off: false, css: '', procedural: [], generic: false, deAmp: cfg.deAmp };
    const topHost = webHostOf(sender.tabUrl) ?? webHostOf(msg.topUrl) ?? CosmeticService.frameHostname(msg.url, sender);
    if (topHost && cfg.isOff(topHost)) return { off: true, css: '', procedural: [], generic: false, deAmp: false };
    const hostname = CosmeticService.frameHostname(msg.url, sender, msg.topUrl);
    if (!hostname) return empty;
    try {
      const r = await this.hostResult(hostname, cfg);
      const { host } = r;
      const policy = softPolicy(hostname, topHost, topHost ? cfg.modeOf(topHost) : 'standard');
      const css = CosmeticService.frameCss(r, policy);
      if (css) {
        // The content script adopts the CSS at once; insertCSS (USER origin)
        // makes it robust against page styles. Do not delay the reply for it.
        void this.deps.insertCss(this.target(sender), css).catch((e: unknown) => log.warn('cosmetic', 'insertCSS', e));
      }
      // generic.json is only loaded when the first tokens arrive, keeping this reply fast.
      const generic = host.genericAllowed && (cfg.enabledMask !== 0 || customHasTokens(cfg.custom));
      const res: MsgCosmeticFrameResponse = { off: false, css, procedural: host.procedural, generic, deAmp: cfg.deAmp };
      // `site` also tells the content script to check soft selectors that arrive with token replies.
      if (policy === 'soft' && cfg.softMask !== 0) {
        res.soft = r.soft;
        res.site = registrableDomain(hostname);
      }
      return res;
    } catch (e) {
      log.warn('cosmetic', 'frame', hostname, e);
      return empty;
    }
  }

  async onTokens(msg: MsgCosmeticTokens, sender: FrameSender): Promise<MsgCosmeticTokensResponse> {
    const cfg = this.deps.config();
    const hostname = CosmeticService.frameHostname(msg.url, sender);
    if (!hostname || !Array.isArray(msg.tokens) || msg.tokens.length === 0) return { css: '' };
    const topHost = webHostOf(sender.tabUrl) ?? hostname;
    if (cfg.isOff(topHost)) return { css: '' };
    try {
      const { host } = await this.hostResult(hostname, cfg);
      if (!host.genericAllowed) return { css: '' };
      const tokens = msg.tokens.filter((t): t is string => typeof t === 'string' && t.length > 1 && t.length < 256).slice(0, MAX_TOKENS_PER_MESSAGE);
      const index = await this.deps.loadGeneric();
      const policy = softPolicy(hostname, topHost, cfg.modeOf(topHost));
      const split = splitGenericSelectors(index, tokens, cfg.enabledMask, host, hostKeyCandidates(hostname), cfg.custom, cfg.softMask);
      const hard = policy === 'hard' ? split.hard.concat(split.soft) : split.hard;
      const css = hard.length === 0 ? '' : buildHideCss(hard);
      if (css) void this.deps.insertCss(this.target(sender), css).catch((e: unknown) => log.warn('cosmetic', 'insertCSS', e));
      return policy === 'soft' && split.soft.length !== 0 ? { css, soft: split.soft } : { css };
    } catch (e) {
      log.warn('cosmetic', 'tokens', hostname, e);
      return { css: '' };
    }
  }
}
