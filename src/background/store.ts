// Bastion Shield service worker — persisted state: user settings, per-site
// settings and custom filters in chrome.storage.local (TRUSTED_CONTEXTS only),
// the managed policy from chrome.storage.managed, and the derived effective
// configuration. All reads are tolerant: broken or missing data falls back to
// defaults so the extension always keeps protecting.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { STORAGE } from '../shared/constants.ts';
import type { BuildMeta, EffectiveConfig, ManagedPolicy, Settings, SitesMap } from '../shared/types.ts';
import * as log from './log.ts';
import { buildEffectiveConfig, defaultSettings, normalizeSettings, pruneUnknownLists, sanitizeManaged } from './settings.ts';
import type { ListInfo } from './settings.ts';
import { coveredBy, effectiveSites, managedSites, sanitizeSites } from './sites.ts';
import type { ManagedSites } from './sites.ts';
import { canonicalJson } from './util.ts';

export const MAX_CUSTOM_FILTERS_BYTES = 1_000_000;
/** Bound on remembered own writes per key whose storage.onChanged echo is still due. */
const MAX_PENDING_ECHOES = 32;

/** What a storage.onChanged event requires from the service worker (SW-1). */
export interface StorageChangePlan {
  /** Re-read chrome.storage.managed first. */
  reloadManaged: boolean;
  /** Drop the compiled custom filters (text or admin filters may have changed). */
  recompileCustom: boolean;
  /** 'now' = applier.now(), 'schedule' = debounced applier.schedule(). */
  apply: 'now' | 'schedule' | null;
}

/**
 * Decide what a storage.onChanged event requires. `localChanged` is the
 * result of Store.applyLocalChange for a 'local' event. `cold` is true when
 * the event arrived before init finished: it is the event that (re)started
 * the worker, and init has already loaded the NEW values, so an in-memory
 * diff cannot see the change. Policy changes are rare and never echoes of our
 * own writes, so they are always re-applied (applyAll is diffed and
 * idempotent).
 */
export function storageChangePlan(area: string, keys: readonly string[], localChanged: boolean, cold: boolean): StorageChangePlan {
  if (area === 'managed') return { reloadManaged: true, recompileCustom: true, apply: 'now' };
  if (area !== 'local') return { reloadManaged: false, recompileCustom: false, apply: null };
  const ours = keys.includes(STORAGE.SETTINGS) || keys.includes(STORAGE.SITES) || keys.includes(STORAGE.CUSTOM_FILTERS);
  const apply = localChanged || (cold && ours);
  return { reloadManaged: false, recompileCustom: apply && keys.includes(STORAGE.CUSTOM_FILTERS), apply: apply ? 'schedule' : null };
}

/**
 * Regional lists (catalog `langs`) are on by default when the browser UI
 * language or any preferred content language matches, like Brave's
 * locale-based regional lists but also honouring multilingual users
 * (a de-CH UI user who reads French sites gets the French list too).
 * `languages` are BCP 47 tags; only the primary subtag is compared.
 */
export function languageMatches(langs: readonly string[] | undefined, languages: readonly string[]): boolean {
  if (!langs || langs.length === 0) return false;
  const want = new Set(langs.map((l) => l.toLowerCase()));
  return languages.some((tag) => want.has(tag.toLowerCase().split(/[-_]/)[0] ?? ''));
}

/** Browser UI language plus preferred content languages (service worker context). */
export function browserLanguages(): string[] {
  const out: string[] = [];
  try {
    out.push(chrome.i18n.getUILanguage());
  } catch {
    /* not available */
  }
  try {
    for (const l of (globalThis.navigator?.languages ?? [])) out.push(l);
  } catch {
    /* not available */
  }
  return out.filter((l) => typeof l === 'string' && l !== '');
}

export function listInfos(meta: BuildMeta | null, languages: readonly string[] = []): ListInfo[] {
  if (!meta) return [];
  return meta.lists.map((l) => ({
    id: l.id,
    default: l.default === true || languageMatches(l.langs, languages),
    locked: l.locked === true,
  }));
}

export class Store {
  user: Settings = defaultSettings();
  sites: SitesMap = {};
  customText = '';
  managed: ManagedPolicy = {};
  meta: BuildMeta | null = null;
  private lists: ListInfo[] = [];
  private effCache: EffectiveConfig | null = null;
  private sitesCache: SitesMap | null = null;
  private managedSitesCache: ManagedSites | null = null;
  /**
   * canonicalJson of values this instance wrote, per storage key, in write
   * order. Their storage.onChanged echoes are skipped: a late echo of an
   * older write must not overwrite newer in-memory state.
   */
  private readonly own = new Map<string, string[]>();

  async load(meta: BuildMeta | null): Promise<void> {
    this.meta = meta;
    this.lists = listInfos(meta, browserLanguages());
    const [local, managed] = await Promise.all([
      log.attempt('store', () => chrome.storage.local.get([STORAGE.SETTINGS, STORAGE.SITES, STORAGE.CUSTOM_FILTERS]), {} as Record<string, unknown>),
      this.readManaged(),
    ]);
    this.user = pruneUnknownLists(normalizeSettings(local[STORAGE.SETTINGS]), this.lists);
    this.sites = sanitizeSites(local[STORAGE.SITES]);
    const custom = local[STORAGE.CUSTOM_FILTERS];
    this.customText = typeof custom === 'string' ? custom.slice(0, MAX_CUSTOM_FILTERS_BYTES) : '';
    this.managed = managed;
    this.invalidate();
  }

  setMeta(meta: BuildMeta | null): void {
    this.meta = meta;
    this.lists = listInfos(meta, browserLanguages());
    this.invalidate();
  }

  listInfos(): ListInfo[] {
    return this.lists;
  }

  private async readManaged(): Promise<ManagedPolicy> {
    try {
      // storage.managed rejects when no policy schema/value exists on some builds.
      const raw = await chrome.storage.managed.get(null);
      return sanitizeManaged(raw);
    } catch {
      return {};
    }
  }

  /** Re-read the policy; true when it changed. */
  async reloadManaged(): Promise<boolean> {
    const next = await this.readManaged();
    if (canonicalJson(next) === canonicalJson(this.managed)) return false;
    this.managed = next;
    this.invalidate();
    return true;
  }

  private invalidate(): void {
    this.effCache = null;
    this.sitesCache = null;
    this.managedSitesCache = null;
  }

  /** Fleet kill switch (policy protectionEnabled: false): protection off everywhere. */
  protectionOff(): boolean {
    return this.managed.protectionEnabled === false;
  }

  /** Normalised policy host sets (cached). */
  managedSites(): ManagedSites {
    if (!this.managedSitesCache) this.managedSitesCache = managedSites(this.managed);
    return this.managedSitesCache;
  }

  effective(): EffectiveConfig {
    if (!this.effCache) this.effCache = buildEffectiveConfig(this.user, this.managed, this.lists);
    return this.effCache;
  }

  settings(): Settings {
    return this.effective().settings;
  }

  lockedSet(): Set<string> {
    return new Set(this.effective().locked);
  }

  effectiveSites(): SitesMap {
    if (!this.sitesCache) this.sitesCache = effectiveSites(this.sites, this.managed, this.managedSites());
    return this.sitesCache;
  }

  /**
   * Fields of one site the user may not change (policy). Policy hosts cover
   * their subdomains, as the schema documents for disabledSites and
   * aggressiveSites.
   */
  siteLocks(site: string): { enabled: boolean; mode: boolean } {
    const m = this.managedSites();
    return {
      enabled: this.managed.allowUserSiteToggle === false || coveredBy(site, m.disabled),
      mode: coveredBy(site, m.aggressive),
    };
  }

  /** Write one key; the write is remembered so its onChanged echo is ignored. */
  private async write(key: string, value: unknown, before: string): Promise<void> {
    const json = canonicalJson(value);
    // An unchanged value produces no onChanged event, so nothing to expect.
    const expectEcho = json !== before;
    let pending = this.own.get(key);
    if (expectEcho) {
      if (!pending) this.own.set(key, (pending = []));
      pending.push(json);
      if (pending.length > MAX_PENDING_ECHOES) pending.splice(0, pending.length - MAX_PENDING_ECHOES);
    }
    try {
      await chrome.storage.local.set({ [key]: value });
    } catch (e) {
      if (expectEcho && pending) {
        const i = pending.lastIndexOf(json);
        if (i !== -1) pending.splice(i, 1);
      }
      throw e;
    }
  }

  async saveSettings(next: Settings): Promise<void> {
    const before = canonicalJson(this.user);
    this.user = normalizeSettings(next);
    this.invalidate();
    await this.write(STORAGE.SETTINGS, this.user, before);
  }

  async saveSites(next: SitesMap): Promise<void> {
    const before = canonicalJson(this.sites);
    this.sites = sanitizeSites(next);
    this.invalidate();
    await this.write(STORAGE.SITES, this.sites, before);
  }

  async saveCustom(text: string): Promise<void> {
    const before = canonicalJson(this.customText);
    this.customText = text.slice(0, MAX_CUSTOM_FILTERS_BYTES);
    this.invalidate();
    await this.write(STORAGE.CUSTOM_FILTERS, this.customText, before);
  }

  /** True (and forgotten) when `newValue` is the echo of one of our own writes. */
  private isOwnEcho(key: string, newValue: unknown): boolean {
    const pending = this.own.get(key);
    if (!pending || pending.length === 0) return false;
    const i = pending.indexOf(canonicalJson(newValue));
    if (i === -1) return false;
    // Echoes arrive in write order: everything up to this one is settled.
    pending.splice(0, i + 1);
    return true;
  }

  /**
   * storage.onChanged for the local area: another trusted context (e.g. the
   * dashboard writing directly) changed our keys. Echoes of this instance's
   * own writes are ignored. Returns true when the in-memory state differs
   * afterwards.
   */
  applyLocalChange(changes: Record<string, chrome.storage.StorageChange>): boolean {
    let changed = false;
    const has = (key: string): boolean => key in changes && !this.isOwnEcho(key, changes[key]?.newValue);
    if (has(STORAGE.SETTINGS)) {
      const next = pruneUnknownLists(normalizeSettings(changes[STORAGE.SETTINGS].newValue), this.lists);
      if (canonicalJson(next) !== canonicalJson(this.user)) {
        this.user = next;
        changed = true;
      }
    }
    if (has(STORAGE.SITES)) {
      const next = sanitizeSites(changes[STORAGE.SITES].newValue);
      if (canonicalJson(next) !== canonicalJson(this.sites)) {
        this.sites = next;
        changed = true;
      }
    }
    if (has(STORAGE.CUSTOM_FILTERS)) {
      const v = changes[STORAGE.CUSTOM_FILTERS].newValue;
      const next = typeof v === 'string' ? v.slice(0, MAX_CUSTOM_FILTERS_BYTES) : '';
      if (next !== this.customText) {
        this.customText = next;
        changed = true;
      }
    }
    if (changed) this.invalidate();
    return changed;
  }
}
