// Bastion Shield — dashboard data access. Caches the service-worker answers
// that several views share (effective config, list state, build meta) and
// normalises response shapes, so views stay small and the SW is asked once.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type {
  ActivityEvent,
  BuildMeta,
  CustomState,
  DeepPartial,
  EffectiveConfig,
  ListsState,
  Settings,
  SitesMap,
} from '../../shared/types.ts';
import { call, fetchPackaged, type Result } from '../shared/messaging.ts';
import { ListDirectory } from '../shared/labels.ts';

let configP: Promise<Result<EffectiveConfig>> | null = null;
let listsP: Promise<Result<ListsState>> | null = null;
let metaP: Promise<BuildMeta | null> | null = null;
let directory: ListDirectory = new ListDirectory(null);

const listeners = new Set<() => void>();

/** Views that show global status (nav header) subscribe to config/list changes. */
export function onStoreChange(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}
function emit(): void {
  for (const fn of listeners) {
    try {
      fn();
    } catch (err) {
      console.error('[bastion] store listener failed', err);
    }
  }
}

function isConfig(x: unknown): x is EffectiveConfig {
  return !!x && typeof x === 'object' && 'settings' in x && typeof (x as EffectiveConfig).settings === 'object';
}
function isListsState(x: unknown): x is ListsState {
  return !!x && typeof x === 'object' && 'enabled' in x && typeof (x as ListsState).enabled === 'object';
}

export function getConfig(force = false): Promise<Result<EffectiveConfig>> {
  if (!configP || force) {
    configP = call<EffectiveConfig>({ type: 'config:get' }).then((r) => {
      if (r.ok && !isConfig(r.data)) return { ok: false, error: 'bad-response' } as const;
      if (r.ok) {
        r.data.locked ??= [];
        r.data.managed ??= {};
      }
      if (r.ok && (!r.data.settings.privacy || !r.data.settings.ui || !r.data.settings.history)) return { ok: false, error: 'bad-response' } as const;
      return r;
    });
    void configP.then(() => emit());
  }
  return configP;
}

export function getLists(force = false): Promise<Result<ListsState>> {
  if (!listsP || force) {
    listsP = call<ListsState>({ type: 'lists:get' }).then((r) => {
      if (r.ok && !isListsState(r.data)) return { ok: false, error: 'bad-response' } as const;
      if (r.ok) {
        r.data.locked ??= [];
        r.data.errors ??= {};
        r.data.budget ??= { used: 0, available: null, regexUsed: 0 };
        if (r.data.meta) directory = new ListDirectory(r.data.meta);
      }
      return r;
    });
    void listsP.then(() => emit());
  }
  return listsP;
}

/** Build meta: prefer the copy inside ListsState, fall back to the packaged file. */
export function getMeta(): Promise<BuildMeta | null> {
  if (!metaP) {
    metaP = getLists().then(async (r) => (r.ok && r.data.meta ? r.data.meta : await fetchPackaged<BuildMeta>('rulesets/meta.json')));
    void metaP.then((m) => {
      if (m && !directory.meta) directory = new ListDirectory(m);
    });
  }
  return metaP;
}

export function dir(): ListDirectory {
  return directory;
}

/**
 * True when a dotted settings path (or a lock pseudo-path: 'lists',
 * 'sites.enabled', 'customFilters') is locked by policy. The service worker
 * lists the exact paths in EffectiveConfig.locked; lockSettings additionally
 * locks the bare dashboard sections ('sites') and every setting path. Lists
 * and the per-site protection switch follow their own locked paths, because
 * the policy may leave them editable (lockLists: false, allowUserSiteToggle).
 */
export function isLocked(cfg: EffectiveConfig | null, path: string): boolean {
  if (!cfg) return false;
  if (cfg.locked.includes(path)) return true;
  return !!cfg.managed.lockSettings && path !== 'lists' && !path.startsWith('lists.') && !path.startsWith('sites.');
}

/** Paths the service worker refused (locked or invalid), from an `{ ignored }` reply. */
export function ignoredPaths(reply: unknown): string[] {
  const v = reply && typeof reply === 'object' ? (reply as { ignored?: unknown }).ignored : undefined;
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

/** EffectiveConfig from a settings:set / backup:import reply (EffectiveConfig & { ignored }). */
function configOf(reply: unknown): EffectiveConfig | null {
  if (!isConfig(reply)) return null;
  const { settings, managed, locked } = reply;
  if (!settings.privacy || !settings.ui || !settings.history) return null;
  return { settings, managed: managed ?? {}, locked: Array.isArray(locked) ? locked : [] };
}

/** Adopt the configuration a write returned, so every view sees the new state. */
export function adoptConfig(reply: unknown): EffectiveConfig | null {
  const cfg = configOf(reply);
  if (cfg) {
    configP = Promise.resolve({ ok: true, data: cfg });
    emit();
  }
  return cfg;
}

export interface SaveSettingsResult {
  config: EffectiveConfig | null;
  /** Paths of the patch the service worker did not apply (locked by policy or invalid). */
  ignored: string[];
}

export async function saveSettings(patch: DeepPartial<Settings>): Promise<Result<SaveSettingsResult>> {
  const r = await call<unknown>({ type: 'settings:set', patch });
  if (!r.ok) return r;
  const ignored = ignoredPaths(r.data);
  const cfg = adoptConfig(r.data);
  if (cfg) return { ok: true, data: { config: cfg, ignored } };
  const fresh = await getConfig(true);
  return { ok: true, data: { config: fresh.ok ? fresh.data : null, ignored } };
}

export async function setList(listId: string, enabled: boolean): Promise<Result<ListsState | null>> {
  const r = await call<unknown>({ type: 'lists:set', listId, enabled });
  if (!r.ok) return r;
  if (isListsState(r.data)) {
    listsP = Promise.resolve({ ok: true, data: r.data });
    emit();
    return { ok: true, data: r.data };
  }
  const fresh = await getLists(true);
  return fresh.ok ? fresh : { ok: true, data: null };
}

/** `{ sites }` reply of sites:get / sites:set (the user's own map), or null. */
function sitesOf(reply: unknown): SitesMap | null {
  const d = reply && typeof reply === 'object' ? (reply as { sites?: unknown }).sites : undefined;
  return d && typeof d === 'object' && !Array.isArray(d) ? { ...(d as SitesMap) } : null;
}

/** The user's own per-site map. Policy sites come from EffectiveConfig.managed. */
export async function getSites(): Promise<Result<SitesMap>> {
  const r = await call<unknown>({ type: 'sites:get' });
  if (!r.ok) return r;
  return { ok: true, data: sitesOf(r.data) ?? {} };
}

/** Save the user's map; resolves to the map the service worker actually stored. */
export async function setSites(sites: SitesMap): Promise<Result<SitesMap>> {
  const r = await call<unknown>({ type: 'sites:set', sites });
  if (!r.ok) return r;
  return { ok: true, data: sitesOf(r.data) ?? { ...sites } };
}

export async function getCustom(): Promise<Result<CustomState>> {
  return call<CustomState>({ type: 'custom:get' });
}

export async function setCustom(text: string): Promise<Result<CustomState>> {
  const r = await call<unknown>({ type: 'custom:set', text });
  if (!r.ok) return r;
  const d = r.data as Partial<CustomState> | null;
  if (d && typeof d === 'object' && d.report) return { ok: true, data: d as CustomState };
  return getCustom();
}

export async function historyEvents(limit: number, before?: number, site?: string, host?: string): Promise<Result<ActivityEvent[]>> {
  const r = await call<unknown>({ type: 'history:events', limit, before, site: site || undefined, host: host || undefined });
  if (!r.ok) return r;
  const d = r.data as { events?: ActivityEvent[] } | ActivityEvent[] | null;
  const events = Array.isArray(d) ? d : Array.isArray(d?.events) ? d.events : [];
  return { ok: true, data: events };
}
