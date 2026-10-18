// Bastion Shield service worker — lazy access to the build output shipped in
// the package (dist/*). Files are fetched on first use and cached for the
// lifetime of the service worker; nothing is loaded at startup unless needed.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BuildMeta, CosmeticMeta, CosmeticShard, ScriptletIndex } from '../shared/types.ts';
import { genericLookupFromText, type GenericLookup } from './cosmetic.ts';
import * as log from './log.ts';
import { packagePath } from './registrations.ts';

export const PATHS = {
  BUILD_META: 'rulesets/meta.json',
  COSMETIC_META: 'cosmetic/meta.json',
  GENERIC: 'cosmetic/generic.json',
  GENERIC_HIGH_DEFAULT: 'cosmetic/generic-high.json',
  SCRIPTLET_INDEX: 'scriptlets/index.json',
  DEBOUNCE: 'data/debounce.json',
  SHARD_DIR: 'cosmetic/specific/',
} as const;

async function fetchOk(path: string): Promise<Response | null> {
  const res = await fetch(chrome.runtime.getURL(packagePath(path)));
  if (res.ok) return res;
  // Missing optional files (e.g. a shard with no hosts) are normal.
  if (res.status !== 404) log.warn('data', path, res.status);
  return null;
}

async function fetchJson<T>(path: string): Promise<T | null> {
  try {
    const res = await fetchOk(path);
    return res ? ((await res.json()) as T) : null;
  } catch (e) {
    log.warn('data', path, e);
    return null;
  }
}

async function fetchText(path: string): Promise<string | null> {
  try {
    const res = await fetchOk(path);
    return res ? await res.text() : null;
  } catch (e) {
    log.warn('data', path, e);
    return null;
  }
}

/** Memoize a loader; failures are not cached so a later call can retry. */
function lazy<T>(load: () => Promise<T | null>): { get(): Promise<T | null>; clear(): void } {
  let p: Promise<T | null> | null = null;
  return {
    get() {
      if (!p) {
        p = load().then((v) => {
          if (v === null) p = null;
          return v;
        });
      }
      return p;
    },
    clear() {
      p = null;
    },
  };
}

function validBuildMeta(v: BuildMeta | null): BuildMeta | null {
  if (!v || !Array.isArray(v.lists)) return null;
  if (!v.rulesetToList || typeof v.rulesetToList !== 'object') v.rulesetToList = {};
  if (!v.redirectResources || typeof v.redirectResources !== 'object') v.redirectResources = {};
  v.lists = v.lists.filter((l) => l && typeof l.id === 'string');
  return v;
}

const buildMeta = lazy(async () => validBuildMeta(await fetchJson<BuildMeta>(PATHS.BUILD_META)));
const cosmeticMeta = lazy(async () => {
  const m = await fetchJson<CosmeticMeta>(PATHS.COSMETIC_META);
  if (!m) return null;
  if (!m.genericHighCss || typeof m.genericHighCss !== 'object') m.genericHighCss = {};
  if (!m.genericHighExcludedHosts || typeof m.genericHighExcludedHosts !== 'object') m.genericHighExcludedHosts = {};
  if (!Array.isArray(m.genericHideHosts)) m.genericHideHosts = [];
  return m;
});
// Kept as text and searched in place (review PERF-5): parsing the 2 MB index
// cost 17-23 ms after every worker start for a few hundred lookups per page.
const genericIndex = lazy(async () => {
  const text = await fetchText(PATHS.GENERIC);
  return text === null ? null : genericLookupFromText(text);
});
let genericHighPath: string | null = null;
const genericHigh = lazy(() => fetchJson<Record<string, string[]>>(genericHighPath ?? PATHS.GENERIC_HIGH_DEFAULT));

export function loadBuildMeta(): Promise<BuildMeta | null> {
  return buildMeta.get();
}

export function loadCosmeticMeta(): Promise<CosmeticMeta | null> {
  return cosmeticMeta.get();
}

export function loadGenericIndex(): Promise<GenericLookup | null> {
  return genericIndex.get();
}

export function loadGenericHigh(meta: CosmeticMeta): Promise<Record<string, string[]> | null> {
  const p = typeof meta.genericHighSelectorsFile === 'string' && meta.genericHighSelectorsFile !== '' ? meta.genericHighSelectorsFile : PATHS.GENERIC_HIGH_DEFAULT;
  if (genericHighPath !== p) {
    genericHighPath = p;
    genericHigh.clear();
  }
  return genericHigh.get();
}

export async function loadShard(name: string): Promise<CosmeticShard | null> {
  const s = await fetchJson<CosmeticShard>(`${PATHS.SHARD_DIR}${name}.json`);
  return s && s.hosts && typeof s.hosts === 'object' ? s : null;
}

/** Read once per applyAll; small enough not to need caching across runs. */
export async function loadScriptletIndex(): Promise<ScriptletIndex | null> {
  const idx = await fetchJson<ScriptletIndex>(PATHS.SCRIPTLET_INDEX);
  if (!idx || typeof idx !== 'object' || !Array.isArray(idx.registrations)) return null;
  if (!Array.isArray(idx.bundles)) idx.bundles = [];
  if (!Array.isArray(idx.merged)) idx.merged = [];
  return idx;
}

export function loadDebounceList(): Promise<unknown> {
  return fetchJson<unknown>(PATHS.DEBOUNCE);
}
