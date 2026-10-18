// Bastion Shield service worker — install, update and browser start
// (ARCHITECTURE §9, §10). Updates reset the enabled static rulesets to the
// manifest defaults and clear every dynamically registered content script
// (persistAcrossSessions does not survive a version change; session rules
// do), so everything is re-applied, registrations first.
// The fingerprinting session seed is a fresh pick of one file per seed set on
// install and on every browser start, persisted so a service-worker restart
// keeps the same seed for the rest of the session.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { SEED_FILES_PER_SET, SEED_SETS, STORAGE } from '../shared/constants.ts';
import * as log from './log.ts';
import { sleep } from './util.ts';

export interface SeedPick {
  files: number[];
  at: number;
}

/** One random file index per seed set. */
export function pickSeeds(random: () => number = defaultRandom): SeedPick {
  const files: number[] = [];
  for (let s = 0; s < SEED_SETS; s++) files.push(Math.floor(random() * SEED_FILES_PER_SET) % SEED_FILES_PER_SET);
  return { files, at: Date.now() };
}

function defaultRandom(): number {
  try {
    const a = new Uint32Array(1);
    crypto.getRandomValues(a);
    return a[0] / 2 ** 32;
  } catch {
    return Math.random();
  }
}

export function seedFilePaths(pick: SeedPick): string[] {
  return pick.files.map((n, set) => `main/seeds/s${set}-${n}.js`);
}

export function validSeedPick(v: unknown): v is SeedPick {
  if (!v || typeof v !== 'object') return false;
  const p = v as SeedPick;
  return (
    Array.isArray(p.files) &&
    p.files.length === SEED_SETS &&
    p.files.every((n) => Number.isInteger(n) && n >= 0 && n < SEED_FILES_PER_SET)
  );
}

let cachedPick: SeedPick | null = null;

export async function currentSeedFiles(): Promise<string[]> {
  if (!cachedPick) {
    const got = await log.attempt('seeds', () => chrome.storage.local.get(STORAGE.SEED_PICK), {} as Record<string, unknown>);
    const v = got[STORAGE.SEED_PICK];
    if (validSeedPick(v)) cachedPick = v;
    else await renewSeeds();
  }
  return seedFilePaths(cachedPick as SeedPick);
}

export async function renewSeeds(): Promise<void> {
  cachedPick = pickSeeds();
  await log.attempt('seeds', () => chrome.storage.local.set({ [STORAGE.SEED_PICK]: cachedPick }));
}

export interface InstallInfo {
  installedAt: number;
  version: string;
  updatedAt?: number;
  previousVersion?: string;
}

export async function recordInstall(reason: string, previousVersion?: string): Promise<void> {
  const version = (() => {
    try {
      return chrome.runtime.getManifest().version;
    } catch {
      return '';
    }
  })();
  const got = await log.attempt('install', () => chrome.storage.local.get(STORAGE.INSTALL), {} as Record<string, unknown>);
  const prev = got[STORAGE.INSTALL] as InstallInfo | undefined;
  const now = Date.now();
  const info: InstallInfo =
    reason === 'install' || !prev || typeof prev.installedAt !== 'number'
      ? { installedAt: now, version }
      : { ...prev, version, updatedAt: now, previousVersion: previousVersion ?? prev.version };
  await log.attempt('install', () => chrome.storage.local.set({ [STORAGE.INSTALL]: info }));
}

/**
 * Managed deployments stay silent: no welcome page when the policy names an
 * organization or the extension was force-installed by policy. Policy values
 * can take a moment to arrive on first launch, so we look twice.
 */
export async function shouldShowWelcome(readOrganization: () => Promise<string | undefined>): Promise<boolean> {
  try {
    const self = await chrome.management?.getSelf?.();
    if (self && self.installType === 'admin') return false;
  } catch {
    /* management.getSelf needs no permission, but be defensive */
  }
  if (await readOrganization()) return false;
  await sleep(1500);
  return !(await readOrganization());
}

export async function openWelcome(): Promise<void> {
  await log.attempt('install', () => chrome.tabs.create({ url: chrome.runtime.getURL('ui/dashboard.html#welcome') }));
}

/** Session rules from an earlier session would be stale after install. */
export async function clearSessionRules(): Promise<void> {
  const current = await log.attempt('install', () => chrome.declarativeNetRequest.getSessionRules(), [] as chrome.declarativeNetRequest.Rule[]);
  if (current.length === 0) return;
  await log.attempt('install', () => chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: current.map((r) => r.id) }));
}
