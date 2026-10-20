// Tests for the persisted store (src/background/store.ts): echoes of the
// worker's own storage writes must not revert newer state (SW-3), and policy
// site locks cover subdomains (ENT-4). chrome.storage is faked in memory.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { STORAGE } from '../../src/shared/constants.ts';
import { Store, languageMatches, listInfos, storageChangePlan } from '../../src/background/store.ts';
import type { BuildMeta } from '../../src/shared/types.ts';

interface FakeStorage {
  local: Map<string, unknown>;
  managed: Record<string, unknown>;
  /** onChanged events produced by local writes, in order (not yet delivered). */
  echoes: Record<string, chrome.storage.StorageChange>[];
  failNextSet: boolean;
}

function installChrome(): FakeStorage {
  const fake: FakeStorage = { local: new Map(), managed: {}, echoes: [], failNextSet: false };
  const local = {
    get: async (keys: string[] | string) => {
      const out: Record<string, unknown> = {};
      for (const k of Array.isArray(keys) ? keys : [keys]) if (fake.local.has(k)) out[k] = structuredClone(fake.local.get(k));
      return out;
    },
    set: async (items: Record<string, unknown>) => {
      if (fake.failNextSet) {
        fake.failNextSet = false;
        throw new Error('QUOTA_BYTES quota exceeded');
      }
      const change: Record<string, chrome.storage.StorageChange> = {};
      for (const [k, v] of Object.entries(items)) {
        const oldValue = fake.local.get(k);
        // Like Chrome: no event for an unchanged value.
        if (JSON.stringify(oldValue) === JSON.stringify(v)) continue;
        fake.local.set(k, structuredClone(v));
        change[k] = { oldValue, newValue: structuredClone(v) };
      }
      if (Object.keys(change).length > 0) fake.echoes.push(change);
    },
  };
  (globalThis as unknown as { chrome: unknown }).chrome = {
    storage: { local, managed: { get: async () => structuredClone(fake.managed) } },
  };
  return fake;
}

test('own write echoes arriving late do not revert newer state (SW-3)', async () => {
  const fake = installChrome();
  const store = new Store();
  await store.load(null);
  await store.saveSites({ 'a.ch': { enabled: false } }); // write A
  await store.saveSites({ 'a.ch': { enabled: false }, 'b.ch': { enabled: false } }); // write B
  const [echoA, echoB] = fake.echoes.splice(0);
  // Echo A arrives after B was applied in memory: it must be ignored.
  assert.equal(store.applyLocalChange(echoA), false);
  assert.deepEqual(Object.keys(store.sites).sort(), ['a.ch', 'b.ch']);
  // Write C builds on B, not on a reverted A.
  await store.saveSites({ ...store.sites, 'c.ch': { mode: 'aggressive' } });
  assert.equal(store.applyLocalChange(echoB), false);
  assert.equal(store.applyLocalChange(fake.echoes.splice(0)[0]), false);
  assert.deepEqual(Object.keys(store.sites).sort(), ['a.ch', 'b.ch', 'c.ch']);
  assert.deepEqual(Object.keys(fake.local.get(STORAGE.SITES) as object).sort(), ['a.ch', 'b.ch', 'c.ch']);
});

test('writes by another trusted context are still applied', async () => {
  installChrome();
  const store = new Store();
  await store.load(null);
  await store.saveCustom('||ads.example^');
  const external = { [STORAGE.CUSTOM_FILTERS]: { oldValue: '||ads.example^', newValue: '||other.example^' } };
  assert.equal(store.applyLocalChange(external), true);
  assert.equal(store.customText, '||other.example^');
  const settings = { [STORAGE.SETTINGS]: { newValue: { ui: { activityLog: false } } } };
  assert.equal(store.applyLocalChange(settings), true);
  assert.equal(store.settings().ui.activityLog, false);
});

test('a failed write forgets its expected echo', async () => {
  const fake = installChrome();
  const store = new Store();
  await store.load(null);
  fake.failNextSet = true;
  await assert.rejects(store.saveCustom('x##.ad'));
  await store.saveCustom('z##.ad');
  fake.echoes.length = 0;
  // Another context now writes the value our failed write had: not our echo.
  const external = { [STORAGE.CUSTOM_FILTERS]: { oldValue: 'z##.ad', newValue: 'x##.ad' } };
  assert.equal(store.applyLocalChange(external), true);
  assert.equal(store.customText, 'x##.ad');
});

test('policy site locks cover subdomains; kill switch flag (ENT-4)', async () => {
  const fake = installChrome();
  fake.managed = { aggressiveSites: ['example.com'], disabledSites: ['crm.muster.ch'], protectionEnabled: false };
  const store = new Store();
  await store.load(null);
  assert.deepEqual(store.siteLocks('shop.example.com'), { enabled: false, mode: true });
  assert.deepEqual(store.siteLocks('example.com'), { enabled: false, mode: true });
  assert.deepEqual(store.siteLocks('portal.crm.muster.ch'), { enabled: true, mode: false });
  assert.deepEqual(store.siteLocks('example.org'), { enabled: false, mode: false });
  assert.equal(store.protectionOff(), true);
  // A user entry below the policy host cannot make it Standard.
  await store.saveSites({ 'shop.example.com': { mode: 'standard' } });
  assert.equal(store.effectiveSites()['shop.example.com'].mode, 'aggressive');
  // The policy flips back: reloadManaged reports the change.
  fake.managed = { aggressiveSites: ['example.com'], disabledSites: ['crm.muster.ch'] };
  assert.equal(await store.reloadManaged(), true);
  assert.equal(store.protectionOff(), false);
});

test('a change that wakes the worker is applied although memory already has it (SW-1)', async () => {
  const fake = installChrome();
  // The worker was stopped; another trusted context wrote new settings.
  fake.local.set(STORAGE.SETTINGS, { lists: { easylist: true }, privacy: { gpc: true } });
  const store = new Store();
  await store.load(null); // init() of the woken worker reads the NEW value
  const change = { [STORAGE.SETTINGS]: { newValue: { lists: { easylist: true }, privacy: { gpc: true } } } };
  const localChanged = store.applyLocalChange(change);
  assert.equal(localChanged, false, 'an in-memory diff cannot see it');
  assert.deepEqual(storageChangePlan('local', Object.keys(change), localChanged, true), { reloadManaged: false, recompileCustom: false, apply: 'schedule' });
  // A warm worker with no difference (e.g. an echo) does nothing.
  assert.deepEqual(storageChangePlan('local', Object.keys(change), false, false), { reloadManaged: false, recompileCustom: false, apply: null });
  // Keys that are not ours never trigger an apply, cold or not.
  assert.equal(storageChangePlan('local', [STORAGE.TOTALS, STORAGE.SEED_PICK], false, true).apply, null);
  // Custom filters are recompiled when they are applied.
  assert.deepEqual(storageChangePlan('local', [STORAGE.CUSTOM_FILTERS], false, true), { reloadManaged: false, recompileCustom: true, apply: 'schedule' });
  assert.deepEqual(storageChangePlan('local', [STORAGE.CUSTOM_FILTERS], true, false), { reloadManaged: false, recompileCustom: true, apply: 'schedule' });
  assert.equal(storageChangePlan('session', [STORAGE.SETTINGS], true, true).apply, null);
});

test('policy changes are always re-applied, also when they woke the worker (SW-1)', async () => {
  const fake = installChrome();
  fake.managed = { disabledSites: ['crm.example.ch'] };
  const store = new Store();
  await store.load(null);
  // The admin removes the site while the worker sleeps; init reads the new policy.
  fake.managed = {};
  await store.load(null);
  assert.equal(await store.reloadManaged(), false, 'nothing left to diff');
  for (const cold of [true, false]) {
    assert.deepEqual(storageChangePlan('managed', ['disabledSites'], false, cold), { reloadManaged: true, recompileCustom: true, apply: 'now' });
  }
});

test('regional lists default on by UI or preferred language (primary subtag)', () => {
  assert.equal(languageMatches(['fr'], ['de-CH', 'fr-CH', 'en']), true);
  assert.equal(languageMatches(['it'], ['de-CH', 'en-GB']), false);
  assert.equal(languageMatches(['de', 'gsw'], ['gsw']), true);
  assert.equal(languageMatches(undefined, ['fr']), false);
  assert.equal(languageMatches([], ['fr']), false);
  const meta = {
    lists: [
      { id: 'easylist', default: true },
      { id: 'regional-fr', default: false, langs: ['fr'] },
      { id: 'regional-it', default: false, langs: ['it'] },
    ],
  } as unknown as BuildMeta;
  const byId = (langs: string[]) => Object.fromEntries(listInfos(meta, langs).map((l) => [l.id, l.default]));
  assert.deepEqual(byId(['de-CH']), { easylist: true, 'regional-fr': false, 'regional-it': false });
  assert.deepEqual(byId(['de-CH', 'fr']), { easylist: true, 'regional-fr': true, 'regional-it': false });
  assert.deepEqual(byId(['it_CH']), { easylist: true, 'regional-fr': false, 'regional-it': true });
});
