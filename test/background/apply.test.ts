// Tests for applyAll (src/background/apply.ts) against in-memory chrome.*
// fakes: registrations are restored first after an update (SW-6), and the
// fleet kill switch (policy protectionEnabled: false) turns everything off
// and back on.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PRIORITY, RULE_ID } from '../../src/shared/constants.ts';
import type { BuildMeta, ManagedPolicy, SitesMap } from '../../src/shared/types.ts';
import type { DnrRule } from '../../src/compiler/types.ts';
import { createApplier } from '../../src/background/apply.ts';
import type { ActivityService } from '../../src/background/activity.ts';
import { EMPTY_COMPILED } from '../../src/background/custom.ts';
import type { CustomCompiled } from '../../src/background/custom.ts';
import { effectiveSettings, defaultSettings } from '../../src/background/settings.ts';
import { effectiveSites } from '../../src/background/sites.ts';
import { listInfos } from '../../src/background/store.ts';

type Level = 'controllable_by_this_extension' | 'controlled_by_this_extension';

interface Fake {
  calls: string[];
  enabledRulesets: string[];
  dynamic: DnrRule[];
  session: DnrRule[];
  scripts: Map<string, { id: string; matches?: string[]; js?: string[] }>;
  privacy: Map<string, { value: unknown; level: Level }>;
  js: { op: 'clear' | 'set'; pattern?: string; setting?: string }[];
}

const META = {
  builtAt: '2026-10-18T00:00:00Z',
  extensionVersion: '1.0.0',
  lists: [
    { id: 'easylist', default: true, bit: 0, rulesetIds: ['easylist'], ruleCount: 100, regexRuleCount: 0, name: { en: 'EasyList', de: 'EasyList' } },
    { id: 'annoyances', default: false, bit: 1, rulesetIds: ['annoyances'], ruleCount: 50, regexRuleCount: 0, name: { en: 'Annoyances', de: 'Ärgernisse' } },
  ],
  rulesetToList: { easylist: 'easylist', annoyances: 'annoyances' },
  redirectResources: {},
  vendor: { ublock: '', braveResources: '', braveLists: '' },
} as unknown as BuildMeta;

function installChrome(): Fake {
  const fake: Fake = { calls: [], enabledRulesets: [], dynamic: [], session: [], scripts: new Map(), privacy: new Map(), js: [] };
  const log = (name: string) => fake.calls.push(name);
  const session = new Map<string, unknown>();
  const privacySetting = (key: string, initial: unknown) => {
    fake.privacy.set(key, { value: initial, level: 'controllable_by_this_extension' });
    return {
      get: async () => {
        const s = fake.privacy.get(key)!;
        return { value: s.value, levelOfControl: s.level };
      },
      set: async ({ value }: { value: unknown }) => {
        log(`privacy.set ${key}`);
        fake.privacy.set(key, { value, level: 'controlled_by_this_extension' });
      },
      clear: async () => {
        log(`privacy.clear ${key}`);
        fake.privacy.set(key, { value: initial, level: 'controllable_by_this_extension' });
      },
    };
  };
  const update = (list: DnrRule[], u: { removeRuleIds?: number[]; addRules?: DnrRule[] }): DnrRule[] => {
    const out = list.filter((r) => !(u.removeRuleIds ?? []).includes(r.id as number));
    for (const r of u.addRules ?? []) {
      if (out.some((x) => x.id === r.id)) throw new Error(`Rule with id ${r.id} does not have a unique ID.`);
      out.push(structuredClone(r));
    }
    return out;
  };
  (globalThis as unknown as { chrome: unknown }).chrome = {
    runtime: {
      getManifest: () => ({ version: '1.0.0', declarative_net_request: { rule_resources: [{ id: 'easylist' }, { id: 'annoyances' }, { id: 'bastion-params' }] } }),
      getURL: (p: string) => `chrome-extension://test/${p}`,
    },
    storage: {
      session: {
        get: async (keys: string | string[]) => {
          const out: Record<string, unknown> = {};
          for (const k of Array.isArray(keys) ? keys : [keys]) if (session.has(k)) out[k] = structuredClone(session.get(k));
          return out;
        },
        set: async (items: Record<string, unknown>) => {
          for (const [k, v] of Object.entries(items)) session.set(k, structuredClone(v));
        },
      },
    },
    declarativeNetRequest: {
      getEnabledRulesets: async () => {
        log('dnr.getEnabledRulesets');
        return [...fake.enabledRulesets];
      },
      getAvailableStaticRuleCount: async () => 300_000,
      updateEnabledRulesets: async (u: { enableRulesetIds?: string[]; disableRulesetIds?: string[] }) => {
        log('dnr.updateEnabledRulesets');
        fake.enabledRulesets = fake.enabledRulesets.filter((id) => !(u.disableRulesetIds ?? []).includes(id));
        for (const id of u.enableRulesetIds ?? []) if (!fake.enabledRulesets.includes(id)) fake.enabledRulesets.push(id);
      },
      getDynamicRules: async () => structuredClone(fake.dynamic),
      updateDynamicRules: async (u: { removeRuleIds?: number[]; addRules?: DnrRule[] }) => {
        log('dnr.updateDynamicRules');
        fake.dynamic = update(fake.dynamic, u);
      },
      getSessionRules: async () => structuredClone(fake.session),
      updateSessionRules: async (u: { removeRuleIds?: number[]; addRules?: DnrRule[] }) => {
        log('dnr.updateSessionRules');
        fake.session = update(fake.session, u);
      },
      isRegexSupported: async () => ({ isSupported: true }),
      setExtensionActionOptions: async () => undefined,
    },
    scripting: {
      getRegisteredContentScripts: async () => {
        log('scripting.getRegisteredContentScripts');
        return Array.from(fake.scripts.values(), (s) => structuredClone(s));
      },
      registerContentScripts: async (list: { id: string }[]) => {
        log('scripting.registerContentScripts');
        for (const s of list) {
          if (fake.scripts.has(s.id)) throw new Error(`Duplicate script ID '${s.id}'`);
          fake.scripts.set(s.id, structuredClone(s));
        }
      },
      updateContentScripts: async (list: { id: string }[]) => {
        log('scripting.updateContentScripts');
        for (const s of list) fake.scripts.set(s.id, { ...fake.scripts.get(s.id), ...structuredClone(s) });
      },
      unregisterContentScripts: async (f: { ids?: string[] }) => {
        log('scripting.unregisterContentScripts');
        for (const id of f.ids ?? []) fake.scripts.delete(id);
      },
    },
    privacy: {
      websites: {
        hyperlinkAuditingEnabled: privacySetting('websites.hyperlinkAuditingEnabled', true),
        topicsEnabled: privacySetting('websites.topicsEnabled', true),
        thirdPartyCookiesAllowed: privacySetting('websites.thirdPartyCookiesAllowed', true),
      },
      network: { webRTCIPHandlingPolicy: privacySetting('network.webRTCIPHandlingPolicy', 'default') },
    },
    contentSettings: {
      javascript: {
        clear: async () => {
          fake.js.push({ op: 'clear' });
        },
        set: async (d: { primaryPattern: string; setting: string }) => {
          fake.js.push({ op: 'set', pattern: d.primaryPattern, setting: d.setting });
        },
      },
    },
    action: {
      setBadgeBackgroundColor: async () => undefined,
      setBadgeTextColor: async () => undefined,
      setBadgeText: async () => undefined,
    },
    tabs: { query: async () => [] },
  };
  // Package data files (cosmetic meta, scriptlet index, debounce list) are absent.
  (globalThis as unknown as { fetch: unknown }).fetch = async () => new Response('', { status: 404 });
  return fake;
}

function setup(policy: { managed: ManagedPolicy }, userSites: SitesMap, meta: BuildMeta | null = META) {
  let iconRefreshes = 0;
  const custom: CustomCompiled = { user: EMPTY_COMPILED, admin: EMPTY_COMPILED, my: [], cosmetic: { specific: [], generic: [] }, genericHideHosts: [] };
  const applier = createApplier(
    {
      settings: () => effectiveSettings(defaultSettings(), policy.managed, listInfos(meta)),
      sites: () => effectiveSites(userSites, policy.managed),
      meta: () => meta,
      custom: () => custom,
      seedFiles: async () => ['main/seeds/s0-0.js'],
      activity: { setBadgeMode: () => undefined } as unknown as ActivityService,
      invalidateCosmetic: () => undefined,
      syncListeners: () => undefined,
      globallyDisabled: () => policy.managed.protectionEnabled === false,
    },
    () => iconRefreshes++,
  );
  return { applier, icons: () => iconRefreshes };
}

const firstIndex = (calls: string[], prefix: string) => calls.findIndex((c) => c.startsWith(prefix));

test('after an update, content scripts are registered before any other step (SW-6)', async () => {
  const fake = installChrome();
  const { applier } = setup({ managed: {} }, {});
  await applier.now('update');
  const scripts = firstIndex(fake.calls, 'scripting.registerContentScripts');
  assert.ok(scripts >= 0, 'scripts registered');
  assert.ok(scripts < firstIndex(fake.calls, 'dnr.'), `registrations first: ${fake.calls.join(', ')}`);
  assert.ok(fake.scripts.has('bs-cosmetic'));
  assert.ok(Array.from(fake.scripts.keys()).some((id) => id.startsWith('bs-privacy')));
  assert.deepEqual(fake.enabledRulesets.sort(), ['bastion-params', 'easylist']);
  const ids = fake.dynamic.map((r) => r.id);
  assert.ok(ids.includes(RULE_ID.STANDARD_1P_ALLOW) && ids.includes(RULE_ID.GPC_HEADER));
  // A second run with nothing changed touches nothing.
  fake.calls.length = 0;
  await applier.now();
  assert.equal(fake.calls.filter((c) => /register|update|unregister|privacy\.(set|clear)/i.test(c) && c !== 'scripting.getRegisteredContentScripts').length, 0, fake.calls.join(', '));
});

test('fleet kill switch: global allow, no scripts, privacy released; full restore afterwards', async () => {
  const fake = installChrome();
  const policy: { managed: ManagedPolicy } = { managed: {} };
  const { applier, icons } = setup(policy, { 'x.ch': { enabled: false }, 'y.ch': { blockScripts: true } });
  await applier.now('startup');
  const iconsBefore = icons();
  const proceed: DnrRule = {
    id: RULE_ID.SESSION_PROCEED_START,
    priority: PRIORITY.PROCEED_ANYWAY,
    action: { type: 'allow' },
    condition: { requestDomains: ['evil.example'], tabIds: [3], resourceTypes: ['main_frame'] },
  };
  fake.session.push(proceed);
  assert.equal(fake.privacy.get('websites.hyperlinkAuditingEnabled')!.level, 'controlled_by_this_extension');
  assert.deepEqual(fake.js.filter((j) => j.op === 'set'), [{ op: 'set', pattern: '*://*.y.ch/*', setting: 'block' }]);
  const normalScripts = Array.from(fake.scripts.keys()).sort();
  assert.ok(normalScripts.length > 0);

  // The admin pulls the switch.
  policy.managed = { protectionEnabled: false };
  fake.js.length = 0;
  await applier.now();
  assert.deepEqual(fake.dynamic, [
    { id: RULE_ID.SITES_DISABLED, priority: PRIORITY.SITE_DISABLED, action: { type: 'allowAllRequests' }, condition: { resourceTypes: ['main_frame'] } },
  ]);
  assert.deepEqual(
    fake.session.sort((a, b) => (a.id as number) - (b.id as number)),
    [{ id: RULE_ID.SESSION_SITES_DISABLED_NO_TAB, priority: PRIORITY.SITE_DISABLED, action: { type: 'allow' }, condition: { tabIds: [-1] } }, proceed],
    'no-tab allow; proceed rules of live tabs are kept',
  );
  assert.equal(fake.scripts.size, 0, 'every registration removed');
  for (const [key, s] of fake.privacy) assert.equal(s.level, 'controllable_by_this_extension', `${key} released`);
  assert.deepEqual(fake.js, [{ op: 'clear' }], 'per-site script blocking released');
  assert.ok(fake.enabledRulesets.includes('easylist'), 'static rulesets stay (the allow outranks them)');
  assert.ok(icons() > iconsBefore, 'tab icons refreshed');

  // The policy flips back: everything is restored.
  policy.managed = {};
  await applier.now();
  assert.deepEqual(Array.from(fake.scripts.keys()).sort(), normalScripts);
  const off = fake.dynamic.find((r) => r.id === RULE_ID.SITES_DISABLED)!;
  assert.deepEqual(off.condition, { requestDomains: ['x.ch'], resourceTypes: ['main_frame'] });
  assert.ok(fake.dynamic.some((r) => r.id === RULE_ID.GPC_HEADER));
  assert.ok(fake.session.some((r) => r.id === RULE_ID.SESSION_SITES_DISABLED_NO_TAB && r.condition.initiatorDomains?.includes('x.ch')));
  assert.equal(fake.privacy.get('websites.hyperlinkAuditingEnabled')!.level, 'controlled_by_this_extension');
  assert.deepEqual(fake.js.filter((j) => j.op === 'set'), [{ op: 'set', pattern: '*://*.y.ch/*', setting: 'block' }]);
});

test('kill switch removes registrations even without build metadata', async () => {
  const fake = installChrome();
  fake.scripts.set('bs-cosmetic', { id: 'bs-cosmetic', matches: ['<all_urls>'] });
  fake.scripts.set('sl-main', { id: 'sl-main', matches: ['<all_urls>'] });
  const { applier } = setup({ managed: { protectionEnabled: false } }, {}, null);
  await applier.now();
  assert.equal(fake.scripts.size, 0);
  assert.equal(fake.dynamic.length, 1);
});
