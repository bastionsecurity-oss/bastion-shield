// Unit tests for the UI side of the message contract (src/shared/types.ts
// "Response shapes" and EffectiveConfig.locked pseudo-paths) and for the
// labels of Bastion's grouped system rules. Runs with a minimal chrome.*
// stub: i18n returns the message key, runtime.sendMessage answers from a
// per-test table.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import test from 'node:test';
import assert from 'node:assert/strict';

type Reply = unknown | ((msg: { type: string }) => unknown);
const replies = new Map<string, Reply>();
const sent: { type: string }[] = [];

(globalThis as Record<string, unknown>).chrome = {
  i18n: { getMessage: (key: string) => key },
  runtime: {
    sendMessage: async (msg: { type: string }) => {
      sent.push(msg);
      const r = replies.get(msg.type);
      return typeof r === 'function' ? (r as (m: { type: string }) => unknown)(msg) : r;
    },
  },
};

const ROOT = new URL('../../src', import.meta.url).href;
const { RULE_ID } = await import(`${ROOT}/shared/constants.ts`);
const { dynamicRuleLabel } = await import(`${ROOT}/ui/shared/labels.ts`);
const store = await import(`${ROOT}/ui/dashboard/store.ts`);

const cfg = (locked: string[], managed: Record<string, unknown> = {}) => ({
  settings: { version: 1, defaultMode: 'standard', lists: {}, privacy: {}, ui: {}, history: {} },
  managed,
  locked,
});

test('system rule labels cover every slot the service worker numbers', () => {
  for (let n = 0; n < 10; n++) {
    assert.equal(dynamicRuleLabel('_dynamic', RULE_ID.SITES_DISABLED + n), 'ruleSiteOff', `SITES_DISABLED+${n}`);
    assert.equal(dynamicRuleLabel('_dynamic', RULE_ID.STANDARD_1P_ALLOW + n), 'ruleStandard1p', `STANDARD_1P_ALLOW+${n}`);
    assert.equal(dynamicRuleLabel('_session', RULE_ID.SESSION_SITES_DISABLED_NO_TAB + n), 'ruleSiteOff', `SESSION_NO_TAB+${n}`);
  }
  assert.equal(dynamicRuleLabel('_dynamic', RULE_ID.GPC_HEADER), 'ruleGpc');
  assert.equal(dynamicRuleLabel('_session', RULE_ID.SESSION_PROCEED_START + 7), 'ruleProceed');
  assert.equal(dynamicRuleLabel('_dynamic', RULE_ID.CUSTOM_START + 3), 'listCustom');
  assert.equal(dynamicRuleLabel('_dynamic', RULE_ID.ADMIN_START), 'listAdmin');
  assert.equal(dynamicRuleLabel('_dynamic', RULE_ID.DEBOUNCE_START + 1), 'ruleDebounce');
  assert.equal(dynamicRuleLabel('_dynamic', RULE_ID.GPC_HEADER + 1), 'ruleDynamic');
});

test('lock pseudo-paths: lists, sites.enabled, customFilters', () => {
  const managedAll = cfg(['customFilters', 'lists', 'lists.easylist', 'privacy.gpc'], { lockSettings: true });
  assert.equal(store.isLocked(managedAll, 'lists'), true);
  assert.equal(store.isLocked(managedAll, 'lists.easylist'), true);
  assert.equal(store.isLocked(managedAll, 'customFilters'), true);
  assert.equal(store.isLocked(managedAll, 'sites'), true, 'lockSettings locks the Sites view');
  assert.equal(store.isLocked(managedAll, 'ui.badge'), true, 'lockSettings locks every setting path');

  // lockSettings with lockLists: false keeps the lists editable: only the SW's locked list decides.
  const listsOpen = cfg(['privacy.gpc'], { lockSettings: true, lockLists: false });
  assert.equal(store.isLocked(listsOpen, 'lists'), false);
  assert.equal(store.isLocked(listsOpen, 'lists.easylist'), false);
  assert.equal(store.isLocked(listsOpen, 'sites.enabled'), false, 'protection switch follows allowUserSiteToggle');

  const plain = cfg(['sites.enabled']);
  assert.equal(store.isLocked(plain, 'sites.enabled'), true);
  assert.equal(store.isLocked(plain, 'privacy.gpc'), false);
  assert.equal(store.isLocked(null, 'privacy.gpc'), false);
});

test('ignored paths from settings:set / backup:import replies', () => {
  assert.deepEqual(store.ignoredPaths({ ignored: ['privacy.gpc', 3, null, 'lists.x'] }), ['privacy.gpc', 'lists.x']);
  assert.deepEqual(store.ignoredPaths({ settings: {} }), []);
  assert.deepEqual(store.ignoredPaths(null), []);
});

test('settings:set: ignored paths are reported and the config is adopted', async () => {
  replies.set('settings:set', { ...cfg(['privacy.gpc']), ignored: ['privacy.gpc'] });
  const r = await store.saveSettings({ privacy: { gpc: false } });
  assert.equal(r.ok, true);
  assert.deepEqual(r.data.ignored, ['privacy.gpc']);
  assert.deepEqual(r.data.config.locked, ['privacy.gpc']);
  assert.equal('ignored' in r.data.config, false, 'the cached config does not carry the reply-only field');
  const cached = await store.getConfig();
  assert.equal(cached.ok, true);
  assert.deepEqual(cached.data.locked, ['privacy.gpc']);

  replies.set('settings:set', { ...cfg([]), ignored: [] });
  const ok = await store.saveSettings({ privacy: { gpc: true } });
  assert.deepEqual(ok.data.ignored, []);
});

test('sites:get / sites:set use the { sites } shape and the stored map', async () => {
  replies.set('sites:get', { sites: { 'example.com': { enabled: false } } });
  const got = await store.getSites();
  assert.deepEqual(got, { ok: true, data: { 'example.com': { enabled: false } } });

  replies.set('sites:get', { sites: null });
  assert.deepEqual((await store.getSites()).data, {});

  // The SW may drop entries (no-op or policy-forced fields): the UI keeps what was stored.
  replies.set('sites:set', { sites: { 'a.ch': { mode: 'aggressive' } } });
  const set = await store.setSites({ 'a.ch': { mode: 'aggressive' }, 'b.ch': { enabled: true } });
  assert.deepEqual(set, { ok: true, data: { 'a.ch': { mode: 'aggressive' } } });

  replies.set('sites:set', { error: 'locked' });
  const locked = await store.setSites({});
  assert.deepEqual(locked, { ok: false, error: 'locked' });
});
