// Tests for the settings model: defaults, validation, managed-policy overlay
// and locked paths (src/background/settings.ts).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  applySettingsPatch,
  buildEffectiveConfig,
  customFiltersLocked,
  defaultSettings,
  effectiveLists,
  listsFullyLocked,
  lockedPaths,
  normalizeSettings,
  pruneUnknownLists,
  sanitizeManaged,
  SETTING_PATHS,
} from '../../src/background/settings.ts';
import type { ListInfo } from '../../src/background/settings.ts';

const LISTS: ListInfo[] = [
  { id: 'bastion', default: true, locked: true },
  { id: 'easylist', default: true },
  { id: 'easyprivacy', default: true },
  { id: 'annoyances', default: false },
];

test('defaults match the documented values', () => {
  const d = defaultSettings();
  assert.equal(d.defaultMode, 'standard');
  assert.equal(d.privacy.gpc, true);
  assert.equal(d.privacy.stripParams, true);
  assert.equal(d.privacy.fingerprinting, 'standard');
  assert.equal(d.privacy.webrtcPolicy, 'default');
  assert.equal(d.privacy.blockThirdPartyCookies, null);
  assert.equal(d.ui.badge, true);
  assert.equal(d.history.retentionDays, 30);
});

test('normalizeSettings tolerates garbage and keeps valid fields', () => {
  assert.deepEqual(normalizeSettings(null), defaultSettings());
  assert.deepEqual(normalizeSettings('nope'), defaultSettings());
  const s = normalizeSettings({
    defaultMode: 'aggressive',
    lists: { easylist: false, 'BAD ID': true, annoyances: 'yes' },
    privacy: { gpc: false, fingerprinting: 'strict', webrtcPolicy: 'bogus', blockThirdPartyCookies: true },
    ui: { badge: 0 },
    history: { retentionDays: 99999.7 },
  });
  assert.equal(s.defaultMode, 'aggressive');
  assert.deepEqual(s.lists, { easylist: false });
  assert.equal(s.privacy.gpc, false);
  assert.equal(s.privacy.fingerprinting, 'strict');
  assert.equal(s.privacy.webrtcPolicy, 'default');
  assert.equal(s.privacy.blockThirdPartyCookies, true);
  assert.equal(s.ui.badge, true);
  assert.equal(s.history.retentionDays, 3650);
});

test('sanitizeManaged accepts registry-style values', () => {
  const m = sanitizeManaged({
    organizationName: '  Muster AG ',
    supportUrl: 'javascript:alert(1)',
    supportEmail: 'it@muster.ch',
    defaultMode: 'aggressive',
    lists: '{"annoyances": 1, "easylist": false}',
    disabledSites: '["intranet.muster.ch", "portal.muster.ch"]',
    aggressiveSites: 'a.ch, b.ch',
    customFilters: '||ads.example^\nexample.com##.ad',
    gpc: 0,
    lockSettings: 'true',
    historyRetentionDays: '14',
    reportBrokenSite: 'email',
    unknownKey: true,
  });
  assert.equal(m.organizationName, 'Muster AG');
  assert.equal(m.supportUrl, undefined);
  assert.equal(m.supportEmail, 'it@muster.ch');
  assert.equal(m.defaultMode, 'aggressive');
  assert.deepEqual(m.lists, { annoyances: true, easylist: false });
  assert.deepEqual(m.disabledSites, ['intranet.muster.ch', 'portal.muster.ch']);
  assert.deepEqual(m.aggressiveSites, ['a.ch', 'b.ch']);
  assert.deepEqual(m.customFilters, ['||ads.example^', 'example.com##.ad']);
  assert.equal(m.gpc, false);
  assert.equal(m.lockSettings, true);
  assert.equal(m.historyRetentionDays, 14);
  assert.equal(m.reportBrokenSite, 'email');
  assert.equal((m as Record<string, unknown>).unknownKey, undefined);
});

test('effective lists: policy > catalog lock > lockLists default > user > default', () => {
  const user = normalizeSettings({ lists: { easylist: false, annoyances: true, bastion: false } });
  assert.deepEqual(effectiveLists(LISTS, user, {}), { bastion: true, easylist: false, easyprivacy: true, annoyances: true });
  assert.deepEqual(effectiveLists(LISTS, user, { lockLists: true }), { bastion: true, easylist: true, easyprivacy: true, annoyances: false });
  assert.deepEqual(effectiveLists(LISTS, user, { lists: { bastion: false, easyprivacy: false } }), {
    bastion: false,
    easylist: false,
    easyprivacy: false,
    annoyances: true,
  });
});

test('policy overlays settings and reports locked paths', () => {
  const user = normalizeSettings({ privacy: { gpc: true, fingerprinting: 'off' }, ui: { badge: false } });
  const cfg = buildEffectiveConfig(user, { gpc: false, fingerprinting: 'strict', showBadge: true, historyRetentionDays: 7, lists: { annoyances: true } }, LISTS);
  assert.equal(cfg.settings.privacy.gpc, false);
  assert.equal(cfg.settings.privacy.fingerprinting, 'strict');
  assert.equal(cfg.settings.ui.badge, true);
  assert.equal(cfg.settings.history.retentionDays, 7);
  assert.equal(cfg.settings.lists.annoyances, true);
  for (const p of ['privacy.gpc', 'privacy.fingerprinting', 'ui.badge', 'history.retentionDays', 'lists.annoyances', 'lists.bastion']) {
    assert.ok(cfg.locked.includes(p), `expected ${p} to be locked`);
  }
  assert.ok(!cfg.locked.includes('defaultMode'));
  // The user's own value is untouched (policy removal restores it).
  assert.equal(user.privacy.gpc, true);
});

test('lockSettings, lockLists and the toggle switches lock everything they cover', () => {
  const locked = lockedPaths({ lockSettings: true, lockLists: true, allowUserSiteToggle: false, allowUserFilters: false }, LISTS);
  for (const p of SETTING_PATHS) assert.ok(locked.includes(p));
  for (const l of LISTS) assert.ok(locked.includes(`lists.${l.id}`));
  assert.ok(locked.includes('lists'));
  assert.ok(locked.includes('sites.enabled'));
  assert.ok(locked.includes('customFilters'));
});

test('applySettingsPatch skips locked and invalid values', () => {
  const user = defaultSettings();
  const locked = new Set(['privacy.gpc', 'lists.bastion']);
  const { settings, ignored } = applySettingsPatch(
    user,
    {
      defaultMode: 'aggressive',
      privacy: { gpc: false, deAmp: false, fingerprinting: 'nonsense', blockThirdPartyCookies: null },
      lists: { bastion: false, easylist: false },
      history: { retentionDays: -5 },
      ui: { activityLog: false },
    },
    locked,
  );
  assert.equal(settings.defaultMode, 'aggressive');
  assert.equal(settings.privacy.gpc, true);
  assert.equal(settings.privacy.deAmp, false);
  assert.equal(settings.privacy.fingerprinting, 'standard');
  assert.equal(settings.lists.bastion, undefined);
  assert.equal(settings.lists.easylist, false);
  assert.equal(settings.history.retentionDays, 0);
  assert.equal(settings.ui.activityLog, false);
  assert.deepEqual(ignored.sort(), ['lists.bastion', 'privacy.fingerprinting', 'privacy.gpc']);
  // Input object not mutated.
  assert.equal(user.defaultMode, 'standard');
});

test('lockLists blocks every list patch', () => {
  const { settings, ignored } = applySettingsPatch(defaultSettings(), { lists: { annoyances: true } }, new Set(['lists']));
  assert.equal(settings.lists.annoyances, undefined);
  assert.deepEqual(ignored, ['lists.annoyances']);
});

test('pruneUnknownLists drops removed catalog ids', () => {
  const s = normalizeSettings({ lists: { easylist: false, gone: true } });
  assert.deepEqual(pruneUnknownLists(s, LISTS).lists, { easylist: false });
  assert.deepEqual(pruneUnknownLists(s, []).lists, { easylist: false, gone: true });
});

test('lockSettings also locks every list and the user filters (ENT-2)', () => {
  const locked = lockedPaths({ lockSettings: true }, LISTS);
  assert.ok(locked.includes('lists'));
  for (const l of LISTS) assert.ok(locked.includes(`lists.${l.id}`));
  assert.ok(locked.includes('customFilters'));
  assert.ok(!locked.includes('sites.enabled'), 'the protection switch follows allowUserSiteToggle');
  assert.equal(listsFullyLocked({ lockSettings: true }), true);
  assert.equal(customFiltersLocked({ lockSettings: true }), true);
  // Explicit keys stay overrides.
  const open = lockedPaths({ lockSettings: true, lockLists: false, allowUserFilters: true }, LISTS);
  assert.ok(!open.includes('lists'));
  assert.ok(!open.includes('lists.easylist'));
  assert.ok(open.includes('lists.bastion'), 'catalog-locked list stays locked');
  assert.ok(!open.includes('customFilters'));
  assert.equal(listsFullyLocked({}), false);
  assert.equal(customFiltersLocked({ allowUserFilters: false }), true);
  // Effective lists follow the catalog defaults while locked, like lockLists.
  const user = normalizeSettings({ lists: { easylist: false, annoyances: true } });
  assert.deepEqual(effectiveLists(LISTS, user, { lockSettings: true }), { bastion: true, easylist: true, easyprivacy: true, annoyances: false });
  assert.deepEqual(effectiveLists(LISTS, user, { lockSettings: true, lockLists: false }), { bastion: true, easylist: false, easyprivacy: true, annoyances: true });
  // A patch that tries to switch the malware/ad lists off is refused.
  const { settings, ignored } = applySettingsPatch(user, { lists: { easylist: false, easyprivacy: false } }, new Set(locked));
  assert.deepEqual(ignored.sort(), ['lists.easylist', 'lists.easyprivacy']);
  assert.equal(settings.lists.easyprivacy, undefined);
});

test('policy host lists are normalised entry by entry; invalid entries dropped', () => {
  const m = sanitizeManaged({
    disabledSites: ['WWW.CRM.Example.CH', 'https://intranet.muster.ch/login', 'bücher.ch', 'not a host', '*.wild.ch', 'crm.example.ch', ''],
    aggressiveSites: 'News.Example.com,  ,exa mple.com',
  });
  assert.deepEqual(m.disabledSites, ['crm.example.ch', 'intranet.muster.ch', 'xn--bcher-kva.ch', 'wild.ch']);
  assert.deepEqual(m.aggressiveSites, ['news.example.com']);
});

test('policy numbers are clamped; empty registry strings ignored; kill switch parsed', () => {
  assert.equal(sanitizeManaged({ historyRetentionDays: -4 }).historyRetentionDays, 0);
  assert.equal(sanitizeManaged({ historyRetentionDays: 99_999 }).historyRetentionDays, 3650);
  assert.equal(sanitizeManaged({ historyRetentionDays: '12.9' }).historyRetentionDays, 12);
  assert.equal(sanitizeManaged({ historyRetentionDays: '' }).historyRetentionDays, undefined);
  assert.equal(sanitizeManaged({ historyRetentionDays: 'abc' }).historyRetentionDays, undefined);
  assert.equal(sanitizeManaged({ protectionEnabled: 0 }).protectionEnabled, false);
  assert.equal(sanitizeManaged({ protectionEnabled: 'true' }).protectionEnabled, true);
  assert.equal(sanitizeManaged({ protectionEnabled: 'maybe' }).protectionEnabled, undefined);
});
