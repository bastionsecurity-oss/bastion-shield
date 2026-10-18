// Unit tests for the UI review fixes: popup state normalisation and the
// ?tabId override, system rules split out of the matched-rules panel,
// late list attribution on the live port, list filter counts, the managed
// support link and the bounce page's same-site refusal.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import test from 'node:test';
import assert from 'node:assert/strict';

const ROOT = new URL('../../src', import.meta.url).href;
const { normalisePopupState, tabIdFromSearch } = await import(`${ROOT}/ui/popup/state.ts`);
const { groupMatches } = await import(`${ROOT}/ui/popup/matched.ts`);
const { ListDirectory } = await import(`${ROOT}/ui/shared/labels.ts`);
const { applyAttributed } = await import(`${ROOT}/ui/shared/messaging.ts`);
const { safeSupportUrl } = await import(`${ROOT}/ui/shared/org.ts`);
const { listFilterCount } = await import(`${ROOT}/ui/dashboard/views/lists.ts`);
const { decodeBounceTarget, isSameSiteBounce, parseFromHost } = await import(`${ROOT}/pages/bounce-decode.ts`);
const { RULE_ID } = await import(`${ROOT}/shared/constants.ts`);

test('popup state: defaults for an older or partial reply', () => {
  const s = normalisePopupState({ tabId: 7, counts: { blocked: 3 } }, 1);
  assert.equal(s.tabId, 7);
  assert.deepEqual(s.counts, { blocked: 3, redirected: 0, stripped: 0, debounced: 0, thirdPartyHosts: 0 });
  assert.equal(s.logging, true);
  assert.equal(s.counting, true);
  assert.equal(s.globallyDisabled, false);
  assert.deepEqual(s.locks, { siteToggle: false, mode: false, settings: false });
  assert.equal(s.managed.reportBrokenSite, 'github');
  assert.equal(normalisePopupState(null, 5).tabId, 5);
});

test('popup state: log, counter, kill switch and mode lock flags are kept', () => {
  const s = normalisePopupState({ logging: false, counting: false, globallyDisabled: true, locks: { mode: true }, counts: { debounced: 2, blocked: -1 } }, 1);
  assert.equal(s.logging, false);
  assert.equal(s.counting, false);
  assert.equal(s.globallyDisabled, true);
  assert.equal(s.locks.mode, true);
  assert.equal(s.counts.debounced, 2);
  assert.equal(s.counts.blocked, 0, 'negative counts are dropped');
});

test('popup state: report channel defaults to e-mail when a helpdesk address is set', () => {
  assert.equal(normalisePopupState({ managed: { supportEmail: 'it@kunde.ch' } }, 1).managed.reportBrokenSite, 'email');
  assert.equal(normalisePopupState({ managed: { supportEmail: 'it@kunde.ch', reportBrokenSite: 'none' } }, 1).managed.reportBrokenSite, 'none');
  assert.equal(normalisePopupState({ managed: { reportBrokenSite: 'bogus' } }, 1).managed.reportBrokenSite, 'github');
});

test('popup ?tabId= override', () => {
  assert.equal(tabIdFromSearch('?tabId=42'), 42);
  assert.equal(tabIdFromSearch('?x=1&tabId=0'), 0);
  for (const bad of ['', '?tabId=', '?tabId=-1', '?tabId=4.2', '?tabId=abc', '?tabId=99999999999', '?tabid=3']) assert.equal(tabIdFromSearch(bad), null, bad);
});

test('matched rules: system rules are a separate, uncounted group', () => {
  const info = (rulesetId: string, ruleId: number) => ({ rule: { rulesetId, ruleId } });
  const infos = [
    ...Array.from({ length: 192 }, () => info('_dynamic', RULE_ID.GPC_HEADER)),
    ...Array.from({ length: 5 }, () => info('_dynamic', RULE_ID.STANDARD_1P_ALLOW)),
    info('_session', RULE_ID.SESSION_PROCEED_START + 3),
    info('easyprivacy', 1),
    info('easyprivacy', 1),
    info('easylist', 9),
    info('_dynamic', RULE_ID.CUSTOM_START + 4),
  ];
  const g = groupMatches(infos, new ListDirectory(null));
  assert.equal(g.total, 4, 'badge counts filter matches only');
  // Most hits first, then by name (labels are '' without chrome.i18n, so the custom group sorts first).
  assert.deepEqual(g.filters.map((x: { key: string }) => x.key), ['list:easyprivacy', 'dyn:', 'list:easylist']);
  assert.ok(g.system);
  assert.equal(g.system.total, 198);
  assert.equal(g.system.system, true);
  assert.equal(g.system.hits[0].ruleId, RULE_ID.GPC_HEADER, 'most frequent first');
  assert.equal(g.filters.some((x: { system?: boolean }) => x.system), false);
});

test('matched rules: protection off leaves only the system group', () => {
  const g = groupMatches([{ rule: { rulesetId: '_dynamic', ruleId: RULE_ID.SITES_DISABLED } }], new ListDirectory(null));
  assert.equal(g.filters.length, 0);
  assert.equal(g.total, 0);
  assert.equal(g.system?.total, 1);
  assert.equal(groupMatches([], new ListDirectory(null)).system, null);
});

test('live port: late attribution updates matching events only', () => {
  const ev = (t: number, tabId: number, url: string, kind = 'blocked') => ({ t, tabId, frameId: 0, kind, url, host: 'x', type: 'script', site: 's', thirdParty: true }) as Record<string, unknown>;
  const feed = [ev(1, 5, 'https://a/'), ev(2, 5, 'https://b/'), ev(2, 6, 'https://b/')];
  const pending = [ev(3, 5, 'https://c/', 'redirected')];
  const n = applyAttributed(
    [
      { t: 2, tabId: 5, url: 'https://b/', kind: 'blocked', list: 'easylist', rule: 'easylist:4' },
      { t: 3, tabId: 5, url: 'https://c/', kind: 'redirected', list: 'ublock' },
      { t: 9, tabId: 5, url: 'https://none/', kind: 'blocked', list: 'x' },
      { t: 1, tabId: 5, url: 'https://a/', kind: 'blocked', list: '' },
    ],
    feed,
    pending,
  );
  assert.equal(n, 2);
  assert.equal(feed[1].list, 'easylist');
  assert.equal(feed[1].rule, 'easylist:4');
  assert.equal(feed[2].list, undefined, 'other tab untouched');
  assert.equal(feed[0].list, undefined, 'empty list id ignored');
  assert.equal(pending[0].list, 'ublock');
  assert.equal(applyAttributed([], feed), 0);
  assert.equal(applyAttributed([{ t: 2, tabId: 5, url: 'https://b/', kind: 'blocked', list: 'easylist', rule: 'easylist:4' }], feed), 0, 'no-op when already attributed');
});

test('lists: headline shows source filters, not merged DNR rules', () => {
  // Peter Lowe: 3'486 host filters merged into 2 DNR rules; 83 badfiltered lines are not in effect.
  assert.equal(listFilterCount({ ruleCount: 2, stats: { filters: 3569, network: 3486, cosmetic: 0, scriptlets: 0, unsupported: 0, badfiltered: 83 } }), 3486);
  // Cookie notices: mostly cosmetic and scriptlet filters, unsupported lines left out.
  assert.equal(listFilterCount({ ruleCount: 1840, stats: { filters: 33478, network: 2175, cosmetic: 24094, scriptlets: 7168, unsupported: 39, badfiltered: 0 } }), 33437);
  assert.equal(listFilterCount({ ruleCount: 12 } as never), 12);
  assert.equal(listFilterCount({ ruleCount: 7, stats: { filters: 0 } } as never), 7);
});

test('managed support link: https only, no credentials', () => {
  assert.equal(safeSupportUrl('https://intranet.kunde.ch/it'), 'https://intranet.kunde.ch/it');
  for (const bad of [undefined, '', 'http://intranet.kunde.ch', 'javascript:alert(1)', 'https://u:p@kunde.ch/', 'not a url']) assert.equal(safeSupportUrl(bad), null, String(bad));
});

test('bounce: ?from= host parsing', () => {
  assert.equal(parseFromHost('?from=Click.Tracker.example'), 'click.tracker.example');
  assert.equal(parseFromHost('?from=https%3A%2F%2Fwww.tracker.example%2Fr'), 'www.tracker.example');
  assert.equal(parseFromHost('?from=b%C3%BCcher.ch'), 'xn--bcher-kva.ch');
  for (const bad of ['', '?x=1', '?from=', '?from=javascript%3Aalert(1)', `?from=${'a'.repeat(300)}.ch`]) assert.equal(parseFromHost(bad), null, bad.slice(0, 30));
});

test('bounce: same-site targets are not followed', () => {
  const target = decodeBounceTarget('https%3A%2F%2Fshop.digitec.ch%2Fp%2F1');
  assert.ok(target);
  assert.equal(isSameSiteBounce(target, 'click.digitec.ch'), true);
  assert.equal(isSameSiteBounce(target, 'digitec.ch'), true);
  assert.equal(isSameSiteBounce(target, 'www.digitec.ch'), true);
  assert.equal(isSameSiteBounce(target, 'tracker.example'), false);
  assert.equal(isSameSiteBounce(target, null), false, 'no from parameter: old behaviour');
  const uk = decodeBounceTarget('https://shop.example.co.uk/');
  assert.equal(isSameSiteBounce(uk, 'other.co.uk'), false, 'two-label public suffix is not one site');
  assert.equal(isSameSiteBounce(uk, 'go.example.co.uk'), true);
});
