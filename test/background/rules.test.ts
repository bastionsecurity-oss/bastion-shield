// Tests for dynamic/session rule generation, budgeting and diffing
// (src/background/rules.ts) and static ruleset planning (rulesets.ts).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PRIORITY, RULE_ID, RULESET_PARAMS } from '../../src/shared/constants.ts';
import type { BuildMeta, BuiltList } from '../../src/shared/types.ts';
import type { DnrRule } from '../../src/compiler/types.ts';
import { effectiveSites, resolveSite } from '../../src/background/sites.ts';
import {
  adaptRuleToBrowser,
  buildGlobalOffRules,
  buildGpcRule,
  buildProceedRule,
  buildSitesDisabledRules,
  buildStandardModeRules,
  buildSystemDynamicRules,
  diffRules,
  isSystemAllowRuleId,
  planRules,
} from '../../src/background/rules.ts';
import { countRules, LIST_ERROR, planRulesets, wantedRulesets } from '../../src/background/rulesets.ts';
import { defaultSettings, normalizeSettings } from '../../src/background/settings.ts';
import { ruleIdFromError, badgeModeFor } from '../../src/background/apply.ts';

test('no sites: no site rules', () => {
  assert.deepEqual(buildSitesDisabledRules({}), { dynamic: [], session: [] });
});

test('disabled sites: allowAllRequests on the top document only + tabId -1 session allow', () => {
  const { dynamic, session } = buildSitesDisabledRules({ 'example.com': { enabled: false }, 'b.ch': { enabled: false }, 'c.ch': { mode: 'aggressive' } });
  assert.equal(dynamic.length, 1);
  // main_frame only: the disabled site's embeds on other sites stay filtered (BS-3).
  assert.deepEqual(dynamic[0], {
    id: RULE_ID.SITES_DISABLED,
    priority: PRIORITY.SITE_DISABLED,
    action: { type: 'allowAllRequests' },
    condition: { requestDomains: ['b.ch', 'example.com'], resourceTypes: ['main_frame'] },
  });
  assert.deepEqual(session[0], {
    id: RULE_ID.SESSION_SITES_DISABLED_NO_TAB,
    priority: PRIORITY.SITE_DISABLED,
    action: { type: 'allow' },
    condition: { tabIds: [-1], initiatorDomains: ['b.ch', 'example.com'] },
  });
});

test('re-enabled subdomain is excluded; re-disabled below it gets its own rule', () => {
  const { dynamic, session } = buildSitesDisabledRules({
    'example.com': { enabled: false },
    'shop.example.com': { enabled: true },
    'cart.shop.example.com': { enabled: false },
    '[::1]': { enabled: false },
  });
  assert.equal(dynamic.length, 2);
  assert.deepEqual(dynamic[0].condition.requestDomains, ['example.com']);
  assert.deepEqual(dynamic[0].condition.excludedRequestDomains, ['shop.example.com']);
  assert.deepEqual(dynamic[1].condition.requestDomains, ['cart.shop.example.com']);
  assert.equal(dynamic[1].id, RULE_ID.SITES_DISABLED + 1);
  assert.deepEqual(session[0].condition.excludedInitiatorDomains, ['shop.example.com']);
  // IPv6 literals cannot be DNR domains and are left out instead of breaking the update.
  assert.ok(!JSON.stringify(dynamic).includes('::1'));
});

test('Standard default: one 1p allow excluding aggressive sites (+topDomains when supported)', () => {
  const sites = { 'a.ch': { mode: 'aggressive' as const }, 'b.ch': { mode: 'standard' as const } };
  const withTop = buildStandardModeRules(sites, 'standard', true);
  assert.deepEqual(withTop, [
    {
      id: RULE_ID.STANDARD_1P_ALLOW,
      priority: PRIORITY.STANDARD_1P_ALLOW,
      action: { type: 'allow' },
      condition: { domainType: 'firstParty', excludedResourceTypes: ['main_frame'], excludedInitiatorDomains: ['a.ch'], excludedTopDomains: ['a.ch'] },
    },
  ]);
  const noTop = buildStandardModeRules(sites, 'standard', false);
  assert.equal(noTop[0].condition.excludedTopDomains, undefined);
  assert.deepEqual(buildStandardModeRules({}, 'standard', true)[0].condition, { domainType: 'firstParty', excludedResourceTypes: ['main_frame'] });
});

test('Aggressive default: rule only for Standard sites, omitted when none', () => {
  assert.deepEqual(buildStandardModeRules({}, 'aggressive', true), []);
  const rules = buildStandardModeRules({ 'nzz.ch': { mode: 'standard' }, 'x.nzz.ch': { mode: 'aggressive' } }, 'aggressive', false);
  assert.equal(rules.length, 1);
  assert.deepEqual(rules[0].condition.initiatorDomains, ['nzz.ch']);
  assert.deepEqual(rules[0].condition.excludedInitiatorDomains, ['x.nzz.ch']);
});

test('GPC header rule applies everywhere at its priority', () => {
  const r = buildGpcRule(['main_frame', 'script']);
  assert.equal(r.id, RULE_ID.GPC_HEADER);
  assert.equal(r.priority, PRIORITY.GPC_HEADER);
  assert.deepEqual(r.action.requestHeaders, [{ header: 'Sec-GPC', operation: 'set', value: '1' }]);
  assert.deepEqual(r.condition.resourceTypes, ['main_frame', 'script']);
  assert.ok(buildGpcRule([]).condition.resourceTypes!.includes('main_frame'));
});

test('system rules follow settings (GPC off, modes, sites)', () => {
  const s = normalizeSettings({ privacy: { gpc: false } });
  const { dynamic, session } = buildSystemDynamicRules(s, { 'x.ch': { enabled: false } }, { topDomainsSupported: false, resourceTypes: [] });
  assert.ok(!dynamic.some((r) => r.id === RULE_ID.GPC_HEADER));
  assert.ok(dynamic.some((r) => r.id === RULE_ID.SITES_DISABLED));
  assert.ok(dynamic.some((r) => r.id === RULE_ID.STANDARD_1P_ALLOW));
  assert.equal(session.length, 1);
  const on = buildSystemDynamicRules(defaultSettings(), {}, { topDomainsSupported: false, resourceTypes: ['main_frame'] });
  assert.ok(on.dynamic.some((r) => r.id === RULE_ID.GPC_HEADER));
});

test('proceed rule: allow requests TO the host in that tab, every type incl. main_frame', () => {
  assert.deepEqual(buildProceedRule(RULE_ID.SESSION_PROCEED_START, 'evil.example', 7, ['main_frame', 'script', 'image']), {
    id: RULE_ID.SESSION_PROCEED_START,
    priority: PRIORITY.PROCEED_ANYWAY,
    action: { type: 'allow' },
    condition: { requestDomains: ['evil.example'], tabIds: [7], resourceTypes: ['main_frame', 'script', 'image'] },
  });
  // Not allowAllRequests: other hosts on the page stay filtered.
  const fallback = buildProceedRule(RULE_ID.SESSION_PROCEED_START, 'evil.example', 7);
  assert.equal(fallback.action.type, 'allow');
  assert.ok(fallback.condition.resourceTypes!.includes('main_frame'));
  assert.ok(fallback.condition.resourceTypes!.includes('sub_frame'));
  // main_frame is never missing (a rule without it would not lift the strict block).
  assert.deepEqual(buildProceedRule(1, 'x.ch', 1, ['script']).condition.resourceTypes, ['main_frame', 'script']);
});

test('fleet kill switch: one global allowAllRequests + no-tab allow replace every system rule', () => {
  const off = buildGlobalOffRules();
  assert.deepEqual(off.dynamic, [
    { id: RULE_ID.SITES_DISABLED, priority: PRIORITY.SITE_DISABLED, action: { type: 'allowAllRequests' }, condition: { resourceTypes: ['main_frame'] } },
  ]);
  assert.deepEqual(off.session, [{ id: RULE_ID.SESSION_SITES_DISABLED_NO_TAB, priority: PRIORITY.SITE_DISABLED, action: { type: 'allow' }, condition: { tabIds: [-1] } }]);
  const sys = buildSystemDynamicRules(defaultSettings(), { 'x.ch': { enabled: false } }, { topDomainsSupported: true, resourceTypes: [], globallyDisabled: true });
  assert.deepEqual(sys, off, 'no GPC, Standard-mode or per-site rules while off');
});

test('aggressiveSites covers subdomains: a user Standard mode below it gets no 1p allow (ENT-4)', () => {
  const user = { 'shop.example.com': { mode: 'standard' as const } };
  const sites = effectiveSites(user, { aggressiveSites: ['example.com'] });
  assert.equal(resolveSite('shop.example.com', sites, defaultSettings()).mode, 'aggressive');
  const rules = buildStandardModeRules(sites, 'standard', true);
  assert.equal(rules.length, 1, 'only the root Standard group');
  assert.equal(rules[0].condition.initiatorDomains, undefined);
  assert.deepEqual(rules[0].condition.excludedInitiatorDomains, ['example.com']);
  assert.ok(!JSON.stringify(rules).includes('"initiatorDomains":["shop.example.com"]'));
});

test('adaptRuleToBrowser drops topDomains rules and strips excludedTopDomains', () => {
  const top: DnrRule = { action: { type: 'block' }, condition: { topDomains: ['a.ch'] } };
  const ex: DnrRule = { action: { type: 'block' }, condition: { urlFilter: 'x', excludedTopDomains: ['a.ch'] } };
  assert.equal(adaptRuleToBrowser(top, false), null);
  assert.deepEqual(adaptRuleToBrowser(ex, false)!.condition, { urlFilter: 'x' });
  assert.equal(adaptRuleToBrowser(top, true), top);
});

test('planRules assigns ids per range and enforces budgets in source order', () => {
  const block = (u: string): DnrRule => ({ priority: 21, action: { type: 'block' }, condition: { urlFilter: u } });
  const redirect = (u: string): DnrRule => ({ priority: 35, action: { type: 'redirect', redirect: { regexSubstitution: 'x#\\1' } }, condition: { regexFilter: u } });
  const plan = planRules(
    [
      { name: 'system', rules: [{ id: RULE_ID.GPC_HEADER, action: { type: 'modifyHeaders' }, condition: {} }] },
      { name: 'admin', rules: [block('a'), block('b')], idStart: RULE_ID.ADMIN_START, idEnd: RULE_ID.ADMIN_END },
      { name: 'debounce', rules: [redirect('r1'), redirect('r2'), redirect('r3')], idStart: RULE_ID.DEBOUNCE_START, idEnd: RULE_ID.DEBOUNCE_END },
      { name: 'user', rules: [block('u1'), block('u2'), block('u3')], idStart: 1, idEnd: 2 },
    ],
    { maxRules: 100, maxUnsafe: 3, maxRegex: 1000 },
  );
  const ids = plan.rules.map((r) => r.id);
  assert.deepEqual(ids, [RULE_ID.GPC_HEADER, RULE_ID.ADMIN_START, RULE_ID.ADMIN_START + 1, RULE_ID.DEBOUNCE_START, RULE_ID.DEBOUNCE_START + 1, 1, 2]);
  assert.deepEqual(plan.dropped, [
    { source: 'debounce', count: 1, reason: 'redirect/modifyHeaders rule limit' },
    { source: 'user', count: 1, reason: 'id range exhausted' },
  ]);
  const rx = planRules([{ name: 'user', rules: [redirect('a'), redirect('b')], idStart: 1 }], { maxRules: 10, maxUnsafe: 10, maxRegex: 1000 }, 999);
  assert.equal(rx.rules.length, 1);
  assert.equal(rx.dropped[0].reason, 'regex rule limit');
});

test('diffRules is minimal and order-insensitive for domain lists', () => {
  const a: DnrRule = { id: 1, priority: 1, action: { type: 'block' }, condition: { requestDomains: ['b.ch', 'a.ch'] } };
  const b: DnrRule = { id: 2, priority: 1, action: { type: 'block' }, condition: { urlFilter: 'x' } };
  const echoed = [{ ...a, condition: { requestDomains: ['a.ch', 'b.ch'], isUrlFilterCaseSensitive: false } }, b];
  assert.deepEqual(diffRules(echoed as DnrRule[], [a, b]), { removeRuleIds: [], addRules: [] });
  const changed: DnrRule = { ...b, condition: { urlFilter: 'y' } };
  const c: DnrRule = { id: 3, priority: 1, action: { type: 'block' }, condition: { urlFilter: 'z' } };
  assert.deepEqual(diffRules([a, b], [changed, c]), { removeRuleIds: [1, 2], addRules: [changed, c] });
});

test('system allow rule ids are recognised for attribution', () => {
  assert.equal(isSystemAllowRuleId('_dynamic', RULE_ID.GPC_HEADER), true);
  assert.equal(isSystemAllowRuleId('_dynamic', RULE_ID.SITES_DISABLED), true);
  assert.equal(isSystemAllowRuleId('_dynamic', 5), false);
  assert.equal(isSystemAllowRuleId('_session', RULE_ID.SESSION_PROCEED_START + 3), true);
  assert.equal(isSystemAllowRuleId('easylist', RULE_ID.GPC_HEADER), false);
});

test('ruleIdFromError and badge mode', () => {
  assert.equal(ruleIdFromError('Rule with id 1000004 specifies an incorrect value for the "condition.regexFilter" key.'), 1000004);
  assert.equal(ruleIdFromError('Internal error'), null);
  assert.equal(badgeModeFor(defaultSettings()), 'self');
  assert.equal(badgeModeFor(normalizeSettings({ privacy: { gpc: false } })), 'browser');
  assert.equal(badgeModeFor(normalizeSettings({ ui: { badge: false } })), 'off');
});

// --- static rulesets -------------------------------------------------------

function list(id: string, ruleCount: number, regexRuleCount = 0, extra: Partial<BuiltList> = {}): BuiltList {
  return {
    id,
    name: { en: id, de: id },
    description: { en: '', de: '' },
    category: 'ads',
    default: true,
    firstPartyProtected: true,
    trusted: false,
    strictBlock: false,
    homepage: '',
    license: '',
    attribution: '',
    bit: 0,
    sources: [],
    rulesetIds: regexRuleCount > 0 ? [id, `${id}.regex`] : [id],
    ruleCount,
    regexRuleCount,
    stats: { filters: 0, network: 0, cosmetic: 0, scriptlets: 0, unsupported: 0, badfiltered: 0 },
    ...extra,
  };
}

const META: BuildMeta = {
  builtAt: '',
  extensionVersion: '1',
  lists: [list('bastion', 10), list('ublock', 6000, 600), list('easylist', 4000, 500), list('regional-de', 2000)],
  rulesetToList: {},
  redirectResources: {},
  vendor: { ublock: '', braveResources: '', braveLists: '' },
};
const ORDER = ['bastion', 'ublock', 'easylist', 'regional-de', RULESET_PARAMS, 'ublock.regex', 'easylist.regex'];

test('wantedRulesets follows settings and manifest order', () => {
  const s = normalizeSettings({ lists: { bastion: true, ublock: true, easylist: true, 'regional-de': false } });
  const { candidates, missing } = wantedRulesets(META, s, ORDER);
  assert.deepEqual(
    candidates.map((c) => c.rulesetId),
    ['bastion', 'ublock', 'easylist', RULESET_PARAMS, 'ublock.regex', 'easylist.regex'],
  );
  assert.deepEqual(missing, {});
  const off = normalizeSettings({ lists: { bastion: true }, privacy: { stripParams: false } });
  assert.deepEqual(
    wantedRulesets(META, off, ORDER).candidates.map((c) => c.rulesetId),
    ['bastion'],
  );
  const notDeclared = wantedRulesets(META, s, ['bastion']);
  assert.equal(notDeclared.missing.ublock, LIST_ERROR.MISSING);
});

test('planRulesets skips only the regex companion when the regex budget overflows', () => {
  const s = normalizeSettings({ lists: { bastion: true, ublock: true, easylist: true, 'regional-de': true } });
  const { candidates } = wantedRulesets(META, s, ORDER);
  const plan = planRulesets(candidates, 1_000_000);
  assert.ok(plan.enabled.includes('easylist'));
  assert.ok(plan.enabled.includes('ublock.regex'));
  assert.ok(!plan.enabled.includes('easylist.regex'));
  assert.equal(plan.errors.easylist, LIST_ERROR.REGEX_LIMIT);
  assert.equal(plan.usedRegex, 600);
});

test('planRulesets drops the least important lists when the rule budget is short', () => {
  const s = normalizeSettings({ lists: { bastion: true, ublock: true, easylist: true, 'regional-de': true } });
  const { candidates } = wantedRulesets(META, s, ORDER);
  const plan = planRulesets(candidates, 10_100);
  assert.deepEqual(plan.enabled, ['bastion', 'ublock', 'easylist', RULESET_PARAMS]);
  assert.equal(plan.errors['regional-de'], LIST_ERROR.RULE_LIMIT);
  // Companions of lists that fit still need room.
  assert.equal(plan.errors.ublock, LIST_ERROR.RULE_LIMIT);
  assert.equal(countRules(META, plan.enabled).rules, 10_010);
  const capped = planRulesets(candidates, 1_000_000, 1000, 2);
  assert.deepEqual(capped.enabled, ['bastion', 'ublock']);
  assert.equal(capped.errors.easylist, LIST_ERROR.RULESET_LIMIT);
});
