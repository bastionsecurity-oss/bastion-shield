// Rule minimization (ARCHITECTURE §4.4 "Merging") on hand-made drafts.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { finalizeRule, minimizeRules } from '../../src/compiler/merge.ts';
import type { RuleDraft } from '../../src/compiler/merge.ts';
import type { DnrRule } from '../../src/compiler/types.ts';

const draft = (rule: DnrRule, source = JSON.stringify(rule.condition)): RuleDraft => ({ rule, sources: [source], count: 1 });
const block = (condition: DnrRule['condition'], priority = 10): DnrRule => ({ priority, action: { type: 'block' }, condition });

test('removeParams of otherwise identical rules merge', () => {
  const rp = (p: string): DnrRule => ({
    priority: 1,
    action: { type: 'redirect', redirect: { transform: { queryTransform: { removeParams: [p] } } } },
    condition: { requestDomains: ['shop.example'], resourceTypes: ['main_frame'] },
  });
  const out = minimizeRules([draft(rp('utm_source')), draft(rp('fbclid')), draft(rp('utm_source'))]);
  assert.equal(out.length, 1);
  assert.deepEqual(out[0].rule.action.redirect?.transform?.queryTransform?.removeParams, ['fbclid', 'utm_source']);
  assert.equal(out[0].count, 3);
});

test('responseHeaders of identical conditions merge into one modifyHeaders rule', () => {
  const csp = (v: string): DnrRule => ({
    priority: 1,
    action: { type: 'modifyHeaders', responseHeaders: [{ header: 'content-security-policy', operation: 'append', value: v }] },
    condition: { requestDomains: ['a.example'], resourceTypes: ['main_frame', 'sub_frame'] },
  });
  const out = minimizeRules([draft(csp("worker-src 'none'")), draft(csp("script-src 'self'"))]);
  assert.equal(out.length, 1);
  assert.equal(out[0].rule.action.responseHeaders?.length, 2);
});

test('different priorities or actions never merge', () => {
  const out = minimizeRules([
    draft(block({ requestDomains: ['a.example'] }, 10)),
    draft(block({ requestDomains: ['b.example'] }, 21)),
    draft({ priority: 10, action: { type: 'allow' }, condition: { requestDomains: ['c.example'] } }),
  ]);
  assert.equal(out.length, 3);
});

test('requestDomains merge, then identical-but-types rules merge', () => {
  const out = minimizeRules([
    draft(block({ requestDomains: ['a.example'], resourceTypes: ['script', 'image'] })),
    draft(block({ requestDomains: ['b.example'], resourceTypes: ['script'] })),
    draft(block({ requestDomains: ['b.example'], resourceTypes: ['image'] })),
  ]);
  assert.deepEqual(out.map((d) => d.rule.condition), [{ requestDomains: ['a.example', 'b.example'], resourceTypes: ['image', 'script'] }]);
});

test('every non-document type collapses to typeless', () => {
  const all = ['sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest', 'ping', 'csp_report', 'media', 'websocket', 'webtransport', 'webbundle', 'other'];
  const out = minimizeRules([draft(block({ urlFilter: '/ads/', resourceTypes: all }))]);
  assert.deepEqual(out[0].rule.condition, { urlFilter: '/ads/' });
});

test('finalizeRule prunes subdomains and dead exclusions', () => {
  assert.deepEqual(
    finalizeRule(block({ initiatorDomains: ['a.example', 'x.a.example', 'b.example'], excludedInitiatorDomains: ['y.a.example', 'z.other'] }))?.condition,
    { initiatorDomains: ['a.example', 'b.example'], excludedInitiatorDomains: ['y.a.example'] },
  );
  assert.equal(finalizeRule(block({ requestDomains: ['x.a.example'], excludedRequestDomains: ['a.example'] })), null);
});

test('arrays are sorted and deduplicated', () => {
  const out = minimizeRules([draft(block({ urlFilter: '/x', initiatorDomains: ['b.example', 'a.example', 'b.example'] }))]);
  assert.deepEqual(out[0].rule.condition.initiatorDomains, ['a.example', 'b.example']);
});
