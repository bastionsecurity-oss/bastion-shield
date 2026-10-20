// Tests for runtime compilation of user and admin custom filters through the
// shared compiler (src/background/custom.ts).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { BuildMeta } from '../../src/shared/types.ts';
import { compileAllCustom, customReport } from '../../src/background/custom.ts';
import { planRules, DYNAMIC_BUDGET } from '../../src/background/rules.ts';
import { RULE_ID, PRIORITY } from '../../src/shared/constants.ts';

const META = { lists: [], rulesetToList: {}, redirectResources: { 'noop.js': '/war/noop.js' } } as unknown as BuildMeta;

test('user and admin filters compile into rules, cosmetic data and a report', () => {
  const user = ['||ads.example.com^', 'example.com##.banner', 'example.com##+js(set-constant, x, 1)', '@@||example.org^$generichide', '##.generic-ad', '$$$ $popup'].join('\n');
  const c = compileAllCustom(user, ['||admin-block.ch^', 'muster.ch##.cookie'], META);
  assert.equal(c.user.rules.length, 1);
  assert.equal(c.user.rules[0].priority, PRIORITY.BLOCK_ALWAYS);
  assert.equal(c.user.scriptletsIgnored, 1);
  assert.ok(c.user.errors.some((e) => e.line === 6));
  assert.equal(c.admin.rules.length, 1);
  assert.ok(c.cosmetic.specific.some((s) => s.payload === '.cookie'));
  assert.ok(c.cosmetic.specific.some((s) => s.payload === '.banner'));
  assert.ok(c.cosmetic.generic.some((g) => g.selector === '.generic-ad'));
  assert.deepEqual(c.genericHideHosts, ['example.org']);
  const report = customReport(c.user, [{ line: 0, text: '', reason: 'x' }]);
  assert.equal(report.network, 1);
  assert.equal(report.scriptletsIgnored, 1);
  assert.equal(report.errors.at(-1)!.reason, 'x');
});

test('empty input compiles to nothing and custom ids land in their ranges', () => {
  const c = compileAllCustom('', [], META);
  assert.deepEqual(c.user.rules, []);
  assert.deepEqual(c.admin.rules, []);
  const filled = compileAllCustom('||a.ch^$script\n||b.ch^$image', ['||c.ch^$xhr'], META);
  const plan = planRules(
    [
      { name: 'admin', rules: filled.admin.rules, idStart: RULE_ID.ADMIN_START, idEnd: RULE_ID.ADMIN_END },
      { name: 'user', rules: filled.user.rules, idStart: RULE_ID.CUSTOM_START, idEnd: RULE_ID.CUSTOM_END },
    ],
    DYNAMIC_BUDGET,
  );
  for (const r of plan.rules) {
    const id = r.id as number;
    assert.ok((id >= RULE_ID.ADMIN_START && id <= RULE_ID.ADMIN_END) || (id >= RULE_ID.CUSTOM_START && id <= RULE_ID.CUSTOM_END));
  }
});
