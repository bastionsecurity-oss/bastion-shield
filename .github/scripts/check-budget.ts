// Fails CI when the default-enabled rulesets no longer fit Chromium's
// guaranteed static-rule budget or the static regex limit. Above the
// guarantee, rules come from a pool shared with other extensions and may be
// missing on customer machines without any visible error.
// Run after a build: node .github/scripts/check-budget.ts [dist]
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { LIMITS, RULESET_PARAMS } from '../../src/shared/constants.ts';
import type { BuildMeta } from '../../src/shared/types.ts';

const dist = process.argv[2] ?? 'dist';
// Keep some headroom for dynamic growth of the lists between two releases.
const HEADROOM = 500;

const metaPath = join(dist, 'rulesets', 'meta.json');
if (!existsSync(metaPath)) {
  console.error(`error: ${metaPath} not found; run the build first`);
  process.exit(1);
}
const meta = JSON.parse(readFileSync(metaPath, 'utf8')) as BuildMeta;

let plain = 0;
let regex = 0;
const rows: string[] = [];
for (const l of meta.lists) {
  if (!l.default) continue;
  plain += l.ruleCount;
  regex += l.regexRuleCount;
  rows.push(`  ${l.id.padEnd(20)} ${String(l.ruleCount).padStart(7)} ${String(l.regexRuleCount).padStart(6)}`);
}
const paramsPath = join(dist, 'rulesets', 'net', `${RULESET_PARAMS}.json`);
if (existsSync(paramsPath)) {
  const n = (JSON.parse(readFileSync(paramsPath, 'utf8')) as unknown[]).length;
  plain += n;
  rows.push(`  ${RULESET_PARAMS.padEnd(20)} ${String(n).padStart(7)} ${'0'.padStart(6)}`);
}

console.log('Default-enabled rulesets          rules  regex');
for (const r of rows) console.log(r);
console.log(`  ${'total'.padEnd(20)} ${String(plain).padStart(7)} ${String(regex).padStart(6)}`);

// Regex rules live in their own companion rulesets but count against the same
// static budget. (If BuiltList.ruleCount already includes them, this errs on
// the safe side.)
const total = plain + regex;
let failed = false;
const budget = LIMITS.GUARANTEED_STATIC_RULES;
if (total > budget) {
  console.error(`error: default rulesets need ${total} static rules, more than the guaranteed ${budget}`);
  failed = true;
} else if (total > budget - HEADROOM) {
  console.warn(`warning: only ${budget - total} rules left below the guaranteed ${budget}`);
}
if (regex > LIMITS.MAX_STATIC_REGEX_RULES) {
  console.error(`error: default rulesets need ${regex} regex rules, more than ${LIMITS.MAX_STATIC_REGEX_RULES}; Chromium would skip a ruleset`);
  failed = true;
}
if (process.env.GITHUB_STEP_SUMMARY) {
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### Rule budget\n\nDefault rulesets: **${total}** static rules (incl. regex) of ${budget} guaranteed, **${regex}** regex rules of ${LIMITS.MAX_STATIC_REGEX_RULES}.\n`);
}
process.exit(failed ? 1 : 0);
