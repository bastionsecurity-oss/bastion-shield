// Real filter lists: compile every list found in $BASTION_TEST_LISTS (or the
// build cache .cache/lists) and check that each emitted rule is one Chromium
// accepts, that the cosmetic and scriptlet data is well formed, and that the
// compiler is fast enough. Skipped when no lists are available (CI without
// network).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { collectBadfilters, compileList } from '../../src/compiler/index.ts';
import type { ProceduralFilter } from '../../src/shared/types.ts';
import { opts, ruleProblems } from './helpers.ts';

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..', '..');
const dir = process.env.BASTION_TEST_LISTS ?? path.join(repoRoot, '.cache', 'lists');
const files = fs.existsSync(dir)
  ? fs.readdirSync(dir).filter((f) => !/\.(?:json|md|etag)$/i.test(f) && fs.statSync(path.join(dir, f)).isFile() && fs.statSync(path.join(dir, f)).size > 0)
  : [];

test('real lists available', { skip: files.length === 0 ? `no lists in ${dir} (set BASTION_TEST_LISTS)` : false }, () => {
  assert.ok(files.length > 0);
});

const texts = new Map(files.map((f) => [f, fs.readFileSync(path.join(dir, f), 'utf8')]));
const badfilters = files.length === 0 ? new Set<string>() : collectBadfilters([...texts.values()]);

const unquoted = (css: string): string => css.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g, '');

function checkProcedural(pf: ProceduralFilter, where: string): void {
  assert.equal(typeof pf.raw, 'string', where);
  assert.equal(typeof pf.selector, 'string', where);
  assert.ok(Array.isArray(pf.tasks), where);
  for (const t of pf.tasks) {
    assert.equal(typeof t[0], 'string', where);
    if (t[0] === 'has' || t[0] === 'not' || t[0] === 'if' || t[0] === 'if-not') checkProcedural(t[1] as ProceduralFilter, where);
  }
}

for (const file of files) {
  test(`compiles ${file}`, () => {
    const text = texts.get(file) as string;
    const format = /hosts/i.test(file) ? 'hosts' : 'abp';
    const t0 = performance.now();
    const out = compileList(text, opts({ listId: file.replace(/\W+/g, '-'), trusted: true, strictBlock: true, badfilters, format }));
    const ms = performance.now() - t0;
    // ~85k-line EasyList must compile in well under 3 s; scale the budget by size.
    assert.ok(ms < 3000 * Math.max(1, text.length / 2_500_000), `${file} took ${Math.round(ms)} ms`);
    for (const { rule, sources, sourceCount } of [...out.rules, ...out.regexRules]) {
      assert.deepEqual(ruleProblems(rule), [], `${file}: ${JSON.stringify(rule).slice(0, 300)}`);
      assert.ok(sources.length >= 1 && sources.length <= 20 && sourceCount >= sources.length);
    }
    for (const r of out.regexRules) assert.ok(r.rule.condition.regexFilter !== undefined);
    for (const r of out.rules) assert.equal(r.rule.condition.regexFilter, undefined);
    for (const s of out.specific) {
      assert.ok(s.hosts.length > 0, `${file}: ${s.raw}`);
      for (const h of s.hosts) assert.match(h, /^(?:[a-z0-9_-]+\.)*(?:[a-z0-9_-]+|\*)$|^\[[0-9a-f:.]+\]$/, `${file}: ${s.raw}`);
      if (s.kind === 2) checkProcedural(JSON.parse(s.payload) as ProceduralFilter, s.raw);
      if (s.kind === 3) assert.match(s.payload, /^.+ \{ .+ \}$/s, s.raw);
      // Braces may only appear inside quoted strings (or in style rule text).
      if (s.kind === 0 || s.kind === 5) assert.ok(!/[{}]/.test(unquoted(s.payload)), `${file}: ${s.raw}`);
    }
    for (const g of out.generic) {
      assert.ok(g.token === null || /^[#.]./.test(g.token), g.raw);
      assert.ok(!/[{}]/.test(unquoted(g.selector)), g.raw);
    }
    for (const s of out.scriptlets) {
      assert.ok(s.hosts.length > 0, s.raw);
      assert.ok(s.exception || s.name !== '', s.raw);
    }
    const st = out.stats;
    assert.ok(st.network + st.cosmetic + st.scriptlets + st.unsupported + st.badfiltered <= st.filters, JSON.stringify(st.reasons));
  });
}
