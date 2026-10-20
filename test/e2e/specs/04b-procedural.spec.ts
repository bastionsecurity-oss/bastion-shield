// Bastion Shield e2e — procedural cosmetic filters end to end: every case of
// test/fixtures/procedural.html is installed as a user custom filter for the
// fixture host (custom:set), so this exercises the runtime compiler, the
// cosmetic:frame response, the cosmetic:procedural injection and the engine.
// The fixture evaluates its own expectations into window.__procResults.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { Page } from '@playwright/test';
import type { CustomState } from '../../../src/shared/types.ts';
import { expect, test } from '../support/fixtures.ts';
import { FIXTURES_DIR } from '../support/paths.ts';

const FIXTURE = path.join(FIXTURES_DIR, 'procedural.html');
const HOST = 'proc.example.com';

interface ProcCase {
  name: string;
  filter: string;
  scenario?: string;
}

interface ProcResults {
  pass: boolean;
  scenario: string;
  cases: Record<string, { pass: boolean; detail: string[] }>;
}

function readCases(): ProcCase[] {
  const html = readFileSync(FIXTURE, 'utf8');
  const m = /<script type="application\/json" id="procedural-cases">([\s\S]*?)<\/script>/.exec(html);
  if (!m) throw new Error('procedural.html has no #procedural-cases block');
  return JSON.parse(m[1]) as ProcCase[];
}

async function results(page: Page, scenario: string): Promise<ProcResults | null> {
  await page.goto(`https://${HOST}/procedural.html${scenario ? `?scenario=${scenario}` : ''}`);
  await page.waitForSelector('html[data-proc-done="1"]', { timeout: 10_000 }).catch(() => {});
  // The engine is throttled (rAF + 100 ms); give late mutations one more round, then re-check.
  await page.waitForTimeout(600);
  return page.evaluate(() => {
    const w = window as unknown as { __procCheck?: () => unknown };
    return (w.__procCheck ? w.__procCheck() : null) as never;
  });
}

test.describe('procedural cosmetic filters', () => {
  test.skip(!existsSync(FIXTURE), 'test/fixtures/procedural.html not present');

  test.afterEach(async ({ ext }) => {
    await ext.sendAndApply({ type: 'custom:set', text: '' }, 3000);
  });

  test('(g) every procedural operator in procedural.html works as a custom filter', async ({ page, ext }, testInfo) => {
    const cases = readCases();
    const scenarios = [...new Set(cases.map((c) => c.scenario ?? ''))];
    for (const scenario of scenarios) {
      // Scenario cases (":others()" hides most of the page) get their own filter set and load.
      const mine = cases.filter((c) => (c.scenario ?? '') === scenario);
      const text = mine.map((c) => HOST + c.filter).join('\n');
      const set = await ext.sendAndApply<{ error?: string }>({ type: 'custom:set', text });
      expect(set.response?.error, 'custom:set response').toBeUndefined();
      const state = await ext.send<CustomState & { error?: string }>({ type: 'custom:get' });
      await testInfo.attach(`custom-state-${scenario || 'default'}`, { body: JSON.stringify(state, null, 2), contentType: 'application/json' });
      expect.soft(state?.report?.errors ?? [], `all procedural custom filters compile (scenario "${scenario}")`).toEqual([]);

      const r = await results(page, scenario);
      await testInfo.attach(`results-${scenario || 'default'}`, { body: JSON.stringify(r, null, 2), contentType: 'application/json' });
      expect(r, `fixture produced results (scenario "${scenario}")`).not.toBeNull();
      const failed = Object.entries(r!.cases).filter(([, v]) => !v.pass);
      console.log(`[procedural${scenario ? ' ' + scenario : ''}] ${Object.keys(r!.cases).length - failed.length}/${Object.keys(r!.cases).length} cases pass`);
      for (const [name, v] of Object.entries(r!.cases)) {
        const filter = cases.find((c) => c.name === name)?.filter ?? '';
        expect.soft(v.detail, `${name}: ${HOST}${filter}`).toEqual([]);
      }
    }

    // Control: without the custom filters nothing on the page is touched.
    await ext.sendAndApply({ type: 'custom:set', text: '' });
    const ctl = await results(page, '');
    const hiddenWithout = Object.entries(ctl?.cases ?? {}).filter(([, v]) => v.pass).map(([k]) => k);
    // Cases whose expectation is only "visible" pass trivially; the others must fail without filters.
    expect.soft(hiddenWithout.length, `cases that "pass" without any filter: ${hiddenWithout.join(', ')}`).toBeLessThan(Object.keys(ctl?.cases ?? {}).length);
  });
});
