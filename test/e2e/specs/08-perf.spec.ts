// Bastion Shield e2e — (n) page-load cost of the extension on a heavy fixture
// page: 10 loads with the extension vs 10 in a plain Chromium profile. This is
// a report with a generous sanity bound, not a micro-benchmark; the real-world
// comparison lives in test/bench/run.ts.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import type { Page } from '@playwright/test';
import { expect, test } from '../support/fixtures.ts';
import { ExtensionHarness } from '../support/extension.ts';
import { HOSTS } from '../support/hosts.ts';
import { REPO_ROOT } from '../support/paths.ts';

const RUNS = Number(process.env.BASTION_PERF_RUNS || 10);

interface Timing {
  dcl: number;
  load: number;
  requests: number;
  heapUsed: number | null;
}

async function measure(page: Page, url: string): Promise<Timing> {
  let requests = 0;
  // Redirect hops (e.g. to a neutered extension resource) are one request, not two.
  const onReq = (r: import('@playwright/test').Request) => {
    if (!r.redirectedFrom()) requests++;
  };
  page.on('request', onReq);
  await page.goto(url, { waitUntil: 'load', timeout: 30_000 });
  page.off('request', onReq);
  const t = await page.evaluate(() => {
    const nav = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
    const mem = (performance as unknown as { memory?: { usedJSHeapSize: number } }).memory;
    return { dcl: nav ? nav.domContentLoadedEventEnd : -1, load: nav ? nav.loadEventEnd : -1, heapUsed: mem ? mem.usedJSHeapSize : null };
  });
  return { ...t, requests };
}

function stats(xs: number[]) {
  const s = [...xs].sort((a, b) => a - b);
  const median = s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
  const mean = s.reduce((a, b) => a + b, 0) / (s.length || 1);
  return { min: Math.round(s[0]), median: Math.round(median), mean: Math.round(mean), max: Math.round(s[s.length - 1]) };
}

test.describe('performance', () => {
  test.setTimeout(240_000);

  test('(n) heavy page: load timings with and without the extension', async ({ page, server }, testInfo) => {
    const url = server.url(HOSTS.A, '/heavy.html');
    // Warm-up loads (first SW wake-up, shard fetches, disk cache of the browser binary).
    await measure(page, url);
    const withExt: Timing[] = [];
    for (let i = 0; i < RUNS; i++) withExt.push(await measure(page, url));

    const plain = await ExtensionHarness.launch({ port: server.port, extension: false });
    let without: Timing[] = [];
    try {
      const p = await plain.context.newPage();
      await measure(p, url);
      for (let i = 0; i < RUNS; i++) without.push(await measure(p, url));
    } finally {
      await plain.close();
    }

    const report = {
      runs: RUNS,
      url,
      withExtension: { dcl: stats(withExt.map((x) => x.dcl)), load: stats(withExt.map((x) => x.load)), requests: stats(withExt.map((x) => x.requests)) },
      withoutExtension: { dcl: stats(without.map((x) => x.dcl)), load: stats(without.map((x) => x.load)), requests: stats(without.map((x) => x.requests)) },
      raw: { withExt, without },
    };
    await testInfo.attach('perf', { body: JSON.stringify(report, null, 2), contentType: 'application/json' });
    try {
      const out = path.join(REPO_ROOT, 'test-results', 'e2e-perf.json');
      mkdirSync(path.dirname(out), { recursive: true });
      writeFileSync(out, JSON.stringify({ at: new Date().toISOString(), ...report }, null, 2));
    } catch {
      /* report attachment is enough */
    }
    console.log(
      `[perf] heavy.html x${RUNS}  DCL median ext=${report.withExtension.dcl.median}ms plain=${report.withoutExtension.dcl.median}ms | ` +
        `load median ext=${report.withExtension.load.median}ms plain=${report.withoutExtension.load.median}ms | ` +
        `requests ext=${report.withExtension.requests.median} plain=${report.withoutExtension.requests.median}`,
    );
    expect(withExt.every((x) => x.load > 0), 'every load completed').toBe(true);
    // Sanity bound only: blocking should never make a page dramatically slower.
    const bound = Math.max(report.withoutExtension.load.median * 3, report.withoutExtension.load.median + 1500);
    expect(report.withExtension.load.median, `median load with extension within sanity bound (${bound} ms)`).toBeLessThanOrEqual(bound);
    expect(report.withExtension.requests.median, 'the extension removes requests, it does not add any').toBeLessThanOrEqual(report.withoutExtension.requests.median);
  });
});
