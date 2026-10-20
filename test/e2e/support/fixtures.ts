// Bastion Shield e2e — Playwright fixtures. One fixture server and one
// Chromium profile with the extension per worker (the suite runs with a
// single worker, so tests share one installed extension, as a user would).
// Playwright restarts the worker after a failure, which gives the remaining
// tests a fresh install.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test as base, expect } from '@playwright/test';
import type { Page } from '@playwright/test';
import { Dist } from './dist.ts';
import { ExtensionHarness } from './extension.ts';
import type { StateSnapshot } from './extension.ts';
import { FixtureServer } from './server.ts';

export interface WorkerFixtures {
  server: FixtureServer;
  dist: Dist;
  ext: ExtensionHarness;
  /** DNR/scripting state right after the install-time applyAll(). */
  installState: { ready: boolean; snapshot: StateSnapshot; launchMs: number };
}

export interface TestFixtures {
  /** A fresh tab in the extension profile; closed after the test. */
  page: Page;
}

export const test = base.extend<TestFixtures, WorkerFixtures>({
  server: [
    async ({}, use) => {
      const server = await new FixtureServer().start();
      await use(server);
      await server.stop();
    },
    { scope: 'worker' },
  ],
  dist: [
    async ({}, use) => {
      await use(new Dist());
    },
    { scope: 'worker' },
  ],
  ext: [
    async ({ server }, use) => {
      const t0 = Date.now();
      const ext = await ExtensionHarness.launch({ port: server.port });
      (ext as unknown as { launchMs: number }).launchMs = Date.now() - t0;
      await use(ext);
      await ext.close();
    },
    { scope: 'worker', timeout: 60_000 },
  ],
  installState: [
    async ({ ext }, use) => {
      const launchMs = (ext as unknown as { launchMs: number }).launchMs ?? 0;
      const r = await ext.waitUntilReady(20_000);
      await use({ ...r, launchMs });
    },
    { scope: 'worker', timeout: 60_000 },
  ],
  page: async ({ ext, installState }, use) => {
    void installState; // every test starts from an applied install
    const page = await ext.context.newPage();
    await use(page);
    await page.close().catch(() => {});
  },
});

export { expect };
