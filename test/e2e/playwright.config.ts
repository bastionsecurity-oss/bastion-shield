// Bastion Shield — Playwright configuration for the end-to-end suite.
//
//   npx playwright test -c test/e2e/playwright.config.ts
//
// Runs Playwright's bundled Chromium (channel "chromium", new headless mode,
// which supports extensions) with the unpacked build from dist/ (override with
// BASTION_DIST). HEADED=1 shows the browser. One worker on purpose: all specs
// share one installed extension, and settings changes must not race.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import path from 'node:path';
import { defineConfig } from '@playwright/test';
import { REPO_ROOT } from './support/paths.ts';

export default defineConfig({
  testDir: path.join(REPO_ROOT, 'test', 'e2e', 'specs'),
  testMatch: /.*\.spec\.ts$/,
  globalSetup: path.join(REPO_ROOT, 'test', 'e2e', 'support', 'global-setup.ts'),
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 120_000,
  expect: { timeout: 10_000 },
  outputDir: path.join(REPO_ROOT, 'test-results', 'e2e'),
  reporter: [
    ['list'],
    ['json', { outputFile: path.join(REPO_ROOT, 'test-results', 'e2e-report.json') }],
    ['html', { outputFolder: path.join(REPO_ROOT, 'playwright-report'), open: 'never' }],
  ],
  use: {
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
});
