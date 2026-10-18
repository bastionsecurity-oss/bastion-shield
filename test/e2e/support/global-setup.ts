// Bastion Shield e2e — fail fast with an actionable message when there is no
// build to test, instead of 30 identical "service worker never started" errors.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { DIST_DIR } from './paths.ts';

export default function globalSetup(): void {
  const manifest = path.join(DIST_DIR, 'manifest.json');
  if (!existsSync(manifest)) {
    throw new Error(`No build at ${DIST_DIR} (manifest.json missing). Run "npm run build" first, or set BASTION_DIST.`);
  }
  try {
    const m = JSON.parse(readFileSync(manifest, 'utf8')) as { manifest_version?: number; version?: string };
    if (m.manifest_version !== 3) throw new Error(`manifest_version is ${m.manifest_version}, expected 3`);
    console.log(`[e2e] testing ${DIST_DIR} (version ${m.version})`);
  } catch (e) {
    throw new Error(`dist/manifest.json is not valid: ${(e as Error).message}`);
  }
}
