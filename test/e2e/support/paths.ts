// Bastion Shield e2e — filesystem locations shared by the e2e suite and the
// benchmark. BASTION_DIST overrides the unpacked build directory (e.g. to
// test a build produced elsewhere in CI).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

export const REPO_ROOT = path.resolve(here, '..', '..', '..');
export const DIST_DIR = path.resolve(process.env.BASTION_DIST || path.join(REPO_ROOT, 'dist'));
export const FIXTURES_DIR = path.join(REPO_ROOT, 'test', 'fixtures');
export const E2E_DIR = path.join(REPO_ROOT, 'test', 'e2e');

export function distExists(): boolean {
  return existsSync(path.join(DIST_DIR, 'manifest.json'));
}
