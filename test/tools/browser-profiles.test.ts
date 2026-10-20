// Guard: every browser our tools and tests start must use a seeded profile.
// An unseeded Chromium/Brave profile makes the browser call Windows LogonUser()
// with an empty password at startup; repeated launches lock the developer's
// Windows account (see tools/lib/chromium-profile.ts).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { freshProfileDir, seedChromiumProfile } from '../../tools/lib/chromium-profile.ts';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));

function sources(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name.startsWith('.')) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) sources(p, out);
    else if (/\.(ts|mts|js|mjs)$/.test(name)) out.push(p);
  }
  return out;
}

test('no unseeded browser launches in tools/ and test/', () => {
  const offenders: string[] = [];
  for (const file of [...sources(join(ROOT, 'tools')), ...sources(join(ROOT, 'test'))]) {
    if (file.endsWith('browser-profiles.test.ts') || file.endsWith('chromium-profile.ts')) continue;
    // Ignore comments: they may mention the forbidden calls to explain the rule.
    const text = readFileSync(file, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    // chromium.launch() always uses a fresh, unseeded temp profile.
    if (/\bchromium\s*\.\s*launch\s*\(/.test(text)) offenders.push(`${relative(ROOT, file)}: chromium.launch()`);
    // Any explicit --user-data-dir / persistent context must be seeded in the same file.
    const startsProfile = /--user-data-dir|launchPersistentContext\s*\(/.test(text);
    if (startsProfile && !/seedChromiumProfile|freshProfileDir/.test(text)) offenders.push(`${relative(ROOT, file)}: profile not seeded`);
  }
  assert.deepEqual(offenders, []);
});

test('seedChromiumProfile writes the cached password-check answer and keeps other keys', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bastion-seed-test-'));
  try {
    seedChromiumProfile(dir);
    let state = JSON.parse(readFileSync(join(dir, 'Local State'), 'utf8'));
    assert.equal(state.password_manager.os_password_blank, false);
    assert.equal(state.password_manager.os_password_last_changed, '99999999999999999');
    state.other = { kept: true };
    // Re-seeding an existing Local State merges instead of replacing.
    writeFileSync(join(dir, 'Local State'), JSON.stringify(state));
    seedChromiumProfile(dir);
    state = JSON.parse(readFileSync(join(dir, 'Local State'), 'utf8'));
    assert.deepEqual(state.other, { kept: true });
    assert.equal(state.password_manager.os_password_blank, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  const fresh = freshProfileDir('bastion-seed-fresh-');
  try {
    assert.ok(existsSync(join(fresh, 'Local State')));
  } finally {
    rmSync(fresh, { recursive: true, force: true });
  }
});

