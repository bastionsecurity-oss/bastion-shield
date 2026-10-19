// Bench launcher (test/bench/browsers.ts): which browsers load the extension,
// which keep their component lists, and that every profile is seeded before
// the browser starts (see tools/lib/chromium-profile.ts).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { commonArgs, prepareProfile } from '../bench/browsers.ts';
import type { BrowserKind, BrowserSpec } from '../bench/browsers.ts';

const spec = (kind: BrowserKind, extra: Partial<BrowserSpec> = {}): BrowserSpec => ({
  kind,
  executable: 'browser.exe',
  userDataDir: join(tmpdir(), 'bastion-bench-args'),
  headless: true,
  ...extra,
});

test('the extension is loaded for any kind that gets an extension folder', () => {
  for (const kind of ['bastion', 'edge', 'brave'] as BrowserKind[]) {
    const args = commonArgs(spec(kind, { extensionDir: 'C:\\ext' }));
    assert.ok(args.includes('--load-extension=C:\\ext'), kind);
    assert.ok(args.includes('--disable-extensions-except=C:\\ext'), kind);
  }
  assert.ok(!commonArgs(spec('chromium')).some((a) => a.startsWith('--load-extension')));
  assert.ok(!commonArgs(spec('brave')).some((a) => a.startsWith('--load-extension')));
});

test('Brave and Edge keep component updates (filter and tracking-prevention lists), Chromium does not', () => {
  for (const kind of ['edge', 'brave'] as BrowserKind[]) assert.ok(!commonArgs(spec(kind)).includes('--disable-component-update'), kind);
  for (const kind of ['chromium', 'bastion'] as BrowserKind[]) assert.ok(commonArgs(spec(kind)).includes('--disable-component-update'), kind);
});

test('CDP listens on loopback only, with the given profile', () => {
  const args = commonArgs(spec('edge', { headless: false }));
  assert.ok(args.includes('--remote-debugging-address=127.0.0.1'));
  assert.ok(args.some((a) => a.endsWith(`=${join(tmpdir(), 'bastion-bench-args')}`)));
  assert.ok(!args.includes('--headless=new'));
});

test('prepareProfile empties the folder, seeds Local State and writes the initial Preferences', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bastion-bench-profile-'));
  try {
    writeFileSync(join(dir, 'stale.txt'), 'from an earlier run');
    const prefs = { extensions: { ui: { developer_mode: true } } };
    prepareProfile(spec('brave', { userDataDir: dir, prefs }));
    assert.throws(() => readFileSync(join(dir, 'stale.txt')));
    const state = JSON.parse(readFileSync(join(dir, 'Local State'), 'utf8'));
    assert.equal(state.password_manager.os_password_blank, false);
    assert.deepEqual(JSON.parse(readFileSync(join(dir, 'Default', 'Preferences'), 'utf8')), prefs);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
