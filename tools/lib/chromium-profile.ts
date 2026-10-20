// Profile helpers for every Chromium/Brave/Edge instance our tools and tests
// launch on Windows.
//
// Why this exists: on startup Chromium's password manager calls
// CanAuthenticateWithScreenLock(), which on Windows tries LogonUser() with an
// EMPTY password to find out whether the OS account has a blank password
// (chrome/browser/password_manager/password_manager_util_win.cc,
// CheckBlankPasswordWithPrefs). The result is cached in the profile's
// "Local State" (password_manager.os_password_blank / _last_changed). A fresh
// --user-data-dir has no cache, so EVERY launch with a new profile records a
// failed interactive logon (Security event 4625). Ten launches within the
// lockout window locked the developer's Windows account. Seeding the cache
// makes Chromium skip the LogonUser() call entirely.
//
// Rule: never launch a browser with an unseeded profile. Use
// launchPersistentContext(freshProfileDir(...)) instead of chromium.launch(),
// and seedChromiumProfile(dir) before spawning a browser with --user-data-dir.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * base::Time internal value (microseconds since 1601) far in the future.
 * Chromium rechecks only when the OS password changed after this value, so the
 * check never runs for a seeded profile. Int64 prefs are serialized as strings.
 */
const PASSWORD_LAST_CHANGED_FAR_FUTURE = '99999999999999999';

/** Write (or merge into) <dir>/Local State so Chromium never probes the OS password. */
export function seedChromiumProfile(userDataDir: string): void {
  mkdirSync(userDataDir, { recursive: true });
  const file = join(userDataDir, 'Local State');
  let state: Record<string, unknown> = {};
  if (existsSync(file)) {
    try {
      state = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
    } catch {
      state = {};
    }
  }
  const pm = (typeof state.password_manager === 'object' && state.password_manager !== null
    ? state.password_manager
    : {}) as Record<string, unknown>;
  pm.os_password_blank = false;
  pm.os_password_last_changed = PASSWORD_LAST_CHANGED_FAR_FUTURE;
  state.password_manager = pm;
  writeFileSync(file, JSON.stringify(state));
}

/** A new, empty, already-seeded user-data-dir under the OS temp directory. */
export function freshProfileDir(prefix = 'bastion-browser-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  seedChromiumProfile(dir);
  return dir;
}
