// Bastion Shield — extension version numbers (ARCHITECTURE §11):
// MAJOR.MINOR.PATCH from package.json plus BUILD = days since 2026-01-01
// (UTC) × 10 + same-day counter (0–9). Chrome requires each part <= 65535,
// which this scheme satisfies until the 2040s.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { join } from 'node:path';
import { ROOT, readJson, writeJson } from './util.ts';

const EPOCH_UTC = Date.UTC(2026, 0, 1);
const COUNTER_FILE = join(ROOT, '.cache', 'build-counter.json');

export function daysSinceEpoch(d: Date): number {
  const day = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  return Math.floor((day - EPOCH_UTC) / 86_400_000);
}

export function buildNumber(d: Date, counter: number): number {
  if (!Number.isInteger(counter) || counter < 0 || counter > 9) {
    throw new Error(`same-day build counter must be 0..9 (got ${counter}); more than 10 releases per day would reuse a version`);
  }
  const days = daysSinceEpoch(d);
  if (days < 0) throw new Error('system clock is before 2026-01-01');
  const n = days * 10 + counter;
  if (n > 65535) throw new Error('BUILD number exceeds 65535; move the version epoch');
  return n;
}

export function baseVersion(pkgVersion: string): string {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(pkgVersion);
  if (!m) throw new Error(`package.json version "${pkgVersion}" is not MAJOR.MINOR.PATCH`);
  for (const p of m.slice(1)) if (Number(p) > 65535) throw new Error(`version part ${p} exceeds 65535`);
  return `${Number(m[1])}.${Number(m[2])}.${Number(m[3])}`;
}

export interface VersionInfo {
  version: string;
  versionName?: string;
  build: number;
  counter: number;
  /** UTC day (YYYY-MM-DD) the counter belongs to. */
  day: string;
}

/**
 * Counter source, in order: BASTION_BUILD_COUNTER (CI), else for release
 * builds the next value of .cache/build-counter.json for today, else the last
 * stored value for today (dev builds do not consume counter values).
 */
export async function computeVersion(opts: { release: boolean; now?: Date }): Promise<VersionInfo> {
  const now = opts.now ?? new Date();
  const pkg = await readJson<{ version: string }>(join(ROOT, 'package.json'));
  const base = baseVersion(pkg.version);
  const today = now.toISOString().slice(0, 10);
  let counter = 0;
  const env = process.env.BASTION_BUILD_COUNTER;
  if (env !== undefined && env !== '') {
    counter = Number(env);
  } else {
    let stored: { day: string; counter: number } | null = null;
    try {
      stored = await readJson<{ day: string; counter: number }>(COUNTER_FILE);
    } catch {
      stored = null;
    }
    const sameDay = stored?.day === today && Number.isInteger(stored.counter);
    if (opts.release) {
      counter = sameDay ? stored!.counter + 1 : 0;
    } else {
      counter = sameDay ? stored!.counter : 0;
    }
  }
  const build = buildNumber(now, counter);
  const version = `${base}.${build}`;
  return { version, versionName: opts.release ? undefined : `${version} dev`, build, counter, day: today };
}

/** Persist the counter after a successful release build (CI passes BASTION_BUILD_COUNTER instead). */
export async function commitBuildCounter(info: VersionInfo): Promise<void> {
  const env = process.env.BASTION_BUILD_COUNTER;
  if (env !== undefined && env !== '') return;
  await writeJson(COUNTER_FILE, { day: info.day, counter: info.counter }, true);
}
