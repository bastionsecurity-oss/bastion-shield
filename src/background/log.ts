// Bastion Shield service worker — logging. Console output is prefixed so it is
// easy to filter in chrome://extensions; recent problems are also kept in a
// small in-memory ring for troubleshooting views. Nothing leaves the device.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { errMsg } from './util.ts';

export interface LogEntry {
  t: number;
  level: 'warn' | 'error';
  scope: string;
  message: string;
}

const RECENT_MAX = 64;
const recent: LogEntry[] = [];

function push(level: LogEntry['level'], scope: string, message: string): void {
  recent.push({ t: Date.now(), level, scope, message });
  if (recent.length > RECENT_MAX) recent.splice(0, recent.length - RECENT_MAX);
}

export function info(scope: string, ...args: unknown[]): void {
  try {
    console.info(`[bastion:${scope}]`, ...args);
  } catch {
    /* console may be unavailable in exotic contexts */
  }
}

export function warn(scope: string, ...args: unknown[]): void {
  push('warn', scope, args.map(errMsg).join(' '));
  try {
    console.warn(`[bastion:${scope}]`, ...args);
  } catch {
    /* ignore */
  }
}

export function error(scope: string, ...args: unknown[]): void {
  push('error', scope, args.map(errMsg).join(' '));
  try {
    console.error(`[bastion:${scope}]`, ...args);
  } catch {
    /* ignore */
  }
}

export function recentProblems(): LogEntry[] {
  return recent.slice();
}

/**
 * Await a chrome.* call and never throw: synchronous throws (API missing,
 * bad arguments) and rejections are logged and turned into `fallback`.
 */
export async function attempt<T>(scope: string, fn: () => Promise<T> | T, fallback: T): Promise<T>;
export async function attempt<T>(scope: string, fn: () => Promise<T> | T): Promise<T | undefined>;
export async function attempt<T>(scope: string, fn: () => Promise<T> | T, fallback?: T): Promise<T | undefined> {
  try {
    return await fn();
  } catch (e) {
    warn(scope, errMsg(e));
    return fallback;
  }
}

/** Like attempt() but reports success/failure with the error message. */
export async function attemptResult<T>(fn: () => Promise<T> | T): Promise<{ ok: true; value: T } | { ok: false; error: string }> {
  try {
    return { ok: true, value: await fn() };
  } catch (e) {
    return { ok: false, error: errMsg(e) };
  }
}
