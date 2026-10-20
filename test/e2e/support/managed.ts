// Bastion Shield e2e — stand-in for enterprise policy (chrome.storage.managed).
//
// A test cannot set chrome.storage.managed: Chromium fills it from the
// platform policy store (registry, plist, /etc), and writing browser policy
// on the developer's machine is not something a test may do. Instead the
// staged copy of the build (never dist/ itself) gets a module service worker
// that loads this shim before the real background.js:
//
//   __e2e_bg.js:  import './__e2e_managed.js'; import './background.js';
//
// The shim replaces chrome.storage.managed.get() with a read of a test-only
// chrome.storage.session key and remembers the storage.onChanged listeners the
// product registers. self.__bastionE2eSetManaged(policy) stores the new policy
// and calls those listeners with area 'managed', which is exactly the event a
// real policy push delivers. Everything after that (sanitizeManaged, the
// storage change plan, the applier, registrations, privacy APIs) is the
// shipped code. Product code is unchanged; only the staged manifest differs.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import type { Worker } from '@playwright/test';

/** chrome.storage.session key that holds the simulated policy. */
export const MANAGED_KEY = '__bastionE2eManaged';

const SHIM = `// e2e only (test/e2e/support/managed.ts): simulated chrome.storage.managed.
const KEY = ${JSON.stringify(MANAGED_KEY)};
const area = chrome.storage.managed;
const read = () => chrome.storage.session.get(KEY).then((r) => (r && r[KEY]) || {});
const fakeGet = function (keys, cb) {
  const p = read().then((all) => {
    if (keys === null || keys === undefined) return all;
    const ks = typeof keys === 'string' ? [keys] : Array.isArray(keys) ? keys : Object.keys(keys);
    const out = {};
    for (const k of ks) if (Object.prototype.hasOwnProperty.call(all, k)) out[k] = all[k];
    return out;
  });
  if (typeof cb === 'function') {
    p.then(cb);
    return undefined;
  }
  return p;
};
try { area.get = fakeGet; } catch (e) { /* fall through */ }
if (area.get !== fakeGet) {
  try { Object.defineProperty(area, 'get', { value: fakeGet, configurable: true, writable: true }); } catch (e) { /* reported below */ }
}
const listeners = [];
const ev = chrome.storage.onChanged;
const origAdd = ev.addListener.bind(ev);
ev.addListener = (fn) => {
  listeners.push(fn);
  return origAdd(fn);
};
self.__bastionE2eSetManaged = async (next) => {
  const prev = await read();
  await chrome.storage.session.set({ [KEY]: next || {} });
  const changes = {};
  for (const k of new Set([...Object.keys(prev), ...Object.keys(next || {})])) {
    if (JSON.stringify(prev[k]) !== JSON.stringify((next || {})[k])) changes[k] = { oldValue: prev[k], newValue: (next || {})[k] };
  }
  for (const fn of listeners) {
    try { fn(changes, 'managed'); } catch (e) { console.error('[e2e] managed listener threw', String(e)); }
  }
  return { patched: area.get === fakeGet, listeners: listeners.length, changed: Object.keys(changes) };
};
`;

/** Add the managed-policy shim to a staged build (rewrites its manifest's service worker entry). */
export function installManagedShim(stagedDir: string): void {
  const manifestPath = path.join(stagedDir, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as { background?: { service_worker?: string; type?: string } };
  const sw = manifest.background?.service_worker ?? 'background.js';
  if (manifest.background?.type !== 'module') throw new Error('managed shim needs a module service worker');
  writeFileSync(path.join(stagedDir, '__e2e_managed.js'), SHIM);
  writeFileSync(path.join(stagedDir, '__e2e_bg.js'), `import './__e2e_managed.js';\nimport './${sw.replace(/^\.?\//, '')}';\n`);
  manifest.background = { ...manifest.background, service_worker: '__e2e_bg.js' };
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
}

/** Push a simulated policy to the running service worker (as a real policy update would arrive). */
export async function setManagedPolicy(sw: Worker, policy: Record<string, unknown>): Promise<{ patched: boolean; listeners: number; changed: string[] }> {
  return sw.evaluate(
    (p: Record<string, unknown>) =>
      (self as unknown as { __bastionE2eSetManaged: (x: unknown) => Promise<{ patched: boolean; listeners: number; changed: string[] }> }).__bastionE2eSetManaged(p),
    policy,
  );
}
