// Bastion Shield e2e — fixture page builders and request classification.
//
// A request counts as blocked when Chromium reports net::ERR_BLOCKED_BY_CLIENT
// (DNR block) or when it was redirected to an extension resource (DNR
// redirect to a neutered script); in both cases the fixture server never sees
// it. A request counts as loaded when the fixture server received it.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { Page, Request } from '@playwright/test';
import type { ResKind } from './pickers.ts';
import type { FixtureServer } from './server.ts';

export interface ResSpec {
  url: string;
  kind: ResKind;
  label?: string;
}

export interface ResResult extends ResSpec {
  serverHit: boolean;
  failure: string | null;
  redirectedTo: string | null;
  pageEvent: string;
  blocked: boolean;
  loaded: boolean;
}

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

/** HTML that requests every resource and records load/error per index in window.__res. */
export function resourcePageHtml(specs: ResSpec[], title = 'Bastion e2e resources', extraBody = ''): string {
  const parts: string[] = [];
  specs.forEach((s, i) => {
    const on = `onload="__r(${i},'load')" onerror="__r(${i},'error')"`;
    switch (s.kind) {
      case 'script':
        parts.push(`<script src="${esc(s.url)}" ${on}></script>`);
        break;
      case 'img':
        parts.push(`<img src="${esc(s.url)}" width="1" height="1" alt="" ${on}>`);
        break;
      case 'css':
        parts.push(`<link rel="stylesheet" href="${esc(s.url)}" ${on}>`);
        break;
      case 'iframe':
        parts.push(`<iframe src="${esc(s.url)}" width="10" height="10" ${on}></iframe>`);
        break;
      case 'fetch':
        parts.push(`<script>fetch(${JSON.stringify(s.url)},{mode:'no-cors',cache:'no-store'}).then(()=>__r(${i},'load'),()=>__r(${i},'error'))</script>`);
        break;
    }
  });
  return `<!doctype html><html><head><meta charset="utf-8"><title>${esc(title)}</title>
<script>
window.__res = new Array(${specs.length}).fill('pending');
window.__r = function (i, v) { window.__res[i] = v; if (window.__res.every(function (x) { return x !== 'pending'; })) window.__done = true; };
if (${specs.length} === 0) window.__done = true;
</script></head><body>
<h1>${esc(title)}</h1>
${parts.join('\n')}
${extraBody}
</body></html>`;
}

function sameResource(a: string, b: string): boolean {
  try {
    const x = new URL(a);
    const y = new URL(b);
    return x.hostname === y.hostname && x.pathname === y.pathname && x.search === y.search && (x.port || '') === (y.port || '');
  } catch {
    return a === b;
  }
}

/**
 * Serve a page with `specs` on pageHost, load it in `page`, and classify each
 * resource. `navigate` lets the caller supply its own navigation (e.g. reload).
 */
export async function loadResources(
  page: Page,
  server: FixtureServer,
  pageHost: string,
  specs: ResSpec[],
  opts: { path?: string; settleMs?: number; title?: string } = {},
): Promise<ResResult[]> {
  const p = opts.path ?? `/e2e/res-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}.html`;
  const pageUrl = server.setPage(pageHost, p, resourcePageHtml(specs, opts.title));
  const failures: { url: string; error: string }[] = [];
  const redirects: { from: string; to: string }[] = [];
  const onFailed = (r: Request) => failures.push({ url: r.url(), error: r.failure()?.errorText ?? 'unknown' });
  const onRequest = (r: Request) => {
    const from = r.redirectedFrom();
    if (from) redirects.push({ from: from.url(), to: r.url() });
  };
  page.on('requestfailed', onFailed);
  page.on('request', onRequest);
  const t0 = Date.now();
  try {
    await page.goto(pageUrl, { waitUntil: 'load', timeout: 30_000 });
    await page.waitForFunction(() => (window as unknown as { __done?: boolean }).__done === true, null, { timeout: 10_000 }).catch(() => {});
    await page.waitForTimeout(opts.settleMs ?? 200);
    const events = (await page.evaluate(() => (window as unknown as { __res?: string[] }).__res ?? []).catch(() => [])) as string[];
    return specs.map((s, i) => {
      const u = new URL(s.url);
      const serverHit = server.hits.some((h) => h.t >= t0 && h.host === u.hostname && h.path === u.pathname + u.search);
      const failure = failures.find((f) => sameResource(f.url, s.url))?.error ?? null;
      const redirectedTo = redirects.find((r) => sameResource(r.from, s.url))?.to ?? null;
      const neutered = !!redirectedTo && redirectedTo.startsWith('chrome-extension://');
      const blocked = !serverHit && (failure === 'net::ERR_BLOCKED_BY_CLIENT' || neutered);
      return { ...s, serverHit, failure, redirectedTo, pageEvent: events[i] ?? 'unknown', blocked, loaded: serverHit };
    });
  } finally {
    page.off('requestfailed', onFailed);
    page.off('request', onRequest);
  }
}

export function describeResults(rs: ResResult[]): string {
  return rs
    .map((r) => `${r.blocked ? 'BLOCKED' : r.loaded ? 'LOADED ' : 'OTHER  '} ${r.kind.padEnd(6)} ${r.url}${r.failure ? ' failure=' + r.failure : ''}${r.redirectedTo ? ' -> ' + r.redirectedTo : ''} page=${r.pageEvent}${r.label ? ' [' + r.label + ']' : ''}`)
    .join('\n');
}

/** Poll until `fn` returns a truthy value or the timeout elapses; returns the last value. */
export async function poll<T>(fn: () => Promise<T>, ok: (v: T) => boolean, timeoutMs = 5000, stepMs = 100): Promise<T> {
  const end = Date.now() + timeoutMs;
  let v = await fn();
  while (!ok(v) && Date.now() < end) {
    await new Promise((r) => setTimeout(r, stepMs));
    v = await fn();
  }
  return v;
}
