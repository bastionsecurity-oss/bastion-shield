// Bastion Shield bench — optional REA cross-check (https://github.com/morluto/rea,
// npm "rea-agents"). For each browser started with --remote-debugging-port on
// 127.0.0.1, REA lists the page targets and passively inspects the benchmark
// page (`inspect-web-page <endpoint> <target> --observation-ms 8000 --json`).
// The Evidence is saved next to the results, and its resource inventory (the
// frames' resource tree with content sizes) is compared with our own CDP
// classification:
//   - a resource REA lists with content_size 0 failed to load (hard block);
//   - a resource with content on an ad/tracker host either got through or is a
//     neutered stub (Bastion's redirect to a web-accessible resource, Brave's
//     in-process $redirect stub); our capture says which;
//   - an ad/tracker resource with content that our capture calls hard-blocked,
//     or a host our capture never saw, is a disagreement worth a look.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import type { SiteCapture } from './capture.ts';
import type { ReferenceSet } from './reference.ts';

export interface ReaRunner {
  /** Command and leading args, e.g. ["npx", "-y", "rea-agents@latest"] or [node, ".../scripts/rea.mjs"]. */
  argv: string[];
  version: string | null;
}

export interface ReaResource {
  url: string;
  type: string;
  contentSize: number | null;
}

export interface ReaSiteResult {
  ok: boolean;
  error: string | null;
  evidenceFile: string | null;
  ms: number;
  allowedOrigins: number;
  /** Resource-tree entries (everything the frames requested, incl. failed ones). */
  resources: number;
  /** Network requests inside REA's own observation window. */
  requests: number;
  completeness: unknown;
  /** Filled by compareWithCapture(). */
  check: {
    adTrackerResources: number;
    /** Ad/tracker resources REA saw with content. */
    adTrackerWithContent: number;
    /** ... of which our capture classified as a neutered stub (expected for redirect rules). */
    confirmedStubs: string[];
    /** Ad/tracker resources REA saw with content_size 0 (failed); our capture should call them blocked. */
    emptyResources: number;
    /** REA shows content, our capture says hard-blocked (ERR_BLOCKED_BY_CLIENT). */
    disagreements: string[];
    /** Ad/tracker hosts in REA's inventory that our CDP capture never saw (capture gap). */
    notInCapture: string[];
  } | null;
}

interface Exec {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

function run(argv: string[], args: string[], timeoutMs: number): Promise<Exec> {
  return new Promise((resolve) => {
    // npx is a .cmd shim on Windows: it needs a shell, and then one quoted command string.
    const useShell = process.platform === 'win32' && /^(npx|npm)(\.cmd)?$/i.test(argv[0]);
    const quote = (s: string) => (/[\s&|<>^"()]/.test(s) ? `"${s.replace(/"/g, '\\"')}"` : s);
    const child = useShell
      ? spawn(argv.concat(args).map(quote).join(' '), { shell: true, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, NO_COLOR: '1' } })
      : spawn(argv[0], argv.slice(1).concat(args), { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, NO_COLOR: '1' } });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (d: string) => (stdout += d));
    child.stderr.on('data', (d: string) => {
      stderr += d;
      if (stderr.length > 200_000) stderr = stderr.slice(-100_000);
    });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        if (process.platform === 'win32' && child.pid) spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true });
        else child.kill('SIGKILL');
      } catch {
        /* ignore */
      }
    }, timeoutMs);
    child.on('error', (e) => {
      stderr += String(e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr, timedOut });
    });
  });
}

function parseJson(stdout: string): any {
  const s = stdout.trim();
  try {
    return JSON.parse(s);
  } catch {
    // Tolerate a banner or npm notice before the JSON document.
    const i = s.indexOf('{');
    if (i > 0) return JSON.parse(s.slice(i));
    throw new Error('REA output is not JSON: ' + s.slice(0, 300));
  }
}

/** Resolve and warm up the REA CLI once (npx downloads rea-agents on first use). */
export async function prepareRea(bin: string | null, log: (s: string) => void): Promise<ReaRunner | null> {
  const argv = bin ? (/\.(mjs|cjs|js)$/.test(bin) ? [process.execPath, bin] : [bin]) : ['npx', '-y', 'rea-agents@latest'];
  log(`rea: warming up ${argv.join(' ')} (first run downloads the package)`);
  const r = await run(argv, ['--version'], 600_000);
  if (r.code !== 0) {
    log(`rea: unavailable (exit ${r.code}${r.timedOut ? ', timed out' : ''}): ${(r.stderr || r.stdout).trim().split('\n').slice(-5).join(' | ')}`);
    return null;
  }
  const version = (r.stdout.trim().split(/\r?\n/).pop() ?? '').trim() || null;
  log(`rea: ready (${version ?? 'unknown version'})`);
  return { argv, version };
}

/** Resource inventory and window requests from REA's Evidence, wherever the envelope puts them. */
export function collectFromEvidence(evidence: unknown): { resources: ReaResource[]; requests: { url: string; status: number | null }[]; completeness: unknown } {
  const resources: ReaResource[] = [];
  const requests: { url: string; status: number | null }[] = [];
  let completeness: unknown = null;
  const seen = new Set<unknown>();
  const walk = (v: any, depth: number) => {
    if (!v || typeof v !== 'object' || seen.has(v) || depth > 12) return;
    seen.add(v);
    if (Array.isArray(v.resources) && v.resources.length && v.resources.every((r: any) => r && typeof r.url === 'string' && 'resource_key' in r)) {
      for (const r of v.resources) resources.push({ url: r.url, type: String(r.type ?? ''), contentSize: typeof r.content_size === 'number' ? r.content_size : null });
    }
    if (v.network && Array.isArray(v.network.requests)) {
      for (const r of v.network.requests) if (r && typeof r.url === 'string') requests.push({ url: r.url, status: typeof r.status === 'number' ? r.status : null });
    }
    if (v.completeness && completeness === null) completeness = v.completeness;
    for (const k of Object.keys(v)) if (k !== 'dom' && k !== 'accessibility') walk(v[k], depth + 1);
  };
  walk(evidence, 0);
  // The same capture can appear in raw and normalized form; count each URL once.
  const uniq = new Map<string, ReaResource>();
  for (const r of resources) if (!uniq.has(r.url)) uniq.set(r.url, r);
  return { resources: [...uniq.values()], requests, completeness };
}

export async function reaInspect(
  rea: ReaRunner,
  opts: { endpoint: string; targetId: string; origins: string[]; observationMs: number; outFile: string },
): Promise<{ result: ReaSiteResult; resources: ReaResource[] }> {
  const t0 = Date.now();
  const result: ReaSiteResult = { ok: false, error: null, evidenceFile: null, ms: 0, allowedOrigins: 0, resources: 0, requests: 0, completeness: null, check: null };
  let resources: ReaResource[] = [];
  try {
    const list = await run(rea.argv, ['list-browser-targets', opts.endpoint, '--json'], 120_000);
    if (list.code !== 0) throw new Error(`list-browser-targets exit ${list.code}: ${(list.stderr || list.stdout).trim().slice(-400)}`);
    if (!JSON.stringify(parseJson(list.stdout)).includes(opts.targetId)) throw new Error(`target ${opts.targetId} not in list-browser-targets output`);
    // REA scopes to the page origin by default; pass every origin we saw so third parties are included.
    const origins = [...new Set(opts.origins)].filter((o) => /^https?:\/\/[^/]+$/.test(o)).slice(0, 400);
    result.allowedOrigins = origins.length;
    const args = ['inspect-web-page', opts.endpoint, opts.targetId, '--observation-ms', String(opts.observationMs), '--json'];
    for (const o of origins) args.push('--allowed-origins', o);
    const insp = await run(rea.argv, args, opts.observationMs + 180_000);
    mkdirSync(path.dirname(opts.outFile), { recursive: true });
    if (insp.code !== 0) {
      writeFileSync(opts.outFile.replace(/\.json$/, '.error.txt'), `exit ${insp.code}\n--- stdout\n${insp.stdout.slice(0, 20000)}\n--- stderr\n${insp.stderr.slice(-20000)}`);
      throw new Error(`inspect-web-page exit ${insp.code}${insp.timedOut ? ' (timeout)' : ''}: ${(insp.stderr || insp.stdout).trim().slice(-400)}`);
    }
    const evidence = parseJson(insp.stdout);
    writeFileSync(opts.outFile, JSON.stringify(evidence));
    result.evidenceFile = opts.outFile;
    const c = collectFromEvidence(evidence);
    resources = c.resources;
    result.resources = c.resources.length;
    result.requests = c.requests.length;
    result.completeness = c.completeness;
    result.ok = true;
  } catch (e) {
    result.error = (e as Error).message;
  }
  result.ms = Date.now() - t0;
  return { result, resources };
}

/** Cross-check REA's resource inventory against our CDP classification of the same visit. */
export function compareWithCapture(result: ReaSiteResult, resources: ReaResource[], cap: SiteCapture, ref: ReferenceSet): void {
  const pageHost = (() => {
    try {
      return new URL(cap.finalUrl ?? cap.url).hostname;
    } catch {
      return '';
    }
  })();
  const byUrl = new Map(cap.requests.map((r) => [r.url, r]));
  const capHosts = new Set(cap.requests.map((r) => r.host));
  const check: NonNullable<ReaSiteResult['check']> = {
    adTrackerResources: 0,
    adTrackerWithContent: 0,
    confirmedStubs: [],
    emptyResources: 0,
    disagreements: [],
    notInCapture: [],
  };
  const notInCapture = new Set<string>();
  for (const r of resources) {
    let host = '';
    try {
      host = new URL(r.url).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (!host || host === pageHost || !ref.matches(host)) continue;
    check.adTrackerResources++;
    if (!capHosts.has(host)) notInCapture.add(host);
    if (!r.contentSize) {
      check.emptyResources++;
      continue;
    }
    check.adTrackerWithContent++;
    const ours = byUrl.get(r.url);
    if (!ours) continue;
    if (ours.neutered) check.confirmedStubs.push(`${r.url} (${r.contentSize} B)`);
    else if (ours.blocked) check.disagreements.push(`${r.url} (${r.contentSize} B, CDP: ${ours.failed ?? 'blocked'})`);
  }
  check.notInCapture = [...notInCapture].sort();
  result.check = check;
}
