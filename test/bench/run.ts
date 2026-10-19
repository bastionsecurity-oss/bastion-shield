// Bastion Shield — real-world parity and performance benchmark.
//
//   node test/bench/run.ts [--sites 20min.ch,blick.ch | --limit 3] [--browsers chromium,bastion,brave,edge]
//                          [--settle 15000] [--rea] [--rea-bin path/to/rea.mjs] [--headed] [--save-requests]
//                          [--append test/bench/results/<run>.json]   (re-measure --sites into an existing run)
//
// Visits each site in browsers that run side by side, one visit at a time
// (rotating the order per site so no browser always goes first):
//   chromium  Playwright's bundled Chromium, no extension (baseline)
//   bastion   the same Chromium with the unpacked dist/ loaded
//   brave     the installed Brave, Shields at defaults, fresh profile
//   edge      the installed Microsoft Edge with the unpacked dist/ loaded,
//             tracking prevention at its default (opt-in: --browsers ...,edge)
// Every browser is a plain process with --remote-debugging-port on 127.0.0.1
// and a fresh --user-data-dir; requests are recorded over CDP (including
// out-of-process iframes). Results go to test/bench/results/<date>.json and a
// Markdown table to test/bench/results/summary.md. With --rea, REA attaches
// to each browser's CDP endpoint and its Evidence is saved under
// test/bench/results/rea/<browser>/<site>.json as an independent cross-check.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { chromium as pwChromium } from 'playwright';
import type { BrowserKind, LaunchedBrowser } from './browsers.ts';
import { defaultBravePath, defaultEdgePath, launchBrowser } from './browsers.ts';
import { captureSite } from './capture.ts';
import type { SiteCapture } from './capture.ts';
import type { Cdp } from './cdp.ts';
import { compareWithCapture, prepareRea, reaInspect } from './rea.ts';
import type { ReaResource, ReaRunner } from './rea.ts';
import { loadReferenceSet } from './reference.ts';
import type { ReferenceSet } from './reference.ts';
import { summaryMarkdown } from './report.ts';
import type { BenchResults, SiteSummary } from './report.ts';
import { SITES } from './sites.ts';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

interface Options {
  sites: string[] | null;
  limit: number | null;
  browsers: BrowserKind[];
  settleMs: number;
  navTimeoutMs: number;
  rea: boolean;
  reaBin: string | null;
  reaObservationMs: number;
  headed: boolean;
  braveHeaded: boolean;
  dist: string;
  brave: string | null;
  edge: string | null;
  chromium: string | null;
  profileRoot: string;
  out: string;
  listsDirs: string[];
  saveRequests: boolean;
  /** Re-measure the selected sites into an existing results file (replacing their entries). */
  append: string | null;
}

function parseArgs(argv: string[]): Options {
  const get = (name: string): string | null => {
    const i = argv.indexOf(`--${name}`);
    if (i !== -1 && i + 1 < argv.length && !argv[i + 1].startsWith('--')) return argv[i + 1];
    const eq = argv.find((a) => a.startsWith(`--${name}=`));
    return eq ? eq.slice(name.length + 3) : null;
  };
  const has = (name: string) => argv.includes(`--${name}`);
  if (has('help')) {
    console.log(readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\n').filter((l) => l.startsWith('//')).slice(0, 20).join('\n'));
    process.exit(0);
  }
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  return {
    sites: get('sites')?.split(',').map((s) => s.trim()).filter(Boolean) ?? null,
    limit: get('limit') ? Number(get('limit')) : null,
    browsers: (get('browsers')?.split(',').map((s) => s.trim()) ?? ['chromium', 'bastion', 'brave']) as BrowserKind[],
    settleMs: Number(get('settle') ?? 15_000),
    navTimeoutMs: Number(get('nav-timeout') ?? 45_000),
    rea: has('rea'),
    reaBin: get('rea-bin'),
    reaObservationMs: Number(get('rea-observation') ?? 8000),
    headed: has('headed'),
    braveHeaded: has('brave-headed'),
    dist: path.resolve(get('dist') ?? process.env.BASTION_DIST ?? path.join(ROOT, 'dist')),
    brave: get('brave') ?? defaultBravePath(),
    edge: get('edge') ?? defaultEdgePath(),
    chromium: get('chromium'),
    profileRoot: path.resolve(get('profile-root') ?? path.join(os.tmpdir(), `bastion-bench-${stamp}`)),
    out: path.resolve(get('out') ?? path.join(HERE, 'results')),
    listsDirs: [get('lists-dir'), process.env.BASTION_LISTS_DIR, path.join(ROOT, '.cache', 'lists')].filter((x): x is string => !!x),
    saveRequests: has('save-requests'),
    append: get('append') ? path.resolve(get('append')!) : null,
  };
}

const log = (s: string) => console.log(`[bench ${new Date().toISOString().slice(11, 19)}] ${s}`);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
/** Kinds that load Bastion Shield from the build. */
const withExtension = (kind: BrowserKind): boolean => kind === 'bastion' || kind === 'edge';

// ---------------------------------------------------------------------------
// Readiness: lists loaded and blocking (Brave fetches its lists as components)
// ---------------------------------------------------------------------------

const PROBE_PAGE = 'https://example.com/';
// Plain block targets in every Brave-equivalent list stack. Not gpt.js: that is
// $redirect-ed to a stub, which Brave serves as an ordinary 200 response.
const PROBE_URLS = [
  'https://pubads.g.doubleclick.net/activity;dc_iu=/1/bastion-probe;ord=1',
  'https://cdn.confiant-integrations.net/bastion-probe/config.js',
  'https://api.permutive.com/bastion-probe',
];

async function probeBlocking(cdp: Cdp): Promise<'blocked' | 'loaded' | 'error'> {
  let targetId: string | null = null;
  const offs: (() => void)[] = [];
  try {
    targetId = (await cdp.send<{ targetId: string }>('Target.createTarget', { url: 'about:blank' })).targetId;
    const { sessionId } = await cdp.send<{ sessionId: string }>('Target.attachToTarget', { targetId, flatten: true });
    const ids = new Map<string, string>();
    let blocked = 0;
    let finished = 0;
    offs.push(
      cdp.on('Network.requestWillBeSent', (p, s) => {
        if (s === sessionId && PROBE_URLS.some((u) => p.request.url.startsWith(u))) ids.set(p.requestId, p.request.url);
      }),
      cdp.on('Network.loadingFailed', (p, s) => {
        if (s === sessionId && ids.has(p.requestId) && p.errorText === 'net::ERR_BLOCKED_BY_CLIENT') blocked++;
      }),
      // Any other outcome (404, ORB, network error) means "not blocked by a content blocker".
      cdp.on('Network.loadingFinished', (p, s) => {
        if (s === sessionId && ids.has(p.requestId)) finished++;
      }),
      cdp.on('Network.responseReceived', (p, s) => {
        if (s === sessionId && ids.has(p.requestId)) finished++;
      }),
    );
    await cdp.send('Network.enable', {}, sessionId);
    await cdp.send('Page.enable', {}, sessionId);
    const loaded = cdp.waitFor('Page.loadEventFired', (_p, s) => s === sessionId, 20_000);
    await cdp.send('Page.navigate', { url: PROBE_PAGE }, sessionId, 20_000);
    await loaded;
    const nonce = Date.now();
    await cdp.send(
      'Runtime.evaluate',
      {
        expression: `(${JSON.stringify(PROBE_URLS)}).forEach((u, i) => { const el = document.createElement(i ? 'script' : 'img'); el.src = u + (u.includes('?') ? '&' : '?') + 'n=${nonce}'; document.body.appendChild(el); })`,
      },
      sessionId,
      10_000,
    );
    const end = Date.now() + 8000;
    while (Date.now() < end && blocked + finished < PROBE_URLS.length) await sleep(200);
    if (blocked > 0) return 'blocked';
    return finished > 0 ? 'loaded' : 'error';
  } catch {
    return 'error';
  } finally {
    for (const off of offs) off();
    if (targetId) await cdp.trySend('Target.closeTarget', { targetId });
  }
}

async function waitUntilBlocking(b: LaunchedBrowser, timeoutMs: number): Promise<{ ready: boolean; note: string }> {
  const t0 = Date.now();
  let last = '';
  while (Date.now() - t0 < timeoutMs) {
    last = await probeBlocking(b.cdp);
    if (last === 'blocked') return { ready: true, note: `blocking active after ${Math.round((Date.now() - t0) / 1000)} s` };
    await sleep(3000);
  }
  return { ready: false, note: `probe still "${last}" after ${Math.round(timeoutMs / 1000)} s` };
}

/**
 * Find our service worker among all extension SWs (Chromium also runs
 * component extensions) by asking each one for its manifest version.
 */
async function findExtension(cdp: Cdp, timeoutMs: number, expect: { version: string; swPath: string }): Promise<{ origin: string; id: string } | null> {
  const end = Date.now() + timeoutMs;
  const checked = new Set<string>();
  while (Date.now() < end) {
    const t = await cdp.trySend<{ targetInfos: { targetId: string; type: string; url: string }[] }>('Target.getTargets');
    for (const sw of t?.targetInfos ?? []) {
      if (sw.type !== 'service_worker' || !sw.url.startsWith('chrome-extension://') || checked.has(sw.targetId)) continue;
      if (!new URL(sw.url).pathname.endsWith('/' + expect.swPath.replace(/^\//, ''))) continue;
      checked.add(sw.targetId);
      const att = await cdp.trySend<{ sessionId: string }>('Target.attachToTarget', { targetId: sw.targetId, flatten: true });
      if (!att) continue;
      const r = await cdp.trySend<{ result: { value?: string } }>('Runtime.evaluate', { expression: 'chrome.runtime.getManifest().version', returnByValue: true }, att.sessionId);
      await cdp.trySend('Target.detachFromTarget', { sessionId: att.sessionId });
      if (r?.result?.value === expect.version) {
        const u = new URL(sw.url);
        // URL.origin is the opaque "null" for chrome-extension: URLs in Node; build it by hand.
        return { origin: `chrome-extension://${u.host}`, id: u.host };
      }
    }
    await sleep(250);
  }
  return null;
}

// ---------------------------------------------------------------------------
// REA: prefer running the cached package's script directly (no shell, no
// command-line length limit) after npx has downloaded it once.
// ---------------------------------------------------------------------------

function findNpxReaScript(): string | null {
  // One command string: npm is a .cmd shim on Windows and needs the shell.
  const r = spawnSync('npm config get cache', { encoding: 'utf8', shell: true, windowsHide: true });
  const cache = (r.stdout || '').trim();
  const dir = path.join(cache, '_npx');
  if (!cache || !existsSync(dir)) return null;
  let best: { file: string; mtime: number } | null = null;
  for (const d of readdirSync(dir)) {
    const file = path.join(dir, d, 'node_modules', 'rea-agents', 'scripts', 'rea.mjs');
    if (!existsSync(file)) continue;
    const mtime = statSync(file).mtimeMs;
    if (!best || mtime > best.mtime) best = { file, mtime };
  }
  return best?.file ?? null;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function summarize(c: SiteCapture, saveAll: boolean): SiteSummary & { requests?: SiteCapture['requests'] } {
  const { requests, ...rest } = c;
  const out: SiteSummary & { requests?: SiteCapture['requests'] } = {
    ...rest,
    adTrackerRequests: requests.filter((r) => r.adTracker).map((r) => ({ url: r.url, blocked: r.blocked, status: r.status, failed: r.failed, type: r.type })),
  };
  if (saveAll) out.requests = requests;
  return out;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  let sites = SITES;
  if (opts.sites) sites = SITES.filter((s) => opts.sites!.includes(s.name)).concat(opts.sites.filter((n) => !SITES.some((s) => s.name === n)).map((n) => ({ name: n, url: n.startsWith('http') ? n : `https://${n}/`, region: 'intl' as const })));
  if (opts.limit) sites = sites.slice(0, opts.limit);
  mkdirSync(opts.out, { recursive: true });
  mkdirSync(opts.profileRoot, { recursive: true });

  const startedAt = new Date().toISOString();
  const previous: BenchResults | null = opts.append ? (JSON.parse(readFileSync(opts.append, 'utf8')) as BenchResults) : null;
  const persist = (): { json: string; md: string } => {
    if (!previous) return writeOut(opts, results);
    const remeasured = new Set<string>((previous.options.remeasured as string[] | undefined) ?? []);
    for (const s of results.sites) remeasured.add(`${s.name} (${Object.keys(s.results).join('+')}) @ ${results.startedAt.slice(0, 16)}`);
    for (const [k, v] of Object.entries(results.browsers)) if (v) previous.browsers[k as BrowserKind] = v;
    previous.options.remeasured = [...remeasured];
    previous.finishedAt = results.finishedAt;
    return writeOut(opts, previous, opts.append!);
  };
  const results: BenchResults = {
    tool: 'bastion-shield-bench',
    version: 1,
    startedAt,
    finishedAt: '',
    machine: {
      platform: process.platform,
      release: os.release(),
      cpus: os.cpus().length,
      cpuModel: os.cpus()[0]?.model?.trim() ?? '?',
      memGb: Math.round(os.totalmem() / 1073741824),
      node: process.version,
    },
    options: { ...opts, sites: sites.map((s) => s.name) },
    browsers: {},
    reference: { hosts: 0, sources: [] },
    rea: { enabled: opts.rea, version: null, argv: null, note: '' },
    sites: [],
  };

  const ref: ReferenceSet = await loadReferenceSet({ dirs: opts.listsDirs, downloadDir: path.join(HERE, '.cache'), log });
  results.reference = { hosts: ref.hosts.size, sources: ref.sources };
  log(`reference set: ${ref.hosts.size} hosts (${ref.sources.map((s) => `${s.name} ${s.version}`).join(', ')})`);

  let rea: ReaRunner | null = null;
  if (opts.rea) {
    rea = await prepareRea(opts.reaBin, log);
    if (rea && !opts.reaBin) {
      const script = findNpxReaScript();
      if (script) {
        rea = { argv: [process.execPath, script], version: rea.version };
        log(`rea: using cached ${script}`);
      }
    }
    results.rea = {
      enabled: !!rea,
      version: rea?.version ?? null,
      argv: rea?.argv ?? null,
      note: rea
        ? 'REA scopes captures to the origins passed with --allowed-origins (here: every origin our CDP capture saw); its network section only covers its own observation window, its resource inventory covers everything the frames loaded.'
        : 'REA could not be started; see the run log.',
    };
  }

  const browsers = new Map<BrowserKind, LaunchedBrowser>();
  const userAgents = new Map<BrowserKind, string>();
  const extensionOrigins = new Map<BrowserKind, string>();
  const chromiumPath = opts.chromium ?? pwChromium.executablePath();
  const cleanup = async () => {
    for (const b of browsers.values()) await b.close().catch(() => {});
    browsers.clear();
  };
  process.on('SIGINT', () => {
    void cleanup().then(() => process.exit(130));
  });

  try {
    for (const kind of opts.browsers) {
      const entry: BenchResults['browsers'][BrowserKind] = { executable: '', product: '', headless: !opts.headed, ready: false, readyNote: '' };
      results.browsers[kind] = entry;
      try {
        if (withExtension(kind) && !existsSync(path.join(opts.dist, 'manifest.json'))) throw new Error(`no build at ${opts.dist}`);
        if (kind === 'brave' && !opts.brave) throw new Error('Brave not found (pass --brave <path>)');
        if (kind === 'edge' && !opts.edge) throw new Error('Edge not found (pass --edge <path>)');
        const executable = kind === 'brave' ? opts.brave! : kind === 'edge' ? opts.edge! : chromiumPath;
        entry.executable = executable;
        let headless = kind === 'brave' ? !(opts.headed || opts.braveHeaded) : !opts.headed;
        // Chromium writes _metadata/ into an unpacked extension's folder; load a copy so dist/ stays
        // pristine (one per browser, so two running browsers never write into the same folder).
        const extDir = withExtension(kind) ? path.join(opts.profileRoot, `${kind}-extension`) : undefined;
        if (extDir) {
          rmSync(extDir, { recursive: true, force: true });
          cpSync(opts.dist, extDir, { recursive: true, filter: (src) => path.basename(src) !== '_metadata' });
        }
        const launch = (h: boolean) => launchBrowser({ kind, executable, headless: h, userDataDir: path.join(opts.profileRoot, kind), extensionDir: extDir });
        let b = await launch(headless);
        browsers.set(kind, b); // registered for cleanup right away; re-set below if relaunched
        entry.product = b.product;
        log(`${kind}: ${b.product} on ${b.httpEndpoint}${headless ? ' (headless)' : ''}`);
        if (withExtension(kind)) {
          const manifest = JSON.parse(readFileSync(path.join(opts.dist, 'manifest.json'), 'utf8')) as { version: string; background?: { service_worker?: string } };
          entry.extensionVersion = manifest.version;
          const ext = await findExtension(b.cdp, 20_000, { version: manifest.version, swPath: manifest.background?.service_worker ?? 'background.js' });
          if (!ext) throw new Error('extension service worker did not start (load error?)');
          extensionOrigins.set(kind, ext.origin);
          entry.extensionId = ext.id;
          await sleep(3000); // install-time applyAll()
        }
        if (kind !== 'chromium') {
          let ready = await waitUntilBlocking(b, kind === 'brave' ? 120_000 : 30_000);
          if (!ready.ready && kind === 'brave' && headless) {
            log(`brave: headless probe failed (${ready.note}); retrying headed`);
            await b.close();
            headless = false;
            b = await launch(false);
            entry.product = b.product;
            ready = await waitUntilBlocking(b, 120_000);
          }
          entry.ready = ready.ready;
          entry.readyNote = ready.note;
          entry.headless = headless;
          log(`${kind}: ${ready.note}`);
        } else {
          entry.ready = true;
        }
        browsers.set(kind, b);
        const ver = await b.cdp.trySend<{ userAgent?: string }>('Browser.getVersion');
        if (ver?.userAgent && /HeadlessChrome/.test(ver.userAgent)) userAgents.set(kind, ver.userAgent.replace('HeadlessChrome', 'Chrome'));
      } catch (e) {
        entry.error = (e as Error).message.split('\n')[0];
        log(`${kind}: skipped: ${(e as Error).message}`);
        // A browser that started but failed its checks must not take part in the visits.
        await browsers.get(kind)?.close().catch(() => {});
        browsers.delete(kind);
      }
    }
    if (!browsers.size) throw new Error('no browser could be started');

    const order = [...browsers.keys()];
    for (const [i, site] of sites.entries()) {
      const entry: BenchResults['sites'][number] = { name: site.name, url: site.url, region: site.region, results: {}, rea: {} };
      results.sites.push(entry);
      if (previous) {
        // Merge per browser: re-measured browsers replace their old data for this site, others are kept.
        const i = previous.sites.findIndex((s) => s.name === site.name);
        if (i === -1) previous.sites.push(entry);
        else {
          previous.sites[i].results = { ...previous.sites[i].results, ...entry.results };
          previous.sites[i].rea = { ...previous.sites[i].rea, ...entry.rea };
        }
      }
      // Rotate the visiting order so no browser is always first on a site.
      const rot = order.map((_, j) => order[(i + j) % order.length]);
      for (const kind of rot) {
        const b = browsers.get(kind)!;
        log(`${site.name} @ ${kind} ...`);
        let reaResources: ReaResource[] = [];
        const cap = await captureSite(b.cdp, site.name, site.url, {
          settleMs: opts.settleMs,
          navTimeoutMs: opts.navTimeoutMs,
          ref,
          extensionOrigin: extensionOrigins.get(kind) ?? null,
          userAgent: userAgents.get(kind) ?? null,
          log,
          duringSettle: rea
            ? async (targetId, origins) => {
                await sleep(1500); // let post-load requests start so their origins are known
                const r = await reaInspect(rea!, {
                  endpoint: b.httpEndpoint,
                  targetId,
                  origins: origins(),
                  observationMs: opts.reaObservationMs,
                  outFile: path.join(opts.out, 'rea', kind, `${site.name.replace(/[^a-z0-9.-]/gi, '_')}.json`),
                });
                entry.rea[kind] = r.result;
                reaResources = r.resources;
              }
            : undefined,
        });
        // Cross-check now that our own classification of the visit is known.
        const rr = entry.rea[kind];
        if (rr?.ok) compareWithCapture(rr, reaResources, cap, ref);
        entry.results[kind] = summarize(cap, opts.saveRequests);
        const c = cap.counts;
        log(
          `  ${cap.ok ? 'ok' : 'FAILED ' + cap.error}: ${c.requests} req, ${c.blocked} blocked, ad/tracker ${c.adTrackerThrough} through / ${c.adTrackerAttempts} attempts, DCL ${cap.timings.dcl ?? '–'} ms, load ${cap.timings.load ?? '–'} ms, heap ${cap.heap.jsHeapUsed ? (cap.heap.jsHeapUsed / 1048576).toFixed(1) + ' MB' : '–'}` +
            (entry.rea[kind]
              ? ` | REA ${entry.rea[kind]!.ok ? `${entry.rea[kind]!.resources} resources, ${entry.rea[kind]!.check?.disagreements.length ?? 0} disagreements` : 'failed: ' + entry.rea[kind]!.error?.slice(0, 120)}`
              : ''),
        );
      }
      // Persist after every site so an interrupted run still leaves data.
      results.finishedAt = new Date().toISOString();
      persist();
    }
  } finally {
    await cleanup();
    // Profiles are removed by each browser's close(); the staged extension copy is ours to remove.
    try {
      for (const kind of opts.browsers) if (withExtension(kind)) rmSync(path.join(opts.profileRoot, `${kind}-extension`), { recursive: true, force: true, maxRetries: 3, retryDelay: 300 });
      if (!readdirSync(opts.profileRoot).length) rmSync(opts.profileRoot, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
  results.finishedAt = new Date().toISOString();
  const files = persist();
  log(`wrote ${files.json} and ${files.md}`);
}

function writeOut(opts: Options, results: BenchResults, file?: string): { json: string; md: string } {
  const json = file ?? path.join(opts.out, `${results.startedAt.slice(0, 19).replace(/:/g, '-')}.json`);
  writeFileSync(json, JSON.stringify(results, null, 1));
  const md = path.join(opts.out, 'summary.md');
  writeFileSync(md, summaryMarkdown(results));
  return { json, md };
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
