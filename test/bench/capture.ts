// Bastion Shield bench — capture one site visit in one browser over CDP:
// every request of the page and of all (out-of-process) iframes and workers
// via Network.requestWillBeSent / responseReceived / loadingFailed /
// loadingFinished, navigation timings, the page's JS heap and, for the
// extension run, the service worker's heap.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { registrableDomain } from '../../src/shared/hash.ts';
import type { Cdp } from './cdp.ts';
import type { ReferenceSet } from './reference.ts';

export interface RequestRecord {
  url: string;
  host: string;
  type: string;
  sessionKind: string;
  redirects: string[];
  finalUrl: string;
  status: number | null;
  failed: string | null;
  blockedReason: string | null;
  finished: boolean;
  bytes: number;
  remoteIP: string | null;
  protocol: string | null;
  fromCache: boolean;
  /** Served without a network connection (Brave's in-process $redirect stubs). */
  stub: boolean;
  /** Replaced by a neutered resource (extension redirect or in-process stub); counted as blocked. */
  neutered: boolean;
  /** Blocked by a content blocker: ERR_BLOCKED_BY_CLIENT, subresource filter, or redirect to a neutered resource. */
  blocked: boolean;
  thirdParty: boolean;
  adTracker: boolean;
}

export interface SiteCapture {
  site: string;
  url: string;
  finalUrl: string | null;
  ok: boolean;
  error: string | null;
  targetId: string | null;
  timings: { dcl: number | null; load: number | null; loadEventSeen: boolean; navigateMs: number };
  heap: { jsHeapUsed: number | null; jsHeapTotal: number | null; nodes: number | null; documents: number | null };
  /** Extension SW heap right after the load event (it is busy then). */
  serviceWorkerAtLoad: { url: string; usedSize: number; totalSize: number } | null;
  /** Extension SW heap at the end of the visit; null = Chromium already stopped the idle SW. */
  serviceWorker: { url: string; usedSize: number; totalSize: number } | null;
  counts: {
    requests: number;
    blocked: number;
    thirdParty: number;
    adTrackerAttempts: number;
    adTrackerBlocked: number;
    adTrackerThrough: number;
    adTrackerOtherFailed: number;
    bytes: number;
  };
  throughHosts: Record<string, number>;
  blockedHosts: Record<string, number>;
  failures: Record<string, number>;
  requests: RequestRecord[];
}

interface Raw {
  url: string;
  type: string;
  sessionKind: string;
  redirects: string[];
  status: number | null;
  failed: string | null;
  blockedReason: string | null;
  finished: boolean;
  bytes: number;
  remoteIP: string | null;
  protocol: string | null;
  fromCache: boolean;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function hostOf(u: string): string {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function isNeuteredTarget(u: string): boolean {
  return u.startsWith('chrome-extension://') || u.startsWith('data:') || u.startsWith('brave://');
}

export interface CaptureOptions {
  settleMs: number;
  navTimeoutMs: number;
  ref: ReferenceSet;
  /** Extension origin to find the SW for heap stats (bastion run). */
  extensionOrigin?: string | null;
  /**
   * User agent to present instead of the headless one. Several sites (Akamai /
   * Cloudflare bot rules) reset HTTP/2 streams for "HeadlessChrome"; every
   * browser gets the same treatment so the comparison stays fair.
   */
  userAgent?: string | null;
  /** Called once the load event fired (or timed out) with the page target id; runs during the settle window. */
  duringSettle?: (targetId: string, observedOrigins: () => string[]) => Promise<void>;
  log: (s: string) => void;
}

export async function captureSite(cdp: Cdp, site: string, url: string, opts: CaptureOptions): Promise<SiteCapture> {
  const raws = new Map<string, Raw>();
  const kinds = new Map<string, string>(); // sessionId -> target type
  const offs: (() => void)[] = [];
  const result: SiteCapture = {
    site,
    url,
    finalUrl: null,
    ok: false,
    error: null,
    targetId: null,
    timings: { dcl: null, load: null, loadEventSeen: false, navigateMs: 0 },
    heap: { jsHeapUsed: null, jsHeapTotal: null, nodes: null, documents: null },
    serviceWorkerAtLoad: null,
    serviceWorker: null,
    counts: { requests: 0, blocked: 0, thirdParty: 0, adTrackerAttempts: 0, adTrackerBlocked: 0, adTrackerThrough: 0, adTrackerOtherFailed: 0, bytes: 0 },
    throughHosts: {},
    blockedHosts: {},
    failures: {},
    requests: [],
  };
  let targetId: string | null = null;
  let session: string | undefined;
  const ours = (s: string | undefined) => !!s && kinds.has(s);
  const key = (s: string | undefined, id: string) => `${s}|${id}`;

  offs.push(
    cdp.on('Network.requestWillBeSent', (p, s) => {
      if (!ours(s)) return;
      const k = key(s, p.requestId);
      const existing = raws.get(k);
      if (existing && p.redirectResponse) {
        existing.redirects.push(p.request.url);
        return;
      }
      raws.set(k, {
        url: p.request.url,
        type: p.type ?? 'Other',
        sessionKind: kinds.get(s!) ?? '?',
        redirects: [],
        status: null,
        failed: null,
        blockedReason: null,
        finished: false,
        bytes: 0,
        remoteIP: null,
        protocol: null,
        fromCache: false,
      });
    }),
    cdp.on('Network.responseReceived', (p, s) => {
      const r = raws.get(key(s, p.requestId));
      if (!r) return;
      const res = p.response ?? {};
      r.status = res.status ?? r.status;
      r.remoteIP = res.remoteIPAddress || null;
      r.protocol = res.protocol || null;
      if (res.fromDiskCache || res.fromServiceWorker || res.fromPrefetchCache) r.fromCache = true;
    }),
    cdp.on('Network.requestServedFromCache', (p, s) => {
      const r = raws.get(key(s, p.requestId));
      if (r) r.fromCache = true;
    }),
    cdp.on('Network.loadingFinished', (p, s) => {
      const r = raws.get(key(s, p.requestId));
      if (r) {
        r.finished = true;
        r.bytes = p.encodedDataLength ?? 0;
      }
    }),
    cdp.on('Network.loadingFailed', (p, s) => {
      const r = raws.get(key(s, p.requestId));
      if (r) {
        r.failed = p.errorText ?? 'failed';
        r.blockedReason = p.blockedReason ?? null;
      }
    }),
    // Out-of-process iframes and workers: enable Network before they run.
    cdp.on('Target.attachedToTarget', (p, parent) => {
      if (!ours(parent)) return;
      const child: string = p.sessionId;
      const type: string = p.targetInfo?.type ?? 'other';
      kinds.set(child, type);
      void (async () => {
        await cdp.trySend('Network.enable', {}, child);
        if (opts.userAgent && (type === 'iframe' || type === 'page')) await cdp.trySend('Emulation.setUserAgentOverride', { userAgent: opts.userAgent }, child);
        if (type === 'iframe' || type === 'page') {
          await cdp.trySend('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, child);
        }
        await cdp.trySend('Runtime.runIfWaitingForDebugger', {}, child);
      })();
    }),
  );

  const t0 = Date.now();
  try {
    const created = await cdp.send<{ targetId: string }>('Target.createTarget', { url: 'about:blank' });
    targetId = created.targetId;
    result.targetId = targetId;
    const att = await cdp.send<{ sessionId: string }>('Target.attachToTarget', { targetId, flatten: true });
    session = att.sessionId;
    kinds.set(session, 'page');
    await cdp.send('Network.enable', {}, session);
    if (opts.userAgent) await cdp.trySend('Emulation.setUserAgentOverride', { userAgent: opts.userAgent }, session);
    await cdp.send('Page.enable', {}, session);
    await cdp.trySend('Performance.enable', {}, session);
    await cdp.trySend('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, session);

    const loadP = cdp.waitFor('Page.loadEventFired', (_p, s) => s === session, opts.navTimeoutMs);
    const nav = await cdp.send<{ frameId: string; errorText?: string }>('Page.navigate', { url }, session, opts.navTimeoutMs);
    if (nav.errorText) throw new Error(`navigate: ${nav.errorText}`);
    const loaded = await loadP;
    result.timings.loadEventSeen = !!loaded;
    result.timings.navigateMs = Date.now() - t0;

    const timing = await cdp.trySend<{ result: { value?: { dcl: number; load: number; url: string } } }>(
      'Runtime.evaluate',
      {
        expression:
          '(() => { const n = performance.getEntriesByType("navigation")[0]; return n ? { dcl: n.domContentLoadedEventEnd, load: n.loadEventEnd, url: location.href } : { dcl: -1, load: -1, url: location.href }; })()',
        returnByValue: true,
      },
      session,
    );
    const tv = timing?.result?.value;
    if (tv) {
      result.timings.dcl = tv.dcl > 0 ? Math.round(tv.dcl) : null;
      result.timings.load = tv.load > 0 ? Math.round(tv.load) : null;
      result.finalUrl = tv.url;
    }

    if (opts.extensionOrigin) result.serviceWorkerAtLoad = await serviceWorkerHeap(cdp, opts.extensionOrigin);

    const observedOrigins = () => {
      const s = new Set<string>();
      for (const r of raws.values()) {
        try {
          const o = new URL(r.url).origin;
          if (o.startsWith('http')) s.add(o);
        } catch {
          /* ignore */
        }
      }
      return [...s];
    };
    const settle = sleep(opts.settleMs);
    const side = opts.duringSettle ? opts.duringSettle(targetId, observedOrigins).catch((e) => opts.log(`  side task failed: ${(e as Error).message}`)) : Promise.resolve();
    await Promise.all([settle, side]);

    const metrics = await cdp.trySend<{ metrics: { name: string; value: number }[] }>('Performance.getMetrics', {}, session);
    const m = new Map((metrics?.metrics ?? []).map((x) => [x.name, x.value]));
    result.heap = {
      jsHeapUsed: m.get('JSHeapUsedSize') ?? null,
      jsHeapTotal: m.get('JSHeapTotalSize') ?? null,
      nodes: m.get('Nodes') ?? null,
      documents: m.get('Documents') ?? null,
    };
    if (opts.extensionOrigin) result.serviceWorker = await serviceWorkerHeap(cdp, opts.extensionOrigin);
    result.ok = true;
  } catch (e) {
    result.error = (e as Error).message;
  } finally {
    for (const off of offs) off();
    if (targetId) await cdp.trySend('Target.closeTarget', { targetId }, undefined, 5000);
  }

  const pageHost = hostOf(result.finalUrl ?? url);
  const pageSite = registrableDomain(pageHost);
  for (const r of raws.values()) {
    if (!/^https?:/.test(r.url)) continue;
    const host = hostOf(r.url);
    const finalUrl = r.redirects.length ? r.redirects[r.redirects.length - 1] : r.url;
    // Bastion's DNR redirects show up as a hop to chrome-extension://. Brave
    // serves its $redirect stubs in-process: a 200 with no remote address that
    // did not come from a cache (verified against plain Chromium, where every
    // non-cached response has a remoteIPAddress).
    const stub = r.status !== null && !r.failed && !r.fromCache && !r.remoteIP;
    const neutered = r.redirects.some(isNeuteredTarget) || stub;
    // Only content-blocker outcomes count; ERR_BLOCKED_BY_ORB / _RESPONSE / CSP are the browser's own.
    const blocked = neutered || r.failed === 'net::ERR_BLOCKED_BY_CLIENT' || r.blockedReason === 'subresource-filter';
    const thirdParty = registrableDomain(host) !== pageSite;
    const rec: RequestRecord = {
      url: r.url,
      host,
      type: r.type,
      sessionKind: r.sessionKind,
      redirects: r.redirects,
      finalUrl,
      status: r.status,
      failed: r.failed,
      blockedReason: r.blockedReason,
      finished: r.finished,
      bytes: r.bytes,
      remoteIP: r.remoteIP,
      protocol: r.protocol,
      fromCache: r.fromCache,
      stub,
      neutered,
      blocked,
      thirdParty,
      adTracker: thirdParty && opts.ref.matches(host),
    };
    result.requests.push(rec);
    const c = result.counts;
    c.requests++;
    c.bytes += rec.bytes;
    if (blocked) {
      c.blocked++;
      result.blockedHosts[host] = (result.blockedHosts[host] ?? 0) + 1;
    }
    if (thirdParty) c.thirdParty++;
    if (rec.failed && !blocked) result.failures[rec.failed] = (result.failures[rec.failed] ?? 0) + 1;
    if (rec.adTracker) {
      c.adTrackerAttempts++;
      if (blocked) c.adTrackerBlocked++;
      else if (rec.status !== null || rec.finished) {
        c.adTrackerThrough++;
        result.throughHosts[host] = (result.throughHosts[host] ?? 0) + 1;
      } else c.adTrackerOtherFailed++;
    }
  }
  return result;
}

/** Heap of the extension's service worker, if it is running. */
export async function serviceWorkerHeap(cdp: Cdp, origin: string): Promise<{ url: string; usedSize: number; totalSize: number } | null> {
  const t = await cdp.trySend<{ targetInfos: { targetId: string; type: string; url: string }[] }>('Target.getTargets');
  const sw = t?.targetInfos.find((x) => x.type === 'service_worker' && x.url.startsWith(origin));
  if (!sw) return null;
  const att = await cdp.trySend<{ sessionId: string }>('Target.attachToTarget', { targetId: sw.targetId, flatten: true });
  if (!att) return null;
  try {
    const h = await cdp.trySend<{ usedSize: number; totalSize: number }>('Runtime.getHeapUsage', {}, att.sessionId);
    return h ? { url: sw.url, usedSize: h.usedSize, totalSize: h.totalSize } : null;
  } finally {
    await cdp.trySend('Target.detachFromTarget', { sessionId: att.sessionId });
  }
}
