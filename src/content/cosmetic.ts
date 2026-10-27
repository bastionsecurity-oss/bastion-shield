// Bastion Shield — cosmetic content script (dist/content/cosmetic.js).
//
// Registered by the service worker: ISOLATED world, document_start, all
// frames, matchOriginAsFallback, <all_urls> minus sites with protection off
// (ARCHITECTURE §5.2). Per frame it
//   1. sends `cosmetic:frame` once and adopts the returned CSS immediately
//      (the SW also inserts it with origin USER, which survives page tricks;
//      the adopted copy only removes the latency),
//   2. hands procedural filters to content/procedural.js, which the SW
//      injects on request (`cosmetic:procedural`),
//   3. runs the generic id/class surveyor when the response allows it,
//      and, in Standard mode, un-hides soft selectors (selectors only
//      first-party-protected lists have) that match first-party content,
//   4. redirects AMP documents to their canonical URL (top frame only),
//   5. shows the blocker notices (content/notice.ts, top frame only): the
//      nerd mode lookalike-domain warning when the response carries one,
//      and «ClickFix blocked» for clipboard writes that uBO's
//      prevent-clipboard-write scriptlet or Bastion's own clipboard guard
//      (ClickFix protection, privacy.clipboardGuard) stopped. The scriptlet reports through a
//      synchronous window event whose name is a per-build token compiled
//      into both files (tools/lib/notice-transform.ts); subframes forward
//      their notices to the top frame through the service worker.
// The isolated world has its own JS built-ins, so page prototype tampering
// cannot reach this script; only the shared DOM is untrusted.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type {
  MsgCosmeticFrame,
  MsgCosmeticFrameResponse,
  MsgCosmeticTokens,
  MsgCosmeticTokensResponse,
  MsgNerdSignal,
  MsgNoticeClip,
  MsgNoticeShow,
  MsgProceduralInject,
  ProceduralFilter,
} from '../shared/types.ts';
import { clipSample } from '../main/clip-detect.ts';
import { isolatedGlobals } from './api.ts';
import { createNotices } from './notice.ts';
import type { NoticeApi } from './notice.ts';
import { NOTICE_SOURCES, parseUboDetail } from './notice-model.ts';
import type { NoticeSource } from './notice-model.ts';
import { deAmpTarget, frameContext, hasQueuedAncestor, isAmpHtml, SURVEY, surveyTokens, throttleDelay } from './tokens.ts';
import { firstPartyTest, isSubtreeFirstParty, showsSignificantText, UNHIDE, UnhideQueues } from './unhide.ts';

// Per-build event name of uBO's clipboard scriptlet -> notice channel, set
// by the build (esbuild define; tools/lib/notice-transform.ts). Unset when
// the file is not built by tools/build.ts (unit tests): no listener then.
declare const __BASTION_NOTICE_EVENT__: string | undefined;
const NOTICE_EVENT: string = typeof __BASTION_NOTICE_EVENT__ === 'string' ? __BASTION_NOTICE_EVENT__ : '';
/** uBO-blocked attempts reported to the nerd counter per page load. */
const MAX_CLIP_REPORTS = 50;

/** Delay before the single retry of a failed message (SW waking up / restarting). */
const RETRY_MS = 120;
const DEAMP_GUARD_KEY = 'bastion-deamp';
const DEAMP_GUARD_MS = 10_000;

const doc = document;
const now = (): number => performance.now();
let dead = false;

function runtimeAlive(): boolean {
  try {
    return !dead && typeof chrome === 'object' && chrome.runtime !== undefined && chrome.runtime.id !== undefined;
  } catch {
    return false;
  }
}

/**
 * sendMessage with one retry. Resolves undefined on failure; never rejects.
 * An invalidated extension context (update/reload while the page is open)
 * marks the script dead so every loop below winds down.
 */
function send<T>(msg: MsgCosmeticFrame | MsgCosmeticTokens | MsgProceduralInject): Promise<T | undefined> {
  return new Promise((resolve) => {
    const attempt = (retries: number): void => {
      if (!runtimeAlive()) {
        dead = true;
        resolve(undefined);
        return;
      }
      let p: Promise<unknown>;
      try {
        p = chrome.runtime.sendMessage(msg) as Promise<unknown>;
      } catch {
        dead = true;
        resolve(undefined);
        return;
      }
      const retry = (): void => {
        if (retries > 0 && runtimeAlive()) setTimeout(() => attempt(retries - 1), RETRY_MS);
        else resolve(undefined);
      };
      p.then((r) => {
        if (r === undefined || r === null) retry();
        else if (typeof r === 'object' && 'error' in (r as object)) resolve(undefined);
        else resolve(r as T);
      }, retry);
    };
    attempt(1);
  });
}

// ---------------------------------------------------------------------------
// CSS
// ---------------------------------------------------------------------------

function adoptCss(css: string): void {
  if (css === '') return;
  try {
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(css);
    const list = doc.adoptedStyleSheets;
    if (typeof list.push === 'function') list.push(sheet);
    else doc.adoptedStyleSheets = [...list, sheet];
    return;
  } catch {
    // Fall back to a <style> element (old engines, odd documents).
  }
  try {
    const style = doc.createElement('style');
    style.textContent = css;
    (doc.head ?? doc.documentElement)?.appendChild(style);
  } catch {
    // The SW's insertCSS still applies.
  }
}

// ---------------------------------------------------------------------------
// Procedural filters
// ---------------------------------------------------------------------------

function startProcedural(raw: unknown[]): void {
  const filters: ProceduralFilter[] = [];
  for (const s of raw) {
    if (typeof s !== 'string') continue;
    try {
      const f = JSON.parse(s) as unknown;
      if (f !== null && typeof f === 'object') filters.push(f as ProceduralFilter);
    } catch {
      // skip malformed entries
    }
  }
  if (filters.length === 0) return;
  const g = isolatedGlobals();
  g.bastionProceduralPending = g.bastionProceduralPending ? g.bastionProceduralPending.concat(filters) : filters;
  const flush = (): void => {
    const api = g.bastionProcedural;
    const list = g.bastionProceduralPending;
    if (api === undefined || list === undefined) return;
    g.bastionProceduralPending = undefined;
    try {
      api.apply(list);
    } catch {
      // engine errors stay inside the engine
    }
  };
  if (g.bastionProcedural !== undefined) {
    flush();
    return;
  }
  void send<unknown>({ type: 'cosmetic:procedural' }).then(flush);
}

// ---------------------------------------------------------------------------
// Standard-mode un-hiding (ARCHITECTURE §5.2.8, content/unhide.ts)
// ---------------------------------------------------------------------------

type SoftSink = (selectors: unknown) => void;

/**
 * Hides soft selectors in a sheet of their own (one rule per selector, so
 * each can be deleted) and un-hides those that match first-party content,
 * on Brave's idle-time schedule. Without a usable sheet the selectors are
 * hidden like the others.
 */
function startUnhider(site: string, base: string): SoftSink {
  let sheet: CSSStyleSheet | null = null;
  try {
    sheet = new CSSStyleSheet();
    const list = doc.adoptedStyleSheets;
    if (typeof list.push === 'function') list.push(sheet);
    else doc.adoptedStyleSheets = [...list, sheet];
  } catch {
    sheet = null;
  }
  if (sheet === null) {
    return (selectors) => {
      if (Array.isArray(selectors)) adoptCss(selectors.filter((s) => typeof s === 'string').map((s) => `${s}{display:none!important}`).join('\n'));
    };
  }
  const css = sheet;
  const queues = new UnhideQueues();
  const isFirstPartyUrl = firstPartyTest(site, base);
  const rules = new Map<string, CSSRule>();
  // Elements already found first party; they still un-hide every selector
  // that matches them (Brave skips them, which can leave one hidden).
  const firstParty = new WeakSet<Element>();
  const idle = (fn: () => void, timeout: number): void => {
    if (typeof requestIdleCallback === 'function') requestIdleCallback(fn, { timeout });
    else setTimeout(fn, 0);
  };
  let started = false;
  let scheduled = false;
  let sleeping = false;

  const query = (selectors: readonly string[]): ArrayLike<Element> => {
    try {
      return doc.querySelectorAll(selectors.join(','));
    } catch {
      // One selector the parser takes in a sheet but not in a query: go one by one.
      const out = new Set<Element>();
      for (const s of selectors) {
        try {
          for (const el of Array.from(doc.querySelectorAll(s))) out.add(el);
        } catch {
          // skip it
        }
      }
      return Array.from(out);
    }
  };

  const unhide = (selectors: ReadonlySet<string>): void => {
    for (const s of selectors) {
      const rule = rules.get(s);
      if (rule === undefined) continue;
      rules.delete(s);
      const i = Array.prototype.indexOf.call(css.cssRules, rule);
      if (i !== -1) css.deleteRule(i);
    }
  };

  const pump = (): void => {
    scheduled = false;
    if (dead) return;
    const work = queues.next();
    if (work === null) return;
    const found = new Set<string>();
    try {
      const matched = query(work.selectors);
      const n = Math.min(matched.length, UNHIDE.MAX_ELEMENTS_PER_PUMP);
      for (let i = 0; i < n; i++) {
        const el = matched[i];
        if (!firstParty.has(el)) {
          if (!isSubtreeFirstParty(el, isFirstPartyUrl) && !showsSignificantText(el as HTMLElement)) continue;
          firstParty.add(el);
        }
        for (const s of work.selectors) {
          if (found.has(s)) continue;
          try {
            if (el.matches(s)) found.add(s);
          } catch {
            // ignore
          }
        }
      }
      unhide(found);
    } catch {
      // A detached or exotic node: the selectors move on and stay hidden.
    }
    queues.settle(work, found);
    sleeping = true;
    setTimeout(() => {
      sleeping = false;
      schedule();
    }, UNHIDE.PUMP_MIN_MS);
  };

  const schedule = (): void => {
    if (!started || scheduled || sleeping || queues.pending === 0) return;
    scheduled = true;
    idle(pump, UNHIDE.PUMP_MAX_MS);
  };

  idle(() => {
    started = true;
    schedule();
  }, UNHIDE.START_MAX_MS);

  return (selectors) => {
    if (!Array.isArray(selectors)) return;
    const added: string[] = [];
    for (const s of selectors) {
      if (typeof s !== 'string' || s === '' || rules.has(s)) continue;
      try {
        const i = css.insertRule(`${s}{display:none!important}`, css.cssRules.length);
        rules.set(s, css.cssRules[i]);
        added.push(s);
      } catch {
        // Invalid selector: never hidden (Brave does the same).
      }
    }
    if (queues.add(added) !== 0) schedule();
  };
}

// ---------------------------------------------------------------------------
// Generic surveyor (ARCHITECTURE §5.2.3)
// ---------------------------------------------------------------------------

function startSurveyor(url: string, isTop: boolean, soft: SoftSink | null): void {
  const interval = isTop ? SURVEY.INTERVAL_TOP : SURVEY.INTERVAL_SUB;
  const seen = new Set<string>();
  // Raw class strings already tokenised (PERF-3: almost all are repeats).
  const seenClass = new Set<string>();
  let pending: string[] = [];
  // Work queues: snapshot lists (querySelectorAll results), added subtree
  // roots, and elements whose id/class attribute changed. `queued` mirrors
  // `roots` (dedupe, and lets a root skip its subtree when an ancestor that
  // is still queued will query it anyway). `attrs` drops back-to-back
  // records of one element (classList.add + remove, toggles): the scan reads
  // the current value, which covers every change.
  let lists: ArrayLike<Element>[] = [];
  let listPos = 0;
  let roots: Element[] = [];
  let queued = new Set<Element>();
  let attrs: Element[] = [];
  let stopped = false;
  let runTimer = 0;
  let flushTimer = 0;
  let idleTimer = 0;
  let lastRun = -Infinity;
  let lastSend = -Infinity;
  let inFlight = false;
  let emptyFlushes = 0;
  let lastNewToken = now();
  let observer: MutationObserver | null = null;

  const scan = (el: Element): void => {
    let id: string | null = null;
    let cls: string | null = null;
    try {
      id = el.getAttribute('id');
      cls = el.getAttribute('class');
    } catch {
      return;
    }
    if (surveyTokens(id, cls, seen, seenClass, pending) !== 0) lastNewToken = now();
  };

  const clearQueues = (): void => {
    lists = [];
    listPos = 0;
    roots = [];
    queued = new Set<Element>();
    attrs = [];
  };

  const stop = (): void => {
    if (stopped) return;
    stopped = true;
    if (observer !== null) {
      observer.disconnect();
      observer = null;
    }
    clearTimeout(runTimer);
    clearTimeout(flushTimer);
    clearTimeout(idleTimer);
    clearQueues();
    seenClass.clear();
  };

  /** Scan queued work for at most SLICE_MS; true when the queues are empty. */
  const work = (): boolean => {
    const deadline = now() + SURVEY.SLICE_MS;
    let n = 0;
    for (;;) {
      if (lists.length !== 0) {
        const list = lists[0];
        if (listPos < list.length) {
          scan(list[listPos++]);
        } else {
          lists.shift();
          listPos = 0;
          continue;
        }
      } else if (attrs.length !== 0) {
        scan(attrs.pop() as Element);
      } else if (roots.length !== 0) {
        const el = roots.pop() as Element;
        queued.delete(el);
        if (!el.isConnected) continue;
        if (el.firstElementChild === null) {
          scan(el); // leaf: one memoised lookup, cheaper than the ancestor walk
        } else if (!hasQueuedAncestor(el, queued, SURVEY.MAX_ANCESTOR_WALK)) {
          scan(el);
          lists.push(el.querySelectorAll('[id],[class]'));
        }
        // Otherwise a still-queued ancestor's query will cover el's subtree.
      } else {
        return true;
      }
      if ((++n & 31) === 0 && now() >= deadline) return false;
    }
  };

  const flush = (): void => {
    if (stopped || inFlight || pending.length === 0) return;
    const wait = throttleDelay(now(), lastSend, interval);
    if (wait > 0) {
      if (flushTimer === 0) {
        flushTimer = setTimeout(() => {
          flushTimer = 0;
          flush();
        }, wait) as unknown as number;
      }
      return;
    }
    let tokens: string[];
    if (pending.length > SURVEY.MAX_TOKENS_PER_MESSAGE) {
      tokens = pending.slice(0, SURVEY.MAX_TOKENS_PER_MESSAGE);
      pending = pending.slice(SURVEY.MAX_TOKENS_PER_MESSAGE);
    } else {
      tokens = pending;
      pending = [];
    }
    inFlight = true;
    lastSend = now();
    void send<MsgCosmeticTokensResponse>({ type: 'cosmetic:tokens', url, tokens }).then((r) => {
      inFlight = false;
      if (dead) {
        stop();
        return;
      }
      const hasSoft = r !== undefined && Array.isArray(r.soft) && r.soft.length !== 0;
      if (hasSoft) {
        if (soft !== null) soft(r.soft);
        else adoptCss(r.soft!.map((s) => `${s}{display:none!important}`).join('\n'));
      }
      if (r !== undefined && typeof r.css === 'string' && r.css !== '') {
        adoptCss(r.css);
        emptyFlushes = 0;
      } else if (hasSoft) {
        emptyFlushes = 0;
      } else if (++emptyFlushes >= SURVEY.MAX_EMPTY_FLUSHES) {
        stop();
        return;
      }
      flush();
    });
  };

  const run = (): void => {
    runTimer = 0;
    if (stopped) return;
    lastRun = now();
    let finished = true;
    try {
      finished = work();
    } catch {
      // A detached or exotic node: skip what is left of this batch.
      clearQueues();
    }
    if (seen.size > SURVEY.MAX_SEEN_TOKENS) {
      stop();
      return;
    }
    flush();
    // Continue a long scan in the next task; new mutations wait for the interval.
    if (!finished) runTimer = setTimeout(run, 0) as unknown as number;
  };

  const schedule = (): void => {
    if (stopped || runTimer !== 0) return;
    runTimer = setTimeout(run, throttleDelay(now(), lastRun, interval)) as unknown as number;
  };

  const onMutations = (records: MutationRecord[]): void => {
    if (dead) {
      stop();
      return;
    }
    const html = doc.documentElement;
    const body = doc.body;
    for (const m of records) {
      if (m.type === 'childList') {
        const added = m.addedNodes;
        for (let i = 0; i < added.length; i++) {
          const node = added[i];
          if (node.nodeType === 1 && !queued.has(node as Element)) {
            queued.add(node as Element);
            roots.push(node as Element);
          }
        }
      } else {
        // <html>/<body> class churn (scroll state, themes) is never rescanned.
        const t = m.target as Element;
        if (t !== html && t !== body && (attrs.length === 0 || attrs[attrs.length - 1] !== t)) attrs.push(t);
      }
    }
    if (roots.length + attrs.length > SURVEY.MAX_QUEUED_NODES) {
      // Collapse a huge backlog (e.g. a throttled background tab) into one rescan.
      clearQueues();
      lists = [doc.querySelectorAll('[id],[class]')];
      listPos = 0;
    }
    schedule();
  };

  const idleCheck = (): void => {
    idleTimer = 0;
    if (stopped) return;
    const idle = now() - lastNewToken;
    if (idle >= SURVEY.IDLE_STOP_MS) {
      stop();
      return;
    }
    idleTimer = setTimeout(idleCheck, SURVEY.IDLE_STOP_MS - idle + 50) as unknown as number;
  };

  try {
    // Snapshot what exists now (html/body included, once), then observe the
    // whole document so nothing parsed or inserted later is missed.
    lists.push(doc.querySelectorAll('[id],[class]'));
    observer = new MutationObserver(onMutations);
    observer.observe(doc, { childList: true, subtree: true, attributes: true, attributeFilter: ['id', 'class'] });
  } catch {
    stop();
    return;
  }
  idleTimer = setTimeout(idleCheck, SURVEY.IDLE_STOP_MS) as unknown as number;
  run();
}

// ---------------------------------------------------------------------------
// De-AMP (ARCHITECTURE §5.2.6)
// ---------------------------------------------------------------------------

/** True when we redirected to `target` moments ago: the canonical page bounced us back. */
function deAmpLoop(target: string): boolean {
  try {
    const store = sessionStorage;
    const prev = store.getItem(DEAMP_GUARD_KEY);
    if (prev !== null) {
      const p = JSON.parse(prev) as { u?: unknown; t?: unknown };
      if (p.u === target && typeof p.t === 'number' && Date.now() - p.t < DEAMP_GUARD_MS) return true;
    }
    store.setItem(DEAMP_GUARD_KEY, JSON.stringify({ u: target, t: Date.now() }));
  } catch {
    // Storage unavailable: rely on the referrer check in deAmpTarget.
  }
  return false;
}

function startDeAmp(): void {
  const html = doc.documentElement;
  if (html === null || !isAmpHtml((n) => html.hasAttribute(n))) return;
  let done = false;
  let observer: MutationObserver | null = null;
  const attempt = (): void => {
    if (done) return;
    const link = doc.querySelector('link[rel~="canonical" i][href]') as HTMLLinkElement | null;
    if (link === null) return;
    done = true;
    observer?.disconnect();
    const target = deAmpTarget(link.href, location.href, doc.referrer);
    if (target === null || deAmpLoop(target)) return;
    try {
      location.replace(target);
    } catch {
      // navigation blocked (sandbox): stay on the AMP page
    }
  };
  attempt();
  if (done) return;
  try {
    observer = new MutationObserver(attempt);
    observer.observe(doc, { childList: true, subtree: true });
  } catch {
    observer = null;
  }
  doc.addEventListener(
    'DOMContentLoaded',
    () => {
      attempt();
      done = true;
      observer?.disconnect();
    },
    { once: true },
  );
}

// ---------------------------------------------------------------------------
// Blocker notices (content/notice.ts)
// ---------------------------------------------------------------------------

/** Fire-and-forget message to the SW. */
function post(msg: MsgNerdSignal | MsgNoticeClip): void {
  if (!runtimeAlive()) return;
  try {
    const p = chrome.runtime.sendMessage(msg) as Promise<unknown> | undefined;
    if (p !== undefined && typeof p.then === 'function') p.then(undefined, () => undefined);
  } catch {
    dead = true;
  }
}

/**
 * Creates the notice API, hands it to nerd-relay.js (shared isolated world)
 * and listens for uBO's clipboard scriptlet. Registered synchronously at
 * document_start, before any page script and before the scriptlet traps
 * (which uBO installs on the first mousemove).
 */
function startNotices(isTop: boolean): NoticeApi {
  const g = isolatedGlobals();
  const api = createNotices({
    isTop,
    forward: (text: string, source: NoticeSource) => post({ type: 'notice:clip', text, source }),
  });
  g.bastionNotice = api;
  const pending = g.bastionNoticePending;
  g.bastionNoticePending = undefined;
  if (pending !== undefined) for (const n of pending) api.clip(n.text, n.source);

  if (NOTICE_EVENT !== '') {
    let reports = 0;
    window.addEventListener(
      NOTICE_EVENT,
      (ev: Event) => {
        let detail: unknown;
        try {
          detail = (ev as CustomEvent<unknown>).detail;
          // Page listeners never see the blocked text.
          ev.stopImmediatePropagation();
        } catch {
          return;
        }
        const text = parseUboDetail(detail);
        if (text === null) return;
        // Nerd mode clip counter (the SW ignores it while nerd mode is off).
        if (reports < MAX_CLIP_REPORTS) {
          reports++;
          post({ type: 'nerd:signal', kind: 'clip', sample: clipSample(text) });
        }
        api.clip(text, 'ubo');
      },
      true,
    );
  }

  if (isTop) {
    // Notices of subframes, forwarded by the SW (MsgNoticeShow).
    chrome.runtime.onMessage.addListener((msg: unknown, sender: chrome.runtime.MessageSender) => {
      try {
        if (sender.id !== chrome.runtime.id || sender.tab !== undefined) return;
        const m = msg as Partial<MsgNoticeShow> | null;
        if (m === null || typeof m !== 'object' || m.type !== 'notice:show') return;
        if (typeof m.text !== 'string' || typeof m.source !== 'string' || !NOTICE_SOURCES.has(m.source)) return;
        api.clip(m.text, m.source as NoticeSource);
      } catch {
        // ignore
      }
    });
  }
  return api;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main(): void {
  const g = isolatedGlobals();
  if (g.bastionCosmeticLoaded) return;
  g.bastionCosmeticLoaded = true;
  if (!runtimeAlive()) return;

  let isTop = true;
  try {
    isTop = window.top === window;
  } catch {
    isTop = false;
  }
  let notices: NoticeApi | null = null;
  try {
    notices = startNotices(isTop);
  } catch {
    notices = null;
  }
  let ctx: ReturnType<typeof frameContext>;
  try {
    ctx = frameContext(location.href, location.origin, location.ancestorOrigins, isTop);
  } catch {
    return;
  }
  const { url, topUrl } = ctx;

  void send<MsgCosmeticFrameResponse>({ type: 'cosmetic:frame', url, topUrl }).then((r) => {
    if (r === undefined || typeof r !== 'object' || r.off === true) return;
    try {
      if (typeof r.css === 'string') adoptCss(r.css);
    } catch {
      // ignore
    }
    let soft: SoftSink | null = null;
    try {
      if (Array.isArray(r.soft) && typeof r.site === 'string' && r.site !== '') {
        soft = startUnhider(r.site, url);
        soft(r.soft);
      }
    } catch {
      soft = null;
    }
    try {
      if (Array.isArray(r.procedural) && r.procedural.length !== 0) startProcedural(r.procedural);
    } catch {
      // ignore
    }
    try {
      if (r.generic === true) startSurveyor(url, isTop, soft);
    } catch {
      // ignore
    }
    try {
      if (r.deAmp === true && isTop) startDeAmp();
    } catch {
      // ignore
    }
    try {
      if (isTop && r.lookalike && notices !== null) notices.lookalike(r.lookalike);
    } catch {
      // ignore
    }
  });
}

try {
  main();
} catch {
  // Never let an exception escape into the console of the page.
}
