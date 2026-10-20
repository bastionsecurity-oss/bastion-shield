// Bastion Shield service worker — nerd mode (docs/NERD-MODE.md). Holds the
// per-tab nerd data the popup shows (fingerprinting meter, clipboard guard
// hits, lookalike warning) and routes bisect requests. Per-tab data lives in
// memory only and resets on every top-level navigation; a sleeping service
// worker forgets it, which is fine for a live meter.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { DEFAULT_PROTECTED, findLookalike } from '../shared/lookalike.ts';
import type { FpVector, LookalikeHit, MsgNerdBisect, MsgNerdSignal, NerdTabState, Settings } from '../shared/types.ts';
import { Bisector } from './nerd-bisect.ts';
import type { BisectDeps } from './nerd-bisect.ts';
import { parseUrl } from './util.ts';

const FP_VECTORS: ReadonlySet<string> = new Set<FpVector>(['canvas', 'webgl', 'audio', 'fonts', 'navigator', 'screen', 'media', 'timing']);
/** Cap per counter: a page calling an API in a hot loop must not overflow anything. */
const MAX_COUNT = 1_000_000;

interface TabNerd {
  fp: Partial<Record<FpVector, number>>;
  clipboardBlocked: number;
  lookalike: LookalikeHit | null;
}

export interface NerdDeps extends BisectDeps {
  settings(): Settings;
}

export class NerdService {
  private readonly tabs = new Map<number, TabNerd>();
  private readonly deps: NerdDeps;
  readonly bisector: Bisector;

  constructor(deps: NerdDeps) {
    this.deps = deps;
    this.bisector = new Bisector(deps);
  }

  private on(): Settings['nerd'] | null {
    const n = this.deps.settings().nerd;
    return n.enabled ? n : null;
  }

  private tab(tabId: number): TabNerd {
    let t = this.tabs.get(tabId);
    if (!t) {
      t = { fp: {}, clipboardBlocked: 0, lookalike: null };
      this.tabs.set(tabId, t);
    }
    return t;
  }

  /** Content relay -> SW. Values from the page are untrusted: only known vectors and bounded counts are kept. */
  onSignal(msg: MsgNerdSignal, tabId: number): { ok: true } | { error: string } {
    const n = this.on();
    if (!n || tabId < 0) return { ok: true };
    if (msg.kind === 'fp') {
      if (!n.fingerprintMeter || typeof msg.counts !== 'object' || msg.counts === null) return { ok: true };
      const t = this.tab(tabId);
      for (const [k, v] of Object.entries(msg.counts)) {
        if (!FP_VECTORS.has(k) || typeof v !== 'number' || !Number.isFinite(v) || v <= 0) continue;
        const key = k as FpVector;
        t.fp[key] = Math.min(MAX_COUNT, (t.fp[key] ?? 0) + Math.floor(v));
      }
      return { ok: true };
    }
    if (msg.kind === 'clip') {
      // Counted whoever blocked it: Bastion's guard, or uBlock filters'
      // prevent-clipboard-write, which blocks with ClickFix protection off too.
      const t = this.tab(tabId);
      t.clipboardBlocked = Math.min(MAX_COUNT, t.clipboardBlocked + 1);
      return { ok: true };
    }
    return { error: 'invalid signal' };
  }

  /**
   * Lookalike check for a top frame (cosmetic:frame reply). Remembered for
   * the popup.
   */
  lookalikeFor(url: string, tabId: number, frameId: number): LookalikeHit | null {
    const n = this.on();
    if (!n || !n.lookalike || frameId !== 0) return null;
    const u = parseUrl(url);
    if (!u || (u.protocol !== 'http:' && u.protocol !== 'https:')) return null;
    const hit = findLookalike(u.hostname.toLowerCase(), [...DEFAULT_PROTECTED, ...n.protectedDomains]);
    if (tabId >= 0) this.tab(tabId).lookalike = hit;
    return hit;
  }

  /** Top-level navigation committed: the page-load counters start over. */
  onCommitted(tabId: number, frameId: number): void {
    if (frameId !== 0) return;
    const t = this.tabs.get(tabId);
    if (t) {
      t.fp = {};
      t.clipboardBlocked = 0;
      t.lookalike = null;
    }
  }

  onTabRemoved(tabId: number): void {
    this.tabs.delete(tabId);
    this.bisector.onTabGone(tabId);
  }

  /**
   * Settings or policy changed. Switching nerd mode off ends every bisect
   * right away (its allow rules would otherwise outlive the feature).
   */
  onSettingsChanged(): void {
    if (!this.on()) void this.bisector.cancelAll();
  }

  bisect(msg: MsgNerdBisect): ReturnType<Bisector['handle']> {
    if (!this.on()) return Promise.resolve({ error: 'nerd mode is off' });
    if (typeof msg.tabId !== 'number' || msg.tabId < 0) return Promise.resolve({ error: 'invalid tab' });
    return this.bisector.handle(msg);
  }

  /** Popup data for a tab; null while nerd mode is off. */
  tabState(tabId: number): NerdTabState | null {
    const n = this.on();
    if (!n) return null;
    const t = this.tabs.get(tabId);
    return {
      fp: n.fingerprintMeter ? { ...(t?.fp ?? {}) } : null,
      clipboardBlocked: t?.clipboardBlocked ?? 0,
      lookalike: t?.lookalike ?? null,
      bisect: this.bisector.view(tabId),
    };
  }
}
