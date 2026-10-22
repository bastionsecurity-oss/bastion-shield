// Bastion Shield — pure helpers for the popup: normalising the service
// worker's popup:state reply (so a partial or older reply never breaks
// rendering) and reading the optional ?tabId=<n> override. DOM-free so it can
// be unit tested.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { PopupState } from '../../shared/types.ts';

/**
 * Tab id from the popup URL (`popup.html?tabId=42`). Used when the popup is
 * opened as a normal tab (tests, keyboard-only users who open it from the
 * dashboard), where chrome.tabs.query would return the popup's own tab.
 */
export function tabIdFromSearch(search: string): number | null {
  try {
    const raw = new URLSearchParams(search).get('tabId');
    if (raw === null || !/^\d{1,10}$/.test(raw)) return null;
    const n = Number(raw);
    return Number.isSafeInteger(n) && n >= 0 ? n : null;
  } catch {
    return null;
  }
}

const num = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : 0);

/** Fill defaults so a partial or older service-worker reply can never break rendering. */
export function normalisePopupState(raw: unknown, fallbackTabId: number): PopupState {
  const r = (raw && typeof raw === 'object' ? raw : {}) as Partial<PopupState>;
  const c = (r.counts ?? {}) as Partial<PopupState['counts']>;
  const fp = r.siteSettings?.fingerprinting;
  const channel = r.managed?.reportBrokenSite;
  const supportEmail = typeof r.managed?.supportEmail === 'string' && r.managed.supportEmail ? r.managed.supportEmail : undefined;
  return {
    tabId: typeof r.tabId === 'number' ? r.tabId : fallbackTabId,
    url: typeof r.url === 'string' ? r.url : null,
    host: typeof r.host === 'string' ? r.host : null,
    site: typeof r.site === 'string' ? r.site : null,
    filterable: r.filterable !== false,
    siteSettings: {
      enabled: r.siteSettings?.enabled !== false,
      mode: r.siteSettings?.mode === 'aggressive' ? 'aggressive' : 'standard',
      blockScripts: !!r.siteSettings?.blockScripts,
      fingerprinting: fp === 'off' || fp === 'strict' ? fp : 'standard',
    },
    counts: { blocked: num(c.blocked), redirected: num(c.redirected), stripped: num(c.stripped), debounced: num(c.debounced), thirdPartyHosts: num(c.thirdPartyHosts) },
    totals: r.totals ?? { since: 0, blocked: 0, byKind: {} },
    recent: Array.isArray(r.recent) ? r.recent.filter((e) => e && typeof e === 'object' && typeof e.t === 'number') : [],
    // Older service workers did not report these: assume the documented defaults.
    logging: r.logging !== false,
    counting: r.counting !== false,
    globallyDisabled: r.globallyDisabled === true,
    locks: { siteToggle: !!r.locks?.siteToggle, mode: !!r.locks?.mode, settings: !!r.locks?.settings },
    managed: {
      organizationName: typeof r.managed?.organizationName === 'string' && r.managed.organizationName ? r.managed.organizationName : undefined,
      supportUrl: typeof r.managed?.supportUrl === 'string' && r.managed.supportUrl ? r.managed.supportUrl : undefined,
      supportEmail,
      // Documented default: e-mail when a helpdesk address is set, otherwise GitHub.
      reportBrokenSite: channel === 'github' || channel === 'email' || channel === 'none' ? channel : supportEmail ? 'email' : 'github',
    },
    incidentCta: r.incidentCta !== false,
    nerd: r.nerd && typeof r.nerd === 'object' ? r.nerd : null,
    version: typeof r.version === 'string' ? r.version : '',
  };
}

// ------------------------------------------------------- connection state --

/**
 * P07 «Keine Verbindung»: the popup asks the service worker for popup:state;
 * when that fails it shows the error tile with «Erneut versuchen», which asks
 * again. The tile stays while a retry runs (the button shows the spinner), so
 * a retry that fails again does not flicker.
 */
export type ConnPhase = 'loading' | 'ready' | 'error';
export interface ConnState {
  phase: ConnPhase;
  /** A retry from the error tile is running. */
  retrying: boolean;
  /** Failed requests in a row (reset on success). */
  failures: number;
}
export type ConnEvent = 'request' | 'ok' | 'fail';

export const CONN_INITIAL: ConnState = { phase: 'loading', retrying: false, failures: 0 };

/** After this many failures in a row the restart hint is emphasised. */
export const CONN_HINT_AFTER = 3;

export function connReduce(s: ConnState, e: ConnEvent): ConnState {
  switch (e) {
    case 'request':
      // From the error tile: keep it, mark the retry. Otherwise: loading.
      return s.phase === 'error' ? { ...s, retrying: true } : { ...s, phase: s.phase === 'ready' ? 'ready' : 'loading', retrying: false };
    case 'ok':
      return { phase: 'ready', retrying: false, failures: 0 };
    case 'fail':
      // A refresh of a drawn popup that fails keeps the popup (live counters still run).
      if (s.phase === 'ready') return { ...s, retrying: false };
      return { phase: 'error', retrying: false, failures: s.failures + 1 };
  }
}

// -------------------------------------------------------- busy indicator --

export interface BusyTimers {
  set: (fn: () => void, ms: number) => unknown;
  clear: (id: unknown) => void;
  now: () => number;
}

const realTimers: BusyTimers = {
  set: (fn, ms) => setTimeout(fn, ms),
  clear: (id) => clearTimeout(id as ReturnType<typeof setTimeout>),
  now: () => Date.now(),
};

/**
 * Runs `task` and reports a loading state the way AGENTS.md asks: the button
 * keeps its label, the spinner shows only after `delayMs` (no flash for fast
 * answers) and, once shown, stays at least `minMs` (no flicker).
 */
export async function withBusy<T>(task: () => Promise<T>, setBusy: (busy: boolean) => void, opts: { delayMs?: number; minMs?: number } = {}, timers: BusyTimers = realTimers): Promise<T> {
  const delay = opts.delayMs ?? 150;
  const min = opts.minMs ?? 300;
  let shownAt = -1;
  const id = timers.set(() => {
    shownAt = timers.now();
    setBusy(true);
  }, delay);
  try {
    return await task();
  } finally {
    timers.clear(id);
    if (shownAt >= 0) {
      const left = min - (timers.now() - shownAt);
      if (left > 0) await new Promise<void>((resolve) => timers.set(resolve, left));
      setBusy(false);
    }
  }
}

// ---------------------------------------------------------------- numbers --

const countFormats = new Map<string, Intl.NumberFormat>();

/**
 * Whole counts in the Swiss format of the UI language: «12'847» (de), «12 847»
 * (fr), «12’847» (it, en). `lang` is the UI language (de, fr, it, en).
 */
export function fmtCount(n: number, lang: string): string {
  if (!Number.isFinite(n)) return '0';
  const locale = `${lang}-CH`;
  let f = countFormats.get(locale);
  if (!f) {
    try {
      f = new Intl.NumberFormat(locale, { maximumFractionDigits: 0, useGrouping: 'always' } as Intl.NumberFormatOptions);
    } catch {
      f = new Intl.NumberFormat('de-CH', { maximumFractionDigits: 0 });
    }
    countFormats.set(locale, f);
  }
  return f.format(Math.round(n));
}

/**
 * Longest middle-truncated form of `text` that `fits` accepts (truncate is
 * truncateMiddle from shared/text.ts). Returns the text itself when it fits.
 */
export function fitText(text: string, fits: (candidate: string) => boolean, truncate: (s: string, max: number) => string): string {
  if (fits(text)) return text;
  // Binary search on the length: a shorter cut never gets wider.
  let lo = 4;
  let hi = text.length - 1;
  let best = truncate(text, lo);
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const c = truncate(text, mid);
    if (fits(c)) {
      best = c;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return best;
}
