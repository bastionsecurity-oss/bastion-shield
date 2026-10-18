// Bastion Shield — UI side of the message contract (docs/ARCHITECTURE.md §7).
// Every call resolves to a Result and never throws: the service worker may be
// starting up, restarting after an update, or (in a broken install) missing.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ActivityEvent, LivePortMessage, Message } from '../../shared/types.ts';
import { PORT_LIVE } from '../../shared/constants.ts';

export type Result<T> = { ok: true; data: T } | { ok: false; error: string };

const DEFAULT_TIMEOUT_MS = 8000;

/** Send a typed message to the service worker. `{error}` replies become failures. */
export async function call<T>(msg: Message, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<Result<T>> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('timeout')), timeoutMs);
    });
    const reply = (await Promise.race([chrome.runtime.sendMessage(msg), timeout])) as unknown;
    if (reply === undefined) return { ok: false, error: 'no-response' };
    if (reply && typeof reply === 'object' && 'error' in reply && typeof (reply as { error: unknown }).error === 'string') {
      return { ok: false, error: (reply as { error: string }).error };
    }
    return { ok: true, data: reply as T };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export type AttributionUpdate = Extract<LivePortMessage, { type: 'attributed' }>['updates'][number];

export interface LiveHandlers {
  backlog?: (events: ActivityEvent[]) => void;
  event: (event: ActivityEvent) => void;
  reset?: (tabId: number) => void;
  /** List attribution that arrived after the events were streamed. */
  attributed?: (updates: AttributionUpdate[]) => void;
  /** Called when the port closes for good (after retries). */
  closed?: () => void;
}

const attrKey = (t: number, tabId: number, url: string, kind: string): string => `${t}|${tabId}|${kind}|${url}`;

/**
 * Apply late list attributions to already shown events, matched on
 * (t, tabId, url, kind). Mutates the events in place; returns how many
 * changed so callers only repaint when needed. Malformed updates are skipped.
 */
export function applyAttributed(updates: readonly AttributionUpdate[], ...rowSets: readonly ActivityEvent[][]): number {
  if (!Array.isArray(updates) || updates.length === 0) return 0;
  const byKey = new Map<string, AttributionUpdate>();
  for (const u of updates) {
    if (!u || typeof u !== 'object' || typeof u.t !== 'number' || typeof u.url !== 'string' || typeof u.list !== 'string' || !u.list) continue;
    byKey.set(attrKey(u.t, u.tabId, u.url, u.kind), u);
  }
  if (byKey.size === 0) return 0;
  let changed = 0;
  for (const rows of rowSets) {
    for (const e of rows) {
      const u = byKey.get(attrKey(e.t, e.tabId, e.url, e.kind));
      if (!u || (e.list === u.list && e.rule === u.rule)) continue;
      e.list = u.list;
      if (typeof u.rule === 'string') e.rule = u.rule;
      changed++;
    }
  }
  return changed;
}

export interface LiveConnection {
  close(): void;
}

/**
 * Subscribe to the live activity stream. The service worker may be suspended
 * and restarted (which drops ports), so we reconnect a few times with backoff
 * while the page is open.
 */
export function connectLive(subscribe: number | 'all', handlers: LiveHandlers): LiveConnection {
  let port: chrome.runtime.Port | null = null;
  let closed = false;
  let attempts = 0;
  let retryTimer: ReturnType<typeof setTimeout> | undefined;

  const open = (): void => {
    if (closed) return;
    try {
      port = chrome.runtime.connect({ name: PORT_LIVE });
    } catch {
      scheduleRetry();
      return;
    }
    port.onMessage.addListener((raw: unknown) => {
      attempts = 0;
      const msg = raw as LivePortMessage;
      if (!msg || typeof msg !== 'object') return;
      try {
        if (msg.type === 'event' && msg.event) handlers.event(msg.event);
        else if (msg.type === 'backlog' && Array.isArray(msg.events)) handlers.backlog?.(msg.events);
        else if (msg.type === 'reset') handlers.reset?.(msg.tabId);
        else if (msg.type === 'attributed' && Array.isArray(msg.updates)) handlers.attributed?.(msg.updates);
      } catch (err) {
        console.error('[bastion] live handler failed', err);
      }
    });
    port.onDisconnect.addListener(() => {
      // Reading lastError marks it handled (otherwise Chrome logs "Unchecked runtime.lastError").
      void chrome.runtime.lastError;
      port = null;
      scheduleRetry();
    });
    try {
      port.postMessage({ subscribe });
    } catch {
      /* onDisconnect will follow */
    }
  };

  const scheduleRetry = (): void => {
    if (closed) return;
    if (attempts >= 6) {
      handlers.closed?.();
      return;
    }
    const delay = Math.min(8000, 250 * 2 ** attempts++);
    retryTimer = setTimeout(open, delay);
  };

  open();
  return {
    close() {
      closed = true;
      if (retryTimer !== undefined) clearTimeout(retryTimer);
      try {
        port?.disconnect();
      } catch {
        /* already gone */
      }
      port = null;
    },
  };
}

/** Fetch a JSON file from the extension package. Resolves null on any failure. */
export async function fetchPackaged<T>(path: string): Promise<T | null> {
  try {
    const res = await fetch(chrome.runtime.getURL(path));
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

/** Current extension version from the manifest ('' when unavailable). */
export function extensionVersion(): string {
  try {
    return chrome.runtime.getManifest().version ?? '';
  } catch {
    return '';
  }
}

/**
 * Open the dashboard at a section. Re-uses an open dashboard tab when there is
 * one (tabs permission is granted), otherwise opens a new tab.
 */
export async function openDashboard(hash = ''): Promise<void> {
  const base = chrome.runtime.getURL('ui/dashboard.html');
  const url = hash ? `${base}#${hash}` : base;
  try {
    // Filter by URL ourselves: chrome-extension:// is not a valid match-pattern scheme for tabs.query.
    const tabs = await chrome.tabs.query({});
    const existing = tabs.find((tb) => tb.id !== undefined && typeof tb.url === 'string' && tb.url.startsWith(base));
    if (existing && existing.id !== undefined) {
      await chrome.tabs.update(existing.id, { active: true, url });
      if (existing.windowId !== undefined) await chrome.windows.update(existing.windowId, { focused: true }).catch(() => undefined);
      return;
    }
  } catch {
    /* fall through to a new tab */
  }
  try {
    await chrome.tabs.create({ url });
  } catch {
    try {
      chrome.runtime.openOptionsPage();
    } catch {
      window.open(url, '_blank', 'noopener');
    }
  }
}
