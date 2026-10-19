// Bastion Shield — hand-off between the compact popup (popup.html) and the
// expanded popup (panel.html), which replace each other in the same popup
// window. The page being left stores its PopupState and the loaded message
// bundle in sessionStorage (scoped to that window), so the next page can draw
// its first frame synchronously: the cross-document view transition then has
// real content to morph into instead of an empty page. Live data is fetched
// right after, as usual.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { PopupState } from '../../shared/types.ts';

const KEY = 'bastion.handoff';
/** A hand-off older than this is stale (the user reopened the popup later). */
export const HANDOFF_MAX_AGE_MS = 10_000;

export interface Handoff {
  t: number;
  tabId: number;
  state: PopupState;
}

export function writeHandoff(tabId: number, state: PopupState): void {
  try {
    sessionStorage.setItem(KEY, JSON.stringify({ t: Date.now(), tabId, state } satisfies Handoff));
  } catch {
    /* storage may be unavailable: the next page just loads normally */
  }
}

/** The hand-off for `tabId` if it is fresh, else null. Never throws. */
export function readHandoff(tabId: number | null, now = Date.now()): Handoff | null {
  if (tabId === null) return null;
  try {
    const raw = sessionStorage.getItem(KEY);
    if (!raw) return null;
    const h = JSON.parse(raw) as Partial<Handoff>;
    if (!h || h.tabId !== tabId || typeof h.t !== 'number' || now - h.t > HANDOFF_MAX_AGE_MS || now < h.t || !h.state || typeof h.state !== 'object') return null;
    return h as Handoff;
  } catch {
    return null;
  }
}
