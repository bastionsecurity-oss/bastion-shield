// Bastion Shield — nerd mode relay, ISOLATED world (dist/content/nerd-relay.js).
//
// Registered with the MAIN-world scripts clipguard.js / fpmeter.js when
// ClickFix protection (privacy.clipboardGuard, on by default) or the nerd
// mode fingerprinting meter is on (registrations.ts): <all_urls>,
// document_start, all frames, matchOriginAsFallback, not on sites with
// protection off. It listens on the per-extension event channel
// (main/nerd-channel.ts) and
//   * answers clipboard checks synchronously: runs the detector and the
//     allow/deny rule (main/clip-detect.ts) with this world's pristine
//     built-ins, cancels the event to block, then reports
//     {type:'nerd:signal', kind:'clip', sample} to the service worker and
//     shows the Bastion notice «ClickFix blocked» through cosmetic.js
//     (self.bastionNotice in the shared isolated world, content/notice.ts;
//     parked in self.bastionNoticePending until cosmetic.js has loaded);
//   * forwards fingerprinting counts as {kind:'fp', counts}, coalesced to at
//     most one message per FP_FORWARD_MS.
// The page can forge channel events if it knows the extension id: that only
// adds to the counters (bounded by the service worker) or shows a notice.
// The relay stops the event's propagation so page listeners never see the
// clipboard text or the counts.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { FpVector, MsgNerdSignal } from '../shared/types.ts';
import { clipSample, containsCollapsed, decideClip, detectDangerousCommand } from '../main/clip-detect.ts';
import { nerdEventName, parseNerdDetail } from '../main/nerd-channel.ts';
import { isolatedGlobals } from './api.ts';

const FP_FORWARD_MS = 1000;
/** Clipboard reports per page load (forged events cannot flood the service worker). */
const MAX_CLIP_REPORTS = 50;
/** Notices parked for cosmetic.js before it has loaded. */
const MAX_PENDING_NOTICES = 10;
/** Form fields inspected by the visible-text check. */
const MAX_FIELDS = 500;

interface RelayGlobals {
  bastionNerdRelayLoaded?: boolean;
}

let dead = false;

function runtimeAlive(): boolean {
  try {
    return !dead && typeof chrome === 'object' && chrome.runtime !== undefined && chrome.runtime.id !== undefined;
  } catch {
    return false;
  }
}

function send(msg: MsgNerdSignal): void {
  if (!runtimeAlive()) {
    dead = true;
    return;
  }
  try {
    const p = chrome.runtime.sendMessage(msg) as Promise<unknown> | undefined;
    if (p !== undefined && typeof p.then === 'function') p.then(undefined, () => undefined);
  } catch {
    dead = true;
  }
}

// ---------------------------------------------------------------------------
// Page state for the allow/deny rule
// ---------------------------------------------------------------------------

const TEXT_INPUT_TYPES: ReadonlySet<string> = new Set(['text', 'search', 'url', 'tel', 'password', 'email', '']);

/** Text of the current selection: the focused input/textarea's selected value, else the document selection. */
export function selectionText(): string {
  try {
    let a: Element | null = document.activeElement;
    // Follow open shadow roots to the focused element.
    for (let i = 0; i < 16 && a !== null && a.shadowRoot !== null && a.shadowRoot.activeElement !== null; i++) a = a.shadowRoot.activeElement;
    if (a instanceof HTMLTextAreaElement || (a instanceof HTMLInputElement && TEXT_INPUT_TYPES.has(a.type))) {
      const s = a.selectionStart;
      const e = a.selectionEnd;
      if (s !== null && e !== null && e > s) return a.value.slice(s, e);
    }
  } catch {
    // inputs without a selection API throw; fall through
  }
  try {
    return window.getSelection()?.toString() ?? '';
  } catch {
    return '';
  }
}

/** Rendered on screen: has a size, is inside the page's positive area, and is not hidden. */
function shown(el: Element): boolean {
  const r = el.getBoundingClientRect();
  if (r.width < 2 || r.height < 2 || r.right <= 0 || r.bottom + window.scrollY <= 0) return false;
  const cv = (el as Element & { checkVisibility?: (o: object) => boolean }).checkVisibility;
  return typeof cv === 'function' ? cv.call(el, { opacityProperty: true, visibilityProperty: true, contentVisibilityAuto: true }) : true;
}

/** Whether `text` appears on the page as rendered text or in a visible form field. */
export function visibleOnPage(text: string): boolean {
  const body = document.body;
  const pageText = body !== null ? body.innerText : (document.documentElement?.textContent ?? '');
  if (containsCollapsed(pageText, text)) return true;
  const fields = document.querySelectorAll('input, textarea');
  for (let i = 0; i < fields.length && i < MAX_FIELDS; i++) {
    const f = fields[i] as HTMLInputElement | HTMLTextAreaElement;
    if (typeof f.value === 'string' && f.value.length >= 6 && containsCollapsed(f.value, text) && shown(f)) return true;
  }
  return false;
}

/** «ClickFix blocked» notice (source 'bastion'), shown by cosmetic.js. */
function showNotice(text: string): void {
  const g = isolatedGlobals();
  if (g.bastionNotice !== undefined) {
    g.bastionNotice.clip(text, 'bastion');
    return;
  }
  const list = g.bastionNoticePending ?? (g.bastionNoticePending = []);
  if (list.length < MAX_PENDING_NOTICES) list.push({ text, source: 'bastion' });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main(): void {
  const g = self as unknown as RelayGlobals;
  if (g.bastionNerdRelayLoaded) return;
  g.bastionNerdRelayLoaded = true;
  if (!runtimeAlive()) return;

  const name = nerdEventName(chrome.runtime.getURL(''));
  let clipReports = 0;
  let fpPending: Partial<Record<FpVector, number>> = {};
  let fpTimer = 0;

  const flushFp = (): void => {
    fpTimer = 0;
    const counts = fpPending;
    fpPending = {};
    if (Object.keys(counts).length > 0) send({ type: 'nerd:signal', kind: 'fp', counts });
  };

  const onEvent = (ev: Event): void => {
    let detail: unknown;
    try {
      detail = (ev as CustomEvent<unknown>).detail;
      ev.stopImmediatePropagation();
    } catch {
      return;
    }
    const d = parseNerdDetail(detail);
    if (d === null) return;
    if (d.kind === 'fp') {
      for (const [k, v] of Object.entries(d.counts) as [FpVector, number][]) fpPending[k] = Math.min(1e9, (fpPending[k] ?? 0) + v);
      if (fpTimer === 0) fpTimer = setTimeout(flushFp, FP_FORWARD_MS) as unknown as number;
      return;
    }
    // Clipboard check: decide now, inside the MAIN world's dispatchEvent call.
    let block = false;
    let text = d.text;
    try {
      const sel = selectionText();
      if (d.source === 'exec') text = sel;
      const verdict = detectDangerousCommand(text);
      block = decideClip(text, verdict, { userCopy: d.userCopy, selection: sel, visible: () => visibleOnPage(text) });
    } catch {
      block = false;
    }
    if (!block) return;
    ev.preventDefault();
    if (clipReports >= MAX_CLIP_REPORTS) return;
    clipReports++;
    send({ type: 'nerd:signal', kind: 'clip', sample: clipSample(text) });
    try {
      showNotice(text);
    } catch {
      // the block itself already happened
    }
  };

  window.addEventListener(name, onEvent, true);
  // Counts collected right before the page goes away (fpmeter flushes on pagehide first).
  window.addEventListener('pagehide', () => {
    if (fpTimer !== 0) {
      clearTimeout(fpTimer);
      flushFp();
    }
  });
}

try {
  main();
} catch {
  // never let an exception reach the page console
}
