// Bastion Shield — blocker notices, pure part (content/notice.ts renders
// them; unit-tested in node).
//
// A notice is shown for a blocked clipboard write ("ClickFix") and for a
// lookalike domain. Clipboard notices come from two sources:
//   'ubo'      uBlock filters' generic ClickFix filter (prevent-clipboard-write,
//              routed here by tools/lib/notice-transform.ts);
//   'bastion'  the nerd mode clipboard guard (main/clipguard.ts).
//
// «Copy anyway» is offered only when Bastion's own detector does not rate
// the text 'high' (medium or no verdict). ClickFix pages instruct visitors
// to click things («press the button, then Win+R, Ctrl+V, Enter»); a
// universal override would become part of the lure. For 'high' shapes
// (hidden or policy-bypassing PowerShell, mshta, cmd tricks, lure comments,
// …) no web page has a legitimate reason to hand the text out, so nothing is
// ever copied; the command stays selectable for people who need to inspect
// it.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { collapseWs, detectDangerousCommand } from '../main/clip-detect.ts';
import type { ClipVerdict } from '../main/clip-detect.ts';

export type NoticeSource = 'ubo' | 'bastion';
export const NOTICE_SOURCES: ReadonlySet<string> = new Set<NoticeSource>(['ubo', 'bastion']);

/** Notices visible at once (newest on top; the oldest goes when a fourth arrives). */
export const MAX_NOTICES = 3;
/** Identical clipboard text within this window gives one notice. */
export const DEDUPE_MS = 2000;
/** Characters of a blocked command kept (display and «copy anyway»). */
export const MAX_NOTICE_TEXT = 20_000;
/** ClickFix notices per page load (a page looping over writeText cannot keep the stack busy). */
export const MAX_CLIP_NOTICES = 30;
/** Detail prefix of the uBO scriptlet event (tools/lib/notice-transform.ts NOTICE_DETAIL_UBO). */
export const UBO_DETAIL_PREFIX = 'ubo|';

export interface ClipOffer {
  verdict: ClipVerdict | null;
  /** Show «Copy anyway» (never for 'high'). */
  copyAnyway: boolean;
}

/** What the notice offers for a blocked clipboard text. Never throws. */
export function clipOffer(text: string): ClipOffer {
  let verdict: ClipVerdict | null = null;
  try {
    verdict = detectDangerousCommand(text);
  } catch {
    // An unrated text is treated like 'high': nothing is offered.
    return { verdict: { severity: 'high', rule: 'error' }, copyAnyway: false };
  }
  return { verdict, copyAnyway: verdict === null || verdict.severity !== 'high' };
}

/** Text of a uBO notice event detail ("ubo|<text>"), or null for anything else. */
export function parseUboDetail(detail: unknown): string | null {
  if (typeof detail !== 'string' || !detail.startsWith(UBO_DETAIL_PREFIX)) return null;
  const text = detail.slice(UBO_DETAIL_PREFIX.length);
  if (text.trim() === '') return null;
  return text.length > MAX_NOTICE_TEXT ? text.slice(0, MAX_NOTICE_TEXT) : text;
}

/** Remembers recent keys; `seen` answers true for a repeat within `windowMs`. */
export class Deduper {
  private readonly last = new Map<string, number>();
  private readonly windowMs: number;

  constructor(windowMs = DEDUPE_MS) {
    this.windowMs = windowMs;
  }

  seen(key: string, now: number): boolean {
    for (const [k, t] of this.last) if (now - t >= this.windowMs) this.last.delete(k);
    const t = this.last.get(key);
    if (t !== undefined && now - t < this.windowMs) return true;
    this.last.set(key, now);
    return false;
  }
}

/** Dedupe key of a clipboard notice: the same command from either source counts once. */
export function clipKey(text: string): string {
  return 'clip|' + collapseWs(text.length > 4096 ? text.slice(0, 4096) : text);
}

/**
 * Where a new notice goes in a newest-first list of `count` notices:
 * returns how many of the oldest must be removed so at most `max` remain.
 */
export function overflow(count: number, max = MAX_NOTICES): number {
  return Math.max(0, count + 1 - max);
}
