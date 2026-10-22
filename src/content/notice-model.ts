// Bastion Shield — blocker notices, pure part (content/notice.ts renders
// them; unit-tested in node).
//
// A notice is shown for a blocked clipboard write ("ClickFix") and for a
// lookalike domain. Clipboard notices come from two sources:
//   'ubo'      uBlock filters' generic ClickFix filter (prevent-clipboard-write,
//              routed here by tools/lib/notice-transform.ts);
//   'bastion'  the nerd mode clipboard guard (main/clipguard.ts).
//
// There is no «copy anyway» button: ClickFix pages instruct visitors to click
// things («press the button, then Win+R, Ctrl+V, Enter»), and any override
// button would become one more step of the lure. The blocked command stays
// visible and selectable in the notice, so someone who really needs it can
// copy it by hand after reading it.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { collapseWs } from '../main/clip-detect.ts';
import { markInvisible, truncateMiddle } from '../ui/shared/text.ts';

export type NoticeSource = 'ubo' | 'bastion';
export const NOTICE_SOURCES: ReadonlySet<string> = new Set<NoticeSource>(['ubo', 'bastion']);

/** Notices kept per page (newest on top, the older ones collapse into one row; the oldest goes beyond this). */
export const MAX_NOTICES = 31;
/** Identical clipboard text within this window gives one notice. */
export const DEDUPE_MS = 2000;
/** Characters of a blocked command kept for display. */
export const MAX_NOTICE_TEXT = 20_000;
/** ClickFix notices per page load (a page looping over writeText cannot keep the stack busy). */
export const MAX_CLIP_NOTICES = 30;
/** Detail prefix of the uBO scriptlet event (tools/lib/notice-transform.ts NOTICE_DETAIL_UBO). */
export const UBO_DETAIL_PREFIX = 'ubo|';

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

// ---------------------------------------------------------------------------
// ClickFix command field
// ---------------------------------------------------------------------------

/** A piece of a blocked command: plain text, or one invisible character shown as its code ("U+202E"). */
export interface CmdPart {
  text: string;
  hidden: boolean;
}

/**
 * Splits a command into plain runs and invisible/bidi control characters
 * (src/ui/shared/text.ts markInvisible), so the notice shows each hidden
 * character as a chip instead of letting it reorder or hide the text. Done
 * per character, so a page cannot fake a chip by writing "⟨U+202E⟩" itself.
 */
export function splitInvisible(text: string): { parts: CmdPart[]; hidden: number } {
  const parts: CmdPart[] = [];
  let run = '';
  let hidden = 0;
  for (const ch of text) {
    const marked = markInvisible(ch);
    if (marked === ch) {
      run += ch;
      continue;
    }
    if (run !== '') parts.push({ text: run, hidden: false });
    run = '';
    hidden++;
    parts.push({ text: marked.replace(/[⟨⟩]/g, ''), hidden: true });
  }
  if (run !== '') parts.push({ text: run, hidden: false });
  return { parts, hidden };
}

/** Characters of a command as people count them (code points). */
export function charCount(text: string): number {
  return [...text].length;
}

/**
 * State of a scrolling field: `scrolls` when its content is taller than the
 * box (only then the fade and the character count show), `atEnd` once it is
 * scrolled to the bottom (the fade goes).
 */
export function scrollState(scrollHeight: number, clientHeight: number, scrollTop: number): { scrolls: boolean; atEnd: boolean } {
  const scrolls = scrollHeight - clientHeight > 1;
  return { scrolls, atEnd: !scrolls || scrollTop + clientHeight >= scrollHeight - 2 };
}

// ---------------------------------------------------------------------------
// Lookalike: which characters of the visited host differ from the real domain
// ---------------------------------------------------------------------------

/** A run of the visited host: `diff` when it differs from the real domain. */
export interface HostPart {
  text: string;
  diff: boolean;
}

/** Two characters that read as one (lookalike.ts skeleton): the pair is marked as a whole. */
const PAIRS: Readonly<Record<string, string>> = { rn: 'm', vv: 'w', cl: 'd' };

function joinParts(flags: readonly boolean[], host: string): HostPart[] {
  const out: HostPart[] = [];
  for (let i = 0; i < host.length; i++) {
    const last = out[out.length - 1];
    if (last !== undefined && last.diff === flags[i]) last.text += host[i];
    else out.push({ text: host[i]!, diff: flags[i]! });
  }
  return out;
}

/**
 * Aligns the real domain inside the visited host (edit distance; leading host
 * characters such as "www." are free, and so is the tail when the host does
 * not end in the real domain's TLD) and marks substituted and inserted
 * characters. A missing character marks its neighbour, so every difference
 * shows somewhere.
 *   hostDiff('rnicrosoft-login.com', 'microsoft.com') -> [rn]icrosoft[-login].com
 */
export function hostDiff(host: string, target: string): HostPart[] {
  const h = host.toLowerCase();
  const t = target.toLowerCase();
  const n = h.length;
  const m = t.length;
  if (n === 0) return [];
  if (m === 0 || n * m > 40_000) return [{ text: host, diff: false }];
  const anchored = t.includes('.') && h.endsWith(t.slice(t.lastIndexOf('.')));
  const SUB = 10;
  const GAP = 10;
  const PAIR = 9;
  // d[i][j]: cost of aligning h[..i) (after a free prefix) with t[..j); op: how.
  const d: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  const op: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  // Whole leading labels ("www.", "login.") are free; anything else costs.
  for (let i = 1; i <= n; i++) {
    d[i]![0] = h[i - 1] === '.' && n - i >= m - 2 ? 0 : d[i - 1]![0]! + GAP;
    op[i]![0] = 3;
  }
  for (let j = 1; j <= m; j++) {
    d[0]![j] = j * GAP;
    op[0]![j] = 4;
  }
  for (let i = 1; i <= n; i++) {
    for (let j = 1; j <= m; j++) {
      const same = h[i - 1] === t[j - 1];
      // On ties an insertion wins (inserted runs stay together and end late), then pair, match, deletion.
      let best = d[i - 1]![j - 1]! + (same ? 0 : SUB);
      let o = same ? 0 : 2;
      if (i >= 2 && PAIRS[h.slice(i - 2, i)] === t[j - 1] && d[i - 2]![j - 1]! + PAIR < best) {
        best = d[i - 2]![j - 1]! + PAIR;
        o = 1;
      }
      if (d[i - 1]![j]! + GAP <= best) {
        best = d[i - 1]![j]! + GAP;
        o = 3;
      }
      if (d[i]![j - 1]! + GAP < best) {
        best = d[i]![j - 1]! + GAP;
        o = 4;
      }
      d[i]![j] = best;
      op[i]![j] = o;
    }
  }
  // The tail after a label or word boundary is free when the TLD differs.
  let end = n;
  if (!anchored) {
    for (let i = Math.max(1, m - 2); i < n; i++) if ((h[i] === '.' || h[i] === '-') && d[i]![m]! < d[end]![m]!) end = i;
  }
  const flags = new Array<boolean>(n).fill(false);
  let i = end;
  let j = m;
  let miss = false;
  while (j > 0 && i > 0) {
    const o = op[i]![j]!;
    if (o === 0 || o === 2) {
      flags[i - 1] = o === 2 || miss;
      miss = false;
      i--;
      j--;
    } else if (o === 1) {
      flags[i - 1] = flags[i - 2] = true;
      miss = false;
      i -= 2;
      j--;
    } else if (o === 3) {
      flags[i - 1] = true;
      miss = false;
      i--;
    } else {
      // A character of the real domain is missing: mark the host character after the gap.
      if (i < end) flags[i] = true;
      else miss = true;
      j--;
    }
  }
  if (miss && i > 0) flags[i - 1] = true;
  if (j > 0) flags[0] = true;
  // Leading characters up to the last free label are inserted text.
  for (; j === 0 && i > 0 && d[i]![0]! > 0; i--) flags[i - 1] = true;
  // Nothing differs inside the match ("paypal.com.evil.net"): the extra tail is the difference.
  if (!flags.includes(true)) for (let k = end; k < n; k++) flags[k] = true;
  return joinParts(flags, host);
}

/**
 * Host parts shortened like truncateMiddle(host, max): the parts of the
 * visible head and tail with an 'ellipsis' marker between them.
 */
export function truncateParts(parts: readonly HostPart[], max: number): { parts: (HostPart | 'ellipsis')[]; truncated: boolean } {
  const host = parts.map((p) => p.text).join('');
  const short = truncateMiddle(host, max);
  if (short === host) return { parts: parts.map((p) => ({ ...p })), truncated: false };
  const head = short.indexOf('…');
  const tail = short.length - head - 1;
  const slice = (from: number, to: number): HostPart[] => {
    const out: HostPart[] = [];
    let pos = 0;
    for (const p of parts) {
      const a = Math.max(from, pos);
      const b = Math.min(to, pos + p.text.length);
      if (a < b) out.push({ text: p.text.slice(a - pos, b - pos), diff: p.diff });
      pos += p.text.length;
    }
    return out;
  };
  return { parts: [...slice(0, head), 'ellipsis', ...slice(host.length - tail, host.length)], truncated: true };
}

// ---------------------------------------------------------------------------
// Stack: the newest card on top, the older ones collapse into one row
// ---------------------------------------------------------------------------

export type NoticeKind = 'clip' | 'lookalike';

export interface StackView {
  /** Cards shown, newest first (the others hide behind the row). */
  visible: number;
  /** Older notices behind the «N weitere Meldungen» row (0: no row). */
  more: number;
  /** Older notices by kind, for the row's summary and tiles. */
  clips: number;
  addresses: number;
  /** The row can expand: older notices have cards (counted-only ones have none). */
  expandable: boolean;
}

/**
 * What the stack shows for `kinds` (newest first), collapsed or expanded.
 * `counted` are ClickFix blocks beyond MAX_CLIP_NOTICES: they get no card
 * but raise the row's count, so people see that blocking goes on.
 */
export function stackView(kinds: readonly NoticeKind[], expanded: boolean, counted = 0): StackView {
  const older = kinds.slice(1);
  return {
    visible: older.length === 0 || expanded ? kinds.length : 1,
    more: older.length + counted,
    clips: older.filter((k) => k === 'clip').length + counted,
    addresses: older.filter((k) => k === 'lookalike').length,
    expandable: older.length > 0,
  };
}

/** A blocked command gets a card while fewer than MAX_CLIP_NOTICES were shown; after that it is only counted. */
export function clipSlot(shown: number, max = MAX_CLIP_NOTICES): 'card' | 'count' {
  return shown < max ? 'card' : 'count';
}
