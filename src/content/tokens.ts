// Bastion Shield — pure helpers for content/cosmetic.ts: which URL a frame
// reports, id/class token extraction for the generic surveyor, throttle
// arithmetic and the de-AMP target check. No DOM access, so they are unit
// tested under Node (test/content/tokens.test.ts).
//
// SPDX-License-Identifier: GPL-3.0-or-later

export interface FrameContext {
  /** URL sent as MsgCosmeticFrame.url / MsgCosmeticTokens.url. */
  url: string;
  /** Top-level page URL as far as the frame can tell (origin only for subframes). */
  topUrl: string;
}

function isHttpUrl(s: string): boolean {
  return s.startsWith('https://') || s.startsWith('http://');
}

function usableOrigin(o: unknown): string {
  return typeof o === 'string' && isHttpUrl(o) ? o : '';
}

/**
 * Frames without an http(s) URL of their own (about:blank, about:srcdoc,
 * blob:, data:) inherit their filtering context from their creator: the
 * frame's own origin when it is a real one (about:blank / blob: inherit it),
 * otherwise the parent from location.ancestorOrigins.
 */
export function frameContext(
  href: string,
  origin: string,
  ancestorOrigins: ArrayLike<string> | null | undefined,
  isTop: boolean,
): FrameContext {
  const n = ancestorOrigins !== null && ancestorOrigins !== undefined ? ancestorOrigins.length : 0;
  let url = href;
  if (!isHttpUrl(href)) {
    const o = usableOrigin(origin) || (n > 0 ? usableOrigin(ancestorOrigins![0]) : '');
    if (o !== '') url = o + '/';
  }
  let topUrl = url;
  if (!isTop && n > 0) {
    const top = usableOrigin(ancestorOrigins![n - 1]);
    if (top !== '') topUrl = top + '/';
  }
  return { url, topUrl };
}

/** Tokens longer than this are never keys of generic filters and only bloat messages. */
export const MAX_TOKEN_LENGTH = 200;

function isSpace(c: number): boolean {
  // ASCII whitespace as defined by HTML for class lists.
  return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0c || c === 0x0d;
}

/**
 * Add the "#id" and ".class" tokens of one element to `out`, skipping
 * those in `seen` (which is updated). Values are sent raw (unescaped); the
 * service worker looks them up in GenericIndex.tokens. Returns the number
 * of new tokens.
 */
export function collectTokens(
  id: string | null,
  cls: string | null,
  seen: Set<string>,
  out: string[],
): number {
  let added = 0;
  if (id !== null && id !== '' && id.length <= MAX_TOKEN_LENGTH) {
    let ok = true;
    for (let i = 0; i < id.length; i++) {
      if (isSpace(id.charCodeAt(i))) {
        ok = false;
        break;
      }
    }
    if (ok) {
      const t = '#' + id;
      if (!seen.has(t)) {
        seen.add(t);
        out.push(t);
        added++;
      }
    }
  }
  if (cls !== null && cls !== '') {
    const len = cls.length;
    let i = 0;
    while (i < len) {
      while (i < len && isSpace(cls.charCodeAt(i))) i++;
      const beg = i;
      while (i < len && !isSpace(cls.charCodeAt(i))) i++;
      if (i > beg && i - beg <= MAX_TOKEN_LENGTH) {
        const t = '.' + cls.slice(beg, i);
        if (!seen.has(t)) {
          seen.add(t);
          out.push(t);
          added++;
        }
      }
    }
  }
  return added;
}

/**
 * collectTokens for the surveyor, memoising raw class attribute strings:
 * most elements of a page share a few hundred class strings (98–99 % of the
 * strings scanned on news front pages are repeats), and a string seen before
 * cannot yield a new token because `seen` only ever grows. Ids are mostly
 * unique and go straight to collectTokens. `seenClass` stops growing at
 * SURVEY.MAX_SEEN_CLASS_STRINGS (later strings are simply tokenised again).
 * The output is identical to calling collectTokens for every element.
 */
export function surveyTokens(
  id: string | null,
  cls: string | null,
  seen: Set<string>,
  seenClass: Set<string>,
  out: string[],
): number {
  if (cls !== null && cls !== '') {
    if (seenClass.has(cls)) cls = null;
    else if (seenClass.size < SURVEY.MAX_SEEN_CLASS_STRINGS) seenClass.add(cls);
  }
  return collectTokens(id, cls, seen, out);
}

/** Minimal element shape for hasQueuedAncestor (tests use plain objects). */
export interface ParentLink {
  readonly parentElement: ParentLink | null;
}

/**
 * True when an ancestor of `el` (within `maxDepth` levels) is still waiting
 * in the surveyor's root queue. That ancestor's querySelectorAll runs later
 * and covers `el`'s whole subtree as it is then, so scanning `el`'s subtree
 * now is wasted work. Only still-queued (not yet scanned) roots count: a
 * subtree scanned earlier may have gained children while detached, which
 * produce no mutation records.
 */
export function hasQueuedAncestor<T extends ParentLink>(el: T, queued: ReadonlySet<T>, maxDepth: number): boolean {
  if (queued.size === 0) return false;
  let p = el.parentElement as T | null;
  for (let d = 0; p !== null && d < maxDepth; d++) {
    if (queued.has(p)) return true;
    p = p.parentElement as T | null;
  }
  return false;
}

/** Milliseconds to wait before the next throttled run (0 = run now). */
export function throttleDelay(now: number, last: number, interval: number): number {
  const d = last + interval - now;
  return d > 0 ? d : 0;
}

/** Surveyor limits (ARCHITECTURE §5.2.3). */
export const SURVEY = {
  /** Token flush interval in the top frame / in subframes (ms). */
  INTERVAL_TOP: 100,
  INTERVAL_SUB: 250,
  /** Stop after this long without a new token (ms). */
  IDLE_STOP_MS: 30_000,
  /** Stop after this many consecutive flushes that produced no CSS. */
  MAX_EMPTY_FLUSHES: 20,
  /** Time slice for scanning (ms). */
  SLICE_MS: 4,
  /** Tokens per cosmetic:tokens message. */
  MAX_TOKENS_PER_MESSAGE: 2000,
  /** Give up on pathological pages (unique ids per element on infinite scroll). */
  MAX_SEEN_TOKENS: 30_000,
  /** Queue size above which queued nodes collapse into one full rescan. */
  MAX_QUEUED_NODES: 20_000,
  /** Raw class strings remembered by surveyTokens (memory bound, ~1 MB worst case). */
  MAX_SEEN_CLASS_STRINGS: 20_000,
  /** Ancestor levels hasQueuedAncestor walks before giving up (bounded cost per root). */
  MAX_ANCESTOR_WALK: 64,
} as const;

function stripHash(u: URL): string {
  const s = u.href;
  const i = s.indexOf('#');
  let out = i === -1 ? s : s.slice(0, i);
  if (out.endsWith('/')) out = out.slice(0, -1);
  return out;
}

/**
 * Where an AMP page should go: its canonical URL, when that is http(s) and
 * not the page itself or the page we came from (Brave's loop checks).
 * Returns null when no redirect should happen.
 */
export function deAmpTarget(canonicalHref: string, currentHref: string, referrer: string): string | null {
  let canon: URL;
  let current: URL;
  try {
    current = new URL(currentHref);
    canon = new URL(canonicalHref, current);
  } catch {
    return null;
  }
  if (canon.protocol !== 'https:' && canon.protocol !== 'http:') return null;
  // Never downgrade an https page to http.
  if (current.protocol === 'https:' && canon.protocol === 'http:') return null;
  if (stripHash(canon) === stripHash(current)) return null;
  if (referrer !== '') {
    try {
      if (stripHash(new URL(referrer)) === stripHash(canon)) return null;
    } catch {
      // ignore malformed referrer
    }
  }
  return canon.href;
}

/** True for `<html amp>` / `<html ⚡>` (not ⚡4ads / ⚡4email, which must stay). */
export function isAmpHtml(hasAttribute: (name: string) => boolean): boolean {
  return hasAttribute('amp') || hasAttribute('⚡');
}
