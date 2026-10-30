// Bastion Shield — Brave's Standard-mode first-party un-hiding, as pure
// helpers for content/cosmetic.ts (ARCHITECTURE §5.2.8, PARITY.md).
//
// In Standard mode, selectors that only first-party-protected lists hide
// ("soft" selectors) are hidden at once and then re-checked: a selector is
// un-hidden for the whole frame when an element it matches is a first-party
// subtree or shows significant text. The behaviour follows brave-core's
// components/cosmetic_filters/resources/data/content_cosmetic.ts (used as a
// reference, THIRD_PARTY_NOTICES §4): same thresholds, same three-queue
// schedule, same first-party test. Differences are noted where they occur.
// No DOM globals, so this file is unit tested under Node
// (test/content/unhide.test.ts).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/** Brave: text ads need at least this many characters ... */
export const MIN_AD_TEXT_CHARS = 30;
/** ... and this many space-separated words. */
export const MIN_AD_TEXT_WORDS = 5;

export const UNHIDE = {
  /** Brave: the first check runs on idle, at the latest this long after start. */
  START_MAX_MS: 2500,
  /** Brave: pumps run on idle, at most this long after the previous one ... */
  PUMP_MAX_MS: 1000,
  /** ... and at least this long after it. */
  PUMP_MIN_MS: 40,
  /** Brave: selectors per pump (one combined querySelectorAll). */
  WORK_SIZE: 60,
  /** Bastion budget: matched elements examined per pump; the rest wait for the next queue. */
  MAX_ELEMENTS_PER_PUMP: 200,
  /** Bastion budget: nodes visited per subtree before it counts as third party. */
  MAX_SUBTREE_NODES: 2000,
} as const;

/** Ids Brave treats as third-party ads wherever they occur in the subtree. */
const KNOWN_AD_ID = /^(?:google_ads_iframe_|div-gpt-ad|adfox_)/;

/**
 * Same-site test of Brave's isFirstPartyUrl: anything that does not start
 * with `//`, `http://` or `https://` is relative and first party (Brave's
 * rule, so data: and blob: count too); the rest resolves against the frame
 * URL and must have `site` (the frame's registrable domain) as its host or
 * as a parent of it.
 */
export function firstPartyTest(site: string, base: string): (url: string) => boolean {
  const s = site.toLowerCase();
  return (url: string): boolean => {
    if (!url.startsWith('//') && !url.startsWith('http://') && !url.startsWith('https://')) return true;
    let host: string;
    try {
      host = new URL(url, base).hostname;
    } catch {
      return false;
    }
    if (host.endsWith('.')) host = host.slice(0, -1);
    return host === s || host.endsWith('.' + s);
  };
}

/** The parts of a DOM node the first-party walk reads. */
export interface WalkNode {
  readonly nodeType: number;
  readonly firstChild: WalkNode | null;
  readonly nextSibling: WalkNode | null;
  readonly parentNode: WalkNode | null;
  getAttribute?(name: string): string | null;
}

/**
 * Brave's isSubTreeFirstParty: walk the subtree in document order.
 *   - an id starting with google_ads_iframe_, div-gpt-ad or adfox_ makes it
 *     third party at once;
 *   - a first-party `src` makes it first party at once;
 *   - a third-party `src`, a `style` with `url(` or `//`, or an empty
 *     `srcdoc` count as third-party resources;
 *   - otherwise it is first party when no third-party resource was found,
 *     so an empty ad slot counts as first party (Brave shows it).
 * Difference: Brave's recursion also walks the root's following siblings
 * (an accident of its firstChild/nextSibling recursion); Bastion only walks
 * the root's own subtree, and stops after MAX_SUBTREE_NODES (third party).
 */
export function isSubtreeFirstParty(root: WalkNode, isFirstPartyUrl: (url: string) => boolean, maxNodes: number = UNHIDE.MAX_SUBTREE_NODES): boolean {
  let foundThirdParty = false;
  let visited = 0;
  let node: WalkNode | null = root;
  while (node !== null) {
    if (++visited > maxNodes) return false;
    if (node.nodeType === 1 && typeof node.getAttribute === 'function') {
      const id = node.getAttribute('id');
      if (id !== null && KNOWN_AD_ID.test(id)) return false;
      const src = node.getAttribute('src');
      if (src !== null) {
        if (isFirstPartyUrl(src)) return true;
        foundThirdParty = true;
      }
      const style = node.getAttribute('style');
      if (style !== null && (style.includes('url(') || style.includes('//'))) foundThirdParty = true;
      const srcdoc = node.getAttribute('srcdoc');
      if (srcdoc !== null && srcdoc.trim() === '') foundThirdParty = true;
    }
    // Next node in document order, never leaving the root's subtree.
    if (node.firstChild !== null) {
      node = node.firstChild;
      continue;
    }
    let up: WalkNode | null = node;
    while (up !== null && up !== root && up.nextSibling === null) up = up.parentNode;
    node = up === null || up === root ? null : up.nextSibling;
  }
  return !foundThirdParty;
}

/** The parts of an element the text test reads. */
export interface TextNode {
  readonly innerText?: string;
  getElementsByTagName(name: string): ArrayLike<{ readonly innerText?: string }>;
}

/**
 * Brave's showsSignificantText: innerText without the text of script and
 * style descendants (a hidden element's innerText is its textContent),
 * trimmed, at least MIN_AD_TEXT_CHARS characters and MIN_AD_TEXT_WORDS words
 * separated by spaces.
 */
export function showsSignificantText(el: TextNode): boolean {
  let text = el.innerText;
  if (typeof text !== 'string') return false;
  for (const tag of ['script', 'style']) {
    const children = el.getElementsByTagName(tag);
    for (let i = 0; i < children.length; i++) {
      const t = children[i].innerText;
      if (typeof t === 'string' && t !== '') text = text.split(t).join('');
    }
  }
  const trimmed = text.trim();
  if (trimmed.length < MIN_AD_TEXT_CHARS) return false;
  let words = 0;
  for (const w of trimmed.split(' ')) if (w.trim().length !== 0) words++;
  return words >= MIN_AD_TEXT_WORDS;
}

/**
 * Brave's three queues. New selectors enter the first; each pump takes up to
 * WORK_SIZE selectors from the first non-empty queue; selectors that matched
 * no first-party element move to the next queue, and after the third they
 * stay hidden for good. Un-hidden selectors are never checked again.
 */
export class UnhideQueues {
  private readonly queues: Set<string>[] = [new Set(), new Set(), new Set()];
  private readonly known = new Set<string>();

  /** Queue selectors seen for the first time; returns how many were new. */
  add(selectors: Iterable<string>): number {
    let n = 0;
    for (const s of selectors) {
      if (typeof s !== 'string' || s === '' || this.known.has(s)) continue;
      this.known.add(s);
      this.queues[0].add(s);
      n++;
    }
    return n;
  }

  get pending(): number {
    return this.queues[0].size + this.queues[1].size + this.queues[2].size;
  }

  /** The next workload, or null when every queue is empty. */
  next(size: number = UNHIDE.WORK_SIZE): { queue: number; selectors: string[] } | null {
    for (let q = 0; q < this.queues.length; q++) {
      const set = this.queues[q];
      if (set.size === 0) continue;
      const selectors: string[] = [];
      for (const s of set) {
        selectors.push(s);
        if (selectors.length >= size) break;
      }
      return { queue: q, selectors };
    }
    return null;
  }

  /** Close a workload from next(): `unhidden` selectors leave, the rest move one queue on. */
  settle(work: { queue: number; selectors: readonly string[] }, unhidden: ReadonlySet<string>): void {
    const cur = this.queues[work.queue];
    const nxt = this.queues[work.queue + 1];
    for (const s of work.selectors) {
      cur.delete(s);
      if (nxt !== undefined && !unhidden.has(s)) nxt.add(s);
    }
  }
}
