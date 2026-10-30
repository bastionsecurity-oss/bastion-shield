// Bastion Shield — nerd mode filter bisect: the pure state machine behind
// "Find the breaking filter" (docs/NERD-MODE.md). No chrome.* here; the
// service worker (background/nerd-bisect.ts) turns each test into session
// allow rules and a reload, and feeds the user's "does it work now?" back in.
//
// Model: the page is broken while some set R of the blocked hosts stays
// blocked, and works once every host in R is let through (monotone). The
// usual case is |R| = 1.
//
//   1. Verify: let every candidate through. Still broken -> 'clean': the cause
//      is not a network block (cosmetic filter, scriptlet, privacy script,
//      or the site itself).
//   2. Binary search with pins. Invariants: allowing K (pinned) alone is
//      broken, allowing K ∪ S (suspects) works. Test K ∪ A, A = first half of
//      S. Works -> S = A. Broken -> S \ A holds a needed host: pin A
//      (K = K ∪ A), S = S \ A. Both keep the invariants; |S| = 1 leaves a host
//      s that is needed given K. This takes ceil(log2 n) steps after the
//      verify step.
//   3. If hosts were pinned, s alone may not be enough (two blocks interact):
//      test the found hosts F alone (one more step, also with a single
//      culprit; 'found' then lets exactly F through). Works -> done. Broken -> search the
//      pinned hosts again with F pinned. After MAX_ROUNDS the result is F plus
//      the unresolved pool, which is known to work together (best effort).
//
// A single culprit among n candidates therefore takes at most
// 2 + ceil(log2 n) answers (1 for n = 1); bisectProgress shows that bound.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { RULE_ID } from './constants.ts';

/** Candidates kept for one bisect (most blocked requests first): 8 halving steps at most. */
export const MAX_CANDIDATES = 256;
/** Culprit rounds before giving up on separating interacting hosts. */
export const MAX_ROUNDS = 3;

export interface BisectMachine {
  /** Every candidate host, in test order. */
  hosts: string[];
  /** What the current test checks. */
  test: 'all' | 'half' | 'found';
  /** Hosts let through for the current test. */
  allowed: string[];
  /** Hosts pinned open (K). */
  pinned: string[];
  /** Suspects (S). */
  suspects: string[];
  /** The half of S under test ('half' tests). */
  half: string[];
  /** Hosts known to be needed (F). */
  found: string[];
  /** Hosts that may still be needed together with F ('found' tests). */
  pool: string[];
  /** Tests answered so far. */
  answered: number;
  rounds: number;
  result: 'testing' | 'found' | 'clean';
  /** Hosts to let through for the page to work (result 'found'). */
  culprits: string[];
  /** Interacting hosts could not be fully separated: `culprits` is a working superset. */
  partial: boolean;
}

const uniq = (xs: readonly string[]): string[] => Array.from(new Set(xs));
const minus = (xs: readonly string[], ys: readonly string[]): string[] => {
  const s = new Set(ys);
  return xs.filter((x) => !s.has(x));
};

/** Worst-case remaining tests for |S| suspects, including the current one. */
export function halvingSteps(n: number): number {
  return n <= 1 ? 0 : Math.ceil(Math.log2(n));
}

/** Hostnames DNR accepts in requestDomains: lower-case ASCII (punycode) or IPv4. */
export function isBisectableHost(host: string): boolean {
  return host.length > 0 && host.length <= 253 && /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(host);
}

function done(m: BisectMachine, culprits: string[], partial = false): BisectMachine {
  return { ...m, result: 'found', culprits: uniq(culprits), partial, allowed: uniq(culprits), half: [] };
}

function nextHalf(m: BisectMachine): BisectMachine {
  // floor: lets fewer hosts through per test (the page stays closer to protected).
  const half = m.suspects.slice(0, Math.max(1, Math.floor(m.suspects.length / 2)));
  return { ...m, test: 'half', half, allowed: uniq([...m.pinned, ...half]) };
}

/** A host s was isolated (needed given the pins): verify the found set or finish. */
function isolated(m: BisectMachine, s: string): BisectMachine {
  const found = uniq([...m.found, s]);
  const pool = minus(m.pinned, found);
  const next = { ...m, found, pool, suspects: [], half: [] };
  // Nothing was pinned besides earlier finds: F ∪ pool = F works (invariant).
  if (pool.length === 0) return done(next, found);
  if (next.rounds >= MAX_ROUNDS) return done(next, [...found, ...pool], true);
  return { ...next, test: 'found', allowed: found };
}

/** Start a bisect over `hosts` (deduplicated, test order kept). No candidates: 'clean'. */
export function startBisect(hosts: readonly string[]): BisectMachine {
  const all = uniq(hosts).slice(0, MAX_CANDIDATES);
  const m: BisectMachine = {
    hosts: all,
    test: 'all',
    allowed: all,
    pinned: [],
    suspects: all,
    half: [],
    found: [],
    pool: [],
    answered: 0,
    rounds: 1,
    result: 'testing',
    culprits: [],
    partial: false,
  };
  return all.length === 0 ? { ...m, result: 'clean', allowed: [] } : m;
}

/** Feed the answer to "does the page work now?" for the current test. Finished machines are returned unchanged. */
export function answerBisect(prev: BisectMachine, works: boolean): BisectMachine {
  if (prev.result !== 'testing') return prev;
  const m = { ...prev, answered: prev.answered + 1 };
  if (m.test === 'all') {
    if (!works) return { ...m, result: 'clean', allowed: [] };
    if (m.hosts.length === 1) return done(m, m.hosts);
    return nextHalf({ ...m, pinned: [], suspects: m.hosts });
  }
  if (m.test === 'half') {
    const next = works ? { ...m, suspects: m.half } : { ...m, pinned: uniq([...m.pinned, ...m.half]), suspects: minus(m.suspects, m.half) };
    if (next.suspects.length === 1) return isolated(next, next.suspects[0]!);
    return nextHalf(next);
  }
  // test 'found': F alone.
  if (works) return done(m, m.found);
  const round = { ...m, rounds: m.rounds + 1, pinned: m.found, suspects: m.pool, pool: [] };
  if (round.suspects.length === 1) return isolated(round, round.suspects[0]!);
  return nextHalf(round);
}

/**
 * 1-based number of the current test and the worst case for a single
 * culprit, for "bisect 2/≤5". The bound is tight: verify, ⌈log₂ n⌉ halvings
 * and (whenever a half had to be pinned, which the longest path always does)
 * one check of the culprit alone. Only interacting hosts make the search
 * longer; the bound then grows, and it never drops below the current step.
 */
export function bisectProgress(m: BisectMachine): { step: number; maxSteps: number } {
  const step = m.answered + 1;
  if (m.result !== 'testing') return { step: m.answered, maxSteps: m.answered };
  let rest: number;
  if (m.test === 'all') rest = m.hosts.length === 1 ? 1 : 2 + halvingSteps(m.hosts.length);
  else if (m.test === 'half') rest = halvingSteps(m.suspects.length) + 1;
  else rest = 1;
  return { step, maxSteps: Math.max(step, m.answered + rest) };
}

/** Toolbar badge text while a test runs ("2/5"; the badge has room for about four characters). */
export function badgeStep(m: BisectMachine): string | null {
  if (m.result !== 'testing') return null;
  const { step, maxSteps } = bisectProgress(m);
  const text = `${step}/${maxSteps}`;
  return text.length <= 4 ? text : String(step);
}

/**
 * DNR conditions that let exactly `allowed` through among `all` candidates.
 * requestDomains also matches subdomains, so an allowed host with a still
 * blocked candidate below it gets its own condition with that host in
 * excludedRequestDomains (which takes precedence). The rest share one.
 */
export function allowConditions(allowed: readonly string[], all: readonly string[]): { requestDomains: string[]; excludedRequestDomains?: string[] }[] {
  const blocked = minus(all, allowed);
  const shared: string[] = [];
  const own: { requestDomains: string[]; excludedRequestDomains: string[] }[] = [];
  for (const a of uniq(allowed)) {
    const below = blocked.filter((b) => b.endsWith(`.${a}`));
    if (below.length === 0) shared.push(a);
    else own.push({ requestDomains: [a], excludedRequestDomains: below });
  }
  return [...(shared.length ? [{ requestDomains: shared }] : []), ...own];
}

/** Session-rule ids reserved for bisect tests (RULE_ID.SESSION_BISECT_*). */
export function isBisectRuleId(id: number): boolean {
  return id >= RULE_ID.SESSION_BISECT_START && id <= RULE_ID.SESSION_BISECT_END;
}

/**
 * The filter carries the `important` option. Options follow the last `$`
 * (a `$` inside a /regex/ pattern is not an option separator).
 */
export function isImportantFilter(text: string): boolean {
  const t = text.trim();
  if (t.startsWith('!') || t.includes('##') || t.includes('#@#') || t.includes('#?#')) return false;
  const i = t.lastIndexOf('$');
  if (i < 0 || ((t.startsWith('/') || t.startsWith('@@/')) && t.indexOf('/', i) > i)) return false;
  return t
    .slice(i + 1)
    .split(',')
    .some((o) => o.trim().toLowerCase() === 'important');
}

/**
 * Narrow exception lines for the user's custom filters ("keep", "allow").
 * A host blocked by an `$important` filter needs an important exception
 * (`@@…$important` ranks above important blocks in custom filters only):
 * known from the filter text, or from `important` when the block came from a
 * rule without one (the user's own filters, an imported list).
 */
export function keepFilterLines(
  culprits: readonly { host: string; filters?: readonly string[]; important?: boolean }[],
  site: string,
  day: string,
  via: 'bisect' | 'allow' = 'bisect',
): string[] {
  const seen = new Set<string>();
  const lines = [`! Bastion ${via} ${day}: ${site}`];
  for (const c of culprits) {
    if (seen.has(c.host)) continue;
    seen.add(c.host);
    const important = c.important === true || (c.filters ?? []).some(isImportantFilter);
    lines.push(`@@||${c.host}^$domain=${site}${important ? ',important' : ''}`);
  }
  return lines;
}

// ---------------------------------------------------------------------------
// Cosmetic phase: the same machine over list ids, then over selectors
// ---------------------------------------------------------------------------

/** Pseudo list id for the user's, the admin's and imported lists' cosmetic filters. */
export const CUSTOM_COSMETIC = 'custom';

/**
 * The `#@#` body that cancels a host-specific cosmetic entry, from the text
 * the cosmetic data keeps: a selector (kind 0), `sel { style }` (kind 3,
 * written back as `sel:style(style)`) or a procedural filter's raw text.
 */
export function cosmeticExceptionBody(selector: string): string {
  const m = /^(.*\S) \{ (.*) \}$/s.exec(selector);
  return m ? `${m[1]}:style(${m[2]})` : selector;
}

/** "keep" for cosmetic culprits: one `site#@#…` exception per selector. */
export function keepCosmeticLines(selectors: readonly string[], site: string, day: string): string[] {
  const bodies = Array.from(new Set(selectors.map(cosmeticExceptionBody)));
  return [`! Bastion bisect ${day}: ${site}`, ...bodies.map((b) => `${site}#@#${b}`)];
}
