// Bastion Shield — «Labor» explain mode: why would this URL be blocked?
// Runs pasted requests against what is installed right now: the enabled
// static rulesets (their JSON from the package, filter texts from the
// transparency maps), the user's and the admin's custom filters (compiled
// here with the same compiler, so every rule keeps its filter text) and the
// other dynamic and session rules (site off, Standard first-party allow,
// debounce, GPC). Every matching rule is listed, the winner is chosen with
// Chromium's order (src/shared/dnr-match.ts).
//
// Bounded and lazy: nothing loads before the user asks; rulesets are fetched
// and scanned one at a time, in chunks with a yield between them, and only
// rules that pass cheap checks (resource type, request domains, the longest
// literal of the urlFilter) get a compiled matcher. A page-level
// allowAllRequests (the page's own main_frame request, approximated by
// https://<site>/) is evaluated too, as Chromium applies it to the requests of
// that page.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BuildMeta, RuleSourceMap } from '../../shared/types.ts';
import { RULE_ID } from '../../shared/constants.ts';
import { compileCondition, decide, domainListMatches, prepareRequest, type ConditionMatcher, type MatchCondition, type MatchRule, type Outcome, type PreparedRequest } from '../../shared/dnr-match.ts';
import { compilePlayground, filtersOfRule, type DryRequest } from './lab-core.ts';

/** Pasted requests checked against the enabled lists per run. */
export const EXPLAIN_MAX_REQUESTS = 20;
/** Matching rules kept per request (the winner is always kept). */
export const EXPLAIN_MAX_HITS = 50;
/** Rules scanned between two yields to the event loop. */
const CHUNK = 4000;

export interface ExplainProbe {
  request: DryRequest;
  prep: PreparedRequest;
  /** The page's own document request (for allowAllRequests), when the page is known. */
  page: PreparedRequest | null;
  spec: string;
  pageSpec: string;
}

export interface ExplainHit {
  /** Static ruleset id, 'custom', 'admin', '_dynamic' or '_session'. */
  source: string;
  /** Rule id (for custom and admin filters: the 1-based line). */
  ruleId: number;
  priority: number;
  action: string;
  /** Matched through the page's allowAllRequests, not the request itself. */
  page: boolean;
  filters: string[];
}

export interface ExplainResult {
  request: DryRequest;
  hits: ExplainHit[];
  /** More rules matched than EXPLAIN_MAX_HITS. */
  capped: boolean;
  winner: ExplainHit | null;
  headers: ExplainHit[];
  outcome: Outcome;
}

export function makeProbe(request: DryRequest): ExplainProbe | null {
  const prep = prepareRequest({ url: request.url, type: request.type, initiator: request.initiator, tabless: request.tabless });
  if (!prep) return null;
  const page = request.initiator ? prepareRequest({ url: `https://${request.initiator}/`, type: 'main_frame', initiator: null }) : null;
  return { request, prep, page, spec: prep.spec.toLowerCase(), pageSpec: page?.spec.toLowerCase() ?? '' };
}

/** Longest run of literal characters of a urlFilter, lower-cased ('' = none). */
export function urlFilterLiteral(f: string): string {
  let best = '';
  for (const part of f.replace(/^\|\|?/, '').split(/[*^|]/)) if (part.length > best.length) best = part;
  return best.toLowerCase();
}

/**
 * Necessary conditions only (false = cannot match): resource type, request
 * and initiator domains, the urlFilter's longest literal. Everything else is
 * left to compileCondition().
 */
export function mayMatch(c: MatchCondition, p: PreparedRequest, specLower: string): boolean {
  if (c.resourceTypes) {
    if (!c.resourceTypes.includes(p.type)) return false;
  } else if (p.type === 'main_frame' && !c.excludedResourceTypes) {
    return false;
  }
  if (c.requestDomains && !domainListMatches(p.host, c.requestDomains)) return false;
  if (c.initiatorDomains && !domainListMatches(p.initiator, c.initiatorDomains)) return false;
  if (c.urlFilter) {
    const lit = urlFilterLiteral(c.urlFilter);
    if (lit && !specLower.includes(lit)) return false;
  }
  return true;
}

/** A DNR rule as stored in a ruleset file or returned by getDynamicRules(). */
export type ExplainRule = MatchRule & { id?: number };
type Rule = ExplainRule;

interface Pending {
  hits: (ExplainHit & { rule: Rule })[];
  capped: boolean;
}

/** The matcher for one probe; collects hits across sources. */
export class ExplainScan {
  readonly probes: ExplainProbe[];
  private readonly pending: Pending[];

  constructor(probes: ExplainProbe[]) {
    this.probes = probes;
    this.pending = probes.map(() => ({ hits: [], capped: false }));
  }

  /**
   * Test `rules` of one source against every probe. `filtersOf` gives the
   * filter texts of a rule id when they are known up front (custom filters).
   */
  scan(source: string, rules: readonly Rule[], from = 0, to = rules.length, filtersOf?: (id: number) => string[]): void {
    for (let i = from; i < to; i++) {
      const rule = rules[i];
      const c = rule?.condition;
      if (!c || !rule.action) continue;
      let m: ConditionMatcher | null = null;
      for (let pi = 0; pi < this.probes.length; pi++) {
        const p = this.probes[pi];
        let page = false;
        let hit = false;
        if (mayMatch(c, p.prep, p.spec)) {
          m ??= compileCondition(c);
          hit = m.test(p.prep);
        }
        if (!hit && rule.action.type === 'allowAllRequests' && p.page && mayMatch(c, p.page, p.pageSpec)) {
          m ??= compileCondition(c);
          hit = page = m.test(p.page);
        }
        if (!hit) continue;
        const id = typeof rule.id === 'number' ? rule.id : i + 1;
        this.pending[pi].hits.push({
          source,
          ruleId: id,
          priority: typeof rule.priority === 'number' ? rule.priority : 1,
          action: rule.action.type,
          page,
          filters: filtersOf ? filtersOf(id) : [],
          rule,
        });
      }
    }
  }

  /** Rule ids of `source` that matched (to fetch their filter texts). */
  matchedIds(source: string): number[] {
    const out = new Set<number>();
    for (const p of this.pending) for (const h of p.hits) if (h.source === source) out.add(h.ruleId);
    return Array.from(out);
  }

  /** Attach filter texts from a transparency map. */
  describe(source: string, map: RuleSourceMap | null): void {
    for (const p of this.pending) for (const h of p.hits) if (h.source === source && !h.filters.length) h.filters = filtersOfRule(map, h.ruleId);
  }

  results(): ExplainResult[] {
    return this.probes.map((probe, i) => {
      // One filter can compile to several rules with the same action (e.g. a
      // custom filter's line): list each (source, id, action, page) once.
      const seen = new Set<string>();
      const all = this.pending[i].hits.filter((h) => {
        const k = `${h.source}|${h.ruleId}|${h.action}|${h.priority}|${h.page}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      });
      const d = decide(all.map((h) => ({ ...h.rule, priority: h.priority, h })));
      const strip = (x: ExplainHit & { rule: Rule }): ExplainHit => ({ source: x.source, ruleId: x.ruleId, priority: x.priority, action: x.action, page: x.page, filters: x.filters });
      const winner = d.winner ? strip(d.winner.h) : null;
      const sorted = all.slice().sort((a, b) => b.priority - a.priority || a.source.localeCompare(b.source) || a.ruleId - b.ruleId);
      let kept = sorted.slice(0, EXPLAIN_MAX_HITS);
      if (d.winner && !kept.includes(d.winner.h)) kept = [d.winner.h, ...kept.slice(0, EXPLAIN_MAX_HITS - 1)];
      return {
        request: probe.request,
        hits: kept.map(strip),
        capped: sorted.length > kept.length,
        winner,
        headers: d.headers.map((x) => strip(x.h)),
        outcome: d.outcome,
      };
    });
  }
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

export interface ExplainDeps {
  meta: BuildMeta | null;
  /** Ids of the enabled static rulesets (chrome.declarativeNetRequest.getEnabledRulesets). */
  enabledRulesets(): Promise<string[]>;
  /** Package path of a ruleset's rule file (manifest rule_resources), or null. */
  rulesetPath(id: string): string | null;
  /** Packaged JSON, null when missing. */
  fetchJson<T>(path: string): Promise<T | null>;
  dynamicRules(): Promise<Rule[]>;
  sessionRules(): Promise<Rule[]>;
  customText(): Promise<string>;
  adminLines(): readonly string[];
  /** Called before each source: done, total, label (ruleset id or source key). */
  progress?(done: number, total: number, source: string): void;
  /** Yield to the event loop (setTimeout 0 in the page; immediate in tests). */
  yieldNow?(): Promise<void>;
  /** Stop early (a newer run started). */
  cancelled?(): boolean;
}

/** Custom filters compiled here, each rule's id = its line, filters = its line's text. */
function customRules(text: string, meta: BuildMeta | null): { rules: Rule[]; texts: Map<number, string> } {
  const rules: Rule[] = [];
  const texts = new Map<number, string>();
  if (!text.trim()) return { rules, texts };
  for (const f of compilePlayground(text, meta).filters) {
    if (f.kind !== 'network') continue;
    texts.set(f.line, f.text);
    for (const r of f.rules) rules.push({ ...r, id: f.line });
  }
  return { rules, texts };
}

const isCustomId = (id: number | undefined): boolean => typeof id === 'number' && id >= RULE_ID.CUSTOM_START && id <= RULE_ID.ADMIN_END;

/** Explain up to EXPLAIN_MAX_REQUESTS requests against everything installed. Null when cancelled. */
export async function explainInstalled(requests: readonly DryRequest[], deps: ExplainDeps): Promise<ExplainResult[] | null> {
  const probes = requests
    .slice(0, EXPLAIN_MAX_REQUESTS)
    .map(makeProbe)
    .filter((p): p is ExplainProbe => p !== null);
  const scan = new ExplainScan(probes);
  if (!probes.length) return [];
  const pause = deps.yieldNow ?? (() => Promise.resolve());
  const ids = (await deps.enabledRulesets()).slice().sort();
  const total = ids.length + 1;
  let done = 0;

  // Installed custom and admin filters, then the other dynamic and session rules.
  deps.progress?.(done, total, 'custom');
  const user = customRules(await deps.customText(), deps.meta);
  scan.scan('custom', user.rules, 0, user.rules.length, (id) => [user.texts.get(id) ?? '']);
  const admin = customRules(deps.adminLines().join('\n'), deps.meta);
  scan.scan('admin', admin.rules, 0, admin.rules.length, (id) => [admin.texts.get(id) ?? '']);
  const dyn = (await deps.dynamicRules()).filter((r) => !isCustomId(r.id));
  scan.scan('_dynamic', dyn);
  scan.scan('_session', await deps.sessionRules());
  done++;

  for (const id of ids) {
    if (deps.cancelled?.()) return null;
    deps.progress?.(done, total, id);
    await pause();
    const path = deps.rulesetPath(id);
    const rules = path ? await deps.fetchJson<Rule[]>(path) : null;
    if (Array.isArray(rules)) {
      for (let i = 0; i < rules.length; i += CHUNK) {
        scan.scan(id, rules, i, Math.min(rules.length, i + CHUNK));
        if (i + CHUNK < rules.length) {
          await pause();
          if (deps.cancelled?.()) return null;
        }
      }
      if (scan.matchedIds(id).length) scan.describe(id, await deps.fetchJson<RuleSourceMap>(`rulesets/filters/${id}.json`));
    }
    done++;
  }
  deps.progress?.(total, total, '');
  return scan.results();
}

/** Filter texts shown per rule before "+N". */
export const FILTERS_SHOWN = 3;

/**
 * A merged rule can carry hundreds of filter texts (one requestDomains list).
 * Those that name the request's host (or its parent domains) come first.
 */
export function relevantFilters(filters: readonly string[], url: string, max = FILTERS_SHOWN): { shown: string[]; more: number } {
  let host = '';
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    /* no ranking */
  }
  const labels = host.split('.');
  const names = labels.slice(0, -1).map((_, i) => labels.slice(i).join('.'));
  const score = (f: string): number => {
    const lf = f.toLowerCase();
    const i = names.findIndex((n) => lf.includes(n));
    return i === -1 ? names.length : i;
  };
  const list = filters.filter(Boolean);
  const ranked = list.map((f, i) => ({ f, i, s: score(f) })).sort((a, b) => a.s - b.s || a.i - b.i);
  return { shown: ranked.slice(0, max).map((x) => x.f), more: Math.max(0, list.length - max) };
}
