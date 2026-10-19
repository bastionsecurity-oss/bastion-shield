// Bastion Shield — «Entwicklertools» (developer tools), check URL against installed rules: why would this URL be blocked?
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
import { PRIORITY, RULE_ID } from '../../shared/constants.ts';
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

/**
 * What a rule does, in words a user knows (the raw DNR action stays visible
 * next to it): a redirect can be a strict block page, a surrogate script, a
 * tracking-parameter strip or a bounce-tracking skip.
 */
export type ActionKind = 'block' | 'allow' | 'page' | 'strict' | 'surrogate' | 'params' | 'debounce' | 'redirect' | 'headers' | 'gpc' | 'upgrade';

export interface ExplainHit {
  /** Static ruleset id, 'custom', 'admin', '_dynamic' or '_session'. */
  source: string;
  /** Rule id (for custom and admin filters: the 1-based line). */
  ruleId: number;
  priority: number;
  action: string;
  kind: ActionKind;
  /** Matched through the page's allowAllRequests, not the request itself. */
  page: boolean;
  /** Filter texts recorded for the rule (a merged rule keeps only the first ones). */
  filters: string[];
  /** Filters merged into the rule, including those not recorded (>= filters.length). */
  filterCount: number;
  /** The rule's requestDomains entry that matched the request host (merged rules), or null. */
  matchedDomain: string | null;
  /**
   * The filter text for matchedDomain, rebuilt from a recorded sibling of the
   * merged rule (e.g. `||000491b06a.com^` -> `||googlesyndication.com^`) when
   * the text itself was not recorded.
   */
  derived?: string;
}

/** The parts of a DNR action actionKind() looks at. */
export interface KindAction {
  type: string;
  redirect?: { extensionPath?: string; regexSubstitution?: string; url?: string; transform?: { query?: string; queryTransform?: { removeParams?: unknown } } };
  requestHeaders?: { header?: string }[];
}

/** Human kind of a DNR rule (see ActionKind). */
export function actionKind(rule: { priority?: number; action: KindAction }): ActionKind {
  const a = rule.action;
  switch (a.type) {
    case 'allow':
      return 'allow';
    case 'allowAllRequests':
      return 'page';
    case 'block':
      return 'block';
    case 'upgradeScheme':
      return 'upgrade';
    case 'modifyHeaders':
      return (a.requestHeaders ?? []).some((x) => typeof x?.header === 'string' && x.header.toLowerCase() === 'sec-gpc') ? 'gpc' : 'headers';
    case 'redirect': {
      const r = a.redirect ?? {};
      const path = typeof r.extensionPath === 'string' ? r.extensionPath : '';
      const target = `${path} ${typeof r.regexSubstitution === 'string' ? r.regexSubstitution : ''} ${typeof r.url === 'string' ? r.url : ''}`;
      if (/pages\/blocked\.html/.test(target) || rule.priority === PRIORITY.STRICT_BLOCK) return 'strict';
      if (/pages\/bounce\.html/.test(target) || rule.priority === PRIORITY.DEBOUNCE) return 'debounce';
      if (r.transform && (r.transform.queryTransform?.removeParams !== undefined || r.transform.query === '')) return 'params';
      if (/^\/?war\//.test(path)) return 'surrogate';
      return 'redirect';
    }
    default:
      return 'redirect';
  }
}

/** Why an allow decides, for the verdict: Bastion's own rules by id, else a filter exception. */
export type AllowReason = 'siteOff' | 'proceed' | 'bisect' | 'standard1p' | 'exception';

export function allowReason(hit: Pick<ExplainHit, 'source' | 'ruleId'>): AllowReason {
  const id = hit.ruleId;
  if (hit.source === '_session') {
    if (id >= RULE_ID.SESSION_PROCEED_START && id <= RULE_ID.SESSION_PROCEED_END) return 'proceed';
    if (id >= RULE_ID.SESSION_BISECT_START && id <= RULE_ID.SESSION_BISECT_END) return 'bisect';
    if (id >= RULE_ID.SESSION_SITES_DISABLED_NO_TAB && id < RULE_ID.SESSION_PROCEED_START) return 'siteOff';
  }
  if (hit.source === '_dynamic') {
    if (id >= RULE_ID.SITES_DISABLED && id < RULE_ID.STANDARD_1P_ALLOW) return 'siteOff';
    if (id >= RULE_ID.STANDARD_1P_ALLOW && id < RULE_ID.GPC_HEADER) return 'standard1p';
  }
  return 'exception';
}

const isAllow = (action: string): boolean => action === 'allow' || action === 'allowAllRequests';

/** What would decide the request without the deciding exception. */
export interface Counterfactual {
  /** The rule that would decide instead (never a modifyHeaders rule), or null. */
  winner: ExplainHit | null;
  /** First header rule that would still apply (e.g. GPC). */
  headers: ExplainHit | null;
  outcome: Outcome;
}

/**
 * "Without this exception": when an allow or allowAllRequests decides, drop
 * it and every other allow of the same kind (same action and the same
 * reason: protection off, proceed anyway, bisect, Standard 1p, or a filter
 * exception) and decide again in Chromium's order (dnr-match.ts decide()).
 * Null when the decider is not an allow.
 */
export function counterfactual(hits: readonly ExplainHit[], winner: ExplainHit | null): Counterfactual | null {
  if (!winner || !isAllow(winner.action)) return null;
  const reason = allowReason(winner);
  const same = (x: ExplainHit): boolean => x.action === winner.action && allowReason(x) === reason;
  const rest = hits.filter((x) => x !== winner && !same(x));
  const d = decide(rest.map((x) => ({ priority: x.priority, action: { type: x.action }, condition: {}, x })));
  return { winner: d.winner?.x ?? null, headers: d.headers[0]?.x ?? null, outcome: d.outcome };
}

export interface ExplainResult {
  request: DryRequest;
  hits: ExplainHit[];
  /** More rules matched than EXPLAIN_MAX_HITS. */
  capped: boolean;
  winner: ExplainHit | null;
  headers: ExplainHit[];
  outcome: Outcome;
  /** The decision without the deciding exception (only when an allow decides). */
  counterfactual: Counterfactual | null;
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
        const priority = typeof rule.priority === 'number' ? rule.priority : 1;
        const filters = filtersOf ? filtersOf(id) : [];
        const host = (page ? p.page : p.prep)?.host ?? '';
        this.pending[pi].hits.push({
          source,
          ruleId: id,
          priority,
          action: rule.action.type,
          kind: actionKind({ priority, action: rule.action as KindAction }),
          page,
          filters,
          filterCount: filters.length,
          matchedDomain: c.requestDomains && c.requestDomains.length > 1 ? longestDomain(host, c.requestDomains) : null,
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

  /** Attach filter texts from a transparency map (and the count of merged filters it records). */
  describe(source: string, map: RuleSourceMap | null): void {
    for (const p of this.pending) {
      for (const h of p.hits) {
        if (h.source !== source || h.filters.length) continue;
        h.filters = filtersOfRule(map, h.ruleId);
        h.filterCount = h.filters.length + moreOfRule(map, h.ruleId);
        const d = h.matchedDomain;
        if (d && !h.filters.some((f) => mentionsDomain(f, d))) {
          const text = deriveFilter(h.filters, h.rule.condition.requestDomains ?? [], d);
          if (text) h.derived = text;
        }
      }
    }
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
      const stripped = new Map<ExplainHit & { rule: Rule }, ExplainHit>();
      const strip = (x: ExplainHit & { rule: Rule }): ExplainHit => {
        let o = stripped.get(x);
        if (!o) {
          o = { source: x.source, ruleId: x.ruleId, priority: x.priority, action: x.action, kind: x.kind, page: x.page, filters: x.filters, filterCount: Math.max(x.filterCount, x.filters.length), matchedDomain: x.matchedDomain };
          if (x.derived) o.derived = x.derived;
          stripped.set(x, o);
        }
        return o;
      };
      const winner = d.winner ? strip(d.winner.h) : null;
      // Over every matching rule, not only the listed ones.
      const cf = counterfactual(all.map(strip), winner);
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
        counterfactual: cf,
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

/** "+N more" count recorded at the end of a transparency-map entry (0 when none). */
export function moreOfRule(map: RuleSourceMap | null, ruleId: number): number {
  const texts = map?.[ruleId];
  if (!Array.isArray(texts)) return 0;
  let n = 0;
  for (const s of texts) {
    const m = typeof s === 'string' ? /^\+(\d+) more$/.exec(s) : null;
    if (m) n += Number(m[1]);
  }
  return n;
}

/** Longest entry of `list` that `host` equals or is a subdomain of, or null. */
export function longestDomain(host: string, list: readonly string[]): string | null {
  const hst = host.toLowerCase();
  let best: string | null = null;
  for (const raw of list) {
    const d = raw.toLowerCase();
    if (best && d.length <= best.length) continue;
    if (hst === d || (hst.length > d.length && hst.endsWith(`.${d}`))) best = d;
  }
  return best;
}

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
const DOMAIN_TOKEN = /[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+/gi;

/** `filter` names `domain` as a whole domain (not inside a longer name). */
export function mentionsDomain(filter: string, domain: string): boolean {
  return new RegExp(`(?:^|[^a-z0-9_.-])${escapeRe(domain.toLowerCase())}(?:$|[^a-z0-9_.-])`).test(filter.toLowerCase());
}

/**
 * Rebuild the filter text of `domain` in a merged rule from a recorded
 * sibling: the first recorded text that names exactly one of the rule's
 * domains, with that domain replaced. Null when no sibling fits.
 */
export function deriveFilter(filters: readonly string[], ruleDomains: readonly string[], domain: string): string | null {
  if (!ruleDomains.length) return null;
  const set = new Set(ruleDomains.map((d) => d.toLowerCase()));
  for (const f of filters) {
    const names = Array.from(f.matchAll(DOMAIN_TOKEN), (m) => ({ text: m[0], at: m.index ?? 0 })).filter((m) => set.has(m.text.toLowerCase()));
    if (names.length !== 1) continue;
    const n = names[0]!;
    return f.slice(0, n.at) + domain + f.slice(n.at + n.text.length);
  }
  return null;
}

export interface FilterDisplay {
  /** Filter texts shown in the cell. */
  shown: string[];
  /** How many of `shown` (from the start) belong to this request and are highlighted. */
  relevant: number;
  /** The shown text was rebuilt from the rule's domain list (ExplainHit.derived). */
  derived: boolean;
  /** Merged filters not shown ("+N more"). */
  more: number;
}

/**
 * The filter cell of an explain row. A merged rule can carry thousands of
 * filters (one requestDomains list) of which only the first few are
 * recorded: those naming the request host or one of its parent domains come
 * first and are highlighted (or the text is rebuilt for the matched domain),
 * the rest is "+N more". When nothing can be tied to the request, the first
 * recorded texts are shown as before.
 */
export function filterDisplay(hit: Pick<ExplainHit, 'filters' | 'filterCount' | 'matchedDomain' | 'derived'>, url: string, max = FILTERS_SHOWN): FilterDisplay {
  const list = hit.filters.filter(Boolean);
  const total = Math.max(hit.filterCount, list.length);
  let host = '';
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    /* no ranking */
  }
  const labels = host ? host.split('.') : [];
  // The host and its parent domains, most specific first (never the bare TLD).
  const names = labels.slice(0, -1).map((_, i) => labels.slice(i).join('.'));
  if (hit.matchedDomain && !names.includes(hit.matchedDomain)) names.push(hit.matchedDomain);
  const rank = (f: string): number => {
    const i = names.findIndex((n) => mentionsDomain(f, n));
    return i === -1 ? Infinity : i;
  };
  const relevant = list
    .map((f, i) => ({ f, i, r: rank(f) }))
    .filter((x) => x.r !== Infinity)
    .sort((a, b) => a.r - b.r || a.i - b.i)
    .map((x) => x.f);
  if (total > 1 && relevant.length) {
    const shown = relevant.slice(0, max);
    return { shown, relevant: shown.length, derived: false, more: Math.max(0, total - shown.length) };
  }
  if (total > 1 && hit.derived) return { shown: [hit.derived], relevant: 1, derived: true, more: Math.max(0, total - 1) };
  const shown = list.slice(0, max);
  return { shown, relevant: 0, derived: false, more: Math.max(0, total - shown.length) };
}
