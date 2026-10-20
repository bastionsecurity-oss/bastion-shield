// Bastion Shield — the logic behind the nerd-mode «Entwicklertools» (developer tools) (views/lab.ts),
// free of DOM so node:test can cover it:
//   - filter playground: compile filters exactly like custom filters
//     (compileCustom, same redirect resources, no scriptlets), one filter at a
//     time so every rule stays attributed to its line, then dry-run the rules
//     against recorded or pasted requests with src/shared/dnr-match.ts;
//   - ruleset integrity: compare dist/rulesets/integrity.json with hashes
//     computed in the page;
//   - provenance and blame: what the build fetched (BuildMeta), and upstream
//     history links for a filter (src/shared/blame.ts).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ActivityEvent, ActivityKind, BuildMeta, RuleSourceMap } from '../../shared/types.ts';
import type { DnrRule, ScriptletInfo } from '../../compiler/types.ts';
import type { IntegrityManifest } from '../../../tools/integrity.ts';
import { collectBadfilters, compileCustom, DEFAULT_ENV, preprocess } from '../../compiler/index.ts';
import { classifyLine, splitLines } from '../../compiler/parser.ts';
import { compileCondition, decide, prepareRequest, type ConditionMatcher, type MatchRule, type Outcome } from '../../shared/dnr-match.ts';
import { blameLinks, type BlameLink } from '../../shared/blame.ts';

// ---------------------------------------------------------------------------
// Playground: compile
// ---------------------------------------------------------------------------

/** network: DNR rules; cosmetic / scriptlet: not dry-run; error: rejected; inert: compiled to nothing (e.g. $badfilter). */
export type FilterKind = 'network' | 'cosmetic' | 'scriptlet' | 'error' | 'inert';

export interface PlaygroundFilter {
  /** Position in `filters` (stable id for the dry run). */
  index: number;
  /** 1-based line in the editor. */
  line: number;
  text: string;
  kind: FilterKind;
  rules: DnrRule[];
  /** Compiler rejection reasons (same codes as the custom-filter report). */
  errors: string[];
}

export interface PlaygroundCompile {
  filters: PlaygroundFilter[];
  /** More than PLAYGROUND_MAX_FILTERS filters: the rest was not compiled. */
  truncated: boolean;
}

export const PLAYGROUND_MAX_FILTERS = 1000;

const NO_SCRIPTLETS: ReadonlyMap<string, ScriptletInfo> = new Map();

/** Redirect resources the build shipped (BuildMeta.redirectResources), as background/custom.ts passes them. */
export function redirectMap(meta: BuildMeta | null): Map<string, { path: string; requiresTrust: boolean }> {
  const m = new Map<string, { path: string; requiresTrust: boolean }>();
  for (const [name, path] of Object.entries(meta?.redirectResources ?? {})) {
    if (typeof path === 'string' && path !== '') m.set(name, { path, requiresTrust: false });
  }
  return m;
}

/**
 * Compile the playground text the way custom filters are compiled at runtime
 * (compileCustom), but one filter per call so each DNR rule keeps its line.
 * `!#if` blocks are resolved over the whole text first and `$badfilter`
 * lines cancel their targets across the text, as in the real editor.
 */
export function compilePlayground(text: string, meta: BuildMeta | null): PlaygroundCompile {
  const pre = preprocess(text, DEFAULT_ENV);
  const badfilters = collectBadfilters(pre);
  const redirectResources = redirectMap(meta);
  const filters: PlaygroundFilter[] = [];
  let truncated = false;
  for (const sl of splitLines(pre)) {
    if (classifyLine(sl.text).kind === 'comment') continue;
    if (filters.length >= PLAYGROUND_MAX_FILTERS) {
      truncated = true;
      break;
    }
    const f: PlaygroundFilter = { index: filters.length, line: sl.line, text: sl.text, kind: 'inert', rules: [], errors: [] };
    try {
      const out = compileCustom(sl.text, { redirectResources, scriptlets: NO_SCRIPTLETS, badfilters });
      f.rules = out.rules;
      f.errors = out.errors.map((e) => e.reason);
      if (out.rules.length) f.kind = 'network';
      else if (out.specific.length || out.generic.length) f.kind = 'cosmetic';
      else if (out.scriptletsIgnored) f.kind = 'scriptlet';
      else if (f.errors.length) f.kind = 'error';
    } catch (e) {
      f.kind = 'error';
      f.errors = [`compiler error: ${e instanceof Error ? e.message : String(e)}`];
    }
    filters.push(f);
  }
  return { filters, truncated };
}

// ---------------------------------------------------------------------------
// Playground: requests
// ---------------------------------------------------------------------------

export interface DryRequest {
  url: string;
  /** DNR resource type. */
  type: string;
  /** Initiating page hostname; null = none (counts as third party, never matches $domain=). */
  initiator: string | null;
  tabless?: boolean;
  source: 'history' | 'pasted';
  /** What Bastion did with it (history only). */
  kind?: ActivityKind;
  /** The list that handled it (history only). */
  list?: string;
  /** 0-based line in the pasted-URL box (pasted only). */
  line?: number;
  /** The line named no type: guessed from the file extension (pasted only). */
  typeGuessed?: boolean;
}

/** History events → requests. The initiator is approximated by the tab's top-level site. */
export function requestsFromEvents(events: readonly ActivityEvent[]): DryRequest[] {
  const out: DryRequest[] = [];
  for (const e of events) {
    if (!e || typeof e.url !== 'string') continue;
    out.push({ url: e.url, type: e.type || 'other', initiator: e.site || null, tabless: e.tabId < 0, source: 'history', kind: e.kind, list: e.list });
  }
  return out;
}

/** Type names accepted in pasted lines (uBO spellings and DNR names). */
const TYPE_ALIASES: Readonly<Record<string, string>> = {
  doc: 'main_frame',
  document: 'main_frame',
  main_frame: 'main_frame',
  frame: 'sub_frame',
  subdocument: 'sub_frame',
  sub_frame: 'sub_frame',
  iframe: 'sub_frame',
  script: 'script',
  js: 'script',
  css: 'stylesheet',
  stylesheet: 'stylesheet',
  image: 'image',
  img: 'image',
  font: 'font',
  media: 'media',
  object: 'object',
  xhr: 'xmlhttprequest',
  fetch: 'xmlhttprequest',
  xmlhttprequest: 'xmlhttprequest',
  ping: 'ping',
  beacon: 'ping',
  websocket: 'websocket',
  csp_report: 'csp_report',
  webtransport: 'webtransport',
  webbundle: 'webbundle',
  other: 'other',
};

/** Resource type from the file extension when a pasted line names none. */
export function guessType(url: string): string {
  let path = '';
  try {
    path = new URL(url).pathname.toLowerCase();
  } catch {
    return 'other';
  }
  const ext = /\.([a-z0-9]{1,5})$/.exec(path)?.[1] ?? '';
  if (ext === 'js' || ext === 'mjs') return 'script';
  if (ext === 'css') return 'stylesheet';
  if (/^(png|jpe?g|gif|webp|avif|svg|ico|bmp)$/.test(ext)) return 'image';
  if (/^(woff2?|ttf|otf|eot)$/.test(ext)) return 'font';
  if (/^(mp4|webm|mp3|m4a|ogg|m3u8|ts)$/.test(ext)) return 'media';
  if (ext === 'html' || ext === 'htm') return 'sub_frame';
  return 'other';
}

function hostOfInput(s: string): string | null {
  try {
    return new URL(s.includes('://') ? s : `https://${s}`).hostname || null;
  } catch {
    return null;
  }
}

/**
 * Pasted requests, one per line: `URL [type] [page]`, e.g.
 * `https://ads.example.net/a.js script news.example.ch`. Without a type it is
 * guessed from the file extension; without a page there is no initiator.
 * Blank lines and `!` / `#` comments are skipped.
 */
export function parseUrlList(text: string): { requests: DryRequest[]; invalid: number[] } {
  const requests: DryRequest[] = [];
  const invalid: number[] = [];
  text.split('\n').forEach((raw, i) => {
    const line = raw.trim();
    if (line === '' || line.startsWith('!') || line.startsWith('#')) return;
    const parts = line.split(/\s+/);
    let url = parts[0];
    if (!/^[a-z][a-z0-9+.-]*:/i.test(url)) url = `https://${url}`;
    if (prepareRequest({ url, type: 'other' }) === null) {
      invalid.push(i + 1);
      return;
    }
    let type: string | null = null;
    let page: string | null = null;
    for (const p of parts.slice(1)) {
      const alias = TYPE_ALIASES[p.toLowerCase().replace(/^\$/, '')];
      if (alias && type === null) type = alias;
      else if (page === null) page = hostOfInput(p);
    }
    const req: DryRequest = { url, type: type ?? guessType(url), initiator: page, source: 'pasted', line: i };
    if (type === null) req.typeGuessed = true;
    requests.push(req);
  });
  return { requests, invalid };
}

// ---------------------------------------------------------------------------
// Playground: dry run
// ---------------------------------------------------------------------------

export interface FilterHit {
  request: DryRequest;
  /** What the playground rules together would do with the request. */
  outcome: Outcome;
  /** This filter's rule decides the request (or one of its modifyHeaders rules applies). */
  decided: boolean;
}

export interface FilterDryRun {
  filter: PlaygroundFilter;
  /** Matching requests (exact count; `hits` is capped at HITS_KEPT). */
  matches: number;
  hits: FilterHit[];
  /** Matches this filter decides; the others lose to a higher-priority playground rule. */
  decided: number;
  /** Resource type → matching requests. */
  types: Record<string, number>;
  /** Matching history requests Bastion had already handled (blocked, redirected, …). */
  alreadyHandled: number;
  /** DNR action types of this filter's rules. */
  actions: string[];
  /** Conditions that a URL cannot tell (responseHeaders). */
  uncertain: string[];
  /** Rules the matcher could not evaluate (e.g. a regex JS rejects). */
  ruleErrors: string[];
}

export interface DryRunResult {
  perFilter: FilterDryRun[];
  /** Requests evaluated (unparsable URLs are skipped and counted apart). */
  requests: number;
  unparsable: number;
  /** Requests matched by at least one playground rule. */
  matched: number;
  outcomes: Partial<Record<Outcome, number>>;
}

export const HITS_KEPT = 500;

type Entry = MatchRule & { fi: number; m: ConditionMatcher };

/** Evaluate every network filter of the playground against every request. */
export function dryRun(filters: readonly PlaygroundFilter[], requests: readonly DryRequest[]): DryRunResult {
  const perFilter: FilterDryRun[] = filters.map((f) => ({
    filter: f,
    matches: 0,
    hits: [],
    decided: 0,
    types: {},
    alreadyHandled: 0,
    actions: Array.from(new Set(f.rules.map((r) => r.action.type))),
    uncertain: [],
    ruleErrors: [],
  }));
  const entries: Entry[] = [];
  for (const f of filters) {
    if (f.kind !== 'network') continue;
    const pf = perFilter[f.index];
    for (const rule of f.rules) {
      const m = compileCondition(rule.condition);
      for (const u of m.uncertain) if (!pf.uncertain.includes(u)) pf.uncertain.push(u);
      if (m.error) pf.ruleErrors.push(m.error);
      entries.push({ priority: rule.priority, action: rule.action, condition: rule.condition, fi: f.index, m });
    }
  }
  const result: DryRunResult = { perFilter, requests: 0, unparsable: 0, matched: 0, outcomes: {} };
  for (const req of requests) {
    const prep = prepareRequest({ url: req.url, type: req.type, initiator: req.initiator, tabless: req.tabless });
    if (!prep) {
      result.unparsable++;
      continue;
    }
    result.requests++;
    const matching = entries.filter((e) => e.m.test(prep));
    if (!matching.length) continue;
    result.matched++;
    const d = decide(matching);
    result.outcomes[d.outcome] = (result.outcomes[d.outcome] ?? 0) + 1;
    const deciders = new Set<number>([...(d.winner ? [d.winner.fi] : []), ...d.headers.map((e) => e.fi)]);
    for (const fi of new Set(matching.map((e) => e.fi))) {
      const pf = perFilter[fi];
      const decided = deciders.has(fi);
      pf.matches++;
      if (decided) pf.decided++;
      pf.types[req.type] = (pf.types[req.type] ?? 0) + 1;
      if (req.kind) pf.alreadyHandled++;
      if (pf.hits.length < HITS_KEPT) pf.hits.push({ request: req, outcome: d.outcome, decided });
    }
  }
  return result;
}

/** Hits grouped by URL and type (history repeats the same request), most frequent first. */
export function groupHits(hits: readonly FilterHit[]): { url: string; type: string; count: number; decided: boolean; outcome: Outcome; site: string | null }[] {
  const by = new Map<string, { url: string; type: string; count: number; decided: boolean; outcome: Outcome; site: string | null }>();
  for (const h of hits) {
    const key = `${h.request.type}|${h.request.url}`;
    const g = by.get(key);
    if (g) g.count++;
    else by.set(key, { url: h.request.url, type: h.request.type, count: 1, decided: h.decided, outcome: h.outcome, site: h.request.initiator });
  }
  return Array.from(by.values()).sort((a, b) => b.count - a.count || a.url.localeCompare(b.url));
}

// ---------------------------------------------------------------------------
// Integrity
// ---------------------------------------------------------------------------

export function isIntegrityManifest(x: unknown): x is IntegrityManifest {
  if (!x || typeof x !== 'object') return false;
  const m = x as Partial<IntegrityManifest>;
  if (m.algorithm !== 'sha256' || typeof m.builtAt !== 'string' || !m.files || typeof m.files !== 'object') return false;
  return Object.entries(m.files).every(([k, v]) => typeof k === 'string' && typeof v === 'string' && /^[0-9a-f]{64}$/.test(v));
}

/** Lower-case hex of a digest. */
export function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Package paths to try for a file of the manifest. The Edge package moves the
 * DNR rulesets (rulesets/net/*.json) to the package root (ARCHITECTURE §11.5).
 */
export function packagedCandidates(path: string): string[] {
  if (/^rulesets\/net\/[^/]+$/.test(path)) return [path, path.slice('rulesets/net/'.length)];
  return [path];
}

export type IntegrityStatus = 'pending' | 'ok' | 'mismatch' | 'missing';

export interface IntegrityRow {
  path: string;
  expected: string;
  actual: string | null;
  status: IntegrityStatus;
}

export function integrityRows(m: IntegrityManifest): IntegrityRow[] {
  return Object.keys(m.files)
    .sort()
    .map((path) => ({ path, expected: m.files[path], actual: null, status: 'pending' }));
}

export function settleRow(row: IntegrityRow, actual: string | null): IntegrityRow {
  return { ...row, actual, status: actual === null ? 'missing' : actual === row.expected ? 'ok' : 'mismatch' };
}

export function integritySummary(rows: readonly IntegrityRow[]): Record<IntegrityStatus, number> {
  const s: Record<IntegrityStatus, number> = { pending: 0, ok: 0, mismatch: 0, missing: 0 };
  for (const r of rows) s[r.status]++;
  return s;
}

// ---------------------------------------------------------------------------
// Provenance and blame
// ---------------------------------------------------------------------------

/** "This is exactly what we fetched": BuildMeta sources per list, ready for JSON. */
export function provenance(meta: BuildMeta): {
  builtAt: string;
  extensionVersion: string;
  vendor: BuildMeta['vendor'];
  lists: { id: string; sources: BuildMeta['lists'][number]['sources'] }[];
} {
  return {
    builtAt: meta.builtAt,
    extensionVersion: meta.extensionVersion,
    vendor: meta.vendor,
    lists: meta.lists.map((l) => ({ id: l.id, sources: l.sources ?? [] })),
  };
}

/** "rulesetId:ruleId" (ActivityEvent.rule) → parts; null for malformed values. */
export function parseRuleRef(ref: string | undefined | null): { rulesetId: string; ruleId: number } | null {
  if (typeof ref !== 'string') return null;
  const i = ref.lastIndexOf(':');
  if (i <= 0) return null;
  const rulesetId = ref.slice(0, i);
  const ruleId = Number(ref.slice(i + 1));
  if (!/^[A-Za-z0-9._-]{1,80}$/.test(rulesetId) || !Number.isInteger(ruleId) || ruleId < 1) return null;
  return { rulesetId, ruleId };
}

/** Filter texts of one rule from a transparency map, without the "+N more" marker. */
export function filtersOfRule(map: RuleSourceMap | null, ruleId: number): string[] {
  const texts = map?.[ruleId];
  return Array.isArray(texts) ? texts.filter((s) => typeof s === 'string' && !/^\+\d+ more$/.test(s)) : [];
}

export interface BlameGroup {
  listId: string;
  filter: string;
  links: BlameLink[];
}

/** Upstream history links for `filter` in one list or, with 'all', in every list that has GitHub-backed sources. */
export function blameFor(meta: BuildMeta | null, listId: string, filter: string): BlameGroup[] {
  const lists = (meta?.lists ?? []).filter((l) => listId === 'all' || l.id === listId);
  const out: BlameGroup[] = [];
  for (const l of lists) {
    const links = blameLinks((l.sources ?? []).map((s) => s.url), filter);
    if (links.length) out.push({ listId: l.id, filter, links });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Deep links (context menu, docs/NERD-MODE.md)
// ---------------------------------------------------------------------------

export type LabSection = 'playground' | 'integrity' | 'blame';

export interface LabLink {
  section: LabSection;
  /** #lab?url=…: a URL to explain (with &site= and &type=). */
  url?: string;
  site?: string;
  type?: string;
  /** #lab?filter=… / #lab/blame?filter=…: a filter to try or look up. */
  filter?: string;
}

const LAB_SECTIONS: readonly LabSection[] = ['playground', 'integrity', 'blame'];
/** Longest deep-link value taken over (the context menu sends at most a few KB). */
export const LINK_MAX = 8192;

/**
 * `#lab[/section][?url=&site=&type=|?filter=]` → section and prefill values.
 * Unknown sections fall back to the playground; values are trimmed and
 * bounded, a URL must be http(s), a site must look like a hostname, a type
 * must be a known DNR type (else it is guessed later).
 */
export function parseLabHash(hash: string): LabLink {
  const raw = hash.replace(/^#/, '');
  const q = raw.indexOf('?');
  const path = (q === -1 ? raw : raw.slice(0, q)).toLowerCase();
  const sub = path.split('/')[1] as LabSection | undefined;
  const link: LabLink = { section: sub && LAB_SECTIONS.includes(sub) ? sub : 'playground' };
  if (q === -1) return link;
  let params: URLSearchParams;
  try {
    params = new URLSearchParams(raw.slice(q + 1));
  } catch {
    return link;
  }
  const get = (k: string): string => (params.get(k) ?? '').trim().slice(0, LINK_MAX);
  const url = get('url');
  if (/^https?:\/\/\S+$/i.test(url)) link.url = url;
  const site = get('site').toLowerCase();
  if (/^[a-z0-9.-]{1,253}$/.test(site) && site.includes('.')) link.site = site;
  const type = TYPE_ALIASES[get('type').toLowerCase()];
  if (type) link.type = type;
  const filter = get('filter');
  if (filter) link.filter = filter;
  return link;
}

/**
 * `text` with line `line` (0-based) of the pasted-URL box rewritten as
 * `URL type [page]`: the explain result's type select changes one request.
 */
export function setRequestType(text: string, line: number, req: Pick<DryRequest, 'url' | 'initiator'>, type: string): string {
  const lines = text.split('\n');
  if (line < 0 || line >= lines.length) return text;
  lines[line] = [req.url, type, req.initiator ?? ''].filter(Boolean).join(' ');
  return lines.join('\n');
}

/** DNR resource types offered in the explain result's type select, in display order. */
export const EXPLAIN_TYPES = ['main_frame', 'sub_frame', 'script', 'image', 'stylesheet', 'font', 'xmlhttprequest', 'ping', 'media', 'websocket', 'other'] as const;

/** A pasted-request line (`URL [type] [page]`, see parseUrlList) for a deep link. */
export function linkRequestLine(link: LabLink): string {
  return [link.url ?? '', link.type ?? '', link.site ?? ''].filter(Boolean).join(' ');
}
