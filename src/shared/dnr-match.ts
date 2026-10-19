// Bastion Shield — a pure re-implementation of how Chromium evaluates a
// declarativeNetRequest rule condition against one request, plus Chromium's
// choice of the winning rule when several match. Used by the nerd-mode filter
// playground to dry-run freshly compiled rules against recorded requests;
// the browser stays the authority (docs/NERD-MODE.md).
//
// Follows Chromium's url_pattern_index / declarative_net_request semantics:
//   - urlFilter: `||` (start of the host or of a subdomain label), `|` (start
//     or end of the URL), `^` (separator: anything but a letter, digit or
//     `_ - . %`, or the end of the URL), `*` (any run of characters); case-
//     insensitive unless isUrlFilterCaseSensitive. Matched against the
//     canonical URL without its fragment.
//   - regexFilter: RE2 approximated by a JS RegExp (a leading `(?i)` is
//     honoured; anything JS cannot parse never matches and is reported).
//   - request / initiator / top domains: a domain matches itself and its
//     subdomains; when both lists match, the longest (most specific) entry
//     decides and an exact tie goes to the exclusion.
//   - domainType: first party = same registrable domain as the initiator
//     (approximated, see registrableDomain); no initiator = third party.
//   - resourceTypes: without resourceTypes and excludedResourceTypes, every
//     type except main_frame.
//   - responseHeaders conditions cannot be known from a URL: they are ignored
//     and reported as `uncertain`.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { isIpAddress, registrableDomain } from './hash.ts';

export type DnrActionType = 'block' | 'allow' | 'allowAllRequests' | 'redirect' | 'modifyHeaders' | 'upgradeScheme';

/** The parts of chrome.declarativeNetRequest.RuleCondition this matcher understands. */
export interface MatchCondition {
  urlFilter?: string;
  regexFilter?: string;
  isUrlFilterCaseSensitive?: boolean;
  requestDomains?: string[];
  excludedRequestDomains?: string[];
  initiatorDomains?: string[];
  excludedInitiatorDomains?: string[];
  topDomains?: string[];
  excludedTopDomains?: string[];
  domainType?: 'firstParty' | 'thirdParty';
  resourceTypes?: string[];
  excludedResourceTypes?: string[];
  requestMethods?: string[];
  excludedRequestMethods?: string[];
  tabIds?: number[];
  excludedTabIds?: number[];
  responseHeaders?: unknown[];
  excludedResponseHeaders?: unknown[];
}

export interface MatchRule {
  id?: number;
  priority?: number;
  action: { type: DnrActionType | string };
  condition: MatchCondition;
}

export interface MatchRequest {
  url: string;
  /** DNR / webRequest resource type (main_frame, script, …). */
  type: string;
  /** Initiator hostname or URL; null/undefined = browser-initiated (no initiator). */
  initiator?: string | null;
  /** Top-level site hostname or URL (topDomains). Defaults to the initiator. */
  top?: string | null;
  /** HTTP method, any case. Default "get". */
  method?: string;
  /** Request without a tab (service worker, extension): tabId -1. */
  tabless?: boolean;
  tabId?: number;
}

/** A request parsed once, matched against many rules. */
export interface PreparedRequest {
  /** Canonical URL without fragment. */
  spec: string;
  host: string;
  hostStart: number;
  hostEnd: number;
  type: string;
  initiator: string | null;
  top: string | null;
  method: string;
  tabId: number | null;
}

function hostOf(v: string | null | undefined): string | null {
  if (!v) return null;
  const s = v.trim().toLowerCase();
  if (s === '') return null;
  if (s.includes('://')) {
    try {
      const h = new URL(s).hostname;
      return h || null;
    } catch {
      return null;
    }
  }
  return s.replace(/\.$/, '');
}

/** Parse a request; null when the URL is not absolute or cannot be parsed. */
export function prepareRequest(req: MatchRequest): PreparedRequest | null {
  let u: URL;
  try {
    u = new URL(req.url);
  } catch {
    return null;
  }
  u.hash = '';
  // URL keeps an empty "#" when the input had one; Chromium's request URL never carries a fragment.
  const spec = u.href.replace(/#$/, '');
  const host = u.hostname;
  let hostStart = -1;
  if (host) {
    // scheme "//" [user[:password]@] host — the serialised userinfo keeps its percent-encoding.
    const userinfo = u.username || u.password ? `${u.username}${u.password ? `:${u.password}` : ''}@`.length : 0;
    hostStart = u.protocol.length + 2 + userinfo;
    if (spec.slice(hostStart, hostStart + host.length) !== host) hostStart = spec.indexOf(host);
  }
  const tabId = typeof req.tabId === 'number' ? req.tabId : req.tabless ? -1 : null;
  const initiator = hostOf(req.initiator);
  return {
    spec,
    host,
    hostStart,
    hostEnd: hostStart === -1 ? -1 : hostStart + host.length,
    type: req.type,
    initiator,
    top: req.top === undefined ? initiator : hostOf(req.top),
    method: (req.method ?? 'get').toLowerCase(),
    tabId,
  };
}

// ---------------------------------------------------------------------------
// urlFilter
// ---------------------------------------------------------------------------

/** Chromium's separator class for `^`: not alphanumeric and not one of `_ - . %`. */
const SEPARATOR = '[^A-Za-z0-9_\\-.%]';

interface UrlFilterMatcher {
  anchor: 'none' | 'start' | 'host';
  re: RegExp;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

/** Compile a urlFilter into a sticky RegExp plus its left anchor. */
export function compileUrlFilter(filter: string, caseSensitive = false): UrlFilterMatcher {
  let p = filter;
  let anchor: UrlFilterMatcher['anchor'] = 'none';
  if (p.startsWith('||')) {
    anchor = 'host';
    p = p.slice(2);
  } else if (p.startsWith('|')) {
    anchor = 'start';
    p = p.slice(1);
  }
  let end = false;
  if (p.endsWith('|') && !p.endsWith('\\|')) {
    end = true;
    p = p.slice(0, -1);
  }
  let src = '';
  for (const ch of p) {
    if (ch === '*') src += '[\\s\\S]*';
    else if (ch === '^') src += `(?:${SEPARATOR}|$)`;
    else src += escapeRe(ch);
  }
  if (end) src += '$';
  // Sticky for anchored patterns (tested at given offsets), plain search otherwise.
  return { anchor, re: new RegExp(src, `${caseSensitive ? '' : 'i'}${anchor === 'none' ? '' : 'y'}`) };
}

function testUrlFilter(m: UrlFilterMatcher, r: PreparedRequest): boolean {
  if (m.anchor === 'none') return m.re.test(r.spec);
  if (m.anchor === 'start') {
    m.re.lastIndex = 0;
    return m.re.test(r.spec);
  }
  // `||`: the match must start at the host or right after a '.' inside the host.
  if (r.hostStart < 0) return false;
  for (let i = r.hostStart; i <= r.hostEnd; i++) {
    if (i !== r.hostStart && r.spec.charCodeAt(i - 1) !== 0x2e) continue;
    m.re.lastIndex = i;
    if (m.re.test(r.spec)) return true;
  }
  return false;
}

/** True when `urlFilter` matches `url` (no other condition is checked). */
export function urlFilterMatches(urlFilter: string, url: string, caseSensitive = false): boolean {
  const r = prepareRequest({ url, type: 'other' });
  return !!r && testUrlFilter(compileUrlFilter(urlFilter, caseSensitive), r);
}

/** RE2 → JS: a leading `(?i)` becomes the i flag. Throws when JS cannot parse it. */
export function compileRegexFilter(source: string, caseSensitive = false): RegExp {
  let s = source;
  let insensitive = !caseSensitive;
  if (s.startsWith('(?i)')) {
    s = s.slice(4);
    insensitive = true;
  }
  return new RegExp(s, insensitive ? 'i' : '');
}

// ---------------------------------------------------------------------------
// Domains
// ---------------------------------------------------------------------------

/** Length of the longest entry of `list` that `host` equals or is a subdomain of (0 = none). */
function longestMatch(host: string, list: readonly string[] | undefined): number {
  if (!list) return 0;
  let best = 0;
  for (const raw of list) {
    const d = raw.toLowerCase();
    if (d.length <= best) continue;
    if (host === d || (host.length > d.length && host.endsWith(d) && host.charCodeAt(host.length - d.length - 1) === 0x2e)) best = d.length;
  }
  return best;
}

/**
 * Include / exclude domain lists: no lists = match; a host without an entry in
 * `include` (when given) does not match; otherwise the most specific matching
 * entry decides and an exact tie goes to the exclusion.
 */
export function domainListMatches(host: string | null, include?: readonly string[], exclude?: readonly string[]): boolean {
  const hasInc = !!include && include.length > 0;
  const hasExc = !!exclude && exclude.length > 0;
  if (!hasInc && !hasExc) return true;
  if (!host) return !hasInc;
  const inc = hasInc ? longestMatch(host, include) : 0;
  if (hasInc && inc === 0) return false;
  const exc = hasExc ? longestMatch(host, exclude) : 0;
  return exc === 0 || exc < inc;
}

/** Third party: no initiator, or a different registrable domain (IP literals compare exactly). */
export function isThirdParty(host: string, initiator: string | null): boolean {
  if (!initiator) return true;
  if (isIpAddress(host) || isIpAddress(initiator)) return host !== initiator;
  return registrableDomain(host) !== registrableDomain(initiator);
}

// ---------------------------------------------------------------------------
// Conditions
// ---------------------------------------------------------------------------

export interface ConditionMatcher {
  test(r: PreparedRequest): boolean;
  /** Condition keys that were ignored because a URL cannot tell (responseHeaders). */
  uncertain: string[];
  /** Set when the condition cannot be evaluated (e.g. a regex JS rejects); test() is then always false. */
  error?: string;
}

const lower = (a: readonly string[] | undefined): string[] | undefined => a?.map((x) => x.toLowerCase());

/** Precompile a rule condition (regexes are built once). */
export function compileCondition(c: MatchCondition): ConditionMatcher {
  const uncertain: string[] = [];
  if (c.responseHeaders?.length) uncertain.push('responseHeaders');
  if (c.excludedResponseHeaders?.length) uncertain.push('excludedResponseHeaders');
  const cs = c.isUrlFilterCaseSensitive === true;
  let url: UrlFilterMatcher | null = null;
  let regex: RegExp | null = null;
  try {
    if (c.regexFilter !== undefined) regex = compileRegexFilter(c.regexFilter, cs);
    else if (c.urlFilter !== undefined && c.urlFilter !== '') url = compileUrlFilter(c.urlFilter, cs);
  } catch (e) {
    return { test: () => false, uncertain, error: `regexFilter: ${e instanceof Error ? e.message : String(e)}` };
  }
  const types = c.resourceTypes;
  const exTypes = c.excludedResourceTypes;
  const methods = lower(c.requestMethods);
  const exMethods = lower(c.excludedRequestMethods);
  return {
    uncertain,
    test(r) {
      if (types) {
        if (!types.includes(r.type)) return false;
      } else if (exTypes) {
        if (exTypes.includes(r.type)) return false;
      } else if (r.type === 'main_frame') {
        return false;
      }
      if (methods && !methods.includes(r.method)) return false;
      if (exMethods && exMethods.includes(r.method)) return false;
      if (c.tabIds && (r.tabId === null || !c.tabIds.includes(r.tabId))) return false;
      if (c.excludedTabIds && r.tabId !== null && c.excludedTabIds.includes(r.tabId)) return false;
      if (!domainListMatches(r.host, c.requestDomains, c.excludedRequestDomains)) return false;
      if (!domainListMatches(r.initiator, c.initiatorDomains, c.excludedInitiatorDomains)) return false;
      if (!domainListMatches(r.top, c.topDomains, c.excludedTopDomains)) return false;
      if (c.domainType) {
        const third = isThirdParty(r.host, r.initiator);
        if ((c.domainType === 'thirdParty') !== third) return false;
      }
      if (url) return testUrlFilter(url, r);
      if (regex) return regex.test(r.spec);
      return true;
    },
  };
}

/** One-shot convenience: does `rule` match `req`? */
export function ruleMatches(rule: MatchRule, req: MatchRequest): boolean {
  const r = prepareRequest(req);
  return !!r && compileCondition(rule.condition).test(r);
}

// ---------------------------------------------------------------------------
// Which rule wins
// ---------------------------------------------------------------------------

/** Chromium's tie-break among rules of equal priority (higher wins). */
export const ACTION_RANK: Readonly<Record<string, number>> = {
  allow: 5,
  allowAllRequests: 4,
  block: 3,
  upgradeScheme: 2,
  redirect: 1,
  modifyHeaders: 0,
};

export type Outcome = 'block' | 'allow' | 'redirect' | 'upgradeScheme' | 'modifyHeaders' | 'none';

export interface Decision<T extends MatchRule> {
  /** The rule that decides the request (never a modifyHeaders rule), or null. */
  winner: T | null;
  /** modifyHeaders rules that still apply: those above the winning allow, or all when nothing else matched. */
  headers: T[];
  outcome: Outcome;
}

const prio = (r: MatchRule): number => (typeof r.priority === 'number' ? r.priority : 1);
const rank = (r: MatchRule): number => ACTION_RANK[r.action.type] ?? -1;

/**
 * Chromium's evaluation order: the highest-priority rule wins; equal
 * priorities go allow > allowAllRequests > block > upgradeScheme > redirect.
 * modifyHeaders rules apply only when nothing blocks or redirects the
 * request and their priority is above the winning allow.
 */
export function decide<T extends MatchRule>(matching: readonly T[]): Decision<T> {
  let winner: T | null = null;
  for (const r of matching) {
    if (r.action.type === 'modifyHeaders') continue;
    if (!winner || prio(r) > prio(winner) || (prio(r) === prio(winner) && rank(r) > rank(winner))) winner = r;
  }
  const wt = winner?.action.type;
  let headers: T[] = [];
  if (!winner) headers = matching.filter((r) => r.action.type === 'modifyHeaders');
  else if (wt === 'allow' || wt === 'allowAllRequests') headers = matching.filter((r) => r.action.type === 'modifyHeaders' && prio(r) > prio(winner!));
  headers.sort((a, b) => prio(b) - prio(a));
  let outcome: Outcome = 'none';
  if (wt === 'block') outcome = 'block';
  else if (wt === 'redirect') outcome = 'redirect';
  else if (wt === 'upgradeScheme') outcome = 'upgradeScheme';
  else if (headers.length) outcome = 'modifyHeaders';
  else if (wt === 'allow' || wt === 'allowAllRequests') outcome = 'allow';
  return { winner, headers, outcome };
}
