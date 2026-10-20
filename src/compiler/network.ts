// Bastion filter compiler — network filters to declarativeNetRequest rules
// (docs/ARCHITECTURE.md §4.4). The semantics follow uBlock Origin's DNR
// converter (static-net-filtering.js dnrFromCompiled) so that lists behave
// as their maintainers test them in uBO Lite; the priorities follow our own
// bands (§4.2) because we add Brave's Standard/Aggressive first-party logic.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { PRIORITY } from '../shared/constants.ts';
import type { DnrAction, DnrCondition, DnrRule, SpecificCosmetic } from './types.ts';
import { DENYALLOW_MODE, NET_DOMAIN_MODE, parseDomainList } from './parser.ts';
import type { DomainEntry, ParsedNetFilter } from './parser.ts';
import { regexToUrlFilter, toRe2 } from './regex.ts';
import { intersectDomains } from './hostname.ts';

/** uBO's network request types, in DNR spelling (everything except main_frame). */
export const NETWORK_TYPES: readonly string[] = [
  'stylesheet', 'image', 'object', 'script', 'xmlhttprequest', 'sub_frame', 'font', 'media', 'websocket', 'ping', 'other',
];
/** Every DNR resource type (used for $all, which includes documents). */
export const ALL_DNR_TYPES: readonly string[] = [
  'main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest', 'ping',
  'csp_report', 'media', 'websocket', 'webtransport', 'webbundle', 'other',
];
const REMOVEPARAM_DEFAULT_TYPES = ['image', 'main_frame', 'sub_frame', 'xmlhttprequest'];
const DOC_TYPES = ['main_frame', 'sub_frame'];

/** Type options -> DNR resource type. */
const TYPE_OPTIONS: ReadonlyMap<string, string> = new Map([
  ['css', 'stylesheet'],
  ['image', 'image'],
  ['object', 'object'],
  ['script', 'script'],
  ['xhr', 'xmlhttprequest'],
  ['frame', 'sub_frame'],
  ['font', 'font'],
  ['media', 'media'],
  ['websocket', 'websocket'],
  ['ping', 'ping'],
  ['other', 'other'],
  ['doc', 'main_frame'],
]);
/** Types DNR cannot filter: uBO handles them outside the network layer. */
const PSEUDO_TYPES = new Set(['popup', 'popunder', 'inline-script', 'inline-font']);
/** Types that make a filter "request typed" (forbidden with $csp/$permissions). */
const REQUEST_TYPE_OPTIONS = new Set(['css', 'font', 'image', 'media', 'other', 'script', 'xhr', 'ping', 'websocket']);
/** Options DNR cannot express: the filter is rejected with this reason. */
const UNSUPPORTED_OPTIONS = new Set([
  'redirect-rule', 'replace', 'urlskip', 'uritransform', 'ipaddress', 'header', 'requestheader', 'strict1p',
  'strict3p', 'cname', 'genericblock', 'webrtc', 'top',
]);
const METHODS = new Set(['connect', 'delete', 'get', 'head', 'options', 'patch', 'post', 'put']);
const reBadCSP = /(?:^|[;,])\s*report-(?:to|uri)\b/i;
const reBadPP = /(?:^|[;,])\s*report-to\b/i;

export type ModifierKind = 'redirect' | 'removeparam' | 'csp' | 'permissions';

/** Option analysis of one network filter (independent of the target list). */
export interface NetAnalysis {
  exception: boolean;
  party: '' | 'firstParty' | 'thirdParty';
  important: boolean;
  matchCase: boolean;
  badfilter: boolean;
  /** Positive DNR types. */
  types: Set<string>;
  /** Positive types DNR cannot express (popup, inline-script …). */
  pseudo: Set<string>;
  /** Cosmetic behaviours of exception filters ($generichide / $specifichide). */
  behavior: Set<'generichide' | 'specifichide'>;
  /** Negated DNR types. */
  notTypes: Set<string>;
  all: boolean;
  from: DomainEntry[] | null;
  to: DomainEntry[] | null;
  denyallow: DomainEntry[] | null;
  methods: string[];
  notMethods: string[];
  modifier: { kind: ModifierKind; value: string } | null;
  reason: string | null;
  /** Set when the filter is valid uBO syntax but cannot be expressed in DNR. */
  unsupported: string | null;
  /** uBO "option units": anything beyond pattern, party and types. */
  hasOptionUnits: boolean;
}

export type AnalyzeResult = { ok: true; a: NetAnalysis } | { ok: false; reason: string };

const invalid = (reason = 'invalid-option'): AnalyzeResult => ({ ok: false, reason });

/**
 * Validate and interpret the options of a parsed network filter, applying
 * the same validity rules as uBO's parser (validateNet), so a filter uBO
 * would reject is rejected here too.
 */
export function analyzeNetFilter(f: ParsedNetFilter): AnalyzeResult {
  const a: NetAnalysis = {
    exception: f.exception,
    party: '',
    important: false,
    matchCase: false,
    badfilter: false,
    types: new Set(),
    pseudo: new Set(),
    behavior: new Set(),
    notTypes: new Set(),
    all: false,
    from: null,
    to: null,
    denyallow: null,
    methods: [],
    notMethods: [],
    modifier: null,
    reason: null,
    unsupported: null,
    hasOptionUnits: false,
  };
  let has1p = false;
  let has3p = false;
  let requestTypeCount = 0;
  let unredirectable = 0;
  let abstractCount = 0;
  let docTypeCount = 0;
  let isMp4 = false;
  const seen = new Set<string>();
  const setModifier = (kind: ModifierKind, value: string): boolean => {
    if (a.modifier !== null) return false;
    a.modifier = { kind, value };
    return true;
  };
  for (const o of f.options) {
    if (!o.known) return invalid(`unknown-option:${o.rawName}`);
    if (o.name !== '_' && seen.has(o.name)) return invalid('duplicate-option');
    seen.add(o.name);
    const hasValue = o.value !== null;
    const name = o.name;
    if (UNSUPPORTED_OPTIONS.has(name)) {
      if (a.unsupported === null) a.unsupported = `unsupported-option:${name}`;
      if (name === 'redirect-rule' && !setModifier('redirect', o.value ?? '')) return invalid();
      continue;
    }
    const dnrType = TYPE_OPTIONS.get(name);
    if (dnrType !== undefined) {
      if (hasValue) return invalid();
      if (o.negated) a.notTypes.add(dnrType);
      else a.types.add(dnrType);
      if (REQUEST_TYPE_OPTIONS.has(name)) requestTypeCount += 1;
      if ((name === 'ping' || name === 'websocket') && !o.negated) unredirectable += 1;
      if (name === 'doc' || name === 'frame' || name === 'object') docTypeCount += 1;
      continue;
    }
    if (PSEUDO_TYPES.has(name)) {
      if (hasValue) return invalid();
      if (!o.negated) a.pseudo.add(name);
      abstractCount += 1;
      unredirectable += 1;
      continue;
    }
    switch (name) {
      case '1p':
      case '3p': {
        if (hasValue) return invalid();
        const first = (name === '1p') !== o.negated;
        if (first) has1p = true;
        else has3p = true;
        break;
      }
      case 'all':
        if (o.negated || hasValue || a.modifier !== null) return invalid();
        a.all = true;
        break;
      case 'badfilter':
        if (o.negated || hasValue) return invalid();
        a.badfilter = true;
        break;
      case '_':
        if (o.negated || hasValue) return invalid();
        break;
      case 'ghide':
      case 'shide':
      case 'ehide':
        if (o.negated || hasValue || a.modifier !== null) return invalid();
        if (name !== 'shide') a.behavior.add('generichide');
        if (name !== 'ghide') a.behavior.add('specifichide');
        unredirectable += 1;
        break;
      case 'csp':
        if (o.negated || (!hasValue && !f.exception) || a.modifier !== null) return invalid();
        if (hasValue && reBadCSP.test(o.value as string)) return invalid('invalid-csp');
        setModifier('csp', o.value ?? '');
        break;
      case 'permissions':
        if (o.negated || (!hasValue && !f.exception) || a.modifier !== null) return invalid();
        if (hasValue && reBadPP.test(o.value as string)) return invalid('invalid-permissions');
        setModifier('permissions', o.value ?? '');
        break;
      case 'redirect':
        if (o.negated || (!hasValue && !f.exception)) return invalid();
        if (!setModifier('redirect', o.value ?? '')) return invalid();
        break;
      case 'empty':
        if (o.negated || hasValue) return invalid();
        if (!setModifier('redirect', 'empty')) return invalid();
        break;
      case 'mp4':
        if (o.negated || hasValue) return invalid();
        if (!setModifier('redirect', 'noopmp4-1s')) return invalid();
        a.types.add('media');
        isMp4 = true;
        break;
      case 'removeparam':
        if (o.negated) return invalid();
        if (!setModifier('removeparam', o.value ?? '')) return invalid();
        break;
      case 'from':
      case 'to': {
        if (o.negated || !hasValue) return invalid();
        const list = parseDomainList(o.value as string, '|', NET_DOMAIN_MODE);
        if (list === null) return invalid('invalid-domain');
        if (name === 'from') a.from = list;
        else a.to = list;
        break;
      }
      case 'denyallow': {
        if (o.negated || !hasValue) return invalid();
        const list = parseDomainList(o.value as string, '|', DENYALLOW_MODE);
        if (list === null) return invalid('invalid-domain');
        a.denyallow = list;
        break;
      }
      case 'method': {
        if (o.negated || !hasValue) return invalid();
        for (const m of (o.value as string).split('|')) {
          const neg = m.startsWith('~');
          const v = (neg ? m.slice(1) : m).toLowerCase();
          if (!METHODS.has(v)) continue;
          if (neg) a.notMethods.push(v);
          else a.methods.push(v);
        }
        a.methods = a.methods.filter((m) => !a.notMethods.includes(m));
        // Unknown methods only: dropping the option would broaden the filter.
        if (a.methods.length === 0 && a.notMethods.length === 0) return invalid('invalid-method');
        break;
      }
      case 'important':
        // `@@…$important` is accepted here; compileNetFilter() allows it only
        // in custom filters (AdGuard-style important exceptions).
        if (o.negated || hasValue) return invalid();
        a.important = true;
        break;
      case 'match-case':
        if (o.negated || hasValue) return invalid();
        a.matchCase = true;
        break;
      case 'reason':
        if (!hasValue) return invalid();
        a.reason = o.value;
        break;
      default:
        return invalid(`unknown-option:${o.rawName}`);
    }
  }
  if (a.denyallow !== null && a.from === null) return invalid('denyallow-without-domain');
  const mod = a.modifier;
  // An important exception lifts blocks; it has no meaning for modifier exceptions.
  if (a.exception && a.important && mod !== null) return invalid();
  if (mod !== null) {
    if (mod.kind === 'csp' || mod.kind === 'permissions') {
      if (abstractCount || a.behavior.size || requestTypeCount) return invalid();
    } else if (mod.kind === 'redirect') {
      if (abstractCount || a.behavior.size || unredirectable) return invalid();
      // $mp4 implies "media" and cannot be combined with any explicit type.
      if (isMp4 && (docTypeCount || requestTypeCount)) return invalid();
    } else if (mod.kind === 'removeparam') {
      if (abstractCount || a.behavior.size) return invalid();
    }
  }
  if (!f.hasOptions && f.pattern.length <= 1) return invalid('pattern-too-short');
  if (has1p !== has3p) a.party = has1p ? 'firstParty' : 'thirdParty';
  a.hasOptionUnits =
    a.from !== null || a.to !== null || a.denyallow !== null || a.modifier !== null || a.notTypes.size !== 0 ||
    a.important || a.methods.length !== 0 || a.notMethods.length !== 0 || a.reason !== null ||
    a.unsupported !== null;
  return { ok: true, a };
}

function domainCanon(list: DomainEntry[] | null): string | null {
  if (list === null) return null;
  return list.map((d) => (d.negated ? '~' : '') + d.value).sort().join('|');
}

/** Pattern as uBO's compiled form would identify it (anchors normalized). */
function patternCanon(f: ParsedNetFilter, a: NetAnalysis): string {
  if (f.kind === 'regex') return `/${f.pattern}/`;
  if (f.kind === 'any') return '*';
  if (f.kind === 'hostname' && (f.hnAnchor || !a.hasOptionUnits)) return `||${f.pattern}^`;
  return (f.hnAnchor ? '||' : f.leftAnchor ? '|' : '') + f.pattern + (f.rightAnchor ? '|' : '');
}

/**
 * $badfilter identity keys: one per type "bucket" (uBO compiles a filter
 * into one entry per type, and $badfilter cancels entries by exact match, so
 * `||x^$script,badfilter` cancels only the script part of `||x^$script,css`).
 * "Just-origin" filters (`*$domain=a|b`, `|https://$domain=a|b`) are further
 * split per hostname, so a badfilter can cancel single hostnames of them.
 */
export function badfilterKeys(f: ParsedNetFilter, a: NetAnalysis): string[] {
  const jo = justOriginDomains(f, a);
  const tokens = typeTokens(a);
  const out: string[] = [];
  if (jo !== null) {
    for (const d of jo) {
      const canon = canonicalFilter(f, a, d);
      for (const t of tokens) out.push(`${canon}|${t}`);
    }
    return out;
  }
  const canon = canonicalFilter(f, a, null);
  for (const t of tokens) out.push(`${canon}|${t}`);
  return out;
}

/** Normalized filter identity (without types); `fromOverride` replaces the $domain list. */
function canonicalFilter(f: ParsedNetFilter, a: NetAnalysis, fromOverride: string | null): string {
  const opts: string[] = [];
  if (a.party !== '') opts.push(a.party === 'firstParty' ? '1p' : '3p');
  if (a.important) opts.push('important');
  if (a.matchCase) opts.push('match-case');
  for (const t of a.notTypes) opts.push(`~${t}`);
  const from = fromOverride ?? domainCanon(a.from);
  if (from !== null) opts.push(`from=${from}`);
  const to = domainCanon(a.to);
  if (to !== null) opts.push(`to=${to}`);
  const deny = domainCanon(a.denyallow);
  if (deny !== null) opts.push(`denyallow=${deny}`);
  if (a.methods.length || a.notMethods.length) {
    opts.push(`method=${[...a.methods, ...a.notMethods.map((m) => `~${m}`)].sort().join('|')}`);
  }
  if (a.modifier !== null) opts.push(`${a.modifier.kind}=${a.modifier.value}`);
  if (a.reason !== null) opts.push(`reason=${a.reason}`);
  if (a.unsupported !== null) opts.push(a.unsupported);
  const pattern = fromOverride !== null && f.kind !== 'any' ? (f.pattern.startsWith('https') ? '|https://' : f.pattern.startsWith('http*') ? '*' : '|http://') : patternCanon(f, a);
  return `${a.exception ? '@@' : ''}${pattern}$${opts.sort().join(',')}`;
}

/**
 * uBO's isJustOrigin(): a pattern-less (or "|http(s)://") filter whose only
 * option unit is a list of positive $domain hostnames. Returns the hostnames.
 */
function justOriginDomains(f: ParsedNetFilter, a: NetAnalysis): string[] | null {
  if (a.from === null || f.kind === 'regex') return null;
  if (
    a.to !== null || a.denyallow !== null || a.modifier !== null || a.notTypes.size !== 0 || a.important ||
    a.methods.length !== 0 || a.notMethods.length !== 0 || a.reason !== null || a.unsupported !== null
  ) {
    return null;
  }
  if (f.kind !== 'any' && !(f.leftAnchor && !f.rightAnchor && /^http[s*]?:(?:\/\/)?$/.test(f.pattern))) return null;
  if (a.from.some((d) => d.negated || d.kind === 'regex')) return null;
  return a.from.map((d) => d.value);
}

/** The type buckets a filter occupies ("*" = all network types). */
function typeTokens(a: NetAnalysis): string[] {
  const set = new Set<string>();
  if (a.all) {
    set.add('*');
    set.add('main_frame');
    set.add('popup');
    set.add('inline-font');
    set.add('inline-script');
  }
  for (const t of a.types) set.add(t);
  for (const t of a.pseudo) set.add(t);
  for (const t of a.behavior) set.add(t);
  if (set.size === 0 && a.modifier !== null && (a.modifier.kind === 'csp' || a.modifier.kind === 'permissions')) {
    set.add('main_frame');
    set.add('sub_frame');
  }
  if (NETWORK_TYPES.every((t) => set.has(t))) {
    for (const t of NETWORK_TYPES) set.delete(t);
    set.add('*');
  }
  if (set.size === 0) set.add('*');
  return Array.from(set).sort();
}

/** Remove the parts cancelled by $badfilter; returns false when nothing remains. */
export function applyBadfilter(f: ParsedNetFilter, a: NetAnalysis, bad: ReadonlySet<string>): boolean {
  if (bad.size === 0) return true;
  const jo = justOriginDomains(f, a);
  if (jo !== null && a.from !== null) {
    // Cancel hostnames whose every type bucket is cancelled.
    const tokens = typeTokens(a);
    const kept = a.from.filter((d) => {
      const canon = canonicalFilter(f, a, d.value);
      return !tokens.every((t) => bad.has(`${canon}|${t}`));
    });
    if (kept.length === 0) return false;
    if (kept.length !== a.from.length) a.from = kept;
    return true;
  }
  const keys = badfilterKeys(f, a);
  const cancelled: string[] = [];
  for (const k of keys) if (bad.has(k)) cancelled.push(k.slice(k.lastIndexOf('|') + 1));
  if (cancelled.length === 0) return true;
  if (cancelled.length === keys.length) return false;
  for (const t of cancelled) {
    if (t === '*') {
      if (a.all) {
        a.all = false;
        if (!cancelled.includes('main_frame')) a.types.add('main_frame');
      }
      // The typeless part is gone: only the remaining explicit buckets stay.
      for (const nt of NETWORK_TYPES) a.types.delete(nt);
      continue;
    }
    if (t === 'main_frame' && a.all) {
      a.all = false;
      for (const nt of ALL_DNR_TYPES) if (nt !== 'main_frame') a.types.add(nt);
      continue;
    }
    a.types.delete(t);
    a.pseudo.delete(t);
    a.behavior.delete(t as 'generichide');
  }
  return a.types.size !== 0 || a.pseudo.size !== 0 || a.behavior.size !== 0 || a.all;
}

export interface RedirectResource {
  path: string;
  requiresTrust: boolean;
}

export interface NetCompileContext {
  listId: string;
  /** Trust of the current line (index.ts updates it at `!#trusted off|on <secret>`). */
  trusted: boolean;
  firstPartyProtected: boolean;
  strictBlock: boolean;
  /**
   * Also emit the first-party copy of modifiers at PRIORITY.MODIFIER_1P
   * (CompileOptions.modifiers1p; always true for custom filters).
   */
  modifiers1p: boolean;
  /** Custom filters: cosmetic flags go to `flagEntries` instead of the list-level host sets. */
  custom: boolean;
  /**
   * `@@…$important` is accepted (user and admin filters only; false for
   * static lists and for lists the user imported, which are third-party text).
   */
  importantExceptions: boolean;
  redirectResources: ReadonlyMap<string, RedirectResource>;
  blockedPagePath: string;
  emit: (rule: DnrRule, source: string) => void;
  usedRedirectResources: Set<string>;
  generichideHosts: Set<string>;
  specifichideHosts: Set<string>;
  flagEntries: SpecificCosmetic[];
  warn: (reason: string) => void;
}

export type NetCompileResult = { ok: true; rules: number } | { ok: false; reason: string };

const sorted = (it: Iterable<string>): string[] => Array.from(new Set(it)).sort();

function strictBlockAction(ctx: NetCompileContext): DnrAction {
  return {
    type: 'redirect',
    redirect: { extensionPath: `${ctx.blockedPagePath}?list=${encodeURIComponent(ctx.listId)}` },
  };
}

function cloneRule(r: DnrRule): DnrRule {
  return JSON.parse(JSON.stringify(r)) as DnrRule;
}

/**
 * First-party copy of a modifier rule ($removeparam, $csp, $permissions,
 * ##^responseheader, and in custom filters their @@ exceptions) at
 * PRIORITY.MODIFIER_1P, above the Standard-mode first-party allow (19), which
 * would otherwise cancel the priority-1 original on same-site subresources.
 * Documents are left to the original (the 1p allow excludes main_frame).
 * Returns null when no other type remains.
 */
function firstPartyCopy(rule: DnrRule): DnrRule | null {
  const r = cloneRule(rule);
  const c = r.condition;
  r.priority = PRIORITY.MODIFIER_1P;
  c.domainType = 'firstParty';
  if (c.resourceTypes !== undefined) {
    const types = c.resourceTypes.filter((t) => t !== 'main_frame');
    if (types.length === 0) return null;
    c.resourceTypes = types;
  } else if (c.excludedResourceTypes !== undefined && !c.excludedResourceTypes.includes('main_frame')) {
    // DNR matches main_frame when only excludedResourceTypes is set.
    c.excludedResourceTypes = sorted([...c.excludedResourceTypes, 'main_frame']);
  }
  return r;
}

/**
 * For main_frame requests the filter's $domain refers to the document being
 * loaded (uBO uses the request hostname as context for top documents), but
 * DNR's initiatorDomains would test the page that started the navigation.
 * Move the main_frame part to its own rule with request domains instead.
 *
 * The same holds for $1p/$3p: uBO treats a document as first-party to itself,
 * while DNR's domainType compares it with the navigation initiator. So the
 * main_frame part drops domainType "firstParty" (always true for uBO) and is
 * dropped entirely for "thirdParty" (never true for uBO). The other types
 * keep domainType: a sub_frame's DNR initiator is its parent document, which
 * is uBO's context too.
 */
export function splitMainFrame(rule: DnrRule): DnrRule[] {
  const c = rule.condition;
  if (c.resourceTypes === undefined || !c.resourceTypes.includes('main_frame')) return [rule];
  if (c.initiatorDomains === undefined && c.excludedInitiatorDomains === undefined && c.domainType === undefined) return [rule];
  const out: DnrRule[] = [];
  const others = c.resourceTypes.filter((t) => t !== 'main_frame');
  if (others.length !== 0) {
    const r = cloneRule(rule);
    r.condition.resourceTypes = others;
    out.push(r);
  }
  const mf = cloneRule(rule);
  const mc = mf.condition;
  mc.resourceTypes = ['main_frame'];
  if (mc.domainType === 'thirdParty') return out;
  delete mc.domainType;
  if (mc.initiatorDomains !== undefined) {
    const req = mc.requestDomains !== undefined ? intersectDomains(mc.requestDomains, mc.initiatorDomains) : mc.initiatorDomains;
    delete mc.initiatorDomains;
    if (req.length === 0) return out;
    mc.requestDomains = sorted(req);
  }
  if (mc.excludedInitiatorDomains !== undefined) {
    mc.excludedRequestDomains = sorted([...(mc.excludedRequestDomains ?? []), ...mc.excludedInitiatorDomains]);
    delete mc.excludedInitiatorDomains;
  }
  out.push(mf);
  return out;
}

function splitDomains(list: DomainEntry[]): { inc: string[]; exc: string[]; incOther: string[]; excOther: number; incTotal: number } {
  const inc: string[] = [];
  const exc: string[] = [];
  const incOther: string[] = [];
  let excOther = 0;
  let incTotal = 0;
  for (const d of list) {
    if (d.negated) {
      if (d.kind === 'host') exc.push(d.value);
      else excOther += 1;
    } else {
      incTotal += 1;
      if (d.kind === 'host') inc.push(d.value);
      else incOther.push(d.value);
    }
  }
  return { inc, exc, incOther, excOther, incTotal };
}

const reRedirectPriority = /:(-?\d+)$/;

/**
 * Hostname at the start of a `||`-anchored pattern ("bing.com/search?" ->
 * "bing.com", "www.google.*\/search" -> "www.google.*", "music.amazon." ->
 * "music.amazon.*"); null when the host part is not a complete hostname.
 */
function hostOfPattern(pattern: string): string | null {
  const end = pattern.search(/[/^:?|*]/);
  const host = end === -1 ? pattern : pattern.slice(0, end);
  const term = end === -1 ? '' : pattern[end];
  const reLabels = /^[a-z0-9-]+(?:\.[a-z0-9-]+)*$/;
  if (term === '*') {
    // "www.google.*/search": an entity, only if the "*" ends the host part.
    const after = pattern.charAt(end + 1);
    if (!host.endsWith('.') || (after !== '' && !/[/^:?|]/.test(after))) return null;
    const base = host.slice(0, -1);
    return reLabels.test(base) ? `${base}.*` : null;
  }
  if (host.endsWith('.')) {
    if (term !== '') return null;
    const base = host.slice(0, -1);
    return reLabels.test(base) ? `${base}.*` : null;
  }
  return reLabels.test(host) && host.includes('.') ? host : null;
}

/** Response headers uBO allows `##^responseheader()` to remove. */
const REMOVABLE_HEADERS = new Set(['location', 'refresh', 'report-to', 'set-cookie']);

/**
 * `example.com##^responseheader(location)`: remove a response header from
 * documents of the listed sites (uBO's only HTML-filtering form that DNR can
 * express). Exceptions are ignored, as in uBO Lite.
 */
export function compileResponseHeaderFilter(
  raw: string,
  entries: DomainEntry[],
  header: string,
  exception: boolean,
  ctx: NetCompileContext,
): NetCompileResult {
  if (exception) return { ok: false, reason: 'unsupported:responseheader-exception' };
  const name = header.trim().toLowerCase();
  if (!REMOVABLE_HEADERS.has(name)) return { ok: false, reason: 'unsupported:responseheader-name' };
  if (entries.length === 0) return { ok: false, reason: 'unsupported:generic-responseheader' };
  const inc: string[] = [];
  const exc: string[] = [];
  let wildcard = false;
  let incTotal = 0;
  for (const d of entries) {
    if (d.negated) {
      if (d.kind === 'host') exc.push(d.value);
      continue;
    }
    incTotal += 1;
    if (d.kind === 'host') inc.push(d.value);
    else if (d.kind === 'wildcard') wildcard = true;
  }
  if (incTotal !== 0 && inc.length === 0 && !wildcard) return { ok: false, reason: 'unsupported-domain:entity-or-regex' };
  const cond: DnrCondition = { resourceTypes: DOC_TYPES.slice() };
  if (inc.length !== 0 && !wildcard) cond.initiatorDomains = sorted(inc);
  if (exc.length !== 0) cond.excludedInitiatorDomains = sorted(exc);
  const base: DnrRule = {
    priority: PRIORITY.MODIFIER,
    action: { type: 'modifyHeaders', responseHeaders: [{ header: name, operation: 'remove' }] },
    condition: cond,
  };
  const all = [base];
  if (ctx.modifiers1p) {
    const copy = firstPartyCopy(base);
    if (copy !== null) all.push(copy);
  }
  let count = 0;
  for (const rule of all) {
    for (const r of splitMainFrame(rule)) {
      ctx.emit(r, raw);
      count += 1;
    }
  }
  return { ok: true, rules: count };
}

/** Compile one analyzed network filter into DNR rules (emitted through ctx). */
export function compileNetFilter(f: ParsedNetFilter, a: NetAnalysis, ctx: NetCompileContext): NetCompileResult {
  // `@@…$important` only in user and admin filters: a third-party list (static
  // or imported by the user) must not be able to override $important blocks
  // (uBO rejects it everywhere).
  if (a.exception && a.important && !ctx.importantExceptions) return { ok: false, reason: 'invalid-option' };
  if (a.unsupported !== null) return { ok: false, reason: a.unsupported };
  const mod = a.modifier;

  // ---- resource types ------------------------------------------------------
  const pos = new Set(a.types);
  if (a.all) for (const t of ALL_DNR_TYPES) pos.add(t);
  const hadPositive = a.types.size !== 0 || a.all || a.pseudo.size !== 0 || a.behavior.size !== 0;
  if (a.behavior.size !== 0 && !a.exception) return { ok: false, reason: 'unsupported-option:generichide-block' };
  if ((mod?.kind === 'csp' || mod?.kind === 'permissions') && pos.size === 0 && !hadPositive) {
    for (const t of DOC_TYPES) pos.add(t);
  }
  if (pos.size === 0 && hadPositive && a.behavior.size === 0) {
    return { ok: false, reason: `unsupported-type:${Array.from(a.pseudo)[0] ?? 'unknown'}` };
  }
  let resourceTypes: string[] | undefined;
  let excludedResourceTypes: string[] | undefined;
  if (pos.size !== 0) {
    for (const t of a.notTypes) pos.delete(t);
    if (pos.size === 0) return { ok: false, reason: 'never-matches' };
    resourceTypes = sorted(pos);
  } else if (a.notTypes.size !== 0) {
    // DNR matches main_frame when only excludedResourceTypes is set (§4.4).
    excludedResourceTypes = sorted([...a.notTypes, 'main_frame']);
  }
  if (mod?.kind === 'removeparam' && resourceTypes === undefined && excludedResourceTypes === undefined) {
    resourceTypes = REMOVEPARAM_DEFAULT_TYPES.slice();
  }

  // ---- pattern ---------------------------------------------------------------
  const cond: DnrCondition = {};
  let patternHosts: string[] | null = null;
  switch (f.kind) {
    case 'regex': {
      const literal = regexToUrlFilter(f.pattern);
      if (literal !== null) {
        cond.urlFilter = literal;
      } else {
        const re2 = toRe2(f.pattern);
        if (re2 === null) return { ok: false, reason: 'regex-not-re2' };
        cond.regexFilter = re2;
      }
      if (a.matchCase) cond.isUrlFilterCaseSensitive = true;
      break;
    }
    case 'hostname':
      if (f.hnAnchor || !a.hasOptionUnits) {
        patternHosts = [f.pattern];
        cond.requestDomains = [f.pattern];
      } else {
        cond.urlFilter = (f.leftAnchor ? '|' : '') + f.pattern + (f.rightAnchor ? '|' : '');
      }
      break;
    case 'any':
      break;
    default: {
      if (f.pattern.length > 1024) return { ok: false, reason: 'pattern-too-long' };
      // uBO's just-origin "|http*://$domain=…" matches any URL of those sites.
      if (f.leftAnchor && /^http\*:(?:\/\/)?$/.test(f.pattern) && justOriginDomains(f, a) !== null) break;
      let p = f.pattern;
      if (!f.hnAnchor && !f.leftAnchor) p = p.replace(/^\*+/, '');
      if (!f.rightAnchor) p = p.replace(/\*+$/, '');
      if (p !== '') cond.urlFilter = (f.hnAnchor ? '||' : f.leftAnchor ? '|' : '') + p + (f.rightAnchor ? '|' : '');
      if (a.matchCase && cond.urlFilter !== undefined && /[A-Za-z]/.test(cond.urlFilter)) {
        cond.isUrlFilterCaseSensitive = true;
      }
    }
  }
  // ---- domains ----------------------------------------------------------------
  const flagsOnly = a.behavior.size !== 0 && pos.size === 0;
  const entityFlagHosts: string[] = [];
  if (a.from !== null) {
    const d = splitDomains(a.from);
    // Entity-only lists can still feed cosmetic flags; DNR needs a hostname.
    if (d.incTotal !== 0 && d.inc.length === 0 && !flagsOnly) return { ok: false, reason: 'unsupported-domain:entity-or-regex' };
    if (d.incOther.length !== 0) ctx.warn('warn:included-entity-dropped');
    if (d.excOther !== 0) ctx.warn('warn:excluded-entity-dropped');
    if (d.inc.length !== 0) cond.initiatorDomains = sorted(d.inc);
    if (d.exc.length !== 0) cond.excludedInitiatorDomains = sorted(d.exc);
    for (const e of d.incOther) if (e.endsWith('.*')) entityFlagHosts.push(e);
  }
  if (a.to !== null) {
    const d = splitDomains(a.to);
    if (d.incTotal !== 0 && d.inc.length === 0 && !flagsOnly) return { ok: false, reason: 'unsupported-domain:entity-or-regex' };
    if (d.incOther.length !== 0) ctx.warn('warn:included-entity-dropped');
    if (d.excOther !== 0) ctx.warn('warn:excluded-entity-dropped');
    if (d.inc.length !== 0) {
      const req = patternHosts !== null ? intersectDomains(patternHosts, d.inc) : d.inc;
      if (req.length === 0) return { ok: false, reason: 'never-matches' };
      cond.requestDomains = sorted(req);
    }
    if (d.exc.length !== 0) cond.excludedRequestDomains = sorted(d.exc);
    if (a.from === null) for (const e of d.incOther) if (e.endsWith('.*')) entityFlagHosts.push(e);
  }
  if (a.denyallow !== null) {
    const hosts = a.denyallow.filter((x) => x.kind === 'host').map((x) => x.value);
    if (hosts.length !== 0) cond.excludedRequestDomains = sorted([...(cond.excludedRequestDomains ?? []), ...hosts]);
  }
  if (a.methods.length !== 0) cond.requestMethods = sorted(a.methods);
  if (a.notMethods.length !== 0) cond.excludedRequestMethods = sorted(a.notMethods);
  if (a.party !== '') cond.domainType = a.party;

  // ---- cosmetic behaviours ($generichide / $specifichide on @@ filters) -------
  if (a.behavior.size !== 0) {
    let hosts = cond.initiatorDomains ?? cond.requestDomains ?? [];
    if (hosts.length === 0 && entityFlagHosts.length === 0 && f.hnAnchor) {
      // "@@||bing.com/search?$generichide": cosmetic flags are per hostname,
      // so apply them to the whole host (uBO matches the URL; uBOL drops it).
      const h = hostOfPattern(f.pattern);
      if (h !== null) {
        ctx.warn('warn:cosmetic-flag-path-broadened');
        if (h.endsWith('.*')) entityFlagHosts.push(h);
        else hosts = [h];
      }
    }
    if (hosts.length === 0 && entityFlagHosts.length === 0) {
      if (pos.size === 0) return { ok: false, reason: 'generichide-without-host' };
    } else {
      for (const flag of a.behavior) {
        if (ctx.custom) {
          ctx.flagEntries.push({ kind: 4, hosts: [...hosts, ...entityFlagHosts], excludedHosts: [], payload: flag, raw: f.raw });
          continue;
        }
        const set = flag === 'generichide' ? ctx.generichideHosts : ctx.specifichideHosts;
        for (const h of hosts) set.add(h);
        if (entityFlagHosts.length !== 0) {
          ctx.flagEntries.push({ kind: 4, hosts: entityFlagHosts.slice(), excludedHosts: [], payload: flag, raw: f.raw });
        }
      }
    }
    if (pos.size === 0) return { ok: true, rules: 0 };
  }

  if (resourceTypes !== undefined) cond.resourceTypes = resourceTypes;
  if (excludedResourceTypes !== undefined) cond.excludedResourceTypes = excludedResourceTypes;

  // ---- action ------------------------------------------------------------------
  const protectedList = ctx.firstPartyProtected;
  let action: DnrAction;
  let priority: number;
  let isBlock = false;
  /** Priority of the third-party copy of a protected-list redirect (BS-1), if any. */
  let redirectCopyPriority: number | null = null;
  if (mod !== null && mod.kind === 'removeparam') {
    const v = mod.value;
    if (v !== '') {
      if (v.startsWith('~')) return { ok: false, reason: 'unsupported:removeparam-negated' };
      if (/^\/.+\/i?$/.test(v) || v.startsWith('|') || v.includes('|')) {
        return { ok: false, reason: 'unsupported:removeparam-regex' };
      }
      // DNR urlFilters must be ASCII; "*" and "^" would be pattern syntax.
      if (/[\s*^]|[^\x21-\x7e]/.test(v)) return { ok: false, reason: 'unsupported:removeparam-value' };
      // Only redirect requests that carry the parameter (uBOL-home#575).
      if (cond.urlFilter === undefined && cond.regexFilter === undefined) {
        cond.urlFilter = `^${v}=`;
      } else if (
        cond.urlFilter !== undefined &&
        cond.urlFilter.startsWith('||') &&
        !cond.urlFilter.endsWith('|') &&
        !cond.urlFilter.toLowerCase().includes(v.toLowerCase())
      ) {
        cond.urlFilter = `${cond.urlFilter}*^${v}=`;
      }
    }
    priority = PRIORITY.MODIFIER;
    action = a.exception
      ? { type: 'allow' }
      : {
          type: 'redirect',
          redirect: v === '' ? { transform: { query: '' } } : { transform: { queryTransform: { removeParams: [v] } } },
        };
  } else if (mod !== null && (mod.kind === 'csp' || mod.kind === 'permissions')) {
    priority = PRIORITY.MODIFIER;
    if (a.exception) {
      // A low-priority allow only cancels other priority-1 modifiers.
      action = { type: 'allow' };
    } else {
      const header = mod.kind === 'csp' ? 'content-security-policy' : 'permissions-policy';
      const value = mod.kind === 'csp' ? mod.value : mod.value.split('|').join(', ');
      // Header values must be printable ASCII for the rule to be valid.
      if (/[^\x20-\x7e]/.test(value)) return { ok: false, reason: `invalid-${mod.kind}` };
      action = { type: 'modifyHeaders', responseHeaders: [{ header, operation: 'append', value }] };
    }
  } else if (mod !== null && mod.kind === 'redirect') {
    if (a.exception) return { ok: false, reason: 'unsupported:redirect-exception' };
    let token = mod.value.trim();
    let n = 0;
    const m = reRedirectPriority.exec(token);
    if (m !== null) {
      n = Math.max(0, parseInt(m[1], 10));
      token = token.slice(0, m.index);
    }
    const res = ctx.redirectResources.get(token);
    if (res === undefined) return { ok: false, reason: `unknown-redirect-resource:${token}` };
    if (res.requiresTrust && !ctx.trusted) return { ok: false, reason: 'untrusted-redirect-resource' };
    if (a.important) priority = PRIORITY.IMPORTANT_REDIRECT + Math.min(8, n);
    else if (protectedList) {
      priority = PRIORITY.REDIRECT_PROTECTED + Math.min(7, n);
      // uBO and Brave serve the stub whatever filter blocked the request, so
      // a third-party copy in the always-apply redirect band wins over
      // always-apply blocks (21). The Standard 1p allow (19) never matches a
      // third-party request, so Standard semantics are unchanged; @@ (30)
      // still wins. restrictRedirectCopies() drops copies no always-apply
      // block can meet.
      if (a.party !== 'firstParty') redirectCopyPriority = PRIORITY.REDIRECT_ALWAYS + Math.min(6, n);
    } else priority = PRIORITY.REDIRECT_ALWAYS + Math.min(6, n);
    action = { type: 'redirect', redirect: { extensionPath: res.path } };
    ctx.usedRedirectResources.add(res.path);
  } else if (a.exception) {
    priority = a.important ? PRIORITY.IMPORTANT_ALLOW : PRIORITY.ALLOW;
    action = { type: 'allow' };
  } else {
    isBlock = true;
    priority = a.important ? PRIORITY.IMPORTANT : protectedList ? PRIORITY.BLOCK_PROTECTED : PRIORITY.BLOCK_ALWAYS;
    action = { type: 'block' };
  }

  const base: DnrRule = { priority, action, condition: cond };
  let count = 0;
  const emit = (r: DnrRule): void => {
    for (const x of splitMainFrame(r)) {
      ctx.emit(x, f.raw);
      count += 1;
    }
  };

  // @@…$document: allowAllRequests for the frame tree (main_frame + sub_frame).
  if (a.exception && mod === null && cond.resourceTypes !== undefined && cond.resourceTypes.includes('main_frame')) {
    const rest = cond.resourceTypes.filter((t) => t !== 'main_frame' && t !== 'sub_frame');
    const aar = cloneRule(base);
    aar.action = { type: 'allowAllRequests' };
    aar.condition.resourceTypes = DOC_TYPES.slice();
    emit(aar);
    if (rest.length !== 0) {
      const r = cloneRule(base);
      r.condition.resourceTypes = rest;
      emit(r);
    }
    return { ok: true, rules: count };
  }

  if (isBlock && ctx.strictBlock && !ctx.custom) {
    const noOptions =
      !hadPositive && a.notTypes.size === 0 && a.party === '' && a.from === null && a.to === null &&
      a.denyallow === null && a.methods.length === 0 && a.notMethods.length === 0;
    if (noOptions && f.kind === 'hostname' && patternHosts !== null) {
      emit(base);
      emit({
        priority: PRIORITY.STRICT_BLOCK,
        action: strictBlockAction(ctx),
        condition: { requestDomains: patternHosts.slice(), resourceTypes: ['main_frame'] },
      });
      return { ok: true, rules: count };
    }
    // "||1.2.3.4:8080^" and other host-only patterns that are not plain
    // hostnames keep their urlFilter (uBOL strict-blocks them too).
    if (noOptions && f.hnAnchor && cond.urlFilter !== undefined && /^\|\|[^*/?|^]+\^$/.test(cond.urlFilter)) {
      emit(base);
      emit({
        priority: PRIORITY.STRICT_BLOCK,
        action: strictBlockAction(ctx),
        condition: { urlFilter: cond.urlFilter, resourceTypes: ['main_frame'] },
      });
      return { ok: true, rules: count };
    }
    if (cond.resourceTypes !== undefined && cond.resourceTypes.includes('main_frame')) {
      const rest = cond.resourceTypes.filter((t) => t !== 'main_frame');
      if (rest.length !== 0) {
        const r = cloneRule(base);
        r.condition.resourceTypes = rest;
        emit(r);
      }
      const sb = cloneRule(base);
      sb.priority = PRIORITY.STRICT_BLOCK;
      sb.action = strictBlockAction(ctx);
      sb.condition.resourceTypes = ['main_frame'];
      emit(sb);
      return { ok: true, rules: count };
    }
  }
  emit(base);
  if (redirectCopyPriority !== null) {
    const copy = cloneRule(base);
    copy.priority = redirectCopyPriority;
    copy.condition.domainType = 'thirdParty';
    emit(copy);
  } else if (
    mod !== null && mod.kind !== 'redirect' && ctx.modifiers1p && a.party !== 'thirdParty' && (!a.exception || ctx.custom)
  ) {
    // Static lists get no exception copies: a list's own @@…$removeparam
    // stays a priority-1 allow, as in Brave. In custom filters the copy keeps
    // the user's @@ able to cancel the user's own first-party copies (allow
    // wins a tie; modifyHeaders needs a strictly higher priority).
    const copy = firstPartyCopy(base);
    if (copy !== null) emit(copy);
  }
  return { ok: true, rules: count };
}
