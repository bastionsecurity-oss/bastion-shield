// Bastion filter compiler — build-time pruning of the third-party copies of
// protected-list redirects (ARCHITECTURE §4.2, PRIORITY.REDIRECT_ALWAYS).
//
// compileList() gives every protected-list $redirect= rule (except $1p ones)
// a copy with domainType "thirdParty" in the always-apply redirect band, so
// the stub wins over always-apply blocks (21) as in uBO and Brave. The copy
// only matters where an always-apply block can match the same request, and
// the static-rule budget is tight, so the build calls
// restrictRedirectCopies() over all compiled lists and keeps just those
// copies. A copy is always a higher-priority duplicate of a rule that stays
// (the original at 11–18), so dropping one never loses the redirect itself.
//
// The overlap test is exact on types, party, methods and domains, and
// sample-based for URL patterns and initiators: a URL written for one rule
// (its urlFilter made literal on its own hosts) must match the other rule,
// and a site-specific block only meets a redirect limited to those sites.
// That keeps the copies for the cases that matter (Outbrain, adservice,
// Funding Choices …) at a few dozen rules instead of every protected
// redirect. A rule it cannot analyse keeps its copy.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { PRIORITY } from '../shared/constants.ts';
import type { CompiledList, CompiledRule, DnrCondition, DnrRule } from './types.ts';
import { ALL_DNR_TYPES } from './network.ts';

export interface RedirectCopyInput {
  /** Catalog flag of the list: copies live in protected lists, blocks come from always-apply lists. */
  firstPartyProtected: boolean;
  /** Compiled output of the list; `rules` and `regexRules` are replaced in place. */
  compiled: Pick<CompiledList, 'rules' | 'regexRules'>;
}

export interface RedirectCopyStats {
  /** Third-party redirect copies found in protected lists. */
  copies: number;
  /** Copies kept because an always-apply block can match the same request. */
  kept: number;
}

/** True for the third-party copy of a protected-list redirect (only those sit in 22–28 in a protected list). */
export function isRedirectCopy(rule: DnrRule): boolean {
  const p = rule.priority ?? 1;
  return (
    rule.action.type === 'redirect' &&
    rule.action.redirect?.extensionPath !== undefined &&
    rule.condition.domainType === 'thirdParty' &&
    p >= PRIORITY.REDIRECT_ALWAYS &&
    p < PRIORITY.STRICT_BLOCK
  );
}

/**
 * Keep only the redirect copies that an always-apply block rule (priority
 * BLOCK_ALWAYS, from a list with firstPartyProtected false) can meet. Never
 * throws: a rule it cannot analyse is kept.
 */
export function restrictRedirectCopies(lists: readonly RedirectCopyInput[]): RedirectCopyStats {
  const blocks: Info[] = [];
  for (const l of lists) {
    if (l.firstPartyProtected) continue;
    for (const cr of [...l.compiled.rules, ...l.compiled.regexRules]) {
      const r = cr.rule;
      if (r.action.type !== 'block' || (r.priority ?? 1) !== PRIORITY.BLOCK_ALWAYS) continue;
      blocks.push(info(r));
    }
  }
  const index = new BlockIndex(blocks);
  const stats: RedirectCopyStats = { copies: 0, kept: 0 };
  const keep = (cr: CompiledRule): boolean => {
    if (!isRedirectCopy(cr.rule)) return true;
    stats.copies += 1;
    let needed = true;
    try {
      const r = info(cr.rule);
      needed = index.candidates(r).some((b) => overlaps(r, b));
    } catch {
      needed = true;
    }
    if (needed) stats.kept += 1;
    return needed;
  };
  for (const l of lists) {
    if (!l.firstPartyProtected) continue;
    l.compiled.rules = l.compiled.rules.filter(keep);
    l.compiled.regexRules = l.compiled.regexRules.filter(keep);
  }
  return stats;
}

// ---------------------------------------------------------------------------
// Rule analysis
// ---------------------------------------------------------------------------

interface Info {
  c: DnrCondition;
  types: Set<string>;
  /** Request hosts the rule is limited to (requestDomains or a literal "||host" urlFilter); null = any. */
  hosts: string[] | null;
  url: RegExp | null;
  /** The rule's regex could not be analysed: assume it matches. */
  opaque: boolean;
  /** samples(), computed on first use. */
  sampleUrls?: string[];
}

function typesOf(c: DnrCondition): Set<string> {
  if (c.resourceTypes !== undefined) return new Set(c.resourceTypes);
  // DNR: no types = every type but main_frame; only exclusions = the rest, main_frame included.
  const ex = new Set(c.excludedResourceTypes ?? ['main_frame']);
  return new Set(ALL_DNR_TYPES.filter((t) => !ex.has(t)));
}

const reHostAnchor = /^\|\|([a-z0-9_-]+(?:\.[a-z0-9_-]+)+)(?:[/^:?|]|$)/;

function info(rule: DnrRule): Info {
  const c = rule.condition;
  let hosts: string[] | null = c.requestDomains ?? null;
  if (hosts === null && c.urlFilter !== undefined) {
    const m = reHostAnchor.exec(c.urlFilter);
    if (m !== null) hosts = [m[1]];
  }
  let url: RegExp | null = null;
  let opaque = false;
  const flags = c.isUrlFilterCaseSensitive === true ? '' : 'i';
  if (c.urlFilter !== undefined) url = urlFilterToRegExp(c.urlFilter, flags);
  else if (c.regexFilter !== undefined) {
    try {
      url = new RegExp(c.regexFilter.replace(/\(\?P</g, '(?<'), flags);
    } catch {
      opaque = true;
    }
  }
  return { c, types: typesOf(c), hosts, url, opaque };
}

/** DNR urlFilter syntax as a JavaScript RegExp. */
export function urlFilterToRegExp(uf: string, flags = 'i'): RegExp {
  let s = uf;
  let re = '';
  if (s.startsWith('||')) {
    re = '^[a-z][a-z0-9+.-]*:\\/\\/(?:[^/?#]*\\.)?';
    s = s.slice(2);
  } else if (s.startsWith('|')) {
    re = '^';
    s = s.slice(1);
  }
  let end = '';
  if (s.endsWith('|')) {
    end = '$';
    s = s.slice(0, -1);
  }
  for (const ch of s) {
    if (ch === '*') re += '.*';
    else if (ch === '^') re += '(?:[^a-zA-Z0-9_.%-]|$)';
    else re += ch.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  }
  return new RegExp(re + end, flags);
}

const coveredBy = (host: string, parent: string): boolean => host === parent || host.endsWith(`.${parent}`);

/** Some host of `a` and some host of `b` can name the same request (one equals or contains the other). */
function setsMeet(a: readonly string[], b: readonly string[]): boolean {
  const sb = new Set(b);
  for (const h of a) {
    for (let p = h; ; ) {
      if (sb.has(p)) return true;
      const i = p.indexOf('.');
      if (i === -1) break;
      p = p.slice(i + 1);
    }
  }
  const sa = new Set(a);
  for (const h of b) {
    for (let p = h; ; ) {
      if (sa.has(p)) return true;
      const i = p.indexOf('.');
      if (i === -1) break;
      p = p.slice(i + 1);
    }
  }
  return false;
}

/** Every host in `hosts` is excluded by `excluded` (so the rules cannot meet there). */
function allExcluded(hosts: readonly string[] | null | undefined, excluded: readonly string[] | undefined): boolean {
  if (hosts === null || hosts === undefined || excluded === undefined || excluded.length === 0) return false;
  return hosts.every((h) => excluded.some((x) => coveredBy(h, x)));
}

function hostOf(url: string): string {
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/?#:]*)/i.exec(url);
  return m === null ? '' : m[1].toLowerCase();
}

/** Does rule `x` match this URL as far as URL pattern and request domains go? */
function matchesUrl(x: Info, url: string): boolean {
  if (x.opaque) return true;
  const host = hostOf(url);
  if (x.c.requestDomains !== undefined && !x.c.requestDomains.some((d) => coveredBy(host, d))) return false;
  if (x.c.excludedRequestDomains !== undefined && x.c.excludedRequestDomains.some((d) => coveredBy(host, d))) return false;
  return x.url === null || x.url.test(url);
}

const MAX_SAMPLE_HOSTS = 64;
/** Initiator used for a rule without initiatorDomains: matches no site-specific block. */
const NEUTRAL_INITIATOR = 'initiator.invalid';
/** Request host used for a rule without a host of its own. */
const NEUTRAL_HOST = 'request.invalid';

/**
 * Concrete URLs the rule is written for: its urlFilter made literal on the
 * rule's own request hosts (a neutral host when it has none). `*` is tried
 * as "" and "x", `^` as "/".
 */
function samples(x: Info): string[] {
  if (x.sampleUrls === undefined) x.sampleUrls = computeSamples(x);
  return x.sampleUrls;
}

function computeSamples(x: Info): string[] {
  const hosts = (x.hosts ?? [NEUTRAL_HOST]).slice(0, MAX_SAMPLE_HOSTS);
  const uf = x.c.urlFilter;
  if (uf === undefined) return x.c.regexFilter !== undefined ? [] : hosts.map((h) => `https://${h}/`);
  const out: string[] = [];
  let s = uf.endsWith('|') ? uf.slice(0, -1) : uf;
  let anchor = '';
  if (s.startsWith('||')) {
    anchor = '||';
    s = s.slice(2);
  } else if (s.startsWith('|')) {
    anchor = '|';
    s = s.slice(1);
  }
  for (const star of ['', 'x']) {
    const lit = s.replace(/\*/g, star).replace(/\^/g, '/');
    if (anchor === '||') {
      out.push(`https://${lit}`);
    } else if (anchor === '|') {
      out.push(lit);
    } else {
      for (const h of hosts) {
        out.push(`https://${h}${lit.startsWith('/') ? '' : '/'}${lit}`);
        out.push(`https://${h}/?${lit}`);
      }
    }
  }
  return out;
}

/**
 * Can the initiators the rule `x` is written for meet rule `y`? A rule
 * without initiatorDomains stands for "any site", which a site-specific rule
 * does not cover (`*$script,3p,domain=one-site.example` keeps no copy).
 */
function initiatorsMeet(x: DnrCondition, y: DnrCondition): boolean {
  if (y.initiatorDomains !== undefined) {
    if (x.initiatorDomains === undefined || !setsMeet(x.initiatorDomains, y.initiatorDomains)) return false;
  }
  const inits = x.initiatorDomains ?? [NEUTRAL_INITIATOR];
  return !allExcluded(inits, y.excludedInitiatorDomains) && !allExcluded(y.initiatorDomains, x.excludedInitiatorDomains);
}

/**
 * Can a request matched by redirect copy `r` also be matched by always-apply
 * block `b`? Exact on types, party, methods and domains; for URL patterns a
 * URL written for one rule (see samples()) must match the other: `r`'s URLs
 * against `b`, and `b`'s URLs against `r` when `b` names its own hosts (a
 * redirect broader than the block: `||a.com^` vs `||cdn.a.com/x.js`).
 * Generic block paths are not grafted onto other hosts: almost every
 * host-wide redirect would meet some generic block that way.
 */
function overlaps(r: Info, b: Info): boolean {
  const rc = r.c;
  const bc = b.c;
  // Party: a copy is always thirdParty.
  if (rc.domainType !== undefined && bc.domainType !== undefined && rc.domainType !== bc.domainType) return false;
  let typeMeet = false;
  for (const t of r.types) {
    if (b.types.has(t)) {
      typeMeet = true;
      break;
    }
  }
  if (!typeMeet) return false;
  if (rc.requestMethods !== undefined && bc.requestMethods !== undefined && !rc.requestMethods.some((m) => bc.requestMethods!.includes(m))) return false;
  if (rc.requestMethods !== undefined && bc.excludedRequestMethods !== undefined && rc.requestMethods.every((m) => bc.excludedRequestMethods!.includes(m))) return false;
  if (bc.requestMethods !== undefined && rc.excludedRequestMethods !== undefined && bc.requestMethods.every((m) => rc.excludedRequestMethods!.includes(m))) return false;
  // Request hosts.
  if (r.hosts !== null && b.hosts !== null && !setsMeet(r.hosts, b.hosts)) return false;
  if (allExcluded(r.hosts, bc.excludedRequestDomains) || allExcluded(b.hosts, rc.excludedRequestDomains)) return false;
  if (!initiatorsMeet(rc, bc)) return false;
  // URL patterns.
  if (r.opaque || b.opaque) return true;
  if (samples(r).some((u) => matchesUrl(b, u))) return true;
  if (b.hosts !== null && samples(b).some((u) => matchesUrl(r, u))) return true;
  return false;
}

/** Always-apply blocks by request host, so a copy is only compared with blocks that can share a host. */
class BlockIndex {
  private readonly anyHost: Info[] = [];
  private readonly all: Info[];
  /** host -> blocks limited to that host. */
  private readonly exact = new Map<string, Info[]>();
  /** host -> blocks limited to that host or a subdomain of it. */
  private readonly below = new Map<string, Info[]>();

  constructor(blocks: Info[]) {
    this.all = blocks;
    const push = (m: Map<string, Info[]>, k: string, v: Info): void => {
      const l = m.get(k);
      if (l === undefined) m.set(k, [v]);
      else if (l[l.length - 1] !== v) l.push(v);
    };
    for (const b of blocks) {
      if (b.hosts === null) {
        this.anyHost.push(b);
        continue;
      }
      for (const h of b.hosts) {
        push(this.exact, h, b);
        for (let p = h; ; ) {
          push(this.below, p, b);
          const i = p.indexOf('.');
          if (i === -1) break;
          p = p.slice(i + 1);
        }
      }
    }
  }

  candidates(r: Info): Info[] {
    if (r.hosts === null) return this.all;
    const out = new Set<Info>(this.anyHost);
    for (const h of r.hosts) {
      for (const b of this.below.get(h) ?? []) out.add(b);
      for (let p = h; ; ) {
        for (const b of this.exact.get(p) ?? []) out.add(b);
        const i = p.indexOf('.');
        if (i === -1) break;
        p = p.slice(i + 1);
      }
    }
    return Array.from(out);
  }
}

// Exposed for tests.
export { overlaps as _overlaps, info as _info };
