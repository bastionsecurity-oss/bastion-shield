// Bastion filter compiler — public entry points. Compiles ABP / uBlock Origin
// filter lists into DNR rules, cosmetic data and scriptlet entries
// (docs/ARCHITECTURE.md §4–§6). Environment-agnostic: no Node or DOM APIs,
// so tools/build.ts uses it at build time and the service worker uses
// compileCustom() for user and admin filters at runtime.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type {
  CompileOptions,
  CompileStats,
  CompiledCustom,
  CompiledList,
  CompiledRule,
  DnrRule,
  GenericCosmetic,
  ScriptletFilter,
  SpecificCosmetic,
} from './types.ts';
import { DEFAULT_ENV, preprocess } from './preprocess.ts';
import { EXT_DOMAIN_MODE, classifyLine, parseDomainList, parseHostsLine, parseNetworkFilter, splitLines } from './parser.ts';
import type { ParsedNetFilter } from './parser.ts';
import { analyzeNetFilter, applyBadfilter, badfilterKeys, compileNetFilter, compileResponseHeaderFilter } from './network.ts';
import type { NetCompileContext } from './network.ts';
import { compileExtended } from './cosmetic.ts';
import type { ExtContext } from './cosmetic.ts';
import { minimizeRules } from './merge.ts';
import type { RuleDraft } from './merge.ts';

export { DEFAULT_ENV, preprocess, evaluateExpression } from './preprocess.ts';
export type { IncludeResolver } from './preprocess.ts';
export { parseProceduralSelector, analyzeSelector } from './procedural.ts';
export { isRe2Compatible, toRe2, regexToUrlFilter } from './regex.ts';
export { parseScriptletArgs } from './scriptlets.ts';
export { normalizeHostname } from './hostname.ts';
export { isRedirectCopy, restrictRedirectCopies } from './copies.ts';
export type { RedirectCopyInput, RedirectCopyStats } from './copies.ts';

const DEFAULT_BLOCKED_PAGE = '/pages/blocked.html';
const DEFAULT_MAX_REJECTED = 200;

export interface BadfilterOptions {
  env?: ReadonlySet<string>;
  format?: 'abp' | 'hosts';
}

/** A hosts-file entry expressed as the equivalent `||host^` filter. */
function hostFilter(host: string, raw: string): ParsedNetFilter {
  return {
    raw,
    exception: false,
    kind: 'hostname',
    pattern: host,
    hnAnchor: true,
    leftAnchor: false,
    rightAnchor: false,
    rightSeparator: true,
    options: [],
    hasOptions: false,
    hostsEntry: true,
  };
}

/**
 * Pre-pass over all lists: the identity keys of every `$badfilter` filter.
 * Pass the result to compileList (CompileOptions.badfilters) so a badfilter
 * in one list cancels the matching filter in every list.
 */
export function collectBadfilters(texts: readonly string[] | string, opts: BadfilterOptions = {}): Set<string> {
  const out = new Set<string>();
  if (opts.format === 'hosts') return out;
  const env = opts.env ?? DEFAULT_ENV;
  for (const text of typeof texts === 'string' ? [texts] : texts) {
    if (typeof text !== 'string' || text.indexOf('badfilter') === -1) continue;
    for (const { text: line } of splitLines(preprocess(text, env))) {
      if (line.indexOf('badfilter') === -1) continue;
      const cls = classifyLine(line);
      if (cls.kind !== 'network') continue;
      const p = parseNetworkFilter(line);
      if (!p.ok) continue;
      const an = analyzeNetFilter(p.filter);
      if (!an.ok || !an.a.badfilter) continue;
      for (const k of badfilterKeys(p.filter, an.a)) out.add(k);
    }
  }
  return out;
}

interface RunOptions {
  listId: string;
  trusted: boolean;
  firstPartyProtected: boolean;
  strictBlock: boolean;
  modifiers1p: boolean;
  custom: boolean;
  /** `@@…$important` allowed (NetCompileContext.importantExceptions). */
  importantExceptions: boolean;
  /** CompileOptions.trustSecret; '' = no `!#trusted` toggles. */
  trustSecret: string;
  env: ReadonlySet<string>;
  redirectResources: CompileOptions['redirectResources'];
  scriptlets: CompileOptions['scriptlets'];
  badfilters: ReadonlySet<string>;
  blockedPagePath: string;
  format: 'abp' | 'hosts';
  maxRejectedSamples: number;
}

interface RunResult {
  rules: CompiledRule[];
  regexRules: CompiledRule[];
  specific: SpecificCosmetic[];
  generic: GenericCosmetic[];
  genericExceptions: string[];
  scriptlets: ScriptletFilter[];
  generichideHosts: string[];
  specifichideHosts: string[];
  usedRedirectResources: string[];
  stats: CompileStats;
  errors: { line: number; text: string; reason: string }[];
  scriptletsIgnored: number;
}

/** Keep the first of several entries with the same key (lists repeat filters). */
function dedupe<T>(items: readonly T[], key: (x: T) => string): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const x of items) {
    const k = key(x);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(x);
  }
  return out;
}

function countLines(text: string): number {
  if (text.length === 0) return 0;
  let n = 1;
  let i = text.indexOf('\n');
  while (i !== -1) {
    n += 1;
    i = text.indexOf('\n', i + 1);
  }
  if (text.endsWith('\n')) n -= 1;
  return n;
}

function run(text: string, o: RunOptions): RunResult {
  const stats: CompileStats = {
    lines: countLines(text),
    filters: 0,
    network: 0,
    cosmetic: 0,
    scriptlets: 0,
    unsupported: 0,
    badfiltered: 0,
    rejected: [],
    reasons: {},
  };
  const errors: RunResult['errors'] = [];
  const bump = (reason: string): void => {
    stats.reasons[reason] = (stats.reasons[reason] ?? 0) + 1;
  };
  const drafts: RuleDraft[] = [];
  const usedRedirectResources = new Set<string>();
  const generichideHosts = new Set<string>();
  const specifichideHosts = new Set<string>();
  const flagEntries: SpecificCosmetic[] = [];
  const netCtx: NetCompileContext = {
    listId: o.listId,
    trusted: o.trusted,
    firstPartyProtected: o.firstPartyProtected,
    strictBlock: o.strictBlock,
    modifiers1p: o.modifiers1p,
    custom: o.custom,
    importantExceptions: o.importantExceptions,
    redirectResources: o.redirectResources,
    blockedPagePath: o.blockedPagePath,
    emit: (rule: DnrRule, source: string) => {
      drafts.push({ rule, sources: [source], count: 1 });
    },
    usedRedirectResources,
    generichideHosts,
    specifichideHosts,
    flagEntries,
    warn: bump,
  };
  const extCtx: ExtContext = {
    trusted: o.trusted,
    custom: o.custom,
    scriptlets: o.scriptlets,
    specific: [],
    generic: [],
    genericExceptions: [],
    scriptletFilters: [],
    warn: bump,
  };
  let scriptletsIgnored = 0;
  const reject = (lineNo: number, filter: string, reason: string): void => {
    stats.unsupported += 1;
    bump(reason);
    if (stats.rejected.length < o.maxRejectedSamples) stats.rejected.push({ filter, reason });
    errors.push({ line: lineNo, text: filter, reason });
  };

  const compileNet = (lineNo: number, raw: string, f: ParsedNetFilter): void => {
    const an = analyzeNetFilter(f);
    if (!an.ok) {
      reject(lineNo, raw, an.reason);
      return;
    }
    if (an.a.badfilter) return; // a directive: consumed by collectBadfilters()
    if (!applyBadfilter(f, an.a, o.badfilters)) {
      stats.badfiltered += 1;
      return;
    }
    let r;
    try {
      r = compileNetFilter(f, an.a, netCtx);
    } catch {
      r = { ok: false as const, reason: 'internal-error' };
    }
    if (r.ok) stats.network += 1;
    else reject(lineNo, raw, r.reason);
  };

  const processLine = (lineNo: number, line: string): void => {
    if (o.format === 'hosts') {
      const hosts = parseHostsLine(line);
      if (hosts === null) {
        stats.filters += 1;
        reject(lineNo, line, 'invalid-hosts-entry');
        return;
      }
      if (hosts.length === 0) return;
      stats.filters += 1;
      let produced = false;
      let cancelled = false;
      let failure: string | null = null;
      for (const h of hosts) {
        const f = hostFilter(h, line);
        const an = analyzeNetFilter(f);
        if (!an.ok) {
          failure = an.reason;
          continue;
        }
        if (!applyBadfilter(f, an.a, o.badfilters)) {
          cancelled = true;
          continue;
        }
        const r = compileNetFilter(f, an.a, netCtx);
        if (r.ok) produced = true;
        else failure = r.reason;
      }
      if (produced) stats.network += 1;
      else if (cancelled) stats.badfiltered += 1;
      else reject(lineNo, line, failure ?? 'invalid-hosts-entry');
      return;
    }
    const cls = classifyLine(line);
    if (cls.kind === 'comment') return;
    if (cls.kind === 'extended' && cls.ext !== undefined) {
      stats.filters += 1;
      const ext = cls.ext;
      const body = line.slice(ext.index + ext.anchor.length);
      if ((ext.anchor === '##' || ext.anchor === '#@#') && body.startsWith('^responseheader(') && body.endsWith(')')) {
        const domainsRaw = line.slice(0, ext.index);
        const entries = domainsRaw === '' ? [] : parseDomainList(domainsRaw, ',', EXT_DOMAIN_MODE);
        if (entries === null) {
          reject(lineNo, line, 'invalid-domain');
          return;
        }
        const r = compileResponseHeaderFilter(line, entries, body.slice(16, -1), ext.anchor === '#@#', netCtx);
        if (r.ok) stats.network += 1;
        else reject(lineNo, line, r.reason);
        return;
      }
      const before = extCtx.genericExceptions.length;
      let r;
      try {
        r = compileExtended(line, cls.ext, extCtx);
      } catch {
        r = { status: 'rejected' as const, reason: 'internal-error' };
      }
      switch (r.status) {
        case 'cosmetic':
          if (o.custom && extCtx.genericExceptions.length !== before) {
            // CompiledCustom has no place for global exceptions.
            extCtx.genericExceptions.length = before;
            reject(lineNo, line, 'unsupported-in-custom:generic-exception');
          } else {
            stats.cosmetic += 1;
          }
          break;
        case 'scriptlet':
          stats.scriptlets += 1;
          break;
        case 'scriptlet-ignored':
          scriptletsIgnored += 1;
          break;
        case 'rejected':
          reject(lineNo, line, r.reason);
          break;
      }
      return;
    }
    const p = parseNetworkFilter(line);
    if (!p.ok) {
      if (p.ignore) return;
      stats.filters += 1;
      reject(lineNo, line, p.reason);
      return;
    }
    stats.filters += 1;
    compileNet(lineNo, line, p.filter);
  };

  // `!#trusted off|on <secret>` (written by the build around untrusted
  // sources of trusted lists) switches trust for the lines that follow, never
  // above the list's own trust. Lines with any other secret, or without the
  // option set, are plain comments, so upstream text cannot turn trust on.
  const trustOff = o.trustSecret === '' ? null : `!#trusted off ${o.trustSecret}`;
  const trustOn = o.trustSecret === '' ? null : `!#trusted on ${o.trustSecret}`;
  for (const { line: lineNo, text: line } of splitLines(preprocess(text, o.env))) {
    if (trustOff !== null && line.startsWith('!#trusted ')) {
      const t = line.replace(/\s+/g, ' ');
      if (t === trustOff || t === trustOn) {
        const trusted = o.trusted && t === trustOn;
        netCtx.trusted = trusted;
        extCtx.trusted = trusted;
      }
      continue;
    }
    const counted = stats.filters;
    try {
      processLine(lineNo, line);
    } catch {
      // Never let one odd line abort a whole list.
      if (stats.filters === counted) stats.filters += 1;
      reject(lineNo, line, 'internal-error');
    }
  }

  const minimized = minimizeRules(drafts);
  const rules: CompiledRule[] = [];
  const regexRules: CompiledRule[] = [];
  for (const d of minimized) {
    const cr: CompiledRule = { rule: d.rule, sources: d.sources, sourceCount: d.count };
    if (d.rule.condition.regexFilter !== undefined) regexRules.push(cr);
    else rules.push(cr);
  }
  return {
    rules,
    regexRules,
    specific: dedupe([...extCtx.specific, ...flagEntries], (s) => `${s.kind}\u0001${s.payload}\u0001${s.hosts.join(',')}\u0001${s.excludedHosts.join(',')}`),
    generic: dedupe(extCtx.generic, (g) => `${g.selector}\u0001${g.excludedHosts.join(',')}`),
    genericExceptions: Array.from(new Set(extCtx.genericExceptions)),
    scriptlets: extCtx.scriptletFilters,
    generichideHosts: Array.from(generichideHosts).sort(),
    specifichideHosts: Array.from(specifichideHosts).sort(),
    usedRedirectResources: Array.from(usedRedirectResources).sort(),
    stats,
    errors,
    scriptletsIgnored,
  };
}

/** Compile one catalog list (already fetched, `!#include`s expanded). */
export function compileList(text: string, opts: CompileOptions): CompiledList {
  const env = opts.env ?? DEFAULT_ENV;
  const format = opts.format ?? 'abp';
  const badfilters = opts.badfilters ?? collectBadfilters(text, { env, format });
  const r = run(text, {
    listId: opts.listId,
    trusted: opts.trusted,
    firstPartyProtected: opts.firstPartyProtected,
    strictBlock: opts.strictBlock,
    modifiers1p: opts.modifiers1p === true,
    custom: false,
    importantExceptions: false,
    trustSecret: opts.trustSecret ?? '',
    env,
    redirectResources: opts.redirectResources,
    scriptlets: opts.scriptlets,
    badfilters,
    blockedPagePath: opts.blockedPagePath ?? DEFAULT_BLOCKED_PAGE,
    format,
    maxRejectedSamples: opts.maxRejectedSamples ?? DEFAULT_MAX_REJECTED,
  });
  return {
    listId: opts.listId,
    rules: r.rules,
    regexRules: r.regexRules,
    specific: r.specific,
    generic: r.generic,
    genericExceptions: r.genericExceptions,
    scriptlets: r.scriptlets,
    generichideHosts: r.generichideHosts,
    specifichideHosts: r.specifichideHosts,
    usedRedirectResources: r.usedRedirectResources,
    stats: r.stats,
  };
}

export type CustomCompileOptions = Omit<CompileOptions, 'listId' | 'trusted' | 'firstPartyProtected' | 'strictBlock'> & {
  /**
   * Accept `@@…$important` exceptions (default true: the user's and the
   * admin's own filters). False for imported filter lists ("My lists"):
   * third-party text must not override $important blocks.
   */
  importantExceptions?: boolean;
};

/**
 * Compile user or admin custom filters (runtime, dynamic rules): always-apply
 * priority band, untrusted, no strict block, and first-party copies of
 * modifiers (modifiers1p is always on; trustSecret is ignored because custom
 * text is never trusted). Scriptlet filters are counted in
 * `scriptletsIgnored` (MV3 cannot add code at runtime). Every rejected line is
 * reported with its 1-based line number.
 */
export function compileCustom(text: string, opts: CustomCompileOptions): CompiledCustom {
  const env = opts.env ?? DEFAULT_ENV;
  const format = opts.format ?? 'abp';
  const own = collectBadfilters(text, { env, format });
  const badfilters = opts.badfilters !== undefined ? new Set([...opts.badfilters, ...own]) : own;
  const r = run(text, {
    listId: 'custom',
    trusted: false,
    firstPartyProtected: false,
    strictBlock: false,
    // Admin and user modifiers must also work on same-site subresources.
    modifiers1p: true,
    custom: true,
    importantExceptions: opts.importantExceptions !== false,
    trustSecret: '',
    env,
    redirectResources: opts.redirectResources,
    scriptlets: opts.scriptlets,
    badfilters,
    blockedPagePath: opts.blockedPagePath ?? DEFAULT_BLOCKED_PAGE,
    format,
    maxRejectedSamples: opts.maxRejectedSamples ?? DEFAULT_MAX_REJECTED,
  });
  return {
    rules: [...r.rules, ...r.regexRules].map((cr) => cr.rule),
    // In custom mode $generichide/$specifichide hosts arrive as kind-4 entries.
    specific: r.specific,
    generic: r.generic,
    scriptletsIgnored: r.scriptletsIgnored,
    errors: r.errors,
  };
}
