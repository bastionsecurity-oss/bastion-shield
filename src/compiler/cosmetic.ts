// Bastion filter compiler — extended (cosmetic and scriptlet) filters:
// `##`, `#@#`, `#?#`, `#@?#`, `##+js(…)`, `#@#+js(…)` (ARCHITECTURE §5.1, §6).
// AdGuard-only (#$#, #%#, #@$#…) and HTML filters (##^) are reported as
// unsupported, as in uBO Lite.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { GenericCosmetic, ScriptletFilter, ScriptletInfo, SpecificCosmetic } from './types.ts';
import { EXT_DOMAIN_MODE, parseDomainList } from './parser.ts';
import type { DomainEntry, ExtAnchor } from './parser.ts';
import { analyzeSelector } from './procedural.ts';
import { genericTokenOf, serializeTokens, splitSelectorList } from './selector.ts';
import { lookupScriptlet, parseScriptletArgs } from './scriptlets.ts';

export interface ExtContext {
  trusted: boolean;
  /** Custom filters: scriptlets are counted and ignored. */
  custom: boolean;
  scriptlets: ReadonlyMap<string, ScriptletInfo>;
  specific: SpecificCosmetic[];
  generic: GenericCosmetic[];
  genericExceptions: string[];
  scriptletFilters: ScriptletFilter[];
  warn: (reason: string) => void;
}

export type ExtResult =
  | { status: 'cosmetic' }
  | { status: 'scriptlet' }
  | { status: 'scriptlet-ignored' }
  | { status: 'rejected'; reason: string };

const reject = (reason: string): ExtResult => ({ status: 'rejected', reason });

interface HostSplit {
  include: string[];
  exclude: string[];
  /** "*" appeared among the included hosts. */
  wildcard: boolean;
  /** Included entries we had to drop (regex, ancestor, path forms). */
  droppedInclude: number;
  includeTotal: number;
}

function splitHosts(entries: DomainEntry[], keepRegex: boolean): HostSplit {
  const out: HostSplit = { include: [], exclude: [], wildcard: false, droppedInclude: 0, includeTotal: 0 };
  for (const d of entries) {
    const usable = d.kind === 'host' || d.kind === 'entity' || (keepRegex && d.kind === 'regex');
    if (d.negated) {
      if (usable) out.exclude.push(d.value);
      continue;
    }
    out.includeTotal += 1;
    if (d.kind === 'wildcard') out.wildcard = true;
    else if (usable) out.include.push(d.value);
    else out.droppedInclude += 1;
  }
  out.include = Array.from(new Set(out.include)).sort();
  out.exclude = Array.from(new Set(out.exclude)).sort();
  return out;
}

/** Compile one extended filter line. */
export function compileExtended(line: string, ext: ExtAnchor, ctx: ExtContext): ExtResult {
  const { anchor } = ext;
  const exception = anchor.charCodeAt(1) === 0x40 /* @ */;
  const core = exception ? `#${anchor.slice(2)}` : anchor;
  const body = line.slice(ext.index + anchor.length);
  const domainsRaw = line.slice(0, ext.index);

  if (core === '#$#' || core === '#$?#') {
    return reject(body.trimEnd().endsWith('}') ? 'unsupported:adguard-css-injection' : 'unsupported:abp-snippet');
  }
  if (core === '#%#') return reject('unsupported:adguard-scriptlet');
  if (body.charCodeAt(0) === 0x5e /* ^ */) {
    return reject(/^\^responseheader\(.*\)$/.test(body) ? 'unsupported:responseheader' : 'unsupported:html-filtering');
  }

  let entries: DomainEntry[] = [];
  if (domainsRaw !== '') {
    const parsed = parseDomainList(domainsRaw, ',', EXT_DOMAIN_MODE);
    if (parsed === null) return reject('invalid-domain');
    entries = parsed;
  }

  if (core === '##' && body.startsWith('+js(')) {
    if (!body.endsWith(')')) return reject('invalid-scriptlet');
    return compileScriptlet(line, body.slice(4, -1), entries, exception, ctx);
  }

  const asProcedural = core === '#?#';
  const analysis = analyzeSelector(body, asProcedural);
  if (analysis.kind === 'invalid') return reject(`invalid-selector:${analysis.reason}`);

  const hosts = splitHosts(entries, false);
  if (hosts.droppedInclude !== 0) ctx.warn('warn:cosmetic-host-syntax-dropped');

  if (exception) {
    // Negated hostnames are meaningless on exceptions (uBO ignores them).
    if (hosts.includeTotal === 0 || hosts.wildcard) {
      if (hosts.includeTotal === 0 && hosts.exclude.length !== 0) return reject('invalid-exception');
      for (const sel of exceptionPayloads(analysis)) ctx.genericExceptions.push(sel);
      return { status: 'cosmetic' };
    }
    if (hosts.include.length === 0) return reject('unsupported-domain-syntax');
    const kind = analysis.kind === 'procedural' ? 5 : 1;
    for (const payload of exceptionPayloads(analysis)) {
      ctx.specific.push({ kind, hosts: hosts.include, excludedHosts: [], payload, raw: line });
    }
    return { status: 'cosmetic' };
  }

  const generic = hosts.includeTotal === 0 || hosts.wildcard;
  if (!generic && hosts.include.length === 0) return reject('unsupported-domain-syntax');
  if (generic) {
    if (analysis.kind !== 'css') return reject('unsupported:generic-procedural');
    let added = 0;
    for (const complex of splitSelectorList(analysis.tokens)) {
      const selector = serializeTokens(complex);
      // uBO drops one-character generic selectors ("##*" would hide everything).
      if (selector.length <= 1) continue;
      ctx.generic.push({ selector, token: genericTokenOf(complex), excludedHosts: hosts.exclude, raw: line });
      added += 1;
    }
    if (added === 0) return reject('invalid-selector:too-generic');
    return { status: 'cosmetic' };
  }
  switch (analysis.kind) {
    case 'css':
      ctx.specific.push({ kind: 0, hosts: hosts.include, excludedHosts: hosts.exclude, payload: analysis.selector, raw: line });
      break;
    case 'style':
      ctx.specific.push({
        kind: 3,
        hosts: hosts.include,
        excludedHosts: hosts.exclude,
        payload: `${analysis.selector} { ${analysis.style} }`,
        raw: line,
      });
      break;
    case 'procedural':
      ctx.specific.push({
        kind: 2,
        hosts: hosts.include,
        excludedHosts: hosts.exclude,
        payload: JSON.stringify(analysis.filter),
        raw: line,
      });
      break;
  }
  return { status: 'cosmetic' };
}

/** What an exception filter cancels: selector text, style rule text or procedural raw text. */
function exceptionPayloads(analysis: Exclude<ReturnType<typeof analyzeSelector>, { kind: 'invalid' }>): string[] {
  switch (analysis.kind) {
    case 'css':
      return splitSelectorList(analysis.tokens).map((t) => serializeTokens(t)).filter((s) => s !== '');
    case 'style':
      return [`${analysis.selector} { ${analysis.style} }`];
    case 'procedural':
      return [analysis.filter.raw];
  }
}

function compileScriptlet(
  line: string,
  inner: string,
  entries: DomainEntry[],
  exception: boolean,
  ctx: ExtContext,
): ExtResult {
  if (ctx.custom) return { status: 'scriptlet-ignored' };
  const args = parseScriptletArgs(inner);
  const hosts = splitHosts(entries, true);
  if (hosts.droppedInclude !== 0) ctx.warn('warn:scriptlet-host-syntax-dropped');
  let name = '';
  let world: 'MAIN' | 'ISOLATED' = 'MAIN';
  if (args.length === 0) {
    if (!exception) return reject('invalid-scriptlet');
  } else {
    const info = lookupScriptlet(ctx.scriptlets, args[0]);
    if (info === undefined) return reject(`unknown-scriptlet:${args[0]}`);
    if (!exception && info.requiresTrust && !ctx.trusted) return reject('untrusted-scriptlet');
    name = info.name;
    world = info.world;
  }
  let include = hosts.include;
  let exclude = hosts.exclude;
  if (exception) {
    exclude = [];
    if (hosts.includeTotal === 0 || hosts.wildcard) include = ['*'];
    else if (include.length === 0) return reject('unsupported-domain-syntax');
  } else {
    if (hosts.wildcard) include = ['*'];
    else if (hosts.includeTotal === 0) {
      return reject(hosts.exclude.length !== 0 ? 'unsupported:negated-only-scriptlet' : 'unsupported:generic-scriptlet');
    } else if (include.length === 0) return reject('unsupported-domain-syntax');
  }
  ctx.scriptletFilters.push({ name, world, args: args.slice(1), hosts: include, excludedHosts: exclude, exception, raw: line });
  return { status: 'scriptlet' };
}
