// Bastion Shield — builds the `bastion-params` static ruleset from Brave's
// query-filter.json (ARCHITECTURE §4.1): one rule per tracking parameter,
// redirect + queryTransform.removeParams, only for cross-site navigations
// (domainType thirdParty, main_frame/sub_frame), GET only as in Brave.
//
// Brave-core also hard-codes a few "conditional" parameters that are kept
// when the URL matches a pattern (components/query_filter/browser/utils.cc).
// Their conditions are plain substrings, so we express them exactly with
// urlFilter-based allow rules at the same priority (allow beats redirect on
// equal priority), without spending any regex budget.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { PRIORITY } from '../../src/shared/constants.ts';
import type { DnrRule } from '../../src/compiler/types.ts';

export interface QueryFilterEntry {
  include: string[];
  exclude: string[];
  params: string[];
}

export interface ParamsRuleset {
  rules: DnrRule[];
  sources: string[][];
  warnings: string[];
}

/** brave-core query_filter: params stripped unless the URL contains one of the substrings. */
const BRAVE_CONDITIONAL: { param: string; unless: string[] }[] = [
  { param: 'ck_subscriber_id', unless: ['/unsubscribe'] },
  { param: 'h_sid', unless: ['/email/'] },
  { param: 'h_slt', unless: ['/email/'] },
  // ([uU]nsubscribe|emailWebview): urlFilter matching is case-insensitive by default.
  { param: 'mkt_tok', unless: ['unsubscribe', 'emailWebview'] },
];
/** brave-core: never strip on this exact host (link-protection service). */
const BRAVE_EXEMPT_HOSTS = ['urldefense.com'];

const PARAM_NAME = /^[A-Za-z0-9_.~!$'()*+,;:@%-]+$/;

/**
 * Hosts from Brave's match patterns: "*://*.x.com/*" and "*://x.com/*" both
 * map to requestDomains "x.com" (requestDomains covers subdomains). Returns
 * null for "<all_urls>"-like patterns, undefined for unsupported ones.
 */
function hostFromPattern(p: string): string | null | undefined {
  if (p === '<all_urls>' || p === '*://*/*') return null;
  const m = /^(\*|https?):\/\/(\*\.)?([a-z0-9.-]+)\/.*$/i.exec(p);
  if (!m) return undefined;
  return m[3].toLowerCase();
}

export function buildParamsRuleset(entries: QueryFilterEntry[]): ParamsRuleset {
  const warnings: string[] = [];
  const rules: DnrRule[] = [];
  const sources: string[][] = [];
  const base = (param: string): DnrRule => ({
    priority: PRIORITY.PARAMS,
    action: { type: 'redirect', redirect: { transform: { queryTransform: { removeParams: [param] } } } },
    condition: {
      urlFilter: `^${param}=`,
      resourceTypes: ['main_frame', 'sub_frame'],
      domainType: 'thirdParty',
      requestMethods: ['get'],
    },
  });

  const seenGlobal = new Set<string>();
  for (const e of entries) {
    if (!e || !Array.isArray(e.include) || !Array.isArray(e.params)) {
      warnings.push('query-filter.json: malformed entry skipped');
      continue;
    }
    const include = e.include.map(hostFromPattern);
    const exclude = (e.exclude ?? []).map(hostFromPattern);
    if (include.some((h) => h === undefined) || exclude.some((h) => h === undefined || h === null)) {
      warnings.push(`query-filter.json: unsupported match pattern in ${JSON.stringify(e.include)} / ${JSON.stringify(e.exclude)}; entry skipped`);
      continue;
    }
    const global = include.includes(null);
    const requestDomains = global ? undefined : [...new Set(include as string[])].sort();
    const excluded = [...new Set([...(exclude as string[]), ...(global ? BRAVE_EXEMPT_HOSTS : [])])].sort();
    for (const param of e.params) {
      if (typeof param !== 'string' || !PARAM_NAME.test(param)) {
        warnings.push(`query-filter.json: unsupported parameter name ${JSON.stringify(param)} skipped`);
        continue;
      }
      if (global) {
        if (seenGlobal.has(param)) continue;
        seenGlobal.add(param);
      }
      const r = base(param);
      if (requestDomains) r.condition.requestDomains = requestDomains;
      if (excluded.length) r.condition.excludedRequestDomains = excluded;
      rules.push(r);
      sources.push([`Brave query-filter: ${param} (${global ? 'all sites' : requestDomains!.join(', ')})`]);
    }
  }

  for (const c of BRAVE_CONDITIONAL) {
    if (!seenGlobal.has(c.param)) {
      const r = base(c.param);
      r.condition.excludedRequestDomains = [...BRAVE_EXEMPT_HOSTS];
      rules.push(r);
      sources.push([`Brave query-filter (brave-core): ${c.param}, kept on URLs containing ${c.unless.join(' or ')}`]);
    }
    for (const needle of c.unless) {
      // The condition may appear before or after the parameter in the URL.
      for (const urlFilter of [`${needle}*^${c.param}=`, `^${c.param}=*${needle}`]) {
        rules.push({
          priority: PRIORITY.PARAMS,
          action: { type: 'allow' },
          condition: { urlFilter, resourceTypes: ['main_frame', 'sub_frame'], domainType: 'thirdParty', requestMethods: ['get'] },
        });
        sources.push([`Brave query-filter (brave-core): keep ${c.param} when the URL contains "${needle}"`]);
      }
    }
  }
  return { rules, sources, warnings };
}
