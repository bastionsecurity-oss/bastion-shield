// Bastion filter compiler — rule minimization (ARCHITECTURE §4.4 "Merging").
// Every merge here is exact: two rules are only combined when they are
// identical except for one array property, and the merged rule matches the
// union of what the inputs matched. (uBOL also unions exclusion lists across
// different inclusion lists, which can narrow a rule; we do not.)
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { DnrAction, DnrRule } from './types.ts';
import { coveredBy, pruneSubdomains } from './hostname.ts';

/** A rule plus the filters that produced it. */
export interface RuleDraft {
  rule: DnrRule;
  sources: string[];
  count: number;
}

export const MAX_SOURCES = 20;

/** DNR resource types other than main_frame. */
const NON_DOCUMENT_TYPES = [
  'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest', 'ping', 'csp_report', 'media',
  'websocket', 'webtransport', 'webbundle', 'other',
];

type MergeProp = 'requestDomains' | 'initiatorDomains' | 'resourceTypes' | 'typeAbsorb' | 'removeParams' | 'responseHeaders';

const join = (a: readonly string[] | undefined): string => (a === undefined ? '-' : a.join(','));

function actionKey(a: DnrAction, skip: MergeProp | null): string {
  let k = a.type;
  const r = a.redirect;
  if (r !== undefined) {
    k += `|ep:${r.extensionPath ?? ''}|url:${r.url ?? ''}|rs:${r.regexSubstitution ?? ''}`;
    const t = r.transform;
    if (t !== undefined) {
      k += `|q:${t.query ?? '-'}|sch:${t.scheme ?? ''}|h:${t.host ?? ''}|p:${t.path ?? ''}|f:${t.fragment ?? ''}`;
      const qt = t.queryTransform;
      if (qt !== undefined) {
        k += `|rp:${skip === 'removeParams' ? '*' : join(qt.removeParams)}`;
        if (qt.addOrReplaceParams !== undefined) k += `|ap:${JSON.stringify(qt.addOrReplaceParams)}`;
      }
    }
  }
  if (a.responseHeaders !== undefined) {
    k += `|rh:${skip === 'responseHeaders' ? '*' : JSON.stringify(a.responseHeaders)}`;
  }
  if (a.requestHeaders !== undefined) k += `|qh:${JSON.stringify(a.requestHeaders)}`;
  return k;
}

/** Canonical identity of a rule, optionally ignoring one mergeable property. */
export function ruleKey(rule: DnrRule, skip: MergeProp | null = null): string {
  const c = rule.condition;
  let k = `${rule.priority ?? 1}|${actionKey(rule.action, skip)}`;
  k += `|u:${c.urlFilter ?? ''}|re:${c.regexFilter ?? ''}|cs:${c.isUrlFilterCaseSensitive === true ? 1 : 0}`;
  k += `|rd:${skip === 'requestDomains' ? '*' : join(c.requestDomains)}`;
  k += `|xrd:${join(c.excludedRequestDomains)}`;
  k += `|id:${skip === 'initiatorDomains' ? '*' : join(c.initiatorDomains)}`;
  k += `|xid:${join(c.excludedInitiatorDomains)}`;
  k += `|td:${join(c.topDomains)}|xtd:${join(c.excludedTopDomains)}`;
  k += `|dt:${c.domainType ?? ''}`;
  if (skip === 'resourceTypes') {
    // Typed rules merge among themselves (the union of their types).
    k += `|rt:${c.resourceTypes === undefined ? 'untyped' : 'typed'}`;
  } else if (skip === 'typeAbsorb') {
    // A typeless rule ("all but main_frame") absorbs typed twins without main_frame.
    k += `|rt:${c.resourceTypes === undefined || !c.resourceTypes.includes('main_frame') ? '*' : join(c.resourceTypes)}`;
  } else {
    k += `|rt:${join(c.resourceTypes)}`;
  }
  k += `|xrt:${join(c.excludedResourceTypes)}`;
  k += `|rm:${join(c.requestMethods)}|xrm:${join(c.excludedRequestMethods)}`;
  if (c.tabIds !== undefined) k += `|tab:${c.tabIds.join(',')}`;
  if (c.responseHeaders !== undefined) k += `|crh:${JSON.stringify(c.responseHeaders)}`;
  if (c.excludedResponseHeaders !== undefined) k += `|cxrh:${JSON.stringify(c.excludedResponseHeaders)}`;
  return k;
}

function cloneRule(r: DnrRule): DnrRule {
  return JSON.parse(JSON.stringify(r)) as DnrRule;
}

/** Sort and deduplicate every array so equal rules produce equal keys. */
export function canonicalizeRule(rule: DnrRule): DnrRule {
  const c = rule.condition;
  for (const prop of [
    'requestDomains', 'excludedRequestDomains', 'initiatorDomains', 'excludedInitiatorDomains',
    'topDomains', 'excludedTopDomains', 'resourceTypes', 'excludedResourceTypes', 'requestMethods',
    'excludedRequestMethods',
  ] as const) {
    const v = c[prop];
    if (v === undefined) continue;
    if (v.length === 0) {
      delete c[prop];
      continue;
    }
    c[prop] = Array.from(new Set(v)).sort();
  }
  // Every type but documents is exactly what DNR matches without resourceTypes.
  const rt = c.resourceTypes;
  if (rt !== undefined && !rt.includes('main_frame') && rt.length >= NON_DOCUMENT_TYPES.length) {
    if (NON_DOCUMENT_TYPES.every((t) => rt.includes(t))) delete c.resourceTypes;
  }
  const qt = rule.action.redirect?.transform?.queryTransform;
  if (qt?.removeParams !== undefined) qt.removeParams = Array.from(new Set(qt.removeParams)).sort();
  return rule;
}

function mergeSources(list: readonly RuleDraft[]): { sources: string[]; count: number } {
  const seen = new Set<string>();
  let count = 0;
  for (const d of list) {
    count += d.count;
    for (const s of d.sources) {
      if (seen.size >= MAX_SOURCES) break;
      seen.add(s);
    }
  }
  return { sources: Array.from(seen), count };
}

function getProp(rule: DnrRule, prop: MergeProp): unknown[] | undefined {
  switch (prop) {
    case 'removeParams':
      return rule.action.redirect?.transform?.queryTransform?.removeParams;
    case 'responseHeaders':
      return rule.action.responseHeaders;
    case 'typeAbsorb':
      return rule.condition.resourceTypes;
    default:
      return rule.condition[prop];
  }
}

function setProp(rule: DnrRule, prop: MergeProp, value: unknown[] | undefined): void {
  switch (prop) {
    case 'removeParams': {
      const qt = rule.action.redirect?.transform?.queryTransform;
      if (qt !== undefined && value !== undefined) qt.removeParams = value as string[];
      return;
    }
    case 'responseHeaders':
      if (value !== undefined) rule.action.responseHeaders = value as DnrAction['responseHeaders'];
      return;
    case 'typeAbsorb':
      if (value === undefined) delete rule.condition.resourceTypes;
      else rule.condition.resourceTypes = value as string[];
      return;
    default:
      if (value === undefined) delete rule.condition[prop];
      else rule.condition[prop] = value as string[];
  }
}

/** Merge rules identical except for `prop` (null = plain deduplication). */
export function mergeOn(drafts: readonly RuleDraft[], prop: MergeProp | null): RuleDraft[] {
  const groups = new Map<string, RuleDraft[]>();
  for (const d of drafts) {
    const k = ruleKey(d.rule, prop);
    const g = groups.get(k);
    if (g === undefined) groups.set(k, [d]);
    else g.push(d);
  }
  const out: RuleDraft[] = [];
  for (const list of groups.values()) {
    if (list.length === 1) {
      out.push(list[0]);
      continue;
    }
    const rule = cloneRule(list[0].rule);
    if (prop !== null) {
      // An absent domain/type list means "any": the union is then "any" too.
      let all = false;
      const acc: unknown[] = [];
      const seen = new Set<string>();
      for (const d of list) {
        const v = getProp(d.rule, prop);
        if (v === undefined) {
          all = true;
          break;
        }
        for (const x of v) {
          const key = typeof x === 'string' ? x : JSON.stringify(x);
          if (seen.has(key)) continue;
          seen.add(key);
          acc.push(x);
        }
      }
      if (all) setProp(rule, prop, undefined);
      else setProp(rule, prop, prop === 'responseHeaders' ? acc : (acc as string[]).sort());
    }
    const { sources, count } = mergeSources(list);
    out.push({ rule, sources, count });
  }
  return out;
}

/** Split multi-type rules so domain lists can merge per type first. */
function explodeTypes(drafts: readonly RuleDraft[]): RuleDraft[] {
  const out: RuleDraft[] = [];
  for (const d of drafts) {
    const types = d.rule.condition.resourceTypes;
    if (types === undefined || types.length < 2) {
      out.push(d);
      continue;
    }
    for (const t of types) {
      const r = cloneRule(d.rule);
      r.condition.resourceTypes = [t];
      out.push({ rule: r, sources: d.sources, count: d.count });
    }
  }
  return out;
}

/**
 * Prune redundant subdomains, drop inclusions that an exclusion already
 * removes, and return null for a rule that can no longer match anything.
 */
export function finalizeRule(rule: DnrRule): DnrRule | null {
  const c = rule.condition;
  for (const [inc, exc] of [
    ['requestDomains', 'excludedRequestDomains'],
    ['initiatorDomains', 'excludedInitiatorDomains'],
  ] as const) {
    if (c[exc] !== undefined) c[exc] = pruneSubdomains(c[exc] as string[]);
    if (c[inc] !== undefined) {
      let list = pruneSubdomains(c[inc] as string[]);
      if (c[exc] !== undefined) {
        const ex = new Set(c[exc] as string[]);
        list = list.filter((h) => !coveredBy(h, ex));
        if (list.length === 0) return null;
        // Exclusions outside every inclusion are dead weight.
        const incSet = new Set(list);
        const keptEx = (c[exc] as string[]).filter((h) => coveredBy(h, incSet));
        if (keptEx.length === 0) delete c[exc];
        else c[exc] = keptEx;
      }
      c[inc] = list;
    }
  }
  return canonicalizeRule(rule);
}

/** Full minimization pipeline. Order matters only for the resulting rule count. */
export function minimizeRules(input: readonly RuleDraft[]): RuleDraft[] {
  let drafts = input.map((d) => ({ rule: canonicalizeRule(d.rule), sources: d.sources, count: d.count }));
  drafts = mergeOn(explodeTypes(drafts), null);
  drafts = mergeOn(drafts, 'requestDomains');
  drafts = mergeOn(drafts, 'initiatorDomains');
  drafts = mergeOn(drafts, 'resourceTypes');
  drafts = mergeOn(drafts, 'removeParams');
  drafts = mergeOn(drafts, 'responseHeaders');
  drafts = mergeOn(drafts, 'requestDomains');
  drafts = mergeOn(drafts, 'initiatorDomains');
  drafts = mergeOn(drafts, 'resourceTypes');
  drafts = mergeOn(drafts, 'typeAbsorb');
  drafts = mergeOn(drafts, 'requestDomains');
  drafts = mergeOn(drafts, 'initiatorDomains');
  const out: RuleDraft[] = [];
  for (const d of drafts) {
    const r = finalizeRule(d.rule);
    if (r !== null) out.push({ rule: r, sources: d.sources, count: d.count });
  }
  return mergeOn(out, null);
}
