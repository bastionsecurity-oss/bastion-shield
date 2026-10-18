// Shared helpers for the compiler tests: default options, a fake redirect
// resource map and scriptlet map, and a validator that checks emitted rules
// against the constraints Chromium enforces when it loads a static ruleset.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { CompileOptions, DnrRule, ScriptletInfo } from '../../src/compiler/types.ts';
import { isRe2Compatible } from '../../src/compiler/index.ts';

export const REDIRECTS: ReadonlyMap<string, { path: string; requiresTrust: boolean }> = new Map([
  ['noop.js', { path: '/war/noop.js', requiresTrust: false }],
  ['noopjs', { path: '/war/noop.js', requiresTrust: false }],
  ['noop.txt', { path: '/war/noop.txt', requiresTrust: false }],
  ['noopframe', { path: '/war/noop.html', requiresTrust: false }],
  ['1x1.gif', { path: '/war/1x1.gif', requiresTrust: false }],
  ['empty', { path: '/war/empty', requiresTrust: false }],
  ['noopmp4-1s', { path: '/war/noop-1s.mp4', requiresTrust: false }],
  ['abp-resource:blank-mp4', { path: '/war/noop-1s.mp4', requiresTrust: false }],
  ['google-ima.js', { path: '/war/google-ima.js', requiresTrust: false }],
  ['google-ima-dai.js', { path: '/war/google-ima-dai.js', requiresTrust: true }],
]);

export const SCRIPTLETS: ReadonlyMap<string, ScriptletInfo> = (() => {
  const m = new Map<string, ScriptletInfo>();
  const add = (name: string, world: 'MAIN' | 'ISOLATED', requiresTrust: boolean, aliases: string[] = []): void => {
    const info = { name, world, requiresTrust };
    m.set(name, info);
    for (const a of aliases) m.set(a, info);
  };
  add('set-constant.js', 'MAIN', false, ['set.js']);
  add('abort-on-property-read.js', 'MAIN', false, ['aopr.js']);
  add('remove-class.js', 'ISOLATED', false, ['rc.js']);
  add('trusted-set-cookie.js', 'MAIN', true);
  add('json-prune.js', 'MAIN', false);
  return m;
})();

export function opts(over: Partial<CompileOptions> = {}): CompileOptions {
  return {
    listId: 'test',
    trusted: false,
    firstPartyProtected: true,
    strictBlock: false,
    redirectResources: REDIRECTS,
    scriptlets: SCRIPTLETS,
    ...over,
  };
}

const DNR_TYPES = new Set([
  'main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest', 'ping',
  'csp_report', 'media', 'websocket', 'webtransport', 'webbundle', 'other',
]);
const METHODS = new Set(['connect', 'delete', 'get', 'head', 'options', 'patch', 'post', 'put', 'other']);
const reDomain = /^(?:[a-z0-9_-]+\.)*[a-z0-9_-]+$|^\[[0-9a-f:.]+\]$/;

/** Problems Chromium would report for this rule (empty array = valid). */
export function ruleProblems(rule: DnrRule): string[] {
  const p: string[] = [];
  const c = rule.condition;
  const a = rule.action;
  if (rule.priority !== undefined && (!Number.isInteger(rule.priority) || rule.priority < 1)) p.push('bad priority');
  if (c.urlFilter !== undefined && c.regexFilter !== undefined) p.push('urlFilter and regexFilter');
  if (c.urlFilter !== undefined) {
    if (c.urlFilter === '') p.push('empty urlFilter');
    if (/[^\x20-\x7e]/.test(c.urlFilter)) p.push('non-ASCII urlFilter');
    if (c.urlFilter.startsWith('||*')) p.push('urlFilter starts with ||*');
  }
  if (c.regexFilter !== undefined) {
    if (/[^\x20-\x7e]/.test(c.regexFilter)) p.push('non-ASCII regexFilter');
    try {
      new RegExp(c.regexFilter.replace(/\(\?P</g, '(?<').replace(/\\x\{([0-9a-fA-F]+)\}/g, '\\u$1'));
    } catch {
      p.push('regexFilter does not compile');
    }
    if (/\(\?[=!]|\(\?<[=!]|\\[1-9]/.test(c.regexFilter)) p.push('regexFilter not RE2');
  }
  for (const prop of ['requestDomains', 'excludedRequestDomains', 'initiatorDomains', 'excludedInitiatorDomains'] as const) {
    const v = c[prop];
    if (v === undefined) continue;
    if (v.length === 0) p.push(`empty ${prop}`);
    for (const d of v) if (!reDomain.test(d)) p.push(`bad ${prop} entry ${d}`);
  }
  for (const prop of ['resourceTypes', 'excludedResourceTypes'] as const) {
    const v = c[prop];
    if (v === undefined) continue;
    if (v.length === 0) p.push(`empty ${prop}`);
    for (const t of v) if (!DNR_TYPES.has(t)) p.push(`bad type ${t}`);
  }
  if (c.resourceTypes !== undefined && c.excludedResourceTypes !== undefined) p.push('resourceTypes and excludedResourceTypes');
  for (const prop of ['requestMethods', 'excludedRequestMethods'] as const) {
    const v = c[prop];
    if (v === undefined) continue;
    if (v.length === 0) p.push(`empty ${prop}`);
    for (const m of v) if (!METHODS.has(m)) p.push(`bad method ${m}`);
  }
  if (a.type === 'allowAllRequests') {
    if (c.resourceTypes === undefined || c.resourceTypes.some((t) => t !== 'main_frame' && t !== 'sub_frame')) {
      p.push('allowAllRequests needs main_frame/sub_frame only');
    }
  }
  if (a.type === 'redirect') {
    const r = a.redirect;
    if (r === undefined) p.push('redirect without redirect');
    else {
      if (r.extensionPath !== undefined && !r.extensionPath.startsWith('/')) p.push('extensionPath must start with /');
      if (r.regexSubstitution !== undefined && c.regexFilter === undefined) p.push('regexSubstitution needs regexFilter');
      const t = r.transform;
      if (t !== undefined && t.query !== undefined && t.queryTransform !== undefined) p.push('query and queryTransform');
      if (t?.queryTransform?.removeParams !== undefined && t.queryTransform.removeParams.length === 0) p.push('empty removeParams');
    }
  }
  if (a.type === 'modifyHeaders') {
    if ((a.responseHeaders ?? []).length === 0 && (a.requestHeaders ?? []).length === 0) p.push('modifyHeaders without headers');
    for (const h of [...(a.responseHeaders ?? []), ...(a.requestHeaders ?? [])]) {
      if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(h.header)) p.push(`bad header name ${h.header}`);
      if (h.operation !== 'remove' && (h.value === undefined || h.value === '')) p.push('header op without value');
      if (h.value !== undefined && /[^\x20-\x7e]/.test(h.value)) p.push('non-ASCII header value');
    }
  }
  if (c.regexFilter !== undefined && !isRe2Compatible(c.regexFilter.replace(/\(\?P</g, '(?<').replace(/\\x\{([0-9a-fA-F]+)\}/g, '\\u$1'))) {
    p.push('regex not RE2-compatible');
  }
  return p;
}

/** Shorthand: the plain DNR rules of a compiled list, without bookkeeping. */
export function rulesOf(list: { rules: { rule: DnrRule }[]; regexRules: { rule: DnrRule }[] }): DnrRule[] {
  return [...list.rules, ...list.regexRules].map((r) => r.rule);
}
