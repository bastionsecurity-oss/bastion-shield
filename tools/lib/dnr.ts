// Bastion Shield — build-time validation and normalization of static DNR
// rules. Unpacked extensions treat a semantically invalid static rule as a
// hard load error (ARCHITECTURE §3), so every rule the compiler emits passes
// through here: checks mirror Chromium's indexed_rule.cc, unknown keys are
// stripped, domains lower-cased, arrays sorted and de-duplicated.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { DnrAction, DnrCondition, DnrHeaderOp, DnrRule } from '../../src/compiler/types.ts';

export const RESOURCE_TYPES = [
  'main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest',
  'ping', 'csp_report', 'media', 'websocket', 'webtransport', 'webbundle', 'other',
] as const;
const RESOURCE_TYPE_SET = new Set<string>(RESOURCE_TYPES);
const REQUEST_METHODS = new Set(['connect', 'delete', 'get', 'head', 'options', 'patch', 'post', 'put', 'other']);
const ACTION_TYPES = new Set(['block', 'allow', 'allowAllRequests', 'redirect', 'modifyHeaders', 'upgradeScheme']);
const TRANSFORM_SCHEMES = new Set(['http', 'https', 'ftp', 'chrome-extension']);
/** kDNRRequestHeaderAppendAllowList (extensions/browser/api/declarative_net_request/constants.h). */
const REQUEST_APPEND_ALLOW = new Set([
  'accept', 'accept-encoding', 'accept-language', 'access-control-request-headers', 'cache-control',
  'connection', 'content-language', 'cookie', 'forwarded', 'if-match', 'if-none-match', 'keep-alive',
  'range', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'user-agent', 'via', 'want-digest',
  'x-forwarded-for',
]);
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

const DOMAIN_KEYS = [
  'requestDomains', 'excludedRequestDomains', 'initiatorDomains', 'excludedInitiatorDomains',
  'topDomains', 'excludedTopDomains',
] as const;
/** Included-list keys: an empty array would silently broaden the rule if dropped, so it is an error. */
const INCLUDED_ARRAY_KEYS = new Set(['requestDomains', 'initiatorDomains', 'topDomains', 'resourceTypes', 'requestMethods']);

const isAscii = (s: string) => /^[\x00-\x7f]*$/.test(s);
const sortedUnique = (a: string[]) => [...new Set(a)].sort();

export interface SanitizeResult {
  rule?: DnrRule;
  error?: string;
}

function headerOps(ops: unknown, request: boolean): { ops?: DnrHeaderOp[]; error?: string } {
  if (!Array.isArray(ops) || ops.length === 0) return { error: `empty ${request ? 'requestHeaders' : 'responseHeaders'}` };
  const out: DnrHeaderOp[] = [];
  for (const op of ops as DnrHeaderOp[]) {
    if (!op || typeof op.header !== 'string' || !HEADER_NAME.test(op.header)) return { error: 'invalid header name' };
    if (op.operation !== 'append' && op.operation !== 'set' && op.operation !== 'remove') return { error: 'invalid header operation' };
    if (request && op.operation === 'append' && !REQUEST_APPEND_ALLOW.has(op.header.toLowerCase())) {
      return { error: `append not allowed for request header ${op.header}` };
    }
    if (op.operation === 'remove') {
      if (op.value !== undefined) return { error: 'remove operation with a value' };
      out.push({ header: op.header, operation: 'remove' });
    } else {
      if (typeof op.value !== 'string') return { error: `${op.operation} operation without a value` };
      if (/[\x00\r\n]/.test(op.value)) return { error: 'invalid header value' };
      out.push({ header: op.header, operation: op.operation, value: op.value });
    }
  }
  return { ops: out };
}

/** RE2 rejects these; JS accepts them. Cheap structural check (the compiler does the full analysis). */
function re2Problem(re: string): string | null {
  if (/\(\?<?[=!]/.test(re)) return 'lookaround is not RE2-compatible';
  if (/(^|[^\\])\\[1-9]/.test(re)) return 'backreference is not RE2-compatible';
  if (/\(\?<[A-Za-z]/.test(re)) return 'JS named group syntax is not RE2-compatible';
  try {
    new RegExp(re);
  } catch {
    return 'regexFilter does not parse';
  }
  return null;
}

/**
 * Validate and normalize one static rule. Returns `{error}` when Chromium
 * would reject it (the caller drops it and reports the reason).
 */
export function sanitizeRule(input: DnrRule, opts: { allowRegex: boolean }): SanitizeResult {
  if (!input || typeof input !== 'object' || !input.action || !input.condition) return { error: 'malformed rule' };
  const a = input.action;
  const c = input.condition;
  if (!ACTION_TYPES.has(a.type)) return { error: `invalid action type ${String(a.type)}` };
  const rule: DnrRule = { action: { type: a.type }, condition: {} };
  if (input.id !== undefined) {
    if (!Number.isInteger(input.id) || input.id < 1) return { error: 'invalid id' };
    rule.id = input.id;
  }
  if (input.priority !== undefined) {
    if (!Number.isInteger(input.priority) || input.priority < 1) return { error: 'invalid priority' };
    rule.priority = input.priority;
  }

  // --- action ---------------------------------------------------------------
  const action: DnrAction = rule.action;
  if (a.type === 'redirect') {
    const r = a.redirect;
    if (!r) return { error: 'redirect without redirect object' };
    if (typeof r.url === 'string') {
      let u: URL;
      try {
        u = new URL(r.url);
      } catch {
        return { error: 'invalid redirect url' };
      }
      if (u.protocol === 'javascript:') return { error: 'javascript: redirect' };
      action.redirect = { url: r.url };
    } else if (typeof r.extensionPath === 'string') {
      if (!r.extensionPath.startsWith('/')) return { error: 'extensionPath must start with "/"' };
      action.redirect = { extensionPath: r.extensionPath };
    } else if (r.transform && typeof r.transform === 'object') {
      const t = r.transform;
      if (t.scheme !== undefined && !TRANSFORM_SCHEMES.has(t.scheme)) return { error: 'invalid transform scheme' };
      if (t.query !== undefined && t.query !== '' && !t.query.startsWith('?')) return { error: 'transform query must start with "?"' };
      if (t.fragment !== undefined && t.fragment !== '' && !t.fragment.startsWith('#')) return { error: 'transform fragment must start with "#"' };
      if (t.query !== undefined && t.queryTransform !== undefined) return { error: 'query and queryTransform both specified' };
      const transform: NonNullable<NonNullable<DnrAction['redirect']>['transform']> = {};
      for (const k of ['scheme', 'host', 'path', 'query', 'fragment'] as const) if (typeof t[k] === 'string') transform[k] = t[k];
      if (typeof (t as { port?: unknown }).port === 'string') (transform as Record<string, unknown>).port = (t as { port: string }).port;
      if (t.queryTransform) {
        const qt = t.queryTransform;
        const out: NonNullable<typeof transform.queryTransform> = {};
        if (qt.removeParams !== undefined) {
          if (!Array.isArray(qt.removeParams) || qt.removeParams.length === 0 || qt.removeParams.some((p) => typeof p !== 'string' || p === '')) {
            return { error: 'invalid removeParams' };
          }
          out.removeParams = sortedUnique(qt.removeParams);
        }
        if (qt.addOrReplaceParams !== undefined) {
          if (!Array.isArray(qt.addOrReplaceParams) || qt.addOrReplaceParams.some((p) => !p || typeof p.key !== 'string' || p.key === '' || typeof p.value !== 'string')) {
            return { error: 'invalid addOrReplaceParams' };
          }
          out.addOrReplaceParams = qt.addOrReplaceParams.map((p) => (p.replaceOnly ? { key: p.key, value: p.value, replaceOnly: true } : { key: p.key, value: p.value }));
        }
        if (!out.removeParams && !out.addOrReplaceParams) return { error: 'empty queryTransform' };
        transform.queryTransform = out;
      }
      if (Object.keys(transform).length === 0) return { error: 'empty transform' };
      action.redirect = { transform };
    } else if (typeof r.regexSubstitution === 'string') {
      if (r.regexSubstitution === '') return { error: 'empty regexSubstitution' };
      action.redirect = { regexSubstitution: r.regexSubstitution };
    } else {
      return { error: 'redirect without target' };
    }
  } else if (a.type === 'modifyHeaders') {
    if (!a.requestHeaders && !a.responseHeaders) return { error: 'modifyHeaders without headers' };
    if (a.requestHeaders) {
      const r = headerOps(a.requestHeaders, true);
      if (r.error) return { error: r.error };
      action.requestHeaders = r.ops;
    }
    if (a.responseHeaders) {
      const r = headerOps(a.responseHeaders, false);
      if (r.error) return { error: r.error };
      action.responseHeaders = r.ops;
    }
  }

  // --- condition ------------------------------------------------------------
  const cond: DnrCondition = rule.condition;
  if (c.urlFilter !== undefined && c.regexFilter !== undefined) return { error: 'urlFilter and regexFilter both specified' };
  if (c.urlFilter !== undefined) {
    if (typeof c.urlFilter !== 'string' || c.urlFilter === '') return { error: 'empty urlFilter' };
    if (!isAscii(c.urlFilter)) return { error: 'non-ASCII urlFilter' };
    if (c.urlFilter.startsWith('||*')) return { error: 'urlFilter "||*" is invalid' };
    cond.urlFilter = c.urlFilter;
  }
  if (c.regexFilter !== undefined) {
    if (!opts.allowRegex) return { error: 'regexFilter in a non-regex ruleset' };
    if (typeof c.regexFilter !== 'string' || c.regexFilter === '') return { error: 'empty regexFilter' };
    if (!isAscii(c.regexFilter)) return { error: 'non-ASCII regexFilter' };
    const p = re2Problem(c.regexFilter);
    if (p) return { error: p };
    cond.regexFilter = c.regexFilter;
  }
  if (action.redirect?.regexSubstitution !== undefined && cond.regexFilter === undefined) {
    return { error: 'regexSubstitution without regexFilter' };
  }
  if (c.isUrlFilterCaseSensitive !== undefined) {
    if (typeof c.isUrlFilterCaseSensitive !== 'boolean') return { error: 'invalid isUrlFilterCaseSensitive' };
    if (c.isUrlFilterCaseSensitive) cond.isUrlFilterCaseSensitive = true;
  }
  for (const k of DOMAIN_KEYS) {
    const v = c[k];
    if (v === undefined) continue;
    if (!Array.isArray(v)) return { error: `${k} is not an array` };
    if (v.length === 0) {
      if (INCLUDED_ARRAY_KEYS.has(k)) return { error: `empty ${k}` };
      continue; // an empty exclusion list is a no-op
    }
    const out: string[] = [];
    for (const d of v) {
      if (typeof d !== 'string' || d === '') return { error: `empty entry in ${k}` };
      if (!isAscii(d)) return { error: `non-ASCII domain in ${k}` };
      out.push(d.toLowerCase());
    }
    cond[k] = sortedUnique(out);
  }
  if (c.domainType !== undefined) {
    if (c.domainType !== 'firstParty' && c.domainType !== 'thirdParty') return { error: 'invalid domainType' };
    cond.domainType = c.domainType;
  }
  for (const k of ['resourceTypes', 'excludedResourceTypes'] as const) {
    const v = c[k];
    if (v === undefined) continue;
    if (!Array.isArray(v)) return { error: `${k} is not an array` };
    if (v.length === 0) {
      if (k === 'resourceTypes') return { error: 'empty resourceTypes' };
      continue;
    }
    for (const t of v) if (!RESOURCE_TYPE_SET.has(t)) return { error: `invalid resource type ${String(t)}` };
    cond[k] = sortedUnique(v);
  }
  if (cond.resourceTypes && cond.excludedResourceTypes && cond.resourceTypes.some((t) => cond.excludedResourceTypes!.includes(t))) {
    return { error: 'resource type both included and excluded' };
  }
  if (cond.excludedResourceTypes && RESOURCE_TYPES.every((t) => cond.excludedResourceTypes!.includes(t))) {
    return { error: 'no applicable resource types' };
  }
  if (a.type === 'allowAllRequests') {
    if (!cond.resourceTypes || cond.resourceTypes.some((t) => t !== 'main_frame' && t !== 'sub_frame')) {
      return { error: 'allowAllRequests needs resourceTypes within main_frame/sub_frame' };
    }
  }
  for (const k of ['requestMethods', 'excludedRequestMethods'] as const) {
    const v = c[k];
    if (v === undefined) continue;
    if (!Array.isArray(v)) return { error: `${k} is not an array` };
    if (v.length === 0) {
      if (k === 'requestMethods') return { error: 'empty requestMethods' };
      continue;
    }
    const out = v.map((m) => String(m).toLowerCase());
    for (const m of out) if (!REQUEST_METHODS.has(m)) return { error: `invalid request method ${m}` };
    cond[k] = sortedUnique(out);
  }
  if (cond.requestMethods && cond.excludedRequestMethods && cond.requestMethods.some((m) => cond.excludedRequestMethods!.includes(m))) {
    return { error: 'request method both included and excluded' };
  }
  if (c.tabIds !== undefined) return { error: 'tabIds are only allowed in session rules' };
  for (const k of ['responseHeaders', 'excludedResponseHeaders'] as const) {
    const v = c[k];
    if (v === undefined) continue;
    if (!Array.isArray(v) || v.length === 0) return { error: `empty ${k}` };
    for (const h of v) if (!h || typeof h.header !== 'string' || !HEADER_NAME.test(h.header)) return { error: `invalid header in ${k}` };
    cond[k] = v.map((h) => {
      const o: { header: string; values?: string[]; excludedValues?: string[] } = { header: h.header };
      if (Array.isArray(h.values)) o.values = h.values.map(String);
      if (Array.isArray(h.excludedValues)) o.excludedValues = h.excludedValues.map(String);
      return o;
    });
  }
  if (a.type === 'modifyHeaders' && action.requestHeaders && (cond.responseHeaders || cond.excludedResponseHeaders)) {
    return { error: 'response-header condition cannot modify request headers' };
  }
  return { rule };
}

/** Stable JSON key order for output files: id, priority, action, condition. */
export function orderRule(rule: DnrRule): DnrRule {
  const out: DnrRule = { id: rule.id, action: rule.action, condition: rule.condition };
  if (rule.priority !== undefined && rule.priority !== 1) {
    return { id: rule.id, priority: rule.priority, action: rule.action, condition: rule.condition };
  }
  return out;
}
