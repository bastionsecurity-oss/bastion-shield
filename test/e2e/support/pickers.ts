// Bastion Shield e2e — choose concrete test subjects (URLs, selectors,
// hostnames, scriptlets) from the shipped build data. Every picker is
// deterministic for a given dist/ so failures are reproducible, and every
// pick carries the original filter text for the failure message.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import type { DnrRule } from '../../../src/compiler/types.ts';
import { PRIORITY } from '../../../src/shared/constants.ts';
import { entityCandidates, hostnameCandidates, isIpAddress, shardOf } from '../../../src/shared/hash.ts';
import type { Dist, LocatedRule } from './dist.ts';
import { REPO_ROOT } from './paths.ts';

export type ResKind = 'script' | 'img' | 'css' | 'fetch' | 'iframe';

// ---------------------------------------------------------------------------
// Network: first-party path rule from a protected list (Standard vs Aggressive)
// ---------------------------------------------------------------------------

export interface PathRulePick {
  rulesetId: string;
  ruleId: number;
  urlFilter: string;
  /** Path (+query) to request on the fixture host. */
  path: string;
  kind: ResKind;
  dnrType: string;
  sources: string[];
}

const KIND_FOR_TYPE: [string, ResKind][] = [
  ['image', 'img'],
  ['script', 'script'],
  ['xmlhttprequest', 'fetch'],
  ['stylesheet', 'css'],
  ['sub_frame', 'iframe'],
];

/** Turn a non-anchored DNR urlFilter into a concrete path that it matches, or null. */
export function pathForUrlFilter(urlFilter: string): string | null {
  let f = urlFilter;
  if (f.startsWith('|')) return null; // scheme/host anchored: cannot be placed on our own host
  if (f.endsWith('|')) f = f.slice(0, -1);
  if (f.length < 4) return null;
  if (!/^[A-Za-z0-9/_.\-*^=&?%~+,;:]+$/.test(f)) return null;
  // '^' is a separator; '/' satisfies it everywhere. '*' needs any filler.
  let p = f.replace(/\*/g, 'x').replace(/\^/g, '/');
  if (p.includes('://')) return null;
  if (!p.startsWith('/')) p = '/bx' + (/^[A-Za-z0-9]/.test(p) ? '/' : '') + p;
  return p;
}

function plainCondition(rule: DnrRule): boolean {
  const c = rule.condition;
  return (
    rule.action.type === 'block' &&
    typeof c.urlFilter === 'string' &&
    !c.regexFilter &&
    !c.requestDomains &&
    !c.initiatorDomains &&
    !c.topDomains &&
    !c.domainType &&
    !c.requestMethods &&
    !c.responseHeaders &&
    !c.tabIds &&
    !c.isUrlFilterCaseSensitive
  );
}

/** Generic block rules of first-party-protected lists, placed on the fixture site as same-site resources. */
export function pickProtectedPathRules(dist: Dist, max = 25): PathRulePick[] {
  const protectedLists = new Set((dist.meta?.lists ?? []).filter((l) => l.firstPartyProtected && l.default).map((l) => l.id));
  const enabled = new Set(dist.expectedDefaultRulesets() ?? dist.manifestEnabledRulesets());
  const out: PathRulePick[] = [];
  for (const res of dist.ruleResources()) {
    if (!enabled.has(res.id) || res.id.endsWith('.regex')) continue;
    const list = dist.listOfRuleset(res.id);
    if (!list || !protectedLists.has(list.id)) continue;
    for (const rule of dist.rules(res.id)) {
      if ((rule.priority ?? 1) !== PRIORITY.BLOCK_PROTECTED || !plainCondition(rule)) continue;
      const p = pathForUrlFilter(rule.condition.urlFilter!);
      if (!p) continue;
      const types = rule.condition.resourceTypes;
      const excluded = new Set(rule.condition.excludedResourceTypes ?? []);
      let kind: ResKind | null = null;
      let dnrType = '';
      for (const [t, k] of KIND_FOR_TYPE) {
        if ((types ? types.includes(t) : true) && !excluded.has(t)) {
          kind = k;
          dnrType = t;
          break;
        }
      }
      if (!kind) continue;
      out.push({ rulesetId: res.id, ruleId: rule.id, urlFilter: rule.condition.urlFilter!, path: p, kind, dnrType, sources: dist.sourceOf(res.id, rule.id) });
    }
  }
  // Prefer short, path-like filters (fewer accidental matches by other lists), then stable by id.
  out.sort((a, b) => Number(!a.urlFilter.startsWith('/')) - Number(!b.urlFilter.startsWith('/')) || a.urlFilter.length - b.urlFilter.length || a.ruleId - b.ruleId);
  // Spread the sample over several rulesets.
  const picked: PathRulePick[] = [];
  const perRuleset = new Map<string, number>();
  for (const p of out) {
    const n = perRuleset.get(p.rulesetId) ?? 0;
    if (n >= Math.ceil(max / 3)) continue;
    perRuleset.set(p.rulesetId, n + 1);
    picked.push(p);
    if (picked.length >= max) break;
  }
  return picked;
}

// ---------------------------------------------------------------------------
// Strict block
// ---------------------------------------------------------------------------

export interface StrictPick {
  rulesetId: string;
  ruleId: number;
  listId: string;
  host: string;
  extensionPath: string;
}

export function pickStrictHosts(dist: Dist, prefer = ['urlhaus', 'ublock-badware', 'easylist', 'ublock'], max = 3): StrictPick[] {
  const enabled = new Set(dist.expectedDefaultRulesets() ?? dist.manifestEnabledRulesets());
  // Hostname-only rules: a pattern-scoped rule ($doc filter with a path) would not fire on our URL.
  const rules = dist.strictHostRules().filter((lr) => enabled.has(lr.rulesetId));
  const rank = (lr: LocatedRule) => {
    const list = dist.listOfRuleset(lr.rulesetId)?.id ?? lr.rulesetId;
    const i = prefer.indexOf(list);
    return i === -1 ? prefer.length : i;
  };
  rules.sort((a, b) => rank(a) - rank(b));
  const out: StrictPick[] = [];
  for (const lr of rules) {
    const hosts = (lr.rule.condition.requestDomains ?? []).filter(
      (h) => !isIpAddress(h) && /^[a-z0-9.-]+$/.test(h) && h.split('.').length >= 2 && !h.startsWith('xn--'),
    );
    if (!hosts.length) continue;
    // Deterministic but not always the first entry (those tend to be numeric-looking junk).
    const sorted = [...hosts].sort();
    const host = sorted[Math.floor(sorted.length / 3)];
    const ext = lr.rule.action.redirect?.extensionPath ?? '';
    const listId = new URLSearchParams(ext.split('?')[1] ?? '').get('list') ?? dist.listOfRuleset(lr.rulesetId)?.id ?? '';
    out.push({ rulesetId: lr.rulesetId, ruleId: lr.rule.id, listId, host, extensionPath: ext });
    if (out.length >= max) break;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Cosmetic
// ---------------------------------------------------------------------------

export interface ElementSpec {
  tag: string;
  attrs: Record<string, string>;
}

/**
 * Build an element that matches a simple compound selector (tag, #id, .class,
 * [attr], [attr=v], [attr^=v], [attr*=v], [attr$=v], [attr~=v]). Returns null for
 * anything with combinators, pseudo-classes or a list.
 */
export function elementForSelector(selector: string): ElementSpec | null {
  const s = selector.trim();
  if (!s || /[\s>+~,]|::?|\\/.test(s.replace(/\[[^\]]*\]/g, '[]'))) return null;
  const m = /^([a-zA-Z][a-zA-Z0-9-]*|\*)?(.*)$/.exec(s);
  if (!m) return null;
  let tag = (m[1] || 'div').toLowerCase();
  if (tag === '*') tag = 'div';
  if (['html', 'body', 'head', 'script', 'style', 'iframe', 'img', 'input', 'br', 'hr', 'meta', 'link', 'template', 'noscript'].includes(tag)) return null;
  const attrs: Record<string, string> = {};
  const classes: string[] = [];
  let rest = m[2];
  const re = /^(?:#([A-Za-z_][\w-]*)|\.([A-Za-z_-][\w-]*)|\[\s*([A-Za-z_][\w-]*)\s*(?:([~^$*|]?=)\s*(?:"([^"]*)"|'([^']*)'|([^\]\s]+))\s*(i)?)?\s*\])/;
  while (rest.length) {
    const t = re.exec(rest);
    if (!t) return null;
    rest = rest.slice(t[0].length);
    if (t[1]) {
      if (attrs.id) return null;
      attrs.id = t[1];
    } else if (t[2]) {
      classes.push(t[2]);
    } else if (t[3]) {
      const name = t[3].toLowerCase();
      const op = t[4];
      const v = t[5] ?? t[6] ?? t[7] ?? '';
      if (name === 'class' || name === 'id') {
        if (op && op !== '=' && op !== '~=') return null;
      }
      if (!op) attrs[name] = attrs[name] ?? 'x';
      else if (op === '=' || op === '~=' || op === '|=') attrs[name] = v;
      else if (op === '^=') attrs[name] = v + 'bx';
      else if (op === '$=') attrs[name] = 'bx' + v;
      else if (op === '*=') attrs[name] = 'bx' + v + 'bx';
      if (name === 'class') {
        classes.push(...attrs.class.split(/\s+/).filter(Boolean));
        delete attrs.class;
      }
    }
  }
  if (classes.length) attrs.class = [...new Set(classes)].join(' ');
  if (!Object.keys(attrs).length && !m[1]) return null;
  if (!Object.keys(attrs).length) return null; // a bare tag selector would hide half the page
  return { tag, attrs };
}

export function elementHtml(el: ElementSpec, id: string, text = 'Bastion e2e test element'): string {
  const esc = (v: string) => v.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
  const attrs = { ...el.attrs };
  // Our own marker for lookups; never collides with the selector's attributes.
  const marker = ` data-bx-probe="${esc(id)}"`;
  const a = Object.entries(attrs).map(([k, v]) => ` ${k}="${esc(v)}"`).join('');
  return `<${el.tag}${a}${marker} style="min-height:10px">${esc(text)}</${el.tag}>`;
}

export interface GenericPick {
  token: string;
  selector: string;
  element: ElementSpec;
  lists: string[];
}

const PREFERRED_TOKENS = ['.ad-banner', '.adsbox', '.ad-container', '.advertisement', '.ad-slot', '#ad-banner', '.banner-ad', '#adbox', '.sponsored-ad', '.adBanner'];

export function pickGenericSelectors(dist: Dist, max = 3): GenericPick[] {
  const tokens = dist.genericIndex().tokens ?? {};
  const mask = dist.defaultListMask();
  const out: GenericPick[] = [];
  const consider = (token: string) => {
    for (const [selector, listMask] of tokens[token] ?? []) {
      if (!((listMask >>> 0) & mask)) continue;
      const el = elementForSelector(selector);
      if (!el) continue;
      out.push({ token, selector, element: el, lists: dist.listNamesForMask(listMask >>> 0) });
      return true;
    }
    return false;
  };
  for (const t of PREFERRED_TOKENS) {
    if (out.length >= max) break;
    consider(t);
  }
  if (out.length < max) {
    for (const t of Object.keys(tokens).sort()) {
      if (out.length >= max) break;
      if (out.some((o) => o.token === t)) continue;
      // Exact-token selectors are the least ambiguous fixtures.
      if ((tokens[t] ?? []).some(([s]) => s === t)) consider(t);
    }
  }
  return out;
}

export interface HighGenericPick {
  listId: string;
  selector: string;
  element: ElementSpec;
}

export function pickHighGenericSelector(dist: Dist): HighGenericPick | null {
  const high = dist.genericHigh();
  const defaults = new Set((dist.meta?.lists ?? []).filter((l) => l.default).map((l) => l.id));
  for (const listId of ['easylist', 'ublock', ...Object.keys(high).sort()]) {
    if (!defaults.has(listId)) continue;
    for (const selector of high[listId] ?? []) {
      const el = elementForSelector(selector);
      if (el && Object.keys(el.attrs).some((k) => k !== 'class' && k !== 'id')) return { listId, selector, element: el };
    }
  }
  return null;
}

export interface SpecificPick {
  host: string;
  hostKey: string;
  selector: string;
  element: ElementSpec;
  lists: string[];
}

const POPULAR_HOSTS = [
  '20min.ch', 'blick.ch', 'watson.ch', 'nzz.ch', 'tagesanzeiger.ch', 'srf.ch', 'letemps.ch', 'ricardo.ch', 'tutti.ch', 'spiegel.de',
  'bild.de', 'lemonde.fr', 'corriere.it', 'reddit.com', 'stackoverflow.com', 'theguardian.com', 'cnn.com', 'weather.com', 'focus.de', 'welt.de',
];

/** Hostname-specific hide filter for a host that is not strict-blocked. */
export function pickSpecificSelectors(dist: Dist, max = 2): SpecificPick[] {
  const mask = dist.defaultListMask();
  const shards = dist.shardCount();
  if (!shards) return [];
  const out: SpecificPick[] = [];
  const tryHost = (host: string): boolean => {
    if (dist.isStrictBlocked(host)) return false;
    const n = shardOf(host, shards);
    const entries = dist.shard(n).hosts?.[host];
    if (!entries) return false;
    const flags = new Set(entries.filter((e) => e[0] === 4 && (e[2] & mask)).map((e) => e[1]));
    if (flags.has('specifichide') || flags.has('elemhide')) return false;
    const excepted = new Set(entries.filter((e) => e[0] === 1).map((e) => e[1]));
    for (const [kind, payload, listMask] of entries) {
      if (kind !== 0 || !((listMask >>> 0) & mask) || excepted.has(payload)) continue;
      const el = elementForSelector(payload);
      if (!el) continue;
      out.push({ host, hostKey: host, selector: payload, element: el, lists: dist.listNamesForMask(listMask >>> 0) });
      return true;
    }
    return false;
  };
  for (const h of POPULAR_HOSTS) {
    if (out.length >= max) break;
    tryHost(h) || tryHost('www.' + h);
  }
  for (let n = 0; n < shards && out.length < max; n++) {
    const hosts = Object.keys(dist.shard(n).hosts ?? {}).filter((h) => !h.endsWith('.*') && !isIpAddress(h) && /^[a-z0-9.-]+\.[a-z]{2,}$/.test(h)).sort();
    for (const h of hosts) {
      if (out.length >= max) break;
      if (out.some((o) => o.host === h)) continue;
      if (tryHost(h)) break; // one per shard keeps the sample diverse
    }
  }
  return out;
}

/** A hostname with a generichide flag (from an `@@||host^$generichide` filter) in an enabled list. */
export function pickGenerichideHost(dist: Dist): { host: string; lists: string[] } | null {
  const mask = dist.defaultListMask();
  const shards = dist.shardCount();
  for (let n = 0; n < shards; n++) {
    const hosts = dist.shard(n).hosts ?? {};
    for (const host of Object.keys(hosts).sort()) {
      if (host.endsWith('.*') || isIpAddress(host) || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host) || dist.isStrictBlocked(host)) continue;
      const e = hosts[host].find((x) => x[0] === 4 && x[1] === 'generichide' && ((x[2] >>> 0) & mask));
      if (e) return { host, lists: dist.listNamesForMask(e[2] >>> 0) };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Scriptlets
// ---------------------------------------------------------------------------

export interface ScriptletPick {
  host: string;
  name: 'abort-on-property-read' | 'set-constant';
  prop: string;
  value?: string;
  filter: string;
  file: string;
  registrationId: string;
}

const ADULT_HINT = /porn|sex|xxx|gay|hentai|nude|milf|adult|tube8|xvideo|xnxx|cam4|onlyfans|erotic|fetish|escort|nsfw/i;
const AOPR = new Set(['abort-on-property-read', 'abort-on-property-read.js', 'aopr', 'aopr.js']);
const SETC = new Set(['set-constant', 'set-constant.js', 'set', 'set.js']);
// 'undefined' is excluded: it is indistinguishable from "scriptlet did not run".
const SIMPLE_VALUES = new Set(['true', 'false', 'null', '0', '1', '""', "''", 'emptyStr', 'noopFunc', 'trueFunc', 'falseFunc']);

/** Directories that may hold the raw list texts the build compiled. */
export function listTextDirs(): string[] {
  const dirs = [
    process.env.BASTION_LISTS_DIR,
    path.join(REPO_ROOT, '.cache', 'lists'),
    path.join(REPO_ROOT, 'filters'),
  ].filter((d): d is string => !!d && existsSync(d));
  return dirs;
}

function* listTexts(): Generator<{ file: string; text: string }> {
  for (const dir of listTextDirs()) {
    const stack = [dir];
    while (stack.length) {
      const d = stack.pop()!;
      let entries: string[] = [];
      try {
        entries = readdirSync(d);
      } catch {
        continue;
      }
      for (const e of entries.sort()) {
        const f = path.join(d, e);
        let st;
        try {
          st = statSync(f);
        } catch {
          continue;
        }
        if (st.isDirectory()) stack.push(f);
        else if (st.isFile() && st.size < 40_000_000 && /\.(txt|list)$|^[^.]+$/.test(e)) {
          try {
            yield { file: f, text: readFileSync(f, 'utf8') };
          } catch {
            /* unreadable */
          }
        }
      }
    }
  }
}

function splitArgs(s: string): string[] {
  // uBO arg lists: comma separated, backslash escapes commas; quotes are optional.
  const out: string[] = [];
  let cur = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '\\' && s[i + 1] === ',') {
      cur += ',';
      i++;
    } else if (c === ',') {
      out.push(cur.trim());
      cur = '';
    } else cur += c;
  }
  out.push(cur.trim());
  return out.map((a) => a.replace(/^(['"])(.*)\1$/, '$2'));
}

/** Decoded tables of one scriptlet data file (tools/scriptlets.ts layout; not part of the contract). */
export interface ScriptletData {
  label: string;
  /** host -> tokens ("k", "~k", "!k", "!", optionally ":tag"). */
  records: Map<string, string[]>;
  /** key id -> [function index, ...args]. */
  payload: Map<number, unknown[]>;
}

/**
 * Parse a data file. Its tables sit in comments of two empty functions:
 * self[N]?.d.push([label, function(){ records }, G, function(){ payload }, flags]).
 * Returns null for anything else.
 */
export function decodeScriptletData(src: string): ScriptletData | null {
  const OPEN = 'function(){/' + '*';
  const CLOSE = '*' + '/}';
  const head = src.indexOf('.d.push([');
  if (head === -1) return null;
  const labelEnd = src.indexOf(',' + OPEN, head);
  if (labelEnd === -1) return null;
  let label: string;
  try {
    label = JSON.parse(src.slice(head + 9, labelEnd)) as string;
  } catch {
    return null;
  }
  const comment = (from: number): [string, number] | null => {
    const i = src.indexOf(OPEN, from);
    if (i === -1) return null;
    const j = src.indexOf(CLOSE, i + OPEN.length);
    return j === -1 ? null : [src.slice(i + OPEN.length, j), j + CLOSE.length];
  };
  const r = comment(labelEnd);
  const p = r ? comment(r[1]) : null;
  if (!r || !p) return null;
  const records = new Map<string, string[]>();
  for (const line of r[0].split('\n')) {
    const sp = line.indexOf(' ');
    if (sp > 0) records.set(line.slice(0, sp), line.slice(sp + 1).split(','));
  }
  const payload = new Map<number, unknown[]>();
  for (const line of p[0].split('\n')) {
    const sp = line.indexOf(' ');
    if (sp <= 0) continue;
    try {
      payload.set(parseInt(line.slice(0, sp), 36), JSON.parse(line.slice(sp + 1)) as unknown[]);
    } catch {
      /* not ours */
    }
  }
  return { label, records, payload };
}

/** Function names of a scriptlet core file, by index (its `F: [...]` table). */
export function scriptletFunctionNames(coreSrc: string): string[] {
  const m = /\bF:\s*\[([^\]]*)\]/.exec(coreSrc);
  return m ? m[1].split(',').map((x) => x.trim()) : [];
}

/** MAIN-world data files of the default lists, with their decoded tables. */
function defaultMainData(dist: Dist): { file: string; data: ScriptletData }[] {
  const defaults = new Set((dist.meta?.lists ?? []).filter((l) => l.default).map((l) => l.id));
  const out: { file: string; data: ScriptletData }[] = [];
  for (const reg of dist.scriptletIndex().registrations ?? []) {
    if (reg.world !== 'MAIN' || !defaults.has(reg.listId) || !dist.has(reg.file)) continue;
    const data = decodeScriptletData(dist.text(reg.file));
    if (data) out.push({ file: reg.file, data });
  }
  return out;
}

/** Hosts (and parents) carrying a #@#+js exception in any of the given data files. */
function scriptletExceptionHosts(files: { data: ScriptletData }[]): Set<string> {
  const out = new Set<string>();
  for (const { data } of files) for (const [h, ts] of data.records) if (ts.some((t) => t.startsWith('!'))) out.add(h);
  return out;
}

/**
 * Scriptlet filters (abort-on-property-read / set-constant with one plain
 * global identifier) whose hostname has a record in the MAIN-world data of a
 * default list that mentions the property: proof that the build shipped them.
 * The scriptlet bundle (`sl-main`) is registered for <all_urls>; the runner
 * matches the hostname in-script.
 */
export function pickScriptlets(dist: Dist, max = 3): ScriptletPick[] {
  const files = defaultMainData(dist);
  if (!files.length) return [];
  const exceptionHosts = scriptletExceptionHosts(files);
  const fileFor = (host: string, prop: string) => {
    for (const cand of hostnameCandidates(host)) {
      for (const f of files) {
        const ts = f.data.records.get(cand);
        if (!ts || ts.some((t) => t.startsWith('~'))) continue;
        if (ts.some((t) => { const al = f.data.payload.get(parseInt(t.split(':')[0], 36)); return Array.isArray(al) && al.includes(prop); })) return f.file;
      }
    }
    return null;
  };
  const seenHosts = new Set<string>();
  const exceptions = new Set<string>();
  const candidates: (ScriptletPick & { order: number })[] = [];
  let order = 0;
  const lineRe = /^([a-z0-9.,~-]+)#(@?)#\+js\((.*)\)\s*$/;
  for (const { file, text } of listTexts()) {
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line.includes('#+js(') && !line.includes('#@#+js(')) continue;
      const m = lineRe.exec(line);
      if (!m) continue;
      const hosts = m[1].split(',').filter((h) => h && !h.startsWith('~'));
      if (m[2] === '@') {
        for (const h of hosts) exceptions.add(h);
        continue;
      }
      if (hosts.length !== 1) continue;
      const host = hosts[0];
      if (host.endsWith('.*') || isIpAddress(host) || !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(host) || seenHosts.has(host)) continue;
      // Test logs and reports name the host; keep them presentable.
      if (ADULT_HINT.test(host)) continue;
      const args = splitArgs(m[3]);
      const name = args[0];
      let pick: Omit<ScriptletPick, 'file' | 'registrationId'> | null = null;
      if (AOPR.has(name) && args.length === 2 && /^[A-Za-z_$][\w$]*$/.test(args[1])) {
        pick = { host, name: 'abort-on-property-read', prop: args[1], filter: line };
      } else if (SETC.has(name) && args.length === 3 && /^[A-Za-z_$][\w$]*$/.test(args[1]) && SIMPLE_VALUES.has(args[2])) {
        pick = { host, name: 'set-constant', prop: args[1], value: args[2], filter: line };
      }
      if (!pick) continue;
      // Properties the browser or our probe page define natively would make the probe meaningless.
      if (pick.prop in globalThis || ['document', 'window', 'navigator', 'location', 'top', 'self', 'parent', 'frames', 'name', 'status'].includes(pick.prop)) continue;
      if (dist.isStrictBlocked(host)) continue;
      if (hostnameCandidates(host).some((h) => exceptionHosts.has(h))) continue;
      const dataFile = fileFor(host, pick.prop);
      if (!dataFile) continue;
      seenHosts.add(host);
      candidates.push({ ...pick, file: dataFile, registrationId: 'sl-main', order: order++ });
    }
  }
  const filtered = candidates.filter((c) => !hostnameCandidates(c.host).some((h) => exceptions.has(h)) && !entityCandidates(c.host).some((h) => exceptions.has(h)));
  // Prefer abort-on-property-read (cleanest signal), keep list order otherwise.
  filtered.sort((a, b) => Number(a.name !== 'abort-on-property-read') - Number(b.name !== 'abort-on-property-read') || a.order - b.order);
  const picks = filtered.slice(0, max).map(({ order: _o, ...rest }) => rest);
  if (picks.length < max) {
    for (const p of pickScriptletsFromShards(dist, max)) {
      if (picks.length >= max) break;
      if (!picks.some((x) => x.host === p.host)) picks.push(p);
    }
  }
  return picks;
}

/**
 * Fallback when no raw list texts are around (e.g. testing a downloaded
 * build): read the tables of the generated data files (decodeScriptletData;
 * the shape is not part of the contract, so any parse problem just yields no
 * picks).
 */
export function pickScriptletsFromShards(dist: Dist, max = 3): ScriptletPick[] {
  const out: ScriptletPick[] = [];
  const core = (dist.scriptletIndex().bundles ?? []).find((b) => b.world === 'MAIN');
  if (!core || !dist.has(core.core)) return out;
  const F = scriptletFunctionNames(dist.text(core.core));
  const files = defaultMainData(dist);
  const exceptionHosts = scriptletExceptionHosts(files);
  for (const { file, data } of files) {
    if (out.length >= max) break;
    for (const [host, tokens] of [...data.records].sort((x, y) => (x[0] < y[0] ? -1 : 1))) {
      if (out.length >= max) break;
      if (tokens.some((t) => /^[~!]/.test(t) || t.includes(':'))) continue;
      if (isIpAddress(host) || host.endsWith('.*') || ADULT_HINT.test(host) || dist.isStrictBlocked(host) || !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(host)) continue;
      if (hostnameCandidates(host).some((h) => exceptionHosts.has(h))) continue;
      for (const t of tokens) {
        const al = data.payload.get(parseInt(t, 36));
        if (!Array.isArray(al)) continue;
        const fn = F[al[0] as number];
        const args = al.slice(1) as string[];
        if (fn === 'abortOnPropertyRead' && args.length === 1 && /^[A-Za-z_$][\w$]*$/.test(args[0] ?? '')) {
          out.push({ host, name: 'abort-on-property-read', prop: args[0], filter: `${host}##+js(aopr, ${args[0]}) [from ${file}]`, file, registrationId: 'sl-main' });
          break;
        }
        if (fn === 'setConstant' && args.length === 2 && /^[A-Za-z_$][\w$]*$/.test(args[0] ?? '') && SIMPLE_VALUES.has(args[1] ?? '')) {
          out.push({ host, name: 'set-constant', prop: args[0], value: args[1], filter: `${host}##+js(set, ${args[0]}, ${args[1]}) [from ${file}]`, file, registrationId: 'sl-main' });
          break;
        }
      }
    }
  }
  return out;
}
