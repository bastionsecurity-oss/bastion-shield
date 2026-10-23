// Bastion Shield — turns the compiled `+js()` filters of every list into a
// small, fixed set of content-script files per world (ARCHITECTURE §6):
//
//   dist/scriptlets/scriptlet-core-<world>.js  every scriptlet function any list uses, once, and the runner
//   dist/scriptlets/<listId>-<world>.js        one list's data: hostname table, exceptions, arglists
//   dist/scriptlets/scriptlet-end-<world>.js   one call: run
//   dist/scriptlets/index.json                 ScriptletIndex for the service worker
//
// The service worker registers ONE content script per world for <all_urls>,
// whose `js` is [core, data files of the enabled lists, end]. Chrome then
// matches a handful of patterns per frame instead of tens of thousands of
// per-host patterns (review PERF-1/PERF-2); the hostname lookup happens in
// the runner:
//
//   - The core declares the (deduplicated) uBO helper and scriptlet functions
//     and the runner, and hands them over on a per-build secret-named global.
//     Each data file pushes its tables onto it; the end file calls the
//     runner, which deletes the global first. No page script can run in
//     between, so pages never see it.
//   - Every frame compiles every data file, so the tables are kept where V8
//     only skips over them: inside a comment of an otherwise empty function.
//     The runner reads them back with Function.prototype.toString (a
//     substring of the script source, no copy) only for the frame's lookups.
//       records  "host tokens\n" sorted by host, binary-searched in place;
//                tokens are base-36 key ids: `k` (entry applies), `~k` (the
//                filter's own ~host), `!k` (#@#+js exception for key k, any
//                list), `!` (host#@#+js(): no scriptlets here). Entities
//                ("google.*") and "*" (generic) are ordinary keys.
//       regexes  [[source, "k,k", literals?]] for /regex/ hostnames (or
//                0). `literals` (regexPrefilter) are substrings every match
//                contains: the runner compiles the regex only when the
//                frame's hostname contains them, so most frames compile none.
//       payload  "k [fnIndex,...args]\n" sorted by key, parsed per hit only.
//       flags    1 = has entity records, 2 = has a "*" record.
//   - Key ids are global per world, so the same (scriptlet, args) from two
//     enabled lists runs once. Exceptions apply when the list defining them
//     is enabled (uBO semantics).
//
// Unmatched frames pay the compile of the files (mostly comment skipping)
// and one binary search per list and hostname candidate.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { randomBytes } from 'node:crypto';
import { Script } from 'node:vm';
import { domainToASCII } from 'node:url';
import { join } from 'node:path';
import type { ScriptletFilter } from '../src/compiler/types.ts';
import type { ScriptletBundle, ScriptletIndex, ScriptletMerged, ScriptletRegistration } from '../src/shared/types.ts';
import { isIpAddress } from '../src/shared/hash.ts';
import { specializeTemplate, type LibFunction, type LibScriptlet, type ResourceSet } from './resources.ts';
import { createLogger, writeJson, writeText, type Logger } from './lib/util.ts';
import { CLIPBOARD_SCRIPTLET, noticeEventName, transformClipboardScriptlet } from './lib/notice-transform.ts';

export interface ScriptletListInput {
  listId: string;
  trusted: boolean;
  scriptlets: ScriptletFilter[];
  /** Hosts flagged "noscriptlets" by cosmetic data (treated like `host#@#+js()`). */
  noScriptletHosts?: string[];
}

export interface EmitScriptletsOptions {
  /** dist/ directory. */
  outDir: string;
  lists: ScriptletListInput[];
  resources: ResourceSet;
  /** Minify whitespace/syntax of core and end files (identifiers stay readable). */
  minify?: boolean;
  log?: Logger;
  /**
   * Lists whose data is also merged into one file per world, used by the SW
   * when all of them are enabled (the default set): one file and one lookup
   * per frame instead of one per list.
   */
  mergedLists?: string[];
  /**
   * Name of the transient global that carries functions and data from the
   * core file to the end file. Must be unguessable by pages: default is a
   * fresh random name per call (per build).
   */
  globalName?: string;
  /**
   * Event name of the blocker-notice channel (tools/lib/notice-transform.ts):
   * uBO's prevent-clipboard-write dispatches it instead of drawing its own
   * alert. Default: a fresh random name per call (per build). The build
   * compiles the same name into content/cosmetic.js.
   */
  noticeEvent?: string;
}

export interface ScriptletFileInfo {
  path: string;
  kind: 'core' | 'data' | 'merged' | 'end';
  /** '' for core and end files. */
  listId: string;
  world: 'MAIN' | 'ISOLATED';
  bytes: number;
  /** Records in the hostname table (data files). */
  hosts: number;
  /** Arglists in the payload (data files). */
  arglists: number;
  /** Functions declared (core files). */
  functions: number;
}

export interface ScriptletListStats {
  /** Distinct (scriptlet, args) entries emitted. */
  entries: number;
  /** Filters dropped, by reason. */
  rejected: Record<string, number>;
  files: number;
  bytes: number;
  /** Distinct hostnames/entities with at least one entry. */
  hosts: number;
  /**
   * trusted-click-element host instances dropped because an entry of the
   * same list with the same selectors and a longer delay covers the host
   * (review PERF-4). The click then happens after that longer delay.
   */
  collapsedClicks: number;
  /** `#@#+js()` exception records carried by this list. */
  exceptions: number;
}

export interface EmitScriptletsResult {
  index: ScriptletIndex;
  files: ScriptletFileInfo[];
  perList: Record<string, ScriptletListStats>;
  globalName: string;
  /** The notice event name compiled into the scriptlet core. */
  noticeEvent: string;
}

type World = 'MAIN' | 'ISOLATED';
const WORLDS: readonly World[] = ['MAIN', 'ISOLATED'];

interface Entry {
  key: string;
  lib: LibScriptlet;
  args: string[];
  /** Hostnames, bare labels and entities: keys of the data file's table. */
  hosts: Set<string>;
  regexes: Set<string>;
  generic: boolean;
  /** `~host` exclusions of this filter. */
  excluded: Set<string>;
}

/** Exception "all scriptlets" (`host#@#+js()`). */
const BROAD = '';
const GENERIC_HOST = '*';
const keyOf = (name: string, args: readonly string[]) => `${name}\u0000${JSON.stringify(args)}`;
const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const CLICK = 'trusted-click-element.js';

export const CORE_FILE = (world: World) => `scriptlets/scriptlet-core-${world.toLowerCase()}.js`;
export const END_FILE = (world: World) => `scriptlets/scriptlet-end-${world.toLowerCase()}.js`;
export const DATA_FILE = (listId: string, world: World) => `scriptlets/${listId}-${world.toLowerCase()}.js`;
export const MERGED_FILE = (world: World) => `scriptlets/scriptlet-merged-${world.toLowerCase()}.js`;

// ---------------------------------------------------------------------------
// Hostname helpers (uBO semantics: every suffix label, entities by stripping
// any number of trailing labels)
// ---------------------------------------------------------------------------

function normalizeHost(h: string): string {
  let s = h.trim().toLowerCase();
  if (s.endsWith('.')) s = s.slice(0, -1);
  if (/[^\x00-\x7f]/.test(s) && !s.endsWith('.*')) {
    const a = domainToASCII(s);
    if (a) s = a;
  }
  return s;
}

type HostKind = 'host' | 'entity' | 'regex' | 'generic' | 'invalid';

function classifyHost(h: string): HostKind {
  if (h === '' || h === '*') return 'generic';
  if (h.length > 2 && h.startsWith('/') && h.endsWith('/')) return 'regex';
  if (h.endsWith('.*')) return /^[a-z0-9_.-]+\.\*$/.test(h) && !h.startsWith('.') ? 'entity' : 'invalid';
  if (isIpAddress(h)) return /^[0-9a-f.:[\]]+$/.test(h) ? 'host' : 'invalid';
  return /^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/.test(h) ? 'host' : 'invalid';
}

/** Index of the `]` closing the character class that starts at `i` (`[`), or -1. */
function classEnd(s: string, i: number): number {
  for (let j = i + 1; j < s.length; j++) {
    if (s[j] === '\\') j++;
    else if (s[j] === ']') return j;
  }
  return -1;
}

/** Literal alternatives of a group body like `com|xyz` or `?:a\.b|c`, else null. */
function groupAlternatives(body: string): string[] | null {
  const b = body.startsWith('?:') ? body.slice(2) : body;
  if (!/^(?:[A-Za-z0-9_-]|\\[./-])+(?:\|(?:[A-Za-z0-9_-]|\\[./-])+)*$/.test(b)) return null;
  return b.split('|').map((a) => a.replace(/\\(.)/g, '$1'));
}

/**
 * Substrings every match of a hostname regex contains (review PERF-1): each
 * item is a required literal, or a list of alternatives one of which is
 * required. The runner tests them with indexOf on the frame's hostname
 * before it compiles the regex, so the usual frame compiles none. Strictly
 * conservative: anything not understood ends a literal, and an unknown
 * escape, a top-level `|` or unbalanced syntax returns null (no prefilter).
 */
export function regexPrefilter(source: string): (string | string[])[] | null {
  const out: (string | string[])[] = [];
  let run = '';
  const flush = () => {
    if (run.length >= 3) out.push(run);
    run = '';
  };
  const quantifier = (j: number): { end: number; zero: boolean } | null => {
    const c = source[j];
    const lazy = (k: number) => (source[k] === '?' ? k + 1 : k);
    if (c === '?' || c === '*') return { end: lazy(j + 1), zero: true };
    if (c === '+') return { end: lazy(j + 1), zero: false };
    if (c === '{') {
      const m = /^\{(\d+)(?:,(\d*))?\}/.exec(source.slice(j));
      if (m) return { end: lazy(j + m[0].length), zero: Number(m[1]) === 0 };
    }
    return null;
  };
  let i = 0;
  while (i < source.length) {
    const c = source[i];
    let end: number;
    let lit: string | null = null;
    let alts: string[] | null = null;
    if (c === '|' || c === ')' || c === '*' || c === '+' || c === '?' || c === '{' || c === '}' || c === ']') return null;
    if (c === '\\') {
      const e = source[i + 1];
      if (e === undefined) return null;
      if ('.-/\\:_$^*+?()[]{}|'.includes(e)) lit = e;
      else if (!'dDwWsSbB'.includes(e)) return null; // \x41, \u.., \1, \k<>, \p{}, \cX, \n ...: not analysed
      end = i + 2;
    } else if (c === '[') {
      const j = classEnd(source, i);
      if (j === -1) return null;
      end = j + 1;
    } else if (c === '(') {
      let depth = 0;
      let j = i;
      for (; j < source.length; j++) {
        const d = source[j];
        if (d === '\\') j++;
        else if (d === '[') {
          j = classEnd(source, j);
          if (j === -1) return null;
        } else if (d === '(') depth++;
        else if (d === ')' && --depth === 0) break;
      }
      if (j >= source.length) return null;
      // Lookarounds and named groups ("(?=", "(?<n>") are not literal.
      const body = source.slice(i + 1, j);
      alts = body.startsWith('?') && !body.startsWith('?:') ? null : groupAlternatives(body);
      end = j + 1;
    } else if (c === '.' || c === '^' || c === '$') {
      end = i + 1;
    } else {
      lit = c;
      end = i + 1;
    }
    const q = quantifier(end);
    if (q !== null && q.zero) {
      // Optional atom: neither it nor a literal across it is required.
      flush();
      i = q.end;
      continue;
    }
    if (lit !== null) {
      run += lit;
      if (q !== null) flush(); // required once, then repeated
    } else {
      flush();
      if (alts !== null && alts.every((a) => a.length >= 2)) out.push(alts.length === 1 ? alts[0] : alts);
    }
    i = q !== null ? q.end : end;
  }
  flush();
  return out.length > 0 ? out : null;
}

// ---------------------------------------------------------------------------
// Runtime (plain JS kept as strings: the part of the generated files we own)
// ---------------------------------------------------------------------------

// `self.origin` covers about:blank/srcdoc/blob frames (inherited origin);
// ancestorOrigins is the fallback for opaque ones.
const RUNTIME_HEAD = String.raw`let hn = '';
try {
  hn = self.location.hostname;
  if (hn === '') {
    let origin = '';
    try { origin = self.origin; } catch (e) {}
    if (!origin || origin === 'null') {
      const ao = self.location.ancestorOrigins;
      if (ao && ao.length !== 0) origin = ao[0];
    }
    const m = /^[a-z][a-z0-9+.-]*:\/\/(\[[^\]]*\]|[^\/:?#]*)/i.exec(origin || '');
    if (m !== null) hn = m[1];
  }
} catch (e) { return; }
hn = hn.toLowerCase();
if (hn.endsWith('.')) hn = hn.slice(0, -1);
if (hn === '') return;`;

// The runner, declared in the core (one compile per renderer, lazily):
// candidate keys are the hostname and every suffix, entity forms of each
// (only looked up in lists that have entities) and "*" (only in lists with
// generic entries). find() binary-searches a string of records
// "key value\n" sorted by key (base-36 numbers when num) and returns the
// value or null. Tables live in a comment of d[1] / d[3] (see the header).
const RUNTIME_RUN = String.raw`function bastionScriptletRun() {
try { delete self[NAME]; } catch (e) {}
if (B.d.length === 0) return;
RUNTIME_HEAD
const keys = [hn];
for (let p = hn.indexOf('.'); p !== -1; p = hn.indexOf('.', p + 1)) keys.push(hn.slice(p + 1));
const nh = keys.length;
const ents = [];
for (let i = 0; i < nh; i++) {
  let k = keys[i];
  for (let p = k.lastIndexOf('.'); p !== -1; p = k.lastIndexOf('.')) { k = k.slice(0, p); ents.push(k + '.*'); }
}
const text = (f) => {
  const s = toStr.call(f);
  return s.slice(s.indexOf('/*') + 2, s.lastIndexOf('*/'));
};
const find = (s, key, num) => {
  let lo = 0, hi = s.length;
  while (lo < hi) {
    const a = s.lastIndexOf('\n', ((lo + hi) >>> 1) - 1) + 1;
    const e = s.indexOf('\n', a);
    const sp = s.indexOf(' ', a);
    const k = num ? parseInt(s.slice(a, sp), 36) : s.slice(a, sp);
    if (k === key) return s.slice(sp + 1, e);
    if (k < key) lo = e + 1; else hi = a;
  }
  return null;
};
const hit = new Map();
const ex = new Set();
let broad = false;
for (let li = 0; li < B.d.length; li++) {
  const d = B.d[li];
  // Per tag (one list of a merged file, '' = shared): [positives, exclusions].
  const groups = new Map();
  const add = (x) => {
    const c = x.charCodeAt(0);
    if (c === 33) { if (x.length === 1) broad = true; else ex.add(parseInt(x.slice(1), 36)); return; }
    const neg = c === 126;
    const body = neg ? x.slice(1) : x;
    const ci = body.indexOf(':');
    const tag = ci === -1 ? '' : body.slice(ci + 1);
    let g = groups.get(tag);
    if (g === undefined) groups.set(tag, (g = [[], null]));
    const k = parseInt(ci === -1 ? body : body.slice(0, ci), 36);
    if (neg) (g[1] || (g[1] = new Set())).add(k); else g[0].push(k);
  };
  const look = (s, k) => {
    const t = find(s, k, false);
    if (t !== null) for (const x of t.split(',')) add(x);
  };
  try {
    const s = text(d[1]);
    for (let i = 0; i < nh; i++) look(s, keys[i]);
    if ((d[4] & 1) !== 0) for (const k of ents) look(s, k);
    if ((d[4] & 2) !== 0) look(s, '*');
    if (d[2] !== 0) {
      for (const g of d[2]) {
        const pf = g[2];
        if (pf !== undefined && !pf.every((x) => (typeof x === 'string' ? hn.indexOf(x) !== -1 : x.some((y) => hn.indexOf(y) !== -1)))) continue;
        let re;
        try { re = new RegExp(g[0]); } catch (e) { continue; }
        for (let i = 0; i < nh; i++) {
          if (re.test(keys[i])) { for (const x of g[1].split(',')) add(x); break; }
        }
      }
    }
  } catch (e) { continue; }
  for (const g of groups.values()) for (const k of g[0]) if ((g[1] === null || !g[1].has(k)) && !hit.has(k)) hit.set(k, li);
}
if (broad || hit.size === 0) return;
const run = [];
const payloads = new Map();
for (const [k, li] of hit) {
  if (ex.has(k)) continue;
  try {
    let p = payloads.get(li);
    if (p === undefined) payloads.set(li, (p = text(B.d[li][3])));
    const j = find(p, k, true);
    if (j !== null) run.push([k, JSON.parse(j)]);
  } catch (e) {}
}
run.sort((a, b) => (B.P[b[1][0]] - B.P[a[1][0]]) || (a[0] - b[0]));
for (const r of run) {
  const al = r[1];
  try { B.F[al[0]](...al.slice(1)); } catch (e) {}
}
}`.replace('RUNTIME_HEAD', () => RUNTIME_HEAD);

function coreHeader(world: World, brave: boolean): string {
  const lines = [
    `/*! Bastion Shield scriptlets: shared code, world ${world}. Generated by tools/scriptlets.ts; do not edit.`,
    ' * Bastion Shield is free software: GPL-3.0-or-later. https://github.com/bastionsecurity-oss/bastion-shield',
    ' * Contains scriptlet code from uBlock Origin, Copyright (C) Raymond Hill and contributors,',
    ' * GPL-3.0-or-later, https://github.com/gorhill/uBlock (vendor/ublock).',
  ];
  if (brave) lines.push(' * Contains resources from Brave adblock-resources, MPL-2.0, https://github.com/brave/adblock-resources (vendor/brave-resources).');
  lines.push(' */');
  return lines.join('\n') + '\n';
}

const endHeader = (world: World) =>
  `/*! Bastion Shield scriptlets: runner, world ${world}. GPL-3.0-or-later. Generated by tools/scriptlets.ts; do not edit. */\n`;

const mergedHeader = (ids: string[], world: World) =>
  `/*! Bastion Shield scriptlet data: lists ${ids.join(', ')} merged, world ${world}. Generated by tools/scriptlets.ts; do not edit. */
`;

const dataHeader = (listId: string, world: World) =>
  `/*! Bastion Shield scriptlet data: list "${listId}", world ${world}. Generated by tools/scriptlets.ts; do not edit. */\n`;

/** Topologically ordered closure (dependencies first) of the given library keys. */
function functionClosure(roots: Iterable<string>, functions: Map<string, LibFunction>): LibFunction[] {
  const out: LibFunction[] = [];
  const state = new Map<string, 1 | 2>();
  const visit = (key: string) => {
    if (state.get(key) !== undefined) return;
    const f = functions.get(key);
    if (!f) return;
    state.set(key, 1);
    for (const d of [...f.deps].sort()) visit(d);
    state.set(key, 2);
    out.push(f);
  };
  for (const r of [...roots].sort()) visit(r);
  return out;
}

const isClassDecl = (code: string) => /^\s*class\b/.test(code);

async function finalizeCode(code: string, minify: boolean, filename: string): Promise<string> {
  let out = asciiOnly(code);
  if (minify) {
    const esbuild = await import('esbuild');
    const r = await esbuild.transform(code, {
      loader: 'js',
      minifyWhitespace: true,
      minifySyntax: true,
      // Identifiers stay as in uBO's sources: transparent and safer.
      minifyIdentifiers: false,
      legalComments: 'inline',
      // One-byte sources: Chrome and V8 keep them as Latin-1 strings.
      charset: 'ascii',
    });
    out = r.code;
  }
  // Parse check: a syntax error here would silently disable every scriptlet.
  new Script(out, { filename });
  return out;
}

/**
 * Review PERF-4: uBO, EasyList and Brave cookie lists often ship the same
 * trusted-click-element selector for a host with different delays; each copy
 * runs its own MutationObserver for up to 10 s. Within one list (safe:
 * lists are toggled as a whole) keep a host only in the entry with the
 * longest delay. Entries with `~host` exclusions are left alone, so no host
 * loses a click it had. Returns the number of host instances dropped.
 */
function collapseClicks(entries: Map<string, Entry>): number {
  const groups = new Map<string, Entry[]>();
  for (const e of entries.values()) {
    if (e.lib.name !== CLICK || e.excluded.size !== 0) continue;
    const g = JSON.stringify([e.args[0] ?? '', e.args[1] ?? '', ...e.args.slice(3)]);
    let a = groups.get(g);
    if (!a) groups.set(g, (a = []));
    a.push(e);
  }
  const delay = (e: Entry) => parseInt(e.args[2] ?? '', 10) || 1;
  let dropped = 0;
  for (const list of groups.values()) {
    if (list.length < 2) continue;
    list.sort((a, b) => delay(b) - delay(a) || cmp(a.key, b.key));
    const taken = new Set<string>();
    for (const e of list) {
      for (const h of [...e.hosts].sort()) {
        if (taken.has(h)) {
          e.hosts.delete(h);
          dropped++;
        } else taken.add(h);
      }
    }
    for (const e of list) if (e.hosts.size === 0 && e.regexes.size === 0 && !e.generic) entries.delete(e.key);
  }
  return dropped;
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------

interface ListState {
  input: ScriptletListInput;
  stats: ScriptletListStats;
  byWorld: Record<World, Map<string, Entry>>;
  /** host (or "*") -> exception keys (BROAD = every scriptlet). */
  exceptions: Map<string, Set<string>>;
}

/** Non-ASCII as \uXXXX: valid in JS source and JSON, keeps every file one-byte (Latin-1) in Chrome and V8. */
export function asciiOnly(s: string): string {
  return s.replace(/[^\x00-\x7f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

interface EncodedData {
  code: (globalName: string, label: string) => string;
  hosts: number;
  arglists: number;
  exceptions: number;
  hostKeys: Set<string>;
}

/**
 * Tables of one data file for one or several lists (see the header). With
 * several lists, a key whose entry has `~host` exclusions in one list and
 * exists in another gets per-list tags (`k:t`, `~k:t`), because an exclusion
 * only cancels the entry of its own list; every other token is shared.
 * Tokens already present on a parent hostname are dropped: the runner looks
 * up every suffix of the frame's hostname, so they add nothing.
 */
function encodeData(parts: ListState[], world: World, keyId: ReadonlyMap<string, number>, keyPayload: readonly string[]): EncodedData | null {
  const recs = new Map<string, Set<string>>();
  const add = (h: string, t: string) => {
    let s = recs.get(h);
    if (!s) recs.set(h, (s = new Set()));
    s.add(t);
  };
  const regex = new Map<string, Set<string>>();
  const used = new Set<number>();
  const hostKeys = new Set<string>();
  const tagged = new Set<string>();
  if (parts.length > 1) {
    const seen = new Map<string, number>();
    const excl = new Set<string>();
    for (const st of parts) {
      for (const e of st.byWorld[world].values()) {
        seen.set(e.key, (seen.get(e.key) ?? 0) + 1);
        if (e.excluded.size !== 0) excl.add(e.key);
      }
    }
    for (const k of excl) if ((seen.get(k) ?? 0) > 1) tagged.add(k);
  }
  let exceptions = 0;
  parts.forEach((st, i) => {
    for (const e of st.byWorld[world].values()) {
      const id = keyId.get(e.key)!;
      used.add(id);
      const k = tagged.has(e.key) ? `${id.toString(36)}:${i.toString(36)}` : id.toString(36);
      for (const h of e.hosts) {
        add(h, k);
        hostKeys.add(h);
      }
      if (e.generic) add(GENERIC_HOST, k);
      for (const x of e.excluded) add(x, `~${k}`);
      for (const re of e.regexes) {
        let a = regex.get(re);
        if (!a) regex.set(re, (a = new Set()));
        a.add(k);
      }
    }
    for (const [h, ks] of st.exceptions) {
      for (const key of ks) {
        if (key === BROAD) add(h, '!');
        else {
          const id = keyId.get(key);
          if (id === undefined) continue; // no list has this (scriptlet, args) in this world
          add(h, `!${id.toString(36)}`);
        }
        exceptions++;
      }
    }
  });
  if (recs.size === 0 && regex.size === 0) return null;
  // Drop tokens a parent hostname already carries (compared with the unpruned sets).
  const drop = new Map<string, string[]>();
  for (const [h, ts] of recs) {
    if (h === GENERIC_HOST || h.endsWith('.*') || isIpAddress(h)) continue;
    for (let p = h.indexOf('.'); p !== -1; p = h.indexOf('.', p + 1)) {
      const parent = recs.get(h.slice(p + 1));
      if (!parent) continue;
      for (const t of ts) if (parent.has(t)) (drop.get(h) ?? drop.set(h, []).get(h)!).push(t);
    }
  }
  for (const [h, ts] of drop) {
    const s = recs.get(h)!;
    for (const t of ts) s.delete(t);
    if (s.size === 0) recs.delete(h);
  }
  const hosts = [...recs.keys()].sort(cmp);
  const records = hosts.map((h) => `${h} ${[...recs.get(h)!].sort(cmp).join(',')}\n`).join('');
  if (records.includes('*/') || /[^\x00-\x7f]/.test(records)) throw new Error('scriptlet records contain "*/" or non-ASCII text');
  const G = [...regex.entries()]
    .sort((a, b) => cmp(a[0], b[0]))
    .map(([re, ks]) => {
      const src = re.slice(1, -1);
      const pf = regexPrefilter(src);
      return pf === null ? [src, [...ks].join(',')] : [src, [...ks].join(','), pf];
    });
  // "*/" can only occur inside JSON strings, where "*\/" is the same text.
  const ids = [...used].sort((a, b) => a - b);
  const payload = ids.map((id) => `${id.toString(36)} ${keyPayload[id]}\n`).join('').replace(/\*\//g, '*\\/');
  const flags = (hosts.some((h) => h.endsWith('.*')) ? 1 : 0) | (recs.has(GENERIC_HOST) ? 2 : 0);
  return {
    hosts: hosts.length,
    arglists: ids.length,
    exceptions,
    hostKeys,
    code: (globalName, label) =>
      `self[${JSON.stringify(globalName)}]?.d.push([${JSON.stringify(label)},function(){/*${records}*/},` +
      `${G.length ? asciiOnly(JSON.stringify(G)) : '0'},function(){/*${payload}*/},${flags}]);\n`,
  };
}

export async function emitScriptlets(opts: EmitScriptletsOptions): Promise<EmitScriptletsResult> {
  const log = opts.log ?? createLogger('scriptlets');
  const { resources } = opts;
  const globalName = opts.globalName ?? `__bastionSl${randomBytes(12).toString('hex')}`;
  const noticeEvent = opts.noticeEvent ?? noticeEventName();
  // uBO's clipboard scriptlet reports to the Bastion notice instead of drawing its own alert (throws when the anchors moved).
  const codeOf = (f: LibFunction): string => (f.key === CLIPBOARD_SCRIPTLET ? transformClipboardScriptlet(f.code, noticeEvent) : f.code);
  if (!/^[A-Za-z_$][\w$]{11,}$/.test(globalName)) throw new Error(`emitScriptlets: invalid globalName ${JSON.stringify(globalName)}`);
  const resolveLib = (name: string): LibScriptlet | undefined => {
    const direct = resources.scriptlets.get(name);
    if (direct) return direct;
    const info = resources.scriptletMap.get(name);
    return info ? resources.scriptlets.get(info.name) : undefined;
  };

  // 1) Entries and exceptions per list.
  const states: ListState[] = [];
  for (const list of opts.lists) {
    if (!/^[a-z0-9-]+$/.test(list.listId) || list.listId.startsWith('scriptlet-')) throw new Error(`emitScriptlets: unusable list id ${list.listId}`);
    const stats: ScriptletListStats = { entries: 0, rejected: {}, files: 0, bytes: 0, hosts: 0, collapsedClicks: 0, exceptions: 0 };
    const reject = (reason: string) => (stats.rejected[reason] = (stats.rejected[reason] ?? 0) + 1);
    const st: ListState = { input: list, stats, byWorld: { MAIN: new Map(), ISOLATED: new Map() }, exceptions: new Map() };
    states.push(st);
    const addEx = (host: string, key: string) => {
      let s = st.exceptions.get(host);
      if (!s) st.exceptions.set(host, (s = new Set()));
      s.add(key);
    };
    for (const h of list.noScriptletHosts ?? []) {
      const n = normalizeHost(h);
      const kind = classifyHost(n);
      if (kind === 'host' || kind === 'entity') addEx(n, BROAD);
    }
    for (const f of list.scriptlets) {
      if (f.exception) {
        const lib = f.name === '' ? undefined : resolveLib(f.name);
        if (f.name !== '' && !lib) continue; // exception for something we do not have
        const key = lib ? keyOf(lib.name, f.args) : BROAD;
        const hosts = f.hosts.map(normalizeHost).filter((h) => h !== '');
        if (hosts.length === 0 || hosts.includes('*')) {
          if (key === BROAD) log.warn(`${list.listId}: ignoring global "#@#+js()" (would disable every scriptlet): ${f.raw}`);
          else addEx(GENERIC_HOST, key);
          continue;
        }
        for (const h of hosts) {
          const kind = classifyHost(h);
          if (kind === 'host' || kind === 'entity') addEx(h, key);
          else reject('exception hostname not supported (regex)');
        }
        continue;
      }
      const lib = resolveLib(f.name);
      if (!lib) {
        reject(`unknown scriptlet ${f.name}`);
        continue;
      }
      if (lib.requiresTrust && !list.trusted) {
        reject('requires trust (list is not trusted)');
        continue;
      }
      const key = keyOf(lib.name, f.args);
      const world = lib.world;
      let e = st.byWorld[world].get(key);
      const fresh = !e;
      if (!e) e = { key, lib, args: [...f.args], hosts: new Set(), regexes: new Set(), generic: false, excluded: new Set() };
      const hosts = f.hosts.map(normalizeHost);
      let usable = 0;
      if (hosts.length === 0) {
        e.generic = true;
        usable++;
      }
      for (const h of hosts) {
        const kind = classifyHost(h);
        if (kind === 'host' || kind === 'entity') e.hosts.add(h);
        else if (kind === 'regex') e.regexes.add(h);
        else if (kind === 'generic') e.generic = true;
        else {
          reject('unsupported hostname syntax');
          continue;
        }
        usable++;
      }
      if (usable === 0) continue;
      for (const x of f.excludedHosts ?? []) {
        const h = normalizeHost(x);
        const kind = classifyHost(h);
        if (kind === 'host' || kind === 'entity') e.excluded.add(h);
      }
      if (fresh) st.byWorld[world].set(key, e);
    }
    for (const w of WORLDS) stats.collapsedClicks += collapseClicks(st.byWorld[w]);
  }

  const files: ScriptletFileInfo[] = [];
  const registrations: ScriptletRegistration[] = [];
  const bundles: ScriptletBundle[] = [];
  const merged: ScriptletMerged[] = [];
  const mergedSet = new Set(opts.mergedLists ?? []);
  const perList: Record<string, ScriptletListStats> = Object.fromEntries(states.map((s) => [s.input.listId, s.stats]));
  const hostsSeen = new Map<string, Set<string>>(states.map((s) => [s.input.listId, new Set<string>()]));

  for (const world of WORLDS) {
    // 2) Global key ids and the function table of this world.
    const rep = new Map<string, Entry>();
    for (const st of states) for (const [k, e] of st.byWorld[world]) if (!rep.has(k)) rep.set(k, e);
    if (rep.size === 0) continue;
    const keys = [...rep.keys()].sort(cmp);
    const keyId = new Map(keys.map((k, i) => [k, i]));
    const fnOfLib = new Map<string, number>();
    const fnNames: string[] = [];
    const fnPrio: number[] = [];
    const templateCode: string[] = [];
    const libKeys = new Set<string>();
    const keyFn: number[] = [];
    const keyArgs: string[][] = [];
    let brave = false;
    for (const k of keys) {
      const { lib, args } = rep.get(k)!;
      if (lib.origin === 'brave') brave = true;
      let fi: number;
      if (lib.template) {
        // One specialized copy per argument list; placeholders are replaced by
        // JS-string-escaped arguments, so no runtime code generation is needed.
        const name = `${lib.fnName}_${fnNames.length}`;
        templateCode.push(specializeTemplate(lib.code, args).replace(`function ${lib.fnName}(`, `function ${name}(`));
        fi = fnNames.length;
        fnNames.push(name);
        fnPrio.push(lib.priority);
        keyArgs.push([]);
      } else {
        libKeys.add(lib.key);
        let f = fnOfLib.get(lib.key);
        if (f === undefined) {
          f = fnNames.length;
          fnNames.push(lib.fnName);
          fnPrio.push(lib.priority);
          fnOfLib.set(lib.key, f);
        }
        fi = f;
        keyArgs.push(args);
      }
      keyFn.push(fi);
    }
    const fns = functionClosure(libKeys, resources.functions);
    const core = [
      '(function bastionScriptletCore() {',
      '// Read by uBO helpers (safeSelf, prevent-xhr): no logger, no WAR secret in MV3.',
      'const scriptletGlobals = {};',
      ...fns.filter((f) => isClassDecl(f.code)).map(codeOf),
      `const NAME = ${JSON.stringify(globalName)};`,
      '// Taken before any page script can run.',
      'const toStr = Function.prototype.toString;',
      `const B = { F: [${fnNames.join(', ')}], P: ${JSON.stringify(fnPrio)}, d: [], r: bastionScriptletRun };`,
      'try { Object.defineProperty(self, NAME, { value: B, configurable: true }); } catch (e) {}',
      RUNTIME_RUN,
      '',
      ...fns.filter((f) => !isClassDecl(f.code)).map(codeOf),
      ...templateCode,
      '})();',
      '',
    ].join('\n');
    const end = `self[${JSON.stringify(globalName)}]?.r();\n`;
    if (libKeys.has(CLIPBOARD_SCRIPTLET) && (!core.includes(noticeEvent) || core.includes('background-color:beige'))) {
      throw new Error(`emitScriptlets: ${CLIPBOARD_SCRIPTLET} in the ${world} core is not routed to the Bastion notice`);
    }
    const corePath = CORE_FILE(world);
    const endPath = END_FILE(world);
    const coreCode = await finalizeCode(coreHeader(world, brave) + core, opts.minify === true, corePath);
    const endCode = await finalizeCode(endHeader(world) + end, opts.minify === true, endPath);
    await writeText(join(opts.outDir, ...corePath.split('/')), coreCode);
    await writeText(join(opts.outDir, ...endPath.split('/')), endCode);
    files.push({ path: corePath, kind: 'core', listId: '', world, bytes: Buffer.byteLength(coreCode), hosts: 0, arglists: 0, functions: fns.length + templateCode.length });
    files.push({ path: endPath, kind: 'end', listId: '', world, bytes: Buffer.byteLength(endCode), hosts: 0, arglists: 0, functions: 0 });
    bundles.push({ world, core: corePath, end: endPath });

    // 3) One data file per list with entries or exceptions in this world.
    const keyPayload = keys.map((_, id) => asciiOnly(JSON.stringify([keyFn[id], ...keyArgs[id]])));
    const withData: ListState[] = [];
    for (const st of states) {
      const enc = encodeData([st], world, keyId, keyPayload);
      if (!enc) continue;
      withData.push(st);
      for (const h of enc.hostKeys) hostsSeen.get(st.input.listId)!.add(h);
      st.stats.entries += st.byWorld[world].size;
      st.stats.exceptions += enc.exceptions;
      const path = DATA_FILE(st.input.listId, world);
      const code = dataHeader(st.input.listId, world) + enc.code(globalName, st.input.listId);
      new Script(code, { filename: path });
      await writeText(join(opts.outDir, ...path.split('/')), code);
      const bytes = Buffer.byteLength(code);
      files.push({ path, kind: 'data', listId: st.input.listId, world, bytes, hosts: enc.hosts, arglists: enc.arglists, functions: 0 });
      st.stats.files++;
      st.stats.bytes += bytes;
      registrations.push({ id: `sl-${st.input.listId}-${world.toLowerCase()}`, listId: st.input.listId, world, file: path, matches: ['<all_urls>'] });
    }

    // 4) The merged data of the usual list set: one file and one lookup per
    // frame instead of one per list (used when all of them are enabled).
    const members = withData.filter((st) => mergedSet.has(st.input.listId));
    if (members.length > 1) {
      const enc = encodeData(members, world, keyId, keyPayload)!;
      const ids = members.map((st) => st.input.listId);
      const path = MERGED_FILE(world);
      const code = mergedHeader(ids, world) + enc.code(globalName, ids.join('+'));
      new Script(code, { filename: path });
      await writeText(join(opts.outDir, ...path.split('/')), code);
      files.push({ path, kind: 'merged', listId: '', world, bytes: Buffer.byteLength(code), hosts: enc.hosts, arglists: enc.arglists, functions: 0 });
      merged.push({ world, lists: ids, file: path });
    }
  }
  for (const st of states) st.stats.hosts = hostsSeen.get(st.input.listId)!.size;

  registrations.sort((a, b) => cmp(a.id, b.id));
  const index: ScriptletIndex = { registrations, bundles, merged };
  await writeJson(join(opts.outDir, 'scriptlets', 'index.json'), index, true);
  const byKind = (k: ScriptletFileInfo['kind']) => files.filter((f) => f.kind === k).reduce((a, f) => a + f.bytes, 0);
  log.info(
    `scriptlets: ${bundles.length} bundle(s), ${registrations.length} data files, ${merged.length} merged; core ${(byKind('core') / 1024).toFixed(0)} KB, ` +
      `data ${(byKind('data') / 1024).toFixed(0)} KB, ${Object.values(perList).reduce((a, s) => a + s.collapsedClicks, 0)} duplicate click instance(s) collapsed`,
  );
  return { index, files, perList, globalName, noticeEvent };
}
