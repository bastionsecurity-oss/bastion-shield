// Bastion Shield — writes the cosmetic data of all lists (ARCHITECTURE §5.1):
//
//   dist/cosmetic/specific/NNN.json   CosmeticShard, hostKey -> [kind, payload, listMask]
//   dist/cosmetic/generic.json        GenericIndex (lowly generic, keyed by #id/.class;
//                                     one sorted token per line, searched in place)
//   dist/cosmetic/generic-high/<id>.css + generic-high.json (highly generic;
//                                     the SW registers ONE CSS content script
//                                     listing every enabled list's file)
//   dist/cosmetic/meta.json           CosmeticMeta (per-list exclusions, plus
//                                     the generichide hosts once for all lists)
//
// Entries of identical (hostKey, kind, payload) from several lists merge into
// one entry whose mask has every list's bit, so the service worker filters by
// the enabled-list mask with a single AND.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { join } from 'node:path';
import { domainToASCII } from 'node:url';
import type { CompiledList, SpecificCosmetic } from '../../src/compiler/types.ts';
import type { CosmeticHostEntry, CosmeticMeta, CosmeticShard, GenericIndex, ProceduralFilter } from '../../src/shared/types.ts';
import { COSMETIC_SHARDS } from '../../src/shared/constants.ts';
import { isIpAddress, shardName, shardOf } from '../../src/shared/hash.ts';
import { hideRules, selectorProblem } from './css.ts';
import { writeJson, writeText, type Logger } from './util.ts';

export interface CosmeticListInput {
  listId: string;
  bit: number;
  compiled: Pick<CompiledList, 'specific' | 'generic' | 'genericExceptions' | 'generichideHosts' | 'specifichideHosts'>;
}

export interface CosmeticListStats {
  specificEntries: number;
  specificHosts: number;
  lowGeneric: number;
  highGeneric: number;
  procedural: number;
  rejected: Record<string, number>;
}

export interface CosmeticResult {
  meta: CosmeticMeta;
  perList: Record<string, CosmeticListStats>;
  bytes: { specific: number; generic: number; genericHigh: number; largestShard: number };
  /** Hosts flagged "noscriptlets" (for tools/scriptlets.ts). */
  noScriptletHosts: Map<string, string[]>;
}

type Kind = CosmeticHostEntry[0];

export function normalizeHostKey(h: string): string | null {
  let s = h.trim().toLowerCase();
  if (s.endsWith('.')) s = s.slice(0, -1);
  if (s === '' || s === '*') return null;
  if (/[^\x00-\x7f]/.test(s)) {
    if (s.endsWith('.*')) {
      const a = domainToASCII(s.slice(0, -2));
      if (!a) return null;
      s = `${a}.*`;
    } else {
      const a = domainToASCII(s);
      if (!a) return null;
      s = a;
    }
  }
  if (s.endsWith('.*')) return /^[a-z0-9_-]+(\.[a-z0-9_-]+)*\.\*$/.test(s) ? s : null;
  if (isIpAddress(s)) return /^[0-9a-f.:[\]]+$/.test(s) ? s : null;
  return /^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/.test(s) ? s : null;
}

/** Hostnames that can become `excludeMatches` patterns (no entities, no bare labels). */
const isPatternHost = (h: string) => !h.endsWith('.*') && (h.includes('.') || isIpAddress(h));

/** Payload for the kind-5 exception that cancels a kind-2 procedural entry. */
function proceduralExceptionPayload(payload: string): string | null {
  try {
    const pf = JSON.parse(payload) as ProceduralFilter;
    if (typeof pf.raw !== 'string' || pf.raw === '') return null;
    const i = pf.raw.indexOf('##');
    return i === -1 ? pf.raw : pf.raw.slice(i + 2);
  } catch {
    return null;
  }
}

export async function writeCosmetic(outDir: string, lists: CosmeticListInput[], log: Logger): Promise<CosmeticResult> {
  const dir = join(outDir, 'cosmetic');
  const specific = new Map<string, Map<string, number>>(); // hostKey -> "kind\0payload" -> mask
  const perList: Record<string, CosmeticListStats> = {};
  const noScriptletHosts = new Map<string, string[]>();

  const add = (host: string, kind: Kind, payload: string, mask: number) => {
    let m = specific.get(host);
    if (!m) specific.set(host, (m = new Map()));
    const k = `${kind}\u0000${payload}`;
    m.set(k, ((m.get(k) ?? 0) | mask) >>> 0);
  };

  // Generic exceptions (`#@#sel` without hostname) apply across lists at build time.
  const genericExceptions = new Set<string>();
  for (const l of lists) for (const s of l.compiled.genericExceptions ?? []) genericExceptions.add(s);

  const tokens = new Map<string, Map<string, number>>(); // token -> selector -> mask
  const high = new Map<string, Set<string>>(); // listId -> selectors
  const highExcluded = new Map<string, Set<string>>(); // listId -> hosts
  const allGenerichide = new Set<string>();
  const exceptionHosts = new Map<string, Set<string>>(); // kind-1 selector -> hosts

  for (const l of lists) {
    const mask = (1 << l.bit) >>> 0;
    const st: CosmeticListStats = { specificEntries: 0, specificHosts: 0, lowGeneric: 0, highGeneric: 0, procedural: 0, rejected: {} };
    perList[l.listId] = st;
    const reject = (r: string) => (st.rejected[r] = (st.rejected[r] ?? 0) + 1);
    const hostsSeen = new Set<string>();
    const listHigh = new Set<string>();
    const listHighExcluded = new Set<string>();
    high.set(l.listId, listHigh);
    highExcluded.set(l.listId, listHighExcluded);

    const addSpecific = (s: SpecificCosmetic): boolean => {
      if (s.kind === 0) {
        const p = selectorProblem(s.payload);
        if (p) {
          reject(`css: ${p}`);
          return false;
        }
      }
      const hosts: string[] = [];
      for (const h of s.hosts ?? []) {
        const k = normalizeHostKey(h);
        if (k) hosts.push(k);
        else reject('unsupported hostname in cosmetic filter');
      }
      if (hosts.length === 0) return false;
      for (const h of hosts) {
        add(h, s.kind, s.payload, mask);
        hostsSeen.add(h);
        st.specificEntries++;
        if (s.kind === 1) {
          let e = exceptionHosts.get(s.payload);
          if (!e) exceptionHosts.set(s.payload, (e = new Set()));
          e.add(h);
        }
        if (s.kind === 4 && (s.payload === 'generichide' || s.payload === 'elemhide')) allGenerichide.add(h);
        if (s.kind === 4 && s.payload === 'noscriptlets') {
          let a = noScriptletHosts.get(l.listId);
          if (!a) noScriptletHosts.set(l.listId, (a = []));
          a.push(h);
        }
      }
      if (s.kind === 2) st.procedural++;
      // `a.com,~b.a.com##sel`: the exclusion becomes an exception entry on the excluded host.
      for (const x of s.excludedHosts ?? []) {
        const k = normalizeHostKey(x);
        if (!k) continue;
        if (s.kind === 0 || s.kind === 3) add(k, 1, s.payload, mask);
        else if (s.kind === 2) {
          const p = proceduralExceptionPayload(s.payload);
          if (p) add(k, 5, p, mask);
          else reject('cannot express ~host exclusion of procedural filter');
        }
      }
      return true;
    };
    for (const s of l.compiled.specific ?? []) addSpecific(s);

    // List-level $generichide / $specifichide become flag entries too, so the
    // service worker sees them through the same shard lookup (and the mask).
    for (const h of l.compiled.generichideHosts ?? []) {
      const k = normalizeHostKey(h);
      if (!k) continue;
      add(k, 4, 'generichide', mask);
      allGenerichide.add(k);
    }
    for (const h of l.compiled.specifichideHosts ?? []) {
      const k = normalizeHostKey(h);
      if (k) add(k, 4, 'specifichide', mask);
    }

    for (const g of l.compiled.generic ?? []) {
      const p = selectorProblem(g.selector);
      if (p) {
        reject(`css: ${p}`);
        continue;
      }
      if (genericExceptions.has(g.selector)) {
        reject('removed by generic #@# exception');
        continue;
      }
      if (g.token) {
        let m = tokens.get(g.token);
        if (!m) tokens.set(g.token, (m = new Map()));
        m.set(g.selector, ((m.get(g.selector) ?? 0) | mask) >>> 0);
        st.lowGeneric++;
      } else {
        listHigh.add(g.selector);
      }
      for (const x of g.excludedHosts ?? []) {
        const k = normalizeHostKey(x);
        if (!k) continue;
        add(k, 1, g.selector, mask);
        if (!g.token) listHighExcluded.add(k);
      }
    }
    st.highGeneric = listHigh.size;
    st.specificHosts = hostsSeen.size;
  }

  // --- specific shards ------------------------------------------------------
  const shards: CosmeticShard[] = Array.from({ length: COSMETIC_SHARDS }, () => ({ hosts: {} }));
  for (const host of [...specific.keys()].sort()) {
    const entries: CosmeticHostEntry[] = [...specific.get(host)!.entries()]
      .map(([k, mask]) => {
        const i = k.indexOf('\u0000');
        return [Number(k.slice(0, i)) as Kind, k.slice(i + 1), mask] as CosmeticHostEntry;
      })
      .sort((a, b) => a[0] - b[0] || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
    shards[shardOf(host)].hosts[host] = entries;
  }
  let specificBytes = 0;
  let largestShard = 0;
  for (let i = 0; i < COSMETIC_SHARDS; i++) {
    const text = JSON.stringify(shards[i]) + '\n';
    specificBytes += Buffer.byteLength(text);
    largestShard = Math.max(largestShard, Buffer.byteLength(text));
    await writeText(join(dir, 'specific', `${shardName(i)}.json`), text);
  }

  // --- lowly generic ----------------------------------------------------------
  // GenericIndex as JSON with one token per line, sorted by token (code unit
  // order, as the SW compares): the SW binary-searches the text instead of
  // parsing it (review PERF-5). JSON escapes newlines inside strings, so raw
  // newlines only separate entries.
  const lines: string[] = [];
  for (const t of [...tokens.keys()].sort()) {
    const value: GenericIndex['tokens'][string] = [...tokens.get(t)!.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
    lines.push(`${JSON.stringify(t)}:${JSON.stringify(value)}`);
  }
  const genericText = `{"tokens":{\n${lines.join(',\n')}\n}}\n`;
  await writeText(join(dir, 'generic.json'), genericText);

  // --- highly generic ---------------------------------------------------------
  const meta: CosmeticMeta = {
    shards: COSMETIC_SHARDS,
    genericHighCss: {},
    genericHighExcludedHosts: {},
    genericHideHosts: [],
    genericHighSelectorsFile: 'cosmetic/generic-high.json',
  };
  const highJson: Record<string, string[]> = {};
  let highBytes = 0;
  const droppedEntityExclusions = new Set<string>();
  // Generichide/elemhide hosts are excluded from the (single) generic-high
  // registration for every list: listed once instead of once per list.
  const hideHosts: string[] = [];
  for (const h of allGenerichide) {
    if (isPatternHost(h)) hideHosts.push(h);
    else droppedEntityExclusions.add(h);
  }
  meta.genericHideHosts = hideHosts.sort();
  for (const l of lists) {
    const sels = [...(high.get(l.listId) ?? [])].sort();
    highJson[l.listId] = sels;
    if (sels.length === 0) {
      meta.genericHighCss[l.listId] = null;
    } else {
      const css = hideRules(sels, 1000);
      const path = `cosmetic/generic-high/${l.listId}.css`;
      await writeText(join(outDir, ...path.split('/')), css);
      highBytes += Buffer.byteLength(css);
      meta.genericHighCss[l.listId] = path;
    }
    // Static registration must skip hosts where a highly generic selector of
    // this list is excepted (and genericHideHosts); the SW injects a filtered
    // copy there instead.
    const excl = new Set<string>(highExcluded.get(l.listId) ?? []);
    for (const sel of sels) for (const h of exceptionHosts.get(sel) ?? []) excl.add(h);
    const hosts: string[] = [];
    for (const h of excl) {
      if (allGenerichide.has(h)) continue;
      if (isPatternHost(h)) hosts.push(h);
      else droppedEntityExclusions.add(h);
    }
    meta.genericHighExcludedHosts[l.listId] = sels.length === 0 ? [] : hosts.sort();
  }
  if (droppedEntityExclusions.size) {
    log.info(`cosmetic: ${droppedEntityExclusions.size} entity/bare-label host(s) cannot become excludeMatches patterns (handled by the SW lookup only)`);
  }
  await writeJson(join(dir, 'generic-high.json'), highJson);
  await writeJson(join(dir, 'meta.json'), meta, true);
  return {
    meta,
    perList,
    bytes: { specific: specificBytes, generic: Buffer.byteLength(genericText), genericHigh: highBytes, largestShard },
    noScriptletHosts,
  };
}
