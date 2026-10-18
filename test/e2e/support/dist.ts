// Bastion Shield e2e — read-only access to the unpacked build (dist/).
//
// The suite never hard-codes filter content: it reads the shipped rulesets,
// cosmetic shards and scriptlet index and picks test subjects from them, so it
// keeps working when the lists change upstream. Formats are the ones declared
// in src/shared/types.ts and src/compiler/types.ts.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { DnrRule } from '../../../src/compiler/types.ts';
import type {
  BuildMeta,
  BuiltList,
  CosmeticMeta,
  CosmeticShard,
  GenericIndex,
  RuleSourceMap,
  ScriptletIndex,
} from '../../../src/shared/types.ts';
import { RULESET_PARAMS } from '../../../src/shared/constants.ts';
import { shardName } from '../../../src/shared/hash.ts';
import { DIST_DIR } from './paths.ts';

export interface RuleResource {
  id: string;
  enabled: boolean;
  path: string;
}

export interface Manifest {
  manifest_version: number;
  name: string;
  version: string;
  background?: { service_worker?: string; type?: string };
  action?: { default_popup?: string };
  options_page?: string;
  declarative_net_request?: { rule_resources?: RuleResource[] };
  web_accessible_resources?: { resources: string[]; matches?: string[]; use_dynamic_url?: boolean }[];
  [k: string]: unknown;
}

export interface LocatedRule {
  rulesetId: string;
  rule: DnrRule & { id: number };
}

export class Dist {
  readonly dir: string;
  private cache = new Map<string, unknown>();

  constructor(dir: string = DIST_DIR) {
    this.dir = dir;
  }

  file(rel: string): string {
    return path.join(this.dir, ...rel.replace(/^\/+/, '').split('/'));
  }

  has(rel: string): boolean {
    return existsSync(this.file(rel));
  }

  json<T>(rel: string): T {
    const key = 'json:' + rel;
    if (!this.cache.has(key)) this.cache.set(key, JSON.parse(readFileSync(this.file(rel), 'utf8')));
    return this.cache.get(key) as T;
  }

  /** JSON file or `fallback` when it does not exist (optional build outputs). */
  maybeJson<T>(rel: string, fallback: T): T {
    return this.has(rel) ? this.json<T>(rel) : fallback;
  }

  text(rel: string): string {
    return readFileSync(this.file(rel), 'utf8');
  }

  get manifest(): Manifest {
    return this.json<Manifest>('manifest.json');
  }

  get meta(): BuildMeta | null {
    return this.maybeJson<BuildMeta | null>('rulesets/meta.json', null);
  }

  ruleResources(): RuleResource[] {
    return this.manifest.declarative_net_request?.rule_resources ?? [];
  }

  manifestEnabledRulesets(): string[] {
    return this.ruleResources().filter((r) => r.enabled).map((r) => r.id).sort();
  }

  /** Rulesets that should be enabled on a fresh install, derived from the catalog defaults in meta.json. */
  expectedDefaultRulesets(): string[] | null {
    const meta = this.meta;
    if (!meta) return null;
    const declared = new Set(this.ruleResources().map((r) => r.id));
    const out = new Set<string>();
    for (const list of meta.lists) {
      if (!list.default) continue;
      for (const id of list.rulesetIds) if (declared.has(id)) out.add(id);
    }
    // Tracking-parameter stripping is on by default (Settings.privacy.stripParams).
    if (declared.has(RULESET_PARAMS)) out.add(RULESET_PARAMS);
    return [...out].sort();
  }

  rules(rulesetId: string): (DnrRule & { id: number })[] {
    const res = this.ruleResources().find((r) => r.id === rulesetId);
    if (!res) return [];
    return this.maybeJson<(DnrRule & { id: number })[]>(res.path, []);
  }

  filtersOf(rulesetId: string): RuleSourceMap {
    return this.maybeJson<RuleSourceMap>(`rulesets/filters/${rulesetId}.json`, []);
  }

  sourceOf(rulesetId: string, ruleId: number): string[] {
    const m = this.filtersOf(rulesetId);
    return (Array.isArray(m) ? m[ruleId] : null) ?? [];
  }

  list(listId: string): BuiltList | undefined {
    return this.meta?.lists.find((l) => l.id === listId);
  }

  listOfRuleset(rulesetId: string): BuiltList | undefined {
    const listId = this.meta?.rulesetToList?.[rulesetId] ?? rulesetId.replace(/\.regex$/, '');
    return this.list(listId);
  }

  /** Bit mask of lists enabled by default (cosmetic/scriptlet data masks). */
  defaultListMask(): number {
    let mask = 0;
    for (const l of this.meta?.lists ?? []) if (l.default) mask |= 1 << l.bit;
    return mask >>> 0;
  }

  listNamesForMask(mask: number): string[] {
    return (this.meta?.lists ?? []).filter((l) => (mask >>> l.bit) & 1).map((l) => l.id);
  }

  /** Every static rule of every declared ruleset (enabled or not). Cached. */
  allRules(): LocatedRule[] {
    const key = 'allRules';
    if (!this.cache.has(key)) {
      const out: LocatedRule[] = [];
      for (const r of this.ruleResources()) for (const rule of this.rules(r.id)) out.push({ rulesetId: r.id, rule });
      this.cache.set(key, out);
    }
    return this.cache.get(key) as LocatedRule[];
  }

  /** Rules (in default-enabled rulesets) whose request-host part matches `host` or one of its parents. */
  rulesForHost(host: string, enabledOnly = true): LocatedRule[] {
    const enabled = new Set(this.expectedDefaultRulesets() ?? this.manifestEnabledRulesets());
    const parents: string[] = [];
    const labels = host.toLowerCase().split('.');
    for (let i = 0; i < labels.length - 1; i++) parents.push(labels.slice(i).join('.'));
    const out: LocatedRule[] = [];
    for (const lr of this.allRules()) {
      if (enabledOnly && !enabled.has(lr.rulesetId)) continue;
      const c = lr.rule.condition;
      const rd = c.requestDomains;
      if (rd && parents.some((p) => rd.includes(p))) {
        out.push(lr);
        continue;
      }
      const uf = c.urlFilter;
      if (uf && uf.startsWith('||')) {
        const hostPart = uf.slice(2).split(/[\^/*:|?]/)[0].toLowerCase();
        if (parents.includes(hostPart)) out.push(lr);
      }
    }
    return out;
  }

  regexRules(): LocatedRule[] {
    return this.allRules().filter((lr) => typeof lr.rule.condition.regexFilter === 'string');
  }

  cosmeticMeta(): CosmeticMeta | null {
    return this.maybeJson<CosmeticMeta | null>('cosmetic/meta.json', null);
  }

  genericIndex(): GenericIndex {
    return this.maybeJson<GenericIndex>('cosmetic/generic.json', { tokens: {} });
  }

  genericHigh(): Record<string, string[]> {
    return this.maybeJson<Record<string, string[]>>('cosmetic/generic-high.json', {});
  }

  shard(n: number): CosmeticShard {
    return this.maybeJson<CosmeticShard>(`cosmetic/specific/${shardName(n)}.json`, { hosts: {} });
  }

  shardCount(): number {
    const meta = this.cosmeticMeta();
    if (meta?.shards) return meta.shards;
    try {
      return readdirSync(this.file('cosmetic/specific')).filter((f) => f.endsWith('.json')).length;
    } catch {
      return 0;
    }
  }

  scriptletIndex(): ScriptletIndex {
    return this.maybeJson<ScriptletIndex>('scriptlets/index.json', { registrations: [] });
  }

  /** main_frame rules that redirect to pages/blocked.html (hostname-only and pattern-scoped). */
  strictBlockRules(): LocatedRule[] {
    return this.allRules().filter((lr) => {
      const a = lr.rule.action;
      return a.type === 'redirect' && (a.redirect?.extensionPath ?? '').includes('/pages/blocked.html');
    });
  }

  /** Strict-block rules that cover whole hosts (no URL pattern): any navigation there is blocked. */
  strictHostRules(): LocatedRule[] {
    return this.strictBlockRules().filter((lr) => !lr.rule.condition.urlFilter && !lr.rule.condition.regexFilter);
  }

  strictHosts(): Set<string> {
    const key = 'strictHosts';
    if (!this.cache.has(key)) {
      const s = new Set<string>();
      for (const lr of this.strictHostRules()) for (const d of lr.rule.condition.requestDomains ?? []) s.add(d);
      this.cache.set(key, s);
    }
    return this.cache.get(key) as Set<string>;
  }

  /** True when `host` or a parent is a strict-block target (navigating there would show blocked.html). */
  isStrictBlocked(host: string): boolean {
    const s = this.strictHosts();
    const labels = host.toLowerCase().split('.');
    for (let i = 0; i < labels.length - 1; i++) if (s.has(labels.slice(i).join('.'))) return true;
    return false;
  }
}
