// Bastion Shield — build orchestrator (ARCHITECTURE §11). Turns the catalog
// and vendored resources into a loadable extension in dist/:
//
//   catalog -> fetch (cache) -> preprocess -> $badfilter pre-pass -> compile
//   -> rulesets (+ transparency maps, bastion-params) -> cosmetic data
//   -> scriptlets -> redirect resources -> seeds/config -> meta.json
//   -> manifest.json -> esbuild bundles -> static assets -> report
//
//   node tools/build.ts                # dev build (readable JS, source maps)
//   node tools/build.ts --offline      # lists from .cache/ only
//   node tools/build.ts --release      # minified, consumes a version counter
//   node tools/build.ts --keep-going   # a list that fails to compile ships empty
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { randomInt, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { deflateRawSync } from 'node:zlib';
import type { CompileOptions, CompiledList, CompiledRule, DnrRule, ScriptletFilter } from '../src/compiler/types.ts';
import type { BuildMeta, BuiltList, Catalog, CatalogList, FingerprintLevel, RuleSourceMap } from '../src/shared/types.ts';
import { LIMITS, REGEX_RULESET_SUFFIX, RULESET_PARAMS, SEED_FILES_PER_SET, SEED_SETS } from '../src/shared/constants.ts';
import { computeRegistrations, registrationStats } from '../src/background/registrations.ts';
import { normalizeSettings } from '../src/background/settings.ts';
import { fetchLists, loadCatalog, type FetchedList } from './fetch-lists.ts';
import { loadResources, WAR_PREFIX, type ResourceSet } from './resources.ts';
import { emitScriptlets, type EmitScriptletsResult } from './scriptlets.ts';
import { NOTICE_EVENT_DEFINE } from './lib/notice-transform.ts';
import { loadUnsupportedRegexes, regexKey } from './validate-dist.ts';
import { vendor, vendorPresent } from './vendor.ts';
import { bundle, copyStatic, type BundleResult } from './lib/bundle.ts';
import { shipped } from './package.ts';
import { writeCosmetic, type CosmeticResult } from './lib/cosmetic.ts';
import { orderRule, sanitizeRule } from './lib/dnr.ts';
import { buildParamsRuleset, type QueryFilterEntry } from './lib/params.ts';
import { commitBuildCounter, computeVersion, type VersionInfo } from './lib/version.ts';
import {
  ROOT,
  color,
  copyInto,
  createLogger,
  fileExists,
  formatBytes,
  formatInt,
  isMain,
  jsonLines,
  parseArgs,
  readJson,
  rel,
  rmrf,
  renderTable,
  walkFiles,
  writeJson,
  writeText,
  type Logger,
} from './lib/util.ts';

export const DIST = join(ROOT, 'dist');
const BLOCKED_PAGE = '/pages/blocked.html';
const MAX_SOURCES_PER_RULE = 20;
/**
 * Content-script budget for the default configuration (review PERF-1/PERF-2):
 * Chrome matches every registered pattern in every frame and keeps the parsed
 * patterns in every renderer, so the set must stay small and bounded.
 */
export const REGISTRATION_BUDGET = { patterns: 2500, registrations: 30 } as const;
/** Lists whose modifier rules are too many to duplicate for first parties (CompileOptions.modifiers1p). */
const NO_MODIFIERS_1P = new Set(['url-tracking']);

export interface BuildOptions {
  offline?: boolean;
  release?: boolean;
  keepGoing?: boolean;
  outDir?: string;
  /** Skip esbuild + static copies (data-only builds for tests). */
  skipBundle?: boolean;
  log?: Logger;
}

// ---------------------------------------------------------------------------
// Compiler module (src/compiler/index.ts, or BASTION_COMPILER for testing)
// ---------------------------------------------------------------------------

interface CompilerModule {
  DEFAULT_ENV: ReadonlySet<string> | readonly string[];
  preprocess(text: string, env: ReadonlySet<string>, resolveInclude?: (path: string) => string | null): unknown;
  collectBadfilters(texts: string[], opts?: unknown): Iterable<string>;
  compileList(text: string, opts: CompileOptions): CompiledList;
  /** src/compiler/copies.ts: keeps only the protected-list redirect copies an always-apply block can meet. */
  restrictRedirectCopies?(lists: { firstPartyProtected: boolean; compiled: CompiledList }[]): { copies: number; kept: number };
}

async function loadCompiler(log: Logger): Promise<{ mod: CompilerModule; env: ReadonlySet<string>; path: string }> {
  const path = process.env.BASTION_COMPILER ? resolve(process.env.BASTION_COMPILER) : join(ROOT, 'src', 'compiler', 'index.ts');
  if (!(await fileExists(path))) {
    throw new Error(`filter compiler not found at ${rel(path)} (set BASTION_COMPILER to use another module)`);
  }
  const mod = (await import(pathToFileURL(path).href)) as Partial<CompilerModule>;
  for (const k of ['preprocess', 'collectBadfilters', 'compileList'] as const) {
    if (typeof mod[k] !== 'function') throw new Error(`${rel(path)} does not export ${k}()`);
  }
  const env = mod.DEFAULT_ENV instanceof Set ? mod.DEFAULT_ENV : new Set<string>(Array.isArray(mod.DEFAULT_ENV) ? mod.DEFAULT_ENV : []);
  if (env.size === 0) log.warn('compiler DEFAULT_ENV is empty: every !#if block evaluates false');
  if (process.env.BASTION_COMPILER) log.warn(`using compiler module ${rel(path)} (BASTION_COMPILER)`);
  return { mod: mod as CompilerModule, env, path };
}

function preprocessed(mod: CompilerModule, text: string, env: ReadonlySet<string>): string {
  const r = mod.preprocess(text, env);
  if (typeof r === 'string') return r;
  if (r && typeof (r as { text?: unknown }).text === 'string') return (r as { text: string }).text;
  if (Array.isArray(r)) return r.join('\n');
  throw new Error('preprocess() returned an unexpected value');
}

/** Fill defaults so a partial CompiledList never crashes the later stages. */
function normalizeCompiled(listId: string, c: Partial<CompiledList> | undefined): CompiledList {
  const stats = c?.stats;
  return {
    listId,
    rules: c?.rules ?? [],
    regexRules: c?.regexRules ?? [],
    specific: c?.specific ?? [],
    generic: c?.generic ?? [],
    genericExceptions: c?.genericExceptions ?? [],
    scriptlets: c?.scriptlets ?? [],
    generichideHosts: c?.generichideHosts ?? [],
    specifichideHosts: c?.specifichideHosts ?? [],
    usedRedirectResources: c?.usedRedirectResources ?? [],
    stats: {
      lines: stats?.lines ?? 0,
      filters: stats?.filters ?? 0,
      network: stats?.network ?? 0,
      cosmetic: stats?.cosmetic ?? 0,
      scriptlets: stats?.scriptlets ?? 0,
      unsupported: stats?.unsupported ?? 0,
      badfiltered: stats?.badfiltered ?? 0,
      rejected: stats?.rejected ?? [],
      reasons: stats?.reasons ?? {},
    },
  };
}

/** Hosts-format lines -> `||host^`, for lists that mix hosts and ABP sources. */
function hostsToAbp(text: string): string {
  const out: string[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    const host = parts.length >= 2 && /^(0\.0\.0\.0|127\.0\.0\.1|::1?|::)$/.test(parts[0]) ? parts[1] : parts.length === 1 ? parts[0] : '';
    if (!host || host === 'localhost' || host === '0.0.0.0' || !host.includes('.')) continue;
    out.push(`||${host.toLowerCase()}^`);
  }
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// Rulesets
// ---------------------------------------------------------------------------

interface RulesetOutput {
  id: string;
  listId: string;
  rules: DnrRule[];
  sources: RuleSourceMap;
  invalid: Record<string, number>;
  invalidSamples: { filter: string; reason: string }[];
  redirectPaths: Set<string>;
}

function finalizeRuleset(
  id: string,
  listId: string,
  compiled: CompiledRule[],
  allowRegex: boolean,
  resources: ResourceSet,
  unsupportedRegex: ReadonlyMap<string, string> = new Map(),
): RulesetOutput {
  const out: RulesetOutput = { id, listId, rules: [], sources: [null], invalid: {}, invalidSamples: [], redirectPaths: new Set() };
  // Identical rules (after normalization) merge their source filters.
  const byJson = new Map<string, number>();
  const counts: number[] = [];
  for (const cr of compiled) {
    const r = sanitizeRule(cr.rule, { allowRegex });
    let error = r.error;
    const path = r.rule?.action.redirect?.extensionPath;
    if (!error && path !== undefined && path.startsWith(WAR_PREFIX) && !resources.redirectByPath.has(path.split(/[?#]/)[0])) {
      error = `redirect target ${path} is not shipped`;
    }
    const re = r.rule?.condition.regexFilter;
    if (!error && re !== undefined) {
      const why = unsupportedRegex.get(regexKey(re, r.rule!.condition.isUrlFilterCaseSensitive === true));
      if (why) error = `regex rejected by Chromium (${why})`;
    }
    if (error || !r.rule) {
      const reason = error ?? 'invalid rule';
      out.invalid[reason] = (out.invalid[reason] ?? 0) + 1;
      if (out.invalidSamples.length < 50) out.invalidSamples.push({ filter: cr.sources?.[0] ?? JSON.stringify(cr.rule), reason });
      continue;
    }
    const rule = r.rule;
    delete rule.id;
    const key = JSON.stringify(rule);
    const prev = byJson.get(key);
    const srcs = Array.isArray(cr.sources) ? cr.sources.filter((s) => typeof s === 'string') : [];
    const n = Math.max(cr.sourceCount ?? srcs.length, srcs.length);
    if (prev !== undefined) {
      const list = out.sources[prev + 1]!;
      for (const s of srcs) if (list.length < MAX_SOURCES_PER_RULE && !list.includes(s)) list.push(s);
      counts[prev] += n;
      continue;
    }
    byJson.set(key, out.rules.length);
    out.rules.push(rule);
    out.sources.push(srcs.slice(0, MAX_SOURCES_PER_RULE));
    counts.push(n);
    if (path?.startsWith(WAR_PREFIX)) out.redirectPaths.add(path.split(/[?#]/)[0]);
  }
  // Dense ids from 1; the transparency map is indexed by id.
  out.rules = out.rules.map((rule, i) => orderRule({ ...rule, id: i + 1 }));
  for (let i = 0; i < counts.length; i++) {
    const list = out.sources[i + 1]!;
    const more = counts[i] - list.length;
    if (more > 0) list.push(`+${more} more`);
  }
  return out;
}

async function writeRuleset(outDir: string, rs: { id: string; rules: DnrRule[]; sources: RuleSourceMap }): Promise<number> {
  const text = jsonLines(rs.rules);
  await writeText(join(outDir, 'rulesets', 'net', `${rs.id}.json`), text);
  await writeText(join(outDir, 'rulesets', 'filters', `${rs.id}.json`), jsonLines(rs.sources));
  return Buffer.byteLength(text);
}

/** ARCHITECTURE §4.1 manifest order. */
const CORE_ORDER = ['ublock', 'easylist', 'easyprivacy', 'ublock-privacy', 'brave', 'brave-firstparty', 'peter-lowe'];

export function rulesetOrder(lists: CatalogList[]): CatalogList[] {
  const rank = (l: CatalogList): [number, number] => {
    if (l.id === 'bastion') return [0, 0];
    if (l.category === 'security') return [1, 0];
    const core = CORE_ORDER.indexOf(l.id);
    if (core !== -1) return [2, core];
    if (l.category === 'regional') return [4, 0];
    if (l.category === 'annoyances') return [5, 0];
    return [3, 0]; // other ads/privacy lists after the core set
  };
  return lists
    .map((l, i) => ({ l, i, r: rank(l) }))
    .sort((a, b) => a.r[0] - b.r[0] || a.r[1] - b.r[1] || a.i - b.i)
    .map((x) => x.l);
}

// ---------------------------------------------------------------------------
// Seeds and config files (ARCHITECTURE §9)
// ---------------------------------------------------------------------------

async function writeSeedsAndConfig(outDir: string): Promise<void> {
  for (let set = 0; set < SEED_SETS; set++) {
    for (let n = 0; n < SEED_FILES_PER_SET; n++) {
      const word = randomInt(0, 2 ** 32);
      await writeText(join(outDir, 'main', 'seeds', `s${set}-${n}.js`), `(self.__bastionSeeds||(self.__bastionSeeds=[]))[${set}]=${word};`);
    }
  }
  const levels: FingerprintLevel[] = ['off', 'standard', 'strict'];
  for (const level of levels) {
    for (const gpc of [0, 1]) {
      await writeText(join(outDir, 'main', `cfg-${level}-gpc${gpc}.js`), `self.__bastionCfg={fp:"${level}",gpc:${gpc === 1}};`);
    }
  }
}

// ---------------------------------------------------------------------------
// Manifest (ARCHITECTURE §12)
// ---------------------------------------------------------------------------

interface ManifestRuleResource {
  id: string;
  enabled: boolean;
  path: string;
}

async function writeManifest(
  outDir: string,
  version: VersionInfo,
  ruleResources: ManifestRuleResource[],
  warResources: string[],
  log: Logger,
): Promise<Record<string, unknown>> {
  const base = await readJson<Record<string, unknown>>(join(ROOT, 'src', 'manifest.base.json'));
  const manifest: Record<string, unknown> = { ...base };
  manifest.version = version.version;
  if (version.versionName) manifest.version_name = version.versionName;
  else delete manifest.version_name;
  manifest.declarative_net_request = { rule_resources: ruleResources };
  manifest.web_accessible_resources = [
    {
      resources: warResources,
      matches: ['<all_urls>'],
      use_dynamic_url: true,
    },
  ];
  const enabled = ruleResources.filter((r) => r.enabled).length;
  if (ruleResources.length > LIMITS.MAX_STATIC_RULESETS) throw new Error(`${ruleResources.length} static rulesets declared (max ${LIMITS.MAX_STATIC_RULESETS})`);
  if (enabled > LIMITS.MAX_ENABLED_STATIC_RULESETS) throw new Error(`${enabled} static rulesets enabled (max ${LIMITS.MAX_ENABLED_STATIC_RULESETS})`);
  // Every file the manifest points at must exist, or Chrome refuses to load.
  const referenced: string[] = [];
  const icons = manifest.icons as Record<string, string> | undefined;
  if (icons) referenced.push(...Object.values(icons));
  const action = manifest.action as { default_icon?: Record<string, string> } | undefined;
  if (action?.default_icon) referenced.push(...Object.values(action.default_icon));
  for (const r of ruleResources) referenced.push(r.path);
  for (const p of referenced) {
    if (!(await fileExists(join(outDir, ...p.split('/'))))) log.warn(`manifest references missing file ${p}`);
  }
  await writeJson(join(outDir, 'manifest.json'), manifest, true);
  return manifest;
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

async function packageSize(outDir: string): Promise<{ files: number; bytes: number; zipEstimate: number }> {
  let bytes = 0;
  let zip = 0;
  let files = 0;
  for (const f of await walkFiles(outDir)) {
    const r = rel(f, outDir);
    if (!shipped(r)) continue;
    const buf = await readFile(f);
    files++;
    bytes += buf.length;
    zip += Math.min(buf.length, deflateRawSync(buf, { level: 9 }).length) + 76 + 2 * Buffer.byteLength(r);
  }
  return { files, bytes, zipEstimate: zip + 22 };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export async function build(opts: BuildOptions = {}): Promise<{ meta: BuildMeta; report: Record<string, unknown> }> {
  const log = opts.log ?? createLogger('build');
  const outDir = opts.outDir ?? DIST;
  const release = opts.release === true;
  const t0 = Date.now();
  const timings: Record<string, number> = {};
  let tPhase = Date.now();
  const phase = (name: string) => {
    timings[name] = Date.now() - tPhase;
    tPhase = Date.now();
  };

  const catalog: Catalog = await loadCatalog();
  if (catalog.lists.length > 32) throw new Error(`catalog has ${catalog.lists.length} lists; list masks support at most 32`);
  const vendorPins = await readJson<Record<string, { commit?: string }>>(join(ROOT, 'vendor', 'VENDOR.json')).catch(() => ({}) as Record<string, { commit?: string }>);
  const version = await computeVersion({ release });
  log.step(`Bastion Shield ${version.version}${release ? ' (release)' : ' (dev)'} -> ${rel(outDir) || outDir}`);

  // 1. Resources from vendor/ (re-vendored from the pinned commits if missing).
  if (!(await vendorPresent())) {
    if (opts.offline) throw new Error('vendor/ is incomplete and --offline was given; run "node tools/vendor.ts"');
    log.warn('vendor/ is incomplete: fetching the commits pinned in vendor/VENDOR.json');
    await vendor({ mode: 'write', log });
  }
  const resources = await loadResources(log);
  log.info(`resources: ${resources.redirectByPath.size} redirect files, ${resources.scriptlets.size} scriptlets`);
  phase('resources');

  // 2. Lists. The trust secret wraps untrusted sources of trusted lists in
  // `!#trusted off/on <secret>`; it never leaves this process.
  const fetched = await fetchLists({ offline: opts.offline, catalog, log, trustSecret: randomUUID() });
  // The markers in the fetched texts use exactly this secret.
  const trustSecret = fetched.trustSecret;
  const fetchedById = new Map<string, FetchedList>(fetched.lists.map((l) => [l.listId, l]));
  phase('fetch');

  // 3. Compile.
  const compiler = await loadCompiler(log);
  log.step(`Compiling ${catalog.lists.length} lists`);
  const texts = new Map<string, { text: string; format: 'abp' | 'hosts' }>();
  for (const l of catalog.lists) {
    const f = fetchedById.get(l.id)!;
    if (f.format === 'hosts') {
      texts.set(l.id, { text: f.text, format: 'hosts' });
      continue;
    }
    const raw = f.format === 'mixed'
      ? f.parts.map((p) => `! --- source: ${p.url}\n${p.format === 'hosts' ? hostsToAbp(p.text) : p.text}`).join('\n')
      : f.text;
    texts.set(l.id, { text: preprocessed(compiler.mod, raw, compiler.env), format: 'abp' });
  }
  const badfilters = new Set<string>(compiler.mod.collectBadfilters([...texts.values()].filter((t) => t.format === 'abp').map((t) => t.text)));
  log.info(`$badfilter pre-pass: ${badfilters.size} filter(s) cancelled across lists`);
  const compiled = new Map<string, CompiledList>();
  const compileErrors: Record<string, string> = {};
  for (const l of catalog.lists) {
    const t = texts.get(l.id)!;
    const c0 = Date.now();
    try {
      const c = compiler.mod.compileList(t.text, {
        listId: l.id,
        trusted: l.trusted,
        firstPartyProtected: l.firstPartyProtected,
        modifiers1p: l.firstPartyProtected === false && !NO_MODIFIERS_1P.has(l.id),
        trustSecret,
        strictBlock: l.strictBlock,
        env: compiler.env,
        redirectResources: resources.redirectMap,
        scriptlets: resources.scriptletMap,
        badfilters,
        blockedPagePath: BLOCKED_PAGE,
        format: t.format,
      });
      compiled.set(l.id, normalizeCompiled(l.id, c));
      log.info(`${l.id.padEnd(18)} compiled in ${Date.now() - c0} ms`);
    } catch (e) {
      const msg = (e as Error).stack ?? String(e);
      if (!opts.keepGoing) throw new Error(`compileList failed for ${l.id}: ${msg}`);
      compileErrors[l.id] = (e as Error).message;
      log.error(`compileList failed for ${l.id} (shipping it empty, --keep-going): ${(e as Error).message}`);
      compiled.set(l.id, normalizeCompiled(l.id, undefined));
    }
  }
  // 3b. Third-party copies of protected-list redirects (PRIORITY.REDIRECT_ALWAYS):
  // keep only those an always-apply block can meet (ARCHITECTURE §4.2). Every
  // catalog list takes part, including optional always-apply lists.
  let redirectCopies: { copies: number; kept: number } | null = null;
  if (typeof compiler.mod.restrictRedirectCopies === 'function') {
    redirectCopies = compiler.mod.restrictRedirectCopies(
      catalog.lists.map((l) => ({ firstPartyProtected: l.firstPartyProtected, compiled: compiled.get(l.id)! })),
    );
    log.info(`${redirectCopies.kept}/${redirectCopies.copies} redirect copies kept`);
  } else {
    log.warn('compiler does not export restrictRedirectCopies(): every protected-list redirect copy ships');
  }
  phase('compile');

  // 4. Fresh output directory.
  await rmrf(outDir);

  // 5. Rulesets.
  log.step('Writing rulesets');
  const ordered = rulesetOrder(catalog.lists);
  const bits = new Map(catalog.lists.map((l, i) => [l.id, i]));
  const mainRs = new Map<string, RulesetOutput>();
  const regexRs = new Map<string, RulesetOutput>();
  const usedRedirects = new Set<string>();
  // Written by tools/validate-dist.ts from Chromium's isRegexSupported().
  const unsupportedRegex = await loadUnsupportedRegexes();
  if (unsupportedRegex.size) log.info(`dropping regexes Chromium rejects: ${unsupportedRegex.size} known (.cache/regex-unsupported.json)`);
  for (const l of catalog.lists) {
    const c = compiled.get(l.id)!;
    const main = finalizeRuleset(l.id, l.id, c.rules, false, resources);
    mainRs.set(l.id, main);
    await writeRuleset(outDir, main);
    for (const p of main.redirectPaths) usedRedirects.add(p);
    if (c.regexRules.length) {
      const rx = finalizeRuleset(l.id + REGEX_RULESET_SUFFIX, l.id, c.regexRules, true, resources, unsupportedRegex);
      if (rx.rules.length) {
        regexRs.set(l.id, rx);
        await writeRuleset(outDir, rx);
        for (const p of rx.redirectPaths) usedRedirects.add(p);
      }
    }
    for (const p of c.usedRedirectResources) {
      const clean = p.split(/[?#]/)[0];
      if (resources.redirectByPath.has(clean)) usedRedirects.add(clean);
    }
  }
  const queryFilter = await readJson<QueryFilterEntry[]>(join(ROOT, 'vendor', 'brave-lists', 'query-filter.json'));
  const params = buildParamsRuleset(queryFilter);
  for (const w of params.warnings) log.warn(w);
  const paramsRules: DnrRule[] = [];
  const paramsSources: RuleSourceMap = [null];
  params.rules.forEach((r, i) => {
    const s = sanitizeRule(r, { allowRegex: false });
    if (!s.rule) throw new Error(`bastion-params rule invalid: ${s.error}`);
    paramsRules.push(orderRule({ ...s.rule, id: paramsRules.length + 1 }));
    paramsSources.push(params.sources[i]);
  });
  await writeRuleset(outDir, { id: RULESET_PARAMS, rules: paramsRules, sources: paramsSources });
  phase('rulesets');

  // 6. Cosmetic.
  log.step('Writing cosmetic data');
  const cosmetic: CosmeticResult = await writeCosmetic(
    outDir,
    catalog.lists.map((l) => ({ listId: l.id, bit: bits.get(l.id)!, compiled: compiled.get(l.id)! })),
    log,
  );
  phase('cosmetic');

  // 7. Scriptlets.
  log.step('Writing scriptlets');
  const scriptlets: EmitScriptletsResult = await emitScriptlets({
    outDir,
    resources,
    minify: release,
    log,
    // Lists on for everyone by default (regional lists depend on the UI language).
    mergedLists: catalog.lists.filter((l) => l.default && !(l.langs && l.langs.length > 0)).map((l) => l.id),
    lists: catalog.lists.map((l) => ({
      listId: l.id,
      trusted: l.trusted,
      scriptlets: compiled.get(l.id)!.scriptlets as ScriptletFilter[],
      noScriptletHosts: cosmetic.noScriptletHosts.get(l.id),
    })),
  });
  phase('scriptlets');

  // 7b. Content-script budget of the default configuration (and, for the
  // report, with every list enabled).
  const contentScripts = registrationBudget(catalog, cosmetic, scriptlets);
  const cs = contentScripts.default;
  log.info(
    `content scripts (default lists): ${cs.registrations} registrations, ${formatInt(cs.patterns)} patterns; ` +
      `always-injected scriptlets: MAIN ${formatBytes(contentScripts.scriptletBytes.MAIN)}, ISOLATED ${formatBytes(contentScripts.scriptletBytes.ISOLATED)}`,
  );
  if (cs.patterns >= REGISTRATION_BUDGET.patterns || cs.registrations >= REGISTRATION_BUDGET.registrations) {
    const msg =
      `content-script budget exceeded for the default configuration: ${cs.registrations} registrations (max ${REGISTRATION_BUDGET.registrations - 1}), ` +
      `${cs.patterns} match+exclude patterns (max ${REGISTRATION_BUDGET.patterns - 1}); every frame pays for each pattern`;
    if (!opts.keepGoing) throw new Error(msg);
    log.error(msg);
  }

  // 8. Redirect resources actually used.
  const warFiles: string[] = [];
  for (const p of [...usedRedirects].sort()) {
    const r = resources.redirectByPath.get(p)!;
    await copyInto(r.sourceFile, join(outDir, ...p.slice(1).split('/')));
    warFiles.push(p.slice(1));
  }
  const redirectNames: Record<string, string> = {};
  for (const [name, v] of [...resources.redirectMap.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    if (usedRedirects.has(v.path)) redirectNames[name] = v.path;
  }
  phase('war');

  // 9. Seeds, config files.
  await writeSeedsAndConfig(outDir);

  // 10. meta.json.
  const lockByList = new Map<string, BuiltList['sources']>();
  for (const s of fetched.lock.sources) {
    let a = lockByList.get(s.list);
    if (!a) lockByList.set(s.list, (a = []));
    a.push({ url: s.url, sha256: s.sha256, bytes: s.bytes, version: s.version, lastModified: s.lastModified });
  }
  const builtLists: BuiltList[] = catalog.lists.map((l) => {
    const c = compiled.get(l.id)!;
    const rx = regexRs.get(l.id);
    const { sources: _sources, ...rest } = l;
    void _sources;
    return {
      ...rest,
      bit: bits.get(l.id)!,
      sources: lockByList.get(l.id) ?? [],
      rulesetIds: rx ? [l.id, rx.id] : [l.id],
      ruleCount: mainRs.get(l.id)!.rules.length,
      regexRuleCount: rx?.rules.length ?? 0,
      stats: {
        filters: c.stats.filters,
        network: c.stats.network,
        cosmetic: c.stats.cosmetic,
        scriptlets: c.stats.scriptlets,
        unsupported: c.stats.unsupported,
        badfiltered: c.stats.badfiltered,
      },
    };
  });
  const rulesetToList: Record<string, string> = { [RULESET_PARAMS]: RULESET_PARAMS };
  for (const l of catalog.lists) {
    rulesetToList[l.id] = l.id;
    const rx = regexRs.get(l.id);
    if (rx) rulesetToList[rx.id] = l.id;
  }
  const meta: BuildMeta = {
    builtAt: new Date().toISOString(),
    extensionVersion: version.version,
    lists: builtLists,
    rulesetToList,
    redirectResources: redirectNames,
    vendor: {
      ublock: vendorPins.ublock?.commit ?? 'unknown',
      braveResources: vendorPins.braveResources?.commit ?? 'unknown',
      braveLists: vendorPins.braveLists?.commit ?? 'unknown',
    },
  };
  await writeJson(join(outDir, 'rulesets', 'meta.json'), meta, true);
  // 10b. SHA-256 of every file under rulesets/ for the dashboard's self-check (nerd-mode Lab).
  await (await import('./integrity.ts')).writeIntegrity(outDir, meta.builtAt);

  // 11. Manifest.
  const ruleResources: ManifestRuleResource[] = [];
  for (const l of ordered) ruleResources.push({ id: l.id, enabled: l.default, path: `rulesets/net/${l.id}.json` });
  ruleResources.push({ id: RULESET_PARAMS, enabled: true, path: `rulesets/net/${RULESET_PARAMS}.json` });
  for (const l of ordered) {
    const rx = regexRs.get(l.id);
    if (rx) ruleResources.push({ id: rx.id, enabled: l.default, path: `rulesets/net/${rx.id}.json` });
  }
  const war = [...warFiles, 'pages/blocked.html', 'pages/bounce.html'];

  // 12. Bundles and static assets.
  let bundled: BundleResult = { built: [], missing: [], failed: [] };
  if (!opts.skipBundle) {
    log.step('Bundling');
    // The scriptlet core and cosmetic.js share the per-build notice event name (tools/lib/notice-transform.ts).
    bundled = await bundle(outDir, { release, log, define: { [NOTICE_EVENT_DEFINE]: JSON.stringify(scriptlets.noticeEvent) } });
    if (bundled.failed.length && !opts.keepGoing) {
      throw new Error(`esbuild failed for ${bundled.failed.map((f) => f.src).join(', ')}`);
    }
    await copyStatic(outDir, log);
    phase('bundle');
  }
  await writeManifest(outDir, version, ruleResources, war, log);

  // 13. Report.
  const enabledLists = catalog.lists.filter((l) => l.default);
  const staticEnabled =
    enabledLists.reduce((a, l) => a + mainRs.get(l.id)!.rules.length + (regexRs.get(l.id)?.rules.length ?? 0), 0) + paramsRules.length;
  const staticAll = catalog.lists.reduce((a, l) => a + mainRs.get(l.id)!.rules.length + (regexRs.get(l.id)?.rules.length ?? 0), 0) + paramsRules.length;
  const regexEnabled = enabledLists.reduce((a, l) => a + (regexRs.get(l.id)?.rules.length ?? 0), 0);
  const regexAll = catalog.lists.reduce((a, l) => a + (regexRs.get(l.id)?.rules.length ?? 0), 0);
  // Simulate Chrome's greedy regex budget in manifest order (ARCHITECTURE §3).
  const skippedRegexRulesets: string[] = [];
  {
    let used = 0;
    for (const r of ruleResources) {
      if (!r.enabled || !r.id.endsWith(REGEX_RULESET_SUFFIX)) continue;
      const n = regexRs.get(r.id.slice(0, -REGEX_RULESET_SUFFIX.length))!.rules.length;
      if (used + n > LIMITS.MAX_STATIC_REGEX_RULES) skippedRegexRulesets.push(r.id);
      else used += n;
    }
  }
  const size = await packageSize(outDir);
  const reasons: Record<string, number> = {};
  for (const c of compiled.values()) for (const [k, v] of Object.entries(c.stats.reasons)) reasons[k] = (reasons[k] ?? 0) + v;
  const listReport = catalog.lists.map((l) => {
    const c = compiled.get(l.id)!;
    const m = mainRs.get(l.id)!;
    const rx = regexRs.get(l.id);
    const cs = cosmetic.perList[l.id];
    const ss = scriptlets.perList[l.id];
    return {
      id: l.id,
      enabled: l.default,
      bit: bits.get(l.id),
      sourceBytes: fetchedById.get(l.id)!.sources.reduce((a, s) => a + s.bytes, 0),
      filters: c.stats.filters,
      rules: m.rules.length,
      regexRules: rx?.rules.length ?? 0,
      invalidRules: { ...m.invalid, ...Object.fromEntries(Object.entries(rx?.invalid ?? {}).map(([k, v]) => [`regex: ${k}`, v])) },
      invalidSamples: [...m.invalidSamples, ...(rx?.invalidSamples ?? [])].slice(0, 20),
      cosmetic: cs,
      scriptlets: ss,
      unsupported: c.stats.unsupported,
      badfiltered: c.stats.badfiltered,
      reasons: c.stats.reasons,
      rejectedSamples: c.stats.rejected.slice(0, 30),
      compileError: compileErrors[l.id],
    };
  });
  const report = {
    version: version.version,
    release,
    builtAt: meta.builtAt,
    durationMs: Date.now() - t0,
    timings,
    compiler: rel(compiler.path),
    budgets: {
      staticRulesEnabled: staticEnabled,
      staticRulesAll: staticAll,
      guaranteedStaticRules: LIMITS.GUARANTEED_STATIC_RULES,
      regexRulesEnabled: regexEnabled,
      regexRulesAll: regexAll,
      maxStaticRegexRules: LIMITS.MAX_STATIC_REGEX_RULES,
      skippedRegexRulesets,
      rulesetsDeclared: ruleResources.length,
      rulesetsEnabled: ruleResources.filter((r) => r.enabled).length,
    },
    params: { rules: paramsRules.length },
    redirectCopies,
    cosmeticBytes: cosmetic.bytes,
    scriptletFiles: scriptlets.files.length,
    scriptletDataFiles: scriptlets.index.registrations.length,
    scriptletBundles: scriptlets.index.bundles?.length ?? 0,
    largestScriptletFiles: [...scriptlets.files].sort((a, b) => b.bytes - a.bytes).slice(0, 10),
    contentScripts,
    redirectResources: warFiles,
    bundles: bundled,
    package: size,
    topUnsupportedReasons: Object.entries(reasons).sort((a, b) => b[1] - a[1]).slice(0, 40),
    skippedBraveResources: resources.skipped,
    warnings: log.warnings,
    lists: listReport,
  };
  await writeJson(join(outDir, 'build-report.json'), report, true);
  if (release) await commitBuildCounter(version);
  phase('report');

  printReport(report, listReport, log);
  return { meta, report };
}

/**
 * Registrations the service worker computes on a fresh install (default
 * settings, default lists, no per-site settings), and with every list on.
 */
function registrationBudget(catalog: Catalog, cosmetic: CosmeticResult, scriptlets: EmitScriptletsResult) {
  const settings = normalizeSettings({});
  const seedFiles = Array.from({ length: SEED_SETS }, (_, set) => `main/seeds/s${set}-0.js`);
  const plan = (ids: Set<string>) =>
    computeRegistrations({ settings, sites: {}, enabledListIds: ids, cosmeticMeta: cosmetic.meta, scriptletIndex: scriptlets.index, seedFiles });
  const defaults = new Set(catalog.lists.filter((l) => l.default).map((l) => l.id));
  const desired = plan(defaults);
  const scriptletBytes = { MAIN: 0, ISOLATED: 0 };
  const size = new Map(scriptlets.files.map((f) => [f.path, f.bytes]));
  for (const d of desired) {
    if (!d.id.startsWith('sl-') || !d.js) continue;
    scriptletBytes[d.world] += d.js.reduce((a, f) => a + (size.get(f) ?? 0), 0);
  }
  return {
    budget: REGISTRATION_BUDGET,
    default: registrationStats(desired),
    all: registrationStats(plan(new Set(catalog.lists.map((l) => l.id)))),
    ids: desired.map((d) => d.id),
    /** Bytes of the scriptlet files injected into every frame, per world (default lists). */
    scriptletBytes,
  };
}

function printReport(report: Record<string, unknown>, lists: Record<string, unknown>[], log: Logger): void {
  type L = {
    id: string;
    enabled: boolean;
    rules: number;
    regexRules: number;
    cosmetic: { specificEntries: number; lowGeneric: number; highGeneric: number; rejected: Record<string, number> };
    scriptlets?: { entries: number; rejected: Record<string, number> };
    unsupported: number;
    invalidRules: Record<string, number>;
  };
  const rows = (lists as unknown as L[]).map((l) => {
    const invalid = Object.values(l.invalidRules).reduce((a, b) => a + b, 0);
    // Selectors removed by a generic #@# exception are intended, not dropped.
    const cssRejected = Object.entries(l.cosmetic?.rejected ?? {})
      .filter(([k]) => !k.startsWith('removed by generic'))
      .reduce((a, [, b]) => a + b, 0);
    const slRejected = Object.values(l.scriptlets?.rejected ?? {}).reduce((a, b) => a + b, 0);
    return [
      l.id,
      l.enabled ? 'on' : 'off',
      l.rules,
      l.regexRules,
      l.cosmetic ? l.cosmetic.specificEntries : 0,
      l.cosmetic ? l.cosmetic.lowGeneric + l.cosmetic.highGeneric : 0,
      l.scriptlets?.entries ?? 0,
      l.unsupported,
      invalid + cssRejected + slRejected,
    ];
  });
  console.log('');
  console.log(renderTable(['list', 'default', 'rules', 'regex', 'specific', 'generic', 'scriptlets', 'unsupported', 'dropped'], rows));
  const b = report.budgets as Record<string, number | string[]>;
  const pkg = report.package as { files: number; bytes: number; zipEstimate: number };
  const flag = (ok: boolean, s: string) => (ok ? color.green(s) : color.yellow(s));
  console.log('');
  console.log(
    `static rules (default lists): ${flag((b.staticRulesEnabled as number) <= LIMITS.GUARANTEED_STATIC_RULES, `${formatInt(b.staticRulesEnabled as number)} / ${formatInt(LIMITS.GUARANTEED_STATIC_RULES)} guaranteed`)}` +
      `   (all lists: ${formatInt(b.staticRulesAll as number)})`,
  );
  console.log(
    `regex rules (default lists):  ${flag((b.regexRulesEnabled as number) <= LIMITS.MAX_STATIC_REGEX_RULES, `${formatInt(b.regexRulesEnabled as number)} / ${formatInt(LIMITS.MAX_STATIC_REGEX_RULES)}`)}` +
      `   (all lists: ${formatInt(b.regexRulesAll as number)})`,
  );
  if ((b.skippedRegexRulesets as string[]).length) log.warn(`Chrome would skip regex rulesets: ${(b.skippedRegexRulesets as string[]).join(', ')}`);
  console.log(`rulesets: ${b.rulesetsDeclared} declared, ${b.rulesetsEnabled} enabled by default`);
  console.log(`package: ${pkg.files} files, ${formatBytes(pkg.bytes)} (zip ~${formatBytes(pkg.zipEstimate)})`);
  const csr = report.contentScripts as ReturnType<typeof registrationBudget>;
  console.log(
    `content scripts (default lists): ${csr.default.registrations} registrations, ${formatInt(csr.default.patterns)} patterns` +
      `   (all lists: ${csr.all.registrations} / ${formatInt(csr.all.patterns)}); scriptlet files: ${report.scriptletFiles}`,
  );
  const warnings = report.warnings as string[];
  console.log(`done in ${((report.durationMs as number) / 1000).toFixed(1)} s, ${warnings.length} warning(s); details: dist/build-report.json`);
}

if (isMain(import.meta.url)) {
  const { flags } = parseArgs(process.argv.slice(2));
  const log = createLogger('build');
  try {
    await build({ offline: flags.has('offline'), release: flags.has('release'), keepGoing: flags.has('keep-going'), log });
  } catch (e) {
    log.error((e as Error).stack ?? String(e));
    process.exitCode = 1;
  }
}

// Exposed for tests.
export { finalizeRuleset, hostsToAbp, normalizeCompiled };
