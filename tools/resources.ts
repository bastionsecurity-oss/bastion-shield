// Bastion Shield — builds, from the vendored sources, (a) the redirect-resource
// map used for `$redirect=` (name/alias -> "/war/<file>") and (b) the
// scriptlet library used for `+js()` (uBO's builtinScriptlets, uBO
// web-accessible JS resources with inline data, and compatible Brave
// resources). Everything here runs at build time only.
//
//   node tools/resources.ts   # prints a summary (sanity check of vendor/)
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { ScriptletInfo } from '../src/compiler/types.ts';
import { ROOT, createLogger, fileExists, isMain, readJson, stripBom, type Logger } from './lib/util.ts';

export const VENDOR_DIR = join(ROOT, 'vendor');
const UBO_DIR = join(VENDOR_DIR, 'ublock');
const UBO_WAR_DIR = join(UBO_DIR, 'web_accessible_resources');
const BRAVE_RES_DIR = join(VENDOR_DIR, 'brave-resources');

/** Extension directory that receives the used redirect resources. */
export const WAR_PREFIX = '/war/';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RedirectResource {
  /** Canonical file name, e.g. "noop.js". */
  name: string;
  /** Extension path, e.g. "/war/noop.js". */
  path: string;
  /** Absolute source file on disk. */
  sourceFile: string;
  aliases: string[];
  requiresTrust: boolean;
  /** uBO `params` (only click2load.html has them, and it is excluded). */
  params?: string[];
  origin: 'ubo' | 'brave';
}

/** A function that ends up in generated scriptlet files. */
export interface LibFunction {
  /** Library key: uBO name ("safe-self.fn", "set-constant.js") or a synthetic one. */
  key: string;
  /** JS identifier the function is declared as. */
  fnName: string;
  /** Function source (a function or class declaration). */
  code: string;
  /** Library keys of dependencies (resolved transitively by the emitter). */
  deps: string[];
}

export interface LibScriptlet extends LibFunction {
  /** Canonical scriptlet name, e.g. "set-constant.js". */
  name: string;
  world: 'MAIN' | 'ISOLATED';
  requiresTrust: boolean;
  /** Higher runs first (uBO: proxy-apply-config.js = 100). */
  priority: number;
  origin: 'ubo' | 'ubo-war' | 'brave';
  /**
   * Brave templates with {{1}}-style placeholders: the code is specialized
   * per argument list at build time (arguments are JS-string escaped), so no
   * runtime code generation is needed.
   */
  template: boolean;
}

export interface ResourceSet {
  /** For CompileOptions.redirectResources: every name and alias. */
  redirectMap: Map<string, { path: string; requiresTrust: boolean }>;
  /** Extension path -> resource (for copying and the manifest). */
  redirectByPath: Map<string, RedirectResource>;
  /** For CompileOptions.scriptlets: every name and alias, with and without ".js". */
  scriptletMap: Map<string, ScriptletInfo>;
  /** Canonical scriptlet name -> scriptlet. */
  scriptlets: Map<string, LibScriptlet>;
  /** Helper functions by library key ("safe-self.fn"). Includes the scriptlets themselves. */
  functions: Map<string, LibFunction>;
  /** Brave resources we could not support, with the reason. */
  skipped: { name: string; reason: string }[];
}

interface UboScriptletDetails {
  name: string;
  fn: { name: string; toString(): string };
  aliases?: string[];
  dependencies?: (string | { details?: { name: string } })[];
  world?: string;
  requiresTrust?: boolean;
  priority?: number;
}

interface UboRedirectDetails {
  alias?: string | string[];
  data?: 'text' | 'blob';
  params?: string[];
  requiresTrust?: boolean;
}

interface BraveMetadataEntry {
  name: string;
  aliases?: string[];
  kind: { mime?: string } | string;
  resourcePath: string;
  /** Newer adblock-rust: bitmask of required permissions (non-zero = privileged). */
  permission?: number;
  dependencies?: string[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const asArray = <T>(v: T | T[] | undefined): T[] => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

/** JS identifier derived from a resource name ("brave-fix.js" -> "brave_brave_fix_js"). */
function identFor(prefix: string, name: string): string {
  return `${prefix}_${name.replace(/[^A-Za-z0-9_$]/g, '_')}`;
}

/** Strip leading licence/comment blocks; the generated file carries its own attribution header. */
function stripLeadingComments(code: string): string {
  let s = stripBom(code);
  for (;;) {
    const t = s.trimStart();
    if (t.startsWith('/*')) {
      const end = t.indexOf('*/');
      if (end === -1) return s;
      s = t.slice(end + 2);
    } else if (t.startsWith('//')) {
      const nl = t.indexOf('\n');
      s = nl === -1 ? '' : t.slice(nl + 1);
    } else {
      return t;
    }
  }
}

/** Escape a value for use inside a JS string literal of any quote style (also safe in template literals). */
export function escapeForJsString(value: string): string {
  return JSON.stringify(value)
    .slice(1, -1)
    .replace(/'/g, "\\'")
    .replace(/`/g, '\\`')
    .replace(/\$\{/g, '\\${')
    .replace(/<\/(script)/gi, '<\\/$1');
}

/** Substitute {{1}}..{{N}} placeholders of a Brave template (missing args become ""). */
export function specializeTemplate(code: string, args: readonly string[]): string {
  return code.replace(/\{\{(\d+)\}\}/g, (_, n: string) => escapeForJsString(args[Number(n) - 1] ?? ''));
}

function addScriptletKeys(map: Map<string, ScriptletInfo>, key: string, info: ScriptletInfo, log: Logger): void {
  const keys = new Set([key]);
  if (key.endsWith('.js')) keys.add(key.slice(0, -3));
  else keys.add(`${key}.js`);
  for (const k of keys) {
    const prev = map.get(k);
    if (prev && prev.name !== info.name) {
      log.warn(`scriptlet key "${k}" maps to both ${prev.name} and ${info.name}; keeping ${prev.name}`);
      continue;
    }
    map.set(k, info);
  }
}

// ---------------------------------------------------------------------------
// uBO redirect resources
// ---------------------------------------------------------------------------

async function loadUboRedirects(log: Logger): Promise<RedirectResource[]> {
  const mod = (await import(pathToFileURL(join(UBO_DIR, 'redirect-resources.js')).href)) as {
    default: Map<string, UboRedirectDetails>;
  };
  const out: RedirectResource[] = [];
  for (const [name, details] of mod.default) {
    // click2load.html needs uBO's own page logic and query parameters; not usable from DNR.
    if (name === 'click2load.html') continue;
    const sourceFile = join(UBO_WAR_DIR, name);
    if (!(await fileExists(sourceFile))) {
      log.warn(`redirect resource ${name} listed in redirect-resources.js but missing in vendor/; skipped`);
      continue;
    }
    out.push({
      name,
      path: WAR_PREFIX + name,
      sourceFile,
      aliases: asArray(details.alias),
      requiresTrust: details.requiresTrust === true,
      params: details.params,
      origin: 'ubo',
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// uBO scriptlets
// ---------------------------------------------------------------------------

async function loadUboScriptlets(set: ResourceSet, log: Logger): Promise<void> {
  const mod = (await import(pathToFileURL(join(UBO_DIR, 'resources', 'scriptlets.js')).href)) as {
    builtinScriptlets: UboScriptletDetails[];
  };
  const fnNames = new Map<string, string>();
  for (const s of mod.builtinScriptlets) {
    if (typeof s?.name !== 'string' || typeof s.fn !== 'function') continue;
    const fnName = s.fn.name;
    if (!fnName) {
      log.warn(`uBO scriptlet ${s.name} has an anonymous function; skipped`);
      continue;
    }
    // Every function is declared in one shared scope, so names must be unique.
    const other = fnNames.get(fnName);
    if (other !== undefined && other !== s.name) {
      log.warn(`uBO function name ${fnName} used by ${other} and ${s.name}; skipping ${s.name}`);
      continue;
    }
    fnNames.set(fnName, s.name);
    // Dependencies may be names or function references (registerScriptlet()
    // normally converts the latter, but be tolerant of both forms).
    const deps: string[] = [];
    for (const d of s.dependencies ?? []) {
      if (typeof d === 'string') deps.push(d);
      else if (typeof d === 'function' || (typeof d === 'object' && d !== null)) {
        const n = (d as { details?: { name?: string } }).details?.name;
        if (typeof n === 'string') deps.push(n);
        else log.warn(`uBO scriptlet ${s.name}: unresolvable dependency reference; ignored`);
      }
    }
    const fn: LibFunction = { key: s.name, fnName, code: s.fn.toString(), deps };
    set.functions.set(s.name, fn);
    if (s.name.endsWith('.fn')) continue; // helper, not injectable
    const world = s.world === 'ISOLATED' ? 'ISOLATED' : 'MAIN';
    const sl: LibScriptlet = {
      ...fn,
      name: s.name,
      world,
      requiresTrust: s.requiresTrust === true,
      priority: typeof s.priority === 'number' ? s.priority : 0,
      origin: 'ubo',
      template: false,
    };
    set.scriptlets.set(s.name, sl);
    const info: ScriptletInfo = { name: s.name, world, requiresTrust: sl.requiresTrust };
    addScriptletKeys(set.scriptletMap, s.name, info, log);
    for (const a of s.aliases ?? []) addScriptletKeys(set.scriptletMap, a, info, log);
  }
  // Dangling dependencies would produce a ReferenceError at injection time.
  for (const f of set.functions.values()) {
    for (const d of f.deps) if (!set.functions.has(d)) log.warn(`uBO ${f.key}: missing dependency ${d}`);
  }
}

/**
 * uBO also lets lists inject web-accessible JS resources that carry inline
 * data (`data: 'text'`) as scriptlets, e.g. `+js(nobab2.js)`. uBO Lite does
 * the same (make-rulesets.js importWAR), so lists rely on it.
 */
async function loadUboWarScriptlets(set: ResourceSet, redirects: RedirectResource[], log: Logger): Promise<void> {
  const mod = (await import(pathToFileURL(join(UBO_DIR, 'redirect-resources.js')).href)) as {
    default: Map<string, UboRedirectDetails>;
  };
  for (const r of redirects) {
    const details = mod.default.get(r.name);
    if (!details || details.data !== 'text' || !r.name.endsWith('.js')) continue;
    if (set.scriptlets.has(r.name)) continue; // builtin scriptlet of the same name wins
    const body = stripLeadingComments(stripBom(await readFile(r.sourceFile, 'utf8'))).trim();
    const fnName = identFor('war', r.name);
    const sl: LibScriptlet = {
      key: `war:${r.name}`,
      fnName,
      code: `function ${fnName}() { // ${r.name}\n${body}\n}`,
      deps: [],
      name: r.name,
      world: 'MAIN',
      requiresTrust: r.requiresTrust,
      priority: 0,
      origin: 'ubo-war',
      template: false,
    };
    set.functions.set(sl.key, sl);
    set.scriptlets.set(r.name, sl);
    const info: ScriptletInfo = { name: r.name, world: 'MAIN', requiresTrust: sl.requiresTrust };
    for (const k of [r.name, ...r.aliases]) {
      if (!set.scriptletMap.has(k) && !set.scriptletMap.has(k.replace(/\.js$/, ''))) addScriptletKeys(set.scriptletMap, k, info, log);
    }
  }
}

// ---------------------------------------------------------------------------
// Brave resources (MPL-2.0)
// ---------------------------------------------------------------------------

async function loadBraveResources(set: ResourceSet, redirects: RedirectResource[], log: Logger): Promise<void> {
  const metaFile = join(BRAVE_RES_DIR, 'metadata.json');
  if (!(await fileExists(metaFile))) {
    log.warn('vendor/brave-resources/metadata.json missing; Brave resources unavailable');
    return;
  }
  const meta = await readJson<BraveMetadataEntry[]>(metaFile);
  const taken = new Set(redirects.flatMap((r) => [r.name, ...r.aliases]));
  for (const entry of meta) {
    const name = entry?.name;
    if (typeof name !== 'string' || typeof entry.resourcePath !== 'string') continue;
    const mime = typeof entry.kind === 'string' ? entry.kind : entry.kind?.mime ?? '';
    const isTemplate = typeof entry.kind === 'string' && entry.kind === 'template';
    if (mime !== 'application/javascript' && !isTemplate) {
      set.skipped.push({ name, reason: `unsupported kind ${JSON.stringify(entry.kind)}` });
      continue;
    }
    const file = join(BRAVE_RES_DIR, 'resources', entry.resourcePath);
    if (entry.resourcePath.includes('..') || !(await fileExists(file))) {
      set.skipped.push({ name, reason: 'resource file missing' });
      continue;
    }
    if (entry.dependencies?.length) {
      set.skipped.push({ name, reason: 'depends on other Brave resources (not supported)' });
      continue;
    }
    const raw = stripBom(await readFile(file, 'utf8'));
    const body = stripLeadingComments(raw).trim();
    // de-amp.js only acts when Brave's browser process defines `deAmpEnabled`;
    // Bastion implements De-AMP natively in the cosmetic content script.
    if (/\bdeAmpEnabled\b/.test(body) && !/\b(?:var|let|const)\s+deAmpEnabled\b/.test(body)) {
      set.skipped.push({ name, reason: 'relies on Brave-injected global deAmpEnabled (De-AMP is built into Bastion)' });
      continue;
    }
    const template = /\{\{\d+\}\}/.test(body);
    const requiresTrust = typeof entry.permission === 'number' && entry.permission !== 0;
    const aliases = asArray(entry.aliases).filter((a) => typeof a === 'string');

    // Scriptlet: wrap the self-contained script into a function so it runs
    // inside the shared scriptlet scope like uBO's own scriptlets.
    if (set.scriptlets.has(name) || set.scriptletMap.has(name)) {
      set.skipped.push({ name, reason: 'name collides with a uBO scriptlet (uBO wins)' });
    } else {
      const fnName = identFor('brave', name);
      const sl: LibScriptlet = {
        key: `brave:${name}`,
        fnName,
        code: `function ${fnName}() { // ${name} (Brave, MPL-2.0)\n${body}\n}`,
        deps: [],
        name,
        world: 'MAIN',
        requiresTrust,
        priority: 0,
        origin: 'brave',
        template,
      };
      set.functions.set(sl.key, sl);
      set.scriptlets.set(name, sl);
      const info: ScriptletInfo = { name, world: 'MAIN', requiresTrust };
      for (const k of [name, ...aliases]) addScriptletKeys(set.scriptletMap, k, info, log);
    }

    // Redirect target too (e.g. brave-sugarcoat.txt uses $redirect=async-sugarcoat-<hash>.js).
    // Templates cannot be redirect targets: the file would contain raw placeholders.
    if (!template && !taken.has(name)) {
      // Brave lists reference some resources without the ".js" suffix
      // (brave-sugarcoat.txt: redirect=async-sugarcoat-<hash>); accept both.
      const extra = name.endsWith('.js') ? [name.slice(0, -3)] : [];
      const all = [...aliases, ...extra].filter((a) => !taken.has(a) && a !== name);
      redirects.push({
        name,
        path: WAR_PREFIX + entry.resourcePath,
        sourceFile: file,
        aliases: [...new Set(all)],
        requiresTrust,
        origin: 'brave',
      });
      taken.add(name);
      for (const a of all) taken.add(a);
    }
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export async function loadResources(log: Logger = createLogger('resources')): Promise<ResourceSet> {
  const set: ResourceSet = {
    redirectMap: new Map(),
    redirectByPath: new Map(),
    scriptletMap: new Map(),
    scriptlets: new Map(),
    functions: new Map(),
    skipped: [],
  };
  const redirects = await loadUboRedirects(log);
  await loadUboScriptlets(set, log);
  await loadUboWarScriptlets(set, redirects, log);
  await loadBraveResources(set, redirects, log);

  for (const r of redirects) {
    set.redirectByPath.set(r.path, r);
    for (const key of [r.name, ...r.aliases]) {
      const prev = set.redirectMap.get(key);
      if (prev && prev.path !== r.path) {
        log.warn(`redirect name "${key}" maps to ${prev.path} and ${r.path}; keeping ${prev.path}`);
        continue;
      }
      set.redirectMap.set(key, { path: r.path, requiresTrust: r.requiresTrust });
    }
  }
  return set;
}

if (isMain(import.meta.url)) {
  const log = createLogger('resources');
  const set = await loadResources(log);
  const worlds = { MAIN: 0, ISOLATED: 0 };
  for (const s of set.scriptlets.values()) worlds[s.world]++;
  const origins: Record<string, number> = {};
  for (const s of set.scriptlets.values()) origins[s.origin] = (origins[s.origin] ?? 0) + 1;
  log.info(`redirect resources: ${set.redirectByPath.size} files, ${set.redirectMap.size} names/aliases`);
  log.info(`scriptlets: ${set.scriptlets.size} (MAIN ${worlds.MAIN}, ISOLATED ${worlds.ISOLATED}) ${JSON.stringify(origins)}`);
  log.info(`scriptlet keys: ${set.scriptletMap.size}, functions incl. helpers: ${set.functions.size}`);
  log.info(`trusted-only scriptlets: ${[...set.scriptlets.values()].filter((s) => s.requiresTrust).length}`);
  for (const s of set.skipped) log.info(`skipped Brave resource ${s.name}: ${s.reason}`);
}
