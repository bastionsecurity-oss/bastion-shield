// Bastion Shield — validates dist/ in a real Chromium (Playwright's bundled
// build). A copy of dist/ is loaded unpacked with EVERY static ruleset
// enabled: unpacked extensions treat any semantically invalid static rule as
// a hard load error, so a running service worker proves all rulesets parse.
// The copy's service worker is replaced by a probe that additionally
//   - checks every regexFilter with declarativeNetRequest.isRegexSupported,
//   - registers the shipped scriptlet bundles (core + all data files + runner per world) and
//     every highly generic CSS registration (with its excludeMatches),
//   - reports static rule counts and timings.
//
//   node tools/validate-dist.ts [--dist=dist] [--headed] [--strict]
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { cp, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { seedChromiumProfile } from './lib/chromium-profile.ts';
import { ROOT, createLogger, fileExists, formatInt, isMain, parseArgs, readJson, writeJson, type Logger } from './lib/util.ts';

/**
 * Regexes Chromium refused (isRegexSupported), keyed by regexKey(). Chromium
 * silently skips such rules at load; tools/build.ts drops them up front when
 * this file exists so rule counts and the regex budget are accurate.
 */
export const REGEX_UNSUPPORTED_FILE = join(ROOT, '.cache', 'regex-unsupported.json');
export const regexKey = (regex: string, caseSensitive: boolean) => `${caseSensitive ? 'c' : 'i'}:${regex}`;

export async function loadUnsupportedRegexes(): Promise<Map<string, string>> {
  try {
    const o = await readJson<Record<string, string>>(REGEX_UNSUPPORTED_FILE);
    return new Map(Object.entries(o));
  } catch {
    return new Map();
  }
}

const PROBE_SW = String.raw`
const t0 = Date.now();
async function json(path) { return (await fetch(chrome.runtime.getURL(path))).json(); }
self.__results = (async () => {
  const out = { errors: [] };
  try {
    const dnr = chrome.declarativeNetRequest;
    out.enabledRulesets = await dnr.getEnabledRulesets();
    out.availableStaticRules = await dnr.getAvailableStaticRuleCount();
    const manifest = chrome.runtime.getManifest();
    out.regexChecked = 0;
    out.regexUnsupported = [];
    for (const rr of manifest.declarative_net_request.rule_resources) {
      const rules = await json(rr.path);
      for (const r of rules) {
        if (!r.condition || r.condition.regexFilter === undefined) continue;
        out.regexChecked++;
        const res = await dnr.isRegexSupported({ regex: r.condition.regexFilter, isCaseSensitive: r.condition.isUrlFilterCaseSensitive === true });
        if (!res.isSupported) out.regexUnsupported.push([rr.id, r.id, res.reason, r.condition.regexFilter, r.condition.isUrlFilterCaseSensitive === true]);
      }
    }
    // Register exactly the shipped layout (see src/background/registrations.ts):
    // one <all_urls> registration per world = core + every list's data file + runner,
    // and one generic-high CSS registration listing every list's CSS.
    const idx = await json('scriptlets/index.json');
    const t1 = Date.now();
    const scripts = (idx.bundles || []).map((b) => ({
      id: 'sl-' + b.world.toLowerCase(),
      js: [b.core, ...idx.registrations.filter((r) => r.world === b.world).map((r) => r.file), b.end],
      matches: ['<all_urls>'], world: b.world,
      runAt: 'document_start', allFrames: true, matchOriginAsFallback: true, persistAcrossSessions: false,
    }));
    try {
      if (scripts.length) await chrome.scripting.registerContentScripts(scripts);
      out.scriptletRegistrations = scripts.length;
      out.scriptletPatterns = scripts.reduce((a, s) => a + s.matches.length, 0);
      out.scriptletFiles = scripts.reduce((a, s) => a + s.js.length, 0);
    } catch (e) {
      out.errors.push('scriptlets: ' + e.message);
    }
    out.scriptletRegisterMs = Date.now() - t1;
    const cm = await json('cosmetic/meta.json');
    const cssFiles = Object.values(cm.genericHighCss).filter(Boolean);
    const hostPattern = (h) => /^[0-9.]+$/.test(h) || h.includes(':') ? '*://' + h + '/*' : '*://*.' + h + '/*';
    const excluded = new Set(cm.genericHideHosts || []);
    for (const hosts of Object.values(cm.genericHighExcludedHosts || {})) for (const h of hosts) excluded.add(h);
    const usable = [...excluded].filter((h) => !h.endsWith('.*') && h.includes('.'));
    const css = cssFiles.length ? [{
      id: 'bs-gh-all', css: cssFiles, matches: ['<all_urls>'],
      excludeMatches: usable.map(hostPattern),
      runAt: 'document_start', allFrames: true, persistAcrossSessions: false,
    }] : [];
    try {
      if (css.length) await chrome.scripting.registerContentScripts(css);
      out.cssRegistrations = css.length;
      out.cssExcludePatterns = css.reduce((a, s) => a + s.excludeMatches.length, 0);
    } catch (e) {
      out.errors.push('generic-high css: ' + e.message);
    }
    const all = await chrome.scripting.getRegisteredContentScripts();
    out.registeredTotal = all.length;
    await chrome.scripting.unregisterContentScripts();
  } catch (e) {
    out.errors.push(String(e && e.stack || e));
  }
  out.ms = Date.now() - t0;
  return out;
})();
`;

interface ProbeResult {
  errors: string[];
  enabledRulesets: string[];
  availableStaticRules: number;
  regexChecked: number;
  regexUnsupported: [string, number, string, string, boolean][];
  scriptletRegistrations?: number;
  scriptletPatterns?: number;
  scriptletRegisterMs?: number;
  cssRegistrations?: number;
  cssExcludePatterns?: number;
  registeredTotal?: number;
  selectorsChecked?: number;
  selectorsInvalid?: string[];
  ms: number;
}

/** Hide selectors shipped in cosmetic data (generic-high, generic index, specific kind 0). */
async function collectSelectors(dir: string): Promise<string[]> {
  const base = join(dir, 'cosmetic');
  const out = new Set<string>();
  try {
    const high = await readJson<Record<string, string[]>>(join(base, 'generic-high.json'));
    for (const arr of Object.values(high)) for (const x of arr) out.add(x);
    const generic = await readJson<{ tokens: Record<string, [string, number][]> }>(join(base, 'generic.json'));
    for (const arr of Object.values(generic.tokens)) for (const [x] of arr) out.add(x);
    for (const f of await readdir(join(base, 'specific'))) {
      const shard = await readJson<{ hosts: Record<string, [number, string, number][]> }>(join(base, 'specific', f));
      for (const es of Object.values(shard.hosts)) for (const e of es) if (e[0] === 0) out.add(e[1]);
    }
  } catch {
    // Missing cosmetic data is reported by the build, not here.
  }
  return [...out];
}

export async function validateDist(opts: { distDir?: string; headed?: boolean; log?: Logger } = {}): Promise<ProbeResult> {
  const log = opts.log ?? createLogger('validate');
  const distDir = resolve(opts.distDir ?? join(ROOT, 'dist'));
  if (!(await fileExists(join(distDir, 'manifest.json')))) throw new Error(`${distDir}/manifest.json not found; build first`);
  const work = await mkdtemp(join(tmpdir(), 'bastion-validate-'));
  const ext = join(work, 'ext');
  try {
    // Skip _metadata/: stale indexed rulesets from an earlier unpacked load.
    await cp(distDir, ext, { recursive: true, filter: (src) => !/[\\/]_metadata([\\/]|$)/.test(src) });
    const manifest = JSON.parse(await readFile(join(ext, 'manifest.json'), 'utf8')) as {
      declarative_net_request: { rule_resources: { id: string; enabled: boolean; path: string }[] };
      background: { service_worker: string; type?: string };
    };
    const declared = manifest.declarative_net_request.rule_resources;
    for (const r of declared) r.enabled = true;
    manifest.background = { service_worker: '__probe.js' };
    await writeFile(join(ext, 'manifest.json'), JSON.stringify(manifest, null, 2));
    await writeFile(join(ext, '__probe.js'), PROBE_SW);

    const { chromium } = await import('@playwright/test');
    log.step(`Loading ${declared.length} rulesets (all enabled) in Chromium`);
    // Seed the profile so Chromium does not probe the Windows password (account lockout).
    seedChromiumProfile(join(work, 'profile'));
    const context = await chromium.launchPersistentContext(join(work, 'profile'), {
      headless: !opts.headed,
      channel: 'chromium',
      args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
    });
    try {
      let [sw] = context.serviceWorkers();
      if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 30_000 }).catch(() => undefined as never);
      if (!sw) throw new Error('the extension did not start: Chromium rejected the unpacked build (invalid manifest or static rule)');
      const res = (await sw.evaluate(() => (self as unknown as { __results: Promise<unknown> }).__results)) as ProbeResult;
      const missing = declared.map((r) => r.id).filter((id) => !res.enabledRulesets.includes(id));
      if (missing.length) res.errors.push(`rulesets not enabled: ${missing.join(', ')}`);
      // Merge into the cache read by tools/build.ts (never forget a known-bad regex).
      const known = await loadUnsupportedRegexes();
      for (const u of res.regexUnsupported) known.set(regexKey(u[3], u[4]), u[2]);
      if (res.regexUnsupported.length) await writeJson(REGEX_UNSUPPORTED_FILE, Object.fromEntries([...known].sort()), true);

      // Every hide selector must parse as a style rule: one bad selector would
      // void a whole group of 1'000 (generic-high CSS, or the SW's grouped CSS).
      const selectors = await collectSelectors(ext);
      const page = await context.newPage();
      const bad: string[] = [];
      for (let i = 0; i < selectors.length; i += 5000) {
        bad.push(
          ...(await page.evaluate((xs: string[]) => {
            const sheet = new CSSStyleSheet();
            return xs.filter((x) => {
              try {
                sheet.insertRule(`${x}{display:none!important}`, 0);
                sheet.deleteRule(0);
                return false;
              } catch {
                return true;
              }
            });
          }, selectors.slice(i, i + 5000))),
        );
      }
      await page.close();
      res.selectorsChecked = selectors.length;
      res.selectorsInvalid = bad;
      for (const x of bad.slice(0, 20)) res.errors.push(`selector Chromium cannot parse: ${x}`);
      if (bad.length > 20) res.errors.push(`... ${bad.length - 20} more invalid selectors`);
      return res;
    } finally {
      await context.close();
    }
  } finally {
    await rm(work, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 });
  }
}

if (isMain(import.meta.url)) {
  const { flags, values } = parseArgs(process.argv.slice(2));
  const log = createLogger('validate');
  try {
    const r = await validateDist({ distDir: values.get('dist'), headed: flags.has('headed'), log });
    log.info(`rulesets enabled: ${r.enabledRulesets.length}; static rules still available: ${formatInt(r.availableStaticRules)}`);
    log.info(`regex rules checked: ${r.regexChecked}, unsupported: ${r.regexUnsupported.length}`);
    for (const u of r.regexUnsupported.slice(0, 10)) log.warn(`regex unsupported in ${u[0]}#${u[1]} (${u[2]}): ${u[3]}`);
    if (r.regexUnsupported.length) {
      log.warn(`${r.regexUnsupported.length} unsupported regex rule(s) recorded in .cache/regex-unsupported.json; the next build drops them`);
    }
    log.info(`scriptlet registrations: ${r.scriptletRegistrations ?? 0} (${formatInt(r.scriptletPatterns ?? 0)} patterns) registered in ${r.scriptletRegisterMs} ms`);
    log.info(`generic-high CSS registrations: ${r.cssRegistrations ?? 0} (${formatInt(r.cssExcludePatterns ?? 0)} excludeMatches)`);
    log.info(`hide selectors parsed by Chromium: ${formatInt(r.selectorsChecked ?? 0)}, invalid: ${r.selectorsInvalid?.length ?? 0}`);
    for (const e of r.errors) log.error(e);
    // Unsupported regexes are skipped by Chromium (not a load error); --strict makes them fatal.
    if (r.errors.length || (flags.has('strict') && r.regexUnsupported.length)) process.exitCode = 1;
    else log.info('OK: Chromium loaded every ruleset and accepted every registration');
  } catch (e) {
    log.error((e as Error).message);
    process.exitCode = 1;
  }
}
