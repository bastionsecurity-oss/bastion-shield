// Bastion Shield — bundles the extension's TypeScript entry points with
// esbuild and copies static assets (HTML/CSS, locales, icons, fonts,
// licences, managed-storage schema) into dist/. Entry points that do not
// exist yet are skipped with a warning so partial trees still build.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { readdir } from 'node:fs/promises';
import { basename, extname, join } from 'node:path';
import { ROOT, copyDir, copyInto, fileExists, readJson, walkFiles, writeJson, type Logger } from './util.ts';

export interface EntryPoint {
  src: string;
  out: string;
  format: 'esm' | 'iife';
}

/** ARCHITECTURE §11.3.11: background.js as ESM; content/main/ui/pages as IIFE. */
export const ENTRY_POINTS: EntryPoint[] = [
  { src: 'src/background/index.ts', out: 'background.js', format: 'esm' },
  { src: 'src/content/cosmetic.ts', out: 'content/cosmetic.js', format: 'iife' },
  { src: 'src/content/procedural.ts', out: 'content/procedural.js', format: 'iife' },
  { src: 'src/main/privacy.ts', out: 'main/privacy.js', format: 'iife' },
  { src: 'src/main/clipguard.ts', out: 'main/clipguard.js', format: 'iife' },
  { src: 'src/main/fpmeter.ts', out: 'main/fpmeter.js', format: 'iife' },
  { src: 'src/content/nerd-relay.ts', out: 'content/nerd-relay.js', format: 'iife' },
  { src: 'src/ui/popup/popup.ts', out: 'ui/popup.js', format: 'iife' },
  { src: 'src/ui/dashboard/dashboard.ts', out: 'ui/dashboard.js', format: 'iife' },
  { src: 'src/pages/blocked.ts', out: 'pages/blocked.js', format: 'iife' },
  { src: 'src/pages/bounce.ts', out: 'pages/bounce.js', format: 'iife' },
];

export interface BundleResult {
  built: { out: string; bytes: number }[];
  missing: string[];
  failed: { src: string; error: string }[];
}

/**
 * `define`: extra esbuild defines (identifier -> JS expression), e.g. the
 * blocker-notice event name for content/cosmetic.js (tools/lib/notice-transform.ts).
 */
export async function bundle(outDir: string, opts: { release: boolean; log: Logger; define?: Record<string, string> }): Promise<BundleResult> {
  const esbuild = await import('esbuild');
  const result: BundleResult = { built: [], missing: [], failed: [] };
  for (const ep of ENTRY_POINTS) {
    const abs = join(ROOT, ...ep.src.split('/'));
    if (!(await fileExists(abs))) {
      result.missing.push(ep.src);
      opts.log.warn(`entry point ${ep.src} not found; ${ep.out} skipped`);
      continue;
    }
    try {
      const r = await esbuild.build({
        entryPoints: [abs],
        outfile: join(outDir, ...ep.out.split('/')),
        bundle: true,
        format: ep.format,
        platform: 'browser',
        target: 'chrome120',
        minify: opts.release,
        // Dev builds stay readable and debuggable; release builds ship no maps.
        sourcemap: opts.release ? false : 'linked',
        legalComments: opts.release ? 'eof' : 'inline',
        charset: 'utf8',
        treeShaking: true,
        logLevel: 'silent',
        metafile: true,
        tsconfig: join(ROOT, 'tsconfig.json'),
        define: { 'process.env.NODE_ENV': JSON.stringify(opts.release ? 'production' : 'development'), ...(opts.define ?? {}) },
      });
      for (const w of r.warnings) opts.log.warn(`esbuild ${ep.src}: ${w.text}`);
      const outputs = Object.entries(r.metafile?.outputs ?? {}).filter(([p]) => !p.endsWith('.map'));
      for (const [, o] of outputs) result.built.push({ out: ep.out, bytes: o.bytes });
    } catch (e) {
      const errs = (e as { errors?: { text: string; location?: { file: string; line: number } | null }[] }).errors;
      const msg = errs?.length
        ? errs.map((x) => `${x.location ? `${x.location.file}:${x.location.line}: ` : ''}${x.text}`).join('; ')
        : (e as Error).message;
      result.failed.push({ src: ep.src, error: msg });
      opts.log.error(`esbuild failed for ${ep.src}: ${msg}`);
    }
  }
  return result;
}

const UI_ASSET_EXT = new Set(['.html', '.css', '.svg', '.png', '.webp', '.woff2', '.json']);

/** Copy HTML/CSS and other static assets. Returns warnings already logged. */
export async function copyStatic(outDir: string, log: Logger): Promise<void> {
  // Popup and dashboard: their HTML/CSS land flat in dist/ui/ next to the bundles.
  const flatUi = new Map<string, string>();
  for (const dir of ['src/ui/popup', 'src/ui/dashboard']) {
    const abs = join(ROOT, ...dir.split('/'));
    let names: string[] = [];
    try {
      names = await readdir(abs);
    } catch {
      log.warn(`${dir}/ not found; UI page not copied`);
      continue;
    }
    for (const n of names.sort()) {
      if (!UI_ASSET_EXT.has(extname(n).toLowerCase())) continue;
      const prev = flatUi.get(n);
      if (prev) {
        log.warn(`ui asset name clash: ${dir}/${n} and ${prev}/${n}; keeping the first`);
        continue;
      }
      flatUi.set(n, dir);
      await copyInto(join(abs, n), join(outDir, 'ui', n));
    }
  }
  for (const page of ['popup.html', 'dashboard.html']) {
    if (!flatUi.has(page)) log.warn(`ui/${page} missing (manifest references it)`);
  }

  // Shared UI assets (design tokens, fonts, icons). TypeScript is bundled, not copied.
  const shared = join(ROOT, 'src', 'ui', 'shared');
  if (await fileExists(shared)) await copyDir(shared, join(outDir, 'ui', 'shared'), (r) => !/\.(ts|tsx|map)$/.test(r));

  // Pages (blocked.html, bounce.html and their CSS).
  const pages = join(ROOT, 'src', 'pages');
  if (await fileExists(pages)) {
    await copyDir(pages, join(outDir, 'pages'), (r) => !r.includes('/') && UI_ASSET_EXT.has(extname(r).toLowerCase()));
  }
  for (const p of ['blocked.html', 'bounce.html']) {
    if (!(await fileExists(join(outDir, 'pages', p)))) log.warn(`pages/${p} missing (web_accessible_resources references it)`);
  }

  // Icons.
  const icons = join(ROOT, 'src', 'icons');
  if (await fileExists(icons)) await copyDir(icons, join(outDir, 'icons'));
  else log.warn('src/icons/ missing');

  // Runtime data the service worker reads: Brave's debounce rules (MPL-2.0).
  const debounce = join(ROOT, 'vendor', 'brave-lists', 'debounce.json');
  if (await fileExists(debounce)) await copyInto(debounce, join(outDir, 'data', 'debounce.json'));
  else log.warn('vendor/brave-lists/debounce.json missing: bounce-tracking protection will be inactive');

  await copyLocales(outDir, log);
  await copyManagedSchema(outDir, log);
  await copyLicenses(outDir, log);
}

const REQUIRED_MESSAGES = ['extName', 'extDescription'];

async function copyLocales(outDir: string, log: Logger): Promise<void> {
  const src = join(ROOT, 'src', '_locales');
  const dst = join(outDir, '_locales');
  let locales: string[] = [];
  try {
    locales = (await readdir(src, { withFileTypes: true })).filter((d) => d.isDirectory()).map((d) => d.name);
  } catch {
    locales = [];
  }
  for (const loc of locales) {
    const file = join(src, loc, 'messages.json');
    if (!(await fileExists(file))) continue;
    try {
      // Re-serialize: catches JSON errors (Chrome refuses to load the extension) and strips BOMs.
      const msgs = await readJson<Record<string, { message: string }>>(file);
      for (const [k, v] of Object.entries(msgs)) {
        if (!v || typeof v.message !== 'string') throw new Error(`message "${k}" has no string "message"`);
      }
      await writeJson(join(dst, loc, 'messages.json'), msgs, true);
    } catch (e) {
      log.error(`src/_locales/${loc}/messages.json: ${(e as Error).message}`);
      throw e;
    }
  }
  // default_locale "en" with __MSG_extName__ must resolve or Chrome refuses to load.
  const enFile = join(dst, 'en', 'messages.json');
  let en: Record<string, { message: string; description?: string }> = {};
  if (await fileExists(enFile)) en = await readJson(enFile);
  let patched = false;
  const fallback: Record<string, string> = {
    extName: 'Bastion Shield',
    extDescription: 'Lean, open-source ad and tracker blocker by Bastion. Nothing leaves your device.',
  };
  for (const k of REQUIRED_MESSAGES) {
    if (!en[k]) {
      en[k] = { message: fallback[k], description: 'Fallback written by tools/build.ts' };
      patched = true;
    }
  }
  if (patched) {
    log.warn(`_locales/en/messages.json lacks ${REQUIRED_MESSAGES.filter((k) => en[k]?.description === 'Fallback written by tools/build.ts').join(', ')}; wrote fallback strings`);
    await writeJson(enFile, en, true);
  }
}

async function copyManagedSchema(outDir: string, log: Logger): Promise<void> {
  const src = join(ROOT, 'policy', 'managed_schema.json');
  const dst = join(outDir, 'managed_schema.json');
  if (await fileExists(src)) {
    try {
      const schema = await readJson<{ type?: string }>(src);
      if (schema.type !== 'object') throw new Error('top-level "type" must be "object"');
      await writeJson(dst, schema, true);
      return;
    } catch (e) {
      log.error(`policy/managed_schema.json: ${(e as Error).message}`);
      throw e;
    }
  }
  log.warn('policy/managed_schema.json not found; wrote a minimal schema (no managed settings will be accepted)');
  await writeJson(dst, { type: 'object', properties: {} }, true);
}

async function copyLicenses(outDir: string, log: Logger): Promise<void> {
  const dst = join(outDir, 'licenses');
  const items: [string, string][] = [
    ['LICENSE', 'LICENSE.txt'],
    ['COPYING', 'LICENSE.txt'],
    ['THIRD_PARTY_NOTICES.md', 'THIRD_PARTY_NOTICES.md'],
    ['AUTHORS.md', 'AUTHORS.md'],
    ['vendor/ublock/LICENSE.txt', 'uBlock-Origin-GPL-3.0.txt'],
    ['vendor/brave-resources/LICENSE', 'brave-adblock-resources-MPL-2.0.txt'],
    ['vendor/brave-lists/LICENSE', 'brave-adblock-lists-MPL-2.0.txt'],
    ['vendor/VENDOR.json', 'VENDOR.json'],
  ];
  let haveMain = false;
  for (const [src, name] of items) {
    const abs = join(ROOT, ...src.split('/'));
    if (!(await fileExists(abs))) continue;
    if (name === 'LICENSE.txt') {
      if (haveMain) continue;
      haveMain = true;
    }
    await copyInto(abs, join(dst, name));
  }
  if (!haveMain) log.warn('no LICENSE file at the repository root; dist/licenses/LICENSE.txt not written');
  // Font licences live next to the fonts (ui/shared/fonts) and are copied with them.
  for (const f of await walkFiles(join(ROOT, 'src', 'ui', 'shared', 'fonts'))) {
    if (/^LICENSE/i.test(basename(f))) await copyInto(f, join(dst, `font-${basename(f)}`));
  }
}
