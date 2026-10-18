// Bastion Shield — (re)creates vendor/ from the commits pinned in
// vendor/VENDOR.json (ARCHITECTURE §11.1). Each entry names a GitHub repo, a
// commit and path patterns; the commit tarball is downloaded from codeload,
// and the matching files (plus the repo's licence) are written below
// vendor/<kebab-case key>/:
//
//   "src/js/resources/*.js"  -> resources/<file>      (last directory kept)
//   "src/js/urlskip.js"      -> urlskip.js            (plain file: basename)
//
//   node tools/vendor.ts            # write vendor/ at the pinned commits
//   node tools/vendor.ts --check    # read-only: compare vendor/ with upstream
//   node tools/vendor.ts --update   # move pins to each repo's HEAD, then write
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { ROOT, createLogger, fileExists, isMain, parseArgs, readJson, rel, sha256, walkFiles, writeJson, writeText, type Logger } from './lib/util.ts';

export const VENDOR_FILE = join(ROOT, 'vendor', 'VENDOR.json');

interface VendorEntry {
  repo: string;
  commit: string;
  license: string;
  paths: string[];
}
type VendorFile = Record<string, VendorEntry>;

const LICENSE_FILES = new Set(['LICENSE', 'LICENSE.txt', 'LICENSE.md', 'COPYING']);
/** uBO pages that need uBO's own extension runtime; never vendored or shipped. */
const EXCLUDED = new Set(['web_accessible_resources/click2load.html', 'web_accessible_resources/dom-inspector.html', 'web_accessible_resources/epicker-ui.html']);
const BINARY_EXT = /\.(gif|png|jpe?g|webp|ico|mp3|mp4|webm|woff2?|ttf|otf|wasm|zip|gz)$/i;

/** Content hash that ignores CRLF vs LF in text files (git autocrlf checkouts on Windows). */
function contentHash(rel: string, data: Buffer): string {
  if (BINARY_EXT.test(rel) || data.includes(0)) return sha256(data);
  return sha256(data.toString('utf8').replace(/\r\n/g, '\n'));
}

export function vendorDirOf(key: string): string {
  return key.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
}

/** Map a repo path to its vendor-relative output path, or null when no pattern matches. */
export function mapVendorPath(repoPath: string, patterns: readonly string[]): string | null {
  const base = repoPath.slice(repoPath.lastIndexOf('/') + 1);
  const dir = repoPath.includes('/') ? repoPath.slice(0, repoPath.lastIndexOf('/')) : '';
  if (dir === '' && LICENSE_FILES.has(base)) return base;
  for (const p of patterns) {
    const pBase = p.slice(p.lastIndexOf('/') + 1);
    const pDir = p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '';
    if (pDir !== dir) continue;
    if (pBase.includes('*')) {
      const re = new RegExp(`^${pBase.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*')}$`);
      if (!re.test(base)) continue;
      const last = dir.slice(dir.lastIndexOf('/') + 1);
      return last ? `${last}/${base}` : base;
    }
    if (pBase === base) return base;
  }
  return null;
}

/** Minimal ustar/pax reader: regular files only. */
export function readTar(buf: Buffer): { files: Map<string, Buffer>; globalComment?: string } {
  const files = new Map<string, Buffer>();
  let p = 0;
  let paxPath: string | undefined;
  let longName: string | undefined;
  let globalComment: string | undefined;
  const parsePax = (data: Buffer): Record<string, string> => {
    const out: Record<string, string> = {};
    let i = 0;
    while (i < data.length) {
      const sp = data.indexOf(0x20, i);
      if (sp === -1) break;
      const len = Number(data.subarray(i, sp).toString('ascii'));
      if (!Number.isFinite(len) || len <= 0) break;
      const rec = data.subarray(sp + 1, i + len - 1).toString('utf8');
      const eq = rec.indexOf('=');
      if (eq !== -1) out[rec.slice(0, eq)] = rec.slice(eq + 1);
      i += len;
    }
    return out;
  };
  while (p + 512 <= buf.length) {
    const h = buf.subarray(p, p + 512);
    if (h.every((b) => b === 0)) break;
    const field = (o: number, n: number) => h.subarray(o, o + n).toString('utf8').replace(/\0.*$/s, '');
    const size = parseInt(field(124, 12).trim() || '0', 8);
    const type = String.fromCharCode(h[156] || 0x30);
    const magic = field(257, 6);
    let name = field(0, 100);
    if (magic.startsWith('ustar')) {
      const prefix = field(345, 155);
      if (prefix) name = `${prefix}/${name}`;
    }
    const data = buf.subarray(p + 512, p + 512 + size);
    p += 512 + Math.ceil(size / 512) * 512;
    if (type === 'g') {
      globalComment = parsePax(data).comment ?? globalComment;
      continue;
    }
    if (type === 'x') {
      paxPath = parsePax(data).path;
      continue;
    }
    if (type === 'L') {
      longName = data.toString('utf8').replace(/\0.*$/s, '');
      continue;
    }
    const full = paxPath ?? longName ?? name;
    paxPath = undefined;
    longName = undefined;
    if (type === '0' || type === '\0' || type === '7') files.set(full, Buffer.from(data));
  }
  return { files, globalComment };
}

async function fetchBuffer(url: string, headers: Record<string, string> = {}): Promise<Buffer> {
  let last = '';
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(url, { headers: { 'user-agent': 'BastionShield-vendor', ...headers }, signal: AbortSignal.timeout(120_000) });
      if (!res.ok) {
        last = `HTTP ${res.status}`;
        if (res.status < 500) break;
        continue;
      }
      return Buffer.from(await res.arrayBuffer());
    } catch (e) {
      last = (e as Error).message;
    }
  }
  throw new Error(`${url}: ${last}`);
}

function ownerRepo(repoUrl: string): string {
  const m = /^https:\/\/github\.com\/([^/]+\/[^/]+?)(?:\.git)?\/?$/.exec(repoUrl);
  if (!m) throw new Error(`unsupported repo URL ${repoUrl} (GitHub only)`);
  return m[1];
}

/** Files of one vendor entry at its pinned commit: vendor-relative path -> bytes. */
export async function fetchVendorEntry(entry: VendorEntry): Promise<Map<string, Buffer>> {
  if (!/^[0-9a-f]{40}$/.test(entry.commit)) throw new Error(`${entry.repo}: commit must be a full 40-hex SHA`);
  const tgz = await fetchBuffer(`https://codeload.github.com/${ownerRepo(entry.repo)}/tar.gz/${entry.commit}`);
  const tar = readTar(gunzipSync(tgz));
  // GitHub stores the commit id in the global pax header: refuse anything else.
  if (tar.globalComment && tar.globalComment !== entry.commit) throw new Error(`${entry.repo}: tarball is for ${tar.globalComment}, expected ${entry.commit}`);
  const out = new Map<string, Buffer>();
  for (const [path, data] of tar.files) {
    const slash = path.indexOf('/');
    if (slash === -1) continue;
    const repoPath = path.slice(slash + 1); // strip "<repo>-<commit>/"
    const target = mapVendorPath(repoPath, entry.paths);
    if (target === null || EXCLUDED.has(target)) continue;
    if (out.has(target)) throw new Error(`${entry.repo}: two files map to ${target}`);
    out.set(target, data);
  }
  if (out.size === 0) throw new Error(`${entry.repo}: no files matched ${entry.paths.join(', ')}`);
  return out;
}

export interface VendorReport {
  key: string;
  dir: string;
  files: number;
  changed: string[];
  missing: string[];
  extra: string[];
}

export async function vendor(opts: { mode: 'write' | 'check' | 'update'; log?: Logger }): Promise<VendorReport[]> {
  const log = opts.log ?? createLogger('vendor');
  const pins = await readJson<VendorFile>(VENDOR_FILE);
  if (opts.mode === 'update') {
    for (const [key, entry] of Object.entries(pins)) {
      const info = JSON.parse((await fetchBuffer(`https://api.github.com/repos/${ownerRepo(entry.repo)}/commits/HEAD`, { accept: 'application/vnd.github+json' })).toString()) as { sha: string };
      if (!/^[0-9a-f]{40}$/.test(info.sha)) throw new Error(`${key}: unexpected API response`);
      if (info.sha !== entry.commit) log.info(`${key}: ${entry.commit.slice(0, 12)} -> ${info.sha.slice(0, 12)}`);
      entry.commit = info.sha;
    }
    await writeJson(VENDOR_FILE, pins, true);
  }
  const reports: VendorReport[] = [];
  for (const [key, entry] of Object.entries(pins)) {
    const dir = join(ROOT, 'vendor', vendorDirOf(key));
    log.step(`${key}: ${entry.repo} @ ${entry.commit.slice(0, 12)}`);
    const files = await fetchVendorEntry(entry);
    const report: VendorReport = { key, dir: `vendor/${vendorDirOf(key)}`, files: files.size, changed: [], missing: [], extra: [] };
    for (const [rel, data] of files) {
      const abs = join(dir, ...rel.split('/'));
      const exists = await fileExists(abs);
      const same = exists && contentHash(rel, await readFile(abs)) === contentHash(rel, data);
      if (!exists) report.missing.push(rel);
      else if (!same) report.changed.push(rel);
      if (opts.mode !== 'check' && !same) await writeText(abs, data);
    }
    // Local files upstream does not have (hand edits, leftovers): reported, never deleted.
    for (const f of await walkFiles(dir)) {
      const r = rel(f, dir);
      if (!files.has(r)) report.extra.push(r);
    }
    reports.push(report);
    log.info(
      `${files.size} files; ${report.missing.length} missing, ${report.changed.length} different${opts.mode === 'check' ? '' : ' (written)'}` +
        (report.extra.length ? `; ${report.extra.length} local-only file(s): ${report.extra.slice(0, 5).join(', ')}` : ''),
    );
  }
  return reports;
}

/** True when the vendored sources the build needs are present. */
export async function vendorPresent(): Promise<boolean> {
  return (
    (await fileExists(join(ROOT, 'vendor', 'ublock', 'resources', 'scriptlets.js'))) &&
    (await fileExists(join(ROOT, 'vendor', 'ublock', 'redirect-resources.js'))) &&
    (await fileExists(join(ROOT, 'vendor', 'brave-lists', 'query-filter.json')))
  );
}

if (isMain(import.meta.url)) {
  const { flags } = parseArgs(process.argv.slice(2));
  const log = createLogger('vendor');
  const mode = flags.has('check') ? 'check' : flags.has('update') ? 'update' : 'write';
  try {
    const reports = await vendor({ mode, log });
    if (mode === 'check') {
      const bad = reports.filter((r) => r.changed.length || r.missing.length);
      for (const r of bad) log.error(`${r.dir}: differs from the pinned commit (${[...r.missing.map((m) => `missing ${m}`), ...r.changed.map((c) => `changed ${c}`)].slice(0, 10).join(', ')})`);
      if (bad.length) process.exitCode = 1;
      else log.info('vendor/ matches the pinned commits');
    }
  } catch (e) {
    log.error((e as Error).message);
    process.exitCode = 1;
  }
}
