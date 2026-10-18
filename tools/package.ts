// Bastion Shield — packages dist/ for distribution (ARCHITECTURE §11.4):
//
//   dist-pkg/bastion-shield-<version>-chromium.zip   Chrome Web Store (and Brave)
//   dist-pkg/bastion-shield-<version>-edge.zip       Edge Add-ons: DNR rulesets at
//                                                    the package root (uBOL does the
//                                                    same for Edge's update validator)
//   dist-pkg/bastion-shield-<version>.crx + update.xml   self-hosting, when a key is set
//
//   node tools/package.ts
//   BASTION_CRX_KEY=key.pem BASTION_UPDATE_BASE_URL=https://updates.example.ch/shield node tools/package.ts
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createCrx3, updateXml, verifyCrx3 } from './lib/crx.ts';
import { createZip, readZip, type ZipEntry } from './lib/zip.ts';
import { ROOT, createLogger, fileExists, formatBytes, isMain, parseArgs, rel, sha256, walkFiles, writeText, type Logger } from './lib/util.ts';

export const PKG_DIR = join(ROOT, 'dist-pkg');

interface Manifest {
  version: string;
  minimum_chrome_version?: string;
  declarative_net_request?: { rule_resources?: { id: string; enabled: boolean; path: string }[] };
  update_url?: string;
  [k: string]: unknown;
}

/**
 * Files that never ship: build diagnostics, source maps, and `_metadata/`
 * (Chromium writes indexed rulesets there when dist/ is loaded unpacked;
 * names starting with "_" are reserved and stores reject them).
 */
export function shipped(relPath: string): boolean {
  if (relPath === 'build-report.json' || relPath.endsWith('.map')) return false;
  const top = relPath.split('/')[0];
  return !(top.startsWith('_') && top !== '_locales');
}

async function collect(distDir: string): Promise<ZipEntry[]> {
  const entries: ZipEntry[] = [];
  for (const f of await walkFiles(distDir)) {
    const r = rel(f, distDir);
    if (!shipped(r)) continue;
    entries.push({ name: r, data: await readFile(f) });
  }
  // manifest.json first: some tools sniff the first entry; the rest sorted.
  entries.sort((a, b) => (a.name === 'manifest.json' ? -1 : b.name === 'manifest.json' ? 1 : a.name < b.name ? -1 : 1));
  return entries;
}

function withManifest(entries: ZipEntry[], manifest: Manifest): ZipEntry[] {
  const data = Buffer.from(JSON.stringify(manifest, null, 2) + '\n');
  return entries.map((e) => (e.name === 'manifest.json' ? { name: e.name, data } : e));
}

/** Edge variant: move every DNR ruleset to the package root and rewrite the manifest paths. */
export function edgeVariant(entries: ZipEntry[], manifest: Manifest): { entries: ZipEntry[]; manifest: Manifest } {
  const m: Manifest = structuredClone(manifest);
  const moves = new Map<string, string>();
  for (const r of m.declarative_net_request?.rule_resources ?? []) {
    const base = r.path.slice(r.path.lastIndexOf('/') + 1);
    moves.set(r.path, base);
    r.path = base;
  }
  const names = new Set(entries.map((e) => e.name));
  for (const [from, to] of moves) {
    if (from !== to && names.has(to)) throw new Error(`edge layout: ${to} already exists at the package root`);
  }
  const out = entries.map((e) => (moves.has(e.name) ? { name: moves.get(e.name)!, data: e.data } : e));
  return { entries: withManifest(out, m), manifest: m };
}

export interface PackageResult {
  version: string;
  artifacts: { file: string; bytes: number; sha256: string }[];
  extensionId?: string;
}

export async function packageDist(opts: { distDir?: string; outDir?: string; keyPath?: string; updateBaseUrl?: string; log?: Logger } = {}): Promise<PackageResult> {
  const log = opts.log ?? createLogger('package');
  const distDir = opts.distDir ?? join(ROOT, 'dist');
  const outDir = opts.outDir ?? PKG_DIR;
  const manifestPath = join(distDir, 'manifest.json');
  if (!(await fileExists(manifestPath))) throw new Error(`${rel(manifestPath)} not found; run "npm run build" first`);
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8')) as Manifest;
  const version = manifest.version;
  if (!/^\d+(\.\d+){0,3}$/.test(version)) throw new Error(`manifest version "${version}" is invalid`);
  const entries = await collect(distDir);
  if (!entries.some((e) => e.name === 'background.js')) log.warn('background.js missing: the package will not work');
  const result: PackageResult = { version, artifacts: [] };
  const write = async (name: string, data: Buffer | string) => {
    const file = join(outDir, name);
    await writeText(file, data);
    const buf = typeof data === 'string' ? Buffer.from(data) : data;
    result.artifacts.push({ file: rel(file), bytes: buf.length, sha256: sha256(buf) });
    log.info(`${name.padEnd(46)} ${formatBytes(buf.length).padStart(10)}`);
  };

  log.step(`Packaging ${version} (${entries.length} files)`);
  const chromiumZip = createZip(entries);
  // Round-trip check: a corrupt archive is rejected by the stores only after upload.
  if (readZip(chromiumZip).size !== entries.length) throw new Error('zip round-trip check failed');
  await write(`bastion-shield-${version}-chromium.zip`, chromiumZip);

  const edge = edgeVariant(entries, manifest);
  await write(`bastion-shield-${version}-edge.zip`, createZip(edge.entries));

  const keyPath = opts.keyPath ?? process.env.BASTION_CRX_KEY;
  const baseUrl = (opts.updateBaseUrl ?? process.env.BASTION_UPDATE_BASE_URL ?? '').replace(/\/+$/, '');
  if (keyPath) {
    const pem = await readFile(resolve(keyPath), 'utf8');
    const crxManifest: Manifest = structuredClone(manifest);
    if (baseUrl) crxManifest.update_url = `${baseUrl}/update.xml`;
    else log.warn('BASTION_UPDATE_BASE_URL not set: the CRX has no update_url and update.xml is not written');
    const crxZip = createZip(withManifest(entries, crxManifest));
    const { crx, id } = createCrx3(crxZip, pem);
    const check = verifyCrx3(crx);
    if (check.id !== id) throw new Error('CRX self-verification failed');
    const crxName = `bastion-shield-${version}.crx`;
    await write(crxName, crx);
    if (baseUrl) {
      await write(
        'update.xml',
        updateXml({ id, version, codebase: `${baseUrl}/${crxName}`, minChromeVersion: manifest.minimum_chrome_version }),
      );
    }
    result.extensionId = id;
    log.info(`extension id (self-hosted CRX): ${id}`);
  } else if (baseUrl) {
    log.warn('BASTION_UPDATE_BASE_URL is set but BASTION_CRX_KEY is not: no CRX/update.xml written');
  }
  const sums = result.artifacts.map((a) => `${a.sha256}  ${a.file.split('/').pop()}`).join('\n') + '\n';
  await writeText(join(outDir, `SHA256SUMS-${version}.txt`), sums);
  return result;
}

if (isMain(import.meta.url)) {
  const { values } = parseArgs(process.argv.slice(2));
  const log = createLogger('package');
  try {
    await packageDist({ keyPath: values.get('key'), updateBaseUrl: values.get('update-base-url'), log });
  } catch (e) {
    log.error((e as Error).message);
    process.exitCode = 1;
  }
}
