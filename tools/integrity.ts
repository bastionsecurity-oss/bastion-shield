// Bastion Shield — ruleset integrity manifest. After the build has written
// dist/rulesets/ (DNR rulesets, transparency maps, meta.json), this hashes
// every file there and writes dist/rulesets/integrity.json. The dashboard's
// nerd-mode Lab re-hashes the packaged files with crypto.subtle and compares.
// A self-check against accidental or local modification of the unpacked
// files, not a signature: whoever can change the rulesets can change this
// file too (the store signature covers the package as a whole).
//
// Usage: node tools/integrity.ts [distDir]   (also called by tools/build.ts)
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { ROOT, isMain, rel, sha256, walkFiles, writeJson } from './lib/util.ts';

/** dist/rulesets/integrity.json */
export interface IntegrityManifest {
  algorithm: 'sha256';
  /** BuildMeta.builtAt of the build that wrote the files. */
  builtAt: string;
  /** Package-relative path ("rulesets/net/easylist.json") -> lower-case hex SHA-256 of the file bytes. */
  files: Record<string, string>;
}

export const INTEGRITY_FILE = 'rulesets/integrity.json';

/** Hash every file under <outDir>/rulesets except the manifest itself, sorted by path. */
export async function computeIntegrity(outDir: string, builtAt: string): Promise<IntegrityManifest> {
  const files: Record<string, string> = {};
  const paths = (await walkFiles(join(outDir, 'rulesets')))
    .map((abs) => ({ abs, path: rel(abs, outDir) }))
    .filter((f) => f.path !== INTEGRITY_FILE)
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  for (const f of paths) files[f.path] = sha256(await readFile(f.abs));
  return { algorithm: 'sha256', builtAt, files };
}

/** Write dist/rulesets/integrity.json; returns the manifest. Leaves every other file untouched. */
export async function writeIntegrity(outDir: string, builtAt: string): Promise<IntegrityManifest> {
  const manifest = await computeIntegrity(outDir, builtAt);
  await writeJson(join(outDir, ...INTEGRITY_FILE.split('/')), manifest, true);
  return manifest;
}

if (isMain(import.meta.url)) {
  const outDir = process.argv[2] ?? join(ROOT, 'dist');
  let builtAt = new Date().toISOString();
  try {
    const meta = JSON.parse(await readFile(join(outDir, 'rulesets', 'meta.json'), 'utf8')) as { builtAt?: string };
    if (typeof meta.builtAt === 'string') builtAt = meta.builtAt;
  } catch {
    /* no meta.json: stamp with now */
  }
  const m = await writeIntegrity(outDir, builtAt);
  console.log(`integrity: ${Object.keys(m.files).length} files hashed -> ${rel(join(outDir, ...INTEGRITY_FILE.split('/')))}`);
}
