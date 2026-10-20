// Bastion Shield build tools — small filesystem, hashing, logging and
// concurrency helpers shared by fetch-lists, build and package. Node-only.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { copyFile, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Repository root (tools/lib/../..). */
export const ROOT = resolve(import.meta.dirname, '..', '..');

export const sha1 = (data: string | Uint8Array): string => createHash('sha1').update(data).digest('hex');
export const sha256 = (data: string | Uint8Array): string => createHash('sha256').update(data).digest('hex');

/** Repo-relative POSIX path, for messages and manifests. */
export function rel(p: string, from: string = ROOT): string {
  return relative(from, p).split(sep).join('/');
}

export async function ensureDir(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true });
}

export async function writeText(file: string, text: string | Uint8Array): Promise<void> {
  await ensureDir(dirname(file));
  await writeFile(file, text);
}

/** Compact JSON unless `pretty` (2-space). Always ends with a newline. */
export async function writeJson(file: string, value: unknown, pretty = false): Promise<void> {
  await writeText(file, JSON.stringify(value, null, pretty ? 2 : undefined) + '\n');
}

/**
 * JSON array with one element per line: compact enough for large rulesets,
 * yet diff- and grep-friendly (the line number tracks the rule id).
 */
export function jsonLines(items: readonly unknown[]): string {
  if (items.length === 0) return '[]\n';
  return '[\n' + items.map((v) => JSON.stringify(v)).join(',\n') + '\n]\n';
}

export async function readJson<T>(file: string): Promise<T> {
  return JSON.parse(stripBom(await readFile(file, 'utf8'))) as T;
}

export function stripBom(s: string): string {
  return s.charCodeAt(0) === 0xfeff ? s.slice(1) : s;
}

export async function fileExists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

export const fileExistsSync = (p: string): boolean => existsSync(p);

export async function rmrf(p: string): Promise<void> {
  // Windows sometimes reports EBUSY/EPERM for a moment after a file handle
  // closes (antivirus, indexer); retry a few times before giving up.
  await rm(p, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}

/** All files below `dir` (absolute paths), sorted for deterministic output. */
export async function walkFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  async function walk(d: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(d, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of entries) {
      const p = join(d, e.name);
      if (e.isDirectory()) await walk(p);
      else if (e.isFile()) out.push(p);
    }
  }
  await walk(dir);
  return out;
}

/** Copy a directory tree. `filter` receives the repo-relative source path. Returns copied file count. */
export async function copyDir(src: string, dst: string, filter?: (relPath: string) => boolean): Promise<number> {
  let n = 0;
  for (const file of await walkFiles(src)) {
    const r = rel(file, src);
    if (filter && !filter(r)) continue;
    const target = join(dst, ...r.split('/'));
    await ensureDir(dirname(target));
    await copyFile(file, target);
    n++;
  }
  return n;
}

export async function copyInto(src: string, dst: string): Promise<void> {
  await ensureDir(dirname(dst));
  await copyFile(src, dst);
}

export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Run `fn` over `items` with at most `limit` in flight; results keep input order. */
export async function mapLimit<T, R>(items: readonly T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

/** 30000 -> "30'000" (Swiss thousands separator; also unambiguous in English output). */
export function formatInt(n: number): string {
  return String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, "'");
}

// ---------------------------------------------------------------------------
// Logging. Colours only on a TTY so CI logs stay clean.
// ---------------------------------------------------------------------------

const useColor = process.stdout.isTTY === true && !process.env.NO_COLOR;
const paint = (code: string, s: string): string => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
export const color = {
  dim: (s: string) => paint('2', s),
  bold: (s: string) => paint('1', s),
  red: (s: string) => paint('31', s),
  green: (s: string) => paint('32', s),
  yellow: (s: string) => paint('33', s),
  cyan: (s: string) => paint('36', s),
};

export interface Logger {
  info(msg: string): void;
  warn(msg: string): void;
  error(msg: string): void;
  step(msg: string): void;
  readonly warnings: string[];
}

export function createLogger(prefix: string, quiet = false): Logger {
  const warnings: string[] = [];
  return {
    warnings,
    info(msg) {
      if (!quiet) console.log(`${color.dim(`[${prefix}]`)} ${msg}`);
    },
    step(msg) {
      if (!quiet) console.log(`${color.cyan(`[${prefix}]`)} ${color.bold(msg)}`);
    },
    warn(msg) {
      warnings.push(msg);
      console.warn(`${color.yellow(`[${prefix}] warning:`)} ${msg}`);
    },
    error(msg) {
      console.error(`${color.red(`[${prefix}] error:`)} ${msg}`);
    },
  };
}

/** Render a plain-text table; numeric-looking cells are right-aligned. */
export function renderTable(header: string[], rows: (string | number)[][]): string {
  const cells = [header, ...rows.map((r) => r.map((c) => (typeof c === 'number' ? formatInt(c) : c)))];
  const widths = header.map((_, i) => Math.max(...cells.map((r) => String(r[i] ?? '').length)));
  const isNum = (s: string) => /^[-+]?[\d'.,]+( ?[KM]?B|%)?$/.test(s);
  const line = (r: (string | number)[]) =>
    r
      .map((c, i) => {
        const s = String(c ?? '');
        return i > 0 && isNum(s) ? s.padStart(widths[i]) : s.padEnd(widths[i]);
      })
      .join('  ');
  const sepLine = widths.map((w) => '-'.repeat(w)).join('  ');
  return [line(cells[0]), sepLine, ...cells.slice(1).map(line)].join('\n');
}

/** Minimal `--flag` / `--key=value` parser. */
export function parseArgs(argv: string[]): { flags: Set<string>; values: Map<string, string>; rest: string[] } {
  const flags = new Set<string>();
  const values = new Map<string, string>();
  const rest: string[] = [];
  for (const a of argv) {
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq === -1) flags.add(a.slice(2));
      else values.set(a.slice(2, eq), a.slice(eq + 1));
    } else rest.push(a);
  }
  return { flags, values, rest };
}

/** True when this module is the process entry point (node tools/x.ts). */
export function isMain(metaUrl: string): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    const norm = (p: string) => (process.platform === 'win32' ? p.toLowerCase() : p);
    return norm(fileURLToPath(metaUrl)) === norm(resolve(entry));
  } catch {
    return false;
  }
}
