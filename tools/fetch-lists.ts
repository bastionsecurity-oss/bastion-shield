// Bastion Shield — downloads every filter-list source in filters/catalog.json,
// expands same-origin `!#include` directives, caches the raw bytes in
// .cache/lists/ (conditional requests via ETag / Last-Modified) and writes
// filters/lock.json so every build is traceable to exact list versions.
//
// Trust (uBO's model, docs/FILTER-LISTS.md): trust is granted per catalog
// source. Upstream `!#trusted` directives are always removed, and an
// untrusted source (`"trusted": false`) inside a trusted list is wrapped in
// `!#trusted off <secret>` ... `!#trusted on <secret>`. The secret is random
// per build and is passed to the compiler as CompileOptions.trustSecret, so
// list text can never switch trust back on.
//
//   node tools/fetch-lists.ts            # online (uses the cache for 304s)
//   node tools/fetch-lists.ts --offline  # cache only, fails if something is missing
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { randomBytes } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import type { Catalog, CatalogList } from '../src/shared/types.ts';
import {
  ROOT,
  createLogger,
  fileExists,
  isMain,
  mapLimit,
  parseArgs,
  readJson,
  rel,
  sha1,
  sha256,
  sleep,
  stripBom,
  writeJson,
  writeText,
  type Logger,
} from './lib/util.ts';

export const CACHE_DIR = join(ROOT, '.cache', 'lists');
export const LOCK_FILE = join(ROOT, 'filters', 'lock.json');
export const CATALOG_FILE = join(ROOT, 'filters', 'catalog.json');

const MAX_INCLUDE_DEPTH = 3;
const RETRIES = 3;
const TIMEOUT_MS = 30_000;
const CONCURRENCY = 6;
/** Sanity cap: no list we ship is anywhere near this; protects against runaway responses. */
const MAX_BYTES = 64 * 1024 * 1024;

export interface LockEntry {
  /** List the source belongs to. */
  list: string;
  /** Source URL, or the repo-relative path for local sources. */
  url: string;
  sha256: string;
  bytes: number;
  version?: string;
  lastModified?: string;
  /** When these exact bytes were first downloaded (stable across 304 revalidations). */
  fetchedAt: string;
  /** Set for sources pulled in through `!#include`. */
  includedFrom?: string;
}

export interface LockFile {
  version: 1;
  sources: LockEntry[];
}

export interface FetchedPart {
  url: string;
  format: 'abp' | 'hosts';
  /**
   * Source text with includes expanded, LF line endings, upstream `!#trusted`
   * directives removed, unclosed `!#if` blocks closed at the end, and (when
   * `trustedOff`) wrapped in the `!#trusted off/on <secret>` markers.
   */
  text: string;
  /** True when this part is an untrusted source of a trusted list and was wrapped in trust markers. */
  trustedOff?: boolean;
}

export interface FetchedList {
  listId: string;
  /** 'mixed' when sources disagree; build.ts then normalizes hosts parts. */
  format: 'abp' | 'hosts' | 'mixed';
  /** All parts concatenated, each preceded by a `--- source:` marker comment. */
  text: string;
  parts: FetchedPart[];
  /** Lock entries for every fetched file (top-level sources and includes). */
  sources: LockEntry[];
}

export interface FetchOptions {
  offline?: boolean;
  catalog?: Catalog;
  log?: Logger;
  /** Write the lock file (default true). */
  writeLock?: boolean;
  /** Overrides for tests. */
  cacheDir?: string;
  lockFile?: string;
  /**
   * Secret for the `!#trusted off/on <secret>` markers around untrusted
   * sources of trusted lists. Pass the same value to compileList() as
   * CompileOptions.trustSecret. Default: a fresh random secret per call,
   * returned in FetchResult.trustSecret.
   */
  trustSecret?: string;
}

export interface FetchResult {
  lists: FetchedList[];
  lock: LockFile;
  /** The secret used in the trust markers (CompileOptions.trustSecret). */
  trustSecret: string;
}

interface CacheMeta {
  url: string;
  etag?: string;
  lastModifiedHeader?: string;
  sha256: string;
  bytes: number;
  fetchedAt: string;
}

interface Downloaded {
  text: string;
  sha256: string;
  bytes: number;
  fetchedAt: string;
  lastModifiedHeader?: string;
}

class FetchError extends Error {}

// ---------------------------------------------------------------------------
// HTTP with cache
// ---------------------------------------------------------------------------

function cachePaths(url: string, dir: string): { text: string; meta: string } {
  const key = sha1(url);
  return { text: join(dir, `${key}.txt`), meta: join(dir, `${key}.json`) };
}

async function readCache(url: string, dir: string): Promise<{ meta: CacheMeta; body: Buffer } | null> {
  const p = cachePaths(url, dir);
  try {
    const [metaText, body] = await Promise.all([readFile(p.meta, 'utf8'), readFile(p.text)]);
    const meta = JSON.parse(metaText) as CacheMeta;
    // A truncated cache file (killed build) must not be trusted.
    if (sha256(body) !== meta.sha256) return null;
    return { meta, body };
  } catch {
    return null;
  }
}

function looksLikeHtml(text: string, contentType: string | null): boolean {
  if (contentType && /\btext\/html\b/i.test(contentType)) return true;
  const head = text.slice(0, 512).trimStart().toLowerCase();
  return head.startsWith('<!doctype') || head.startsWith('<html') || head.startsWith('<head') || head.startsWith('<?xml');
}

function decode(body: Uint8Array): string {
  return stripBom(new TextDecoder('utf-8').decode(body)).replace(/\r\n?/g, '\n');
}

async function readPackageVersion(): Promise<string> {
  try {
    return (await readJson<{ version: string }>(join(ROOT, 'package.json'))).version;
  } catch {
    return '0.0.0';
  }
}

/** Per-run de-duplication: a URL shared by several lists is fetched once. */
type Memo = Map<string, Promise<Downloaded>>;

async function download(url: string, ctx: { offline: boolean; log: Logger; cacheDir: string; memo: Memo }): Promise<Downloaded> {
  let p = ctx.memo.get(url);
  if (!p) {
    p = downloadUncached(url, ctx.offline, ctx.log, ctx.cacheDir);
    ctx.memo.set(url, p);
  }
  return p;
}

async function downloadUncached(url: string, offline: boolean, log: Logger, cacheDir: string): Promise<Downloaded> {
  const cached = await readCache(url, cacheDir);
  const fromCache = (c: { meta: CacheMeta; body: Buffer }): Downloaded => ({
    text: decode(c.body),
    sha256: c.meta.sha256,
    bytes: c.meta.bytes,
    fetchedAt: c.meta.fetchedAt,
    lastModifiedHeader: c.meta.lastModifiedHeader,
  });
  if (offline) {
    if (!cached) {
      throw new FetchError(`--offline: no cached copy of ${url}. Run "npm run fetch-lists" once with network access.`);
    }
    return fromCache(cached);
  }

  const ua = `BastionShield-build/${await readPackageVersion()} (+https://github.com/bastionsecurity-oss/bastion-shield)`;
  let lastError = '';
  let attempts = 0;
  for (let attempt = 0; attempt <= RETRIES; attempt++) {
    if (attempt > 0) await sleep(1000 * 2 ** (attempt - 1));
    attempts++;
    const headers: Record<string, string> = { 'user-agent': ua, accept: 'text/plain, */*;q=0.5' };
    if (cached?.meta.etag) headers['if-none-match'] = cached.meta.etag;
    if (cached?.meta.lastModifiedHeader) headers['if-modified-since'] = cached.meta.lastModifiedHeader;
    let res: Response;
    try {
      res = await fetch(url, { headers, redirect: 'follow', signal: AbortSignal.timeout(TIMEOUT_MS) });
    } catch (e) {
      lastError = `network error: ${(e as Error).message}`;
      continue;
    }
    if (res.status === 304 && cached) {
      await res.body?.cancel().catch(() => {});
      return fromCache(cached);
    }
    if (res.status === 429 || res.status >= 500) {
      lastError = `HTTP ${res.status}`;
      await res.body?.cancel().catch(() => {});
      continue;
    }
    if (!res.ok) {
      lastError = `HTTP ${res.status}`;
      await res.body?.cancel().catch(() => {});
      break; // 4xx: retrying will not help
    }
    let body: Buffer;
    try {
      body = Buffer.from(await res.arrayBuffer());
    } catch (e) {
      lastError = `read error: ${(e as Error).message}`;
      continue;
    }
    if (body.length > MAX_BYTES) throw new FetchError(`${url}: response larger than ${MAX_BYTES} bytes`);
    const text = decode(body);
    if (text.trim() === '') {
      lastError = 'empty response';
      continue;
    }
    if (looksLikeHtml(text, res.headers.get('content-type'))) {
      // Captive portals, CDN error pages and "list moved" pages are HTML.
      throw new FetchError(`${url}: refusing HTML response (content-type ${res.headers.get('content-type') ?? 'unknown'})`);
    }
    const meta: CacheMeta = {
      url,
      etag: res.headers.get('etag') ?? undefined,
      lastModifiedHeader: res.headers.get('last-modified') ?? undefined,
      sha256: sha256(body),
      bytes: body.length,
      fetchedAt: cached && cached.meta.sha256 === sha256(body) ? cached.meta.fetchedAt : new Date().toISOString(),
    };
    const p = cachePaths(url, cacheDir);
    await writeText(p.text, body);
    await writeJson(p.meta, meta, true);
    return { text, sha256: meta.sha256, bytes: meta.bytes, fetchedAt: meta.fetchedAt, lastModifiedHeader: meta.lastModifiedHeader };
  }
  if (cached) {
    log.warn(`${url}: ${lastError}; using cached copy from ${cached.meta.fetchedAt}`);
    return fromCache(cached);
  }
  throw new FetchError(`${url}: download failed after ${attempts} attempt(s) (${lastError})`);
}

async function readLocal(absPath: string): Promise<Downloaded> {
  const [body, st] = await Promise.all([readFile(absPath), stat(absPath)]);
  // mtime keeps lock.json stable between builds when the file did not change.
  return { text: decode(body), sha256: sha256(body), bytes: body.length, fetchedAt: st.mtime.toISOString() };
}

// ---------------------------------------------------------------------------
// Headers and includes
// ---------------------------------------------------------------------------

export function parseListHeaders(text: string): { version?: string; lastModified?: string } {
  const head = text.slice(0, 8192);
  const pick = (re: RegExp) => re.exec(head)?.[1]?.trim() || undefined;
  return {
    version: pick(/^!\s*Version:\s*(.+)$/im),
    lastModified:
      pick(/^!\s*Last modified:\s*(.+)$/im) ?? pick(/^!\s*Updated:\s*(.+)$/im) ?? pick(/^#\s*last updated:\s*(.+)$/im),
  };
}

interface ExpandContext {
  list: string;
  offline: boolean;
  log: Logger;
  cacheDir: string;
  memo: Memo;
  entries: LockEntry[];
  /** URLs already inlined in this list: duplicates are skipped like uBO does. */
  seen: Set<string>;
  /** For local sources: includes must stay inside this directory. */
  localRoot?: string;
}

/** Resolve an `!#include` target; returns null (with reason) when it is not allowed. */
export function resolveInclude(target: string, parentUrl: string): { url: string } | { error: string } {
  if (target.includes('..')) return { error: 'path traversal ("..") not allowed' };
  let parent: URL;
  let child: URL;
  try {
    parent = new URL(parentUrl);
    child = new URL(target, parent);
  } catch {
    return { error: 'invalid URL' };
  }
  if (child.origin !== parent.origin || child.protocol !== parent.protocol) {
    return { error: `cross-origin include (${child.origin}) not allowed` };
  }
  if (!/^(https?|file):$/.test(child.protocol)) return { error: `unsupported scheme ${child.protocol}` };
  // Same directory or below, as uBO does (relative to the parent's folder).
  const parentDir = parent.pathname.slice(0, parent.pathname.lastIndexOf('/') + 1);
  if (!child.pathname.startsWith(parentDir)) return { error: 'include outside the parent directory' };
  child.hash = '';
  return { url: child.href };
}

async function expandIncludes(text: string, parentUrl: string, depth: number, ctx: ExpandContext): Promise<string> {
  if (!/^!#include\b/m.test(text)) return text;
  const lines = text.split('\n');
  const out: string[] = [];
  let ifDepth = 0;
  for (const line of lines) {
    const t = line.trim();
    if (/^!#if\b/.test(t)) ifDepth++;
    else if (/^!#endif\b/.test(t)) ifDepth = Math.max(0, ifDepth - 1);
    const m = /^!#include\s+(\S+)/.exec(t);
    if (!m) {
      out.push(line);
      continue;
    }
    const target = m[1];
    if (depth >= MAX_INCLUDE_DEPTH) {
      ctx.log.warn(`${ctx.list}: include "${target}" in ${parentUrl} exceeds max depth ${MAX_INCLUDE_DEPTH}; skipped`);
      out.push(`! [bastion] include skipped (max depth): ${target}`);
      continue;
    }
    const r = resolveInclude(target, parentUrl);
    if ('error' in r) {
      ctx.log.warn(`${ctx.list}: include "${target}" in ${parentUrl}: ${r.error}; skipped`);
      out.push(`! [bastion] include skipped (${r.error}): ${target}`);
      continue;
    }
    if (ctx.seen.has(r.url)) {
      out.push(`! [bastion] include already inlined: ${r.url}`);
      continue;
    }
    ctx.seen.add(r.url);
    let dl: Downloaded;
    let lockUrl = r.url;
    try {
      if (r.url.startsWith('file:')) {
        const abs = fileURLToPath(r.url);
        if (!ctx.localRoot || !abs.startsWith(ctx.localRoot + sep)) {
          throw new FetchError('local include outside the list directory');
        }
        dl = await readLocal(abs);
        lockUrl = rel(abs);
      } else {
        dl = await download(r.url, ctx);
      }
    } catch (e) {
      // An include inside an `!#if` block may legitimately be unavailable on
      // our platform; a top-level include is part of the list and must exist.
      if (ifDepth > 0) {
        ctx.log.warn(`${ctx.list}: conditional include ${r.url} failed (${(e as Error).message}); skipped`);
        out.push(`! [bastion] include failed: ${r.url}`);
        continue;
      }
      throw e;
    }
    const hdr = parseListHeaders(dl.text);
    ctx.entries.push({
      list: ctx.list,
      url: lockUrl,
      sha256: dl.sha256,
      bytes: dl.bytes,
      version: hdr.version,
      lastModified: hdr.lastModified ?? dl.lastModifiedHeader,
      fetchedAt: dl.fetchedAt,
      includedFrom: parentUrl.startsWith('file:') ? rel(fileURLToPath(parentUrl)) : parentUrl,
    });
    const expanded = await expandIncludes(dl.text, r.url, depth + 1, ctx);
    out.push(`! >>> include: ${lockUrl}`, expanded.replace(/\n+$/, ''), `! <<< include: ${lockUrl}`);
  }
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// Trust markers
// ---------------------------------------------------------------------------

/** A `!#trusted` directive line, whatever its arguments (uBO syntax: `!#trusted on|off`). */
const TRUSTED_DIRECTIVE = /^[ \t]*!#trusted\b.*$/gm;
/** Secrets are plain tokens so they survive the compiler's whitespace split. */
const SECRET_RE = /^[A-Za-z0-9._~-]{16,128}$/;

export function newTrustSecret(): string {
  return randomBytes(16).toString('hex');
}

/**
 * Remove every `!#trusted` directive from upstream text. Each one becomes a
 * comment of its own, so line numbers stay stable. A list can therefore never
 * switch trust on (or forge our markers).
 */
export function stripTrustDirectives(text: string, format: 'abp' | 'hosts' = 'abp'): string {
  if (!text.includes('!#trusted')) return text;
  const comment = format === 'hosts' ? '# [bastion] upstream trust directive removed' : '! [bastion] upstream trust directive removed';
  return text.replace(TRUSTED_DIRECTIVE, comment);
}

/**
 * Close `!#if` blocks a source leaves open, so one source's conditionals
 * cannot swallow the lines (and trust markers) of the next source. uBO
 * evaluates every list file separately, so this matches its semantics.
 * Mirrors the compiler's preprocessor: directives start at column 0, and an
 * `!#endif` without an open block is a no-op.
 */
export function closeOpenConditionals(text: string): string {
  if (!text.includes('!#if')) return text;
  let depth = 0;
  for (const line of text.split('\n')) {
    if (/^!#if\b/.test(line)) depth++;
    else if (/^!#endif\b/.test(line)) depth = Math.max(0, depth - 1);
  }
  if (depth === 0) return text;
  const closers = Array.from({ length: depth }, () => '!#endif');
  return `${text.replace(/\n+$/, '')}\n! [bastion] closing ${depth} unclosed conditional block(s)\n${closers.join('\n')}`;
}

/** Wrap an untrusted part of a trusted list in the per-build trust markers. */
export function wrapUntrusted(text: string, secret: string): string {
  return `!#trusted off ${secret}\n${text.replace(/\n+$/, '')}\n!#trusted on ${secret}`;
}

// ---------------------------------------------------------------------------
// Lists
// ---------------------------------------------------------------------------

async function fetchList(
  list: CatalogList,
  offline: boolean,
  log: Logger,
  cacheDir: string,
  memo: Memo,
  trustSecret: string,
): Promise<FetchedList> {
  const ctx: ExpandContext = { list: list.id, offline, log, cacheDir, memo, entries: [], seen: new Set() };
  const parts: FetchedPart[] = [];
  for (const src of list.sources) {
    const format = src.format ?? 'abp';
    let dl: Downloaded;
    let url: string;
    let baseUrl: string;
    if (src.path) {
      const abs = resolve(ROOT, src.path);
      if (!abs.startsWith(ROOT + sep)) throw new FetchError(`${list.id}: local path ${src.path} escapes the repository`);
      if (!(await fileExists(abs))) throw new FetchError(`${list.id}: local source ${src.path} not found`);
      dl = await readLocal(abs);
      url = rel(abs);
      baseUrl = pathToFileURL(abs).href;
      ctx.localRoot = dirname(abs);
    } else if (src.url) {
      dl = await download(src.url, ctx);
      url = src.url;
      baseUrl = src.url;
    } else {
      throw new FetchError(`${list.id}: source without url or path`);
    }
    ctx.seen.add(baseUrl);
    const hdr = parseListHeaders(dl.text);
    ctx.entries.push({
      list: list.id,
      url,
      sha256: dl.sha256,
      bytes: dl.bytes,
      version: hdr.version,
      lastModified: hdr.lastModified ?? dl.lastModifiedHeader,
      fetchedAt: dl.fetchedAt,
    });
    // Hosts files have no include syntax; keep them byte-for-byte (the compiler has a hosts mode).
    let text = format === 'hosts' ? dl.text : await expandIncludes(dl.text, baseUrl, 0, ctx);
    text = stripTrustDirectives(text, format);
    if (format === 'hosts') {
      // Hosts entries are plain hostname blocks: they cannot use trusted
      // scriptlets or redirects, so they need no markers.
      parts.push({ url, format, text });
      continue;
    }
    text = closeOpenConditionals(text);
    if (list.trusted && src.trusted === false) {
      parts.push({ url, format, text: wrapUntrusted(text, trustSecret), trustedOff: true });
    } else {
      parts.push({ url, format, text });
    }
  }
  const formats = new Set(parts.map((p) => p.format));
  const format: FetchedList['format'] = formats.size === 1 ? [...formats][0] : 'mixed';
  const text = parts
    .map((p) => `${p.format === 'hosts' ? '#' : '!'} --- source: ${p.url}\n${p.text.replace(/\n+$/, '')}`)
    .join('\n') + '\n';
  return { listId: list.id, format, text, parts, sources: ctx.entries };
}

export async function loadCatalog(): Promise<Catalog> {
  const catalog = await readJson<Catalog>(CATALOG_FILE);
  if (catalog.version !== 1 || !Array.isArray(catalog.lists)) throw new Error('filters/catalog.json: unsupported format');
  const ids = new Set<string>();
  for (const l of catalog.lists) {
    if (!/^[a-z0-9-]+$/.test(l.id)) throw new Error(`catalog: invalid list id "${l.id}"`);
    if (ids.has(l.id)) throw new Error(`catalog: duplicate list id "${l.id}"`);
    ids.add(l.id);
  }
  return catalog;
}

export async function fetchLists(opts: FetchOptions = {}): Promise<FetchResult> {
  const log = opts.log ?? createLogger('fetch');
  const catalog = opts.catalog ?? (await loadCatalog());
  const offline = opts.offline === true;
  log.step(`Fetching ${catalog.lists.length} lists${offline ? ' (offline, cache only)' : ''}`);
  const t0 = Date.now();
  const cacheDir = opts.cacheDir ?? CACHE_DIR;
  const trustSecret = opts.trustSecret ?? newTrustSecret();
  if (!SECRET_RE.test(trustSecret)) throw new Error('fetchLists: trustSecret must be 16-128 characters of [A-Za-z0-9._~-]');
  const memo: Memo = new Map();
  const lists = await mapLimit(catalog.lists, CONCURRENCY, async (l) => {
    const fl = await fetchList(l, offline, log, cacheDir, memo, trustSecret);
    const bytes = fl.sources.reduce((a, s) => a + s.bytes, 0);
    log.info(`${l.id.padEnd(18)} ${String(fl.sources.length).padStart(2)} file(s) ${(bytes / 1024).toFixed(0).padStart(6)} KB`);
    return fl;
  });
  const lock: LockFile = { version: 1, sources: lists.flatMap((l) => l.sources) };
  const lockFile = opts.lockFile ?? LOCK_FILE;
  if (opts.writeLock !== false) await writeJson(lockFile, lock, true);
  // Keep the combined texts around: handy for debugging and for tools/compare-ubo.ts.
  for (const l of lists) await writeText(join(cacheDir, 'combined', `${l.listId}.txt`), l.text);
  const wrapped = lists.flatMap((l) => l.parts.filter((p) => p.trustedOff).map((p) => `${l.listId}: ${p.url}`));
  if (wrapped.length > 0) log.info(`untrusted sources in trusted lists (trust markers): ${wrapped.join(', ')}`);
  log.info(`done in ${((Date.now() - t0) / 1000).toFixed(1)} s${opts.writeLock !== false ? `, lock: ${rel(lockFile)}` : ''}`);
  return { lists, lock, trustSecret };
}

if (isMain(import.meta.url)) {
  const { flags } = parseArgs(process.argv.slice(2));
  const log = createLogger('fetch');
  try {
    await fetchLists({ offline: flags.has('offline'), log });
  } catch (e) {
    log.error((e as Error).message);
    process.exitCode = 1;
  }
}
