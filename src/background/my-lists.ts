// Bastion Shield service worker — imported filter lists ("My lists"). Users
// add a list from a .txt file or from an https address; it is stored in
// chrome.storage.local and compiled at runtime like the user's own filters
// (custom.ts), except that `@@…$important` is refused: network filters become
// dynamic rules in the list's id slot, cosmetic filters are served by
// cosmetic.ts, scriptlets are counted and ignored. The compiled form is
// stored too, so a restarted worker does not recompile megabytes of filters.
// Web-address lists can refetch themselves about once a day
// (conditional requests, so an unchanged list costs one small response).
// Nothing is downloaded unless the user added a web address.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { MY_LISTS, STORAGE } from '../shared/constants.ts';
import { listTitle, parseListTitle } from '../shared/list-title.ts';
import type { MyListMeta } from '../shared/types.ts';
import type { CompiledCustom } from '../compiler/types.ts';
import type { MyListInput } from './custom.ts';
import * as log from './log.ts';
import { canonicalJson, errMsg, isPlainObject } from './util.ts';

/** Error codes returned to the dashboard (it shows a localised text for each). */
export type MyListError = 'locked' | 'not-found' | 'too-many' | 'too-large' | 'empty' | 'not-a-list' | 'invalid-url' | 'duplicate-url' | 'fetch-failed';

const ID_RE = /^[a-z0-9]{10}$/;

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

export { listTitle, parseListTitle };

/** Readable name for a web address: host and last path segment. */
export function urlLabel(url: string): string {
  try {
    const u = new URL(url);
    const last = u.pathname.split('/').filter(Boolean).pop() ?? '';
    return last ? `${u.hostname} › ${decodeURIComponent(last)}` : u.hostname;
  } catch {
    return url;
  }
}

/** https only, no credentials, bounded length. Returns the normalised address or null. */
export function normalizeListUrl(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  const s = input.trim();
  if (s === '' || s.length > MY_LISTS.MAX_URL_LENGTH) return null;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || u.username !== '' || u.password !== '' || u.hostname === '') return null;
  u.hash = '';
  return u.href;
}

/**
 * Does `text` look like a filter list? Rejects empty files, binary data and
 * HTML pages (a wrong address often answers with an HTML error or login page).
 */
export function checkListText(text: string): MyListError | null {
  if (text.length > MY_LISTS.MAX_BYTES) return 'too-large';
  if (text.includes('\u0000')) return 'not-a-list';
  const head = text.slice(0, 2048).replace(/^﻿/, '').trimStart().toLowerCase();
  if (head.startsWith('<!doctype') || head.startsWith('<html') || head.startsWith('<?xml') || head.startsWith('{')) return 'not-a-list';
  return text.split(/\r?\n/).some(isFilterLine) ? null : 'empty';
}

/**
 * A filter line (what the user thinks of as "a filter"): not blank, not a `!`
 * or `[` comment and not a `#` comment of hosts files. Cosmetic filters
 * (`##`, `#@#`, `#?#`, `#$#`, `#%#`) are filters.
 */
function isFilterLine(line: string): boolean {
  const t = line.trim();
  if (t === '' || t.startsWith('!') || t.startsWith('[')) return false;
  return !t.startsWith('#') || /^#(@?#|[?$%]#|@[?$%]#)/.test(t);
}

/** Filter lines in a list (isFilterLine). The DNR rule count is much smaller: host filters merge into one rule. */
export function countFilterLines(text: string): number {
  let n = 0;
  for (const line of text.split(/\r?\n/)) if (isFilterLine(line)) n++;
  return n;
}

/** The lowest slot no list uses, or -1 when all MY_LISTS.MAX are taken. */
export function freeSlot(lists: readonly Pick<MyListMeta, 'slot'>[]): number {
  const used = new Set(lists.map((l) => l.slot));
  for (let i = 0; i < MY_LISTS.MAX; i++) if (!used.has(i)) return i;
  return -1;
}

/** The list with the same title (case-insensitive), if any: the dashboard asks "replace or add?". */
export function sameTitle(lists: readonly MyListMeta[], title: string): MyListMeta | undefined {
  const want = title.trim().toLowerCase();
  return lists.find((l) => l.title.trim().toLowerCase() === want);
}

/** A web-address list is refetched when auto-update is on and the last attempt is a day old. */
export function isUpdateDue(l: MyListMeta, now: number): boolean {
  return l.source === 'url' && l.autoUpdate && l.enabled && now - l.checked >= MY_LISTS.UPDATE_AFTER_MS;
}

function str(v: unknown, max: number): string | undefined {
  return typeof v === 'string' && v !== '' ? v.slice(0, max) : undefined;
}
function num(v: unknown): number {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0;
}

/** Tolerant read of the stored index: broken entries and duplicate ids or slots are dropped. */
export function sanitizeMyLists(raw: unknown): MyListMeta[] {
  if (!Array.isArray(raw)) return [];
  const out: MyListMeta[] = [];
  const ids = new Set<string>();
  const slots = new Set<number>();
  for (const r of raw) {
    if (!isPlainObject(r)) continue;
    const id = r.id;
    const slot = r.slot;
    if (typeof id !== 'string' || !ID_RE.test(id) || ids.has(id)) continue;
    if (typeof slot !== 'number' || !Number.isInteger(slot) || slot < 0 || slot >= MY_LISTS.MAX || slots.has(slot)) continue;
    const source = r.source === 'url' ? 'url' : 'file';
    const url = source === 'url' ? normalizeListUrl(r.url) : null;
    if (source === 'url' && !url) continue;
    const m: MyListMeta = {
      id,
      slot,
      title: str(r.title, MY_LISTS.MAX_TITLE_LENGTH) ?? 'List',
      source,
      enabled: r.enabled !== false,
      autoUpdate: source === 'url' && r.autoUpdate !== false,
      added: num(r.added),
      updated: num(r.updated),
      checked: num(r.checked),
      bytes: num(r.bytes),
    };
    if (url) m.url = url;
    const fileName = str(r.fileName, 255);
    if (fileName && source === 'file') m.fileName = fileName;
    const error = str(r.error, 300);
    if (error) m.error = error;
    const etag = str(r.etag, 300);
    if (etag) m.etag = etag;
    const lastModified = str(r.lastModified, 100);
    if (lastModified) m.lastModified = lastModified;
    ids.add(id);
    slots.add(slot);
    out.push(m);
    if (out.length >= MY_LISTS.MAX) break;
  }
  return out;
}

export function textKey(id: string): string {
  return `${STORAGE.MY_LIST_PREFIX}${id}`;
}

export function newListId(random: () => number = Math.random): string {
  const abc = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let s = '';
  for (let i = 0; i < 10; i++) s += abc[Math.floor(random() * abc.length) % abc.length];
  return s;
}

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------

export type FetchResult =
  | { status: 'ok'; text: string; etag?: string; lastModified?: string }
  | { status: 'unchanged' }
  | { status: 'error'; code: MyListError; detail: string };

export type FetchFn = (url: string, init: RequestInit) => Promise<Response>;

/**
 * Download a list: no cookies or credentials, conditional when we have a
 * validator, at most MY_LISTS.MAX_BYTES (stops reading beyond that).
 */
export async function fetchList(fetchFn: FetchFn, url: string, prev: { etag?: string; lastModified?: string } = {}, timeoutMs = 60_000): Promise<FetchResult> {
  const headers: Record<string, string> = { Accept: 'text/plain, */*;q=0.5' };
  if (prev.etag) headers['If-None-Match'] = prev.etag;
  if (prev.lastModified) headers['If-Modified-Since'] = prev.lastModified;
  const ctrl = typeof AbortController === 'function' ? new AbortController() : null;
  const timer = ctrl ? setTimeout(() => ctrl.abort(), timeoutMs) : undefined;
  try {
    const res = await fetchFn(url, { headers, credentials: 'omit', cache: 'no-cache', redirect: 'follow', referrerPolicy: 'no-referrer', signal: ctrl?.signal });
    if (res.status === 304) return { status: 'unchanged' };
    if (!res.ok) return { status: 'error', code: 'fetch-failed', detail: `HTTP ${res.status}` };
    if (res.url && !res.url.startsWith('https:')) return { status: 'error', code: 'invalid-url', detail: 'redirected to a non-https address' };
    const len = Number(res.headers.get('content-length'));
    if (Number.isFinite(len) && len > MY_LISTS.MAX_BYTES) return { status: 'error', code: 'too-large', detail: `${len} bytes` };
    const text = await readCapped(res, MY_LISTS.MAX_BYTES);
    if (text === null) return { status: 'error', code: 'too-large', detail: `more than ${MY_LISTS.MAX_BYTES} bytes` };
    const out: FetchResult = { status: 'ok', text };
    const etag = res.headers.get('etag');
    const lm = res.headers.get('last-modified');
    if (etag) out.etag = etag;
    if (lm) out.lastModified = lm;
    return out;
  } catch (e) {
    return { status: 'error', code: 'fetch-failed', detail: errMsg(e) };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function readCapped(res: Response, max: number): Promise<string | null> {
  const body = res.body;
  if (!body || typeof body.getReader !== 'function') {
    const t = await res.text();
    return t.length > max ? null : t;
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      void reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.byteLength;
  }
  return new TextDecoder('utf-8').decode(all);
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export interface MyListsStorage {
  get(keys: string[]): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string[]): Promise<void>;
}

export interface MyListsDeps {
  storage: MyListsStorage;
  fetch: FetchFn;
  now(): number;
  random?: () => number;
}

export type AddInput = { file: { name: string; text: string }; url?: undefined } | { url: string; file?: undefined };

export class MyListsService {
  private lists: MyListMeta[] = [];
  private texts = new Map<string, string>();
  /** canonicalJson of index values this instance wrote whose storage echo is still due. */
  private ownWrites: string[] = [];
  /** Bumped on every change, so compile caches know when to rebuild. */
  version = 0;
  private readonly deps: MyListsDeps;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(deps: MyListsDeps) {
    this.deps = deps;
  }

  /**
   * Changes are applied one at a time (a daily update must not race a user's
   * upload). Downloads happen before, outside the queue: a slow server never
   * holds up switching or removing lists.
   */
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const p = this.queue.then(fn, fn);
    this.queue = p.catch(() => undefined);
    return p;
  }

  async load(): Promise<void> {
    const idx = await log.attempt('mylists', () => this.deps.storage.get([STORAGE.MY_LISTS]), {} as Record<string, unknown>);
    this.lists = sanitizeMyLists(idx[STORAGE.MY_LISTS]);
    const keys = this.lists.map((l) => textKey(l.id));
    const texts = keys.length ? await log.attempt('mylists', () => this.deps.storage.get(keys), {} as Record<string, unknown>) : {};
    this.texts.clear();
    for (const l of this.lists) {
      const t = texts[textKey(l.id)];
      this.texts.set(l.id, typeof t === 'string' ? t : '');
    }
    this.version++;
  }

  all(): MyListMeta[] {
    return this.lists.map((l) => ({ ...l }));
  }

  get(id: string): MyListMeta | undefined {
    return this.lists.find((l) => l.id === id);
  }

  text(id: string): string {
    return this.texts.get(id) ?? '';
  }

  private counts = new Map<string, { text: string; n: number }>();

  /** countFilterLines of a list, cached until its text changes. */
  filterCount(id: string): number {
    const text = this.text(id);
    const hit = this.counts.get(id);
    if (hit && hit.text === text) return hit.n;
    const n = countFilterLines(text);
    this.counts.set(id, { text, n });
    return n;
  }

  /** Lists whose filters apply (enabled), in slot order, with their text. */
  enabled(): MyListInput[] {
    return this.lists
      .filter((l) => l.enabled)
      .sort((a, b) => a.slot - b.slot)
      .map((l) => ({ id: l.id, slot: l.slot, text: this.text(l.id), stamp: textStamp(l) }));
  }

  /**
   * Compiled copies of the enabled lists saved by saveCompiled() that still
   * match their text and `build` (extension version and build meta): a
   * restarted worker reuses them instead of recompiling megabytes of filters.
   */
  async loadCompiled(build: string): Promise<{ input: MyListInput; compiled: CompiledCustom }[]> {
    const inputs = this.enabled();
    if (inputs.length === 0) return [];
    const got = await log.attempt('mylists', () => this.deps.storage.get(inputs.map((l) => compiledKey(l.id))), {} as Record<string, unknown>);
    const out: { input: MyListInput; compiled: CompiledCustom }[] = [];
    for (const input of inputs) {
      const rec = got[compiledKey(input.id)];
      if (!isPlainObject(rec) || rec.s !== `${build}|${input.stamp}` || typeof rec.c !== 'string') continue;
      try {
        const c = JSON.parse(rec.c) as unknown;
        if (isCompiledCustom(c)) out.push({ input, compiled: c });
      } catch {
        // a damaged copy is recompiled
      }
    }
    return out;
  }

  /** Persist a list's compiled form (custom.ts calls this after every compile of an imported list). */
  async saveCompiled(input: MyListInput, build: string, compiled: CompiledCustom): Promise<void> {
    if (input.stamp === undefined || !this.get(input.id)) return;
    // A JSON string: one value is much faster to read back than the object tree.
    const rec = { s: `${build}|${input.stamp}`, c: JSON.stringify(compiled) };
    await log.attempt('mylists', () => this.deps.storage.set({ [compiledKey(input.id)]: rec }));
  }

  /**
   * storage.onChanged: another instance (the incognito worker) changed the
   * index. True when reloaded. Every change rewrites the index, so text keys
   * alone are ignored; echoes of this instance's own index writes are
   * skipped, and the reload waits for any change in progress (it must not
   * read storage between a text write and the index write of an upload).
   */
  onStorageChanged(changes: Record<string, chrome.storage.StorageChange>): Promise<boolean> {
    const idx = changes[STORAGE.MY_LISTS];
    if (!idx) return Promise.resolve(false);
    const i = this.ownWrites.indexOf(canonicalJson(idx.newValue ?? []));
    if (i !== -1) {
      // Echoes arrive in write order: everything up to this one is settled.
      this.ownWrites.splice(0, i + 1);
      return Promise.resolve(false);
    }
    return this.serial(async () => {
      await this.load();
      return true;
    });
  }

  private async writeIndex(): Promise<void> {
    this.version++;
    this.ownWrites.push(canonicalJson(this.lists));
    if (this.ownWrites.length > 32) this.ownWrites.shift();
    await this.deps.storage.set({ [STORAGE.MY_LISTS]: this.lists });
  }

  /**
   * Store `next` (and its new text, if any) in place of the list with its id,
   * or as a new list. The text is written first and memory changes only once
   * it is stored, so a failed write never leaves metadata (validators, source)
   * describing contents that are not there.
   */
  private async commit(next: MyListMeta, text?: string): Promise<void> {
    if (text !== undefined) await this.deps.storage.set({ [textKey(next.id)]: text });
    const i = this.lists.findIndex((l) => l.id === next.id);
    if (i === -1) this.lists.push(next);
    else this.lists[i] = next;
    if (text !== undefined) this.texts.set(next.id, text);
    await this.writeIndex();
  }

  /** Why `url` cannot become (or replace) a list right now, if it cannot. */
  private urlProblem(url: string, replaceId: string | undefined): MyListError | null {
    if (replaceId !== undefined && !this.get(replaceId)) return 'not-found';
    if (this.lists.some((l) => l.id !== replaceId && l.url === url)) return 'duplicate-url';
    if (replaceId === undefined && freeSlot(this.lists) < 0) return 'too-many';
    return null;
  }

  /**
   * Add a list from a file or a web address, or replace the contents of
   * `replaceId`. Downloads run outside the change queue (they can take a
   * minute), so switching or removing lists never waits for one; the checks
   * are repeated when the result is stored.
   */
  async add(input: AddInput, replaceId?: string): Promise<{ list: MyListMeta } | { error: MyListError; detail?: string }> {
    let contents: Contents;
    if (input.file) {
      const bad = checkListText(input.file.text);
      if (bad) return { error: bad };
      contents = { source: 'file', text: input.file.text, fileName: input.file.name.slice(0, 255) };
    } else {
      const url = normalizeListUrl(input.url);
      if (!url) return { error: 'invalid-url' };
      const early = this.urlProblem(url, replaceId);
      if (early) return { error: early };
      const got = await fetchList(this.deps.fetch, url);
      if (got.status !== 'ok') return got.status === 'error' ? { error: got.code, detail: got.detail } : { error: 'fetch-failed' };
      const bad = checkListText(got.text);
      if (bad) return { error: bad };
      contents = { source: 'url', text: got.text, url, etag: got.etag, lastModified: got.lastModified };
    }
    return this.serial(() => (replaceId !== undefined ? this.replaceNow(replaceId, contents) : this.addNow(contents)));
  }

  private async addNow(c: Contents): Promise<{ list: MyListMeta } | { error: MyListError }> {
    if (c.source === 'url') {
      const problem = this.urlProblem(c.url, undefined);
      if (problem) return { error: problem };
    }
    const slot = freeSlot(this.lists);
    if (this.lists.length >= MY_LISTS.MAX || slot < 0) return { error: 'too-many' };
    const now = this.deps.now();
    let id = newListId(this.deps.random);
    while (this.get(id)) id = newListId(this.deps.random);
    const meta: MyListMeta = {
      id,
      slot,
      title: listTitle(c.text, c.source === 'file' ? c.fileName : urlLabel(c.url)),
      source: c.source,
      enabled: true,
      autoUpdate: c.source === 'url',
      added: now,
      updated: now,
      checked: now,
      bytes: c.text.length,
      ...sourceFields(c),
    };
    await this.commit(meta, c.text);
    return { list: { ...meta } };
  }

  /**
   * Replace a list's contents, keeping its id, slot, title and on/off state.
   * A file replaces a web-address list's contents and turns it into a file
   * list (it no longer updates itself); a web address re-points the list.
   */
  private async replaceNow(id: string, c: Contents): Promise<{ list: MyListMeta } | { error: MyListError }> {
    const l = this.get(id);
    if (!l) return { error: 'not-found' };
    if (c.source === 'url') {
      const problem = this.urlProblem(c.url, id);
      if (problem) return { error: problem };
    }
    const now = this.deps.now();
    const next: MyListMeta = { ...l, source: c.source, autoUpdate: c.source === 'url', updated: now, checked: now, bytes: c.text.length };
    delete next.url;
    delete next.fileName;
    delete next.etag;
    delete next.lastModified;
    delete next.error;
    Object.assign(next, sourceFields(c));
    await this.commit(next, c.text);
    return { list: { ...next } };
  }

  set(id: string, patch: { enabled?: boolean; autoUpdate?: boolean }): Promise<{ list: MyListMeta } | { error: MyListError }> {
    return this.serial(async () => {
      const l = this.get(id);
      if (!l) return { error: 'not-found' as const };
      const next: MyListMeta = { ...l };
      if (typeof patch.enabled === 'boolean') next.enabled = patch.enabled;
      if (typeof patch.autoUpdate === 'boolean' && l.source === 'url') next.autoUpdate = patch.autoUpdate;
      await this.commit(next);
      return { list: { ...next } };
    });
  }

  remove(id: string): Promise<{ ok: true } | { error: MyListError }> {
    return this.serial(async () => {
      const i = this.lists.findIndex((l) => l.id === id);
      if (i < 0) return { error: 'not-found' as const };
      this.lists.splice(i, 1);
      this.texts.delete(id);
      await this.writeIndex();
      await log.attempt('mylists', () => this.deps.storage.remove([textKey(id), compiledKey(id)]));
      return { ok: true as const };
    });
  }

  /** Download one web-address list now. `changed` is true when its contents changed. */
  async update(id: string): Promise<{ list: MyListMeta; changed: boolean } | { error: MyListError; detail?: string }> {
    const l = this.get(id);
    if (!l) return { error: 'not-found' };
    if (l.source !== 'url' || !l.url) return { error: 'invalid-url' };
    const url = l.url;
    const got = await fetchList(this.deps.fetch, url, { etag: l.etag, lastModified: l.lastModified });
    return this.serial(() => this.applyDownload(id, url, got));
  }

  /** Store the result of a download of `url` for list `id` (inside the change queue). */
  private async applyDownload(id: string, url: string, got: FetchResult): Promise<{ list: MyListMeta; changed: boolean } | { error: MyListError; detail?: string }> {
    const l = this.get(id);
    if (!l) return { error: 'not-found' };
    // Re-pointed or turned into a file list while it downloaded: the result is stale.
    if (l.source !== 'url' || l.url !== url) return { list: { ...l }, changed: false };
    const now = this.deps.now();
    const next: MyListMeta = { ...l, checked: now };
    let text: string | undefined;
    if (got.status === 'error') {
      next.error = `${got.code}: ${got.detail}`.slice(0, 300);
    } else if (got.status === 'unchanged') {
      delete next.error;
    } else {
      const bad = checkListText(got.text);
      if (bad) {
        next.error = bad;
      } else {
        delete next.error;
        delete next.etag;
        delete next.lastModified;
        if (got.etag) next.etag = got.etag;
        if (got.lastModified) next.lastModified = got.lastModified;
        if (got.text !== this.text(id)) {
          text = got.text;
          next.updated = now;
          next.bytes = got.text.length;
        }
      }
    }
    await this.commit(next, text);
    return got.status === 'error' ? { error: got.code, detail: got.detail } : { list: { ...next }, changed: text !== undefined };
  }

  private dueRun: Promise<boolean> | null = null;

  /**
   * Hourly alarm: refetch every list that is due, one download at a time and
   * outside the change queue. True when any list's contents changed. A call
   * while a run is in progress joins it.
   */
  updateDue(): Promise<boolean> {
    // Cleared in a later microtask, after the assignment (a run with nothing due finishes synchronously).
    this.dueRun ??= this.runDue().finally(() => {
      this.dueRun = null;
    });
    return this.dueRun;
  }

  private async runDue(): Promise<boolean> {
    let changed = false;
    for (const { id } of this.lists.filter((x) => isUpdateDue(x, this.deps.now()))) {
      // Look again: the user may have updated, re-pointed or removed it meanwhile.
      const l = this.get(id);
      if (!l || !l.url || !isUpdateDue(l, this.deps.now())) continue;
      const url = l.url;
      const got = await fetchList(this.deps.fetch, url, { etag: l.etag, lastModified: l.lastModified });
      try {
        const r = await this.serial(() => this.applyDownload(id, url, got));
        if ('changed' in r && r.changed) changed = true;
      } catch (e) {
        // Not stored (storage error): the list stays as it was and is due again next hour.
        log.warn('mylists', 'update', id, e);
      }
    }
    return changed;
  }
}

/** New contents for a list: a file, or a downloaded web address. */
type Contents =
  | { source: 'file'; text: string; fileName: string }
  | { source: 'url'; text: string; url: string; etag?: string; lastModified?: string };

/** The source fields of a list's metadata for `c` (fileName, or url and its validators). */
function sourceFields(c: Contents): Partial<MyListMeta> {
  if (c.source === 'file') return { fileName: c.fileName };
  const out: Partial<MyListMeta> = { url: c.url };
  if (c.etag) out.etag = c.etag;
  if (c.lastModified) out.lastModified = c.lastModified;
  return out;
}

/** Changes whenever a list's text does (every text change sets `updated`; `bytes` guards same-millisecond edits). */
function textStamp(l: MyListMeta): string {
  return `${l.updated}:${l.bytes}`;
}

export function compiledKey(id: string): string {
  return `${STORAGE.MY_LIST_COMPILED_PREFIX}${id}`;
}

function isCompiledCustom(v: unknown): v is CompiledCustom {
  return (
    isPlainObject(v) &&
    Array.isArray(v.rules) &&
    Array.isArray(v.specific) &&
    Array.isArray(v.generic) &&
    typeof v.scriptletsIgnored === 'number' &&
    Array.isArray(v.errors)
  );
}
