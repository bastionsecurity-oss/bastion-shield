// Bastion Shield service worker — imported filter lists ("My lists"). Users
// add a list from a .txt file or from an https address; it is stored in
// chrome.storage.local and compiled at runtime like the user's own filters
// (custom.ts): network filters become dynamic rules in the list's id slot,
// cosmetic filters are served by cosmetic.ts, scriptlets are counted and
// ignored. Web-address lists can refetch themselves about once a day
// (conditional requests, so an unchanged list costs one small response).
// Nothing is downloaded unless the user added a web address.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { MY_LISTS, STORAGE } from '../shared/constants.ts';
import { listTitle, parseListTitle } from '../shared/list-title.ts';
import type { MyListMeta } from '../shared/types.ts';
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
  const hasRule = text.split(/\r?\n/).some((l) => {
    const t = l.trim();
    return t !== '' && !t.startsWith('!') && !t.startsWith('#') && !t.startsWith('[');
  });
  return hasRule ? null : 'empty';
}

/**
 * Filter lines in a list (what the user thinks of as "filters"): not blank,
 * not a `!` or `[` comment and not a `#` comment of hosts files. Cosmetic
 * filters (`##`, `#@#`, `#?#`, `#$#`, `#%#`) count. The DNR rule count is
 * much smaller: host filters merge into one rule.
 */
export function countFilterLines(text: string): number {
  let n = 0;
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (t === '' || t.startsWith('!') || t.startsWith('[')) continue;
    if (t.startsWith('#') && !/^#(@?#|[?$%]#|@[?$%]#)/.test(t)) continue;
    n++;
  }
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

  /** Changes are applied one at a time (a daily update must not race a user's upload). */
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
  enabled(): { id: string; slot: number; text: string }[] {
    return this.lists
      .filter((l) => l.enabled)
      .sort((a, b) => a.slot - b.slot)
      .map((l) => ({ id: l.id, slot: l.slot, text: this.text(l.id) }));
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

  add(input: AddInput, replaceId?: string): Promise<{ list: MyListMeta } | { error: MyListError; detail?: string }> {
    return this.serial(async () => {
      if (replaceId !== undefined) return this.replaceNow(replaceId, input);
      if (this.lists.length >= MY_LISTS.MAX) return { error: 'too-many' as const };
      const slot = freeSlot(this.lists);
      if (slot < 0) return { error: 'too-many' as const };
      const now = this.deps.now();
      let id = newListId(this.deps.random);
      while (this.get(id)) id = newListId(this.deps.random);
      if (input.file) {
        const bad = checkListText(input.file.text);
        if (bad) return { error: bad };
        const meta: MyListMeta = {
          id,
          slot,
          title: listTitle(input.file.text, input.file.name),
          source: 'file',
          fileName: input.file.name.slice(0, 255),
          enabled: true,
          autoUpdate: false,
          added: now,
          updated: now,
          checked: now,
          bytes: input.file.text.length,
        };
        await this.deps.storage.set({ [textKey(id)]: input.file.text });
        this.texts.set(id, input.file.text);
        this.lists.push(meta);
        await this.writeIndex();
        return { list: { ...meta } };
      }
      const url = normalizeListUrl(input.url);
      if (!url) return { error: 'invalid-url' as const };
      if (this.lists.some((l) => l.url === url)) return { error: 'duplicate-url' as const };
      const got = await fetchList(this.deps.fetch, url);
      if (got.status !== 'ok') return got.status === 'error' ? { error: got.code, detail: got.detail } : { error: 'fetch-failed' as const };
      const bad = checkListText(got.text);
      if (bad) return { error: bad };
      const meta: MyListMeta = {
        id,
        slot,
        title: listTitle(got.text, urlLabel(url)),
        source: 'url',
        url,
        enabled: true,
        autoUpdate: true,
        added: now,
        updated: now,
        checked: now,
        bytes: got.text.length,
      };
      if (got.etag) meta.etag = got.etag;
      if (got.lastModified) meta.lastModified = got.lastModified;
      await this.deps.storage.set({ [textKey(id)]: got.text });
      this.texts.set(id, got.text);
      this.lists.push(meta);
      await this.writeIndex();
      return { list: { ...meta } };
    });
  }

  /**
   * Replace a list's contents, keeping its id, slot, title and on/off state.
   * A file replaces a web-address list's contents and turns it into a file
   * list (it no longer updates itself); a web address re-points the list.
   */
  private async replaceNow(id: string, input: AddInput): Promise<{ list: MyListMeta } | { error: MyListError; detail?: string }> {
    const l = this.get(id);
    if (!l) return { error: 'not-found' };
    const now = this.deps.now();
    let text: string;
    if (input.file) {
      text = input.file.text;
      const bad = checkListText(text);
      if (bad) return { error: bad };
      l.source = 'file';
      l.fileName = input.file.name.slice(0, 255);
      delete l.url;
      delete l.etag;
      delete l.lastModified;
      l.autoUpdate = false;
    } else {
      const url = normalizeListUrl(input.url);
      if (!url) return { error: 'invalid-url' };
      if (this.lists.some((o) => o.id !== id && o.url === url)) return { error: 'duplicate-url' };
      const got = await fetchList(this.deps.fetch, url);
      if (got.status !== 'ok') return got.status === 'error' ? { error: got.code, detail: got.detail } : { error: 'fetch-failed' };
      text = got.text;
      const bad = checkListText(text);
      if (bad) return { error: bad };
      l.source = 'url';
      l.url = url;
      delete l.fileName;
      delete l.etag;
      delete l.lastModified;
      if (got.etag) l.etag = got.etag;
      if (got.lastModified) l.lastModified = got.lastModified;
      l.autoUpdate = true;
    }
    l.updated = now;
    l.checked = now;
    l.bytes = text.length;
    delete l.error;
    await this.deps.storage.set({ [textKey(id)]: text });
    this.texts.set(id, text);
    await this.writeIndex();
    return { list: { ...l } };
  }

  set(id: string, patch: { enabled?: boolean; autoUpdate?: boolean }): Promise<{ list: MyListMeta } | { error: MyListError }> {
    return this.serial(async () => {
      const l = this.get(id);
      if (!l) return { error: 'not-found' as const };
      if (typeof patch.enabled === 'boolean') l.enabled = patch.enabled;
      if (typeof patch.autoUpdate === 'boolean' && l.source === 'url') l.autoUpdate = patch.autoUpdate;
      await this.writeIndex();
      return { list: { ...l } };
    });
  }

  remove(id: string): Promise<{ ok: true } | { error: MyListError }> {
    return this.serial(async () => {
      const i = this.lists.findIndex((l) => l.id === id);
      if (i < 0) return { error: 'not-found' as const };
      this.lists.splice(i, 1);
      this.texts.delete(id);
      await this.writeIndex();
      await log.attempt('mylists', () => this.deps.storage.remove([textKey(id)]));
      return { ok: true as const };
    });
  }

  /** Download one web-address list now. `changed` is true when its contents changed. */
  update(id: string): Promise<{ list: MyListMeta; changed: boolean } | { error: MyListError; detail?: string }> {
    return this.serial(() => this.updateNow(id));
  }

  private async updateNow(id: string): Promise<{ list: MyListMeta; changed: boolean } | { error: MyListError; detail?: string }> {
    const l = this.get(id);
    if (!l) return { error: 'not-found' };
    if (l.source !== 'url' || !l.url) return { error: 'invalid-url' };
    const now = this.deps.now();
    const got = await fetchList(this.deps.fetch, l.url, { etag: l.etag, lastModified: l.lastModified });
    l.checked = now;
    let changed = false;
    if (got.status === 'error') {
      l.error = `${got.code}: ${got.detail}`.slice(0, 300);
    } else if (got.status === 'unchanged') {
      delete l.error;
    } else {
      const bad = checkListText(got.text);
      if (bad) {
        l.error = bad;
      } else {
        delete l.error;
        if (got.etag) l.etag = got.etag;
        else delete l.etag;
        if (got.lastModified) l.lastModified = got.lastModified;
        else delete l.lastModified;
        if (got.text !== this.text(id)) {
          changed = true;
          l.updated = now;
          l.bytes = got.text.length;
          await this.deps.storage.set({ [textKey(id)]: got.text });
          this.texts.set(id, got.text);
        }
      }
    }
    await this.writeIndex();
    return got.status === 'error' ? { error: got.code, detail: got.detail } : { list: { ...l }, changed };
  }

  /** Daily alarm: refetch every list that is due. True when any list's contents changed. */
  updateDue(): Promise<boolean> {
    return this.serial(async () => {
      const now = this.deps.now();
      let changed = false;
      for (const l of this.lists.filter((x) => isUpdateDue(x, now))) {
        const r = await this.updateNow(l.id);
        if ('changed' in r && r.changed) changed = true;
      }
      return changed;
    });
  }
}
