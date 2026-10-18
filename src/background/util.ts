// Bastion Shield service worker — small dependency-free helpers (LRU, stable
// JSON comparison, a debounced serial runner, URL and date helpers). Nothing
// here touches chrome.*, so every function is unit-testable under Node.
//
// SPDX-License-Identifier: GPL-3.0-or-later

/** Least-recently-used map with a fixed capacity (Map keeps insertion order). */
export class Lru<K, V> {
  private readonly map = new Map<K, V>();
  private readonly max: number;

  constructor(max: number) {
    this.max = Math.max(1, max);
  }

  get(key: K): V | undefined {
    const v = this.map.get(key);
    if (v === undefined) return undefined;
    // Refresh recency.
    this.map.delete(key);
    this.map.set(key, v);
    return v;
  }

  has(key: K): boolean {
    return this.map.has(key);
  }

  set(key: K, value: V): void {
    if (this.map.has(key)) this.map.delete(key);
    this.map.set(key, value);
    while (this.map.size > this.max) {
      const oldest = this.map.keys().next().value as K;
      this.map.delete(oldest);
    }
  }

  delete(key: K): void {
    this.map.delete(key);
  }

  clear(): void {
    this.map.clear();
  }

  get size(): number {
    return this.map.size;
  }
}

/**
 * JSON with object keys sorted and `undefined` members dropped, so two
 * structurally equal values always serialize the same way (Chrome returns
 * rules and registrations with keys in its own order).
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((v) => (v === undefined ? null : canonicalize(v)));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v === undefined) continue;
      out[key] = canonicalize(v);
    }
    return out;
  }
  return value;
}

export function deepEqual(a: unknown, b: unknown): boolean {
  return canonicalJson(a) === canonicalJson(b);
}

export function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === 'string') return e;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

export function chunk<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

export function uniqueSorted(items: Iterable<string>): string[] {
  return Array.from(new Set(items)).sort();
}

/** Local-time YYYY-MM-DD (history aggregates are per local day). */
export function dayKey(t: number): string {
  const d = new Date(t);
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${d.getFullYear()}-${m}-${day}`;
}

/** Local midnight `days` days before the day containing `t`. */
export function startOfDayOffset(t: number, days: number): number {
  const d = new Date(t);
  d.setHours(0, 0, 0, 0);
  d.setDate(d.getDate() - days);
  return d.getTime();
}

export function isDayKey(s: unknown): s is string {
  return typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s);
}

/** Parse a URL without throwing. */
export function parseUrl(url: string | undefined | null): URL | null {
  if (typeof url !== 'string' || url === '') return null;
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

/** Lower-case hostname of an http(s)/ws(s) URL, or null. */
export function webHostOf(url: string | undefined | null): string | null {
  const u = parseUrl(url);
  if (!u) return null;
  if (u.protocol !== 'http:' && u.protocol !== 'https:' && u.protocol !== 'ws:' && u.protocol !== 'wss:') return null;
  return u.hostname.toLowerCase() || null;
}

/** URL without query and fragment (history never stores them). */
export function stripQueryAndFragment(url: string): string {
  const q = url.search(/[?#]/);
  return q === -1 ? url : url.slice(0, q);
}

export function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max);
}

export interface Timers {
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

const defaultTimers: Timers = {
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (h) => clearTimeout(h as ReturnType<typeof setTimeout>),
};

export interface DebouncedRunner {
  /** Run the task after `delayMs` of quiet; resolves once a run that started after this call has finished. */
  schedule(delayMs?: number): Promise<void>;
  /** Like schedule() but without waiting for the quiet period. */
  now(): Promise<void>;
  /** True while a run is in progress or pending. */
  busy(): boolean;
}

/**
 * Debounced, strictly serial task runner. Runs never overlap; requests that
 * arrive during a run are coalesced into one follow-up run. The task's errors
 * are reported to `onError` and never reject the waiters.
 */
export function createDebouncedRunner(
  task: () => Promise<void>,
  defaultDelayMs: number,
  onError: (e: unknown) => void = () => {},
  timers: Timers = defaultTimers,
): DebouncedRunner {
  let waiters: (() => void)[] = [];
  let running = false;
  let timer: unknown = null;
  let nextDelay = defaultDelayMs;

  const arm = (delay: number): void => {
    if (running) {
      nextDelay = Math.min(nextDelay, delay);
      return;
    }
    if (timer !== null) {
      if (delay > 0) return; // keep the existing (shorter or equal) debounce
      timers.clearTimeout(timer);
    }
    timer = timers.setTimeout(run, delay);
  };

  const run = async (): Promise<void> => {
    timer = null;
    running = true;
    const batch = waiters;
    waiters = [];
    nextDelay = defaultDelayMs;
    try {
      await task();
    } catch (e) {
      try {
        onError(e);
      } catch {
        /* ignore */
      }
    }
    running = false;
    for (const w of batch) w();
    if (waiters.length > 0) arm(nextDelay);
  };

  const enqueue = (delay: number): Promise<void> =>
    new Promise<void>((resolve) => {
      waiters.push(resolve);
      arm(delay);
    });

  return {
    schedule: (delayMs = defaultDelayMs) => enqueue(delayMs),
    now: () => enqueue(0),
    busy: () => running || timer !== null,
  };
}

/** A promise that can be resolved from outside (used for the SW ready gate). */
export function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void } {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}
