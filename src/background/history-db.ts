// Bastion Shield service worker — IndexedDB blocking history (ARCHITECTURE §8):
// database `bastion-activity` with `events` (auto key, index `t`) and `daily`
// (keyPath `day`). Local only; pruned by retention via chrome.alarms.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { HISTORY_MAX_EVENTS, IDB } from '../shared/constants.ts';
import type { ActivityEvent, DailyAggregate } from '../shared/types.ts';
import { emptyDaily, mergeDaily } from './activity.ts';
import type { HistoryStore } from './activity.ts';
import * as log from './log.ts';

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error ?? new Error('IndexedDB request failed'));
  });
}

function done(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(tx.error ?? new Error('IndexedDB transaction aborted'));
    tx.onerror = () => reject(tx.error ?? new Error('IndexedDB transaction failed'));
  });
}

export interface EventQuery {
  limit: number;
  before?: number;
  site?: string;
  host?: string;
}

export class HistoryDb implements HistoryStore {
  private db: Promise<IDBDatabase> | null = null;
  private writesSinceCap = 0;

  private open(): Promise<IDBDatabase> {
    if (this.db) return this.db;
    this.db = new Promise<IDBDatabase>((resolve, reject) => {
      let r: IDBOpenDBRequest;
      try {
        r = indexedDB.open(IDB.NAME, IDB.VERSION);
      } catch (e) {
        reject(e);
        return;
      }
      r.onupgradeneeded = () => {
        const db = r.result;
        if (!db.objectStoreNames.contains(IDB.STORE_EVENTS)) {
          const s = db.createObjectStore(IDB.STORE_EVENTS, { autoIncrement: true });
          s.createIndex('t', 't');
        }
        if (!db.objectStoreNames.contains(IDB.STORE_DAILY)) db.createObjectStore(IDB.STORE_DAILY, { keyPath: 'day' });
      };
      r.onsuccess = () => {
        const db = r.result;
        // Another context upgrading the schema: let it, reopen on next use.
        db.onversionchange = () => {
          db.close();
          this.db = null;
        };
        resolve(db);
      };
      r.onerror = () => reject(r.error ?? new Error('IndexedDB open failed'));
      r.onblocked = () => log.warn('history', 'open blocked');
    });
    this.db.catch(() => {
      this.db = null;
    });
    return this.db;
  }

  private mergeDailyInTx(store: IDBObjectStore, deltas: readonly DailyAggregate[]): void {
    for (const delta of deltas) {
      const g = store.get(delta.day);
      g.onsuccess = () => {
        const cur = (g.result as DailyAggregate | undefined) ?? emptyDaily(delta.day);
        store.put(mergeDaily(cur, delta));
      };
    }
  }

  async write(records: ActivityEvent[], dailyDeltas: DailyAggregate[]): Promise<number[]> {
    const db = await this.open();
    const tx = db.transaction([IDB.STORE_EVENTS, IDB.STORE_DAILY], 'readwrite');
    const events = tx.objectStore(IDB.STORE_EVENTS);
    const keys: number[] = new Array(records.length);
    records.forEach((rec, i) => {
      const r = events.add(rec);
      r.onsuccess = () => {
        keys[i] = r.result as number;
      };
    });
    this.mergeDailyInTx(tx.objectStore(IDB.STORE_DAILY), dailyDeltas);
    await done(tx);
    this.writesSinceCap += records.length;
    if (this.writesSinceCap >= 1000) {
      this.writesSinceCap = 0;
      void this.cap().catch((e: unknown) => log.warn('history', 'cap', e));
    }
    return keys;
  }

  async patch(updates: { key: number; record: ActivityEvent }[], dailyDeltas: DailyAggregate[]): Promise<void> {
    const db = await this.open();
    const tx = db.transaction([IDB.STORE_EVENTS, IDB.STORE_DAILY], 'readwrite');
    const events = tx.objectStore(IDB.STORE_EVENTS);
    for (const u of updates) {
      // Only overwrite records that still exist (pruning may have removed them).
      const g = events.getKey(u.key);
      g.onsuccess = () => {
        if (g.result !== undefined) events.put(u.record, u.key);
      };
    }
    this.mergeDailyInTx(tx.objectStore(IDB.STORE_DAILY), dailyDeltas);
    await done(tx);
  }

  async queryDaily(fromDay: string, toDay: string): Promise<DailyAggregate[]> {
    const db = await this.open();
    const tx = db.transaction(IDB.STORE_DAILY, 'readonly');
    const lo = fromDay <= toDay ? fromDay : toDay;
    const hi = fromDay <= toDay ? toDay : fromDay;
    const all = await req(tx.objectStore(IDB.STORE_DAILY).getAll(IDBKeyRange.bound(lo, hi)));
    return (all as DailyAggregate[]).sort((a, b) => (a.day < b.day ? -1 : 1));
  }

  async queryEvents(q: EventQuery): Promise<ActivityEvent[]> {
    const db = await this.open();
    const tx = db.transaction(IDB.STORE_EVENTS, 'readonly');
    const index = tx.objectStore(IDB.STORE_EVENTS).index('t');
    const range = typeof q.before === 'number' && Number.isFinite(q.before) ? IDBKeyRange.upperBound(q.before, true) : null;
    const limit = Math.max(1, Math.min(1000, Math.floor(q.limit) || 100));
    const out: ActivityEvent[] = [];
    await new Promise<void>((resolve, reject) => {
      const c = index.openCursor(range, 'prev');
      let scanned = 0;
      c.onsuccess = () => {
        const cur = c.result;
        if (!cur || out.length >= limit || scanned > 200_000) {
          resolve();
          return;
        }
        scanned++;
        const ev = cur.value as ActivityEvent;
        if ((!q.site || ev.site === q.site) && (!q.host || ev.host === q.host)) out.push(ev);
        cur.continue();
      };
      c.onerror = () => reject(c.error ?? new Error('cursor failed'));
    });
    return out;
  }

  /** Delete events older than `cutoffT` and aggregates before `cutoffDay`. */
  async prune(cutoffT: number, cutoffDay: string): Promise<void> {
    const db = await this.open();
    const tx = db.transaction([IDB.STORE_EVENTS, IDB.STORE_DAILY], 'readwrite');
    const index = tx.objectStore(IDB.STORE_EVENTS).index('t');
    const c = index.openKeyCursor(IDBKeyRange.upperBound(cutoffT, true));
    const events = tx.objectStore(IDB.STORE_EVENTS);
    c.onsuccess = () => {
      const cur = c.result;
      if (!cur) return;
      events.delete(cur.primaryKey);
      cur.continue();
    };
    tx.objectStore(IDB.STORE_DAILY).delete(IDBKeyRange.upperBound(cutoffDay, true));
    await done(tx);
    await this.cap();
  }

  /** Keep at most HISTORY_MAX_EVENTS events (oldest dropped first). */
  async cap(max = HISTORY_MAX_EVENTS): Promise<void> {
    const db = await this.open();
    const count = await req(db.transaction(IDB.STORE_EVENTS, 'readonly').objectStore(IDB.STORE_EVENTS).count());
    let excess = count - max;
    if (excess <= 0) return;
    const tx = db.transaction(IDB.STORE_EVENTS, 'readwrite');
    const store = tx.objectStore(IDB.STORE_EVENTS);
    const c = store.index('t').openKeyCursor();
    c.onsuccess = () => {
      const cur = c.result;
      if (!cur || excess <= 0) return;
      store.delete(cur.primaryKey);
      excess--;
      cur.continue();
    };
    await done(tx);
  }

  async clear(): Promise<void> {
    const db = await this.open();
    const tx = db.transaction([IDB.STORE_EVENTS, IDB.STORE_DAILY], 'readwrite');
    tx.objectStore(IDB.STORE_EVENTS).clear();
    tx.objectStore(IDB.STORE_DAILY).clear();
    await done(tx);
  }
}
