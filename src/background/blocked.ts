// Bastion Shield service worker — strict-block interstitial support
// (ARCHITECTURE §4.5). onBeforeRedirect tells us which URL a tab was about to
// open when DNR sent it to pages/blocked.html; the page asks for it
// ("blocked:info") and may ask to proceed. Proceeding is only possible to the
// host that was actually blocked in that tab: it adds a per-tab session
// `allow` for requests to that host and navigates the tab there. The record
// is forgotten on the tab's next top-level commit, so it never outlives the
// blocked page.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { RULE_ID } from '../shared/constants.ts';
import type { BuildMeta, MsgBlockedInfoResponse } from '../shared/types.ts';
import type { DnrRule } from '../compiler/types.ts';
import * as log from './log.ts';
import { buildProceedRule } from './rules.ts';
import { isDnrDomain } from './sites.ts';
import { isPlainObject, parseUrl } from './util.ts';

interface BlockedRecord {
  url: string;
  listId: string | null;
  t: number;
}

/** storage.session key holding every tab's record (a restarted worker must still answer the page). */
export const SESSION_RECORDS_KEY = 'blocked:records';
const MAX_RECORDS = 200;
const MAX_PROCEED_RULES = 1000;
export const BLOCKED_PAGE_PATH = '/pages/blocked.html';

/** Localized list name: UI language, then English. */
export function listName(meta: BuildMeta | null, listId: string | null, uiLang: string): string | null {
  if (!meta || !listId) return null;
  const l = meta.lists.find((x) => x.id === listId);
  if (!l) return null;
  const lang = uiLang.toLowerCase().slice(0, 2) as 'en' | 'de' | 'fr' | 'it';
  return l.name[lang] ?? l.name.en ?? listId;
}

/** Choose a free id in the proceed range. */
export function nextProceedId(existing: readonly number[]): number | null {
  const used = new Set(existing);
  for (let id = RULE_ID.SESSION_PROCEED_START; id <= RULE_ID.SESSION_PROCEED_END; id++) if (!used.has(id)) return id;
  return null;
}

/** True for a URL of our strict-block page (static or dynamic extension origin). */
export function isBlockedPageUrl(url: string | undefined): boolean {
  const u = parseUrl(url);
  return u !== null && (u.protocol === 'chrome-extension:' || u.protocol === 'extension:') && u.pathname === BLOCKED_PAGE_PATH;
}

/** Same host, compared case-insensitively; both must be http(s). */
export function sameBlockedHost(requested: string, recorded: string): boolean {
  const a = parseUrl(requested);
  const b = parseUrl(recorded);
  if (!a || !b) return false;
  const web = (u: URL) => u.protocol === 'http:' || u.protocol === 'https:';
  return web(a) && web(b) && a.hostname.toLowerCase() === b.hostname.toLowerCase();
}

function validRecord(v: unknown): v is BlockedRecord {
  return isPlainObject(v) && typeof v.url === 'string' && typeof v.t === 'number' && (v.listId === null || typeof v.listId === 'string');
}

export interface BlockedPagesDeps {
  meta(): BuildMeta | null;
  /** Resource types the browser knows (the proceed rule lists them all). */
  resourceTypes(): readonly string[];
}

export class BlockedPages {
  private readonly records = new Map<number, BlockedRecord>();
  private readonly deps: BlockedPagesDeps;
  private restored: Promise<void> | null = null;

  constructor(deps: BlockedPagesDeps) {
    this.deps = deps;
  }

  /** Load the records a previous worker instance persisted (memory wins). */
  restore(): Promise<void> {
    if (!this.restored) {
      this.restored = (async () => {
        const got = await log.attempt('blocked', () => chrome.storage.session.get(SESSION_RECORDS_KEY), {} as Record<string, unknown>);
        const raw = got[SESSION_RECORDS_KEY];
        if (!isPlainObject(raw)) return;
        for (const [k, v] of Object.entries(raw)) {
          const tabId = Number(k);
          if (Number.isInteger(tabId) && tabId >= 0 && validRecord(v) && !this.records.has(tabId)) this.records.set(tabId, v);
        }
      })();
    }
    return this.restored;
  }

  private persist(): void {
    void this.restore().then(() =>
      log.attempt('blocked', () => chrome.storage.session.set({ [SESSION_RECORDS_KEY]: Object.fromEntries(this.records) })),
    );
  }

  /** True while any tab has a blocked-page record (the commit listener must stay on). */
  hasRecords(): boolean {
    return this.records.size > 0;
  }

  /** Called synchronously from onBeforeRedirect. */
  record(tabId: number, url: string, listId: string | undefined): void {
    this.records.delete(tabId);
    this.records.set(tabId, { url, listId: listId ?? null, t: Date.now() });
    while (this.records.size > MAX_RECORDS) {
      const oldest = this.records.keys().next().value as number;
      this.records.delete(oldest);
    }
    this.persist();
  }

  /** Top-level commit in `tabId` that is not the blocked page: the record is stale. */
  forget(tabId: number): void {
    if (!this.records.delete(tabId)) return;
    this.persist();
  }

  private async lookup(tabId: number): Promise<BlockedRecord | null> {
    await this.restore();
    return this.records.get(tabId) ?? null;
  }

  async info(tabId: number, pageUrl: string | undefined): Promise<MsgBlockedInfoResponse> {
    const rec = await this.lookup(tabId);
    // The page's own ?list= parameter is the fallback when the redirect was not seen.
    const pageList = parseUrl(pageUrl)?.searchParams.get('list') ?? null;
    const listId = rec?.listId ?? pageList;
    const url = rec?.url ?? null;
    const host = parseUrl(url)?.hostname ?? null;
    const meta = this.deps.meta();
    const lang = (() => {
      try {
        return chrome.i18n.getUILanguage();
      } catch {
        return 'en';
      }
    })();
    const list = meta?.lists.find((l) => l.id === listId) ?? null;
    return {
      url,
      host,
      listId: listId ?? null,
      listName: listName(meta, listId, lang),
      category: list?.category ?? null,
    };
  }

  async proceed(tabId: number, url: string): Promise<{ ok: true } | { error: string }> {
    const u = parseUrl(url);
    if (!u || (u.protocol !== 'http:' && u.protocol !== 'https:')) return { error: 'invalid url' };
    // Only the navigation that was actually blocked in this tab may be allowed.
    const rec = await this.lookup(tabId);
    if (!rec) return { error: 'no blocked navigation' };
    if (!sameBlockedHost(url, rec.url)) return { error: 'url does not match the blocked navigation' };
    const host = u.hostname.toLowerCase();
    if (!isDnrDomain(host)) return { error: 'unsupported host' };
    const current = await log.attempt('blocked', () => chrome.declarativeNetRequest.getSessionRules(), [] as chrome.declarativeNetRequest.Rule[]);
    const proceedRules = current.filter((r) => isProceedRuleId(r.id));
    // Already allowed for this tab and host (current rule shape): just navigate.
    const existing = proceedRules.find(
      (r) => r.action.type === 'allow' && r.condition.tabIds?.includes(tabId) && r.condition.requestDomains?.includes(host),
    );
    if (!existing) {
      const removeRuleIds: number[] = [];
      if (proceedRules.length >= MAX_PROCEED_RULES) removeRuleIds.push(...proceedRules.slice(0, proceedRules.length - MAX_PROCEED_RULES + 1).map((r) => r.id));
      const id = nextProceedId(proceedRules.map((r) => r.id).filter((x) => !removeRuleIds.includes(x)));
      if (id === null) return { error: 'no free rule id' };
      const rule: DnrRule = buildProceedRule(id, host, tabId, this.deps.resourceTypes());
      try {
        await chrome.declarativeNetRequest.updateSessionRules({
          removeRuleIds,
          addRules: [rule as chrome.declarativeNetRequest.Rule],
        });
      } catch (e) {
        log.error('blocked', 'proceed rule', e);
        return { error: 'could not add allow rule' };
      }
    }
    this.forget(tabId);
    try {
      await chrome.tabs.update(tabId, { url: u.href });
    } catch (e) {
      log.warn('blocked', 'navigate', e);
      return { error: 'navigation failed' };
    }
    return { ok: true };
  }

  /** Tab closed: forget it and drop its proceed rules. */
  async onTabRemoved(tabId: number): Promise<void> {
    this.forget(tabId);
    const current = await log.attempt('blocked', () => chrome.declarativeNetRequest.getSessionRules(), [] as chrome.declarativeNetRequest.Rule[]);
    const ids = current.filter((r) => isProceedRuleId(r.id) && r.condition.tabIds?.includes(tabId)).map((r) => r.id);
    if (ids.length > 0) await log.attempt('blocked', () => chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids }));
  }
}

export function isProceedRuleId(id: number): boolean {
  return id >= RULE_ID.SESSION_PROCEED_START && id <= RULE_ID.SESSION_PROCEED_END;
}
