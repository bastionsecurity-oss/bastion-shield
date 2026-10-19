// Bastion Shield service worker — message router (ARCHITECTURE §7). Every
// message type in shared/types.ts is handled here. Senders are validated:
// only our own extension contexts are answered, content-script messages must
// come from a tab, strict-block messages from the top frame of
// pages/blocked.html, and UI messages from one of our extension pages. Every
// request gets a JSON reply; failures are `{error}`.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type {
  BackupFile,
  CustomState,
  EffectiveConfig,
  HistoryResult,
  ListsState,
  ManagedPolicy,
  Message,
  MyListsState,
  MsgNoticeClip,
  MsgNoticeShow,
  PopupState,
  Settings,
  SitesMap,
} from '../shared/types.ts';
import type { ActivityService } from './activity.ts';
import type { Applier } from './apply.ts';
import { badgeModeFor } from './apply.ts';
import type { BlockedPages } from './blocked.ts';
import type { CosmeticService, FrameSender } from './cosmetic.ts';
import { customReport } from './custom.ts';
import type { CustomCompiled } from './custom.ts';
import type { HistoryDb } from './history-db.ts';
import type { MyListsService } from './my-lists.ts';
import { MY_LISTS } from '../shared/constants.ts';
import type { NerdService } from './nerd.ts';
import * as log from './log.ts';
import { PROCEDURAL_SCRIPT_FILE } from './registrations.ts';
import { classifySender, isAllowed, isKnownType } from './sender.ts';
import type { SenderInfo } from './sender.ts';
import { applySettingsPatch, LOCK_ALL_LISTS, LOCK_CUSTOM_FILTERS, LOCK_MY_LISTS, normalizeSettings } from './settings.ts';
import { effectiveSites, isFilterableUrl, keepPolicyOwnedFields, normalizeSiteKey, patchSite, resolveSite, sanitizeSites, siteKeyFromUrl } from './sites.ts';
import type { Store } from './store.ts';
import { MAX_CUSTOM_FILTERS_BYTES } from './store.ts';
import { errMsg, isDayKey, isPlainObject, parseUrl } from './util.ts';

export interface MessageContext {
  store: Store;
  applier: Applier;
  cosmetic: CosmeticService;
  activity: ActivityService;
  blocked: BlockedPages;
  history: HistoryDb;
  nerd: NerdService;
  myLists: MyListsService;
  custom(): CustomCompiled;
  /** Recompile custom filters after the text or policy changed. */
  recompileCustom(): void;
  /** Called after history settings changed (prune now). */
  pruneHistory(): Promise<void>;
}

function frameSender(sender: SenderInfo): FrameSender {
  return {
    tabId: sender.tab?.id ?? -1,
    frameId: typeof sender.frameId === 'number' ? sender.frameId : 0,
    documentId: sender.documentId,
    url: sender.url,
    origin: sender.origin,
    tabUrl: sender.tab?.url,
  };
}

/** Longest blocked text forwarded to the top frame (content/notice-model.ts MAX_NOTICE_TEXT). */
const MAX_NOTICE_TEXT = 20_000;

/**
 * A subframe's blocker notice goes to the tab's top frame, where notices are
 * rendered (content/notice.ts). The top frame shows its own notices directly.
 */
function forwardNotice(msg: MsgNoticeClip, sender: SenderInfo): { ok: true } | { error: string } {
  const tabId = sender.tab?.id;
  if (typeof tabId !== 'number' || tabId < 0) return { error: 'no tab' };
  if (sender.frameId === 0) return { ok: true };
  if (typeof msg.text !== 'string' || msg.text.trim() === '' || (msg.source !== 'ubo' && msg.source !== 'bastion')) return { error: 'invalid notice' };
  const show: MsgNoticeShow = { type: 'notice:show', text: msg.text.slice(0, MAX_NOTICE_TEXT), source: msg.source };
  try {
    const p = chrome.tabs.sendMessage(tabId, show, { frameId: 0 }) as Promise<unknown> | undefined;
    if (p !== undefined && typeof p.then === 'function') p.then(undefined, () => undefined);
  } catch {
    // tab gone or no listener (protection off in the top frame)
  }
  return { ok: true };
}

function version(): string {
  try {
    return chrome.runtime.getManifest().version;
  } catch {
    return '';
  }
}

export function listsLocked(locked: readonly string[], listIds: readonly string[]): string[] {
  if (locked.includes(LOCK_ALL_LISTS)) return [...listIds];
  return listIds.filter((id) => locked.includes(`lists.${id}`));
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

function config(ctx: MessageContext): EffectiveConfig {
  return ctx.store.effective();
}

/** Report-a-broken-site target: the policy's choice; managed helpdesks before the public tracker. */
export function reportBrokenSiteFor(managed: ManagedPolicy): PopupState['managed']['reportBrokenSite'] {
  return managed.reportBrokenSite ?? (managed.supportEmail ? 'email' : 'github');
}

/** Popup flags for the activity log (individual events) and the per-tab counters. */
export function activityFlags(settings: Settings): { logging: boolean; counting: boolean } {
  return { logging: settings.ui.activityLog, counting: settings.ui.activityLog || badgeModeFor(settings) === 'self' };
}

async function popupState(ctx: MessageContext, tabId: number): Promise<PopupState> {
  // The popup calls getMatchedRules itself; leave it the shared quota.
  ctx.activity.notePopupQuery();
  const tab = await log.attempt('popup', () => chrome.tabs.get(tabId), null as chrome.tabs.Tab | null);
  const url = tab?.url || tab?.pendingUrl || null;
  const u = parseUrl(url);
  const web = u !== null && (u.protocol === 'http:' || u.protocol === 'https:');
  const host = web ? u.hostname.toLowerCase() : null;
  const site = siteKeyFromUrl(url);
  const settings = ctx.store.settings();
  const managed = ctx.store.managed;
  const resolved = resolveSite(host ?? '', ctx.store.effectiveSites(), settings);
  const { counts, recent } = await ctx.activity.tabSummary(tabId);
  const locks = site !== null ? ctx.store.siteLocks(site) : { enabled: managed.allowUserSiteToggle === false, mode: false };
  return {
    tabId,
    url,
    host,
    site,
    filterable: isFilterableUrl(url),
    siteSettings: resolved,
    counts,
    totals: ctx.activity.getTotals(),
    recent,
    ...activityFlags(settings),
    globallyDisabled: ctx.store.protectionOff(),
    locks: { siteToggle: locks.enabled, mode: locks.mode, settings: managed.lockSettings === true },
    managed: {
      organizationName: managed.organizationName,
      reportBrokenSite: reportBrokenSiteFor(managed),
      supportEmail: managed.supportEmail,
      supportUrl: managed.supportUrl,
    },
    incidentCta: settings.ui.incidentCta,
    nerd: ctx.nerd.tabState(tabId),
    version: version(),
  };
}

/** Per-site fields that lockSettings locks (the protection switch follows allowUserSiteToggle). */
const LOCK_SETTINGS_SITE_FIELDS = ['mode', 'blockScripts', 'fingerprinting'] as const;

/**
 * Pure part of site:set: drop locked fields from the patch, apply it, and
 * drop an `enabled: true` that only restates what the site inherits anyway
 * (switching a site off and on again must not leave a phantom exception).
 */
export function planSiteSet(
  sites: SitesMap,
  site: string,
  rawPatch: Record<string, unknown>,
  managed: ManagedPolicy,
  settings: Settings,
  locks: { enabled: boolean; mode: boolean },
): { sites: SitesMap; ignored: string[] } {
  const patch: Record<string, unknown> = { ...rawPatch };
  const ignored: string[] = [];
  const drop = (field: string): void => {
    if (!(field in patch)) return;
    delete patch[field];
    if (!ignored.includes(field)) ignored.push(field);
  };
  if (locks.enabled) drop('enabled');
  if (locks.mode) drop('mode');
  if (managed.lockSettings === true) for (const f of LOCK_SETTINGS_SITE_FIELDS) drop(f);
  const next = patchSite(sites, site, patch);
  const entry = next[site];
  if (entry?.enabled === true) {
    const rest = effectiveSites(next, managed);
    delete rest[site];
    if (resolveSite(site, rest, settings).enabled) {
      const copy = { ...entry };
      delete copy.enabled;
      if (Object.keys(copy).length === 0) delete next[site];
      else next[site] = copy;
    }
  }
  return { sites: next, ignored };
}

async function siteSet(ctx: MessageContext, msg: Extract<Message, { type: 'site:set' }>): Promise<unknown> {
  const site = normalizeSiteKey(msg.site);
  if (!site) return { error: 'invalid site' };
  if (!isPlainObject(msg.patch)) return { error: 'invalid patch' };
  const { sites, ignored } = planSiteSet(ctx.store.sites, site, msg.patch, ctx.store.managed, ctx.store.settings(), ctx.store.siteLocks(site));
  await ctx.store.saveSites(sites);
  await ctx.applier.now();
  if (typeof msg.reloadTabId === 'number' && msg.reloadTabId >= 0) {
    await log.attempt('site', () => chrome.tabs.reload(msg.reloadTabId as number));
  }
  return { ok: true, ignored, siteSettings: resolveSite(site, ctx.store.effectiveSites(), ctx.store.settings()) };
}

async function listsState(ctx: MessageContext): Promise<ListsState | { error: string }> {
  const meta = ctx.store.meta;
  if (!meta) return { error: 'filter metadata unavailable' };
  const report = ctx.applier.report();
  const cfg = ctx.store.effective();
  const available = await log.attempt('lists', () => chrome.declarativeNetRequest.getAvailableStaticRuleCount(), report.budget.available);
  return {
    meta,
    enabled: cfg.settings.lists,
    budget: { used: report.budget.used, available: available ?? null, regexUsed: report.budget.regexUsed },
    locked: listsLocked(cfg.locked, meta.lists.map((l) => l.id)),
    errors: report.listErrors,
  };
}

async function listsSet(ctx: MessageContext, msg: Extract<Message, { type: 'lists:set' }>): Promise<unknown> {
  if (typeof msg.listId !== 'string' || typeof msg.enabled !== 'boolean') return { error: 'invalid request' };
  const meta = ctx.store.meta;
  if (meta && !meta.lists.some((l) => l.id === msg.listId)) return { error: 'unknown list' };
  const { settings, ignored } = applySettingsPatch(ctx.store.user, { lists: { [msg.listId]: msg.enabled } }, ctx.store.lockedSet());
  if (ignored.length > 0) return { error: 'locked' };
  await ctx.store.saveSettings(settings);
  await ctx.applier.now();
  return listsState(ctx);
}

function customState(ctx: MessageContext): CustomState {
  const c = ctx.custom();
  const report = ctx.applier.report();
  return {
    text: ctx.store.customText,
    admin: ctx.store.managed.customFilters ?? [],
    report: customReport(c.user, report.customErrors),
    locked: ctx.store.lockedSet().has(LOCK_CUSTOM_FILTERS),
  };
}

function myListsState(ctx: MessageContext): MyListsState {
  const locked = ctx.store.lockedSet().has(LOCK_MY_LISTS);
  const compiled = new Map(ctx.custom().my.map((m) => [m.id, m.compiled]));
  const errors = ctx.applier.report().myListErrors ?? {};
  const empty = { rules: [], specific: [], generic: [], scriptletsIgnored: 0, errors: [] };
  return {
    lists: ctx.myLists.all().map((l) => ({ ...l, filters: ctx.myLists.filterCount(l.id), report: customReport(compiled.get(l.id) ?? empty, errors[l.id] ?? []) })),
    locked,
    maxLists: MY_LISTS.MAX,
    maxBytes: MY_LISTS.MAX_BYTES,
  };
}

/** Every change to an imported list: recompile, apply, answer with the new state (or the error). */
async function myListsChange(ctx: MessageContext, change: () => Promise<object>): Promise<unknown> {
  if (ctx.store.lockedSet().has(LOCK_MY_LISTS)) return { error: 'locked' };
  const r = await change();
  if ('error' in r) return r;
  ctx.recompileCustom();
  await ctx.applier.now();
  return myListsState(ctx);
}

function myListsAdd(ctx: MessageContext, msg: Extract<Message, { type: 'mylists:add' }>): Promise<unknown> {
  const replaceId = typeof msg.replaceId === 'string' ? msg.replaceId : undefined;
  if (isPlainObject(msg.file)) {
    const { name, text } = msg.file as { name?: unknown; text?: unknown };
    if (typeof name !== 'string' || typeof text !== 'string') return Promise.resolve({ error: 'not-a-list' });
    if (text.length > MY_LISTS.MAX_BYTES) return Promise.resolve({ error: 'too-large' });
    return myListsChange(ctx, () => ctx.myLists.add({ file: { name, text } }, replaceId));
  }
  if (typeof msg.url === 'string') return myListsChange(ctx, () => ctx.myLists.add({ url: msg.url as string }, replaceId));
  return Promise.resolve({ error: 'invalid-url' });
}

/**
 * A whole user site map from the dashboard or a backup: validated, and
 * policy-owned fields keep the user's current values.
 */
export function userSitesFromInput(raw: unknown, prev: SitesMap, managed: ManagedPolicy): SitesMap {
  return keepPolicyOwnedFields(sanitizeSites(raw), prev, managed);
}

async function customSet(ctx: MessageContext, msg: Extract<Message, { type: 'custom:set' }>): Promise<unknown> {
  if (ctx.store.lockedSet().has(LOCK_CUSTOM_FILTERS)) return { error: 'locked' };
  if (typeof msg.text !== 'string') return { error: 'invalid text' };
  if (msg.text.length > MAX_CUSTOM_FILTERS_BYTES) return { error: 'too large' };
  await ctx.store.saveCustom(msg.text);
  ctx.recompileCustom();
  await ctx.applier.now();
  return customState(ctx);
}

async function historyQuery(ctx: MessageContext, msg: Extract<Message, { type: 'history:query' }>): Promise<HistoryResult | { error: string }> {
  if (!isDayKey(msg.fromDay) || !isDayKey(msg.toDay)) return { error: 'invalid day' };
  await ctx.activity.flushAll();
  const days = await ctx.history.queryDaily(msg.fromDay, msg.toDay).catch((e: unknown) => {
    log.warn('history', e);
    return [];
  });
  return { days, totals: ctx.activity.getTotals() };
}

async function historyEvents(ctx: MessageContext, msg: Extract<Message, { type: 'history:events' }>): Promise<unknown> {
  await ctx.activity.flushAll();
  const limit = typeof msg.limit === 'number' ? msg.limit : 100;
  const events = await ctx.history
    .queryEvents({
      limit,
      before: typeof msg.before === 'number' ? msg.before : undefined,
      site: typeof msg.site === 'string' && msg.site !== '' ? msg.site : undefined,
      host: typeof msg.host === 'string' && msg.host !== '' ? msg.host : undefined,
    })
    .catch((e: unknown) => {
      log.warn('history', e);
      return [];
    });
  return { events };
}

async function historyClear(ctx: MessageContext): Promise<unknown> {
  await ctx.activity.flushAll();
  try {
    await ctx.history.clear();
  } catch (e) {
    return { error: errMsg(e) };
  }
  ctx.activity.clearLive();
  ctx.activity.resetTotals();
  return { ok: true };
}

function backupExport(ctx: MessageContext): BackupFile {
  return {
    format: 'bastion-shield-backup',
    version: 1,
    exportedAt: new Date().toISOString(),
    settings: normalizeSettings(ctx.store.user),
    sites: { ...ctx.store.sites },
    customFilters: ctx.store.customText,
  };
}

async function backupImport(ctx: MessageContext, msg: Extract<Message, { type: 'backup:import' }>): Promise<unknown> {
  const data = msg.data as unknown;
  if (!isPlainObject(data) || data.format !== 'bastion-shield-backup' || data.version !== 1) return { error: 'not a Bastion Shield backup' };
  const locked = ctx.store.lockedSet();
  // The backup replaces every setting the user may change; locked paths keep
  // their current value (the policy overrides them anyway). List choices
  // missing from the backup fall back to the catalog default.
  const base = normalizeSettings(ctx.store.user);
  for (const id of Object.keys(base.lists)) {
    if (!locked.has(`lists.${id}`) && !locked.has(LOCK_ALL_LISTS)) delete base.lists[id];
  }
  const { settings, ignored } = applySettingsPatch(base, normalizeSettings(data.settings), locked);
  await ctx.store.saveSettings(settings);
  if (ctx.store.managed.lockSettings === true) {
    // Per-site rows are locked with the settings: keep them as they are.
    ignored.push('sites');
  } else {
    await ctx.store.saveSites(userSitesFromInput(data.sites, ctx.store.sites, ctx.store.managed));
  }
  if (!locked.has(LOCK_CUSTOM_FILTERS) && typeof data.customFilters === 'string') {
    await ctx.store.saveCustom(data.customFilters.slice(0, MAX_CUSTOM_FILTERS_BYTES));
    ctx.recompileCustom();
  }
  await ctx.applier.now();
  return { ...config(ctx), ignored };
}

async function proceduralInject(sender: SenderInfo): Promise<unknown> {
  const tabId = sender.tab?.id;
  if (typeof tabId !== 'number') return { error: 'no tab' };
  const target: chrome.scripting.InjectionTarget = sender.documentId
    ? ({ tabId, documentIds: [sender.documentId] } as chrome.scripting.InjectionTarget)
    : ({ tabId, frameIds: [typeof sender.frameId === 'number' ? sender.frameId : 0] } as chrome.scripting.InjectionTarget);
  try {
    await chrome.scripting.executeScript({ target, files: [PROCEDURAL_SCRIPT_FILE], injectImmediately: true });
    return { ok: true };
  } catch (e) {
    // The frame may have navigated away; nothing to do.
    return { error: errMsg(e) };
  }
}

/** Dispatch one validated message. */
export async function handleMessage(ctx: MessageContext, msg: Message, sender: SenderInfo): Promise<unknown> {
  switch (msg.type) {
    case 'cosmetic:frame':
    {
      if (typeof msg.url !== 'string') return { error: 'invalid url' };
      const fs = frameSender(sender);
      const res = await ctx.cosmetic.onFrame(msg, fs);
      if (res.off || fs.frameId !== 0) return res;
      const lookalike = ctx.nerd.lookalikeFor(msg.url, fs.tabId, fs.frameId);
      return lookalike ? { ...res, lookalike } : res;
    }
    case 'cosmetic:tokens':
      if (typeof msg.url !== 'string' || !Array.isArray(msg.tokens)) return { error: 'invalid request' };
      return ctx.cosmetic.onTokens(msg, frameSender(sender));
    case 'cosmetic:procedural':
      return proceduralInject(sender);
    case 'blocked:info':
      return ctx.blocked.info(sender.tab?.id ?? -1, sender.url);
    case 'blocked:proceed':
      if (typeof msg.url !== 'string') return { error: 'invalid url' };
      return ctx.blocked.proceed(sender.tab?.id ?? -1, msg.url);
    case 'popup:state':
      if (typeof msg.tabId !== 'number') return { error: 'invalid tab' };
      return popupState(ctx, msg.tabId);
    case 'site:set':
      return siteSet(ctx, msg);
    case 'config:get':
      return config(ctx);
    case 'settings:set': {
      const before = ctx.store.settings().history;
      const { settings, ignored } = applySettingsPatch(ctx.store.user, msg.patch, ctx.store.lockedSet());
      await ctx.store.saveSettings(settings);
      void ctx.applier.schedule();
      const after = ctx.store.settings().history;
      if (before.retentionDays !== after.retentionDays || before.enabled !== after.enabled) void ctx.pruneHistory();
      return { ...config(ctx), ignored };
    }
    case 'lists:get':
      return listsState(ctx);
    case 'lists:set':
      return listsSet(ctx, msg);
    case 'sites:get':
      // The user's own map; policy entries are reported via EffectiveConfig.managed.
      return { sites: { ...ctx.store.sites } };
    case 'sites:set': {
      if (!isPlainObject(msg.sites)) return { error: 'invalid sites' };
      // The dashboard Sites view is locked under lockSettings (as in the popup).
      if (ctx.store.managed.lockSettings === true) return { error: 'locked' };
      await ctx.store.saveSites(userSitesFromInput(msg.sites, ctx.store.sites, ctx.store.managed));
      await ctx.applier.now();
      return { sites: { ...ctx.store.sites } };
    }
    case 'custom:get':
      return customState(ctx);
    case 'custom:set':
      return customSet(ctx, msg);
    case 'mylists:get':
      return myListsState(ctx);
    case 'mylists:add':
      return myListsAdd(ctx, msg);
    case 'mylists:set':
      if (typeof msg.id !== 'string') return { error: 'not-found' };
      return myListsChange(ctx, () =>
        ctx.myLists.set(msg.id, {
          enabled: typeof msg.enabled === 'boolean' ? msg.enabled : undefined,
          autoUpdate: typeof msg.autoUpdate === 'boolean' ? msg.autoUpdate : undefined,
        }),
      );
    case 'mylists:remove':
      if (typeof msg.id !== 'string') return { error: 'not-found' };
      return myListsChange(ctx, () => ctx.myLists.remove(msg.id));
    case 'mylists:update':
      if (typeof msg.id !== 'string') return { error: 'not-found' };
      return myListsChange(ctx, () => ctx.myLists.update(msg.id));
    case 'history:query':
      return historyQuery(ctx, msg);
    case 'history:events':
      return historyEvents(ctx, msg);
    case 'history:clear':
      return historyClear(ctx);
    case 'backup:export':
      return backupExport(ctx);
    case 'backup:import':
      return backupImport(ctx, msg);
    case 'nerd:signal':
      return ctx.nerd.onSignal(msg, sender.tab?.id ?? -1);
    case 'nerd:bisect':
      return ctx.nerd.bisect(msg);
    case 'notice:clip':
      return forwardNotice(msg, sender);
    default:
      return { error: `unknown message type: ${String((msg as { type?: unknown }).type)}` };
  }
}

/**
 * chrome.runtime.onMessage listener. `ready` gates handling until the service
 * worker finished loading its state; the reply is sent asynchronously.
 */
export function createMessageListener(
  ctxReady: Promise<MessageContext>,
  runtimeId: string,
  extensionOrigin: string,
  /** URLs of pages/blocked.html on the static and the dynamic origin (sender check for blocked:*). */
  blockedPageUrls: readonly string[] = [],
): (msg: unknown, sender: chrome.runtime.MessageSender, sendResponse: (r: unknown) => void) => boolean | undefined {
  return (msg, sender, sendResponse) => {
    const kind = classifySender(sender as SenderInfo, runtimeId, extensionOrigin);
    if (kind === null) return undefined; // not ours: stay silent
    if (!isPlainObject(msg) || typeof msg.type !== 'string') {
      sendResponse({ error: 'invalid message' });
      return undefined;
    }
    const type = msg.type;
    if (!isKnownType(type)) {
      sendResponse({ error: `unknown message type: ${type}` });
      return undefined;
    }
    if (!isAllowed(type, kind, sender as SenderInfo, blockedPageUrls)) {
      sendResponse({ error: 'sender not allowed' });
      return undefined;
    }
    ctxReady
      .then((ctx) => handleMessage(ctx, msg as unknown as Message, sender as SenderInfo))
      .then(
        (res) => {
          try {
            sendResponse(res === undefined ? { ok: true } : res);
          } catch {
            /* the sender went away */
          }
        },
        (e: unknown) => {
          log.error('messaging', type, e);
          try {
            sendResponse({ error: errMsg(e) });
          } catch {
            /* ignore */
          }
        },
      );
    return true;
  };
}
