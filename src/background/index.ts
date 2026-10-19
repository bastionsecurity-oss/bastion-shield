// Bastion Shield — MV3 service worker entry (bundled to dist/background.js).
//
// Every event listener is added synchronously at the top level so Chrome can
// wake the worker for it. All asynchronous initialisation sits behind one
// `ready` promise; events that arrive earlier are chained onto it, so nothing
// is lost and their order is kept. Activity listeners that the current
// settings do not need are removed after initialisation, so the worker is not
// woken for every blocked request when nobody wants the log or the badge.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { PORT_LIVE, STORAGE } from '../shared/constants.ts';
import type { ListCategory, Settings } from '../shared/types.ts';
import { ActivityService, classifyRedirect, persistenceFor } from './activity.ts';
import type { ActivityConfig, LivePort, MatchInfo, RequestDetails } from './activity.ts';
import { badgeModeFor, browserResourceTypes, createApplier, SESSION_APPLIED_KEY } from './apply.ts';
import { BlockedPages, isBlockedPageUrl } from './blocked.ts';
import { CosmeticService } from './cosmetic.ts';
import type { CosmeticConfig, CosmeticTarget } from './cosmetic.ts';
import { compileAllCustom } from './custom.ts';
import type { CustomCompiled } from './custom.ts';
import { loadBuildMeta, loadCosmeticMeta, loadGenericHigh, loadGenericIndex, loadShard } from './data.ts';
import { HistoryDb } from './history-db.ts';
import { clearSessionRules, currentSeedFiles, openWelcome, recordInstall, renewSeeds, shouldShowWelcome } from './install.ts';
import * as log from './log.ts';
import { createMessageListener } from './messaging.ts';
import type { MessageContext } from './messaging.ts';
import { NerdService } from './nerd.ts';
import { registerNerdCommands } from './nerd-commands.ts';
import { chromeMenus, NerdMenus } from './nerd-menus.ts';
import { LOCK_CUSTOM_FILTERS } from './settings.ts';
import { explicitField, resolveSite } from './sites.ts';
import { Store, storageChangePlan } from './store.ts';
import { dayKey, deferred, isPlainObject, startOfDayOffset, webHostOf } from './util.ts';

const RUNTIME_ID = chrome.runtime.id;
const EXTENSION_ORIGIN = chrome.runtime.getURL('');
/**
 * pages/blocked.html on the static origin and (use_dynamic_url) on the
 * session's dynamic origin; only these may send blocked:* messages.
 */
const BLOCKED_PAGE_URLS = Array.from(new Set([`${EXTENSION_ORIGIN}pages/blocked.html`, chrome.runtime.getURL('pages/blocked.html')]));
/**
 * Incognito instance (manifest "incognito": "split"). It never persists
 * history or totals: activity from incognito tabs stays in memory only.
 */
const INCOGNITO = (() => {
  try {
    return chrome.extension?.inIncognitoContext === true;
  } catch {
    return false;
  }
})();
const PRUNE_ALARM = 'bastion:history-prune';
const PRUNE_PERIOD_MIN = 6 * 60;
const GREY_TABS_KEY = 'icons:grey';
const ICON_SIZES = [16, 24, 32] as const;
const ICONS_OFF = Object.fromEntries(ICON_SIZES.map((s) => [s, `icons/icon-off-${s}.png`])) as Record<string, string>;
const ICONS_ON = Object.fromEntries(ICON_SIZES.map((s) => [s, `icons/icon-on-${s}.png`])) as Record<string, string>;

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

const store = new Store();
const history = new HistoryDb();
let customCache: CustomCompiled | null = null;

function custom(): CustomCompiled {
  if (!customCache) customCache = compileAllCustom(store.customText, store.managed.customFilters ?? [], store.meta);
  return customCache;
}

function recompileCustom(): void {
  customCache = null;
}

function settings(): Settings {
  return store.settings();
}

function categoryOf(listId: string | undefined): ListCategory | 'unknown' {
  if (!listId) return 'unknown';
  if (listId === 'custom' || listId === 'admin') return 'custom';
  if (listId === 'bastion-params') return 'privacy';
  return store.meta?.lists.find((l) => l.id === listId)?.category ?? 'unknown';
}

const activity = new ActivityService({
  now: () => Date.now(),
  config: (): ActivityConfig => {
    const s = settings();
    return {
      activityLog: s.ui.activityLog,
      ...persistenceFor(s, INCOGNITO),
      badgeMode: badgeModeFor(s),
      rulesetToList: store.meta?.rulesetToList ?? {},
      categoryOf,
    };
  },
  sessionGet: async (key) => (await chrome.storage.session.get(key))[key],
  sessionSet: async (items) => chrome.storage.session.set(items),
  sessionRemove: async (keys) => chrome.storage.session.remove(keys),
  getMatchedRules: async (minTimeStamp) => {
    const r = await chrome.declarativeNetRequest.getMatchedRules({ minTimeStamp });
    return (r?.rulesMatchedInfo ?? []) as unknown as MatchInfo[];
  },
  history,
  loadTotals: async () => (await chrome.storage.local.get(STORAGE.TOTALS))[STORAGE.TOTALS],
  saveTotals: async (t) => chrome.storage.local.set({ [STORAGE.TOTALS]: t }),
  setBadge: async (tabId, text) => {
    // A running bisect shows its step on this tab's badge (nerd-bisect.ts).
    if (nerd.bisector.holdsBadge(tabId)) return;
    await chrome.action.setBadgeText({ tabId, text: text as string });
  },
  setTimeout: (fn, ms) => setTimeout(fn, ms),
});

function enabledMask(s: Settings): { mask: number; ids: Set<string> } {
  let mask = 0;
  const ids = new Set<string>();
  for (const l of store.meta?.lists ?? []) {
    if (!s.lists[l.id]) continue;
    ids.add(l.id);
    if (Number.isInteger(l.bit) && l.bit >= 0 && l.bit < 32) mask = (mask | (1 << l.bit)) >>> 0;
  }
  return { mask, ids };
}

const cosmetic = new CosmeticService({
  loadMeta: loadCosmeticMeta,
  loadShard,
  loadGeneric: loadGenericIndex,
  loadGenericHigh,
  config: (): CosmeticConfig => {
    const s = settings();
    const sites = store.effectiveSites();
    const { mask, ids } = enabledMask(s);
    const allOff = store.protectionOff();
    return {
      enabledMask: mask,
      enabledListIds: ids,
      deAmp: s.privacy.deAmp,
      custom: custom().cosmetic,
      isOff: (host) => allOff || !resolveSite(host, sites, s).enabled,
    };
  },
  insertCss: async (target: CosmeticTarget, css: string) => {
    const t = target.documentId ? { tabId: target.tabId, documentIds: [target.documentId] } : { tabId: target.tabId, frameIds: [target.frameId] };
    await chrome.scripting.insertCSS({ target: t as chrome.scripting.InjectionTarget, css, origin: 'USER' });
  },
});

const blocked = new BlockedPages({ meta: () => store.meta, resourceTypes: browserResourceTypes });

const applier = createApplier(
  {
    settings,
    sites: () => store.effectiveSites(),
    meta: () => store.meta,
    custom,
    seedFiles: currentSeedFiles,
    activity,
    invalidateCosmetic: () => cosmetic.invalidate(),
    syncListeners,
    globallyDisabled: () => store.protectionOff(),
    incognito: INCOGNITO,
  },
  () => void refreshIcons(),
);

async function pruneHistory(): Promise<void> {
  const s = settings();
  const now = Date.now();
  const days = Math.max(0, s.history.retentionDays);
  const cutoff = startOfDayOffset(now, days);
  // retentionDays 0 keeps today's aggregate only, no individual events.
  await history.prune(days === 0 ? now + 1 : cutoff, dayKey(cutoff)).catch((e: unknown) => log.warn('history', 'prune', e));
}

/** Transparency maps (dist/rulesets/filters/<rulesetId>.json), loaded on demand for bisect results. */
const ruleMaps = new Map<string, Promise<(string[] | null)[]>>();
function ruleMap(rulesetId: string): Promise<(string[] | null)[]> {
  let p = ruleMaps.get(rulesetId);
  if (!p) {
    p = fetch(chrome.runtime.getURL(`rulesets/filters/${encodeURIComponent(rulesetId)}.json`))
      .then((r) => (r.ok ? (r.json() as Promise<(string[] | null)[]>) : []))
      .catch(() => []);
    ruleMaps.set(rulesetId, p);
  }
  return p;
}

const nerd = new NerdService({
  settings,
  blockedOnTab: async (tabId) => {
    const { recent } = await activity.tabSummary(tabId, 1000);
    return recent.filter((e) => e.kind === 'blocked' || e.kind === 'redirected').map((e) => ({ host: e.host, rule: e.rule, list: e.list }));
  },
  siteOf: async (tabId) => {
    const tab = await log.attempt('nerd', () => chrome.tabs.get(tabId), null as chrome.tabs.Tab | null);
    return tab?.url ? webHostOf(tab.url)?.replace(/^www\./, '') ?? null : null;
  },
  describeRules: async (rules) => {
    const filters = new Set<string>();
    const lists = new Set<string>();
    for (const r of rules) {
      const i = r.lastIndexOf(':');
      if (i <= 0) continue;
      const rulesetId = r.slice(0, i);
      const ruleId = Number(r.slice(i + 1));
      const list = store.meta?.rulesetToList[rulesetId];
      if (list) lists.add(list);
      const texts = (await ruleMap(rulesetId))[ruleId];
      for (const t of texts ?? []) filters.add(t);
    }
    return { filters: Array.from(filters), lists: Array.from(lists) };
  },
  addCustomFilters: async (lines) => {
    // Same rule as custom:set: policy may make the user's filters read-only.
    if (store.lockedSet().has(LOCK_CUSTOM_FILTERS)) throw new Error('locked');
    const text = store.customText.replace(/\s*$/, '');
    await store.saveCustom(`${text}${text === '' ? '' : '\n'}${lines.join('\n')}\n`);
    recompileCustom();
    await applier.now();
  },
  badge: (tabId, text) => {
    void log.attempt('badge', async () => {
      await chrome.action.setBadgeText({ tabId, text: text as string });
      // Back to the normal badge: our own counter repaints it, the browser's counter shows through null.
      if (text === null && badgeModeFor(settings()) === 'self') activity.refreshBadges();
    });
  },
});

/** Nerd-mode context menu: follows settings.nerd.enabled through syncListeners(). */
const nerdMenus = new NerdMenus({
  menus: chromeMenus(),
  msg: (key) => chrome.i18n.getMessage(key),
  dashboardUrl: chrome.runtime.getURL('ui/dashboard.html'),
  nerdOn: () => settings().nerd.enabled,
  bisect: (msg) => nerd.bisect(msg),
  openTab: async (url, tab) => {
    const next = typeof tab?.index === 'number' && typeof tab.windowId === 'number' && tab.windowId >= 0;
    await log.attempt('menus', () =>
      chrome.tabs.create(next ? { url, index: tab!.index! + 1, windowId: tab!.windowId, openerTabId: tab!.id } : { url }),
    );
  },
  // The bisect asks its questions in the popup (Chrome 127+, may need a focused window).
  openPopup: async () => {
    await log.attempt('menus', () => chrome.action.openPopup());
  },
});

const ready = deferred<MessageContext>();
let isReady = false;
const ctx: MessageContext = { store, applier, cosmetic, activity, blocked, history, nerd, custom, recompileCustom, pruneHistory };

// ---------------------------------------------------------------------------
// Toolbar icon for tabs with protection off
// ---------------------------------------------------------------------------

const greyTabs = new Set<number>();

function persistGreyTabs(): void {
  void log.attempt('icon', () => chrome.storage.session.set({ [GREY_TABS_KEY]: Array.from(greyTabs) }));
}

async function updateTabIcon(tabId: number, url: string | undefined): Promise<void> {
  const host = webHostOf(url);
  const off = host !== null && (store.protectionOff() || !resolveSite(host, store.effectiveSites(), settings()).enabled);
  if (off && !greyTabs.has(tabId)) {
    greyTabs.add(tabId);
    persistGreyTabs();
    await log.attempt('icon', () => chrome.action.setIcon({ tabId, path: ICONS_OFF }));
  } else if (!off && greyTabs.has(tabId)) {
    greyTabs.delete(tabId);
    persistGreyTabs();
    await log.attempt('icon', () => chrome.action.setIcon({ tabId, path: ICONS_ON }));
  } else if (off) {
    // A navigation may have reset the tab-specific icon; set it again (cheap).
    await log.attempt('icon', () => chrome.action.setIcon({ tabId, path: ICONS_OFF }));
  }
}

async function refreshIcons(): Promise<void> {
  const tabs = await log.attempt('icon', () => chrome.tabs.query({}), [] as chrome.tabs.Tab[]);
  for (const t of tabs) if (typeof t.id === 'number') await updateTabIcon(t.id, t.url);
}

// ---------------------------------------------------------------------------
// Activity listeners (added synchronously, pruned after init per settings)
// ---------------------------------------------------------------------------

function toDetails(d: chrome.webRequest.OnErrorOccurredDetails | chrome.webRequest.OnBeforeRedirectDetails): RequestDetails {
  const r = d as unknown as Record<string, unknown>;
  return {
    tabId: d.tabId,
    frameId: d.frameId,
    url: d.url,
    type: String(d.type),
    timeStamp: d.timeStamp,
    initiator: typeof r.initiator === 'string' ? r.initiator : undefined,
    error: typeof r.error === 'string' ? r.error : undefined,
    redirectUrl: typeof r.redirectUrl === 'string' ? r.redirectUrl : undefined,
    statusCode: typeof r.statusCode === 'number' ? r.statusCode : undefined,
  };
}

function onErrorOccurred(d: chrome.webRequest.OnErrorOccurredDetails): void {
  if (d.error !== 'net::ERR_BLOCKED_BY_CLIENT') return;
  const details = toDetails(d);
  if (isReady) activity.onError(details);
  else void ready.promise.then(() => activity.onError(details));
}

/** main_frame redirects: always on, the strict-block page depends on it. */
function onMainFrameRedirect(d: chrome.webRequest.OnBeforeRedirectDetails): void {
  const details = toDetails(d);
  const cls = details.redirectUrl ? classifyRedirect(details.url, details.redirectUrl, details.statusCode) : null;
  if (!cls) return;
  if (cls.kind === 'strict' && details.tabId >= 0) {
    blocked.record(details.tabId, details.url, cls.listId);
    // The record is cleared on the tab's next commit: keep that listener on.
    if (isReady) syncListeners();
  }
  const run = () => {
    const s = settings();
    if (s.ui.activityLog || badgeModeFor(s) === 'self') activity.onRedirect(details);
  };
  if (isReady) run();
  else void ready.promise.then(run);
}

/** Subresource redirects (neutered resources, stripped parameters). */
function onSubresourceRedirect(d: chrome.webRequest.OnBeforeRedirectDetails): void {
  if (d.type === 'main_frame') return; // handled by onMainFrameRedirect
  const details = toDetails(d);
  if (isReady) activity.onRedirect(details);
  else void ready.promise.then(() => activity.onRedirect(details));
}

function onCommitted(d: chrome.webNavigation.WebNavigationTransitionCallbackDetails): void {
  if (d.frameId !== 0) return;
  const lifecycle = (d as unknown as { documentLifecycle?: string }).documentLifecycle;
  if (lifecycle === 'prerender') return;
  const run = () => {
    // Any other top-level document than the blocked page makes its record stale.
    if (!isBlockedPageUrl(d.url)) blocked.forget(d.tabId);
    activity.onCommitted(d.tabId, d.url);
    nerd.onCommitted(d.tabId, d.frameId);
    nerd.bisector.onCommitted(d.tabId, d.url);
    void updateTabIcon(d.tabId, d.url);
  };
  if (isReady) run();
  else void ready.promise.then(run);
}

const ALL_URLS_FILTER = { urls: ['<all_urls>'] };

function setListener<F extends (...args: never[]) => void>(
  event: { addListener(fn: F, ...rest: never[]): void; removeListener(fn: F): void; hasListener(fn: F): boolean } | undefined,
  fn: F,
  want: boolean,
  filter?: object,
): void {
  if (!event) return;
  try {
    const has = event.hasListener(fn);
    if (want && !has) {
      if (filter) (event.addListener as (fn: F, filter: object) => void)(fn, filter);
      else event.addListener(fn);
    } else if (!want && has) {
      event.removeListener(fn);
    }
  } catch (e) {
    log.warn('listeners', e);
  }
}

/** Keep only the listeners the current settings need. */
function syncListeners(): void {
  const s = settings();
  const needActivity = s.ui.activityLog || badgeModeFor(s) === 'self';
  const anyDisabled =
    store.protectionOff() || Array.from(explicitField(store.effectiveSites(), 'enabled').values()).some((v) => v === false) || greyTabs.size > 0;
  setListener(chrome.webRequest?.onErrorOccurred, onErrorOccurred, needActivity, ALL_URLS_FILTER);
  setListener(chrome.webRequest?.onBeforeRedirect, onSubresourceRedirect, needActivity, ALL_URLS_FILTER);
  setListener(chrome.webNavigation?.onCommitted, onCommitted, needActivity || anyDisabled || blocked.hasRecords() || s.nerd.enabled);
  void nerdMenus.sync(s.nerd.enabled);
  nerd.onSettingsChanged();
}

// --- top-level registration (synchronous) -----------------------------------

registerNerdCommands({
  ready: ready.promise,
  bisect: (msg) => nerd.bisect(msg),
  canBisect: () => settings().nerd.enabled && settings().ui.activityLog,
  activeTabId: async () => (await log.attempt('commands', () => chrome.tabs.query({ active: true, lastFocusedWindow: true }), [] as chrome.tabs.Tab[]))[0]?.id ?? null,
});

try {
  chrome.contextMenus.onClicked.addListener((info, tab) => {
    void ready.promise.then(() => nerdMenus.onClicked(info, tab)).catch((e: unknown) => log.warn('menus', e));
  });
} catch (e) {
  log.error('listeners', 'contextMenus unavailable', e);
}

try {
  chrome.webRequest.onErrorOccurred.addListener(onErrorOccurred, ALL_URLS_FILTER);
  chrome.webRequest.onBeforeRedirect.addListener(onSubresourceRedirect, ALL_URLS_FILTER);
  chrome.webRequest.onBeforeRedirect.addListener(onMainFrameRedirect, { urls: ['<all_urls>'], types: ['main_frame'] });
} catch (e) {
  log.error('listeners', 'webRequest unavailable', e);
}
try {
  chrome.webNavigation.onCommitted.addListener(onCommitted);
} catch (e) {
  log.error('listeners', 'webNavigation unavailable', e);
}

chrome.runtime.onMessage.addListener(createMessageListener(ready.promise, RUNTIME_ID, EXTENSION_ORIGIN, BLOCKED_PAGE_URLS));

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== PORT_LIVE) return;
  const sender = port.sender;
  if (!sender || sender.id !== RUNTIME_ID || typeof sender.url !== 'string' || !sender.url.startsWith(EXTENSION_ORIGIN)) {
    try {
      port.disconnect();
    } catch {
      /* ignore */
    }
    return;
  }
  const live: LivePort = { postMessage: (m) => port.postMessage(m) };
  activity.addPort(live);
  port.onMessage.addListener((m: unknown) => {
    if (!isPlainObject(m)) return;
    const sub = m.subscribe;
    if (sub !== 'all' && !(typeof sub === 'number' && Number.isInteger(sub))) return;
    void ready.promise.then(() => activity.subscribe(live, sub as number | 'all'));
  });
  port.onDisconnect.addListener(() => {
    void chrome.runtime.lastError;
    activity.removePort(live);
  });
});

chrome.runtime.onInstalled.addListener((details) => {
  void ready.promise.then(async () => {
    try {
      await recordInstall(details.reason, details.previousVersion);
      if (details.reason === 'install') {
        // Persist the defaults (lists stay {} = "follow the catalog default").
        const stored = await log.attempt('install', () => chrome.storage.local.get(STORAGE.SETTINGS), {} as Record<string, unknown>);
        if (stored[STORAGE.SETTINGS] === undefined) await log.attempt('install', () => store.saveSettings(store.user));
        await clearSessionRules();
        await renewSeeds();
        await applier.now('install');
        if (!INCOGNITO && (await shouldShowWelcome(async () => (await store.reloadManaged().then(() => store.managed.organizationName)) || undefined))) {
          await openWelcome();
        }
      } else {
        // Updates reset enabled rulesets to the manifest defaults and clear
        // every dynamically registered content script (session rules survive):
        // re-apply everything, registrations first.
        await applier.now('update');
      }
    } catch (e) {
      log.error('install', e);
    }
    // Context menus are rebuilt from scratch on install and update.
    await nerdMenus.sync(settings().nerd.enabled, true);
  });
});

chrome.runtime.onStartup.addListener(() => {
  void ready.promise.then(async () => {
    await renewSeeds();
    await applier.now('startup');
    await nerdMenus.sync(settings().nerd.enabled, true);
  });
});

chrome.storage.onChanged.addListener((changes, area) => {
  // An event that arrives before init finished is the one that (re)started
  // the worker: init() has already loaded the NEW values, so comparing them
  // with memory would find no difference and the change would never reach
  // DNR, registrations or chrome.privacy (SW-1).
  const cold = !isReady;
  void ready.promise.then(async () => {
    if (area !== 'managed' && area !== 'local') return;
    const localChanged = area === 'local' && store.applyLocalChange(changes);
    const plan = storageChangePlan(area, Object.keys(changes), localChanged, cold);
    if (plan.reloadManaged) await store.reloadManaged();
    if (plan.recompileCustom) recompileCustom();
    if (plan.apply === 'now') await applier.now();
    else if (plan.apply === 'schedule') void applier.schedule();
  });
});

chrome.alarms?.onAlarm.addListener((alarm) => {
  if (alarm.name !== PRUNE_ALARM) return;
  void ready.promise.then(pruneHistory);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  void ready.promise.then(() => {
    activity.onTabRemoved(tabId);
    nerd.onTabRemoved(tabId);
    void blocked.onTabRemoved(tabId);
    if (greyTabs.delete(tabId)) persistGreyTabs();
  });
});

chrome.tabs.onReplaced?.addListener((added, removed) => {
  void ready.promise.then(() => activity.onTabReplaced(added, removed));
});

chrome.runtime.onSuspend?.addListener(() => {
  void activity.flushAll();
});

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

async function init(): Promise<void> {
  // Keep settings and history away from content scripts.
  await log.attempt('init', () => chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }));
  const meta = await loadBuildMeta();
  if (!meta) log.error('init', 'rulesets/meta.json missing or invalid; list toggles unavailable');
  await store.load(meta);
  await activity.init();
  await blocked.restore();
  await applier.restoreReport();
  const session = await log.attempt('init', () => chrome.storage.session.get([GREY_TABS_KEY, SESSION_APPLIED_KEY]), {} as Record<string, unknown>);
  const grey = session[GREY_TABS_KEY];
  if (Array.isArray(grey)) for (const id of grey) if (typeof id === 'number') greyTabs.add(id);
  const alarm = await log.attempt('init', () => chrome.alarms.get(PRUNE_ALARM));
  if (!alarm) await log.attempt('init', () => chrome.alarms.create(PRUNE_ALARM, { delayInMinutes: 1, periodInMinutes: PRUNE_PERIOD_MIN }));

  // Self-heal: session storage is empty after a browser restart or after the
  // extension was re-enabled (neither fires onInstalled/onStartup reliably),
  // and session rules are gone then too.
  const marker = session[SESSION_APPLIED_KEY] as { version?: string } | undefined;
  let version = '';
  try {
    version = chrome.runtime.getManifest().version;
  } catch {
    /* ignore */
  }
  if (!marker || marker.version !== version) void applier.now('startup');
}

void init()
  .catch((e: unknown) => log.error('init', e))
  .finally(() => {
    isReady = true;
    ready.resolve(ctx);
    syncListeners();
  });
