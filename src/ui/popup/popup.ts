// Bastion Shield — toolbar popup. Shows the current site, the per-site
// protection switch, live counters and feed for the current page load, the
// DNR rules that matched (with original filter text) and per-site settings.
// Budget: well under 30 ms of script before first meaningful paint, so the
// static skeleton is in popup.html and everything here is incremental.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ActivityEvent, BlockingMode, BuildMeta, FingerprintLevel, PopupState, SiteSettings } from '../../shared/types.ts';
import { $, h, reducedMotion, replace, toast } from '../shared/dom.ts';
import { fmtDateLong, fmtNumber, fmtTime, plural, t, translate } from '../shared/i18n.ts';
import { hydrateIcons, icon } from '../shared/icons.ts';
import { applyAttributed, call, connectLive, fetchPackaged, openDashboard, type LiveConnection } from '../shared/messaging.ts';
import { lockBadge, lockIcon, segmented, switchControl, type SegHandle, type SwitchHandle } from '../shared/controls.ts';
import { kindLabel, ListDirectory, typeLabel } from '../shared/labels.ts';
import { orgNameEl } from '../shared/org.ts';
import { createMatchedPanel, type MatchedPanel } from './matched.ts';
import { startReport } from './report.ts';
import { normalisePopupState, tabIdFromSearch } from './state.ts';

const FEED_MAX = 50;
const TAB_KEY = 'bastion.popup.tab';

let state: PopupState | null = null;
let tabId = -1;
let dir = new ListDirectory(null);
let live: LiveConnection | null = null;
let matched: MatchedPanel | null = null;

const counts = { blocked: 0, redirected: 0, stripped: 0, debounced: 0, thirdPartyHosts: 0 };
const thirdHosts = new Set<string>();
const seen = new Set<string>();
let feed: ActivityEvent[] = [];
let freshRows = 0;
let shownTotal = -1;
let paintQueued = false;

let siteSwitch: SwitchHandle | null = null;
let modeSeg: SegHandle<BlockingMode> | null = null;
let scriptsSwitch: SwitchHandle | null = null;
let fpSeg: SegHandle<FingerprintLevel> | null = null;

const evKey = (e: ActivityEvent): string => `${e.t}|${e.kind}|${e.frameId}|${e.url}`;

// ------------------------------------------------------------------ helpers --

async function activeTab(): Promise<chrome.tabs.Tab | null> {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab ?? null;
  } catch {
    return null;
  }
}

function setHidden(id: string, hidden: boolean): void {
  const el = document.getElementById(id);
  if (el) el.hidden = hidden;
}

function closeSoon(): void {
  // Give Chrome a tick to act on tabs.create / reload before the popup goes away.
  setTimeout(() => window.close(), 30);
}

// ------------------------------------------------------------------- render --

function showError(): void {
  document.body.dataset.state = 'error';
  setHidden('pp-error', false);
  for (const id of ['pp-count-section', 'pp-tabs']) setHidden(id, true);
  $('.pp-site').hidden = true;
  $('#pp-totals').textContent = '';
}

function renderHeader(s: PopupState): void {
  const org = $('#pp-org');
  if (s.managed.organizationName) {
    replace(
      org,
      h('span', { class: 'pp-head__org-label mono-label', text: t('managedByLabel') }),
      orgNameEl(s.managed.organizationName, s.managed.supportUrl, 'pp-head__org-name', closeSoon),
    );
    org.title = t('managedBy', s.managed.organizationName);
    org.hidden = false;
  } else {
    org.hidden = true;
  }
  // For browser pages show the scheme too ("chrome://settings"), a bare "settings" reads oddly.
  let shown = s.host ?? s.site ?? '';
  if (!s.filterable && s.url) {
    try {
      const u = new URL(s.url);
      shown = u.protocol === 'http:' || u.protocol === 'https:' ? u.hostname : `${u.protocol}//${u.hostname}`;
    } catch {
      /* keep host */
    }
  }
  $('#pp-host').textContent = shown;
  const totals = s.totals;
  $('#pp-totals').textContent = totals && totals.since ? t('popupTotals', [fmtNumber(totals.blocked ?? 0), fmtDateLong(totals.since)]) : ' ';
}

/** Counter and feed when the activity log or the per-tab counters are switched off. */
function renderCountMode(): void {
  const s = state;
  if (!s) return;
  const off = $('#pp-count-off');
  $('#pp-count-body').hidden = !s.counting;
  off.hidden = s.counting;
  if (!s.counting) {
    // Never show a misleading 0: say that counting is off (and whether protection still runs).
    off.textContent = s.siteSettings.enabled ? t('popupCountOff') : t('popupCountOffSiteOff');
    $('#pp-count-section').setAttribute('aria-label', `${t('popupBlockedOnPage')}: ${off.textContent}`);
  }
  $('#pp-feed-all').hidden = !s.logging;
  renderFeed();
}

function renderSiteState(): void {
  const s = state!;
  const on = s.siteSettings.enabled;
  document.body.dataset.site = on ? 'on' : 'off';
  $('#pp-mark').classList.toggle('mark--off', !on);
  $('#pp-toggle-state').textContent = on ? t('popupSiteOnState') : t('popupSiteOffState');
  const disable = !on || s.locks.settings;
  modeSeg?.setDisabled(disable || s.locks.mode);
  scriptsSwitch?.setDisabled(disable);
  fpSeg?.setDisabled(disable);
  renderCountMode();
}

function modeHint(m: BlockingMode): string {
  return m === 'aggressive' ? t('popupModeAggressiveHint') : t('popupModeStandardHint');
}

function fpHint(l: FingerprintLevel): string {
  return l === 'off' ? t('fpOffHint') : l === 'strict' ? t('fpStrictHint') : t('fpStandardHint');
}

interface SiteSetReply {
  ok?: boolean;
  ignored?: string[];
  siteSettings?: SiteSettings;
}

async function setSite(patch: SiteSettings): Promise<boolean> {
  const s = state!;
  const site = s.site ?? s.host;
  if (!site) return false;
  const res = await call<SiteSetReply>({ type: 'site:set', site, patch });
  if (!res.ok) {
    toast(t('errorSaveFailed'), icon('alert', 15));
    return false;
  }
  // The service worker drops fields that policy locks; revert the control and say why.
  const ignored = Array.isArray(res.data?.ignored) ? res.data.ignored : [];
  if (ignored.length && Object.keys(patch).every((k) => ignored.includes(k))) {
    toast(t('lockedByPolicy'), icon('lock', 15));
    return false;
  }
  // site:set answers { ok, ignored, siteSettings } with the settings the site now resolves to.
  const resolved = res.data?.siteSettings;
  if (resolved && typeof resolved === 'object') {
    const next = normalisePopupState({ siteSettings: resolved }, tabId).siteSettings;
    const keys = Object.keys(patch) as (keyof SiteSettings)[];
    s.siteSettings = next;
    if (keys.some((k) => patch[k] !== undefined && next[k] !== patch[k])) {
      // A parent-domain policy decides this field: keep the control on the effective value.
      toast(t('lockedByPolicy'), icon('lock', 15));
      return false;
    }
  } else {
    Object.assign(s.siteSettings, patch);
  }
  showReloadHint();
  return true;
}

function setLock(id: string, el: HTMLElement | null): void {
  const slot = $(`#${id}`);
  replace(slot, el);
  slot.hidden = el === null;
}

function renderControls(): void {
  const s = state!;
  const ss = s.siteSettings;

  siteSwitch = switchControl({
    checked: ss.enabled,
    labelledBy: 'pp-toggle-label',
    describedBy: 'pp-toggle-state',
    large: true,
    disabled: s.locks.siteToggle,
    onChange: async (v) => {
      const ok = await setSite({ enabled: v });
      if (ok) renderSiteState();
      return ok;
    },
  });
  replace($('#pp-toggle-slot'), siteSwitch.el);
  setLock('pp-toggle-lock', s.locks.siteToggle ? lockIcon() : null);

  modeSeg = segmented<BlockingMode>({
    options: [
      { value: 'standard', label: t('modeStandard') },
      { value: 'aggressive', label: t('modeAggressive') },
    ],
    value: ss.mode,
    labelledBy: 'pp-mode-label',
    onChange: async (v) => {
      const ok = await setSite({ mode: v });
      if (ok) $('#pp-mode-hint').textContent = modeHint(v);
      return ok;
    },
  });
  replace($('#pp-mode-slot'), modeSeg.el);
  $('#pp-mode-hint').textContent = modeHint(ss.mode);
  // A policy (e.g. aggressiveSites on a parent domain) fixes the mode for this site only.
  setLock('pp-mode-lock', s.locks.mode && !s.locks.settings ? lockIcon() : null);

  scriptsSwitch = switchControl({
    checked: ss.blockScripts,
    labelledBy: 'pp-scripts-label',
    describedBy: 'pp-scripts-hint',
    onChange: (v) => setSite({ blockScripts: v }),
  });
  replace($('#pp-scripts-slot'), scriptsSwitch.el);

  fpSeg = segmented<FingerprintLevel>({
    options: [
      { value: 'off', label: t('fpOff') },
      { value: 'standard', label: t('fpStandard') },
      { value: 'strict', label: t('fpStrict') },
    ],
    value: ss.fingerprinting,
    labelledBy: 'pp-fp-label',
    onChange: async (v) => {
      const ok = await setSite({ fingerprinting: v });
      if (ok) $('#pp-fp-hint').textContent = fpHint(v);
      return ok;
    },
  });
  replace($('#pp-fp-slot'), fpSeg.el);
  $('#pp-fp-hint').textContent = fpHint(ss.fingerprinting);

  setLock('pp-controls-lock', s.locks.settings ? lockBadge() : null);
  renderSiteState();
}

function showReloadHint(): void {
  const bar = $('#pp-reload');
  if (!bar.hidden) return;
  // Overlays the footer on purpose: growing the popup would make it jump.
  bar.hidden = false;
}

// ------------------------------------------------------------ counts & feed --

function schedulePaint(): void {
  if (paintQueued) return;
  paintQueued = true;
  requestAnimationFrame(() => {
    paintQueued = false;
    paintCounts();
    renderFeed();
  });
}

function paintCounts(): void {
  const total = counts.blocked + counts.redirected + counts.stripped + counts.debounced;
  const el = $('#pp-count');
  el.textContent = fmtNumber(total);
  if (shownTotal >= 0 && total > shownTotal && !reducedMotion() && typeof el.animate === 'function') {
    el.animate([{ transform: 'translateY(3px)', opacity: 0.55 }, { transform: 'none', opacity: 1 }], { duration: 220, easing: 'cubic-bezier(0.2, 0, 0, 1)' });
  }
  shownTotal = total;
  $('#pp-c-blocked').textContent = fmtNumber(counts.blocked);
  $('#pp-c-redirected').textContent = fmtNumber(counts.redirected);
  $('#pp-c-stripped').textContent = fmtNumber(counts.stripped);
  $('#pp-c-debounced').textContent = fmtNumber(counts.debounced);
  $('#pp-c-debounced-row').hidden = counts.debounced === 0;
  // Distinct third-party hosts are context for the total, not another blocked count.
  const third = $('#pp-c-third');
  third.textContent = counts.thirdPartyHosts > 0 ? plural(counts.thirdPartyHosts, 'popupThirdPartyHostsOne', 'popupThirdPartyHosts') : '';
  third.hidden = counts.thirdPartyHosts === 0;
  if (state?.counting !== false) $('#pp-count-section').setAttribute('aria-label', `${t('popupBlockedOnPage')}: ${fmtNumber(total)}`);
}

function feedRow(e: ActivityEvent, isNew: boolean): HTMLElement {
  const listName = e.list ? dir.name(e.list) : '';
  const meta = h('span', { class: 'pp-ev__meta' }, h('span', { text: typeLabel(e.type) }), e.kind !== 'blocked' ? h('span', { class: 'tag', text: kindLabel(e.kind) }) : null);
  return h(
    'li',
    { class: `pp-ev${isNew ? ' pp-ev--new' : ''}` },
    h(
      'div',
      { class: 'pp-ev__row' },
      h('span', { class: 'pp-ev__host', text: e.host || e.url, attrs: { title: e.host || e.url } }),
      h('time', { class: 'pp-ev__time', text: fmtTime(e.t), attrs: { datetime: new Date(e.t).toISOString() } }),
    ),
    h('div', { class: 'pp-ev__row' }, meta, h('span', { class: 'pp-ev__list', text: listName, attrs: { title: listName || undefined } })),
  );
}

function renderFeed(): void {
  const logging = state?.logging !== false;
  replace($('#pp-feed'), ...feed.map((e, i) => feedRow(e, i < freshRows)));
  freshRows = 0;
  $('#pp-feed-empty').hidden = feed.length > 0 || !logging;
  $('#pp-feed-off').hidden = logging;
}

function countEvent(e: ActivityEvent): void {
  if (e.kind === 'blocked' || e.kind === 'strict') counts.blocked++;
  else if (e.kind === 'redirected') counts.redirected++;
  else if (e.kind === 'debounced') counts.debounced++;
  else if (e.kind === 'stripped') counts.stripped++;
  if (e.thirdParty && e.host && !thirdHosts.has(e.host)) {
    thirdHosts.add(e.host);
    counts.thirdPartyHosts++;
  }
}

function addEvent(e: ActivityEvent, count: boolean): void {
  const key = evKey(e);
  if (seen.has(key)) return;
  seen.add(key);
  if (count) countEvent(e);
  feed.unshift(e);
  if (feed.length > FEED_MAX) feed.length = FEED_MAX;
  if (!reducedMotion()) freshRows = Math.min(freshRows + 1, 8);
}

function resetPage(): void {
  counts.blocked = counts.redirected = counts.stripped = counts.debounced = counts.thirdPartyHosts = 0;
  thirdHosts.clear();
  seen.clear();
  feed = [];
  schedulePaint();
}

function startLive(s: PopupState): void {
  // Events newer than the state snapshot were not counted yet; older unseen ones were.
  const snapshotT = s.recent.length ? Math.max(...s.recent.map((e) => e.t)) : 0;
  live = connectLive(tabId, {
    backlog: (events) => {
      for (const e of events) if (e.tabId === tabId) addEvent(e, e.t > snapshotT);
      feed.sort((a, b) => b.t - a.t);
      schedulePaint();
    },
    event: (e) => {
      if (e.tabId !== tabId) return;
      addEvent(e, true);
      schedulePaint();
    },
    reset: (id) => {
      if (id !== tabId) return;
      resetPage();
      // A navigation may have changed the site: refresh host and site settings.
      void refreshState();
    },
    attributed: (updates) => {
      if (applyAttributed(updates, feed)) schedulePaint();
    },
  });
  window.addEventListener('pagehide', () => live?.close(), { once: true });
}

async function refreshState(): Promise<void> {
  const res = await call<PopupState>({ type: 'popup:state', tabId });
  if (!res.ok || !res.data || typeof res.data !== 'object') return;
  const prev = state;
  const next = normalisePopupState(res.data, tabId);
  if (prev && (next.globallyDisabled !== prev.globallyDisabled || next.filterable !== prev.filterable)) {
    // The kind of page changed (browser page, policy kill switch): start over.
    location.reload();
    return;
  }
  state = next;
  renderHeader(next);
  if (!prev || next.site !== prev.site) {
    renderControls();
    void matched?.refresh();
  } else {
    renderCountMode();
  }
}

// --------------------------------------------------------------------- tabs --

function setupTabs(): void {
  const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('.pp-tab'));
  const select = (tab: HTMLButtonElement, focus: boolean): void => {
    for (const tb of tabs) {
      const on = tb === tab;
      tb.setAttribute('aria-selected', String(on));
      tb.tabIndex = on ? 0 : -1;
      const panel = document.getElementById(tb.getAttribute('aria-controls') ?? '');
      if (panel) panel.hidden = !on;
    }
    if (focus) tab.focus();
    try {
      localStorage.setItem(TAB_KEY, tab.id);
    } catch {
      /* storage may be unavailable */
    }
  };
  for (const tab of tabs) {
    tab.addEventListener('click', () => {
      select(tab, false);
      // A click is a user gesture: getMatchedRules is quota-exempt here.
      if (tab.id === 'pp-tab-rules') void matched?.refresh();
    });
  }
  $('.pp-tabs__bar').addEventListener('keydown', (ev) => {
    const idx = tabs.findIndex((tb) => tb.getAttribute('aria-selected') === 'true');
    let next = -1;
    if (ev.key === 'ArrowRight') next = (idx + 1) % tabs.length;
    else if (ev.key === 'ArrowLeft') next = (idx - 1 + tabs.length) % tabs.length;
    else if (ev.key === 'Home') next = 0;
    else if (ev.key === 'End') next = tabs.length - 1;
    if (next < 0) return;
    ev.preventDefault();
    select(tabs[next], true);
    if (tabs[next].id === 'pp-tab-rules') void matched?.refresh();
  });
  let saved: string | null = null;
  try {
    saved = localStorage.getItem(TAB_KEY);
  } catch {
    saved = null;
  }
  const initial = tabs.find((tb) => tb.id === saved);
  if (initial) select(initial, false);
}

// --------------------------------------------------------------------- main --

function bindStatic(): void {
  $('#pp-dashboard').addEventListener('click', () => {
    void openDashboard();
    closeSoon();
  });
  $('#pp-feed-all').addEventListener('click', () => {
    void openDashboard('activity');
    closeSoon();
  });
  $('#pp-feed-settings').addEventListener('click', () => {
    void openDashboard('settings');
    closeSoon();
  });
  $('#pp-reload-btn').addEventListener('click', async () => {
    try {
      await chrome.tabs.reload(tabId);
    } catch {
      /* tab may be gone */
    }
    closeSoon();
  });
  $('#pp-reload-close').addEventListener('click', () => {
    $('#pp-reload').hidden = true;
  });
  $('#pp-rules-refresh').addEventListener('click', () => void matched?.refresh());
  $('#pp-report').addEventListener('click', async () => {
    if (!state) return;
    const opened = await startReport(state);
    if (opened) closeSoon();
  });
}

/** Calm full-panel state: no counters, no tabs, no per-site switch. */
function renderCalm(stateName: string, sectionId: string, s: PopupState): void {
  document.body.dataset.state = stateName;
  setHidden(sectionId, false);
  setHidden('pp-count-section', true);
  setHidden('pp-tabs', true);
  $('.pp-site__row').hidden = true;
  if (!s.host) $('.pp-site').hidden = true;
}

function render(s: PopupState): void {
  document.body.dataset.state = 'ready';
  renderHeader(s);

  if (s.globallyDisabled) {
    // Managed kill switch: protection is off everywhere, so there is nothing to toggle.
    renderCalm('global-off', 'pp-global-off', s);
    $('#pp-mark').classList.add('mark--off');
    return;
  }
  if (!s.filterable) {
    renderCalm('unfilterable', 'pp-unfilterable', s);
    return;
  }

  counts.blocked = s.counts.blocked;
  counts.redirected = s.counts.redirected;
  counts.stripped = s.counts.stripped;
  counts.debounced = s.counts.debounced;
  counts.thirdPartyHosts = s.counts.thirdPartyHosts;
  for (const e of s.recent) {
    seen.add(evKey(e));
    if (e.thirdParty && e.host) thirdHosts.add(e.host);
  }
  feed = s.recent.slice().sort((a, b) => b.t - a.t).slice(0, FEED_MAX);
  paintCounts();
  renderControls();

  const channel = s.managed.reportBrokenSite;
  $('#pp-report').hidden = channel === 'none' || (channel === 'email' && !s.managed.supportEmail);
}

async function main(): Promise<void> {
  translate();
  hydrateIcons();
  setupTabs();
  bindStatic();

  const metaPromise = fetchPackaged<BuildMeta>('rulesets/meta.json');
  // popup.html?tabId=<n> (popup opened as a tab, e.g. in tests); otherwise the active tab.
  const fromQuery = tabIdFromSearch(location.search);
  if (fromQuery !== null) {
    tabId = fromQuery;
  } else {
    const tab = await activeTab();
    if (!tab || tab.id === undefined) return showError();
    tabId = tab.id;
  }

  const res = await call<PopupState>({ type: 'popup:state', tabId });
  if (!res.ok || !res.data || typeof res.data !== 'object') return showError();
  state = normalisePopupState(res.data, tabId);
  render(state);
  if (!state.filterable || state.globallyDisabled) return;

  startLive(state);
  matched = createMatchedPanel($('#pp-rules'), $('#pp-rules-count'), tabId, dir);
  void matched.refresh();

  const meta = await metaPromise;
  if (meta) {
    dir = new ListDirectory(meta);
    matched.setDirectory(dir);
    renderFeed();
  }
}

void main().catch((err) => {
  console.error('[bastion] popup failed', err);
  showError();
});
