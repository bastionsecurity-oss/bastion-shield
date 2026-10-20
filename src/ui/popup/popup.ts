// Bastion Shield — toolbar popup (compact). Shows the current site with its
// protection switch, live counters for the current page load, an estimate of
// data and time saved, the blocking mode, and actions: report a broken site,
// open the expanded view (panel.html, same popup) and the «Cyber-Vorfall?»
// CTA. In nerd mode a statusline sits at the bottom (nerd.ts).
// Budget: well under 30 ms of script before first meaningful paint, so the
// static skeleton is in popup.html and everything here is incremental.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ActivityEvent, BlockingMode, PopupState, SiteSettings } from '../../shared/types.ts';
import { $, reducedMotion, replace } from '../shared/dom.ts';
import { fmtNumber, initI18n, initI18nSync, plural, t, translate } from '../shared/i18n.ts';
import { readHandoff, writeHandoff } from '../shared/handoff.ts';
import { hydrateIcons } from '../shared/icons.ts';
import { call, connectLive, type LiveConnection } from '../shared/messaging.ts';
import { lockIcon, segmented, type SegHandle } from '../shared/controls.ts';
import { orgNameEl } from '../shared/org.ts';
import { ctaOrBrand } from '../shared/incident.ts';
import { estimateFromSample, fmtBytes, fmtDuration, savingsUnits } from '../shared/savings.ts';
import { countEvent, eventKey, sampleType } from '../shared/page-activity.ts';
import { createNerdStatusline, type NerdStatusline } from './nerd.ts';
import { startReport } from './report.ts';
import { setupExpand } from './expand.ts';
import { setSiteSettings } from './site-set.ts';
import { normalisePopupState, tabIdFromSearch } from './state.ts';

let state: PopupState | null = null;
let tabId = -1;
let live: LiveConnection | null = null;

const counts = { blocked: 0, redirected: 0, stripped: 0, debounced: 0, thirdPartyHosts: 0 };
const thirdHosts = new Set<string>();
const seen = new Set<string>();
/** Resource types of the blocked requests seen on this page (sample for the savings estimate). */
let types: string[] = [];
let shownTotal = -1;
let paintQueued = false;

let modeSeg: SegHandle<BlockingMode> | null = null;
let nerd: NerdStatusline | null = null;


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

/** Expanded view in the same popup window (Chrome resizes the popup to the new page). */
export function panelUrl(id: number, view = 'site'): string {
  return `panel.html?tabId=${id}#${view}`;
}

// ------------------------------------------------------------------- render --

function showError(): void {
  document.body.dataset.state = 'error';
  replace($('#pp-cta-slot'), ctaOrBrand(true, '', closeSoon));
  setHidden('pp-error', false);
  setHidden('pp-count-section', true);
  $('#pp-report').hidden = true;
}

function renderHeader(s: PopupState): void {
  const org = $('#pp-org');
  if (s.managed.organizationName) {
    replace(org, document.createTextNode(t('managedByLabel')), orgNameEl(s.managed.organizationName, s.managed.supportUrl, 'pp-org__name', closeSoon));
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
  $('#pp-host').textContent = shown || ' ';
}

/** Counter when the activity log or the per-tab counters are switched off. */
function renderCountMode(): void {
  const s = state;
  if (!s) return;
  const off = $('#pp-count-off');
  $('#pp-count-body').hidden = !s.counting;
  $('#pp-savings').hidden = !s.counting;
  off.hidden = s.counting;
  if (!s.counting) {
    // Never show a misleading 0: say that counting is off (and whether protection still runs).
    off.textContent = s.siteSettings.enabled ? t('popupCountOff') : t('popupCountOffSiteOff');
    $('#pp-count-section').setAttribute('aria-label', `${t('popupBlockedOnPage')}: ${off.textContent}`);
  }
}

function renderSiteState(): void {
  const s = state!;
  const on = s.siteSettings.enabled;
  document.body.dataset.site = on ? 'on' : 'off';
  const btn = $<HTMLButtonElement>('#pp-protect');
  btn.setAttribute('aria-checked', String(on));
  btn.disabled = s.locks.siteToggle;
  $('#pp-mark').classList.toggle('mark--off', !on);
  $('#pp-toggle-state').textContent = on ? t('popupProtectionOn') : t('popupProtectionOff');
  modeSeg?.setDisabled(!on || s.locks.settings || s.locks.mode);
  renderCountMode();
}

async function setSite(patch: SiteSettings): Promise<boolean> {
  const ok = await setSiteSettings(state!, tabId, patch);
  if (ok) showReloadHint();
  return ok;
}

function setLock(id: string, el: HTMLElement | null): void {
  const slot = $(`#${id}`);
  replace(slot, el);
  slot.hidden = el === null;
}

let protectBusy = false;

function renderControls(): void {
  const s = state!;
  const ss = s.siteSettings;
  setLock('pp-toggle-lock', s.locks.siteToggle ? lockIcon() : null);

  modeSeg = segmented<BlockingMode>({
    options: [
      { value: 'standard', label: t('modeStandard') },
      { value: 'aggressive', label: t('modeAggressive') },
    ],
    value: ss.mode,
    labelledBy: 'pp-mode-label',
    onChange: (v) => setSite({ mode: v }),
  });
  replace($('#pp-mode-slot'), modeSeg.el);
  // A policy (e.g. aggressiveSites on a parent domain) fixes the mode for this site only.
  setLock('pp-mode-lock', s.locks.mode || s.locks.settings ? lockIcon() : null);
  renderSiteState();
}

async function toggleProtection(): Promise<void> {
  const s = state;
  if (!s || protectBusy || s.locks.siteToggle) return;
  protectBusy = true;
  const next = !s.siteSettings.enabled;
  // Optimistic: flip now, revert if the service worker refuses.
  s.siteSettings.enabled = next;
  renderSiteState();
  const ok = await setSite({ enabled: next });
  if (!ok) s.siteSettings.enabled = !next;
  renderSiteState();
  protectBusy = false;
}

function showReloadHint(): void {
  const bar = $('#pp-reload');
  if (!bar.hidden) return;
  bar.hidden = false;
}

// --------------------------------------------------------------- counting --

function schedulePaint(): void {
  if (paintQueued) return;
  paintQueued = true;
  requestAnimationFrame(() => {
    paintQueued = false;
    paintCounts();
  });
}

function setBar(id: string, n: number): void {
  const el = $(`#${id}`);
  el.style.flexGrow = String(n);
  el.hidden = n <= 0;
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
  // Bar: blocked (dark), replaced by surrogates (mid), the rest of the requests is unknown,
  // so the light track only shows when nothing was blocked yet.
  setBar('pp-bar-blocked', counts.blocked);
  setBar('pp-bar-replaced', counts.redirected + counts.stripped + counts.debounced);
  setBar('pp-bar-rest', total === 0 ? 1 : 0);
  // Distinct third-party hosts are context for the total, not another blocked count.
  $('#pp-c-third').textContent = counts.thirdPartyHosts > 0 ? plural(counts.thirdPartyHosts, 'popupHostsOne', 'popupHosts') : '';

  const est = estimateFromSample(types, counts.blocked + counts.redirected);
  const data = fmtBytes(est.bytes);
  const time = fmtDuration(est.ms, savingsUnits());
  $('#pp-data').textContent = data.value;
  $('#pp-data-unit').textContent = data.unit;
  $('#pp-time').textContent = time.value;
  $('#pp-time-unit').textContent = time.unit;
  $('#pp-savings').title = t('savingsEstimateNote');
  if (state?.counting !== false) $('#pp-count-section').setAttribute('aria-label', `${t('popupBlockedOnPage')}: ${fmtNumber(total)}`);
}

function addEvent(e: ActivityEvent, count: boolean): void {
  const key = eventKey(e);
  if (seen.has(key)) return;
  seen.add(key);
  if (count) countEvent(counts, e, thirdHosts);
  sampleType(types, e);
}

function resetPage(): void {
  counts.blocked = counts.redirected = counts.stripped = counts.debounced = counts.thirdPartyHosts = 0;
  thirdHosts.clear();
  seen.clear();
  types = [];
  schedulePaint();
}

function startLive(s: PopupState): void {
  // Events newer than the state snapshot were not counted yet; older unseen ones were.
  const snapshotT = s.recent.length ? Math.max(...s.recent.map((e) => e.t)) : 0;
  live = connectLive(tabId, {
    backlog: (events) => {
      for (const e of events) if (e.tabId === tabId) addEvent(e, e.t > snapshotT);
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
  });
  window.addEventListener('pagehide', () => live?.close(), { once: true });
}

async function refreshState(poll = false): Promise<void> {
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
  if (!prev || next.site !== prev.site) renderControls();
  else renderCountMode();
  renderNerd(next, !poll);
}

/** Fingerprinting and clipboard counters are not streamed: poll while the statusline is shown. */
const NERD_POLL_MS = 2500;
let nerdPoll: ReturnType<typeof setInterval> | undefined;

/** Nerd statusline: created on first use, so a popup with nerd mode off never touches it. */
function renderNerd(s: PopupState, askBisect: boolean): void {
  if (!s.nerd && !nerd) return;
  nerd ??= createNerdStatusline($('#pp-nerd'), {
    tabId,
    logging: () => state?.logging !== false,
    counts: () => ({ ...counts }),
    refresh: () => void refreshState(),
    close: closeSoon,
  });
  nerd.update(s);
  if (askBisect) void nerd.refreshBisect();
  if (s.nerd && nerdPoll === undefined && s.filterable && !s.globallyDisabled) {
    nerdPoll = setInterval(() => void refreshState(true), NERD_POLL_MS);
    window.addEventListener('pagehide', () => clearInterval(nerdPoll), { once: true });
  }
}

// --------------------------------------------------------------------- main --

function bindStatic(): void {
  $('#pp-protect').addEventListener('click', () => void toggleProtection());
  // Gear: morph into the expanded view inside this popup (expand.ts). The hand-off lets
  // the expanded view draw its first frame at once.
  const morph = setupExpand({
    panelUrl: () => `${panelUrl(tabId).replace('#', '&embed=1#')}`,
    beforeExpand: () => {
      if (state) writeHandoff(tabId, { ...state, counts: { ...counts } });
    },
    fallback: () => {
      live?.close();
      if (state) writeHandoff(tabId, { ...state, counts: { ...counts } });
      location.href = panelUrl(tabId);
    },
    onCollapse: (raw) => {
      // Changes made in the expanded view (protection, mode) show in the compact one.
      if (!raw || typeof raw !== 'object') return;
      const next = normalisePopupState(raw, tabId);
      if (!state) return;
      state.siteSettings = next.siteSettings;
      if (state.incidentCta !== next.incidentCta) replace($('#pp-cta-slot'), ctaOrBrand(next.incidentCta, '', closeSoon));
      state.incidentCta = next.incidentCta;
      modeSeg?.set(next.siteSettings.mode);
      renderSiteState();
    },
  });
  $('#pp-expand').addEventListener('click', () => morph.expand());
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
  $('#pp-report').addEventListener('click', async () => {
    if (!state) return;
    const opened = await startReport(state);
    if (opened) closeSoon();
  });
}

/** Calm full-panel state: no counters, no per-site switch. */
function renderCalm(stateName: string, sectionId: string): void {
  document.body.dataset.state = stateName;
  setHidden(sectionId, false);
  setHidden('pp-count-section', true);
}

function render(s: PopupState): void {
  document.body.dataset.state = 'ready';
  renderHeader(s);
  replace($('#pp-cta-slot'), ctaOrBrand(s.incidentCta, '', closeSoon));

  if (s.globallyDisabled) {
    // Managed kill switch: protection is off everywhere, so there is nothing to toggle.
    renderCalm('global-off', 'pp-global-off');
    return;
  }
  if (!s.filterable) {
    renderCalm('unfilterable', 'pp-unfilterable');
    return;
  }

  counts.blocked = s.counts.blocked;
  counts.redirected = s.counts.redirected;
  counts.stripped = s.counts.stripped;
  counts.debounced = s.counts.debounced;
  counts.thirdPartyHosts = s.counts.thirdPartyHosts;
  for (const e of s.recent) {
    seen.add(eventKey(e));
    sampleType(types, e);
    if (e.thirdParty && e.host) thirdHosts.add(e.host);
  }
  paintCounts();
  renderControls();

  const channel = s.managed.reportBrokenSite;
  $('#pp-report').hidden = channel === 'none' || (channel === 'email' && !s.managed.supportEmail);
  renderNerd(s, true);
}

async function main(): Promise<void> {
  if (!initI18nSync()) await initI18n();
  translate();
  hydrateIcons();
  bindStatic();

  // Back from the expanded view (same popup window): draw the hand-off now, refresh below.
  const handoff = readHandoff(tabIdFromSearch(location.search));
  if (handoff) {
    tabId = handoff.tabId;
    state = normalisePopupState(handoff.state, tabId);
    render(state);
  }

  // popup.html?tabId=<n> (popup opened as a tab, e.g. in tests, or back from the panel).
  const fromQuery = tabIdFromSearch(location.search);
  if (fromQuery !== null) {
    tabId = fromQuery;
  } else {
    const tab = await activeTab();
    if (!tab || tab.id === undefined) return showError();
    tabId = tab.id;
  }

  const res = await call<PopupState>({ type: 'popup:state', tabId });
  if (!res.ok || !res.data || typeof res.data !== 'object') return handoff ? undefined : showError();
  state = normalisePopupState(res.data, tabId);
  if (handoff) resetPage();
  render(state);
  if (!state.filterable || state.globallyDisabled) return;
  startLive(state);
}

void main().catch((err) => {
  console.error('[bastion] popup failed', err);
  showError();
});
