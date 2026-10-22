// Bastion Shield — toolbar popup (compact), artboards P01–P15. Shows the
// current site with its protection switch, live counters for the current page
// load, an estimate of data and time saved, the blocking mode, and actions:
// report a broken site (bottom sheet, report.ts), open the expanded view
// (panel.html, same popup) and the «Cyber-Vorfall?» CTA. Calm states: «Hier
// nicht aktiv» (browser pages), «Schutz pausiert» (IT kill switch), «Keine
// Verbindung» with «Erneut versuchen». In nerd mode a statusline sits at the
// bottom (nerd.ts).
// Budget: well under 30 ms of script before first meaningful paint, so the
// static skeleton is in popup.html and everything here is incremental.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ActivityEvent, BlockingMode, PopupState, SiteSettings } from '../../shared/types.ts';
import { $, h, reducedMotion, replace, toast } from '../shared/dom.ts';
import { initI18n, initI18nSync, t, translate, uiLang } from '../shared/i18n.ts';
import { readHandoff, writeHandoff } from '../shared/handoff.ts';
import { hydrateIcons, icon } from '../shared/icons.ts';
import { call, connectLive, openDashboard, type LiveConnection } from '../shared/messaging.ts';
import { lockIcon, segmented, type SegHandle } from '../shared/controls.ts';
import { orgNameEl, safeSupportUrl } from '../shared/org.ts';
import { ctaOrBrand } from '../shared/incident.ts';
import { estimateFromSample, fmtBytes, fmtDuration, savingsUnits } from '../shared/savings.ts';
import { countEvent, eventKey, sampleType } from '../shared/page-activity.ts';
import { truncateMiddle, withUnit } from '../shared/text.ts';
import { createNerdStatusline, type NerdStatusline } from './nerd.ts';
import { startReport } from './report.ts';
import { setupExpand } from './expand.ts';
import { setSiteSettings } from './site-set.ts';
import { CONN_HINT_AFTER, CONN_INITIAL, connReduce, fitText, fmtCount, normalisePopupState, tabIdFromSearch, withBusy, type ConnEvent, type ConnState } from './state.ts';

let state: PopupState | null = null;
let tabId = -1;
let live: LiveConnection | null = null;
let conn: ConnState = CONN_INITIAL;
/** Site settings when the popup opened: the reload bar hides again when they are back. */
let initialSite: { enabled: boolean; mode: BlockingMode } | null = null;

const counts = { blocked: 0, redirected: 0, stripped: 0, debounced: 0, thirdPartyHosts: 0 };
const thirdHosts = new Set<string>();
const seen = new Set<string>();
/** Resource types of the blocked requests seen on this page (sample for the savings estimate). */
let types: string[] = [];
let shownTotal = -1;
let paintQueued = false;

let modeSeg: SegHandle<BlockingMode> | null = null;
let nerd: NerdStatusline | null = null;

const num = (n: number): string => fmtCount(n, uiLang);

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

function dispatch(e: ConnEvent): void {
  conn = connReduce(conn, e);
  // After a few failures the restart hint is the way out: make it stand out.
  $('#pp-retry-hint').classList.toggle('pp-calm__hint--strong', conn.failures >= CONN_HINT_AFTER);
}

// ------------------------------------------------------------------- render --

const CALM = ['pp-unfilterable', 'pp-global-off', 'pp-error'];

/** One of the calm tiles instead of counters and switches (or none: «ready»). */
function showCalm(stateName: 'ready' | 'unfilterable' | 'global-off' | 'error', sectionId: string | null): void {
  document.body.dataset.state = stateName;
  for (const id of CALM) setHidden(id, id !== sectionId);
  setHidden('pp-count-section', sectionId !== null);
  if (sectionId !== null) setHidden('pp-site-off', true);
}

function showError(): void {
  showCalm('error', 'pp-error');
  if (!$('#pp-cta-slot').firstChild) replace($('#pp-cta-slot'), ctaOrBrand(true, '', closeSoon));
  $('#pp-report').hidden = true;
}

/** Host in the protection tile: cut in the middle so start and TLD stay, full host in title. */
function paintHost(shown: string): void {
  const wrap = $('#pp-host');
  const vis = $('#pp-host-vis');
  $('#pp-host-full').textContent = shown;
  wrap.title = shown;
  if (!shown) {
    vis.textContent = ' ';
    return;
  }
  vis.textContent = shown;
  // Measured against the tile; before layout (hidden) the full host stays and CSS cuts it.
  if (vis.clientWidth > 0) vis.textContent = fitText(shown, (c) => ((vis.textContent = c), vis.scrollWidth <= vis.clientWidth), truncateMiddle);
}

function renderHeader(s: PopupState): void {
  const org = $('#pp-org');
  if (s.managed.organizationName) {
    replace(
      org,
      icon('lock', 12),
      h('span', { class: 'pp-org__label', text: t('managedByLabel') }),
      orgNameEl(s.managed.organizationName, s.managed.supportUrl, 'pp-org__name', closeSoon),
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
  paintHost(shown);
}

/** «IT kontaktieren» under «Schutz pausiert», only when the policy names a support page or address. */
function renderContact(s: PopupState): void {
  const slot = $('#pp-contact-slot');
  const email = s.managed.supportEmail;
  const mail = email && /^[^\s@<>?#]+@[^\s@<>?#]+$/.test(email) ? `mailto:${email}` : null;
  const href = safeSupportUrl(s.managed.supportUrl) ?? mail;
  if (!href) {
    slot.hidden = true;
    replace(slot);
    return;
  }
  const web = !href.startsWith('mailto:');
  const a = h('a', { class: 'btn btn--quiet pp-calm__link', attrs: { href, target: web ? '_blank' : null, rel: 'noopener noreferrer', 'data-contact': 'it' }, text: t('popupContactIt') });
  if (web) a.addEventListener('click', () => closeSoon());
  replace(slot, a);
  slot.hidden = false;
}

/** Counter tile, the «nothing blocked here» note (site off) or «counting off» (P12). */
function renderCountMode(): void {
  const s = state;
  if (!s || document.body.dataset.state !== 'ready') return;
  const on = s.siteSettings.enabled;
  // P02: protection off for this site says so instead of showing counters.
  setHidden('pp-site-off', on);
  setHidden('pp-count-section', !on);
  $('#pp-count-body').hidden = !s.counting;
  $('#pp-count-off').hidden = s.counting;
  $('#pp-savings').hidden = !s.counting;
  document.body.classList.toggle('pp-no-savings', !s.counting);
  if (!s.counting) $('#pp-count-section').setAttribute('aria-label', `${t('popupBlockedOnPage')}: ${t('popupCounterOff')}`);
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
  syncReloadBar();
}

async function setSite(patch: SiteSettings): Promise<boolean> {
  const ok = await setSiteSettings(state!, tabId, patch);
  syncReloadBar();
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

/** What the user asked for while a save is still running (a second press is never lost). */
let protectWanted: boolean | null = null;

async function toggleProtection(): Promise<void> {
  const s = state;
  if (!s || s.locks.siteToggle) return;
  // Optimistic: flip now, revert if the service worker refuses.
  protectWanted = !(protectWanted ?? s.siteSettings.enabled);
  s.siteSettings.enabled = protectWanted;
  renderSiteState();
  if (protectBusy) return;
  protectBusy = true;
  while (protectWanted !== null) {
    const want: boolean = protectWanted;
    const ok = await setSite({ enabled: want });
    if (protectWanted !== want) continue; // pressed again meanwhile: save the latest wish
    if (!ok) s.siteSettings.enabled = !want;
    protectWanted = null;
  }
  renderSiteState();
  protectBusy = false;
}

/**
 * P04: the bar shows while the site settings differ from what the page was
 * loaded with, and hides when they are back. The popup reserves room for it
 * (body.pp-has-reload) so it never covers the CTA.
 */
function syncReloadBar(): void {
  const s = state;
  const changed = !!s && !!initialSite && (s.siteSettings.enabled !== initialSite.enabled || s.siteSettings.mode !== initialSite.mode);
  const bar = $('#pp-reload');
  if (bar.hidden === !changed) return;
  bar.hidden = !changed;
  document.body.classList.toggle('pp-has-reload', changed);
}

/** P12 «Einschalten»: turn the activity log (and with it the counters) back on. */
async function counterOn(): Promise<void> {
  const btn = $<HTMLButtonElement>('#pp-count-on');
  const res = await withBusy(
    () => call<{ ignored?: unknown }>({ type: 'settings:set', patch: { ui: { activityLog: true } } }),
    (b) => btn.setAttribute('aria-busy', String(b)),
  );
  btn.removeAttribute('aria-busy');
  if (!res.ok) {
    toast(t('errorSaveFailed'), icon('alert', 15));
    return;
  }
  if (Array.isArray(res.data?.ignored) && res.data.ignored.includes('ui.activityLog')) {
    toast(t('lockedByPolicy'), icon('lock', 15));
    return;
  }
  await refreshState();
  if (state?.counting) $<HTMLElement>('#pp-protect').focus({ preventScroll: true });
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
  const replaced = counts.redirected + counts.stripped + counts.debounced;
  const el = $('#pp-count');
  el.textContent = num(total);
  if (shownTotal >= 0 && total > shownTotal && !reducedMotion() && typeof el.animate === 'function') {
    el.animate([{ transform: 'translateY(3px)', opacity: 0.55 }, { transform: 'none', opacity: 1 }], { duration: 220, easing: 'cubic-bezier(0.2, 0, 0, 1)' });
  }
  shownTotal = total;
  $('#pp-c-blocked').textContent = num(counts.blocked);
  $('#pp-c-redirected').textContent = num(counts.redirected);
  $('#pp-c-stripped').textContent = num(counts.stripped);
  $('#pp-c-debounced').textContent = num(counts.debounced);
  // Bar: blocked (ink), replaced by surrogates or cleaned (grey); the light track only
  // shows while nothing was blocked yet. The legend names both with their counts.
  setBar('pp-bar-blocked', counts.blocked);
  setBar('pp-bar-replaced', replaced);
  setBar('pp-bar-rest', total === 0 ? 1 : 0);
  $('#pp-legend-blocked-text').textContent = t('popupLegendBlocked', num(counts.blocked));
  $('#pp-legend-replaced-text').textContent = t('popupLegendReplaced', num(replaced));
  $('#pp-legend-replaced').hidden = replaced === 0;
  // Distinct third-party hosts are context for the total, not another blocked count.
  const hosts = counts.thirdPartyHosts;
  $('#pp-c-third').textContent = hosts > 0 ? t(hosts === 1 ? 'popupHostsOne' : 'popupHosts', num(hosts)) : '';

  const est = estimateFromSample(types, counts.blocked + counts.redirected);
  const data = fmtBytes(est.bytes);
  const time = fmtDuration(est.ms, savingsUnits());
  $('#pp-data').textContent = data.value;
  $('#pp-data-unit').textContent = data.unit;
  $('#pp-time').textContent = time.value;
  $('#pp-time-unit').textContent = time.unit;
  $('#pp-stat-data').setAttribute('aria-label', `${withUnit(data.value, data.unit)} ${t('popupDataSaved')}`);
  $('#pp-stat-time').setAttribute('aria-label', `${withUnit(time.value, time.unit)} ${t('popupTimeSaved')}`);
  $('#pp-savings').title = t('savingsEstimateNote');
  if (state?.counting !== false) $('#pp-count-section').setAttribute('aria-label', `${t('popupBlockedOnPage')}: ${num(total)}`);
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
  live?.close();
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
      // A navigation reloads the page: what it was loaded with is the new baseline.
      initialSite = null;
      // A navigation may have changed the site: refresh host and site settings.
      void refreshState();
    },
  });
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
  initialSite ??= { enabled: next.siteSettings.enabled, mode: next.siteSettings.mode };
  renderHeader(next);
  if (!prev || next.site !== prev.site) renderControls();
  else {
    renderCountMode();
    syncReloadBar();
  }
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
  $('#pp-expand').addEventListener('click', () => {
    // Without a tab (no connection) there is no «Diese Website»: open the settings instead.
    if (tabId < 0) {
      void openDashboard('settings').then(closeSoon);
      return;
    }
    morph.expand();
  });
  $('#pp-reload-btn').addEventListener('click', async () => {
    try {
      await chrome.tabs.reload(tabId);
    } catch {
      /* tab may be gone */
    }
    closeSoon();
  });
  $('#pp-report').addEventListener('click', async () => {
    if (!state) return;
    const opened = await startReport(state);
    if (opened) closeSoon();
  });
  $('#pp-count-on').addEventListener('click', () => void counterOn());
  $('#pp-retry').addEventListener('click', () => void retry());
}

function render(s: PopupState): void {
  renderHeader(s);
  replace($('#pp-cta-slot'), ctaOrBrand(s.incidentCta, '', closeSoon));

  if (s.globallyDisabled) {
    // P06: managed kill switch. Protection is off everywhere, so there is nothing to toggle.
    showCalm('global-off', 'pp-global-off');
    renderContact(s);
    $('#pp-report').hidden = true;
    return;
  }
  if (!s.filterable) {
    // P05: browser pages and stores. Nothing to report either.
    showCalm('unfilterable', 'pp-unfilterable');
    $('#pp-report').hidden = true;
    return;
  }
  showCalm('ready', null);

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
  // The host is measured once the tile is laid out.
  renderHeader(s);

  const channel = s.managed.reportBrokenSite;
  $('#pp-report').hidden = channel === 'none' || (channel === 'email' && !s.managed.supportEmail);
  renderNerd(s, true);
}

/** Ask the service worker for this tab's state and draw it. False when it did not answer. */
async function load(handoff: boolean): Promise<boolean> {
  dispatch('request');
  if (tabId < 0) {
    const tab = await activeTab();
    if (!tab || tab.id === undefined) {
      dispatch('fail');
      return false;
    }
    tabId = tab.id;
  }
  const res = await call<PopupState>({ type: 'popup:state', tabId });
  if (!res.ok || !res.data || typeof res.data !== 'object') {
    dispatch('fail');
    return false;
  }
  dispatch('ok');
  state = normalisePopupState(res.data, tabId);
  initialSite = { enabled: state.siteSettings.enabled, mode: state.siteSettings.mode };
  if (handoff) resetPage();
  render(state);
  if (state.filterable && !state.globallyDisabled) startLive(state);
  return true;
}

/** P07 «Erneut versuchen»: the button keeps its label, spinner after ~150 ms for at least ~300 ms. */
async function retry(): Promise<void> {
  const btn = $<HTMLButtonElement>('#pp-retry');
  if (conn.retrying) return;
  const ok = await withBusy(
    () => load(false),
    (b) => btn.setAttribute('aria-busy', String(b)),
  );
  btn.removeAttribute('aria-busy');
  if (ok) $<HTMLElement>(state && state.filterable && !state.globallyDisabled ? '#pp-protect' : '#pp-expand').focus({ preventScroll: true });
  else showError();
}

async function main(): Promise<void> {
  if (!initI18nSync()) await initI18n();
  translate();
  hydrateIcons();
  bindStatic();
  window.addEventListener('pagehide', () => live?.close(), { once: true });

  // Back from the expanded view (same popup window): draw the hand-off now, refresh below.
  const handoff = readHandoff(tabIdFromSearch(location.search));
  if (handoff) {
    tabId = handoff.tabId;
    state = normalisePopupState(handoff.state, tabId);
    render(state);
  }

  // popup.html?tabId=<n> (popup opened as a tab, e.g. in tests, or back from the panel).
  const fromQuery = tabIdFromSearch(location.search);
  if (fromQuery !== null) tabId = fromQuery;

  const ok = await load(!!handoff);
  if (!ok && !handoff) showError();
}

void main().catch((err) => {
  console.error('[bastion] popup failed', err);
  showError();
});
