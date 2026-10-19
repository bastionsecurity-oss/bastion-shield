// Bastion Shield — dashboard entry point: hash router (#overview, #activity,
// #lists, #filters, #sites, #privacy, #settings, #about, #welcome, and #site in
// the expanded popup), the navigation footer (organisation, «Cyber-Vorfall?»)
// and view lifecycle (dispose / unsaved-changes guard). The same app runs as
// the dashboard tab (dashboard.html) and as the expanded popup (panel.html).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { $, $$, h, replace } from '../shared/dom.ts';
import { initI18n, initI18nSync, t, translate } from '../shared/i18n.ts';
import { readHandoff, writeHandoff } from '../shared/handoff.ts';
import { hydrateIcons } from '../shared/icons.ts';
import { orgNameEl } from '../shared/org.ts';
import { ctaOrBrand } from '../shared/incident.ts';
import { closePopup, embedded, errorState, loading, openInTab, popupMode, popupTabId, type View } from './common.ts';
import { EASE_OUT, MORPH_PAIRS, PANEL_SELECTORS, enter, finished, isMorphMessage, leave, morphIn, morphOut, rectsOf, type MorphMessage } from '../shared/morph.ts';
import { getConfig, onStoreChange } from './store.ts';
import { collapseState, siteView } from './views/site.ts';
import { overviewView } from './views/overview.ts';
import { activityView } from './views/activity.ts';
import { listsView } from './views/lists.ts';
import { filtersView } from './views/filters.ts';
import { sitesView } from './views/sites.ts';
import { privacyView } from './views/privacy.ts';
import { settingsView } from './views/settings.ts';
import { aboutView } from './views/about.ts';
import { welcomeView } from './views/welcome.ts';

const VIEWS: Record<string, { make: () => View; titleKey: string }> = {
  site: { make: siteView, titleKey: 'navSite' },
  overview: { make: overviewView, titleKey: 'navOverview' },
  activity: { make: activityView, titleKey: 'navActivity' },
  lists: { make: listsView, titleKey: 'navLists' },
  filters: { make: filtersView, titleKey: 'navFilters' },
  sites: { make: sitesView, titleKey: 'navSites' },
  privacy: { make: privacyView, titleKey: 'navPrivacy' },
  settings: { make: settingsView, titleKey: 'navSettings' },
  about: { make: aboutView, titleKey: 'navAbout' },
  welcome: { make: welcomeView, titleKey: 'welcomeTitle' },
};

let current: { name: string; view: View } | null = null;
let navToken = 0;
let firstRoute = true;

/** In the expanded popup these open the dashboard tab instead (closing the popup would lose work). */
const TAB_ONLY = new Set(['filters', 'welcome']);

function viewName(): string {
  const raw = location.hash.replace(/^#/, '').split(/[?&/]/)[0].toLowerCase();
  const fallback = popupMode ? 'site' : 'overview';
  // «Diese Website» needs a browser tab: it only exists in the expanded popup.
  if (raw === 'site' && !popupMode) return fallback;
  return raw in VIEWS ? raw : fallback;
}

async function route(): Promise<void> {
  const name = viewName();
  if (current && current.name === name && !firstRoute) return;
  if (popupMode && TAB_ONLY.has(name)) {
    history.replaceState(null, '', `#${current?.name ?? 'site'}`);
    await openInTab(name);
    if (current) return;
    location.hash = '#site';
    return;
  }

  // Unsaved-changes guard: put the old hash back if the view wants to stay.
  if (current?.view.canLeave) {
    const ok = await current.view.canLeave();
    if (!ok) {
      // replaceState does not fire hashchange, so this does not re-enter route().
      history.replaceState(null, '', `#${current.name}`);
      return;
    }
  }
  try {
    current?.view.dispose?.();
  } catch (err) {
    console.error('[bastion] dispose failed', err);
  }

  const token = ++navToken;
  const def = VIEWS[name];
  const view = def.make();
  current = { name, view };
  document.body.dataset.view = name;
  document.title = `${t(def.titleKey)} – ${t('extName')}`;
  for (const a of $$<HTMLAnchorElement>('.db-nav__link')) {
    if (a.dataset.view === name) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }

  const root = $('#db-view');
  root.setAttribute('aria-busy', 'true');
  replace(root, loading());
  const container = h('div', { class: `db-page db-page--${name}` });
  try {
    await view.render(container);
  } catch (err) {
    console.error('[bastion] view failed', err);
    replace(container, errorState(() => location.reload()));
  }
  if (token !== navToken) return; // the user moved on while this view loaded
  replace(root, container);
  root.setAttribute('aria-busy', 'false');
  if (!firstRoute) {
    // Move focus to the new heading so screen readers announce the view.
    const heading = container.querySelector<HTMLElement>('h1');
    heading?.focus({ preventScroll: true });
    $('#db-main').scrollTop = 0;
    window.scrollTo(0, 0);
  }
  firstRoute = false;
}

/** Navigation footer: managing organisation (if any) and the «Cyber-Vorfall?» CTA or the brand plate. */
async function renderFoot(): Promise<void> {
  const foot = $('#db-nav-foot');
  // Expanded popup: draw the footer from the hand-off first (part of the morph), then confirm.
  const handoff = popupMode ? readHandoff(popupTabId()) : null;
  if (handoff && !foot.firstChild) {
    replace(
      foot,
      handoff.state.managed?.organizationName
        ? h('div', { class: 'db-nav__org' }, h('span', { class: 'db-nav__org-label', text: t('managedByLabel') }), orgNameEl(handoff.state.managed.organizationName, handoff.state.managed.supportUrl, 'db-nav__org-name'))
        : null,
      ctaOrBrand(handoff.state.incidentCta !== false, 'db-nav__cta', closePopup),
    );
  }
  const cfgR = await getConfig();
  const cfg = cfgR.ok ? cfgR.data : null;
  // Managed fleet-wide kill switch: protection is off everywhere until the policy changes.
  const globalOff = cfg?.managed.protectionEnabled === false;
  document.body.dataset.protection = globalOff ? 'off' : 'on';
  document.getElementById('db-mark')?.classList.toggle('mark--off', globalOff);
  replace(
    foot,
    cfg?.managed.organizationName
      ? h('div', { class: 'db-nav__org' }, h('span', { class: 'db-nav__org-label', text: t('managedByLabel') }), orgNameEl(cfg.managed.organizationName, cfg.managed.supportUrl, 'db-nav__org-name'))
      : null,
    ctaOrBrand(cfg?.settings.ui.incidentCta !== false, 'db-nav__cta', popupMode ? closePopup : undefined),
  );
}

/** Popup mode: collapse back to the compact popup, and send tab-only sections to the dashboard tab. */
function bindPopupChrome(): void {
  if (!popupMode) return;
  const tabId = popupTabId();
  document.getElementById('db-collapse')?.addEventListener('click', () => {
    if (embedded) {
      // Inside the compact popup: ask it to morph back (it answers with 'out').
      toParent({ bx: 'collapse', rects: rectsOf(PANEL_SELECTORS), state: collapseState?.() ?? null });
      return;
    }
    // Hand the latest numbers back so the compact popup draws at once and the tiles morph back.
    const snap = collapseState?.();
    if (snap && tabId !== null) writeHandoff(tabId, snap);
    location.href = tabId === null ? 'popup.html' : `popup.html?tabId=${tabId}`;
  });
  for (const a of $$<HTMLAnchorElement>('[data-open-tab]')) {
    a.addEventListener('click', (ev) => {
      ev.preventDefault();
      void openInTab(a.dataset.openTab ?? '');
    });
  }
}

// ------------------------------------------------ Morph (embedded panel) --

function toParent(msg: MorphMessage): void {
  window.parent.postMessage(msg, location.origin);
}

/** Everything in the view that has no counterpart in the compact popup. */
function unpaired(): HTMLElement[] {
  const paired = new Set(MORPH_PAIRS.map((p) => document.querySelector(PANEL_SELECTORS[p])));
  const out: HTMLElement[] = [];
  const view = document.querySelector('.db-page');
  for (const el of Array.from(view?.children ?? []) as HTMLElement[]) {
    if (paired.has(el)) continue;
    // The tiles row holds paired tiles: animate the tiles, not the row.
    if (el.classList.contains('site-tiles')) continue;
    out.push(el);
  }
  return out;
}

/** Our half of the morph: incoming ('in') or outgoing ('out'). */
function bindMorph(): void {
  addEventListener('message', (ev: MessageEvent) => {
    if (ev.source !== window.parent || ev.origin !== location.origin || !isMorphMessage(ev.data)) return;
    const msg = ev.data;
    const nav = document.querySelector<HTMLElement>('.db-nav');
    const anims: Animation[] = [];
    if (msg.bx === 'in' || msg.bx === 'out') document.documentElement.dataset.morph = msg.bx;
    if (msg.bx === 'in') {
      for (const p of MORPH_PAIRS) {
        const el = document.querySelector<HTMLElement>(PANEL_SELECTORS[p]);
        const from = msg.rects[p];
        if (el && from) anims.push(...morphIn(el, from));
      }
      if (nav) anims.push(enter(nav, -48, 0));
      unpaired().forEach((el, i) => anims.push(enter(el, 0, 14, 90 + i * 40)));
      void finished(anims).then(() => delete document.documentElement.dataset.morph);
    } else if (msg.bx === 'out') {
      for (const p of MORPH_PAIRS) {
        const el = document.querySelector<HTMLElement>(PANEL_SELECTORS[p]);
        const to = msg.rects[p];
        if (el && to) anims.push(...morphOut(el, to));
      }
      if (nav) anims.push(nav.animate([{ opacity: 1, transform: 'none' }, { opacity: 0, transform: 'translateX(-48px)' }], { duration: 240, easing: EASE_OUT, fill: 'forwards' }));
      for (const el of unpaired()) anims.push(leave(el, 0, 10));
    }
  });
}

async function main(): Promise<void> {
  if (!initI18nSync()) await initI18n();
  translate();
  hydrateIcons();
  bindPopupChrome();
  if (embedded) bindMorph();
  window.addEventListener('hashchange', () => void route());
  onStoreChange(() => void renderFoot());
  void renderFoot();
  await route();
  if (embedded) {
    // Tell the compact popup where our paired elements are once fonts and layout settled.
    await document.fonts?.ready?.catch(() => undefined);
    requestAnimationFrame(() => requestAnimationFrame(() => toParent({ bx: 'ready', rects: rectsOf(PANEL_SELECTORS) })));
  }
}

void main();
