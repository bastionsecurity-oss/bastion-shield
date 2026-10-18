// Bastion Shield — dashboard entry point: hash router (#overview, #activity,
// #lists, #filters, #sites, #privacy, #settings, #about, #welcome), the
// navigation status block and view lifecycle (dispose / unsaved-changes guard).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { $, $$, h, replace } from '../shared/dom.ts';
import { plural, t, translate } from '../shared/i18n.ts';
import { hydrateIcons } from '../shared/icons.ts';
import { extensionVersion } from '../shared/messaging.ts';
import { orgNameEl } from '../shared/org.ts';
import { errorState, loading, type View } from './common.ts';
import { getConfig, getLists, onStoreChange } from './store.ts';
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

function viewName(): string {
  const raw = location.hash.replace(/^#/, '').split(/[?&/]/)[0].toLowerCase();
  return raw in VIEWS ? raw : 'overview';
}

async function route(): Promise<void> {
  const name = viewName();
  if (current && current.name === name && !firstRoute) return;

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

async function renderStatus(): Promise<void> {
  const [cfgR, listsR] = await Promise.all([getConfig(), getLists()]);
  const status = $('#db-status');
  const foot = $('#db-nav-foot');
  if (!cfgR.ok) {
    replace(status, h('span', { class: 'db-status__line', text: t('dashErrorTitle') }));
    return;
  }
  const cfg = cfgR.data;
  const lists = listsR.ok ? listsR.data : null;
  const enabled = lists ? Object.values(lists.enabled).filter(Boolean).length : 0;
  // Managed fleet-wide kill switch: protection is off everywhere until the policy changes.
  const globalOff = cfg.managed.protectionEnabled === false;
  document.body.dataset.protection = globalOff ? 'off' : 'on';
  document.getElementById('db-mark')?.classList.toggle('mark--off', globalOff);
  replace(
    status,
    h('span', { class: 'db-status__state' }, h('span', { class: `db-status__dot${globalOff ? ' db-status__dot--off' : ''}`, attrs: { 'aria-hidden': 'true' } }), globalOff ? t('navStatusOff') : t('navStatusOn')),
    globalOff
      ? h('span', { class: 'db-status__line', text: t('navStatusOffByOrg') })
      : h(
          'span',
          { class: 'db-status__line' },
          cfg.settings.defaultMode === 'aggressive' ? t('navStatusAggressive') : t('navStatusStandard'),
          lists ? h('br') : null,
          lists ? plural(enabled, 'navStatusListsOne', 'navStatusLists') : null,
        ),
  );
  replace(
    foot,
    cfg.managed.organizationName
      ? h('div', { class: 'db-nav__org' }, h('span', { class: 'mono-label', text: t('managedByLabel') }), orgNameEl(cfg.managed.organizationName, cfg.managed.supportUrl, 'db-nav__org-name'))
      : null,
    h('a', { class: 'db-nav__version mono', attrs: { href: '#about' }, text: t('navVersion', extensionVersion() || '–') }),
  );
}

function main(): void {
  translate();
  hydrateIcons();
  window.addEventListener('hashchange', () => void route());
  onStoreChange(() => void renderStatus());
  void renderStatus();
  void route();
}

main();
