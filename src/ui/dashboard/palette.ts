// Bastion Shield — command palette for the dashboard and the expanded popup
// (Ctrl+K / ⌘K, or the search button in the navigation). One field finds
// sections, individual settings (by name or by what they do), filter lists
// and a few actions; arrow keys move, Enter opens, Esc closes. Opening a
// setting navigates to its section, scrolls it into view, highlights the row
// and focuses its control. Matching lives in palette-core.ts.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { $$, h, replace } from '../shared/dom.ts';
import { localized, t } from '../shared/i18n.ts';
import { icon } from '../shared/icons.ts';
import { openInTab, popupMode } from './common.ts';
import { rankEntries, type PaletteEntry, type PaletteGroup, type PaletteHit } from './palette-core.ts';
import { railAvailable, railCollapsed, setRail, shortcutLabel } from './rail.ts';
import { getConfig, getLists, isLocked } from './store.ts';
import { persist } from './views/privacy.ts';

interface Item extends PaletteEntry {
  run(): void | Promise<void>;
  /** Leading visual: a nav tile clone or an icon name. */
  lead?: Node;
}

/** Setting rows by section: [label key, group title key, description key?]. */
const SETTINGS: Record<string, [string, string, string?][]> = {
  privacy: [
    ['privGpc', 'privGroupSignals', 'privGpcDesc'],
    ['privParams', 'privGroupSignals', 'privParamsDesc'],
    ['privDebounce', 'privGroupSignals', 'privDebounceDesc'],
    ['privAmp', 'privGroupSignals', 'privAmpDesc'],
    ['privClipboard', 'privGroupClipboard', 'privClipboardDesc'],
    ['privFingerprint', 'privGroupFingerprint', 'privFingerprintDesc'],
    ['privPing', 'privGroupBrowser', 'privPingDesc'],
    ['privSandbox', 'privGroupBrowser', 'privSandboxDesc'],
    ['privWebrtc', 'privGroupBrowser', 'privWebrtcDesc'],
    ['privCookies', 'privGroupBrowser', 'privCookiesDesc'],
  ],
  settings: [
    ['setMode', 'setGroupBlocking', 'setModeDesc'],
    ['setLanguage', 'setGroupLanguage'],
    ['setBadge', 'setGroupDisplay', 'setBadgeDesc'],
    ['setIncidentCta', 'setGroupDisplay', 'setIncidentCtaDesc'],
    ['setActivityLog', 'setGroupActivity', 'setActivityLogDesc'],
    ['setHistory', 'setGroupActivity', 'setHistoryDesc'],
    ['setRetention', 'setGroupActivity', 'setRetentionDesc'],
    ['setClearHistory', 'setGroupActivity', 'setClearHistoryDesc'],
    ['setGroupBackup', 'setGroupBackup'],
    ['setGroupReset', 'setGroupReset'],
    ['nerdSettingsEnabled', 'nerdSettingsTitle', 'nerdSettingsEnabledDesc'],
  ],
};
/** Only while nerd mode is on (the rows are hidden otherwise). */
const NERD_SETTINGS: [string, string, string?][] = [
  ['nerdSettingsFpMeter', 'nerdSettingsTitle', 'nerdSettingsFpMeterDesc'],
  ['nerdSettingsLookalike', 'nerdSettingsTitle', 'nerdSettingsLookalikeDesc'],
  ['nerdSettingsDomains', 'nerdSettingsTitle', 'nerdSettingsDomainsHint'],
];

const GROUP_TITLE: Record<PaletteGroup, string> = {
  views: 'cmdkGroupViews',
  actions: 'cmdkGroupActions',
  settings: 'cmdkGroupSettings',
  lists: 'cmdkGroupLists',
};

let dialog: HTMLDialogElement | null = null;

/** Wait until the router has drawn `view` (dashboard.ts dispatches db:routed). */
function routedTo(view: string): Promise<boolean> {
  if (document.body.dataset.view === view && document.querySelector(`.db-page--${view}`)) return Promise.resolve(true);
  return new Promise((resolve) => {
    const done = (ok: boolean) => {
      document.removeEventListener('db:routed', on);
      clearTimeout(timer);
      resolve(ok);
    };
    const on = (ev: Event) => {
      if ((ev as CustomEvent<string>).detail === view) done(true);
    };
    const timer = setTimeout(() => done(false), 4000);
    document.addEventListener('db:routed', on);
    location.hash = `#${view}`;
  });
}

/** Go to a section, then bring the element labelled `text` into view, highlight it and focus its control. */
async function reveal(view: string, text: string, selector: string): Promise<void> {
  if (!(await routedTo(view))) return;
  const page = document.querySelector(`.db-page--${view}`);
  const label = Array.from(page?.querySelectorAll<HTMLElement>(selector) ?? []).find((el) => el.textContent?.trim() === text);
  if (!label) return;
  const target = label.closest<HTMLElement>('.db-row, .lists-row, .nerd-domains__block, .db-panel') ?? label;
  target.scrollIntoView({ block: 'center', behavior: 'smooth' });
  target.classList.remove('db-flash');
  void target.offsetWidth; // restart the animation
  target.classList.add('db-flash');
  setTimeout(() => target.classList.remove('db-flash'), 1800);
  const ctl = target.querySelector<HTMLElement>('.db-row__ctl button, .db-row__ctl select, .db-row__ctl input, .db-row__ctl a, [role="switch"], textarea, button');
  ctl?.focus({ preventScroll: true });
}

async function buildItems(): Promise<Item[]> {
  const items: Item[] = [];
  const cfgR = await getConfig();
  const cfg = cfgR.ok ? cfgR.data : null;
  const nerd = cfg?.settings.nerd?.enabled === true;

  // Sections: straight from the navigation, so the palette never offers what the nav hides.
  for (const a of $$<HTMLAnchorElement>('.db-nav__list .db-nav__link[data-view]')) {
    if (a.closest('[hidden]')) continue;
    const view = a.dataset.view ?? '';
    const label = a.querySelector('.db-nav__label')?.textContent?.trim() ?? view;
    const tile = a.querySelector('.db-nav__tile')?.cloneNode(true) ?? null;
    items.push({
      id: `view:${view}`,
      group: 'views',
      label,
      lead: tile ?? undefined,
      hint: a.dataset.openTab ? t('cmdkOpensTab') : undefined,
      run: () => {
        if (a.dataset.openTab) void openInTab(a.dataset.openTab);
        else location.hash = `#${view}`;
      },
    });
  }

  const sectionTitle = (view: string) => t(view === 'privacy' ? 'navPrivacy' : 'navSettings');
  const addSettings = (view: string, rows: [string, string, string?][]) => {
    for (const [key, groupKey, descKey] of rows) {
      const text = t(key);
      items.push({
        id: `set:${key}`,
        group: 'settings',
        label: text,
        hint: groupKey === key ? sectionTitle(view) : `${sectionTitle(view)} › ${t(groupKey)}`,
        keywords: descKey ? t(descKey) : undefined,
        run: () => reveal(view, text, '.db-row__label, .db-panel__head h2, .db-panel__head .eyebrow'),
      });
    }
  };
  addSettings('privacy', SETTINGS.privacy);
  addSettings('settings', SETTINGS.settings);
  if (nerd) addSettings('settings', NERD_SETTINGS);

  // Filter lists by name (and description).
  const lists = await getLists();
  if (lists.ok) {
    for (const l of lists.data.meta.lists ?? []) {
      const name = localized(l.name);
      if (!name) continue;
      items.push({
        id: `list:${l.id}`,
        group: 'lists',
        label: name,
        hint: lists.data.enabled[l.id] ? t('cmdkListOn') : t('cmdkListOff'),
        keywords: localized(l.description),
        run: () => reveal('lists', name, '.lists-row__name'),
      });
    }
  }

  // Actions.
  if (railAvailable()) {
    items.push({
      id: 'act:rail',
      group: 'actions',
      label: t(railCollapsed() ? 'railExpand' : 'railCollapse'),
      keywords: 'sidebar seitenleiste navigation menu',
      shortcut: shortcutLabel('.'),
      lead: icon('dashboard', 15),
      run: () => setRail(),
    });
  }
  if (popupMode) {
    items.push({
      id: 'act:dashboard',
      group: 'actions',
      label: t('panelOpenDashboard'),
      keywords: 'dashboard tab',
      lead: icon('openTab', 15),
      run: () => openInTab('overview'),
    });
  }
  if (cfg && !isLocked(cfg, 'nerd.enabled')) {
    // The easter egg: never listed, found by typing it.
    items.push({
      id: 'act:nerd',
      group: 'actions',
      label: t(nerd ? 'cmdkNerdOff' : 'cmdkNerdOn'),
      keywords: 'nerd sudo developer entwickler hacker matrix',
      hidden: true,
      lead: icon('lab', 15),
      run: async () => {
        await persist({ nerd: { enabled: !nerd } });
      },
    });
  }
  return items;
}

function highlight(label: string, ranges: [number, number][]): Node[] {
  if (!ranges.length) return [document.createTextNode(label)];
  const out: Node[] = [];
  let at = 0;
  for (const [a, b] of ranges) {
    if (a > at) out.push(document.createTextNode(label.slice(at, a)));
    out.push(h('mark', { text: label.slice(a, b) }));
    at = b;
  }
  if (at < label.length) out.push(document.createTextNode(label.slice(at)));
  return out;
}

function leadFor(item: Item): Node {
  if (item.lead) return item.lead.cloneNode(true);
  if (item.group === 'lists') return icon('lists', 15);
  return icon('settings', 15);
}

async function open(): Promise<void> {
  if (dialog?.open) return;
  // Another modal (a confirmation) owns the keyboard.
  if (document.querySelector('dialog[open]')) return;
  const items = await buildItems();
  let hits: PaletteHit[] = [];
  let active = 0;

  const listId = 'cmdk-list';
  const input = h('input', {
    class: 'cmdk__input',
    attrs: {
      type: 'text',
      role: 'combobox',
      'aria-expanded': 'true',
      'aria-controls': listId,
      'aria-autocomplete': 'list',
      'aria-label': t('cmdkLabel'),
      placeholder: t('cmdkPlaceholder'),
      autocomplete: 'off',
      spellcheck: 'false',
    },
  });
  const list = h('ul', { class: 'cmdk__list', attrs: { id: listId, role: 'listbox', 'aria-label': t('cmdkLabel') } });
  const empty = h('p', { class: 'cmdk__empty', attrs: { role: 'status' } });
  const kbd = (k: string) => h('kbd', { class: 'cmdk__kbd', text: k });
  const d = h(
    'dialog',
    { class: `cmdk${popupMode ? ' cmdk--popup' : ''}`, attrs: { 'aria-label': t('cmdkLabel') } },
    h(
      'div',
      { class: 'cmdk__box' },
      h('div', { class: 'cmdk__field' }, icon('search', 16), input, kbd('Esc')),
      list,
      empty,
      h(
        'div',
        { class: 'cmdk__foot', attrs: { 'aria-hidden': 'true' } },
        h('span', null, kbd('↑'), kbd('↓'), ` ${t('cmdkHintMove')}`),
        h('span', null, kbd('↵'), ` ${t('cmdkHintOpen')}`),
        h('span', null, kbd('Esc'), ` ${t('cmdkHintClose')}`),
      ),
    ),
  ) as HTMLDialogElement;
  dialog = d;

  const optionId = (i: number) => `cmdk-opt-${i}`;
  const setActive = (i: number, scroll = true) => {
    if (!hits.length) return;
    active = (i + hits.length) % hits.length;
    for (const el of Array.from(list.querySelectorAll<HTMLElement>('[role="option"]'))) {
      const on = el.id === optionId(active);
      el.setAttribute('aria-selected', String(on));
      if (on && scroll) el.scrollIntoView({ block: 'nearest' });
    }
    input.setAttribute('aria-activedescendant', optionId(active));
  };

  const draw = () => {
    hits = rankEntries(items, input.value);
    active = 0;
    const rows: Node[] = [];
    let group: PaletteGroup | null = null;
    hits.forEach((hit, i) => {
      const item = hit.entry as Item;
      if (item.group !== group) {
        group = item.group;
        rows.push(h('li', { class: 'cmdk__group', text: t(GROUP_TITLE[group]), attrs: { role: 'presentation' } }));
      }
      rows.push(
        h(
          'li',
          {
            class: `cmdk__opt cmdk__opt--${item.group}`,
            attrs: { id: optionId(i), role: 'option', 'aria-selected': 'false' },
            on: {
              pointermove: () => active !== i && setActive(i, false),
              click: () => void run(i),
            },
          },
          h('span', { class: 'cmdk__lead' }, leadFor(item)),
          h('span', { class: 'cmdk__text' }, h('span', { class: 'cmdk__label' }, ...highlight(item.label, hit.ranges)), item.hint ? h('span', { class: 'cmdk__hint', text: item.hint }) : null),
          item.shortcut ? kbd(item.shortcut) : null,
          h('span', { class: 'cmdk__enter', attrs: { 'aria-hidden': 'true' } }, icon('chevronRight', 14)),
        ),
      );
    });
    replace(list, ...rows);
    empty.textContent = hits.length ? '' : t('cmdkEmpty', input.value.trim());
    empty.hidden = hits.length > 0;
    if (hits.length) setActive(0);
    else input.removeAttribute('aria-activedescendant');
  };

  const run = async (i: number) => {
    const item = hits[i]?.entry as Item | undefined;
    if (!item) return;
    d.close();
    await item.run();
  };

  input.addEventListener('input', draw);
  input.addEventListener('keydown', (ev) => {
    if (ev.isComposing) return;
    const step = ev.key === 'ArrowDown' || (ev.key === 'Tab' && !ev.shiftKey) ? 1 : ev.key === 'ArrowUp' || (ev.key === 'Tab' && ev.shiftKey) ? -1 : ev.key === 'PageDown' ? 5 : ev.key === 'PageUp' ? -5 : 0;
    if (step) {
      ev.preventDefault();
      if (Math.abs(step) === 5) setActive(Math.max(0, Math.min(hits.length - 1, active + step)));
      else setActive(active + step);
    } else if (ev.key === 'Enter') {
      ev.preventDefault();
      void run(active);
    }
  });
  // Click on the backdrop closes.
  d.addEventListener('click', (ev) => {
    if (ev.target === d) d.close();
  });
  d.addEventListener('close', () => {
    d.remove();
    if (dialog === d) dialog = null;
  });

  document.body.appendChild(d);
  draw();
  d.showModal();
  input.focus();
}

function close(): void {
  dialog?.close();
}

/** Ctrl+K / ⌘K toggles the palette; [data-cmdk] buttons open it. */
export function initPalette(): void {
  window.addEventListener('keydown', (ev: KeyboardEvent) => {
    if ((ev.ctrlKey || ev.metaKey) && !ev.altKey && !ev.shiftKey && ev.key.toLowerCase() === 'k') {
      ev.preventDefault();
      if (dialog?.open) close();
      else void open();
    }
  });
  for (const b of $$<HTMLElement>('[data-cmdk]')) b.addEventListener('click', () => void open());
}
