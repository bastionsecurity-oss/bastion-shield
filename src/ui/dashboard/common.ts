// Bastion Shield — dashboard building blocks: page header, panels, setting
// rows, loading / error / empty states and date keys shared by all views.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { append, h, type Child } from '../shared/dom.ts';
import { t } from '../shared/i18n.ts';
import { icon } from '../shared/icons.ts';
import { openDashboard } from '../shared/messaging.ts';

export interface View {
  /** Render into root. May be async; the router shows a loading state meanwhile. */
  render(root: HTMLElement): void | Promise<void>;
  /** Return false to keep the user on this view (e.g. unsaved edits). */
  canLeave?(): boolean | Promise<boolean>;
  /** Stop timers / ports when the user navigates away. */
  dispose?(): void;
}

/**
 * Popup mode: the app runs as the expanded popup (panel.html, 760×560)
 * instead of the dashboard tab. Sections that need room or would lose work
 * when the popup closes open the dashboard tab instead.
 */
export const popupMode = typeof document !== 'undefined' && document.body?.classList.contains('db--popup') === true;

/** Expanded view running inside the compact popup's iframe (the morph, see popup/expand.ts). */
export const embedded = popupMode && typeof window !== 'undefined' && window.parent !== window;

/** Close the popup window (from the iframe: its top window). */
export function closePopup(): void {
  setTimeout(() => {
    try {
      (window.top ?? window).close();
    } catch {
      window.close();
    }
  }, 30);
}

/** Tab the expanded popup belongs to (panel.html?tabId=<n>), or null. */
export function popupTabId(): number | null {
  const raw = new URLSearchParams(typeof location !== 'undefined' ? location.search : '').get('tabId');
  const n = raw === null ? Number.NaN : Number(raw);
  return Number.isInteger(n) && n >= 0 ? n : null;
}

/** Open a dashboard section in a tab; from the popup, close the popup afterwards. */
export async function openInTab(hash: string): Promise<void> {
  await openDashboard(hash);
  if (popupMode) closePopup();
}

/** Button that opens a dashboard section in a tab (used in popup mode). */
export function openTabButton(hash: string, label: string): HTMLElement {
  return h('button', { class: 'btn btn--secondary btn--sm', attrs: { type: 'button', 'data-open-tab': hash }, on: { click: () => void openInTab(hash) } }, icon('openTab', 14), label);
}

/** A figure tile («Diese Website», «Übersicht»): value, optional unit, label; `dark` for the headline figure. */
export function statTile(value: string, unit: string, label: string, dark = false, id?: string): HTMLElement {
  return h(
    'div',
    { class: `site-tile${dark ? ' site-tile--dark' : ''}`, attrs: { id } },
    h('div', { class: 'site-tile__value' }, h('span', { class: 'num', text: value }), unit ? h('span', { class: 'site-tile__unit', text: ` ${unit}` }) : null),
    h('div', { class: 'site-tile__label', text: label }),
  );
}

/** Append children, skipping null/false (Element.append would render "null"). */
export function mount(root: Element, ...children: Child[]): void {
  append(root, children);
}

/**
 * Page header: 40px title (24px in the panel), one visible lead sentence
 * (16px, ink 2), optional actions aligned to the right and the bottom. The h1
 * takes focus on navigation so screen readers announce the view.
 */
export function pageHead(title: string, lead?: Child, aside?: Child): HTMLElement {
  return h(
    'header',
    { class: 'db-head' },
    h('div', { class: 'db-head__text' }, h('h1', { class: 'db-head__title', text: title, attrs: { tabindex: -1 } }), lead ? (typeof lead === 'string' ? h('p', { class: 'db-head__lead', text: lead }) : lead) : null),
    aside ? h('div', { class: 'db-head__aside' }, aside) : null,
  );
}

export interface PanelOptions {
  title?: string;
  aside?: Child;
  class?: string;
  id?: string;
  /** Use an <h2> for the panel title (default) so the outline stays meaningful. */
  flush?: boolean;
}

/** Section of a settings-like view: 24px h2, then rows separated by 1px lines, no fill (DB27). */
export function panel(opts: PanelOptions, ...children: Child[]): HTMLElement {
  return h(
    'section',
    { class: `db-panel${opts.flush ? ' db-panel--flush' : ''}${opts.class ? ` ${opts.class}` : ''}`, attrs: { id: opts.id } },
    opts.title ? h('div', { class: 'db-panel__head' }, h('h2', { class: 'db-panel__title', text: opts.title }), opts.aside ? h('span', { class: 'db-panel__aside' }, opts.aside) : null) : null,
    ...children,
  );
}

export interface CardOptions {
  title?: string;
  /** Right side of the title row (meta text or a quiet link). */
  aside?: Child;
  class?: string;
  /** Title size: 'section' (24px, list groups) or 'title' (17px, default). */
  size?: 'section' | 'title';
  /** Rows go edge to edge (lists): the card has no inner padding. */
  flush?: boolean;
}

/** Bordered card (1px line, radius 24): overview charts, top lists, list groups (DB01, DB11). */
export function card(opts: CardOptions, ...children: Child[]): HTMLElement {
  return h(
    'section',
    { class: `db-card${opts.flush ? ' db-card--flush' : ''}${opts.size === 'section' ? ' db-card--section' : ''}${opts.class ? ` ${opts.class}` : ''}` },
    opts.title ? h('div', { class: 'db-card__head' }, h('h2', { class: 'db-card__title', text: opts.title }), opts.aside ? h('div', { class: 'db-card__aside' }, opts.aside) : null) : null,
    ...children,
  );
}

export interface RowOptions {
  label: string;
  desc?: string;
  control: Child;
  locked?: boolean;
  /** id used to label the control (aria-labelledby). */
  labelId: string;
  descId?: string;
}

/**
 * Label (14px semibold) with its one-sentence explanation below, control on
 * the right (DB27/DB28). A locked row says why instead: lock + «Von Ihrer
 * Organisation festgelegt», and the control is dimmed.
 */
export function settingRow(o: RowOptions): HTMLElement {
  return h(
    'div',
    { class: `db-row${o.locked ? ' db-row--locked' : ''}` },
    h(
      'div',
      { class: 'db-row__text' },
      h('div', { class: 'db-row__label', text: o.label, attrs: { id: o.labelId } }),
      o.locked
        ? lockedNote(o.descId)
        : o.desc
          ? h('p', { class: 'db-row__desc', text: o.desc, attrs: { id: o.descId } })
          : null,
    ),
    h('div', { class: 'db-row__ctl' }, o.control),
  );
}

/** «🔒 Von Ihrer Organisation festgelegt»: the line a locked row shows in place of its description. */
export function lockedNote(id?: string): HTMLElement {
  return h('p', { class: 'db-locked', attrs: { id } }, icon('lock', 12), h('span', { text: t('lockedByPolicy') }));
}

export function loading(): HTMLElement {
  return h('div', { class: 'db-loading', attrs: { role: 'status' } }, h('span', { class: 'db-loading__bar' }), h('span', { class: 'sr-only', text: t('stateLoading') }));
}

/**
 * Run `work` while `btn` shows it is busy: the label stays, the spinner
 * appears after 150 ms and then stays at least 300 ms (AGENTS.md).
 */
export async function withBusy<T>(btn: HTMLElement, work: () => Promise<T>): Promise<T> {
  let shownAt = 0;
  const timer = setTimeout(() => {
    shownAt = Date.now();
    btn.setAttribute('aria-busy', 'true');
  }, 150);
  try {
    return await work();
  } finally {
    clearTimeout(timer);
    if (shownAt) {
      const left = 300 - (Date.now() - shownAt);
      if (left > 0) await new Promise((r) => setTimeout(r, left));
    }
    btn.removeAttribute('aria-busy');
  }
}

/**
 * Error banner (DB04): danger-soft card, tile, title, one sentence and
 * «Erneut versuchen», which runs `onRetry` (the view loads again; no page reload).
 */
export function errorState(onRetry?: () => void | Promise<void>, title = t('dashErrorTitle'), text = t('dashErrorText')): HTMLElement {
  const retry = onRetry
    ? h('button', { class: 'btn btn--primary db-error__retry', attrs: { type: 'button' } }, icon('reload', 15), t('actionRetry'))
    : null;
  retry?.addEventListener('click', () => void withBusy(retry, async () => onRetry?.()));
  return h(
    'div',
    { class: 'db-error', attrs: { role: 'alert' } },
    h('span', { class: 'db-error__tile', attrs: { 'aria-hidden': 'true' } }, icon('alert', 22)),
    h('div', { class: 'db-error__text' }, h('h2', { class: 'db-error__title', text: title }), h('p', { class: 'db-error__body', text })),
    retry,
  );
}

/** Render the current view again (the router listens): the retry action of a view's error banner. */
export function retryView(): void {
  document.dispatchEvent(new CustomEvent('db:retry'));
}

/** Dark banner «Schutz pausiert» while the organisation's policy switched protection off everywhere (DB04). */
export function pausedBanner(): HTMLElement {
  return h(
    'div',
    { class: 'db-paused', attrs: { role: 'status' } },
    h('span', { class: 'db-paused__tile', attrs: { 'aria-hidden': 'true' } }, icon('pause', 16)),
    h('div', null, h('p', { class: 'db-paused__title', text: t('dashPausedTitle') }), h('p', { class: 'db-paused__body', text: t('dashPausedText') })),
  );
}

/** Empty state (DB03, DB10): optional decorative picture, title, one sentence, optional action. */
export function emptyState(title: string, text?: string, action?: Child, art?: Child): HTMLElement {
  return h(
    'div',
    { class: `db-empty${art ? ' db-empty--art' : ''}` },
    art ? h('div', { class: 'db-empty__art', attrs: { 'aria-hidden': 'true' } }, art) : null,
    h('div', { class: 'db-empty__main' }, h('p', { class: 'db-empty__title', text: title }), text ? h('p', { class: 'db-empty__text', text }) : null, action ?? null),
  );
}

/** Local calendar day key, YYYY-MM-DD (matches DailyAggregate.day). */
export function dayKey(d: Date): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

/** Parse a YYYY-MM-DD key as local noon (avoids DST edge cases). */
export function dayTime(key: string): number {
  const [y, m, d] = key.split('-').map(Number);
  return new Date(y, (m || 1) - 1, d || 1, 12).getTime();
}

/** Validate and normalise a hostname typed or pasted by the user. Returns null if invalid. */
export function normaliseHost(input: string): string | null {
  let s = input.trim().toLowerCase();
  if (!s) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//.test(s)) s = `https://${s}`;
  let host: string;
  try {
    const u = new URL(s);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    host = u.hostname; // punycode, lower-case
  } catch {
    return null;
  }
  if (host.endsWith('.')) host = host.slice(0, -1);
  if (host.startsWith('www.') && host.indexOf('.', 4) !== -1) host = host.slice(4);
  if (!/^[a-z0-9.-]+$/.test(host) && !/^\[[0-9a-f:.]+\]$/.test(host)) return null;
  if (!host.includes('.') && host !== 'localhost') return null;
  if (host.length > 253) return null;
  return host;
}

/** Stable unique id for aria wiring inside dynamically built views. */
let uid = 0;
export function nextId(prefix: string): string {
  uid += 1;
  return `${prefix}-${uid}`;
}
