// Bastion Shield — dashboard building blocks: page header, panels, setting
// rows, loading / error / empty states and date keys shared by all views.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { append, h, type Child } from '../shared/dom.ts';
import { t } from '../shared/i18n.ts';
import { icon } from '../shared/icons.ts';
import { eyebrow, lockIcon, notice } from '../shared/controls.ts';
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

/** Append children, skipping null/false (Element.append would render "null"). */
export function mount(root: Element, ...children: Child[]): void {
  append(root, children);
}

/** Page header. The h1 takes focus on navigation so screen readers announce the view. */
export function pageHead(title: string, lead?: Child, aside?: Child): HTMLElement {
  return h(
    'header',
    { class: 'db-head' },
    // The lead stays for screen readers only: the title already says what the page is.
    h('div', { class: 'db-head__text' }, h('h1', { class: 'db-head__title', text: title, attrs: { tabindex: -1 } }), lead ? (typeof lead === 'string' ? h('p', { class: 'db-head__lead sr-only', text: lead }) : lead) : null),
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

export function panel(opts: PanelOptions, ...children: Child[]): HTMLElement {
  return h(
    'section',
    { class: `db-panel${opts.flush ? ' db-panel--flush' : ''}${opts.class ? ` ${opts.class}` : ''}`, attrs: { id: opts.id } },
    opts.title ? h('div', { class: 'db-panel__head' }, eyebrow(opts.title, opts.aside, 'h2')) : null,
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

/** Label + one-line explanation on the left, control (and lock) on the right. */
export function settingRow(o: RowOptions): HTMLElement {
  return h(
    'div',
    { class: `db-row${o.locked ? ' db-row--locked' : ''}` },
    h(
      'div',
      { class: 'db-row__text' },
      h('div', { class: 'db-row__label', text: o.label, attrs: { id: o.labelId } }),
      // Kept as the control's accessible description, not shown: rows stay one line.
      o.desc ? h('p', { class: 'db-row__desc sr-only', text: o.desc, attrs: { id: o.descId } }) : null,
    ),
    h('div', { class: 'db-row__ctl' }, o.locked ? lockIcon() : null, o.control),
  );
}

export function loading(): HTMLElement {
  return h('div', { class: 'db-loading', attrs: { role: 'status' } }, h('span', { class: 'db-loading__bar' }), h('span', { class: 'sr-only', text: t('stateLoading') }));
}

export function errorState(onRetry?: () => void): HTMLElement {
  return h(
    'div',
    { class: 'db-error' },
    notice(t('dashErrorTitle'), t('dashErrorText'), 'alert'),
    onRetry ? h('button', { class: 'btn btn--secondary', attrs: { type: 'button' }, on: { click: onRetry } }, icon('reload', 15), t('actionRefresh')) : null,
  );
}

export function emptyState(title: string, text?: string, action?: Child): HTMLElement {
  return h('div', { class: 'db-empty' }, h('p', { class: 'db-empty__title', text: title }), text ? h('p', { class: 'db-empty__text', text }) : null, action ?? null);
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
