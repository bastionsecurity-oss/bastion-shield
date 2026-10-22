// Bastion Shield — navigation rail (Paper DB01 / DB15): brand, search
// (opens the command palette, [data-cmdk]), groups Überblick / Regeln /
// System and the CTA at the bottom; 240px in the tab, 200px in the expanded
// popup. In the wide tab layout (≥ 1024px) it can collapse: the sidebar shows only
// the icon tiles and the content gets the room; labels stay in the
// accessibility tree and appear as a tooltip on hover or keyboard focus.
// Toggle: the button in the navigation header or Ctrl+. (also in the
// command palette). The choice is remembered per surface (tab / popup) in
// localStorage, a per-device convenience only.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { h } from '../shared/dom.ts';
import { t } from '../shared/i18n.ts';
import { popupMode } from './common.ts';

const STORE_KEY = popupMode ? 'bs.rail.popup' : 'bs.rail.tab';
const WIDE = '(min-width: 1024px)';

let tip: HTMLElement | null = null;
let tipFor: Element | null = null;

function readStored(): boolean {
  try {
    return localStorage.getItem(STORE_KEY) === 'collapsed';
  } catch {
    return false;
  }
}

function writeStored(collapsed: boolean): void {
  try {
    localStorage.setItem(STORE_KEY, collapsed ? 'collapsed' : 'open');
  } catch {
    /* private window or blocked storage: the rail still works for this page */
  }
}

/** The collapsible rail exists in the wide dashboard tab (below 1024px the nav is a top bar; the 200px popup rail stays open). */
export function railAvailable(): boolean {
  if (popupMode) return false;
  try {
    return window.matchMedia(WIDE).matches;
  } catch {
    return true;
  }
}

export function railCollapsed(): boolean {
  return document.documentElement.dataset.rail === 'collapsed';
}

function syncButton(): void {
  const btn = document.getElementById('db-rail-toggle');
  if (!btn) return;
  const collapsed = railCollapsed();
  const label = t(collapsed ? 'railExpand' : 'railCollapse');
  btn.setAttribute('aria-label', label);
  btn.setAttribute('aria-expanded', String(!collapsed));
  btn.title = `${label} (${shortcutLabel('.')})`;
}

/** "Ctrl K" / "⌘ K" for the current platform, with a non-breaking space inside the combo. */
export function shortcutLabel(key: string): string {
  const mac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  return `${mac ? '⌘' : 'Ctrl'} ${key.toUpperCase()}`;
}

/** What the user chose; shown only where a rail exists (a narrow tab has a top bar instead). */
let wanted = false;

function apply(): void {
  document.documentElement.dataset.rail = wanted && railAvailable() ? 'collapsed' : 'open';
  hideTip();
  syncButton();
}

/** Collapse or expand the rail (toggle without an argument). */
export function setRail(collapsed = !railCollapsed()): void {
  wanted = collapsed;
  writeStored(collapsed);
  apply();
}

// ------------------------------------------------------------- Tooltips --

function tipText(el: Element): string {
  const label = el.querySelector('.db-nav__label');
  return (label?.textContent ?? el.getAttribute('aria-label') ?? '').trim();
}

function showTip(el: Element): void {
  if (!railCollapsed() || !railAvailable()) return;
  const text = tipText(el);
  if (!text) return;
  if (!tip) {
    tip = h('div', { class: 'db-tip', attrs: { 'aria-hidden': 'true' } });
    document.body.appendChild(tip);
  }
  tip.textContent = text;
  const r = el.getBoundingClientRect();
  tip.style.top = `${Math.round(r.top + r.height / 2)}px`;
  tip.style.left = `${Math.round(r.right + 10)}px`;
  tip.classList.add('db-tip--show');
  tipFor = el;
}

function hideTip(): void {
  tip?.classList.remove('db-tip--show');
  tipFor = null;
}

const TIP_TARGETS = '.db-nav__link, .db-nav__icon-btn, .db-nav__search, .db-nav__cta, .db-nav__brand';

/**
 * Arrow keys move between the navigation links (Home / End jump to the
 * first / last); Tab still walks every control in order.
 */
function bindArrowKeys(nav: HTMLElement): void {
  nav.addEventListener('keydown', (ev: KeyboardEvent) => {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(ev.key) || ev.altKey || ev.ctrlKey || ev.metaKey) return;
    const links = Array.from(nav.querySelectorAll<HTMLElement>('.db-nav__link')).filter((a) => a.offsetParent !== null);
    const i = links.indexOf(document.activeElement as HTMLElement);
    if (i < 0) return;
    ev.preventDefault();
    const next = ev.key === 'Home' ? 0 : ev.key === 'End' ? links.length - 1 : (i + (ev.key === 'ArrowDown' ? 1 : -1) + links.length) % links.length;
    links[next].focus();
  });
}

function bindTips(nav: HTMLElement): void {
  nav.addEventListener('pointerover', (ev) => {
    const el = (ev.target as Element).closest(TIP_TARGETS);
    if (el && el !== tipFor) showTip(el);
  });
  nav.addEventListener('pointerleave', hideTip);
  nav.addEventListener('focusin', (ev) => {
    const el = (ev.target as Element).closest(TIP_TARGETS);
    if (el && (el as HTMLElement).matches(':focus-visible')) showTip(el);
  });
  nav.addEventListener('focusout', hideTip);
  nav.addEventListener('click', hideTip);
  nav.addEventListener('scroll', hideTip, { passive: true });
}

/**
 * Apply the remembered state before the first frame (no transition), wire
 * the toggle button, the shortcut and the tooltips.
 */
export function initRail(): void {
  const root = document.documentElement;
  root.dataset.railInstant = '';
  wanted = readStored();
  apply();
  // Two frames: the first paints the restored width, transitions start after that.
  requestAnimationFrame(() => requestAnimationFrame(() => delete root.dataset.railInstant));
  if (!popupMode) {
    try {
      window.matchMedia(WIDE).addEventListener('change', apply);
    } catch {
      /* old engines: the state applies on the next load */
    }
  }

  const kbd = document.getElementById('db-search-kbd');
  if (kbd) kbd.textContent = shortcutLabel('K');
  const nav = document.querySelector<HTMLElement>('.db-nav');
  if (!nav) return;
  bindArrowKeys(nav);
  // Stagger index for the label fade (CSS --i).
  nav.querySelectorAll<HTMLElement>('.db-nav__link').forEach((a, i) => a.style.setProperty('--i', String(i)));
  document.getElementById('db-rail-toggle')?.addEventListener('click', () => setRail());
  bindTips(nav);

  window.addEventListener('keydown', (ev: KeyboardEvent) => {
    if ((ev.ctrlKey || ev.metaKey) && !ev.altKey && !ev.shiftKey && ev.key === '.') {
      if (!railAvailable()) return;
      ev.preventDefault();
      setRail();
    }
  });
}
