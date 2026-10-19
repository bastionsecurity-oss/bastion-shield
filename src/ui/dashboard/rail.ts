// Bastion Shield — collapsible navigation rail for the dashboard tab (wide
// layout, ≥ 1024px) and the expanded popup. Collapsed, the sidebar shows only
// the icon tiles and the content gets the room; labels stay in the
// accessibility tree and appear as a tooltip on hover or keyboard focus.
// Toggle: the button in the navigation header or Ctrl+. (also in the
// command palette). The choice is remembered per surface (tab / popup) in
// localStorage, a per-device convenience only.
//
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

/** The rail exists in the expanded popup and in the wide dashboard layout (below 1024px the nav is a top bar). */
export function railAvailable(): boolean {
  if (popupMode) return true;
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

/** "Ctrl+." / "⌘." for the current platform. */
export function shortcutLabel(key: string): string {
  const mac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  return mac ? `⌘${key.toUpperCase()}` : `Ctrl+${key.toUpperCase()}`;
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

const TIP_TARGETS = '.db-nav__link, .db-nav__icon-btn, .db-nav__collapse, .db-nav__cta, .db-nav__brand';

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

  const nav = document.querySelector<HTMLElement>('.db-nav');
  if (!nav) return;
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
