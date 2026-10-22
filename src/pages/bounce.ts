// Bastion Shield — bounce-tracking skip page (pages/bounce.html, artboards
// S08–S10). A debounce rule redirects a tracking hop here with the real
// destination in the fragment; we decode and validate it, then replace this
// history entry with the destination so "Back" never lands on the tracker or
// on this page. The redirect starts as soon as the short S08 state is painted
// (DOMContentLoaded), so a slow destination never shows a blank tab. When the rule passes the tracker's host (?from=<host>) and the
// target is on the same site, this is not a cross-site bounce: we do not
// follow it and explain why instead (the user may still open the target).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { decodeBounceTarget, isSameSiteBounce, parseFromHost } from './bounce-decode.ts';
import { initI18n, initI18nSync, t, translate } from '../ui/shared/i18n.ts';
import { hydrateIcons } from '../ui/shared/icons.ts';
import { truncateMiddle } from '../ui/shared/text.ts';
import { SLOT, goBack, setBrandText, splitAtSlot } from './pages-core.ts';

/** Longest host shown in full; longer ones are cut in the middle (full host in title). */
const HOST_MAX = 48;

function rawFragment(): string {
  // location.hash would do, but reading href keeps any '#' inside the target intact.
  const href = location.href;
  const i = href.indexOf('#');
  return i === -1 ? '' : href.slice(i + 1);
}

const target = decodeBounceTarget(rawFragment());
const sameSite = target !== null && isSameSiteBounce(target, parseFromHost(location.search));

/** Replace this history entry with the destination (Back never returns to the tracker or here). */
function follow(href: string): void {
  try {
    location.replace(href);
  } catch {
    /* the visible state still offers the link */
  }
}

/** Fill «before $1 after» around the host element; keeps the static copy when the key is missing. */
function fillAround(key: string, beforeId: string, afterId: string): void {
  const msg = t(key, SLOT);
  if (!msg) return;
  const parts = splitAtSlot(msg);
  const before = document.getElementById(beforeId);
  const after = document.getElementById(afterId);
  if (before) before.textContent = parts.before;
  if (after) after.textContent = parts.after ? ` ${parts.after}` : '';
}

function showHost(el: HTMLElement | null, host: string): void {
  if (!el) return;
  el.textContent = truncateMiddle(host, HOST_MAX);
  el.title = host;
}

/** Fill the visible copy for the current state (runs again once the UI language bundle is loaded). */
function paint(): void {
  try {
    translate();
  } catch {
    /* static German fallback copy stays */
  }
  if (target && sameSite) {
    document.title = t('bounceSameSiteTitle') || document.title;
    fillAround('bounceSameSiteText', 'bn-same-before', 'bn-same-after');
    showHost(document.getElementById('bn-same-host'), target.hostname);
  } else if (target) {
    fillAround('bounceOpening', 'bn-ok-before', 'bn-ok-after');
    showHost(document.getElementById('bn-link'), target.hostname);
  } else {
    document.title = t('bounceInvalidTitle') || document.title;
    const text = document.getElementById('bn-invalid-text');
    if (text) setBrandText(text, text.textContent ?? '');
  }
}

function render(): void {
  // The document may already be unloading because the redirect above started.
  if (!document.body) return;
  // Hide the copy until it is in the chosen language (no flash of the browser language).
  if (!initI18nSync() && !(target && !sameSite)) document.body.dataset.lang = 'pending';
  try {
    hydrateIcons();
  } catch {
    /* icons are decorative */
  }
  paint();
  const back = (): void => void goBack();
  if (target && sameSite) {
    document.body.dataset.state = 'samesite';
    const link = document.getElementById('bn-same-link') as HTMLAnchorElement | null;
    if (link) link.href = target.href;
    document.getElementById('bn-same-back')?.addEventListener('click', back);
  } else if (target) {
    const link = document.getElementById('bn-link') as HTMLAnchorElement | null;
    if (link) link.href = target.href;
    document.body.dataset.state = 'ok';
    // Paint S08 first: a script-initiated navigation from <head> would stop the
    // parser, leaving a blank tab while a slow destination loads.
    follow(target.href);
  } else {
    document.body.dataset.state = 'invalid';
    document.getElementById('bn-back')?.addEventListener('click', back);
  }
  // The language setting lives in storage: repaint in the chosen UI language.
  const done = (): void => {
    delete document.body.dataset.lang;
  };
  void initI18n().then(paint).then(done, done);
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', render, { once: true });
else render();
