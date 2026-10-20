// Bastion Shield — bounce-tracking skip page (pages/bounce.html). A debounce
// rule redirects a tracking hop here with the real destination in the
// fragment; we decode and validate it, then replace this history entry with
// the destination so "Back" never lands on the tracker or on this page.
// The script runs from <head> so the redirect starts before the body parses.
// When the rule passes the tracker's host (?from=<host>) and the target is on
// the same site, this is not a cross-site bounce: we do not follow it and
// explain why instead (the user may still open the target themselves).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { decodeBounceTarget, isSameSiteBounce, parseFromHost } from './bounce-decode.ts';
import { t, translate } from '../ui/shared/i18n.ts';
import { hydrateIcons } from '../ui/shared/icons.ts';

function rawFragment(): string {
  // location.hash would do, but reading href keeps any '#' inside the target intact.
  const href = location.href;
  const i = href.indexOf('#');
  return i === -1 ? '' : href.slice(i + 1);
}

const target = decodeBounceTarget(rawFragment());
const sameSite = target !== null && isSameSiteBounce(target, parseFromHost(location.search));
if (target && !sameSite) {
  try {
    location.replace(target.href);
  } catch {
    /* the visible state below still offers a link */
  }
}

function render(): void {
  // The document may already be unloading because the redirect above started.
  if (!document.body) return;
  try {
    translate();
    hydrateIcons();
  } catch {
    /* static German fallback copy stays */
  }
  const back = (): void => {
    if (history.length > 1) history.back();
    else window.close();
  };
  if (target && sameSite) {
    document.body.dataset.state = 'samesite';
    document.title = t('bounceSameSiteTitle') || document.title;
    const host = document.getElementById('bn-same-host');
    if (host) host.textContent = target.hostname;
    const link = document.getElementById('bn-same-link') as HTMLAnchorElement | null;
    if (link) link.href = target.href;
    document.getElementById('bn-same-back')?.addEventListener('click', back);
    return;
  }
  if (target) {
    const host = document.getElementById('bn-host');
    if (host) host.textContent = target.hostname;
    const link = document.getElementById('bn-link') as HTMLAnchorElement | null;
    if (link) link.href = target.href;
    document.body.dataset.state = 'ok';
    return;
  }
  document.body.dataset.state = 'invalid';
  document.title = t('bounceInvalidTitle') || document.title;
  document.getElementById('bn-back')?.addEventListener('click', back);
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', render, { once: true });
else render();
