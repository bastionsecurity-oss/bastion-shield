// Bastion Shield — strict-block interstitial (pages/blocked.html). Asks the
// service worker which URL / list triggered the block (blocked:info), offers
// «Zurück» as the primary action and «Trotzdem fortfahren» behind an explicit
// confirmation (blocked:proceed → the SW adds a per-tab session allow rule).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { MsgBlockedInfoResponse } from '../shared/types.ts';
import { initI18n, t, translate } from '../ui/shared/i18n.ts';
import { hydrateIcons, icon } from '../ui/shared/icons.ts';
import { call } from '../ui/shared/messaging.ts';

const $ = <T extends HTMLElement = HTMLElement>(id: string): T | null => document.getElementById(id) as T | null;

function setText(id: string, text: string): void {
  const el = $(id);
  if (el) el.textContent = text;
}

function categoryCopy(cat: string | null): { eyebrow: string; reason: string; category: string; confirm: string } {
  if (cat === 'security') {
    return { eyebrow: t('blockedEyebrowSecurity'), reason: t('blockedReasonSecurity'), category: t('blockedCatSecurity'), confirm: t('blockedConfirmTextSecurity') };
  }
  if (cat === 'ads' || cat === 'privacy' || cat === 'regional') {
    return { eyebrow: t('blockedEyebrow'), reason: t('blockedReasonTracking'), category: t('blockedCatTracking'), confirm: t('blockedConfirmText') };
  }
  return { eyebrow: t('blockedEyebrow'), reason: t('blockedReasonGeneric'), category: t('blockedCatOther'), confirm: t('blockedConfirmText') };
}

async function goBack(): Promise<void> {
  if (history.length > 1) {
    history.back();
    return;
  }
  // Opened in a fresh tab: there is nothing to go back to, so open a new-tab page instead.
  try {
    const tab = await chrome.tabs.getCurrent();
    if (tab?.id !== undefined) {
      await chrome.tabs.update(tab.id, { url: 'chrome://newtab/' });
      return;
    }
  } catch {
    /* fall through */
  }
  location.replace('about:blank');
}

async function main(): Promise<void> {
  await initI18n();
  translate();
  hydrateIcons();

  // Never offer actions inside a frame: a page could embed this one to trick a click.
  const framed = window.top !== window;
  const params = new URLSearchParams(location.search);
  const listParam = params.get('list');

  const res = await call<MsgBlockedInfoResponse>({ type: 'blocked:info' });
  const info: MsgBlockedInfoResponse = res.ok && res.data ? res.data : { url: null, host: null, listId: listParam, listName: null, category: null };

  const copy = categoryCopy(info.category);
  document.body.dataset.category = info.category ?? 'unknown';
  document.body.dataset.state = 'ready';
  setText('bl-eyebrow-text', copy.eyebrow);
  setText('bl-reason', copy.reason);
  setText('bl-category', copy.category);
  setText('bl-confirm-text', copy.confirm);
  setText('bl-list', info.listName || info.listId || listParam || '–');

  const host = $('bl-host');
  if (host && info.host) {
    host.textContent = info.host;
    host.hidden = false;
    document.title = `${t('blockedTitle')} – ${info.host}`;
  }

  const back = $<HTMLButtonElement>('bl-back');
  const proceed = $<HTMLButtonElement>('bl-proceed');
  const confirm = $('bl-confirm');
  const cancel = $<HTMLButtonElement>('bl-confirm-cancel');
  const go = $<HTMLButtonElement>('bl-confirm-go');
  const err = $('bl-error');

  back?.addEventListener('click', () => void goBack());
  if (framed || !info.url) {
    // Without the original URL (service worker restarted, page opened directly) we cannot proceed.
    if (proceed) proceed.hidden = true;
    if (framed && back) back.hidden = true;
  }

  proceed?.addEventListener('click', () => {
    if (!confirm) return;
    confirm.hidden = false;
    proceed.setAttribute('aria-expanded', 'true');
    proceed.hidden = true;
    cancel?.focus();
  });
  cancel?.addEventListener('click', () => {
    if (!confirm || !proceed) return;
    confirm.hidden = true;
    proceed.hidden = false;
    proceed.setAttribute('aria-expanded', 'false');
    proceed.focus();
  });
  go?.addEventListener('click', async () => {
    if (!info.url || !go) return;
    go.disabled = true;
    if (err) err.hidden = true;
    const r = await call<unknown>({ type: 'blocked:proceed', url: info.url });
    if (r.ok) return; // the service worker navigates this tab
    go.disabled = false;
    if (err) {
      err.replaceChildren(icon('alert', 16), document.createTextNode(t('blockedProceedFailed')));
      err.hidden = false;
    }
  });

  back?.focus();
}

void main().catch((e) => console.error('[bastion] blocked page failed', e));
