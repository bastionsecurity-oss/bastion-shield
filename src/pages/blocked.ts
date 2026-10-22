// Bastion Shield — strict-block interstitial (pages/blocked.html, artboards
// S01–S07). Asks the service worker which URL / list triggered the block
// (blocked:info), offers «Zurück» as the primary action and «Trotzdem
// öffnen…» behind an inline confirm bar (blocked:proceed → the SW adds a
// per-tab session allow rule and navigates the tab). A failed proceed shows an
// error row whose «Erneut versuchen» sends the same request again.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { MsgBlockedInfoResponse } from '../shared/types.ts';
import { initI18n, t, translate } from '../ui/shared/i18n.ts';
import { hydrateIcons } from '../ui/shared/icons.ts';
import { call } from '../ui/shared/messaging.ts';
import { truncateMiddle } from '../ui/shared/text.ts';
import { SLOT, blockCopyKeys, blockKind, chipMaxChars, goBack, setBrandText, splitAtSlot } from './pages-core.ts';

const $ = <T extends HTMLElement = HTMLElement>(id: string): T => document.getElementById(id) as T;

/** Spinner after ~150 ms, kept for at least ~300 ms (AGENTS.md «Loading buttons»). */
async function withBusy<T>(btn: HTMLButtonElement, work: () => Promise<T>): Promise<T> {
  btn.disabled = true;
  let shownAt = 0;
  const timer = setTimeout(() => {
    btn.setAttribute('aria-busy', 'true');
    shownAt = performance.now();
  }, 150);
  try {
    return await work();
  } finally {
    clearTimeout(timer);
    if (shownAt) {
      const left = 300 - (performance.now() - shownAt);
      if (left > 0) await new Promise((r) => setTimeout(r, left));
    }
    btn.removeAttribute('aria-busy');
    btn.disabled = false;
  }
}

/** Show the host in its chip: two lines at most, then cut in the middle (S04). */
function fitHost(chip: HTMLElement, host: string): void {
  chip.textContent = host;
  const style = getComputedStyle(chip);
  const pad = parseFloat(style.paddingLeft) + parseFloat(style.paddingRight);
  const width = (chip.parentElement?.clientWidth ?? 0) - pad;
  // Measure the glyph advance with the chip's own font (mono: every character is as wide).
  const probe = document.createElement('span');
  probe.style.cssText = 'position:absolute;visibility:hidden;white-space:pre;padding:0';
  probe.textContent = 'm'.repeat(40);
  chip.append(probe);
  const charPx = probe.getBoundingClientRect().width / 40;
  probe.remove();
  // Break after dots and hyphens (never a lone character on line 2); cut
  // further in the middle until that layout fits two lines.
  const perLine = Math.max(1, Math.floor(width / charPx));
  let max = chipMaxChars(width, charPx, 2);
  let text = truncateMiddle(host, max);
  while (max > 8 && hostLines(text, perLine) > 2) text = truncateMiddle(host, --max);
  chip.replaceChildren(...text.split(/(?<=[.\-])/).flatMap((part, i) => (i ? [document.createElement('wbr'), part] : [part])));
}

/** Lines `text` takes with `perLine` characters each when it may break only after «.» and «-» (or anywhere inside a longer part). */
function hostLines(text: string, perLine: number): number {
  let lines = 1;
  let used = 0;
  for (const part of text.split(/(?<=[.\-])/)) {
    if (used + part.length <= perLine) {
      used += part.length;
      continue;
    }
    if (used > 0) lines++;
    lines += Math.floor((part.length - 1) / perLine);
    used = part.length % perLine || perLine;
  }
  return lines;
}

async function main(): Promise<void> {
  await initI18n();
  translate();
  hydrateIcons();
  setBrandText($('bl-foot'), t('blockedFoot') || $('bl-foot').textContent || '');

  // Never offer actions inside a frame: a page could embed this one to trick a click.
  const framed = window.top !== window;
  const listParam = new URLSearchParams(location.search).get('list');

  const res = await call<MsgBlockedInfoResponse>({ type: 'blocked:info' });
  const info: MsgBlockedInfoResponse = res.ok && res.data ? res.data : { url: null, host: null, listId: listParam, listName: null, category: null };

  const kind = blockKind(info.category);
  const keys = blockCopyKeys(kind);
  document.body.dataset.kind = kind;

  const title = t(keys.title);
  if (title) $('bl-title').textContent = title;
  $('bl-category').textContent = t(keys.category) || '–';
  $('bl-list').textContent = info.listName || info.listId || listParam || '–';
  const confirmText = t(keys.confirm);
  if (confirmText) $('bl-confirm-text').textContent = confirmText;

  const chip = $('bl-host');
  if (info.host) {
    const parts = splitAtSlot(t(keys.text, SLOT));
    const before = $('bl-text-before');
    before.textContent = parts.before;
    before.hidden = !parts.before;
    $('bl-text-after').textContent = parts.after;
    chip.hidden = false;
    chip.title = info.host;
    document.title = `${title || t('blockedTitle')} - ${info.host}`;
    const host = info.host;
    fitHost(chip, host);
    let raf = 0;
    new ResizeObserver(() => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => fitHost(chip, host));
    }).observe($('bl-text'));
    void document.fonts?.ready.then(() => fitHost(chip, host));
  } else if (title) {
    document.title = title;
  }
  if (info.url) {
    $('bl-url').textContent = info.url;
    $('bl-url-row').hidden = false;
  }

  const back = $<HTMLButtonElement>('bl-back');
  const proceed = $<HTMLButtonElement>('bl-proceed');
  const confirm = $('bl-confirm');
  const cancel = $<HTMLButtonElement>('bl-confirm-cancel');
  const go = $<HTMLButtonElement>('bl-confirm-go');
  const err = $('bl-error');
  const retry = $<HTMLButtonElement>('bl-retry');
  const detailsToggle = $<HTMLButtonElement>('bl-details-toggle');
  const details = $('bl-details');

  back.addEventListener('click', () => void goBack());
  if (framed || !info.url) {
    // Without the original URL (service worker restarted, page opened directly) we cannot proceed.
    proceed.hidden = true;
    if (framed) back.hidden = true;
  }

  const openConfirm = (): void => {
    err.hidden = true;
    confirm.hidden = false;
    proceed.setAttribute('aria-expanded', 'true');
    cancel.focus();
  };
  const closeConfirm = (restoreFocus = true): void => {
    confirm.hidden = true;
    proceed.setAttribute('aria-expanded', 'false');
    if (restoreFocus) proceed.focus();
  };

  proceed.addEventListener('click', () => {
    if (confirm.hidden) openConfirm();
    else closeConfirm();
  });
  cancel.addEventListener('click', () => closeConfirm());
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape' || confirm.hidden) return;
    e.preventDefault();
    closeConfirm();
  });

  const sendProceed = async (btn: HTMLButtonElement): Promise<void> => {
    if (!info.url) return;
    const r = await withBusy(btn, () => call<unknown>({ type: 'blocked:proceed', url: info.url! }));
    if (r.ok) return; // the service worker navigates this tab
    closeConfirm(false);
    err.hidden = false;
    retry.focus();
  };
  go.addEventListener('click', () => void sendProceed(go));
  retry.addEventListener('click', () => void sendProceed(retry));

  detailsToggle.addEventListener('click', () => {
    const open = details.hidden;
    details.hidden = !open;
    detailsToggle.setAttribute('aria-expanded', String(open));
  });

  document.body.dataset.state = 'ready';
}

void main().catch((e) => {
  document.body.dataset.state = 'ready';
  console.error('[bastion] blocked page failed', e);
});
