// Bastion Shield — logic shared by the extension pages (blocked.html,
// bounce.html): which copy a block category gets, how a message with a host
// placeholder is split around the host chip, how many characters the host
// chip may show before it is cut in the middle, and «Zurück» that also works
// in a tab without history.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

export type BlockKind = 'security' | 'tracking' | 'other';

/** Map a list category to the three variants of the strict-block page (S01, S03, other). */
export function blockKind(category: string | null | undefined): BlockKind {
  if (category === 'security') return 'security';
  if (category === 'ads' || category === 'privacy' || category === 'regional') return 'tracking';
  return 'other';
}

export interface BlockCopyKeys {
  title: string;
  /** Sentence with the host as $1. */
  text: string;
  category: string;
  confirm: string;
}

/** i18n keys for each variant. */
export function blockCopyKeys(kind: BlockKind): BlockCopyKeys {
  switch (kind) {
    case 'security':
      return { title: 'blockedTitleSecurity', text: 'blockedTextSecurity', category: 'blockedCatSecurity', confirm: 'blockedConfirmTextSecurity' };
    case 'tracking':
      return { title: 'blockedTitleTracking', text: 'blockedTextTracking', category: 'blockedCatTracking', confirm: 'blockedConfirmTextTracking' };
    default:
      return { title: 'blockedTitle', text: 'blockedTextOther', category: 'blockedCatOther', confirm: 'blockedConfirmText' };
  }
}

/** Marker passed as $1 so the translated sentence can be split around the host. */
export const SLOT = '\u0000';

/**
 * Split a message that was formatted with SLOT as its placeholder into the text
 * before and after the slot. Without a slot the whole text is `after`
 * (the host chip then comes first, which matches every locale we ship).
 */
export function splitAtSlot(text: string): { before: string; after: string; hasSlot: boolean } {
  const i = text.indexOf(SLOT);
  if (i === -1) return { before: '', after: text, hasSlot: false };
  return { before: text.slice(0, i).trimEnd(), after: text.slice(i + SLOT.length).trimStart(), hasSlot: true };
}

/**
 * How many characters a monospace host chip can show in `lines` lines of
 * `widthPx` (content box) with a glyph advance of `charPx`. Never below 12,
 * so a very narrow layout still shows a recognisable start and end.
 */
export function chipMaxChars(widthPx: number, charPx: number, lines = 2): number {
  if (!(widthPx > 0) || !(charPx > 0)) return Number.POSITIVE_INFINITY;
  const perLine = Math.floor(widthPx / charPx);
  return Math.max(12, perLine * lines);
}

export const BRAND = 'Bastion Shield';

/** Split text around every «Bastion Shield» so the brand can be marked translate="no". */
export function splitBrand(text: string): { text: string; brand: boolean }[] {
  const out: { text: string; brand: boolean }[] = [];
  let rest = text;
  for (let i = rest.indexOf(BRAND); i !== -1; i = rest.indexOf(BRAND)) {
    if (i > 0) out.push({ text: rest.slice(0, i), brand: false });
    out.push({ text: BRAND, brand: true });
    rest = rest.slice(i + BRAND.length);
  }
  if (rest) out.push({ text: rest, brand: false });
  return out;
}

/** Fill `el` with text, wrapping «Bastion Shield» in <span translate="no">. */
export function setBrandText(el: HTMLElement, text: string): void {
  el.replaceChildren(
    ...splitBrand(text).map((part) => {
      if (!part.brand) return document.createTextNode(part.text);
      const span = document.createElement('span');
      span.translate = false;
      span.textContent = part.text;
      return span;
    }),
  );
}

/**
 * «Zurück»: the previous page when there is one. A tab that started on this
 * page (link opened in a new tab, typed address) has no history, so the tab
 * goes to the new-tab page instead of doing nothing.
 */
export async function goBack(): Promise<void> {
  if (history.length > 1) {
    const before = location.href;
    history.back();
    // history.back() is a no-op when the previous entry is gone (e.g. after a
    // session restore): fall through to the new-tab page after a moment.
    await new Promise((r) => setTimeout(r, 400));
    if (location.href !== before || document.visibilityState === 'hidden') return;
  }
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
