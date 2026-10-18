// Bastion Shield — UI localisation helpers on top of chrome.i18n. All copy
// lives in src/_locales/<lang>/messages.json; markup carries data-i18n keys and
// translate() fills them in, so no visible string is hard-coded in the UI.
//
// SPDX-License-Identifier: GPL-3.0-or-later

export type UiLang = 'de' | 'en' | 'fr' | 'it';

/** Read a message; never throws. Missing keys yield '' (the locale check script catches them). */
export function t(key: string, subs?: string | number | (string | number)[]): string {
  try {
    const list = subs === undefined ? undefined : (Array.isArray(subs) ? subs : [subs]).map(String);
    return chrome.i18n.getMessage(key, list) || '';
  } catch {
    return '';
  }
}

/**
 * The language of the message bundle Chrome actually resolved. Every bundle
 * defines `localeCode`, so this reflects the fallback to default_locale too
 * (getUILanguage() would report e.g. "es" even though English is shown).
 */
export const uiLang: UiLang = (() => {
  const code = t('localeCode');
  return code === 'de' || code === 'fr' || code === 'it' || code === 'en' ? code : 'en';
})();

/** BCP 47 tag for number/date formatting: Swiss conventions in every language (100’000). */
export const formatLocale = `${uiLang}-CH`;

const ATTRS = ['title', 'aria-label', 'placeholder', 'alt'] as const;

/**
 * Fill every element below `root` that carries data-i18n (textContent) or
 * data-i18n-<attr> (attribute value). Elements with data-i18n-sub="a|b" get
 * substitutions.
 */
export function translate(root: ParentNode = document): void {
  if (root === document) {
    document.documentElement.lang = uiLang;
    const title = document.querySelector<HTMLElement>('title[data-i18n]');
    if (title) document.title = t(title.dataset.i18n ?? '');
  }
  for (const el of Array.from(root.querySelectorAll<HTMLElement>('[data-i18n]'))) {
    const subs = el.dataset.i18nSub ? el.dataset.i18nSub.split('|') : undefined;
    const msg = t(el.dataset.i18n ?? '', subs);
    if (msg) el.textContent = msg;
  }
  for (const attr of ATTRS) {
    const dataKey = `i18n${attr.replace(/(^|-)([a-z])/g, (_m, _d: string, c: string) => c.toUpperCase())}`;
    for (const el of Array.from(root.querySelectorAll<HTMLElement>(`[data-i18n-${attr}]`))) {
      const msg = t(el.dataset[dataKey] ?? '');
      if (msg) el.setAttribute(attr, msg);
    }
  }
}

/** Pick the localized variant of a catalog name/description object. */
export function localized(obj: { en: string; de: string; fr?: string; it?: string } | undefined | null): string {
  if (!obj) return '';
  return obj[uiLang] || obj.en || obj.de || '';
}

let numberFmt: Intl.NumberFormat | null = null;
let compactFmt: Intl.NumberFormat | null = null;

/**
 * Integer with the Swiss apostrophe in every UI language (100’000, 4’321).
 * CLDR would give fr-CH a narrow space and skip grouping of 4-digit numbers in
 * it-CH; one consistent Swiss style reads better across the product.
 */
export function fmtNumber(n: number): string {
  if (!Number.isFinite(n)) return '0';
  try {
    numberFmt ??= new Intl.NumberFormat('de-CH', { maximumFractionDigits: 0, useGrouping: 'always' } as Intl.NumberFormatOptions);
    return numberFmt.format(n);
  } catch {
    return String(Math.round(n));
  }
}

/** Short form for chart axes (1’200 → 1.2k style per locale). */
export function fmtCompact(n: number): string {
  if (Math.abs(n) < 10_000) return fmtNumber(n);
  try {
    compactFmt ??= new Intl.NumberFormat(formatLocale, { notation: 'compact', maximumFractionDigits: 1 });
    return compactFmt.format(n);
  } catch {
    return fmtNumber(n);
  }
}

const dtCache = new Map<string, Intl.DateTimeFormat>();
function dtf(key: string, opts: Intl.DateTimeFormatOptions): Intl.DateTimeFormat {
  let f = dtCache.get(key);
  if (!f) {
    try {
      f = new Intl.DateTimeFormat(formatLocale, opts);
    } catch {
      f = new Intl.DateTimeFormat(undefined, opts);
    }
    dtCache.set(key, f);
  }
  return f;
}

/** 13:22:05 */
export function fmtTime(ms: number): string {
  return dtf('time', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(ms);
}

/** 18.10.2026 */
export function fmtDate(ms: number): string {
  return dtf('date', { day: '2-digit', month: '2-digit', year: 'numeric' }).format(ms);
}

/** 18. Oktober 2026 */
export function fmtDateLong(ms: number): string {
  return dtf('dateLong', { day: 'numeric', month: 'long', year: 'numeric' }).format(ms);
}

/** 18.10.2026, 13:22 */
export function fmtDateTime(ms: number): string {
  return dtf('dateTime', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }).format(ms);
}

/** Sa., 18.10. — used for chart tooltips. */
export function fmtDayShort(ms: number): string {
  return dtf('dayShort', { weekday: 'short', day: '2-digit', month: '2-digit' }).format(ms);
}

/** 18.10. — chart axis. */
export function fmtDayAxis(ms: number): string {
  return dtf('dayAxis', { day: '2-digit', month: '2-digit' }).format(ms);
}

/** Choose between a singular and plural message key. */
export function plural(n: number, oneKey: string, otherKey: string): string {
  return t(n === 1 ? oneKey : otherKey, fmtNumber(n));
}
