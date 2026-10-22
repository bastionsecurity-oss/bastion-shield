// Bastion Shield — UI localisation. All copy lives in
// src/_locales/<lang>/messages.json; markup carries data-i18n keys and
// translate() fills them in, so no visible string is hard-coded in the UI.
// The UI language is the user's choice (Einstellungen › Sprache, default
// the browser's); initI18n() loads that bundle, chrome.i18n is the fallback.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

export type UiLang = 'de' | 'en' | 'fr' | 'it';
/** User choice in Einstellungen (settings ui.language): a language or the browser's. */
export type UiLanguagePref = UiLang | 'auto';
export const UI_LANGS: readonly UiLang[] = ['de', 'en', 'fr', 'it'];

interface MessageEntry {
  message: string;
  placeholders?: Record<string, { content: string }>;
}
type Bundle = Record<string, MessageEntry>;

/**
 * Bundle loaded by initI18n() from _locales/<lang>/messages.json. We read the
 * packaged file ourselves instead of relying on chrome.i18n alone: it lets the
 * user pick a language other than the browser's, and it is never stale (some
 * browsers keep an old message cache after an unpacked extension is reloaded).
 */
let bundle: Bundle | null = null;

/** chrome.i18n message format: $NAME$ placeholders -> content with $1..$9, "$$" -> "$". */
export function formatMessage(entry: MessageEntry, subs: readonly string[] = []): string {
  const ph = entry.placeholders ?? {};
  const sub = (content: string): string => content.replace(/\$(\d)/g, (_m, d: string) => subs[Number(d) - 1] ?? '');
  return entry.message
    .replace(/\$([A-Za-z0-9_@]+)\$/g, (m, name: string) => {
      const p = ph[name.toLowerCase()] ?? ph[name];
      return p ? sub(p.content) : m;
    })
    .replace(/\$\$/g, '$');
}

/** Read a message; never throws. Missing keys yield '' (the locale check script catches them). */
export function t(key: string, subs?: string | number | (string | number)[]): string {
  const list = subs === undefined ? undefined : (Array.isArray(subs) ? subs : [subs]).map(String);
  const entry = bundle?.[key];
  if (entry && typeof entry.message === 'string') return formatMessage(entry, list);
  try {
    return chrome.i18n.getMessage(key, list) || '';
  } catch {
    return '';
  }
}

function browserLang(): UiLang {
  try {
    const code = chrome.i18n.getUILanguage().toLowerCase().slice(0, 2);
    return (UI_LANGS as readonly string[]).includes(code) ? (code as UiLang) : 'en';
  } catch {
    return 'en';
  }
}

/**
 * The UI language in use. Until initI18n() resolves it is the language of the
 * bundle Chrome resolved (every bundle defines `localeCode`).
 */
export let uiLang: UiLang = (() => {
  const code = t('localeCode');
  return code === 'de' || code === 'fr' || code === 'it' || code === 'en' ? code : 'en';
})();

/** BCP 47 tag for number/date formatting: Swiss conventions in every language (100’000). */
export let formatLocale = `${uiLang}-CH`;

/** Default when the user never chose: the browser's language (English when it is not de/fr/it). */
export const DEFAULT_UI_LANGUAGE: UiLanguagePref = 'auto';

/** Resolve a stored preference to a concrete language. */
export function resolveLanguage(pref: unknown, browser: UiLang = browserLang()): UiLang {
  if (pref === 'auto') return browser;
  if (typeof pref === 'string' && (UI_LANGS as readonly string[]).includes(pref)) return pref as UiLang;
  return DEFAULT_UI_LANGUAGE === 'auto' ? browser : DEFAULT_UI_LANGUAGE;
}

/**
 * Load the message bundle for the user's language (settings ui.language,
 * read straight from storage so the first paint is already translated).
 * Call once before translate(); never throws.
 */
export async function initI18n(): Promise<void> {
  let pref: unknown;
  try {
    const stored = await chrome.storage.local.get('settings');
    pref = (stored?.settings as { ui?: { language?: unknown } } | undefined)?.ui?.language;
  } catch {
    pref = undefined;
  }
  const lang = resolveLanguage(pref);
  try {
    const res = await fetch(chrome.runtime.getURL(`_locales/${lang}/messages.json`));
    if (res.ok) useBundle(lang, (await res.json()) as Bundle);
  } catch {
    /* chrome.i18n stays the fallback */
  }
  if (bundle) {
    try {
      sessionStorage.setItem(CACHE_KEY, JSON.stringify({ lang, bundle }));
    } catch {
      /* no cache: the next page loads the bundle itself */
    }
  }
}

const CACHE_KEY = 'bastion.i18n';

function useBundle(lang: UiLang, b: Bundle): void {
  bundle = b;
  uiLang = lang;
  formatLocale = `${lang}-CH`;
  dtCache.clear();
  compactFmt = null;
}

/**
 * Synchronous start: re-use the bundle a previous page of the same popup
 * window loaded (compact <-> expanded popup), so the first frame is already
 * translated. Returns false when there is none; then await initI18n().
 */
export function initI18nSync(): boolean {
  try {
    const raw = sessionStorage.getItem(CACHE_KEY);
    if (!raw) return false;
    const c = JSON.parse(raw) as { lang?: unknown; bundle?: unknown };
    if (!(UI_LANGS as readonly unknown[]).includes(c.lang) || !c.bundle || typeof c.bundle !== 'object') return false;
    useBundle(c.lang as UiLang, c.bundle as Bundle);
    return true;
  } catch {
    return false;
  }
}

/** Forget the cached bundle (the user picked another language). */
export function clearI18nCache(): void {
  try {
    sessionStorage.removeItem(CACHE_KEY);
  } catch {
    /* nothing cached */
  }
}

const ATTRS = ['title', 'aria-label', 'placeholder', 'alt'] as const;
const BRAND = 'Bastion Shield';

/**
 * Set `text` as the content of `el`, with «Bastion Shield» inside a
 * translate="no" span so page translators leave the brand alone (AGENTS.md).
 */
export function setBrandedText(el: HTMLElement, text: string): void {
  if (!text.includes(BRAND) || el.closest('[translate="no"]') || el.tagName === 'TITLE' || el.tagName === 'OPTION') {
    el.textContent = text;
    return;
  }
  el.replaceChildren(
    ...text
      .split(BRAND)
      .flatMap((part, i) => {
        const brand = document.createElement('span');
        brand.setAttribute('translate', 'no');
        brand.textContent = BRAND;
        return i ? [brand, part] : [part];
      })
      .filter((n) => n !== ''),
  );
}

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
    if (msg) setBrandedText(el, msg);
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
