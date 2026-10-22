// Bastion Shield — the logic behind «Eigene Filter» (views/filters.ts), free
// of DOM so node:test can cover it: the 1 MB limit (the same number the
// service worker enforces in background/store.ts), the editor counter, the
// number of unapplied changes, a live check of every line with the same
// compiler the service worker uses, and a plain-language reason for each
// compiler rejection code (with «Meinten Sie …?» for misspelt options).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BuildMeta, CustomState } from '../../shared/types.ts';
import type { ScriptletInfo } from '../../compiler/types.ts';
import { compileCustom } from '../../compiler/index.ts';
import { OPTION_ALIASES } from '../../compiler/parser.ts';
import { redirectMap } from './lab-core.ts';

/** Most characters the editor may apply: 1 MB, as MAX_CUSTOM_FILTERS_BYTES in background/store.ts. */
export const MAX_CUSTOM_CHARS = 1_000_000;

/** Above this size the editor checks lines on «Filter anwenden» only, not while typing. */
export const LIVE_CHECK_MAX = 300_000;

/** Errors listed in the result panel (the service worker keeps 500). */
export const ERRORS_LISTED = 200;

const NBSP = '\u00a0';

/** Lines in the editor; an empty editor has none. */
export function lineCount(text: string): number {
  if (text === '') return 0;
  let n = 1;
  for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) n += 1;
  return n;
}

/** «38 KB», «1.3 MB» (decimal units: 1 MB = 1'000'000 characters), in the UI language's Swiss format. */
export function fmtSize(chars: number, locale = 'de-CH', units: { kb: string; mb: string } = { kb: 'KB', mb: 'MB' }): string {
  const fmt = (v: number, digits: number): string => {
    try {
      return new Intl.NumberFormat(locale, { maximumFractionDigits: digits, minimumFractionDigits: 0 }).format(v);
    } catch {
      return String(Math.round(v * 10 ** digits) / 10 ** digits);
    }
  };
  if (chars >= 1_000_000) return `${fmt(Math.floor(chars / 100_000) / 10, 1)}${NBSP}${units.mb}`;
  return `${fmt(Math.ceil(chars / 1000), 0)}${NBSP}${units.kb}`;
}

/** The limit as the editor shows it («1 MB»). */
export function fmtLimit(locale = 'de-CH', units?: { kb: string; mb: string }): string {
  return fmtSize(MAX_CUSTOM_CHARS, locale, units);
}

/** A file that is not text (a spreadsheet, a zip): control characters near its start. */
export function looksBinary(text: string): boolean {
  return /[\u0000-\u0008\u000E-\u001A]/.test(text.slice(0, 4096));
}

export function tooBig(text: string): boolean {
  return text.length > MAX_CUSTOM_CHARS;
}

/**
 * Unapplied changes as a person counts them: a changed line is one change,
 * an added or removed line one each (lines compared as a multiset, so moving
 * a line is no change).
 */
export function changeCount(saved: string, current: string): number {
  if (saved === current) return 0;
  const counts = new Map<string, number>();
  for (const l of saved.split('\n')) counts.set(l, (counts.get(l) ?? 0) + 1);
  let added = 0;
  for (const l of current.split('\n')) {
    const c = counts.get(l) ?? 0;
    if (c > 0) counts.set(l, c - 1);
    else added += 1;
  }
  let removed = 0;
  for (const c of counts.values()) removed += c;
  return Math.max(added, removed, 1);
}

// ---------------------------------------------------------------------------
// Reasons
// ---------------------------------------------------------------------------

/** Every option spelling the compiler knows. */
const OPTION_NAMES: readonly string[] = Array.from(OPTION_ALIASES.keys()).filter((k) => k !== '_');

function distance(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 2) return 3;
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array<number>(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      // Swapped neighbours («documnet») count as one edit.
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

/** The known option closest to a misspelt one (at most two edits), or null. */
export function suggestOption(name: string): string | null {
  const n = name.toLowerCase();
  if (n.length < 3) return null;
  let best: string | null = null;
  let bestD = 3;
  for (const o of OPTION_NAMES) {
    const d = distance(n, o);
    if (d < bestD || (d === bestD && best !== null && o.length > best.length)) {
      best = o;
      bestD = d;
    }
  }
  return bestD <= 2 ? best : null;
}

/** A message key and its substitutions (views/filters.ts translates it). */
export interface Reason {
  key: string;
  subs: string[];
}

/** Plain-language reason for a compiler rejection code (CustomState.report.errors[].reason). */
export function reasonFor(code: string): Reason {
  const c = code.toLowerCase();
  const tail = (p: string): string => code.slice(p.length);
  if (c.startsWith('unknown-option:')) {
    const name = tail('unknown-option:');
    const s = suggestOption(name);
    return s ? { key: 'cfErrOptionSuggest', subs: [name, s] } : { key: 'cfErrOption', subs: [name] };
  }
  if (c.startsWith('unsupported-option:') || c === 'unsupported-pseudo' || c.startsWith('unsupported-type:')) return { key: 'cfErrUnsupportedOption', subs: [] };
  if (c.startsWith('invalid-selector') || c === 'empty-selector' || c === 'invalid-procedural' || c === 'procedural') return { key: 'cfErrSelector', subs: [] };
  if (c.startsWith('unsupported:generic-') || c === 'generichide-without-host' || c === 'unsupported-in-custom:generic-exception') return { key: 'cfErrNeedsSite', subs: [] };
  if (c === 'invalid-domain' || c.startsWith('unsupported-domain') || c === 'denyallow-without-domain' || c === 'invalid-hosts-entry') return { key: 'cfErrDomain', subs: [] };
  if (c === 'invalid-regex' || c === 'regex-not-re2' || c === 'regex') return { key: 'cfErrRegex', subs: [] };
  if (c === 'pattern-too-short') return { key: 'cfErrTooShort', subs: [] };
  if (c === 'pattern-too-long') return { key: 'cfErrTooLong', subs: [] };
  if (c.startsWith('unknown-redirect-resource') || c === 'untrusted-redirect-resource' || c === 'unsupported:redirect-exception') return { key: 'cfErrRedirect', subs: [] };
  if (c.includes('scriptlet') || c.includes('snippet')) return { key: 'cfErrScriptlet', subs: [] };
  if (c === 'duplicate-option') return { key: 'cfErrDuplicateOption', subs: [] };
  if (c.startsWith('unsupported') || c.includes('html')) return { key: 'cfErrUnsupported', subs: [] };
  if (c === 'never-matches') return { key: 'cfErrNeverMatches', subs: [] };
  return { key: 'cfErrSyntax', subs: [] };
}

// ---------------------------------------------------------------------------
// Live check
// ---------------------------------------------------------------------------

const NO_SCRIPTLETS: ReadonlyMap<string, ScriptletInfo> = new Map();
const OPTION_TAIL = /\$(~?[a-z0-9_-]+(?:=[^,]*)?(?:,~?[a-z0-9_-]+(?:=[^,]*)?)*)$/i;

/**
 * A network filter whose option list holds no known option at all is taken
 * by uBO (and the compiler) as part of the address, so it never matches
 * («@@||bank.ch^$documnet»). Flag the first misspelt option instead.
 */
export function misspeltOption(line: string): string | null {
  const s = line.trim();
  if (s === '' || s.startsWith('!') || s.startsWith('#') || s.startsWith('[') || /#[@?$%]?#|#\+js/.test(s)) return null;
  const m = OPTION_TAIL.exec(s);
  if (!m) return null;
  const names = m[1].split(',').map((o) => o.replace(/^~/, '').replace(/=.*$/, '').toLowerCase());
  if (names.some((n) => OPTION_ALIASES.has(n))) return null;
  return names.find((n) => suggestOption(n) !== null) ?? null;
}

/** Compiles the editor text like the service worker does (compileCustom), for the live result panel. */
export function checkFilters(text: string, meta: BuildMeta | null): CustomState['report'] {
  const out = compileCustom(text, { redirectResources: redirectMap(meta), scriptlets: NO_SCRIPTLETS });
  const errors = [...out.errors];
  const flagged = new Set(errors.map((e) => e.line));
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (flagged.has(i + 1)) continue;
    const bad = misspeltOption(lines[i]);
    if (bad) errors.push({ line: i + 1, text: lines[i].trim(), reason: `unknown-option:${bad}` });
  }
  errors.sort((a, b) => a.line - b.line);
  return { network: out.rules.length, cosmetic: out.specific.length + out.generic.length, scriptletsIgnored: out.scriptletsIgnored, errors };
}
