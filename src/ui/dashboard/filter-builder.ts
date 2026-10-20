// Bastion Shield — «Eigene Filter» guided builder and file import / export.
// Pure logic (no DOM): turns a plain choice («block this domain», «hide this
// element on that site», …) into one filter line in uBO/ABP syntax, and merges
// an imported filter file into the editor text. The view wires it up.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { normaliseHost } from './common.ts';

export type BuilderAction = 'block-domain' | 'block-script' | 'hide-element' | 'allow-site';

export const BUILDER_ACTIONS: BuilderAction[] = ['block-domain', 'block-script', 'hide-element', 'allow-site'];

export interface BuilderInput {
  action: BuilderAction;
  /** Domain, script URL or CSS selector, depending on the action. */
  target: string;
  /** Optional site the filter is limited to (block-script, hide-element). */
  site?: string;
}

/** Why a builder input can't become a filter; the view maps it to a message key. */
export type BuilderError = 'domain' | 'script' | 'selector' | 'site';

export type BuilderResult = { ok: true; filter: string } | { ok: false; error: BuilderError };

/** Optional «only on this site» field: empty is fine, garbage is not. */
function optionalSite(site: string | undefined): string | null | undefined {
  const s = (site ?? '').trim();
  if (!s) return undefined;
  return normaliseHost(s);
}

/** `example.com/js/ads.js?x=1` or a full URL → `example.com/js/ads.js`; a bare domain → `example.com^`. */
function scriptPattern(input: string): string | null {
  let s = input.trim();
  if (!s || /\s/.test(s)) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `https://${s.replace(/^\/\//, '')}`;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  const host = normaliseHost(u.hostname);
  if (!host) return null;
  const path = u.pathname === '/' ? '' : u.pathname;
  return path ? `${host}${path}` : `${host}^`;
}

export function buildFilter(input: BuilderInput): BuilderResult {
  const target = input.target.trim();
  switch (input.action) {
    case 'block-domain': {
      const host = normaliseHost(target);
      return host ? { ok: true, filter: `||${host}^` } : { ok: false, error: 'domain' };
    }
    case 'allow-site': {
      const host = normaliseHost(target);
      return host ? { ok: true, filter: `@@||${host}^$document` } : { ok: false, error: 'domain' };
    }
    case 'block-script': {
      const pattern = scriptPattern(target);
      if (!pattern) return { ok: false, error: 'script' };
      const site = optionalSite(input.site);
      if (site === null) return { ok: false, error: 'site' };
      return { ok: true, filter: `||${pattern}$script${site ? `,domain=${site}` : ''}` };
    }
    case 'hide-element': {
      // One line, and not a scriptlet / exception / HTML filter in disguise.
      if (!target || /[\r\n]/.test(target) || /^(\+js|@|\^|#[#@?$%])/.test(target)) return { ok: false, error: 'selector' };
      const site = optionalSite(input.site);
      if (site === null) return { ok: false, error: 'site' };
      return { ok: true, filter: `${site ?? ''}##${target}` };
    }
  }
}

/** True when the editor already holds exactly this filter line. */
export function hasFilter(text: string, filter: string): boolean {
  return text.split(/\r?\n/).some((l) => l.trim() === filter);
}

/** Append one line, keeping a single trailing newline between old and new. */
export function appendLine(text: string, line: string): string {
  if (!text.trim()) return line;
  return `${text.replace(/\s+$/, '')}\n${line}`;
}

// ----------------------------------------------------------- file import --

const EXPORT_TITLE = '! Title: Bastion Shield – my filters';

/** The .txt written by «Export»: a plain filter list any uBO/ABP-style blocker reads. */
export function exportText(text: string, now: Date): string {
  const body = text.replace(/\r\n?/g, '\n').replace(/\s+$/, '');
  return `${EXPORT_TITLE}\n! Exported: ${now.toISOString()}\n\n${body}\n`;
}

/** Pull filter text out of an imported file: a .txt list, or a full Bastion backup (.json). */
export function importedFilters(raw: string): string | null {
  const s = raw.replace(/^﻿/, '');
  if (/^\s*\{/.test(s)) {
    try {
      const d = JSON.parse(s) as Record<string, unknown>;
      if (d && d.format === 'bastion-shield-backup' && typeof d.customFilters === 'string') return d.customFilters;
    } catch {
      /* not JSON after all: fall through and treat it as a list */
    }
    return null;
  }
  // Binary or obviously not text: refuse instead of filling the editor with junk.
  if (s.includes('\u0000')) return null;
  return s;
}

export interface MergeResult {
  text: string;
  added: number;
  skipped: number;
}

/**
 * Add the imported lines to the editor text. Filters already present are
 * skipped, as is our own export header; comments and blank lines are kept
 * only when they come with new filters.
 */
export function mergeFilters(current: string, imported: string): MergeResult {
  const have = new Set(current.split(/\r?\n/).map((l) => l.trim()).filter(Boolean));
  const out: string[] = [];
  let added = 0;
  let skipped = 0;
  for (const rawLine of imported.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === EXPORT_TITLE || line.startsWith('! Exported: ')) continue;
    const isFilter = line !== '' && !line.startsWith('!') && !(line.startsWith('#') && !line.startsWith('##') && !line.startsWith('#@#') && !line.startsWith('#?#'));
    if (!isFilter) {
      out.push(line);
      continue;
    }
    if (have.has(line)) {
      skipped += 1;
      continue;
    }
    have.add(line);
    out.push(line);
    added += 1;
  }
  if (!added) return { text: current, added, skipped };
  const block = out.join('\n').replace(/^\n+|\n+$/g, '').replace(/\n{3,}/g, '\n\n');
  const base = current.replace(/\s+$/, '');
  return { text: base ? `${base}\n\n${block}` : block, added, skipped };
}
