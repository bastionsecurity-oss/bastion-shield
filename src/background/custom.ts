// Bastion Shield service worker — user and admin custom filters. The same
// compiler that builds the shipped lists compiles them at runtime: network
// filters become dynamic DNR rules, cosmetic filters are served by
// cosmetic.ts. Scriptlets cannot be added at runtime in MV3 without the
// userScripts toggle, so they are counted and ignored (ARCHITECTURE §6).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { compileCustom } from '../compiler/index.ts';
import type { CustomCompileOptions } from '../compiler/index.ts';
import type { CompiledCustom, ScriptletInfo } from '../compiler/types.ts';
import type { BuildMeta, CustomState } from '../shared/types.ts';
import type { CustomCosmetic } from './cosmetic.ts';
import * as log from './log.ts';
import { errMsg } from './util.ts';

/** One imported list ("My lists"), compiled. */
export interface MyListCompiled {
  id: string;
  /** Rule-id slot (RULE_ID.MY_LISTS_START + slot × MY_LISTS.SLOT_SIZE). */
  slot: number;
  compiled: CompiledCustom;
}

/** An imported list to compile; `key` changes whenever its text does (cache key). */
export interface MyListInput {
  id: string;
  slot: number;
  text: string;
}

export interface CustomCompiled {
  user: CompiledCustom;
  admin: CompiledCustom;
  /** Enabled imported lists, in slot order (empty when policy forbids them). */
  my: MyListCompiled[];
  /** user + admin + imported-list cosmetic filters. */
  cosmetic: CustomCosmetic;
  /** Hosts with generichide/elemhide from custom filters (excluded from generic-high CSS). */
  genericHideHosts: string[];
}

export const EMPTY_COMPILED: CompiledCustom = { rules: [], specific: [], generic: [], scriptletsIgnored: 0, errors: [] };

function redirectMap(meta: BuildMeta | null): Map<string, { path: string; requiresTrust: boolean }> {
  const m = new Map<string, { path: string; requiresTrust: boolean }>();
  // Only resources the build shipped as web-accessible can be redirect targets.
  for (const [name, path] of Object.entries(meta?.redirectResources ?? {})) {
    if (typeof path === 'string' && path !== '') m.set(name, { path, requiresTrust: false });
  }
  return m;
}

function compileOne(text: string, listId: string, meta: BuildMeta | null): CompiledCustom {
  if (text.trim() === '') return { ...EMPTY_COMPILED, errors: [] };
  // The compiler applies the custom-filter semantics itself: always-apply
  // priority band (also first-party), untrusted, no strict block.
  const options: CustomCompileOptions = {
    redirectResources: redirectMap(meta),
    scriptlets: new Map<string, ScriptletInfo>(),
  };
  try {
    const out = compileCustom(text, options);
    return {
      rules: Array.isArray(out?.rules) ? out.rules : [],
      specific: Array.isArray(out?.specific) ? out.specific : [],
      generic: Array.isArray(out?.generic) ? out.generic : [],
      scriptletsIgnored: typeof out?.scriptletsIgnored === 'number' ? out.scriptletsIgnored : 0,
      errors: Array.isArray(out?.errors) ? out.errors : [],
    };
  } catch (e) {
    log.error('custom', listId, e);
    return { ...EMPTY_COMPILED, errors: [{ line: 0, text: '', reason: `compiler error: ${errMsg(e)}` }] };
  }
}

/**
 * Imported lists can be megabytes; recompiling all of them whenever the user
 * edits one filter would stall the worker. Results are kept per list id and
 * text (the text is compared, not hashed: it is in memory anyway).
 */
const myCache = new Map<string, { text: string; meta: BuildMeta | null; compiled: CompiledCustom }>();

function compileMyList(l: MyListInput, meta: BuildMeta | null): CompiledCustom {
  const hit = myCache.get(l.id);
  if (hit && hit.text === l.text && hit.meta === meta) return hit.compiled;
  const compiled = compileOne(l.text, `my:${l.id}`, meta);
  myCache.set(l.id, { text: l.text, meta, compiled });
  return compiled;
}

export function compileAllCustom(userText: string, adminLines: readonly string[], meta: BuildMeta | null, myLists: readonly MyListInput[] = []): CustomCompiled {
  const user = compileOne(userText, 'custom', meta);
  const admin = compileOne(adminLines.join('\n'), 'admin', meta);
  const my = myLists.map((l) => ({ id: l.id, slot: l.slot, compiled: compileMyList(l, meta) }));
  for (const id of Array.from(myCache.keys())) if (!myLists.some((l) => l.id === id)) myCache.delete(id);
  const specific = [...admin.specific, ...user.specific, ...my.flatMap((m) => m.compiled.specific)];
  const generic = [...admin.generic, ...user.generic, ...my.flatMap((m) => m.compiled.generic)];
  const genericHideHosts = new Set<string>();
  for (const s of specific) {
    if (s.kind !== 4 || (s.payload !== 'generichide' && s.payload !== 'elemhide')) continue;
    for (const h of s.hosts) if (!h.endsWith('.*')) genericHideHosts.add(h);
  }
  return { user, admin, my, cosmetic: { specific, generic }, genericHideHosts: Array.from(genericHideHosts).sort() };
}

/** Report shown in the dashboard's custom-filter editor. */
export function customReport(c: CompiledCustom, extraErrors: CustomState['report']['errors'] = []): CustomState['report'] {
  return {
    network: c.rules.length,
    cosmetic: c.specific.length + c.generic.length,
    scriptletsIgnored: c.scriptletsIgnored,
    errors: [...c.errors, ...extraErrors].slice(0, 500),
  };
}
