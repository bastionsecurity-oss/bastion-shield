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

export interface CustomCompiled {
  user: CompiledCustom;
  admin: CompiledCustom;
  /** user + admin cosmetic filters. */
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

export function compileAllCustom(userText: string, adminLines: readonly string[], meta: BuildMeta | null): CustomCompiled {
  const user = compileOne(userText, 'custom', meta);
  const admin = compileOne(adminLines.join('\n'), 'admin', meta);
  const specific = [...admin.specific, ...user.specific];
  const generic = [...admin.generic, ...user.generic];
  const genericHideHosts = new Set<string>();
  for (const s of specific) {
    if (s.kind !== 4 || (s.payload !== 'generichide' && s.payload !== 'elemhide')) continue;
    for (const h of s.hosts) if (!h.endsWith('.*')) genericHideHosts.add(h);
  }
  return { user, admin, cosmetic: { specific, generic }, genericHideHosts: Array.from(genericHideHosts).sort() };
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
