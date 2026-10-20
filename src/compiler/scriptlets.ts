// Bastion filter compiler — scriptlet filters (`host##+js(name, args…)` and
// `host#@#+js(…)` exceptions). Argument splitting follows uBO's
// ArglistParser: commas separate arguments, an argument may be wrapped in
// "…", '…' or `…` (so it can contain commas), "\," escapes a comma in an
// unquoted argument, and surrounding whitespace is trimmed.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ScriptletInfo } from './types.ts';

const isWs = (c: string | undefined): boolean => c === ' ' || c === '\t';
const isQuote = (c: string | undefined): boolean => c === '"' || c === "'" || c === '`';

/** Remove the backslash of "\<sep>" (an escaped backslash stays as written). */
function unescapeChar(s: string, sep: string): string {
  if (s.indexOf('\\' + sep) === -1) return s;
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '\\' && i + 1 < s.length) {
      if (s[i + 1] === sep) {
        out += sep;
      } else {
        out += c + s[i + 1];
      }
      i += 1;
      continue;
    }
    out += c;
  }
  return out;
}

/**
 * Split the inside of `+js( … )` into arguments. The first argument is the
 * scriptlet token. An empty string yields [] (the broad `#@#+js()`
 * exception). A trailing comma does not add an empty argument (uBO).
 */
export function parseScriptletArgs(inner: string): string[] {
  const s = inner;
  const n = s.length;
  if (s.trim() === '') return [];
  const args: string[] = [];
  let i = 0;
  for (;;) {
    let qb = i;
    while (qb < n && isWs(s[qb])) qb += 1;
    let arg = '';
    let next = n;
    let done = false;
    const q = s[qb];
    if (isQuote(q)) {
      let j = qb + 1;
      while (j < n) {
        if (s[j] === '\\' && j + 1 < n) {
          j += 2;
          continue;
        }
        if (s[j] === q) break;
        j += 1;
      }
      if (j < n) {
        let k = j + 1;
        while (k < n && isWs(s[k])) k += 1;
        if (k >= n || s[k] === ',') {
          arg = unescapeChar(s.slice(qb + 1, j), q as string);
          next = k >= n ? n : k + 1;
          done = true;
        }
      }
    }
    if (!done) {
      let j = qb;
      while (j < n) {
        if (s[j] === '\\' && j + 1 < n) {
          j += 2;
          continue;
        }
        if (s[j] === ',') break;
        j += 1;
      }
      arg = unescapeChar(s.slice(qb, j).replace(/[ \t]+$/, ''), ',');
      next = j < n ? j + 1 : n;
    }
    args.push(arg);
    if (next >= n) break;
    i = next;
  }
  return args;
}

/** Look a scriptlet up by name or alias, with or without ".js". */
export function lookupScriptlet(map: ReadonlyMap<string, ScriptletInfo>, token: string): ScriptletInfo | undefined {
  const t = token.trim();
  if (t === '') return undefined;
  const direct = map.get(t);
  if (direct !== undefined) return direct;
  if (t.endsWith('.js')) return map.get(t.slice(0, -3));
  return map.get(`${t}.js`);
}
