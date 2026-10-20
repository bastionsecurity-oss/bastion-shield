// Bastion filter compiler — list preprocessor (!#if / !#else / !#endif and
// !#include), with the same token semantics as uBlock Origin's preparser
// (static-filtering-parser.js, utils.preparser) so lists that branch on
// "ext_ubol" or "env_mv3" compile the way their maintainers test them.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * `!#if` tokens and the environment "state" each one maps to in uBO. A token
 * is true when the caller's env contains the token itself or its state. The
 * special state "false" never holds.
 */
export const PREPARSER_TOKENS: ReadonlyMap<string, string> = new Map([
  ['ext_ublock', 'ublock'],
  ['ext_ubol', 'ubol'],
  ['ext_devbuild', 'devbuild'],
  ['env_brave', 'brave'],
  ['env_chromium', 'chromium'],
  ['env_edge', 'edge'],
  ['env_firefox', 'firefox'],
  ['env_legacy', 'legacy'],
  ['env_mobile', 'mobile'],
  ['env_mv3', 'mv3'],
  ['env_safari', 'safari'],
  ['cap_html_filtering', 'html_filtering'],
  ['cap_ipaddress', 'ipaddress'],
  ['false', 'false'],
  ['ext_abp', 'false'],
  ['adguard', 'adguard'],
  ['adguard_app_android', 'false'],
  ['adguard_app_cli', 'false'],
  ['adguard_app_ios', 'false'],
  ['adguard_app_mac', 'false'],
  ['adguard_app_windows', 'false'],
  ['adguard_ext_android_cb', 'false'],
  ['adguard_ext_chromium', 'chromium'],
  ['adguard_ext_chromium_mv3', 'mv3'],
  ['adguard_ext_edge', 'edge'],
  ['adguard_ext_firefox', 'firefox'],
  ['adguard_ext_opera', 'chromium'],
  ['adguard_ext_safari', 'false'],
]);

/**
 * Tokens that are true for Bastion Shield: we behave like uBO Lite on
 * Chromium (uBOL builds with env = chromium, native_css_has, mv3, ublock,
 * ubol). HTML filtering and $ipaddress are not available (cap_* false), and
 * we are neither Brave's engine nor AdGuard.
 */
export const DEFAULT_ENV: ReadonlySet<string> = new Set([
  'ext_ublock',
  'ext_ubol',
  'env_chromium',
  'env_mv3',
  'adguard_ext_chromium',
  'adguard_ext_chromium_mv3',
  'adguard_ext_opera',
]);

/** true / false, or undefined for an unknown token (uBO then keeps the block). */
function evaluateToken(raw: string, env: ReadonlySet<string>): boolean | undefined {
  const not = raw.charCodeAt(0) === 0x21 /* ! */;
  const token = not ? raw.slice(1) : raw;
  let state: boolean | undefined;
  if (env.has(token)) {
    state = true;
  } else {
    const mapped = PREPARSER_TOKENS.get(token);
    if (mapped === undefined) {
      if (!token.startsWith('cap_')) return undefined;
      state = false;
    } else {
      state = mapped !== 'false' && env.has(mapped);
    }
  }
  return not ? !state : state;
}

/**
 * Evaluate a `!#if` expression: tokens joined by && / || and evaluated left
 * to right without precedence, optionally wrapped in one pair of parentheses
 * (uBO semantics). Returns undefined when the expression is not understood.
 */
export function evaluateExpression(expr: string, env: ReadonlySet<string>): boolean | undefined {
  let e = expr.trim();
  if (e.startsWith('(') && e.endsWith(')')) e = e.slice(1, -1).trim();
  const parts = e.split(/\s+/).filter((s) => s !== '');
  if (parts.length === 0) return undefined;
  if (parts[0] === '&&' || parts[0] === '||') return undefined;
  let result = evaluateToken(parts[0], env);
  for (let i = 1; i < parts.length; i += 2) {
    const op = parts[i];
    const tok = parts[i + 1];
    if (tok === undefined || (op !== '&&' && op !== '||')) return undefined;
    const state = evaluateToken(tok, env);
    if (state === undefined) return undefined;
    result = op === '||' ? result || state : result && state;
  }
  return result;
}

export type IncludeResolver = (path: string) => string | null | undefined;

interface IfFrame {
  known: boolean;
  discard: boolean;
}

const MAX_INCLUDE_DEPTH = 4;

/**
 * Apply `!#if` directives (discarded lines become empty so line numbers stay
 * stable) and, when a resolver is given, expand `!#include <path>` with the
 * resolved text (itself preprocessed). Includes are not expanded inside a
 * discarded block. Without a resolver, `!#include` lines are left as comments.
 */
export function preprocess(
  text: string,
  env: ReadonlySet<string> = DEFAULT_ENV,
  resolveInclude?: IncludeResolver,
): string {
  return preprocessInner(text, env, resolveInclude, 0, new Set());
}

function preprocessInner(
  text: string,
  env: ReadonlySet<string>,
  resolveInclude: IncludeResolver | undefined,
  depth: number,
  seen: Set<string>,
): string {
  if (text.indexOf('!#') === -1) return text;
  const lines = text.split('\n');
  const stack: IfFrame[] = [];
  let discarding = false;
  const recompute = (): boolean => stack.some((f) => f.known && f.discard);
  let changed = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.charCodeAt(0) !== 0x21 /* ! */ || line.charCodeAt(1) !== 0x23 /* # */) {
      if (discarding && line !== '') {
        lines[i] = '';
        changed = true;
      }
      continue;
    }
    const l = line.endsWith('\r') ? line.slice(0, -1) : line;
    const directive = /^!#(if|else|endif|include)\b(.*)$/.exec(l);
    if (directive === null) {
      // `!#trusted` markers survive discarded blocks: an `!#if` left open by
      // one source must not swallow the trust switch around the next source.
      if (discarding && !l.startsWith('!#trusted ')) {
        lines[i] = '';
        changed = true;
      }
      continue;
    }
    const kind = directive[1];
    if (kind === 'if') {
      const result = evaluateExpression(directive[2], env);
      stack.push({ known: result !== undefined, discard: result === false });
      discarding = recompute();
      lines[i] = '';
      changed = true;
    } else if (kind === 'else') {
      const top = stack[stack.length - 1];
      if (top !== undefined) top.discard = !top.discard;
      discarding = recompute();
      lines[i] = '';
      changed = true;
    } else if (kind === 'endif') {
      stack.pop();
      discarding = recompute();
      lines[i] = '';
      changed = true;
    } else {
      // include
      if (discarding) {
        lines[i] = '';
        changed = true;
        continue;
      }
      if (resolveInclude === undefined || depth >= MAX_INCLUDE_DEPTH) continue;
      const path = directive[2].trim().split(/\s+/)[0] ?? '';
      if (path === '' || seen.has(path)) {
        lines[i] = '';
        changed = true;
        continue;
      }
      let sub: string | null | undefined;
      try {
        sub = resolveInclude(path);
      } catch {
        sub = undefined;
      }
      lines[i] = '';
      changed = true;
      if (typeof sub === 'string' && sub !== '') {
        seen.add(path);
        lines[i] = preprocessInner(sub, env, resolveInclude, depth + 1, seen);
        seen.delete(path);
      }
    }
  }
  return changed ? lines.join('\n') : text;
}
