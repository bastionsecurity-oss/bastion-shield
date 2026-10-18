// Bastion Shield — conservative CSS selector sanity check used by the build.
// Hide rules are emitted in groups (`a,\nb,\n…{display:none!important}`): a
// single selector the browser cannot parse invalidates the whole group, so we
// drop selectors that are structurally broken or use pseudo-classes Chromium
// does not know (typically procedural operators that leaked through).
//
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * Pseudo-classes Chromium parses in a style rule, verified by inserting
 * `div:<name>{}` into a stylesheet in Chromium 156: the @page-only
 * :first/:left/:right and the media-state :playing/:paused/:muted/... are
 * rejected there, so they are deliberately absent. -webkit-* is handled below.
 */
const PSEUDO_CLASSES = new Set([
  'active', 'any-link', 'autofill', 'checked', 'current', 'default', 'defined', 'dir', 'disabled',
  'empty', 'enabled', 'first-child', 'first-of-type', 'focus', 'focus-visible', 'focus-within',
  'fullscreen', 'future', 'has', 'host', 'host-context', 'hover', 'in-range', 'indeterminate', 'invalid', 'is',
  'lang', 'last-child', 'last-of-type', 'link', 'modal', 'not', 'nth-child', 'nth-last-child',
  'nth-last-of-type', 'nth-of-type', 'only-child', 'only-of-type', 'open', 'optional', 'out-of-range', 'past',
  'picture-in-picture', 'placeholder-shown', 'popover-open', 'read-only', 'read-write',
  'required', 'root', 'scope', 'state', 'target', 'user-invalid',
  'user-valid', 'valid', 'visited', 'where', 'xr-overlay',
  'horizontal', 'vertical', 'decrement', 'increment', 'start', 'end', 'double-button', 'single-button',
  'no-button', 'corner-present', 'window-inactive', 'active-view-transition', 'active-view-transition-type',
]);

/** Pseudo-elements (`::x`, and the legacy single-colon forms). */
const PSEUDO_ELEMENTS = new Set([
  'after', 'backdrop', 'before', 'cue', 'file-selector-button', 'first-letter', 'first-line',
  'grammar-error', 'highlight', 'marker', 'part', 'placeholder', 'selection', 'slotted', 'spelling-error',
  'target-text', 'view-transition', 'view-transition-group', 'view-transition-image-pair', 'view-transition-new',
  'view-transition-old', 'details-content', 'scroll-marker', 'scroll-marker-group', 'scroll-button', 'column',
  'picker', 'picker-icon', 'checkmark',
]);

const LEGACY_SINGLE_COLON_ELEMENTS = new Set(['after', 'before', 'first-letter', 'first-line']);

/** Returns null when the selector looks safe, else a short reason. */
export function selectorProblem(sel: string): string | null {
  if (sel.length === 0) return 'empty selector';
  if (sel.length > 8192) return 'selector too long';
  if (/[\x00-\x08\x0a-\x1f\x7f]/.test(sel)) return 'control character';
  const stack: string[] = [];
  let quote = '';
  for (let i = 0; i < sel.length; i++) {
    const c = sel[i];
    if (c === '\\') {
      i++; // escaped character, whatever it is
      if (i >= sel.length) return 'dangling escape';
      continue;
    }
    if (quote) {
      if (c === quote) quote = '';
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      continue;
    }
    if (c === '{' || c === '}' || c === ';') return `unexpected "${c}"`;
    if (c === '/' && sel[i + 1] === '*') return 'comment in selector';
    if (c === '(' || c === '[') stack.push(c);
    else if (c === ')' || c === ']') {
      const open = stack.pop();
      if ((c === ')' && open !== '(') || (c === ']' && open !== '[')) return 'unbalanced brackets';
    } else if (c === ':' && stack[stack.length - 1] !== '[') {
      const isElement = sel[i + 1] === ':';
      const start = isElement ? i + 2 : i + 1;
      const m = /^-?[A-Za-z][A-Za-z0-9-]*/.exec(sel.slice(start, start + 64));
      if (!m) return 'malformed pseudo-class';
      const name = m[0].toLowerCase();
      // Chromium parses a long tail of -webkit- pseudos (scrollbar parts, autofill, ...).
      if (name.startsWith('-webkit-')) {
        i = start + m[0].length - 1;
        continue;
      }
      if (name.startsWith('-abp-') || name.startsWith('-ext-')) return `procedural operator :${name}`;
      const known = isElement ? PSEUDO_ELEMENTS.has(name) : PSEUDO_CLASSES.has(name) || LEGACY_SINGLE_COLON_ELEMENTS.has(name);
      if (!known) return `unknown pseudo ${isElement ? '::' : ':'}${name}`;
      i = start + m[0].length - 1;
    }
  }
  if (quote) return 'unterminated string';
  if (stack.length !== 0) return 'unbalanced brackets';
  const t = sel.trim();
  // Leading combinators are only valid inside :has(); top-level they break the group.
  if (/^[>+~,]/.test(t)) return 'leading combinator';
  if (/[>+~,]$/.test(t)) return 'trailing combinator';
  return null;
}

/** Group selectors into `sel,\nsel{display:none!important}` rules of at most `perRule`. */
export function hideRules(selectors: readonly string[], perRule = 1000): string {
  const out: string[] = [];
  for (let i = 0; i < selectors.length; i += perRule) {
    out.push(`${selectors.slice(i, i + perRule).join(',\n')}{display:none!important}`);
  }
  return out.length ? out.join('\n') + '\n' : '';
}
