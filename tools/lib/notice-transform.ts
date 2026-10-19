// Bastion Shield — build-time transform of uBO's prevent-clipboard-write
// scriptlet (vendor/ublock/resources/prevent-clipboard-write.js, which stays
// untouched so `npm run vendor:check` keeps passing).
//
// uBlock filters ship a generic ClickFix filter
// `*,~…##+js(prevent-clipboard-write, <regex>, domAlert, <message>, …)`. The
// scriptlet traps navigator.clipboard.writeText and execCommand('copy') and,
// with `domAlert`, shows its own beige bar at the top of the page. Bastion
// shows every blocker notice in its own style, so the transform:
//
//   1. replaces the alert UI (`htmlTemplate` … `let currentAlert = null;`)
//      with `bastionNotice`, a function that dispatches a synchronous
//      CustomEvent `<eventName>` on the frame's window with the string detail
//      `ubo|<blocked text>`. Built-ins (EventTarget#dispatchEvent,
//      CustomEvent, Reflect.apply, Object.create) are captured when the
//      scriptlet runs, at document_start before any page script;
//   2. replaces the call `domAlert(text)` with `bastionNotice(text)`.
//
// The blocking logic (pattern, excludeMatches, the traps, the return values)
// is not touched: the write is still prevented exactly as in uBO. The
// isolated content script content/cosmetic.js listens for `<eventName>`,
// stops the event and shows the Bastion notice (content/notice.ts). Without
// that listener nothing is shown: the beige bar cannot come back.
//
// The event name is a random token per build (noticeEventName), compiled
// into both the scriptlet core (here) and cosmetic.js (esbuild define
// __BASTION_NOTICE_EVENT__). It never appears in anything a page can read:
// content-script files are not web-accessible, and the scriptlet keeps it in
// a closure. See docs/NERD-MODE.md "Blocker notices" for the forgery analysis.
//
// If uBO changes the scriptlet so that an anchor no longer matches, the
// transform throws and the build fails (and test/tools/notice-transform.test.ts
// fails on the vendored file), so a vendor update cannot silently bring the
// beige bar back.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { randomBytes } from 'node:crypto';

/** uBO resource name of the scriptlet. */
export const CLIPBOARD_SCRIPTLET = 'prevent-clipboard-write.js';
/** Detail prefix the content script expects. */
export const NOTICE_DETAIL_UBO = 'ubo|';
/** Name of the esbuild define that carries the event name into cosmetic.js. */
export const NOTICE_EVENT_DEFINE = '__BASTION_NOTICE_EVENT__';

const EVENT_RE = /^[a-z][a-z0-9]{19,}$/;

/** A fresh event name: "bsn" + 24 random hex digits (96 bits). */
export function noticeEventName(): string {
  return `bsn${randomBytes(12).toString('hex')}`;
}

export class NoticeTransformError extends Error {}

const REGION_START = 'const htmlTemplate = [';
const REGION_END = 'let currentAlert = null;';
const CALL_RE = /if\s*\(\s*extraArgs\.domAlert\s*\)\s*\{\s*domAlert\(\s*text\s*\);\s*\}/g;

function count(hay: string, needle: string): number {
  let n = 0;
  for (let i = hay.indexOf(needle); i !== -1; i = hay.indexOf(needle, i + needle.length)) n++;
  return n;
}

function fail(msg: string): never {
  throw new NoticeTransformError(
    `notice-transform: ${msg}. uBO's prevent-clipboard-write scriptlet changed upstream; ` +
      'update tools/lib/notice-transform.ts so its DOM alert stays replaced by the Bastion notice.',
  );
}

/** The replacement for the alert UI. `name` is validated by the caller (no quoting needed). */
function noticeFn(name: string): string {
  return [
    '// Bastion Shield (tools/lib/notice-transform.ts): instead of uBO\'s DOM alert,',
    '// a synchronous event to the isolated content script, which shows the',
    '// Bastion notice. Built-ins are captured before any page script runs.',
    'const bastionNotice = (( ) => {',
    `    const name = '${name}';`,
    '    const target = self;',
    '    const dispatch = self.EventTarget.prototype.dispatchEvent;',
    '    const CE = self.CustomEvent;',
    '    const apply = Reflect.apply;',
    '    const create = Object.create;',
    '    return text => {',
    '        try {',
    '            const init = create(null);',
    `            init.detail = '${NOTICE_DETAIL_UBO}' + text;`,
    '            apply(dispatch, target, [ new CE(name, init) ]);',
    '        } catch ( e ) {',
    '        }',
    '    };',
    '})();',
  ].join('\n');
}

/**
 * Transform the source of uBO's preventClipboardWrite function. Throws
 * NoticeTransformError when an anchor is missing or ambiguous.
 */
export function transformClipboardScriptlet(code: string, eventName: string): string {
  if (!EVENT_RE.test(eventName)) throw new NoticeTransformError(`notice-transform: invalid event name ${JSON.stringify(eventName)}`);
  if (!/^function\s+preventClipboardWrite\s*\(/.test(code.trimStart())) fail('function preventClipboardWrite not found');
  if (count(code, REGION_START) !== 1) fail(`anchor "${REGION_START}" found ${count(code, REGION_START)} times`);
  if (count(code, REGION_END) !== 1) fail(`anchor "${REGION_END}" found ${count(code, REGION_END)} times`);
  const a = code.indexOf(REGION_START);
  const b = code.indexOf(REGION_END) + REGION_END.length;
  if (b <= a) fail('alert anchors out of order');
  const region = code.slice(a, b);
  if (!region.includes('beige') || !region.includes('const domAlert = clipboardText =>')) fail('alert region does not hold the DOM alert');
  const calls = code.match(CALL_RE) ?? [];
  if (calls.length !== 1) fail(`"if ( extraArgs.domAlert ) { domAlert(text); }" found ${calls.length} times`);
  let out = code.slice(0, a) + noticeFn(eventName) + code.slice(b);
  out = out.replace(CALL_RE, 'if ( extraArgs.domAlert ) { bastionNotice(text); }');
  // Nothing of the alert UI may survive.
  for (const gone of ['beige', 'DOMParser', 'showPopover', 'domAlert(', 'currentAlert', 'htmlTemplate']) {
    if (out.includes(gone)) fail(`"${gone}" still present after the transform`);
  }
  // The blocking traps must be intact.
  for (const kept of ["proxyApplyFn('navigator.clipboard.writeText'", "proxyApplyFn('document.execCommand'", 'safe.testPattern(pattern, text)', 'bastionNotice(text)']) {
    if (!out.includes(kept)) fail(`"${kept}" missing after the transform`);
  }
  return out;
}
