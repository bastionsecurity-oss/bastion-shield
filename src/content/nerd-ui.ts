// Bastion Shield — nerd mode in-page notices (ISOLATED world): the
// lookalike-domain warning bar (cosmetic.js, top frame) and the clipboard
// guard toast (nerd-relay.js).
//
// Both live in a closed shadow root under a host element appended to
// <html>. The host's own inline styles are set with !important (inline
// important declarations beat any page stylesheet) and reset everything
// else with `all: initial`; inside the shadow root only our own stylesheet
// applies, and nothing of it leaks into the page. Texts come from
// chrome.i18n (nerdGuard* keys) with English fallbacks for an invalidated
// extension context. All page-derived text (hostnames) is set with
// textContent, never parsed as HTML.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { LookalikeHit } from '../shared/types.ts';

const FALLBACK: Readonly<Record<string, string>> = {
  nerdGuardLookalikeTitle: 'This looks like $1 but is $2',
  nerdGuardReasonHomoglyph: 'The address uses look-alike characters (homoglyphs).',
  nerdGuardReasonTypo: 'The address differs by a typing error (typosquatting).',
  nerdGuardReasonCombo: 'The address combines the brand name with other words (combosquatting).',
  nerdGuardLookalikeHint: 'Check the address before you sign in or pay.',
  actionDismiss: 'Dismiss',
  nerdGuardClipTitle: 'Suspicious command removed from the clipboard (ClickFix)',
  nerdGuardClipBody: 'This page tried to put a command on your clipboard. Bastion Shield replaced it with a harmless note. Never paste commands from websites into Run, Terminal or PowerShell.',
  extName: 'Bastion Shield',
};

/** chrome.i18n text with placeholders, or the English fallback. */
export function t(key: string, subs: string[] = []): string {
  try {
    const m = chrome.i18n.getMessage(key, subs);
    if (typeof m === 'string' && m !== '') return m;
  } catch {
    // invalidated context or no i18n
  }
  let s = FALLBACK[key] ?? key;
  subs.forEach((v, i) => {
    s = s.split(`$${i + 1}`).join(v);
  });
  return s;
}

const HOST_STYLE: readonly [string, string][] = [
  ['all', 'initial'],
  ['position', 'fixed'],
  ['z-index', '2147483647'],
  ['display', 'block'],
  ['margin', '0'],
  ['padding', '0'],
  ['border', '0'],
  ['pointer-events', 'none'],
  ['contain', 'layout style'],
];

const BASE_CSS = `
:host { all: initial; }
* { box-sizing: border-box; }
.box {
  pointer-events: auto;
  font: 400 14px/1.4 "Inter", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  color: #FFFFFF;
  background: #171C1E;
  border-left: 4px solid #DA291C;
  box-shadow: 0 6px 24px rgba(0, 0, 0, 0.28);
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 12px 14px;
  text-align: left;
  -webkit-font-smoothing: antialiased;
}
.icon { flex: none; width: 20px; height: 20px; margin-top: 1px; color: #E6392E; }
.text { flex: 1 1 auto; min-width: 0; }
.title { font-weight: 600; font-size: 14px; margin: 0; overflow-wrap: anywhere; }
.detail { margin: 2px 0 0; color: #D7DDDF; font-size: 13px; overflow-wrap: anywhere; }
.brand { margin: 0 0 2px; color: #A9B6BA; font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase; }
code { font: 500 13px/1.4 ui-monospace, "Cascadia Mono", Consolas, monospace; color: #FFFFFF; }
button {
  flex: none;
  font: 600 13px/1 system-ui, -apple-system, "Segoe UI", sans-serif;
  color: #171C1E;
  background: #F1EDE6;
  border: 0;
  border-radius: 999px;
  padding: 8px 14px;
  cursor: pointer;
}
button:hover { background: #FFFFFF; }
button:focus-visible { outline: 2px solid #FFFFFF; outline-offset: 2px; }
`;

const ICON_PATH = 'M12 2 1 21h22L12 2zm0 4.2L19.6 19H4.4L12 6.2zM11 10v5h2v-5h-2zm0 6v2h2v-2h-2z';

interface Mounted {
  host: HTMLElement;
  root: ShadowRoot;
}

function mount(pos: readonly [string, string][]): Mounted | null {
  const html = document.documentElement;
  if (html === null) return null;
  const host = document.createElement('div');
  for (const [k, v] of [...HOST_STYLE, ...pos]) host.style.setProperty(k, v, 'important');
  const root = host.attachShadow({ mode: 'closed' });
  const style = document.createElement('style');
  style.textContent = BASE_CSS;
  root.appendChild(style);
  html.appendChild(host);
  return { host, root };
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls: string, text?: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (cls !== '') e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function icon(): SVGSVGElement {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', 'icon');
  svg.setAttribute('aria-hidden', 'true');
  const p = document.createElementNS(ns, 'path');
  p.setAttribute('d', ICON_PATH);
  p.setAttribute('fill', 'currentColor');
  svg.appendChild(p);
  return svg;
}

/**
 * "This looks like <target> but is <host>" with the title split around the
 * placeholders so both domains render as <code>.
 */
function lookalikeTitle(hit: LookalikeHit): HTMLElement {
  const title = el('p', 'title');
  const A = '\u0001';
  const B = '\u0002';
  const tpl = t('nerdGuardLookalikeTitle', [A, B]);
  const parts = tpl.split(/([\u0001\u0002])/);
  for (const part of parts) {
    if (part === A) title.appendChild(el('code', '', hit.target));
    else if (part === B) title.appendChild(el('code', '', hit.host));
    else if (part !== '') title.appendChild(document.createTextNode(part));
  }
  return title;
}

const REASON_KEY: Readonly<Record<LookalikeHit['reason'], string>> = {
  homoglyph: 'nerdGuardReasonHomoglyph',
  typo: 'nerdGuardReasonTypo',
  combo: 'nerdGuardReasonCombo',
};

let bannerShown = false;

/** Warning bar for a lookalike domain (top frame). Shown once per page load. */
export function showLookalikeBanner(hit: LookalikeHit): void {
  if (bannerShown || hit === null || typeof hit !== 'object') return;
  if (typeof hit.host !== 'string' || typeof hit.target !== 'string' || !(hit.reason in REASON_KEY)) return;
  const m = mount([
    ['top', '0'],
    ['left', '0'],
    ['right', '0'],
    ['width', '100%'],
  ]);
  if (m === null) return;
  bannerShown = true;
  const box = el('div', 'box');
  box.setAttribute('role', 'alert');
  box.appendChild(icon());
  const text = el('div', 'text');
  text.appendChild(el('p', 'brand', t('extName')));
  text.appendChild(lookalikeTitle(hit));
  text.appendChild(el('p', 'detail', `${t(REASON_KEY[hit.reason])} ${t('nerdGuardLookalikeHint')}`));
  box.appendChild(text);
  const btn = el('button', '', t('actionDismiss'));
  btn.type = 'button';
  btn.addEventListener('click', () => m.host.remove());
  box.appendChild(btn);
  m.root.appendChild(box);
}

const TOAST_MS = 9000;
let toast: { m: Mounted; timer: number; count: HTMLElement; n: number } | null = null;

/** Toast after a blocked clipboard write; repeated blocks update the same toast. */
export function showClipToast(): void {
  if (toast !== null && toast.m.host.isConnected) {
    toast.n++;
    toast.count.textContent = ` (${toast.n})`;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(hideToast, TOAST_MS) as unknown as number;
    return;
  }
  const m = mount([
    ['right', '16px'],
    ['bottom', '16px'],
    ['max-width', 'min(420px, calc(100vw - 32px))'],
  ]);
  if (m === null) return;
  const box = el('div', 'box');
  box.setAttribute('role', 'status');
  box.style.borderRadius = '10px';
  box.appendChild(icon());
  const text = el('div', 'text');
  text.appendChild(el('p', 'brand', t('extName')));
  const title = el('p', 'title', t('nerdGuardClipTitle'));
  const count = el('span', '');
  title.appendChild(count);
  text.appendChild(title);
  text.appendChild(el('p', 'detail', t('nerdGuardClipBody')));
  box.appendChild(text);
  const btn = el('button', '', t('actionDismiss'));
  btn.type = 'button';
  btn.addEventListener('click', hideToast);
  box.appendChild(btn);
  m.root.appendChild(box);
  toast = { m, timer: setTimeout(hideToast, TOAST_MS) as unknown as number, count, n: 1 };
}

function hideToast(): void {
  if (toast === null) return;
  clearTimeout(toast.timer);
  toast.m.host.remove();
  toast = null;
}
