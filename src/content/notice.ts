// Bastion Shield — blocker notices in the page (ISOLATED world, bundled into
// content/cosmetic.js, which runs in every frame where protection is on,
// with nerd mode on or off).
//
// One component for every in-page notice of the blocker (Paper «UI
// Optimised» N01–N09):
//   * ClickFix blocked: a blocked clipboard write, from uBlock filters'
//     prevent-clipboard-write (tools/lib/notice-transform.ts) or from the
//     nerd mode clipboard guard (content/nerd-relay.ts). Tile, title, one
//     sentence; the command stays collapsed behind «Befehl ansehen»;
//   * lookalike domain (nerd mode): «Das ist nicht microsoft.com» with the
//     real and the visited address, the differing characters boxed.
//
// Rendering: top frame only. A subframe hands its clipboard notices to the
// service worker (`notice:clip`), which forwards them to frame 0
// (`notice:show`). Cards stack top-right (top 12px, right 12px, width
// min(340px, 100vw - 24px)), the newest on top; older ones collapse into a
// «2 weitere Meldungen» row that expands them. The host element sits in the
// top layer (popover="manual") with z-index max, so page overlays cannot
// cover it; its inline styles are !important after `all: initial` (inline
// important declarations beat any page stylesheet), and everything else
// lives in a CLOSED shadow root, so page CSS neither reaches in nor does ours
// leak out. Page-derived text (commands, hostnames) is only ever set with
// textContent. Security notices never dismiss themselves. Texts come from
// chrome.i18n (`notice*` keys) with English fallbacks for an invalidated
// extension context.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { LookalikeHit } from '../shared/types.ts';
import {
  charCount,
  clipKey,
  clipSlot,
  Deduper,
  hostDiff,
  MAX_NOTICE_TEXT,
  overflow,
  scrollState,
  splitInvisible,
  stackView,
  truncateParts,
} from './notice-model.ts';
import type { NoticeKind, NoticeSource } from './notice-model.ts';

const FALLBACK: Readonly<Record<string, string>> = {
  noticeClose: 'Close',
  noticeClipTitle: 'Dangerous command stopped',
  noticeClipBody: 'Don’t paste anything into Run, Terminal or PowerShell.',
  noticeClipCommandLabel: 'Blocked command',
  noticeShowCommand: 'Show command',
  noticeHideCommand: 'Hide command',
  noticeCopyHint: 'Only copy it if you understand it.',
  noticeChars: '$1 characters',
  noticeHiddenOne: '1 hidden character',
  noticeHiddenMany: '$1 hidden characters',
  noticeInvisibleChar: 'Invisible character $1',
  noticeLookTitle: 'This isn’t $1',
  noticeLookReal: 'Real',
  noticeLookThis: 'This page',
  noticeFullAddress: 'Full address',
  noticeLookalikeLeave: 'Leave site',
  noticeStay: 'Stay anyway',
  noticeMore: '$1 more notices',
  noticeMoreOne: '1 more notice',
  noticeMoreCmdOne: '1 command',
  noticeMoreCmds: '$1 commands',
  noticeMoreAddr: '1 address',
  noticeMoreShow: 'Show',
  noticeMoreHide: 'Hide',
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

function uiLang(): string {
  try {
    return chrome.i18n.getUILanguage().split(/[-_]/)[0] || 'en';
  } catch {
    return 'en';
  }
}

let numberFormat: Intl.NumberFormat | null = null;
/** 1'204 in the Swiss style of the UI language. */
function fmt(n: number): string {
  try {
    numberFormat ??= new Intl.NumberFormat(`${uiLang()}-CH`);
    return numberFormat.format(n);
  } catch {
    return String(n);
  }
}

/** «1 Befehl» / «3 Befehle»: the one-key for exactly one, else the many-key with the formatted number. */
function plural(n: number, one: string, many: string): string {
  return n === 1 ? t(one) : t(many, [fmt(n)]);
}

const HOST_STYLE: readonly [string, string][] = [
  ['all', 'initial'],
  ['position', 'fixed'],
  ['inset', 'auto'],
  ['top', '12px'],
  ['right', '12px'],
  ['left', 'auto'],
  ['bottom', 'auto'],
  ['width', 'min(340px, calc(100vw - 24px))'],
  ['max-height', 'calc(100vh - 24px)'],
  ['z-index', '2147483647'],
  ['display', 'block'],
  ['margin', '0'],
  ['padding', '0'],
  ['border', '0'],
  ['background', 'transparent'],
  ['overflow', 'visible'],
  ['pointer-events', 'none'],
  ['contain', 'layout style'],
  ['color-scheme', 'light dark'],
];

/** Visible characters of a host in the «Diese Seite» row (14px mono in 200px). */
const HOST_MAX = 23;

// Gletscher palette (DESIGN.md, src/ui/shared/tokens.css). Bundesrot only in
// the mark's diamond; no status colour: the tiles, boxes and text carry it.
const CSS = `
:host { all: initial; }
* { box-sizing: border-box; }
[hidden] { display: none !important; }
.stack {
  --bg: #FFFFFF; --line: #D7DDDF; --ink: #171C1E; --ink-cmd: #17171A; --ink-2: #4C575D; --ink-3: #5F6B71;
  --field: #F2F4F5; --field-line: #E4E8E9; --compare: #F2F4F5;
  --tile: #171C1E; --on-tile: #FFFFFF; --chip: #171C1E; --on-chip: #FFFFFF;
  --primary: #171C1E; --primary-hover: #2A3134; --on-primary: #FFFFFF;
  --underline: #A9B6BA; --outline: #798186; --hover: rgba(228, 232, 233, 0.75);
  --focus: #2A3134; --diamond: #DA291C; --thumb: #A9B6BA;
  --shadow: 0 1px 2px rgba(23, 28, 30, 0.06), 0 10px 28px rgba(23, 28, 30, 0.14);
  --shadow-row: 0 1px 2px rgba(23, 28, 30, 0.06), 0 6px 16px rgba(23, 28, 30, 0.10);
  display: flex; flex-direction: column; gap: 8px;
  font: 400 14px/20px "Inter", system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  color: var(--ink);
  text-align: left;
  -webkit-font-smoothing: antialiased;
}
@media (prefers-color-scheme: dark) {
  .stack {
    --bg: #171C1E; --line: #262C2E; --ink: #FFFFFF; --ink-cmd: #FFFFFF; --ink-2: #A9B6BA; --ink-3: #8D9A9F;
    --field: #1F2629; --field-line: #262C2E; --compare: #252A2C;
    --tile: #FFFFFF; --on-tile: #171C1E; --chip: #FFFFFF; --on-chip: #171C1E;
    --primary: #FFFFFF; --primary-hover: #D7DDDF; --on-primary: #171C1E;
    --underline: #798186; --outline: #798186; --hover: rgba(255, 255, 255, 0.08);
    --focus: #D7DDDF; --diamond: #E6392E; --thumb: #4C575D;
    --shadow: 0 1px 2px rgba(0, 0, 0, 0.3), 0 12px 32px rgba(0, 0, 0, 0.5);
    --shadow-row: 0 1px 2px rgba(0, 0, 0, 0.3), 0 6px 16px rgba(0, 0, 0, 0.4);
  }
}
.stack.open { max-height: calc(100vh - 24px); overflow-y: auto; overscroll-behavior: contain; scrollbar-width: none; padding-bottom: 8px; }
.older { display: flex; flex-direction: column; gap: 8px; }
.card, .more {
  pointer-events: auto;
  position: relative;
  width: 100%;
  margin: 0;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 24px;
  box-shadow: var(--shadow);
}
.card { display: flex; flex-direction: column; gap: 8px; padding: 12px; }
.card.look { gap: 12px; }
.enter { animation: enter 200ms cubic-bezier(0.2, 0, 0, 1) both; }
@keyframes enter { from { opacity: 0; transform: translateY(-8px); } }
p { margin: 0; }
button { font: inherit; color: inherit; margin: 0; }
.head { display: flex; align-items: flex-start; gap: 12px; }
.look .head { align-items: center; }
.tile {
  position: relative; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  width: 48px; height: 48px; border-radius: 12px;
  background: var(--tile); color: var(--on-tile);
}
.tile svg { width: 24px; height: 24px; }
.badge {
  position: absolute; right: -5px; bottom: -5px;
  display: flex; align-items: center; justify-content: center;
  width: 22px; height: 22px; border-radius: 999px;
  background: var(--bg); color: var(--tile); box-shadow: 0 0 0 1.5px var(--tile);
}
.badge svg { width: 10px; height: 10px; }
.text { display: flex; flex-direction: column; gap: 2px; flex: 1 1 0; min-width: 0; padding-top: 2px; }
.look .text { padding-top: 0; }
.title {
  font: 600 17px/22px "Inter Tight", "Inter", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  letter-spacing: -0.012em; color: var(--ink); overflow-wrap: anywhere;
}
.body { color: var(--ink-2); overflow-wrap: anywhere; }
.close {
  flex-shrink: 0;
  display: inline-flex; align-items: center; justify-content: center;
  width: 32px; height: 32px; padding: 0;
  border: 0; border-radius: 999px;
  background: transparent; color: var(--ink-2);
  cursor: pointer;
}
.close svg { width: 14px; height: 14px; }
.foot { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding-left: 56px; }
.disc {
  display: inline-flex; align-items: center; gap: 6px;
  height: 32px; padding: 0 8px;
  border: 0; border-radius: 999px; background: transparent;
  font-size: 13px; font-weight: 600; line-height: 16px; color: var(--ink);
  cursor: pointer;
}
.disc svg { width: 12px; height: 12px; flex-shrink: 0; transition: transform 160ms cubic-bezier(0.2, 0, 0, 1); }
.disc[aria-expanded="true"] svg { transform: rotate(90deg); }
.brand { display: inline-flex; align-items: center; gap: 6px; padding-right: 4px; font-size: 12px; line-height: 16px; color: var(--ink-3); white-space: nowrap; }
.mark { width: 14px; height: 14px; flex-shrink: 0; }
.mark .ring { fill: var(--ink-3); }
.mark .dia { fill: var(--diamond); }
.sr { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
@media (max-width: 363.98px) {
  .brand-name { position: absolute; width: 1px; height: 1px; margin: -1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
}
.cmdbox { display: flex; flex-direction: column; gap: 6px; }
.field {
  position: relative; overflow: hidden;
  background: var(--field); border: 1px solid var(--field-line); border-radius: 12px;
}
.field:has(.cmd:focus-visible) { outline: 2px solid var(--focus); outline-offset: 2px; }
.cmd {
  max-height: 126px;
  margin: 0; padding: 10px 18px 10px 12px;
  overflow-y: auto; overscroll-behavior: contain;
  color: var(--ink-cmd);
  font: 400 12px/18px "IBM Plex Mono", ui-monospace, "Cascadia Mono", "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-all;
  user-select: text; -webkit-user-select: text; cursor: text;
  scrollbar-width: thin; scrollbar-color: var(--thumb) transparent;
  outline: none;
}
.inv {
  display: inline-block; margin: 0 1px; padding: 0 4px; border-radius: 4px;
  background: var(--chip); color: var(--on-chip);
  font-size: 11px; line-height: 16px; vertical-align: baseline;
  user-select: none; -webkit-user-select: none;
}
.fade {
  position: absolute; left: 0; right: 10px; bottom: 0; height: 36px;
  background: linear-gradient(to bottom, transparent, var(--field) 85%);
  pointer-events: none; opacity: 0;
  transition: opacity 160ms cubic-bezier(0.2, 0, 0, 1);
}
.field.scrolls:not(.at-end) .fade { opacity: 1; }
.meta { display: flex; justify-content: space-between; gap: 12px; font-size: 12px; line-height: 16px; color: var(--ink-3); }
.meta.stacked { flex-direction: column; gap: 2px; }
.meta .strong { font-weight: 600; color: var(--ink); }
.meta .count { flex-shrink: 0; white-space: nowrap; }
.compare { margin: 0; background: var(--compare); border-radius: 12px; }
.row { display: flex; align-items: center; gap: 8px; padding: 10px 12px; }
.row + .row, .full { border-top: 1px solid var(--field-line); }
.row dt { flex-shrink: 0; width: 80px; font-size: 12px; line-height: 16px; color: var(--ink-2); }
.row dd {
  flex: 1 1 0; min-width: 0; margin: 0;
  font: 500 14px/20px "IBM Plex Mono", ui-monospace, "Cascadia Mono", "SF Mono", Menlo, Consolas, monospace;
  color: var(--ink); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.diff { padding: 0 2px; border-radius: 4px; background: var(--chip); color: var(--on-chip); }
.ell { color: var(--ink-3); }
.full { display: flex; flex-direction: column; gap: 6px; padding: 4px 12px 12px; }
.full .disc { align-self: flex-start; margin-left: -8px; }
.fullhost {
  font: 400 12px/18px "IBM Plex Mono", ui-monospace, "Cascadia Mono", "SF Mono", Menlo, Consolas, monospace;
  color: var(--ink); overflow-wrap: anywhere; word-break: break-all;
}
.actions { display: flex; align-items: center; gap: 8px; }
.actions .spacer { flex: 1 1 0; }
.actions .mark { margin-right: 6px; }
.btn {
  display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0;
  height: 40px; border: 0; border-radius: 999px; background: transparent;
  font-size: 14px; font-weight: 600; line-height: 18px; white-space: nowrap;
  cursor: pointer;
  transition: transform 120ms cubic-bezier(0.2, 0, 0, 1);
}
.btn.primary { padding: 0 18px; background: var(--primary); color: var(--on-primary); }
.btn.primary:hover { background: var(--primary-hover); }
.btn.quiet { padding: 0 10px; color: var(--ink); text-decoration: underline 1px var(--underline); text-underline-offset: 4px; }
.btn.quiet:hover { text-decoration-color: var(--ink); }
.btn.outline { height: 32px; padding: 0 12px; font-size: 13px; line-height: 16px; color: var(--ink); box-shadow: inset 0 0 0 1px var(--outline); }
.btn.outline:hover { background: var(--hover); box-shadow: inset 0 0 0 1px var(--ink); }
.btn:active, .close:active, .disc:active { transform: scale(0.98); }
.close:hover, .disc:hover { background: var(--hover); color: var(--ink); }
.more { display: flex; align-items: center; gap: 12px; padding: 8px 8px 8px 12px; box-shadow: var(--shadow-row); }
.minis { display: flex; flex-shrink: 0; }
.mini {
  display: flex; align-items: center; justify-content: center;
  width: 28px; height: 28px; border-radius: 8px;
  background: var(--tile); color: var(--on-tile); box-shadow: 0 0 0 2px var(--bg);
}
.mini + .mini { margin-left: -8px; }
.mini svg { width: 14px; height: 14px; }
.more .text { gap: 0; padding-top: 0; }
.more-title { font-weight: 600; color: var(--ink); }
.more-sum { font-size: 12px; line-height: 16px; color: var(--ink-3); }
.btn:focus-visible, .close:focus-visible, .disc:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
@media (prefers-reduced-motion: reduce) {
  .enter { animation: none; }
  .btn, .disc svg, .fade { transition: none; }
  .btn:active, .close:active, .disc:active { transform: none; }
}
`;

const SVG = 'http://www.w3.org/2000/svg';
// The Bastion mark (src/icons/mark-on.svg): octagon ring and diamond.
const RING =
  'M 55.00 76.50 L 60.55 76.50 L 76.50 60.55 L 76.50 39.45 L 60.55 23.50 L 39.45 23.50 L 23.50 39.45 L 23.50 60.55 L 39.45 76.50 L 45.00 76.50 L 45.00 83.50 L 36.55 83.50 L 16.50 63.45 L 16.50 36.55 L 36.55 16.50 L 63.45 16.50 L 83.50 36.55 L 83.50 63.45 L 63.45 83.50 L 55.00 83.50 Z';
const DIAMOND = 'M 50 40 L 60 50 L 50 60 L 40 50 Z';
const PROMPT = 'M5 7 10 12 5 17M12.5 17.5h7';
const NOT_EQUAL = 'M4.5 9h15M4.5 15h15M15.5 4 8.5 20';

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls: string, text?: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (cls !== '') e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

/** A stroked line icon (decorative). */
function icon(viewBox: string, d: string, width: string, cap = 'square'): SVGSVGElement {
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', viewBox);
  svg.setAttribute('aria-hidden', 'true');
  const p = document.createElementNS(SVG, 'path');
  p.setAttribute('d', d);
  p.setAttribute('fill', 'none');
  p.setAttribute('stroke', 'currentColor');
  p.setAttribute('stroke-width', width);
  p.setAttribute('stroke-linecap', cap);
  svg.appendChild(p);
  return svg;
}

function mark(): SVGSVGElement {
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', '13 13 74 74');
  svg.setAttribute('class', 'mark');
  svg.setAttribute('aria-hidden', 'true');
  const ring = document.createElementNS(SVG, 'path');
  ring.setAttribute('class', 'ring');
  ring.setAttribute('fill-rule', 'evenodd');
  ring.setAttribute('d', RING);
  const dia = document.createElementNS(SVG, 'path');
  dia.setAttribute('class', 'dia');
  dia.setAttribute('d', DIAMOND);
  svg.append(ring, dia);
  return svg;
}

/** «Bastion Shield» with the mark; `visible` false keeps the name for screen readers only. */
function brand(visible: boolean): HTMLElement {
  const b = el('span', visible ? 'brand' : '');
  b.translate = false;
  b.append(mark(), el('span', visible ? 'brand-name' : 'sr', 'Bastion Shield'));
  return b;
}

/** The 48px tile (decorative): ClickFix prompt with the stop badge, or ≠ for a lookalike. */
function tile(kind: NoticeKind): HTMLElement {
  const tl = el('div', 'tile');
  tl.setAttribute('aria-hidden', 'true');
  if (kind === 'clip') {
    tl.appendChild(icon('0 0 24 24', PROMPT, '2.2'));
    const badge = el('span', 'badge');
    badge.appendChild(icon('0 0 16 16', 'M3 3l10 10M13 3 3 13', '2.6', 'round'));
    tl.appendChild(badge);
  } else {
    tl.appendChild(icon('0 0 24 24', NOT_EQUAL, '2.2'));
  }
  return tl;
}

function button(cls: string, label: string, onClick: () => void): HTMLButtonElement {
  const b = el('button', cls, label);
  b.type = 'button';
  b.addEventListener('click', (ev) => {
    ev.stopPropagation();
    onClick();
  });
  return b;
}

let ids = 0;
const uid = (p: string): string => `${p}${(++ids).toString(36)}${Math.random().toString(36).slice(2, 6)}`;

/**
 * A disclosure button (chevron + label, 32px) for `region`: toggles
 * `hidden`, aria-expanded and the label; `onToggle` runs after each change.
 */
function disclosure(region: HTMLElement, show: string, hide: string, onToggle?: (open: boolean) => void): HTMLButtonElement {
  region.id ||= uid('r');
  region.hidden = true;
  const b = el('button', 'disc');
  b.type = 'button';
  b.setAttribute('aria-expanded', 'false');
  b.setAttribute('aria-controls', region.id);
  const label = el('span', '', show);
  b.append(icon('0 0 16 16', 'm6.25 3.75 4.25 4.25-4.25 4.25', '1.6'), label);
  b.addEventListener('click', (ev) => {
    ev.stopPropagation();
    const open = b.getAttribute('aria-expanded') !== 'true';
    b.setAttribute('aria-expanded', String(open));
    label.textContent = open ? hide : show;
    region.hidden = !open;
    onToggle?.(open);
  });
  return b;
}

/** Leave the page: back when there is history, else about:blank (also when "back" stays in this document). */
function leavePage(): void {
  try {
    if (history.length > 1) {
      const timer = setTimeout(() => location.replace('about:blank'), 700);
      // Navigated away (or into the bfcache): never fire later.
      addEventListener('pagehide', () => clearTimeout(timer), { once: true });
      history.back();
      return;
    }
  } catch {
    // fall through
  }
  try {
    location.replace('about:blank');
  } catch {
    // sandboxed: nothing we can do
  }
}

/** The command field: chips for invisible characters, fade and character count only while it scrolls. */
function commandBox(text: string): { box: HTMLElement; measure: () => void } {
  const box = el('div', 'cmdbox');
  box.translate = false;
  const field = el('div', 'field');
  const cmd = el('div', 'cmd');
  cmd.setAttribute('role', 'region');
  cmd.setAttribute('aria-label', t('noticeClipCommandLabel'));
  const { parts, hidden } = splitInvisible(text);
  for (const p of parts) {
    if (!p.hidden) {
      cmd.appendChild(document.createTextNode(p.text));
      continue;
    }
    const chip = el('span', 'inv', p.text);
    chip.setAttribute('role', 'img');
    chip.setAttribute('aria-label', t('noticeInvisibleChar', [p.text]));
    cmd.appendChild(chip);
  }
  const fade = el('div', 'fade');
  fade.setAttribute('aria-hidden', 'true');
  field.append(cmd, fade);

  const meta = el('div', hidden > 0 ? 'meta stacked' : 'meta');
  meta.translate = true;
  const count = el('span', 'count', t('noticeChars', [fmt(charCount(text))]));
  const hint = el('span', '', t('noticeCopyHint'));
  let strong: HTMLElement | null = null;
  if (hidden > 0) {
    strong = el('span', 'strong');
    meta.append(strong, hint);
  } else {
    meta.append(hint, count);
  }
  box.append(field, meta);

  const measure = (): void => {
    const s = scrollState(cmd.scrollHeight, cmd.clientHeight, cmd.scrollTop);
    field.classList.toggle('scrolls', s.scrolls);
    field.classList.toggle('at-end', s.atEnd);
    // A scrolling field is keyboard-scrollable; a short one is not a tab stop.
    if (s.scrolls) cmd.tabIndex = 0;
    else cmd.removeAttribute('tabindex');
    if (strong !== null) {
      const h = plural(hidden, 'noticeHiddenOne', 'noticeHiddenMany');
      strong.textContent = s.scrolls ? `${h} - ${count.textContent}` : h;
    } else {
      count.hidden = !s.scrolls;
    }
  };
  cmd.addEventListener('scroll', measure, { passive: true });
  try {
    new ResizeObserver(() => {
      if (!box.hidden) measure();
    }).observe(cmd);
  } catch {
    // no ResizeObserver: measured on open
  }
  return { box, measure };
}

/** «Diese Seite»: the host with differing characters boxed, cut in the middle when long. */
function hostLine(host: string, target: string): { dd: HTMLElement; truncated: boolean } {
  const dd = el('dd', '');
  dd.translate = false;
  dd.title = host;
  const { parts, truncated } = truncateParts(hostDiff(host, target), HOST_MAX);
  for (const p of parts) {
    if (p === 'ellipsis') dd.appendChild(el('span', 'ell', '…'));
    else if (p.diff) dd.appendChild(el('mark', 'diff', p.text));
    else dd.appendChild(document.createTextNode(p.text));
  }
  return { dd, truncated };
}

export interface NoticeApi {
  /** A clipboard write was blocked (any frame; subframes forward to the top frame). */
  clip(text: string, source: NoticeSource): void;
  /** Lookalike warning for this page (top frame). */
  lookalike(hit: LookalikeHit): void;
}

export interface NoticeOptions {
  isTop: boolean;
  /** Subframes: hand a clipboard notice to the top frame (via the service worker). */
  forward(text: string, source: NoticeSource): void;
}

interface Card {
  el: HTMLElement;
  kind: NoticeKind;
}

export function createNotices(opts: NoticeOptions): NoticeApi {
  let host: HTMLElement | null = null;
  let root: ShadowRoot | null = null;
  let stack: HTMLElement | null = null;
  const cards: Card[] = []; // newest first
  const dedupe = new Deduper();
  let lookalikeShown = false;
  let clipShown = 0;
  let expanded = false;
  // ClickFix blocks beyond MAX_CLIP_NOTICES: no card, only the row count goes up.
  let counted = 0;

  // The «N weitere Meldungen» row and the container of the older cards.
  const older = el('div', 'older');
  older.id = uid('o');
  const more = el('div', 'more');
  const minis = el('div', 'minis');
  minis.setAttribute('aria-hidden', 'true');
  const moreTitle = el('p', 'more-title');
  const moreSum = el('p', 'more-sum');
  const moreText = el('div', 'text');
  moreText.append(moreTitle, moreSum);
  const moreBtn = button('btn outline', '', () => {
    expanded = !expanded;
    render();
  });
  moreBtn.setAttribute('aria-controls', older.id);
  // Only shown when the row stands alone (every card closed, blocking went on).
  const closeRow = (): void => {
    counted = 0;
    dropHost();
  };
  const moreClose = el('button', 'close');
  moreClose.type = 'button';
  moreClose.setAttribute('aria-label', t('noticeClose'));
  moreClose.title = t('noticeClose');
  moreClose.appendChild(icon('0 0 16 16', 'M3.5 3.5l9 9M12.5 3.5l-9 9', '1.6', 'round'));
  moreClose.addEventListener('click', (ev) => {
    ev.stopPropagation();
    closeRow();
  });
  more.append(minis, moreText, moreBtn, moreClose);
  more.addEventListener('keydown', (ev) => {
    if (ev.key !== 'Escape') return;
    if (cards.length === 0) closeRow();
    else if (expanded) {
      expanded = false;
      render();
    } else return;
    ev.stopPropagation();
    ev.preventDefault();
  });

  const ensureHost = (): HTMLElement | null => {
    const html = document.documentElement;
    if (html === null) return null;
    if (host === null || stack === null) {
      host = document.createElement('div');
      for (const [k, v] of HOST_STYLE) host.style.setProperty(k, v, 'important');
      root = host.attachShadow({ mode: 'closed' });
      const style = document.createElement('style');
      style.textContent = CSS;
      stack = el('div', 'stack');
      stack.lang = uiLang();
      root.append(style, stack);
    }
    if (!host.isConnected) {
      html.appendChild(host);
      // Top layer: above page dialogs, fullscreen elements and z-index wars.
      try {
        host.setAttribute('popover', 'manual');
        host.showPopover();
      } catch {
        host.removeAttribute('popover');
      }
    }
    return stack;
  };

  /** Places the cards: newest first, then the row, then the older ones (moved only when needed, so focus stays). */
  const render = (): void => {
    if (stack === null) return;
    const view = stackView(
      cards.map((c) => c.kind),
      expanded,
      counted,
    );
    if (!view.expandable) expanded = false;
    const first = cards[0];
    if (first !== undefined && stack.firstChild !== first.el) stack.prepend(first.el);
    if (view.more === 0) {
      more.remove();
      older.remove();
    } else {
      // Without cards (all closed, blocking goes on) the row stands alone and can be closed itself.
      if (first === undefined) {
        if (stack.firstChild !== more) stack.prepend(more);
      } else if (first.el.nextSibling !== more) first.el.after(more);
      moreBtn.hidden = !view.expandable;
      moreClose.hidden = first !== undefined;
      if (more.nextSibling !== older) more.after(older);
      cards.slice(1).forEach((c, i) => {
        if (older.children[i] !== c.el) older.insertBefore(c.el, older.children[i] ?? null);
      });
      moreTitle.textContent = plural(view.more, 'noticeMoreOne', 'noticeMore');
      const sum: string[] = [];
      if (view.clips > 0) sum.push(plural(view.clips, 'noticeMoreCmdOne', 'noticeMoreCmds'));
      if (view.addresses > 0) sum.push(t('noticeMoreAddr'));
      moreSum.textContent = sum.join(' - ');
      minis.replaceChildren();
      if (view.clips > 0) minis.appendChild(el('span', 'mini')).appendChild(icon('0 0 24 24', PROMPT, '2.6'));
      if (view.addresses > 0) minis.appendChild(el('span', 'mini')).appendChild(icon('0 0 24 24', NOT_EQUAL, '2.6'));
      moreBtn.textContent = t(view.visible > 1 ? 'noticeMoreHide' : 'noticeMoreShow');
      moreBtn.setAttribute('aria-expanded', String(view.visible > 1));
      older.hidden = view.visible <= 1;
    }
    stack.classList.toggle('open', view.visible > 1);
  };

  const remove = (card: HTMLElement): void => {
    const i = cards.findIndex((c) => c.el === card);
    const hadFocus = root !== null && root.activeElement !== null && card.contains(root.activeElement);
    if (i !== -1) cards.splice(i, 1);
    card.remove();
    if (cards.length === 0) {
      // Closing the last card dismisses the stack, counted blocks included.
      counted = 0;
      dropHost();
      return;
    }
    render();
    // Keyboard users stay in the notices: focus the card that took its place.
    if (hadFocus) {
      const next = cards[Math.min(i, cards.length - 1)]!.el;
      const target = next.closest('[hidden]') === null ? next : cards[0]!.el;
      target.querySelector<HTMLElement>('.close')?.focus();
    }
  };

  function dropHost(): void {
    more.remove();
    older.remove();
    expanded = false;
    if (host !== null) {
      try {
        if (host.matches(':popover-open')) host.hidePopover();
      } catch {
        // not a popover
      }
      host.remove();
    }
  }

  /** A card with tile, title, optional sentence, close button and Esc handling. */
  const card = (kind: NoticeKind, title: HTMLElement, body?: string): HTMLElement => {
    const c = el('section', `card ${kind === 'clip' ? 'clip' : 'look'} enter`);
    c.addEventListener('animationend', () => c.classList.remove('enter'), { once: true });
    c.setAttribute('role', 'alert');
    title.id = uid('t');
    c.setAttribute('aria-labelledby', title.id);
    const head = el('div', 'head');
    const text = el('div', 'text');
    text.appendChild(title);
    if (body !== undefined) {
      const p = el('p', 'body', body);
      p.id = uid('b');
      c.setAttribute('aria-describedby', p.id);
      text.appendChild(p);
    }
    const close = el('button', 'close');
    close.type = 'button';
    close.setAttribute('aria-label', t('noticeClose'));
    close.title = t('noticeClose');
    close.appendChild(icon('0 0 16 16', 'M3.5 3.5l9 9M12.5 3.5l-9 9', '1.6', 'round'));
    close.addEventListener('click', (ev) => {
      ev.stopPropagation();
      remove(c);
    });
    c.addEventListener('keydown', (ev) => {
      if (ev.key !== 'Escape') return;
      ev.stopPropagation();
      ev.preventDefault();
      remove(c);
    });
    head.append(tile(kind), text, close);
    c.appendChild(head);
    return c;
  };

  const show = (c: HTMLElement, kind: NoticeKind): void => {
    if (ensureHost() === null) return;
    for (let n = overflow(cards.length); n > 0; n--) remove(cards[cards.length - 1]!.el);
    // remove() may have dropped the host: attach again.
    ensureHost();
    cards.unshift({ el: c, kind });
    render();
  };

  const clipTop = (raw: string, _source: NoticeSource): void => {
    const text = raw.length > MAX_NOTICE_TEXT ? raw.slice(0, MAX_NOTICE_TEXT) : raw;
    if (dedupe.seen(clipKey(text), Date.now())) return;
    if (clipSlot(clipShown) === 'count') {
      // Past the cap: no new card, but the row shows that blocking continues.
      counted++;
      if (ensureHost() !== null) render();
      return;
    }
    clipShown++;
    const c = card('clip', el('p', 'title', t('noticeClipTitle')), t('noticeClipBody'));
    // No «copy anyway»: an override button would become part of the lure. The
    // command stays behind the disclosure, selectable for anyone who needs it.
    const { box, measure } = commandBox(text);
    const foot = el('div', 'foot');
    foot.append(disclosure(box, t('noticeShowCommand'), t('noticeHideCommand'), (open) => open && measure()), brand(true));
    c.append(foot, box);
    show(c, 'clip');
  };

  return {
    clip(text: string, source: NoticeSource): void {
      if (typeof text !== 'string' || text.trim() === '') return;
      if (!opts.isTop) {
        opts.forward(text.length > MAX_NOTICE_TEXT ? text.slice(0, MAX_NOTICE_TEXT) : text, source);
        return;
      }
      try {
        clipTop(text, source);
      } catch {
        // the block itself already happened
      }
    },
    lookalike(hit: LookalikeHit): void {
      if (!opts.isTop || lookalikeShown || hit === null || typeof hit !== 'object') return;
      if (typeof hit.host !== 'string' || typeof hit.target !== 'string' || hit.host === '' || hit.target === '') return;
      lookalikeShown = true;
      try {
        // «Das ist nicht $1»: the domain never goes through HTML parsing.
        const title = el('p', 'title');
        const MARK = '\u0001';
        for (const part of t('noticeLookTitle', [MARK]).split(/(\u0001)/)) {
          if (part === MARK) {
            const d = el('span', '', hit.target);
            d.translate = false;
            title.appendChild(d);
          } else if (part !== '') {
            title.appendChild(document.createTextNode(part));
          }
        }
        const c = card('lookalike', title);

        const compare = el('dl', 'compare');
        const real = el('div', 'row');
        const realHost = el('dd', '', hit.target);
        realHost.translate = false;
        real.append(el('dt', '', t('noticeLookReal')), realHost);
        const here = el('div', 'row');
        const { dd, truncated } = hostLine(hit.host, hit.target);
        here.append(el('dt', '', t('noticeLookThis')), dd);
        compare.append(real, here);
        if (truncated) {
          // The whole address stays reachable behind «Ganze Adresse».
          const full = el('div', 'full');
          const all = el('p', 'fullhost', hit.host);
          all.translate = false;
          full.append(disclosure(all, t('noticeFullAddress'), t('noticeFullAddress')), all);
          compare.appendChild(full);
        }

        const actions = el('div', 'actions');
        const spacer = el('span', 'spacer');
        actions.append(
          button('btn primary', t('noticeLookalikeLeave'), leavePage),
          button('btn quiet', t('noticeStay'), () => remove(c)),
          spacer,
          brand(false),
        );
        c.append(compare, actions);
        show(c, 'lookalike');
      } catch {
        // never disturb the page
      }
    },
  };
}
