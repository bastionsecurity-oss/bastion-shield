// Bastion Shield — blocker notices in the page (ISOLATED world, bundled into
// content/cosmetic.js, which runs in every frame where protection is on,
// with nerd mode on or off).
//
// One component for every in-page notice of the blocker:
//   * ClickFix blocked: a blocked clipboard write, from uBlock filters'
//     prevent-clipboard-write (tools/lib/notice-transform.ts) or from the
//     nerd mode clipboard guard (content/nerd-relay.ts);
//   * lookalike domain (nerd mode): «Achtung: möglicherweise Phishing».
//
// Rendering: top frame only. A subframe hands its clipboard notices to the
// service worker (`notice:clip`), which forwards them to frame 0
// (`notice:show`). Cards stack top-right (top 12px, right 12px, width
// min(360px, 100vw - 24px)), newest on top, at most MAX_NOTICES. The host
// element sits in the top layer (popover="manual") with z-index max, so page
// overlays cannot cover it; its inline styles are !important after
// `all: initial` (inline important declarations beat any page stylesheet),
// and everything else lives in a CLOSED shadow root, so page CSS neither
// reaches in nor does ours leak out. Page-derived text (commands, hostnames)
// is only ever set with textContent. Security notices never dismiss
// themselves. Texts come from chrome.i18n (`notice*` keys) with English
// fallbacks for an invalidated extension context.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { LookalikeHit } from '../shared/types.ts';
import { clipKey, Deduper, MAX_CLIP_NOTICES, MAX_NOTICE_TEXT, overflow } from './notice-model.ts';
import type { NoticeSource } from './notice-model.ts';

const FALLBACK: Readonly<Record<string, string>> = {
  noticeClose: 'Close',
  noticeClipTitle: 'Bastion Shield blocked a possible ClickFix attack',
  noticeClipBody: 'This page tried to put a command on your clipboard. Never paste commands from websites into Run, Terminal or PowerShell.',
  noticeClipCommandLabel: 'Blocked command',
  noticeClipManual: 'If you really need this command, select and copy it yourself – after checking what it does.',
  noticeSourceUbo: 'Detected by: uBlock filters',
  noticeSourceBastion: 'Detected by: Bastion ClickFix protection',
  noticeLookalikeTitle: 'Warning: possible phishing',
  noticeLookalikeBody: 'This address looks like $1, but it is not: $2',
  noticeLookalikeReasonHomoglyph: 'The address uses look-alike characters (homoglyphs).',
  noticeLookalikeReasonTypo: 'The address differs by a typing error (typosquatting).',
  noticeLookalikeReasonCombo: 'The address combines the brand name with other words (combosquatting).',
  noticeLookalikeHint: 'Check the address before you sign in or pay.',
  noticeLookalikeLeave: 'Leave site',
  noticeLookalikeProceed: 'Continue anyway',
  noticeSourceLookalike: 'Detected by: Bastion lookalike protection',
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
  ['inset', 'auto'],
  ['top', '12px'],
  ['right', '12px'],
  ['left', 'auto'],
  ['bottom', 'auto'],
  ['width', 'min(360px, calc(100vw - 24px))'],
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

// Gletscher palette (src/ui/shared/tokens.css). Bundesrot appears only in
// the mark's diamond.
const CSS = `
:host { all: initial; }
* { box-sizing: border-box; }
.stack { display: flex; flex-direction: column; gap: 8px; }
.card {
  --bg: #FFFFFF; --ink: #17171A; --ink-strong: #171C1E; --ink-2: #4C575D; --ink-3: #5F6B71;
  --line: #D7DDDF; --code-bg: #F2F4F5; --code-line: #E4E8E9; --hover: rgba(228, 232, 233, 0.7);
  --ring: #2A3134; --diamond: #DA291C;
  --primary: #171C1E; --primary-hover: #2A3134; --on-primary: #FFFFFF; --focus: #2A3134;
  pointer-events: auto;
  position: relative;
  display: grid;
  grid-template-columns: 22px minmax(0, 1fr);
  column-gap: 10px;
  width: 100%;
  margin: 0;
  padding: 14px 14px 12px 14px;
  background: var(--bg);
  color: var(--ink);
  border: 1px solid var(--line);
  border-radius: 16px;
  box-shadow: 0 1px 2px rgba(23, 28, 30, 0.06), 0 10px 28px rgba(23, 28, 30, 0.14);
  font: 400 13px/1.45 "Inter", system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  text-align: left;
  -webkit-font-smoothing: antialiased;
  animation: enter 200ms cubic-bezier(0.2, 0, 0, 1) both;
}
@media (prefers-color-scheme: dark) {
  .card {
    --bg: #171C1E; --ink: #FFFFFF; --ink-strong: #FFFFFF; --ink-2: #A9B6BA; --ink-3: #8D9A9F;
    --line: #2A3134; --code-bg: #1F2629; --code-line: #2A3134; --hover: rgba(255, 255, 255, 0.07);
    --ring: #D7DDDF; --diamond: #E6392E;
    --primary: #FFFFFF; --primary-hover: #D7DDDF; --on-primary: #171C1E; --focus: #D7DDDF;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.3), 0 12px 32px rgba(0, 0, 0, 0.5);
  }
}
@keyframes enter { from { opacity: 0; transform: translateY(-8px); } }
@media (prefers-reduced-motion: reduce) { .card { animation: none; } }
.mark { grid-row: 1 / span 6; width: 22px; height: 22px; margin-top: 0; }
.mark .ring { fill: var(--ring); }
.mark .dia { fill: var(--diamond); }
.main { min-width: 0; }
.title {
  margin: 1px 32px 0 0;
  font-size: 14px; font-weight: 600; line-height: 1.35; letter-spacing: -0.006em;
  color: var(--ink-strong); overflow-wrap: anywhere;
}
.body { margin: 4px 0 0; color: var(--ink-2); overflow-wrap: anywhere; }
.dom { font-weight: 600; color: var(--ink-strong); }
.cmd {
  display: block;
  margin: 10px 0 0;
  padding: 8px 10px;
  max-height: calc(6 * 1.5em + 18px);
  overflow: auto;
  background: var(--code-bg);
  border: 1px solid var(--code-line);
  border-radius: 10px;
  color: var(--ink);
  font: 400 12px/1.5 "IBM Plex Mono", ui-monospace, "Cascadia Mono", "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  white-space: pre-wrap;
  word-break: break-all;
  user-select: text;
  -webkit-user-select: text;
  cursor: text;
  scrollbar-width: thin;
}
.note { margin: 10px 0 0; color: var(--ink-2); font-size: 12.5px; overflow-wrap: anywhere; }
.note.ok { color: var(--ink-strong); font-weight: 500; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0 0; }
button { font: inherit; margin: 0; }
.btn {
  display: inline-flex; align-items: center; justify-content: center;
  min-height: 32px; padding: 0 14px;
  border: 1px solid transparent; border-radius: 999px;
  background: transparent; color: var(--ink-strong);
  font-size: 13px; font-weight: 600; line-height: 1;
  cursor: pointer;
  transition: background-color 120ms cubic-bezier(0.2, 0, 0, 1);
}
.btn:active { transform: scale(0.98); }
.btn.primary { background: var(--primary); color: var(--on-primary); }
.btn.primary:hover { background: var(--primary-hover); }
.btn.text { padding: 0 10px; }
.btn.text:hover { background: var(--hover); }
.src { margin: 10px 0 0; color: var(--ink-3); font-size: 11.5px; line-height: 1.35; }
.close {
  position: absolute; top: 8px; right: 8px;
  display: inline-flex; align-items: center; justify-content: center;
  width: 28px; height: 28px; padding: 0;
  border: 0; border-radius: 999px;
  background: transparent; color: var(--ink-2);
  cursor: pointer;
}
.close:hover { background: var(--hover); color: var(--ink-strong); }
.close svg { width: 14px; height: 14px; }
.btn:focus-visible, .close:focus-visible, .cmd:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
@media (prefers-reduced-motion: reduce) { .btn { transition: none; } .btn:active { transform: none; } }
`;

const SVG = 'http://www.w3.org/2000/svg';
// The Bastion mark (src/icons/mark-on.svg): octagon ring and diamond.
const RING =
  'M 55.00 76.50 L 60.55 76.50 L 76.50 60.55 L 76.50 39.45 L 60.55 23.50 L 39.45 23.50 L 23.50 39.45 L 23.50 60.55 L 39.45 76.50 L 45.00 76.50 L 45.00 83.50 L 36.55 83.50 L 16.50 63.45 L 16.50 36.55 L 36.55 16.50 L 63.45 16.50 L 83.50 36.55 L 83.50 63.45 L 63.45 83.50 L 55.00 83.50 Z';
const DIAMOND = 'M 50 40 L 60 50 L 50 60 L 40 50 Z';

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls: string, text?: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (cls !== '') e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
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

function closeIcon(): SVGSVGElement {
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', '0 0 16 16');
  svg.setAttribute('aria-hidden', 'true');
  const p = document.createElementNS(SVG, 'path');
  p.setAttribute('d', 'M3.5 3.5l9 9M12.5 3.5l-9 9');
  p.setAttribute('stroke', 'currentColor');
  p.setAttribute('stroke-width', '1.6');
  p.setAttribute('stroke-linecap', 'round');
  p.setAttribute('fill', 'none');
  svg.appendChild(p);
  return svg;
}

function button(cls: string, label: string, onClick: () => void): HTMLButtonElement {
  const b = el('button', `btn ${cls}`, label);
  b.type = 'button';
  b.addEventListener('click', (ev) => {
    ev.stopPropagation();
    onClick();
  });
  return b;
}

/** Text with $1/$2 placeholders split so the domains render emphasised (never parsed as HTML). */
function withDomains(key: string, a: string, b: string): HTMLElement {
  const p = el('p', 'body');
  const A = '\u0001';
  const B = '\u0002';
  for (const part of t(key, [A, B]).split(/([\u0001\u0002])/)) {
    if (part === A) p.appendChild(el('span', 'dom', a));
    else if (part === B) p.appendChild(el('span', 'dom', b));
    else if (part !== '') p.appendChild(document.createTextNode(part));
  }
  return p;
}

const REASON_KEY: Readonly<Record<LookalikeHit['reason'], string>> = {
  homoglyph: 'noticeLookalikeReasonHomoglyph',
  typo: 'noticeLookalikeReasonTypo',
  combo: 'noticeLookalikeReasonCombo',
};

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

export function createNotices(opts: NoticeOptions): NoticeApi {
  let host: HTMLElement | null = null;
  let stack: HTMLElement | null = null;
  const cards: HTMLElement[] = []; // newest first
  const dedupe = new Deduper();
  let lookalikeShown = false;
  let clipShown = 0;

  const ensureHost = (): HTMLElement | null => {
    const html = document.documentElement;
    if (html === null) return null;
    if (host === null || stack === null) {
      host = document.createElement('div');
      for (const [k, v] of HOST_STYLE) host.style.setProperty(k, v, 'important');
      const root = host.attachShadow({ mode: 'closed' });
      const style = document.createElement('style');
      style.textContent = CSS;
      stack = el('div', 'stack');
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

  const remove = (card: HTMLElement): void => {
    const i = cards.indexOf(card);
    if (i !== -1) cards.splice(i, 1);
    card.remove();
    if (cards.length === 0 && host !== null) {
      try {
        if (host.matches(':popover-open')) host.hidePopover();
      } catch {
        // not a popover
      }
      host.remove();
    }
  };

  /** A card with the mark, title, close button and Esc handling; the caller fills `main`. */
  const card = (title: string): { card: HTMLElement; main: HTMLElement } => {
    const c = el('section', 'card');
    c.setAttribute('role', 'alert');
    const id = `n${Math.random().toString(36).slice(2)}`;
    c.setAttribute('aria-labelledby', id);
    const main = el('div', 'main');
    const h = el('p', 'title', title);
    h.id = id;
    main.appendChild(h);
    const close = el('button', 'close');
    close.type = 'button';
    close.setAttribute('aria-label', t('noticeClose'));
    close.title = t('noticeClose');
    close.appendChild(closeIcon());
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
    c.append(mark(), main, close);
    return { card: c, main };
  };

  const show = (c: HTMLElement): void => {
    const s = ensureHost();
    if (s === null) return;
    for (let n = overflow(cards.length); n > 0; n--) remove(cards[cards.length - 1]);
    // remove() may have dropped the host: attach again.
    const s2 = ensureHost() ?? s;
    s2.prepend(c);
    cards.unshift(c);
  };

  const clipTop = (raw: string, source: NoticeSource): void => {
    const text = raw.length > MAX_NOTICE_TEXT ? raw.slice(0, MAX_NOTICE_TEXT) : raw;
    if (clipShown >= MAX_CLIP_NOTICES || dedupe.seen(clipKey(text), Date.now())) return;
    clipShown++;
    const { card: c, main } = card(t('noticeClipTitle'));
    main.appendChild(el('p', 'body', t('noticeClipBody')));
    const cmd = el('code', 'cmd', text);
    cmd.tabIndex = 0;
    cmd.setAttribute('aria-label', t('noticeClipCommandLabel'));
    main.appendChild(cmd);
    // No «copy anyway»: an override button would become part of the lure. The
    // command above stays selectable for anyone who really needs it.
    main.appendChild(el('p', 'note', t('noticeClipManual')));
    const src = el('p', 'src', t(source === 'ubo' ? 'noticeSourceUbo' : 'noticeSourceBastion'));
    main.appendChild(src);
    show(c);
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
      if (typeof hit.host !== 'string' || typeof hit.target !== 'string' || !(hit.reason in REASON_KEY)) return;
      lookalikeShown = true;
      try {
        const { card: c, main } = card(t('noticeLookalikeTitle'));
        main.appendChild(withDomains('noticeLookalikeBody', hit.target, hit.host));
        main.appendChild(el('p', 'note', `${t(REASON_KEY[hit.reason])} ${t('noticeLookalikeHint')}`));
        const actions = el('div', 'actions');
        actions.append(
          button('primary', t('noticeLookalikeLeave'), leavePage),
          button('text', t('noticeLookalikeProceed'), () => remove(c)),
        );
        main.append(actions, el('p', 'src', t('noticeSourceLookalike')));
        show(c);
      } catch {
        // never disturb the page
      }
    },
  };
}

