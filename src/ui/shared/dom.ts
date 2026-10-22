// Bastion Shield — tiny DOM helpers for the vanilla-TS UI. No framework: the
// popup must start in a few milliseconds, so we build nodes directly and never
// interpolate untrusted strings into HTML (hostnames and URLs come from the
// web and are always inserted as text).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

export type Child = Node | string | number | null | undefined | false;
type Listener = (ev: Event) => void;

export interface Props {
  class?: string;
  text?: string;
  /** Event listeners, e.g. { click: fn }. */
  on?: Record<string, Listener>;
  /** Attributes; null/undefined/false skip, true sets an empty attribute. */
  attrs?: Record<string, string | number | boolean | null | undefined>;
  dataset?: Record<string, string>;
  hidden?: boolean;
}

/** Create an element with props and children. */
export function h<K extends keyof HTMLElementTagNameMap>(tag: K, props?: Props | null, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (props) applyProps(el, props);
  append(el, children);
  return el;
}

function applyProps(el: Element, props: Props): void {
  if (props.class) el.setAttribute('class', props.class);
  if (props.text !== undefined) el.textContent = props.text;
  if (props.hidden) (el as HTMLElement).hidden = true;
  if (props.attrs) {
    for (const [k, v] of Object.entries(props.attrs)) {
      if (v === null || v === undefined || v === false) continue;
      el.setAttribute(k, v === true ? '' : String(v));
    }
  }
  if (props.dataset) for (const [k, v] of Object.entries(props.dataset)) (el as HTMLElement).dataset[k] = v;
  if (props.on) for (const [k, fn] of Object.entries(props.on)) el.addEventListener(k, fn);
}

export function append(el: Node, children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
  }
}

const SVG_NS = 'http://www.w3.org/2000/svg';

/** Create an SVG element (for charts). */
export function s<K extends keyof SVGElementTagNameMap>(tag: K, attrs?: Record<string, string | number>, ...children: Child[]): SVGElementTagNameMap[K] {
  const el = document.createElementNS(SVG_NS, tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  append(el, children);
  return el;
}

/** Remove all children. */
export function clear(el: Element): void {
  while (el.firstChild) el.removeChild(el.firstChild);
}

/** Replace all children. */
export function replace(el: Element, ...children: Child[]): void {
  clear(el);
  append(el, children);
}

/** querySelector that throws a readable error during development if missing. */
export function $<T extends Element = HTMLElement>(sel: string, root: ParentNode = document): T {
  const el = root.querySelector<T>(sel);
  if (!el) throw new Error(`Missing element: ${sel}`);
  return el;
}

export function $opt<T extends Element = HTMLElement>(sel: string, root: ParentNode = document): T | null {
  return root.querySelector<T>(sel);
}

export function $$<T extends Element = HTMLElement>(sel: string, root: ParentNode = document): T[] {
  return Array.from(root.querySelectorAll<T>(sel));
}

/** Respect the user's motion preference for script-driven animation. */
export function reducedMotion(): boolean {
  try {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  } catch {
    return false;
  }
}

/** Debounce a function (trailing). */
export function debounce<A extends unknown[]>(fn: (...args: A) => void, ms: number): (...args: A) => void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return (...args: A) => {
    if (timer !== undefined) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = undefined;
      fn(...args);
    }, ms);
  };
}

export interface ToastOptions {
  /** One action button («Rückgängig», «Erneut versuchen»). The toast closes after it runs. */
  action?: { label: string; run: () => unknown };
  /** Stays until closed (errors with a retry); gets a close button and is never pushed out. */
  sticky?: boolean;
  /** Accessible name of the close button of a sticky toast. */
  closeLabel?: string;
}

export interface ToastHandle {
  el: HTMLElement;
  close(): void;
}

/** Visible toasts at once (T01): a fourth pushes the oldest non-sticky one out. */
export const MAX_TOASTS = 3;
/** Display time: plain message, message with an action. */
export const TOAST_MS = 3000;
export const TOAST_ACTION_MS = 6000;

let toastRegion: HTMLElement | null = null;

/** Older toasts in the stack fade back a little (T01). */
function markOld(region: HTMLElement): void {
  const live = (Array.from(region.children) as HTMLElement[]).filter((c) => !c.classList.contains('toast--leaving'));
  live.forEach((c, i) => c.classList.toggle('toast--old', i < live.length - 1));
}
const CLOSE_SVG = '<svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true" focusable="false"><path d="M3.5 3.5l9 9M12.5 3.5l-9 9" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';

/**
 * Brief, polite status message at the bottom centre (also announced to screen
 * readers). With `action` it stays 6 s instead of 3 s; `sticky` toasts stay
 * until closed. The timer pauses while the toast is hovered or focused.
 */
export function toast(message: string, icon?: Node, opts: ToastOptions = {}): ToastHandle {
  if (!toastRegion?.isConnected) {
    toastRegion = h('div', { class: 'toasts', attrs: { role: 'status', 'aria-live': 'polite' } });
    document.body.appendChild(toastRegion);
  }
  const region = toastRegion;
  const el = h('div', { class: `toast${opts.action || opts.sticky ? ' toast--actions' : ''}`, dataset: { sticky: String(!!opts.sticky) } });
  const msg = h('span', { class: 'toast__msg', text: message, attrs: { title: message } });
  append(el, [icon ?? null, msg]);

  let timer: ReturnType<typeof setTimeout> | undefined;
  let remaining = opts.sticky ? Infinity : opts.action ? TOAST_ACTION_MS : TOAST_MS;
  let started = 0;
  let closed = false;
  const close = (): void => {
    if (closed) return;
    closed = true;
    if (timer !== undefined) clearTimeout(timer);
    const hadFocus = el.contains(document.activeElement);
    el.classList.remove('toast--show');
    el.classList.add('toast--leaving');
    const done = (): void => {
      el.remove();
      if (region.childElementCount === 0) region.remove();
      else markOld(region);
    };
    if (reducedMotion()) done();
    else setTimeout(done, 220);
    if (hadFocus) (document.querySelector<HTMLElement>('main, [role="main"]') ?? document.body).focus?.();
  };
  const pause = (): void => {
    if (timer === undefined) return;
    clearTimeout(timer);
    timer = undefined;
    remaining -= Date.now() - started;
  };
  const resume = (): void => {
    if (closed || timer !== undefined || remaining === Infinity || el.matches(':hover') || el.contains(document.activeElement)) return;
    started = Date.now();
    timer = setTimeout(close, Math.max(remaining, 1000));
  };

  if (opts.action) {
    const a = opts.action;
    const btn = h('button', { class: 'toast__action', text: a.label, attrs: { type: 'button' } });
    btn.addEventListener('click', () => {
      close();
      void a.run();
    });
    el.appendChild(btn);
  }
  if (opts.sticky) {
    const x = h('button', { class: 'toast__close', attrs: { type: 'button', 'aria-label': opts.closeLabel ?? 'Close', title: opts.closeLabel ?? 'Close' } });
    x.innerHTML = CLOSE_SVG;
    x.addEventListener('click', close);
    el.appendChild(x);
  }
  el.addEventListener('pointerenter', pause);
  el.addEventListener('pointerleave', resume);
  el.addEventListener('focusin', pause);
  el.addEventListener('focusout', () => setTimeout(resume, 0));
  el.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') {
      ev.stopPropagation();
      close();
    }
  });

  // At most MAX_TOASTS: push out the oldest one that is not sticky.
  const open = (): HTMLElement[] => (Array.from(region.children) as HTMLElement[]).filter((c) => !c.classList.contains('toast--leaving'));
  while (open().length >= MAX_TOASTS) {
    const victim = open().find((c) => c.dataset.sticky !== 'true') ?? open()[0];
    victim.dispatchEvent(new Event('toast:close'));
  }
  el.addEventListener('toast:close', close);
  region.appendChild(el);
  markOld(region);
  // Force a frame between insertion and the visible state so it can transition in.
  requestAnimationFrame(() => el.classList.add('toast--show'));
  resume();
  return { el, close };
}

/** Save a text blob as a file through a temporary object URL (nothing leaves the device). */
export function downloadText(filename: string, text: string, mime: string): void {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = h('a', { attrs: { href: url, download: filename } });
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** Ask the user for a file and read it as text. Resolves null when cancelled or unreadable. */
export function pickTextFile(accept: string): Promise<string | null> {
  return new Promise((resolve) => {
    const input = h('input', { attrs: { type: 'file', accept } });
    input.style.display = 'none';
    let settled = false;
    const done = (v: string | null): void => {
      if (settled) return;
      settled = true;
      input.remove();
      resolve(v);
    };
    input.addEventListener('change', () => {
      const file = input.files?.[0];
      if (!file) return done(null);
      // Settings files are tiny; refuse anything absurd instead of freezing the page.
      if (file.size > 20 * 1024 * 1024) return done(null);
      file.text().then(done, () => done(null));
    });
    input.addEventListener('cancel', () => done(null));
    document.body.appendChild(input);
    input.click();
  });
}

/**
 * Ask the user for a text file and read it, keeping its name. Resolves null
 * when cancelled or unreadable, `{ tooLarge: true }` above `maxBytes`.
 */
export function pickNamedTextFile(accept: string, maxBytes: number): Promise<{ name: string; text: string } | { tooLarge: true } | null> {
  return new Promise((resolve) => {
    const input = h('input', { attrs: { type: 'file', accept } });
    input.style.display = 'none';
    let settled = false;
    const done = (v: { name: string; text: string } | { tooLarge: true } | null): void => {
      if (settled) return;
      settled = true;
      input.remove();
      resolve(v);
    };
    input.addEventListener('change', () => {
      const file = input.files?.[0];
      if (!file) return done(null);
      if (file.size > maxBytes) return done({ tooLarge: true });
      file.text().then(
        (text) => done({ name: file.name, text }),
        () => done(null),
      );
    });
    input.addEventListener('cancel', () => done(null));
    document.body.appendChild(input);
    input.click();
  });
}
