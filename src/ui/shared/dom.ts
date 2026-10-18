// Bastion Shield — tiny DOM helpers for the vanilla-TS UI. No framework: the
// popup must start in a few milliseconds, so we build nodes directly and never
// interpolate untrusted strings into HTML (hostnames and URLs come from the
// web and are always inserted as text).
//
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

let toastEl: HTMLElement | null = null;
let toastTimer: ReturnType<typeof setTimeout> | undefined;

/** Brief, polite status message (also announced to screen readers). */
export function toast(message: string, icon?: Node): void {
  if (!toastEl) {
    toastEl = h('div', { class: 'toast', attrs: { role: 'status', 'aria-live': 'polite' } });
    document.body.appendChild(toastEl);
  }
  replace(toastEl, icon ?? null, h('span', { text: message }));
  // Force a frame between insertion and the visible state so it can transition in.
  requestAnimationFrame(() => toastEl?.classList.add('toast--show'));
  if (toastTimer !== undefined) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastEl?.classList.remove('toast--show'), 2600);
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
