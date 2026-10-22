// Bastion Shield — inline line icons and the brand mark. Static markup only
// (never interpolated with data), parsed once per use through a <template>.
// Icons follow the Bastion line style: 1.5px strokes, square ends, currentColor.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const P = 'fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="square" stroke-linejoin="miter"';

const ICONS = {
  tick: `<svg viewBox="0 0 12 12"><path d="M6 0V4.5M6 7.5V12M0 6H4.5M7.5 6H12" fill="none" stroke="currentColor"/></svg>`,
  lock: `<svg viewBox="0 0 16 16"><path ${P} d="M3.75 7.25h8.5v6.5h-8.5zM5.5 7.25V5a2.5 2.5 0 0 1 5 0v2.25"/></svg>`,
  external: `<svg viewBox="0 0 16 16"><path ${P} d="M9.5 2.75h3.75V6.5M13 3 7.75 8.25M11.25 9.5v3.75h-8.5v-8.5H6.5"/></svg>`,
  chevronRight: `<svg viewBox="0 0 16 16"><path ${P} d="m6.25 3.75 4.25 4.25-4.25 4.25"/></svg>`,
  chevronDown: `<svg viewBox="0 0 16 16"><path ${P} d="m3.75 6.25 4.25 4.25 4.25-4.25"/></svg>`,
  check: `<svg viewBox="0 0 16 16"><path ${P} d="m3.25 8.25 3 3 6.5-6.5"/></svg>`,
  info: `<svg viewBox="0 0 16 16"><circle ${P} cx="8" cy="8" r="6.25"/><path ${P} d="M8 7.25v4M8 4.75v.5"/></svg>`,
  alert: `<svg viewBox="0 0 16 16"><circle ${P} cx="8" cy="8" r="6.25"/><path ${P} d="M8 4.5v4.25M8 10.75v.5"/></svg>`,
  reload: `<svg viewBox="0 0 16 16"><path ${P} d="M12.9 6.25A5.25 5.25 0 1 0 13.25 8M13.25 2.75v3.5h-3.5"/></svg>`,
  overview: `<svg viewBox="0 0 16 16"><path ${P} d="M2.75 2.75h4v4h-4zM9.25 2.75h4v4h-4zM2.75 9.25h4v4h-4zM9.25 9.25h4v4h-4z"/></svg>`,
  activity: `<svg viewBox="0 0 16 16"><path ${P} d="M1.5 8h3l1.75-4.25 3.5 8.5L11.5 6.5l.75 1.5h2.25"/></svg>`,
  lists: `<svg viewBox="0 0 16 16"><path ${P} d="M6 4h7.25M6 8h7.25M6 12h7.25M2.75 4h.5M2.75 8h.5M2.75 12h.5"/></svg>`,
  filters: `<svg viewBox="0 0 16 16"><path ${P} d="M5.5 3.25 2.25 8l3.25 4.75M10.5 3.25 13.75 8l-3.25 4.75"/></svg>`,
  sites: `<svg viewBox="0 0 16 16"><circle ${P} cx="8" cy="8" r="6.25"/><path ${P} d="M1.75 8h12.5M8 1.75c-3.5 3.5-3.5 9 0 12.5M8 1.75c3.5 3.5 3.5 9 0 12.5"/></svg>`,
  privacy: `<svg viewBox="0 0 16 16"><path ${P} d="M8 2.25 13.25 4.25v3.5c0 3.25-2.25 5.25-5.25 6-3-.75-5.25-2.75-5.25-6v-3.5z"/><path ${P} d="M8 6.5v3"/></svg>`,
  settings: `<svg viewBox="0 0 16 16"><path ${P} d="M2.25 4.5h5.25M11 4.5h2.75M8.25 2.75h2v3.5h-2zM2.25 11.5h3M8.5 11.5h5.25M5.75 9.75h2v3.5h-2z"/></svg>`,
  about: `<svg viewBox="0 0 16 16"><path ${P} d="M2.75 2.75h10.5v10.5H2.75z"/><path ${P} d="M8 7.25v3.5M8 5v.5"/></svg>`,
  lab: `<svg viewBox="0 0 16 16"><path ${P} d="M6 2.25h4M6.75 2.25v4.25l-3.5 6.75h9.5l-3.5-6.75V2.25M4.75 10.5h6.5"/></svg>`,
  close: `<svg viewBox="0 0 16 16"><path ${P} d="m3.75 3.75 8.5 8.5M12.25 3.75l-8.5 8.5"/></svg>`,
  download: `<svg viewBox="0 0 16 16"><path ${P} d="M8 2.25v8M4.75 7 8 10.25 11.25 7M2.75 13.25h10.5"/></svg>`,
  upload: `<svg viewBox="0 0 16 16"><path ${P} d="M8 10.25v-8M4.75 5.5 8 2.25l3.25 3.25M2.75 13.25h10.5"/></svg>`,
  pause: `<svg viewBox="0 0 16 16"><path ${P} d="M5.25 3.25v9.5M10.75 3.25v9.5"/></svg>`,
  play: `<svg viewBox="0 0 16 16"><path ${P} d="M4.75 3v10l8-5z"/></svg>`,
  trash: `<svg viewBox="0 0 16 16"><path ${P} d="M2.75 4.25h10.5M6.25 4.25V2.75h3.5v1.5M4 4.25l.75 9h6.5l.75-9"/></svg>`,
  plus: `<svg viewBox="0 0 16 16"><path ${P} d="M8 3v10M3 8h10"/></svg>`,
  search: `<svg viewBox="0 0 16 16"><circle ${P} cx="7" cy="7" r="4.25"/><path ${P} d="m10.25 10.25 3.5 3.5"/></svg>`,
  flag: `<svg viewBox="0 0 16 16"><path ${P} d="M3.25 14V2.5M3.25 3h8.5l-1.75 3 1.75 3h-8.5"/></svg>`,
  arrowLeft: `<svg viewBox="0 0 16 16"><path ${P} d="M13 8H3.5M7.25 4 3.25 8l4 4"/></svg>`,
  arrowRight: `<svg viewBox="0 0 16 16"><path ${P} d="M3 8h9.5M8.75 4l4 4-4 4"/></svg>`,
  dashboard: `<svg viewBox="0 0 16 16"><path ${P} d="M2.75 2.75h10.5v10.5H2.75zM6.25 2.75v10.5"/></svg>`,
  // Browser chrome glyphs (Fluent UI System Icons, MIT), as Edge draws them, so the
  // «pin the extension» hint matches the toolbar the user is looking at.
  pin: `<svg viewBox="0 0 20 20"><path fill="currentColor" d="M10.1221 3.13715C10.7326 1.91616 12.3599 1.65208 13.3251 2.61737L17.382 6.67419C18.3472 7.63947 18.0832 9.26676 16.8622 9.87726L13.4037 11.6065C13.0751 11.7708 12.8183 12.0499 12.6818 12.391L11.2459 15.981C10.9792 16.6476 10.1179 16.8244 9.61027 16.3167L7 13.7064L3.70711 16.9993H3V16.2922L6.29289 12.9993L3.68262 10.3891C3.17498 9.88142 3.35177 9.02011 4.01834 8.75348L7.60829 7.3175C7.94939 7.18106 8.22855 6.92419 8.39285 6.5956L10.1221 3.13715ZM12.618 3.32447C12.1354 2.84183 11.3217 2.97387 11.0165 3.58437L9.28727 7.04282C9.01345 7.59046 8.54818 8.01858 7.97968 8.24598L4.38973 9.68196L10.3174 15.6096L11.7534 12.0197C11.9808 11.4512 12.4089 10.9859 12.9565 10.7121L16.415 8.98283C17.0255 8.67758 17.1575 7.86394 16.6749 7.3813L12.618 3.32447Z"/></svg>`,
  puzzle: `<svg viewBox="0 0 20 20"><path fill="currentColor" d="M11 3C10.3096 3 9.75 3.55964 9.75 4.25V5H6.5C6.22386 5 6 5.22386 6 5.5V8.75H5.25C4.55964 8.75 4 9.30964 4 10C4 10.6904 4.55964 11.25 5.25 11.25H6V14.5C6 14.7761 6.22386 15 6.5 15H9.75V15.75C9.75 16.4404 10.3096 17 11 17C11.6904 17 12.25 16.4404 12.25 15.75V15H15.5C15.7761 15 16 14.7761 16 14.5V12.25H15.25C14.0074 12.25 13 11.2426 13 10C13 8.75736 14.0074 7.75 15.25 7.75H16V5.5C16 5.22386 15.7761 5 15.5 5H12.25V4.25C12.25 3.55964 11.6904 3 11 3ZM8.76373 4C8.88809 2.87501 9.84186 2 11 2C12.1581 2 13.1119 2.87501 13.2363 4H15.5C16.3284 4 17 4.67157 17 5.5V8.75H15.25C14.5596 8.75 14 9.30964 14 10C14 10.6904 14.5596 11.25 15.25 11.25H17V14.5C17 15.3284 16.3284 16 15.5 16H13.2363C13.1119 17.125 12.1581 18 11 18C9.84186 18 8.88809 17.125 8.76373 16H6.5C5.67157 16 5 15.3284 5 14.5V12.2363C3.87501 12.1119 3 11.1581 3 10C3 8.84186 3.87501 7.88809 5 7.76373V5.5C5 4.67157 5.67157 4 6.5 4H8.76373Z"/></svg>`,
  device: `<svg viewBox="0 0 16 16"><path ${P} d="M2.25 3.25h11.5v7.5H2.25zM5.5 13.25h5M8 10.75v2.5"/></svg>`,
  eye: `<svg viewBox="0 0 16 16"><path ${P} d="M1.5 8S4 3.5 8 3.5 14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8z"/><circle ${P} cx="8" cy="8" r="2"/></svg>`,
  incident: `<svg viewBox="0 0 16 16"><path ${P} d="M8 1.75 13.25 3.75v3.75c0 3.25-2.25 5.5-5.25 6.75-3-1.25-5.25-3.5-5.25-6.75V3.75z"/><path ${P} d="M8 5v3.25M8 10.25v.5"/></svg>`,
  rail: `<svg viewBox="0 0 16 16"><path ${P} d="M2.75 2.75h10.5v10.5H2.75zM6.25 2.75v10.5M10.75 6.25 9 8l1.75 1.75"/></svg>`,
  collapse: `<svg viewBox="0 0 16 16"><path ${P} d="M2.75 9.25h4v4M13.25 6.75h-4v-4M9.25 6.75l4.5-4.5M2.25 13.75l4.5-4.5"/></svg>`,
  expand: `<svg viewBox="0 0 16 16"><path ${P} d="M9.5 2.25h4.25V6.5M6.5 13.75H2.25V9.5M13.75 2.25 9 7M2.25 13.75 7 9"/></svg>`,
  openTab: `<svg viewBox="0 0 16 16"><path ${P} d="M5.5 10.5 11.25 4.75M6.5 4.75h4.75V9.5"/></svg>`,
  shieldOn: `<svg viewBox="0 0 16 16"><path ${P} d="M8 1.75 13.25 3.75v3.75c0 3.25-2.25 5.5-5.25 6.75-3-1.25-5.25-3.5-5.25-6.75V3.75z"/><path ${P} d="m5.5 7.75 1.75 1.75 3.25-3.25"/></svg>`,
} as const;

export type IconName = keyof typeof ICONS;

const tpl = typeof document !== 'undefined' ? document.createElement('template') : null;

/** A decorative icon (aria-hidden). Size defaults to 16px; CSS can override. */
export function icon(name: IconName, size = 16, className = ''): SVGSVGElement {
  tpl!.innerHTML = ICONS[name];
  const svg = tpl!.content.firstElementChild as SVGSVGElement;
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  svg.setAttribute('class', `icon icon--${name}${className ? ` ${className}` : ''}`);
  return svg;
}

const MARK = `<svg viewBox="13 13 74 74"><path class="mark__ring" fill-rule="evenodd" d="M 55.00 76.50 L 60.55 76.50 L 76.50 60.55 L 76.50 39.45 L 60.55 23.50 L 39.45 23.50 L 23.50 39.45 L 23.50 60.55 L 39.45 76.50 L 45.00 76.50 L 45.00 83.50 L 36.55 83.50 L 16.50 63.45 L 16.50 36.55 L 36.55 16.50 L 63.45 16.50 L 83.50 36.55 L 83.50 63.45 L 63.45 83.50 L 55.00 83.50 Z"/><path class="mark__diamond" d="M 50 40 L 60 50 L 50 60 L 40 50 Z"/></svg>`;

/**
 * The Bastion shield-and-diamond mark. Colours come from CSS (--mark-stroke,
 * --mark-diamond); the diamond is the only place Bundesrot may appear in this UI.
 */
export function mark(size = 24, off = false): SVGSVGElement {
  tpl!.innerHTML = MARK;
  const svg = tpl!.content.firstElementChild as SVGSVGElement;
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  svg.setAttribute('class', `mark${off ? ' mark--off' : ''}`);
  return svg;
}

/** Fill every [data-icon] placeholder in static markup with its icon. */
export function hydrateIcons(root: ParentNode = document): void {
  for (const el of Array.from(root.querySelectorAll<HTMLElement>('[data-icon]'))) {
    const name = el.dataset.icon as IconName;
    if (!(name in ICONS)) continue;
    const size = Number(el.dataset.iconSize) || 16;
    el.replaceWith(icon(name, size, el.className));
  }
  for (const el of Array.from(root.querySelectorAll<HTMLElement>('[data-mark]'))) {
    const size = Number(el.dataset.markSize) || 24;
    const m = mark(size, el.dataset.mark === 'off');
    if (el.className) m.classList.add(...el.className.split(/\s+/).filter(Boolean));
    if (el.id) m.id = el.id;
    el.replaceWith(m);
  }
}
