// Bastion Shield — dependency-free charts for the dashboard: a single-series
// column chart (blocked per day) and a ranked bar list (top hosts / sites /
// categories). Inline SVG, hairline grid, one ink colour, keyboard and
// pointer tooltips, and a screen-reader table so no value is hover-only.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { debounce, h, replace, s } from '../shared/dom.ts';
import { fmtCompact, fmtNumber } from '../shared/i18n.ts';

export interface ColumnDatum {
  /** Short axis label, e.g. "18.10." */
  axis: string;
  /** Long label for tooltip and table, e.g. "Sa., 18.10." */
  label: string;
  value: number;
  /** Rendered in the quiet tone (e.g. today, still in progress). */
  quiet?: boolean;
}

/** Round up to a "nice" axis maximum (n × 10^k with an even n where possible). */
function niceMax(v: number): number {
  if (v <= 0) return 4;
  const exp = Math.floor(Math.log10(v));
  const base = 10 ** exp;
  // Even steps keep the half-way gridline a round number too.
  for (const m of [1, 1.2, 1.6, 2, 2.4, 3, 4, 5, 6, 8, 10]) if (v <= m * base) return m * base;
  return 10 * base;
}

/** Column path with 2px rounded top corners (brand radius) and a square baseline. */
function columnPath(x: number, y: number, w: number, hgt: number): string {
  const r = Math.min(2, w / 2, hgt);
  return `M${x},${y + hgt}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + hgt}Z`;
}

export function columnChart(data: ColumnDatum[], opts: { ariaLabel: string; valueLabel: string; height?: number }): HTMLElement {
  const height = opts.height ?? 240;
  const wrap = h('div', { class: 'chart' });
  const tip = h('div', { class: 'chart__tip', attrs: { role: 'status', 'aria-live': 'polite' }, hidden: true });
  // Tables ignore height/overflow, so the visually-hidden wrapper must be a div.
  const table = h(
    'div',
    { class: 'sr-only' },
    h(
      'table',
      null,
      h('caption', { text: opts.ariaLabel }),
      h('thead', null, h('tr', null, h('th', { text: '', attrs: { scope: 'col' } }), h('th', { text: opts.valueLabel, attrs: { scope: 'col' } }))),
      h('tbody', null, ...data.map((d) => h('tr', null, h('th', { text: d.label, attrs: { scope: 'row' } }), h('td', { text: fmtNumber(d.value) })))),
    ),
  );
  const svgHost = h('div', { class: 'chart__svg' });
  wrap.append(svgHost, tip, table);

  let active = -1;
  let layout: { x: (i: number) => number; band: number; top: number; plotH: number; max: number } | null = null;
  let bars: SVGPathElement[] = [];

  const showTip = (i: number): void => {
    if (!layout || i < 0 || i >= data.length) {
      tip.hidden = true;
      return;
    }
    active = i;
    bars.forEach((b, j) => b.classList.toggle('chart__bar--active', j === i));
    const d = data[i];
    replace(tip, h('strong', { class: 'chart__tip-value', text: fmtNumber(d.value) }), h('span', { class: 'chart__tip-label', text: d.label }));
    tip.hidden = false;
    const cx = layout.x(i) + layout.band / 2;
    const barTop = layout.top + layout.plotH - (d.value / layout.max) * layout.plotH;
    const w = wrap.clientWidth;
    tip.style.left = `${Math.max(48, Math.min(w - 48, cx))}px`;
    tip.style.top = `${Math.max(0, barTop - 8)}px`;
  };
  const hideTip = (): void => {
    active = -1;
    tip.hidden = true;
    bars.forEach((b) => b.classList.remove('chart__bar--active'));
  };

  const draw = (): void => {
    const width = Math.max(280, svgHost.clientWidth || 720);
    const padL = 44;
    const padR = 6;
    const top = 12;
    const bottom = 26;
    const plotW = width - padL - padR;
    const plotH = height - top - bottom;
    const n = Math.max(1, data.length);
    const band = plotW / n;
    const barW = Math.max(2, Math.min(24, band - 2));
    const max = niceMax(Math.max(0, ...data.map((d) => d.value)));
    const x = (i: number): number => padL + i * band;
    layout = { x, band, top, plotH, max };

    const svg = s('svg', { width, height, viewBox: `0 0 ${width} ${height}`, class: 'chart__canvas', role: 'img', 'aria-label': opts.ariaLabel, tabindex: 0 });
    // Hairline grid + y labels at 0, 1/2, max.
    for (const f of [0, 0.5, 1]) {
      const y = top + plotH - f * plotH;
      svg.append(s('line', { x1: padL, x2: width - padR, y1: y + 0.5, y2: y + 0.5, class: f === 0 ? 'chart__axis' : 'chart__grid' }));
      svg.append(s('text', { x: padL - 8, y: y + 3.5, 'text-anchor': 'end', class: 'chart__ylabel' }, fmtCompact(max * f)));
    }
    bars = data.map((d, i) => {
      const bh = d.value > 0 ? Math.max(1, (d.value / max) * plotH) : 0;
      const bx = x(i) + (band - barW) / 2;
      const p = s('path', { d: columnPath(bx, top + plotH - bh, barW, bh), class: `chart__bar${d.quiet ? ' chart__bar--quiet' : ''}` });
      svg.append(p);
      return p;
    });
    // X labels: every 7th day counting back from the last, so "today" is always labelled.
    data.forEach((d, i) => {
      if ((data.length - 1 - i) % 7 !== 0) return;
      svg.append(s('text', { x: x(i) + band / 2, y: height - 8, 'text-anchor': 'middle', class: 'chart__xlabel' }, d.axis));
    });
    // Hit targets span the full band height: easier than aiming at a thin bar.
    data.forEach((_d, i) => {
      const hit = s('rect', { x: x(i), y: top, width: band, height: plotH, class: 'chart__hit' });
      hit.addEventListener('pointerenter', () => showTip(i));
      svg.append(hit);
    });
    svg.addEventListener('pointerleave', hideTip);
    svg.addEventListener('blur', hideTip);
    svg.addEventListener('focus', () => showTip(active >= 0 ? active : data.length - 1));
    svg.addEventListener('keydown', (ev) => {
      if (ev.key !== 'ArrowLeft' && ev.key !== 'ArrowRight' && ev.key !== 'Home' && ev.key !== 'End') return;
      ev.preventDefault();
      const cur = active >= 0 ? active : data.length - 1;
      const next = ev.key === 'Home' ? 0 : ev.key === 'End' ? data.length - 1 : Math.max(0, Math.min(data.length - 1, cur + (ev.key === 'ArrowLeft' ? -1 : 1)));
      showTip(next);
    });
    replace(svgHost, svg);
  };

  // Draw after insertion (needs layout width) and on resize.
  requestAnimationFrame(draw);
  if (typeof ResizeObserver !== 'undefined') {
    let lastW = 0;
    const redraw = debounce(() => {
      const w = svgHost.clientWidth;
      if (Math.abs(w - lastW) > 1) {
        lastW = w;
        draw();
      }
    }, 80);
    const ro = new ResizeObserver(() => {
      // Removing the view fires one last observation; stop observing then.
      if (!svgHost.isConnected) {
        ro.disconnect();
        return;
      }
      redraw();
    });
    ro.observe(svgHost);
  }
  return wrap;
}

export interface BarRow {
  label: string;
  value: number;
  mono?: boolean;
  title?: string;
}

/** Ranked list with a proportional hairline bar under each label. */
export function barList(rows: BarRow[], ariaLabel: string): HTMLElement {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return h(
    'ol',
    { class: 'barlist', attrs: { 'aria-label': ariaLabel } },
    ...rows.map((r) => {
      const fill = h('span', { class: 'barlist__fill' });
      fill.style.width = `${Math.max(1, (r.value / max) * 100)}%`;
      return h(
        'li',
        { class: 'barlist__row' },
        h('span', { class: `barlist__label${r.mono ? ' mono' : ''}`, text: r.label, attrs: { title: r.title ?? r.label } }),
        h('span', { class: 'barlist__value num', text: fmtNumber(r.value) }),
        h('span', { class: 'barlist__track', attrs: { 'aria-hidden': 'true' } }, fill),
      );
    }),
  );
}

/** Usage meter (budget): fill, track and a marker at the guaranteed limit. */
export function meter(opts: { value: number; max: number; label: string; valueText: string }): HTMLElement {
  const pct = opts.max > 0 ? Math.min(100, (opts.value / opts.max) * 100) : 0;
  const fill = h('span', { class: 'meter__fill' });
  fill.style.width = `${pct}%`;
  return h(
    'div',
    {
      class: `meter${pct >= 90 ? ' meter--high' : ''}`,
      attrs: { role: 'meter', 'aria-label': opts.label, 'aria-valuemin': 0, 'aria-valuemax': opts.max, 'aria-valuenow': Math.round(opts.value), 'aria-valuetext': opts.valueText },
    },
    fill,
  );
}
