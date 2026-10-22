// Bastion Shield — dependency-free charts for the dashboard: a single-series
// column chart (blocked per day) and a ranked bar list (top hosts / sites /
// categories). Inline SVG, one ink colour, a baseline instead of a grid,
// keyboard and pointer tooltips, and a screen-reader table so no value is
// hover-only. Paper DB01 (tab: y axis, 180px) and DB15 (panel: compact, 90px).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { debounce, h, replace, s } from '../shared/dom.ts';
import { fmtNumber, formatLocale } from '../shared/i18n.ts';

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
export function niceMax(v: number): number {
  if (v <= 0) return 4;
  const exp = Math.floor(Math.log10(v));
  const base = 10 ** exp;
  // Even steps keep the half-way label a round number too.
  for (const m of [1, 1.2, 1.6, 2, 2.4, 3, 4, 5, 6, 8, 10]) if (v <= m * base + 1e-9) return m * base;
  return 10 * base;
}

/** Axis label: 0, 750, 1.5k, 3k, 1.2M (decimal separator of the UI locale, no grouping). */
export function axisLabel(n: number, locale = formatLocale): string {
  const fmt = (v: number): string => {
    try {
      return new Intl.NumberFormat(locale, { maximumFractionDigits: 1, useGrouping: false }).format(v);
    } catch {
      return String(Math.round(v * 10) / 10);
    }
  };
  const abs = Math.abs(n);
  if (abs >= 1e6) return `${fmt(n / 1e6)}M`;
  if (abs >= 1e3) return `${fmt(n / 1e3)}k`;
  return fmt(n);
}

/**
 * Day columns that get an axis label: every 7th day from the first (none
 * closer than 4 days to the end) and the last one («Heute»). Compact: first and last.
 */
export function xLabelIndices(n: number, compact = false): number[] {
  if (n <= 0) return [];
  if (n === 1) return [0];
  if (compact) return [0, n - 1];
  const out: number[] = [];
  for (let i = 0; i < n - 4; i += 7) out.push(i);
  out.push(n - 1);
  return out;
}

/** Highest day (the first one on a tie), or null when every day is 0. */
export function peakOf<T extends { value: number }>(data: readonly T[]): T | null {
  let best: T | null = null;
  for (const d of data) if (d.value > 0 && (!best || d.value > best.value)) best = d;
  return best;
}

/** Column path: rounded top corners (4px), slightly rounded baseline corners (2px). */
function columnPath(x: number, y: number, w: number, hgt: number, rt: number, rb: number): string {
  const t = Math.max(0, Math.min(rt, w / 2, hgt / 2));
  const b = Math.max(0, Math.min(rb, w / 2, hgt / 2));
  return `M${x},${y + hgt - b}V${y + t}Q${x},${y} ${x + t},${y}H${x + w - t}Q${x + w},${y} ${x + w},${y + t}V${y + hgt - b}Q${x + w},${y + hgt} ${x + w - b},${y + hgt}H${x + b}Q${x},${y + hgt} ${x},${y + hgt - b}Z`;
}

export interface ColumnOptions {
  ariaLabel: string;
  valueLabel: string;
  /** Plot height in px (180 in the tab, 90 in the panel). */
  height?: number;
  /** Panel: no y axis, only the first day and «Heute» labelled, 3px gaps. */
  compact?: boolean;
}

export function columnChart(data: ColumnDatum[], opts: ColumnOptions): HTMLElement {
  const compact = opts.compact === true;
  const plotH = opts.height ?? (compact ? 90 : 180);
  const top = 6;
  const height = top + plotH + 28;
  const wrap = h('div', { class: `chart${compact ? ' chart--compact' : ''}` });
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
  svgHost.style.minHeight = `${height}px`;
  wrap.append(svgHost, tip, table);

  let active = -1;
  let layout: { x: (i: number) => number; band: number; plotH: number; max: number } | null = null;
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
    const barTop = top + layout.plotH - (d.value / layout.max) * layout.plotH;
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
    const width = Math.max(200, svgHost.clientWidth || 720);
    // Y labels sit in a 36px column, 12px from the plot (DB01); the panel has none.
    const padL = compact ? 0 : 48;
    const plotW = width - padL;
    const n = Math.max(1, data.length);
    const gap = compact ? 3 : 4;
    const band = plotW / n;
    const barW = Math.max(2, band - gap);
    const max = niceMax(Math.max(0, ...data.map((d) => d.value)));
    const x = (i: number): number => padL + i * band;
    layout = { x, band, plotH, max };

    const svg = s('svg', { width, height, viewBox: `0 0 ${width} ${height}`, class: 'chart__canvas', role: 'img', 'aria-label': opts.ariaLabel, tabindex: 0 });
    if (!compact) {
      for (const f of [0, 0.5, 1]) {
        const y = top + plotH - f * plotH;
        svg.append(s('text', { x: 36, y: f === 1 ? y + 9 : f === 0 ? y : y + 4, 'text-anchor': 'end', class: 'chart__ylabel' }, axisLabel(max * f)));
      }
    }
    svg.append(s('line', { x1: padL, x2: width, y1: top + plotH + 0.5, y2: top + plotH + 0.5, class: 'chart__axis' }));
    bars = data.map((d, i) => {
      const bh = d.value > 0 ? Math.max(2, (d.value / max) * plotH) : 0;
      const p = s('path', { d: columnPath(x(i) + gap / 2, top + plotH - bh, barW, bh, compact ? 3 : 4, compact ? 3 : 2), class: `chart__bar${d.quiet ? ' chart__bar--quiet' : ''}` });
      svg.append(p);
      return p;
    });
    for (const i of xLabelIndices(data.length, compact)) {
      const first = i === 0;
      const last = i === data.length - 1 && !first;
      const lx = first ? x(i) + gap / 2 : last ? width : x(i) + band / 2;
      svg.append(s('text', { x: lx, y: height - 8, 'text-anchor': first ? 'start' : last ? 'end' : 'middle', class: `chart__xlabel${last ? ' chart__xlabel--now' : ''}` }, data[i].axis));
    }
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
  /** Text shown (a host may be cut in the middle). */
  label: string;
  value: number;
  /** Full value for `title` when `label` is shortened. */
  title?: string;
  /** Hosts and sites: mono, translate="no". */
  mono?: boolean;
  /** Quiet tone (unattributed requests). */
  quiet?: boolean;
}

/** Ranked list: label and count, a 3px proportional bar below (DB01). `bars: false` for the panel rows. */
export function barList(rows: BarRow[], ariaLabel: string, bars = true): HTMLElement {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return h(
    'ol',
    { class: `barlist${bars ? '' : ' barlist--plain'}`, attrs: { 'aria-label': ariaLabel } },
    ...rows.map((r) => {
      const fill = h('span', { class: 'barlist__fill' });
      fill.style.width = `${Math.max(1, (r.value / max) * 100)}%`;
      return h(
        'li',
        { class: `barlist__row${r.quiet ? ' barlist__row--quiet' : ''}` },
        h('span', { class: `barlist__label${r.mono ? ' mono' : ''}`, text: r.label, attrs: { title: r.title && r.title !== r.label ? r.title : undefined, translate: r.mono ? 'no' : undefined } }),
        h('span', { class: 'barlist__value num', text: fmtNumber(r.value) }),
        bars ? h('span', { class: 'barlist__track', attrs: { 'aria-hidden': 'true' } }, fill) : null,
      );
    }),
  );
}

/** Usage meter (budget): fill on a track. */
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
