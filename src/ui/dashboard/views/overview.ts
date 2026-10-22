// Bastion Shield — dashboard «Übersicht» (Paper DB01–DB04, panel DB15):
// blocked requests, data and waiting time saved (estimate) over 30 days,
// blocked requests per day with its peak, top hosts, top sites and the split
// by list category (4 rows, «Alle N anzeigen» shows up to 8). States: no data
// yet, history off (with «Verlauf einschalten»), error banner with «Erneut
// versuchen», «Schutz pausiert» while the organisation switched protection off.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { DailyAggregate, EffectiveConfig, HistoryResult } from '../../../shared/types.ts';
import { h, replace, s } from '../../shared/dom.ts';
import { fmtNumber, formatLocale, t } from '../../shared/i18n.ts';
import { estimateSavings, fmtBytes, fmtDuration, savedRequestsByType, savingsUnits } from '../../shared/savings.ts';
import { icon } from '../../shared/icons.ts';
import { call } from '../../shared/messaging.ts';
import { brandText } from '../../shared/controls.ts';
import { truncateMiddle, withUnit } from '../../shared/text.ts';
import { CATEGORY_ORDER, categoryLabel } from '../../shared/labels.ts';
import { barList, columnChart, peakOf, type BarRow, type ColumnDatum } from '../chart.ts';
import { card, dayKey, dayTime, emptyState, errorState, lockedNote, mount, pausedBanner, popupMode, retryView, withBusy, type View } from '../common.ts';
import { getConfig, isLocked, saveSettings } from '../store.ts';

const DAYS = 30;
/** Rows a top list shows at first; «Alle N anzeigen» reveals up to TOP_MAX. */
export const TOP_FIRST = 4;
export const TOP_MAX = 8;
/** Hosts longer than this are cut in the middle (start and registrable domain stay). */
const HOST_MAX = popupMode ? 40 : 22;

/** «23.9.» on the axis and «Mo., 13.10.» for the peak and tooltips (numeric day and month, DB01). */
function dayFmt(ms: number, weekday: boolean): string {
  const opts: Intl.DateTimeFormatOptions = weekday ? { weekday: 'short', day: 'numeric', month: 'numeric' } : { day: 'numeric', month: 'numeric' };
  try {
    return new Intl.DateTimeFormat(formatLocale, opts).format(ms);
  } catch {
    return new Date(ms).toLocaleDateString(undefined, opts);
  }
}

function sumInto(target: Record<string, number>, src: Record<string, number> | undefined): void {
  if (!src) return;
  for (const [k, v] of Object.entries(src)) if (typeof v === 'number' && Number.isFinite(v)) target[k] = (target[k] ?? 0) + v;
}

/** The `n` largest entries, largest first (ties keep their order). */
export function topEntries(rec: Record<string, number>, n: number): [string, number][] {
  return Object.entries(rec)
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n);
}

/** Category rows: by count, unattributed requests always last (never the top bar). */
export function categoryEntries(cats: Record<string, number>): [string, number][] {
  const order = [...CATEGORY_ORDER, 'custom', 'unknown'];
  const unknown = (k: string): number => (k === 'unknown' || !order.includes(k) ? 1 : 0);
  return Object.entries(cats)
    .filter(([, v]) => v > 0)
    .sort((a, b) => unknown(a[0]) - unknown(b[0]) || b[1] - a[1] || order.indexOf(a[0]) - order.indexOf(b[0]));
}

/** Host rows for a bar list: cut in the middle, the full host in `title`. */
export function hostRows(entries: [string, number][], max = HOST_MAX): BarRow[] {
  return entries.map(([k, v]) => ({ label: truncateMiddle(k, max), title: k, value: v, mono: true }));
}

/** 30 day columns ending today; days without an aggregate count 0. */
export function daySeries(days: readonly DailyAggregate[], today: Date, n = DAYS): ColumnDatum[] {
  const byDay = new Map(days.map((d) => [d.day, d]));
  const out: ColumnDatum[] = [];
  for (let i = 0; i < n; i++) {
    const d = new Date(today.getFullYear(), today.getMonth(), today.getDate() - (n - 1 - i), 12);
    const key = dayKey(d);
    const isToday = i === n - 1;
    const ms = dayTime(key);
    out.push({
      axis: isToday ? t('ovToday') : dayFmt(ms, false),
      label: isToday ? `${t('ovToday')}, ${dayFmt(ms, true)}` : dayFmt(ms, true),
      value: byDay.get(key)?.total ?? 0,
      quiet: isToday,
    });
  }
  return out;
}

/** Figure tile (DB01: label, value, note; panel DB15: value and a short label). */
function figure(label: string, value: string, note: string, short: string, dark = false): HTMLElement {
  return h(
    'div',
    { class: `ov-tile${dark ? ' ov-tile--dark' : ''}` },
    h('span', { class: 'ov-tile__label', text: label }),
    h('span', { class: 'ov-tile__figure' }, h('span', { class: 'ov-tile__value num', text: value }), h('span', { class: 'ov-tile__note', text: popupMode ? short : note })),
  );
}

/** Bars of the «Noch keine Daten» picture (decorative). */
function emptyArt(): SVGSVGElement {
  const svg = s('svg', { width: 160, height: 72, viewBox: '0 0 160 72', 'aria-hidden': 'true', focusable: 'false', class: 'ov-empty__art' });
  [[8, 18], [38, 42], [68, 28], [98, 66], [128, 10]].forEach(([x, hgt], i) => svg.append(s('rect', { x, y: 70 - hgt, width: 24, height: hgt, rx: 3, class: i === 4 ? 'ov-empty__bar ov-empty__bar--now' : 'ov-empty__bar' })));
  svg.append(s('line', { x1: 0, x2: 160, y1: 70.5, y2: 70.5, class: 'ov-empty__base' }));
  return svg;
}

/** «Verlauf ist ausgeschaltet» (DB03 variant): pause tile, sentence, «Verlauf einschalten», the total so far. */
function historyOffCard(cfg: EffectiveConfig, total: number): HTMLElement {
  const locked = isLocked(cfg, 'history.enabled');
  const on = h('button', { class: 'btn btn--primary', attrs: { type: 'button' } }, t('ovHistoryOffAction'));
  on.addEventListener('click', () =>
    void withBusy(on, async () => {
      const r = await saveSettings({ history: { enabled: true } });
      if (r.ok && !r.data.ignored.length) retryView();
    }),
  );
  return h(
    'section',
    { class: 'db-card ov-off' },
    h('span', { class: 'ov-off__tile', attrs: { 'aria-hidden': 'true' } }, icon('pause', 18)),
    h(
      'div',
      { class: 'ov-off__text' },
      h('h2', { class: 'ov-off__title', text: t('ovHistoryOffTitle') }),
      h('p', { class: 'ov-off__body' }, ...brandText(t('ovHistoryOffText'))),
      locked ? lockedNote() : on,
    ),
    total > 0 ? h('p', { class: 'ov-off__total' }, h('span', { class: 'ov-off__num num', text: fmtNumber(total) }), h('span', { text: t('ovHistoryOffTotal') })) : null,
  );
}

/** Top list card: 4 rows, then «Alle N anzeigen» / «Weniger anzeigen» (a disclosure). */
function topCard(title: string, rows: BarRow[], cls: string): HTMLElement {
  const body = h('div', { class: 'ov-top__body' });
  const bars = !popupMode;
  if (!rows.length) {
    replace(body, h('p', { class: 'ov-top__empty', text: t('ovTopEmpty') }));
    return card({ title, class: `ov-top ${cls}`, flush: popupMode }, body);
  }
  let open = false;
  const more = rows.length > TOP_FIRST;
  const toggle = more ? h('button', { class: 'ov-top__more', attrs: { type: 'button', 'aria-expanded': 'false' } }) : null;
  const paint = (): void => {
    replace(body, barList(open ? rows : rows.slice(0, TOP_FIRST), title, bars));
    if (toggle) {
      toggle.textContent = open ? t('ovShowLess') : popupMode ? t('ovShowAllShort') : t('ovShowAll', fmtNumber(rows.length));
      toggle.setAttribute('aria-expanded', String(open));
    }
  };
  toggle?.addEventListener('click', () => {
    open = !open;
    paint();
  });
  paint();
  // Panel (DB15): «Alle» sits in the card head; tab (DB01): under the rows.
  return popupMode
    ? card({ title, aside: toggle, class: `ov-top ${cls}`, flush: true }, body)
    : card({ title, class: `ov-top ${cls}` }, body, toggle ? h('div', { class: 'ov-top__foot' }, toggle) : null);
}

export function overviewView(): View {
  return {
    async render(root) {
      const today = new Date();
      const from = new Date(today.getFullYear(), today.getMonth(), today.getDate() - (DAYS - 1), 12);
      const [cfgR, histR] = await Promise.all([
        getConfig(true),
        call<HistoryResult>({ type: 'history:query', fromDay: dayKey(from), toDay: dayKey(today) }),
      ]);

      const lead = popupMode
        ? h('p', { class: 'db-head__lead', text: t('ovPeriodLabel', fmtNumber(DAYS)) })
        : h('p', { class: 'db-head__lead' }, ...brandText(t('ovLead', fmtNumber(DAYS))));
      const head = h('header', { class: 'db-head' }, h('div', { class: 'db-head__text' }, h('h1', { class: 'db-head__title', text: t('navOverview'), attrs: { tabindex: -1 } }), lead));
      const foot = h(
        'div',
        { class: 'ov-foot' },
        h('p', { class: 'ov-foot__note' }, icon('device', 16), h('span', { text: t('ovLocalShort') })),
        h('a', { class: 'ov-foot__link', attrs: { href: '#activity' }, text: t('ovOpenActivity') }),
      );

      const cfg = cfgR.ok ? cfgR.data : null;
      // Managed fleet-wide kill switch (policy protectionEnabled: false).
      const paused = cfg?.managed.protectionEnabled === false ? pausedBanner() : null;
      const hist = histR.ok && histR.data && Array.isArray(histR.data.days) ? histR.data : null;
      if (!cfg || (!hist && cfg.settings.history.enabled)) {
        // DB04: the service worker did not answer. «Erneut versuchen» loads the view again.
        mount(root, head, paused, errorState(retryView), foot);
        return;
      }
      const days = hist?.days ?? [];
      const total = hist?.totals?.blocked ?? 0;

      if (!cfg.settings.history.enabled) {
        mount(root, head, paused, historyOffCard(cfg, total), foot);
        return;
      }
      const series = daySeries(days, today);
      const sum = series.reduce((a, d) => a + d.value, 0);
      if (sum === 0) {
        mount(root, head, paused, emptyState(t('ovNoDataTitle'), t('ovNoDataText'), null, emptyArt()), foot);
        return;
      }

      // ---- Tiles (last 30 days) ------------------------------------------
      const byType: Record<string, number> = {};
      for (const d of days) sumInto(byType, savedRequestsByType(d)); // stripped and debounced requests still loaded
      const est = estimateSavings(byType);
      const data = fmtBytes(est.bytes);
      const time = fmtDuration(est.ms, savingsUnits());
      const tiles = h(
        'section',
        { class: 'ov-tiles', attrs: { 'aria-label': t('ovPeriodLabel', fmtNumber(DAYS)) } },
        figure(t('ovTileLabelBlocked'), fmtNumber(sum), t('ovTileRequests'), t('ovTileBlockedShort'), true),
        figure(t('ovTileLabelData'), withUnit(data.value, data.unit), t('ovTileEstimate'), t('popupDataSaved')),
        figure(t('ovTileLabelTime'), withUnit(time.value, time.unit), t('ovTileEstimate'), t('ovTileTime')),
      );

      // ---- Chart -------------------------------------------------------------
      const peak = peakOf(series);
      const peakText = peak ? (popupMode ? t('ovChartPeakShort', fmtNumber(peak.value)) : t('ovChartPeak', [fmtNumber(peak.value), peak.label])) : '';
      const chart = card(
        { title: t('ovChartTitle'), aside: peakText, class: 'ov-chart' },
        columnChart(series, { ariaLabel: t('ovChartAria', [fmtNumber(sum)]), valueLabel: t('ovChartValue'), compact: popupMode }),
        popupMode ? null : h('p', { class: 'ov-chart__note' }, h('span', { class: 'ov-chart__key', attrs: { 'aria-hidden': 'true' } }), t('ovChartTodayNote')),
      );

      // ---- Top lists ---------------------------------------------------------
      const hosts: Record<string, number> = {};
      const sites: Record<string, number> = {};
      const cats: Record<string, number> = {};
      for (const d of days) {
        sumInto(hosts, d.byHost);
        sumInto(sites, d.bySite);
        sumInto(cats, d.byCategory as Record<string, number>);
      }
      const catRows: BarRow[] = categoryEntries(cats)
        .slice(0, TOP_MAX)
        .map(([k, v]) => ({ label: categoryLabel(k), value: v, quiet: k === 'unknown' }));
      const grid = h(
        'div',
        { class: 'ov-grid' },
        topCard(t('ovTopHosts'), hostRows(topEntries(hosts, TOP_MAX)), 'ov-top--hosts'),
        topCard(t('ovTopSites'), hostRows(topEntries(sites, TOP_MAX)), 'ov-top--sites'),
        topCard(t('ovByCategory'), catRows, 'ov-top--cats'),
      );

      mount(root, head, paused, tiles, chart, grid, foot);
    },
  };
}
