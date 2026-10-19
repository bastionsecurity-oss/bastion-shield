// Bastion Shield — dashboard «Übersicht»: blocked requests, data and waiting
// time saved (estimate) over 30 days, blocked requests per day, top hosts, top
// sites and the split by list category. Reads history:query once per visit.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { DailyAggregate, HistoryResult } from '../../../shared/types.ts';
import { h } from '../../shared/dom.ts';
import { fmtDayAxis, fmtDayShort, fmtNumber, t } from '../../shared/i18n.ts';
import { estimateSavings, fmtBytes, fmtDuration } from '../../shared/savings.ts';
import { icon } from '../../shared/icons.ts';
import { call } from '../../shared/messaging.ts';
import { notice } from '../../shared/controls.ts';
import { CATEGORY_ORDER, categoryLabel } from '../../shared/labels.ts';
import { barList, columnChart, type ColumnDatum } from '../chart.ts';
import { dayKey, dayTime, emptyState, errorState, panel, type View, mount } from '../common.ts';
import { getConfig } from '../store.ts';

const DAYS = 30;
const TOP_N = 8;

function sumInto(target: Record<string, number>, src: Record<string, number> | undefined): void {
  if (!src) return;
  for (const [k, v] of Object.entries(src)) if (typeof v === 'number' && Number.isFinite(v)) target[k] = (target[k] ?? 0) + v;
}

function top(rec: Record<string, number>, n: number): [string, number][] {
  return Object.entries(rec)
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n);
}

export function overviewView(): View {
  return {
    async render(root) {
      const today = new Date();
      const from = new Date(today.getFullYear(), today.getMonth(), today.getDate() - (DAYS - 1), 12);
      const [cfgR, histR] = await Promise.all([
        getConfig(),
        call<HistoryResult>({ type: 'history:query', fromDay: dayKey(from), toDay: dayKey(today) }),
      ]);
      if (!cfgR.ok) {
        mount(root, errorState(() => location.reload()));
        return;
      }
      const cfg = cfgR.data;
      const hist = histR.ok && histR.data ? histR.data : { days: [] as DailyAggregate[], totals: { since: 0, blocked: 0, byKind: {} } };
      const days = Array.isArray(hist.days) ? hist.days : [];

      // ---- Header + tiles (last 30 days) -----------------------------------
      // Managed fleet-wide kill switch (policy protectionEnabled: false).
      const globalOff = cfg.managed.protectionEnabled === false;
      const byType: Record<string, number> = {};
      let period = 0;
      for (const d of days) {
        sumInto(byType, d.byType);
        period += d.total ?? 0;
      }
      const est = estimateSavings(byType);
      const data = fmtBytes(est.bytes);
      const time = fmtDuration(est.ms, { s: t('unitSeconds'), min: t('unitMinutes'), h: t('unitHours') });
      const tileEl = (value: string, unit: string, label: string, dark = false): HTMLElement =>
        h('div', { class: `site-tile${dark ? ' site-tile--dark' : ''}` }, h('div', { class: 'site-tile__value' }, h('span', { class: 'num', text: value }), unit ? h('span', { class: 'site-tile__unit', text: ` ${unit}` }) : null), h('div', { class: 'site-tile__label', text: label }));
      const head = h('header', { class: 'db-head' }, h('div', { class: 'db-head__text' }, h('h1', { class: 'db-head__title', text: t('navOverview'), attrs: { tabindex: -1 } })));
      const offNotice = globalOff ? h('div', { class: 'db-gap' }, notice(t('popupGlobalOffTitle'), t('popupGlobalOffText'), 'info')) : null;
      const hero = h(
        'section',
        { class: 'site-tiles ov-tiles', attrs: { 'aria-label': t('ovPeriodLabel', fmtNumber(DAYS)), title: t('savingsEstimateNote') } },
        tileEl(fmtNumber(period), '', t('ovTileBlocked', fmtNumber(DAYS)), true),
        tileEl(data.value, data.unit, t('popupDataSaved')),
        tileEl(time.value, time.unit, t('ovTileTime')),
      );

      // ---- Chart ------------------------------------------------------------
      const byDay = new Map(days.map((d) => [d.day, d]));
      const series: ColumnDatum[] = [];
      let sum = 0;
      for (let i = 0; i < DAYS; i++) {
        const d = new Date(from.getFullYear(), from.getMonth(), from.getDate() + i, 12);
        const key = dayKey(d);
        const v = byDay.get(key)?.total ?? 0;
        sum += v;
        const isToday = i === DAYS - 1;
        series.push({ axis: isToday ? t('ovToday') : fmtDayAxis(dayTime(key)), label: isToday ? `${t('ovToday')}, ${fmtDayShort(dayTime(key))}` : fmtDayShort(dayTime(key)), value: v, quiet: isToday });
      }

      let chartBody: HTMLElement;
      if (!cfg.settings.history.enabled) {
        chartBody = emptyState(t('ovHistoryOffTitle'), t('ovHistoryOffText'), h('a', { class: 'btn btn--secondary btn--sm', attrs: { href: '#settings' } }, t('ovHistoryOffAction')));
      } else if (sum === 0) {
        chartBody = emptyState(t('ovNoDataTitle'), t('ovNoDataText'));
      } else {
        chartBody = columnChart(series, { ariaLabel: t('ovChartAria', [fmtNumber(sum)]), valueLabel: t('ovChartValue'), height: 230 });
      }
      const chartPanel = panel(
        { title: t('ovChartTitle'), aside: sum ? h('span', null, t('ovChartSum', fmtNumber(sum))) : null, class: 'ov-chart' },
        chartBody,
        sum ? h('p', { class: 'ov-chart__note' }, h('span', { class: 'ov-chart__key', attrs: { 'aria-hidden': 'true' } }), t('ovChartTodayNote')) : null,
      );

      // ---- Top lists ----------------------------------------------------------
      const hosts: Record<string, number> = {};
      const sites: Record<string, number> = {};
      const cats: Record<string, number> = {};
      for (const d of days) {
        sumInto(hosts, d.byHost);
        sumInto(sites, d.bySite);
        sumInto(cats, d.byCategory as Record<string, number>);
      }
      const hostRows = top(hosts, TOP_N).map(([k, v]) => ({ label: k, value: v, mono: true }));
      const siteRows = top(sites, TOP_N).map(([k, v]) => ({ label: k, value: v, mono: true }));
      const catOrder = [...CATEGORY_ORDER, 'custom', 'unknown'];
      // Unattributed requests are not a category: always list them last, never as the top bar.
      const isUnknown = (k: string): number => (k === 'unknown' || !catOrder.includes(k) ? 1 : 0);
      const catRows = Object.entries(cats)
        .filter(([, v]) => v > 0)
        .sort((a, b) => isUnknown(a[0]) - isUnknown(b[0]) || b[1] - a[1] || catOrder.indexOf(a[0]) - catOrder.indexOf(b[0]))
        .map(([k, v]) => ({ label: categoryLabel(k), value: v }));

      const empty = (): HTMLElement => h('p', { class: 'db-muted', text: t('ovTopEmpty') });
      const grid = h(
        'div',
        { class: 'ov-grid' },
        panel({ title: t('ovTopHosts') }, hostRows.length ? barList(hostRows, t('ovTopHosts')) : empty()),
        panel({ title: t('ovTopSites') }, siteRows.length ? barList(siteRows, t('ovTopSites')) : empty()),
        panel({ title: t('ovByCategory') }, catRows.length ? barList(catRows, t('ovByCategory')) : empty()),
      );

      const foot = h(
        'p',
        { class: 'ov-foot' },
        icon('device', 15),
        h('span', { text: t('ovLocalNote') }),
        h('a', { attrs: { href: '#activity' }, text: t('ovOpenActivity') }),
      );

      mount(root, head, offNotice, hero, chartPanel, grid, foot);
    },
  };
}
