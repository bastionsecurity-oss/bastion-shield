// Bastion Shield — dashboard «Aktivität»: live log across all tabs (port
// subscription 'all') and the persisted history (history:events), with
// filters by site / host / type / kind, pause, clear and CSV / JSON export.
// In nerd mode, rows with an attributed rule get a «history» link to the
// filter's upstream history (views/lab.ts openRuleHistory).
// Everything stays local; exports are files the user saves themselves.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ActivityEvent, BuildMeta } from '../../../shared/types.ts';
import { debounce, downloadText, h, replace, toast } from '../../shared/dom.ts';
import { fmtDate, fmtNumber, fmtTime, plural, t } from '../../shared/i18n.ts';
import { icon } from '../../shared/icons.ts';
import { applyAttributed, connectLive, call, type LiveConnection } from '../../shared/messaging.ts';
import { confirmDialog, notice, segmented } from '../../shared/controls.ts';
import { KINDS, kindLabel, RESOURCE_TYPES, typeLabel } from '../../shared/labels.ts';
import { emptyState, pageHead, type View, mount } from '../common.ts';
import { dir, getConfig, getMeta, historyEvents } from '../store.ts';
import { openRuleHistory } from './lab.ts';

type Mode = 'live' | 'history';

const LIVE_MAX = 2000;
const RENDER_MAX = 500;
const PAGE = 200;

interface Filters {
  site: string;
  host: string;
  type: string;
  kind: string;
}

function matches(e: ActivityEvent, f: Filters): boolean {
  if (f.kind && e.kind !== f.kind) return false;
  if (f.type && e.type !== f.type) return false;
  if (f.site && !(e.site ?? '').toLowerCase().includes(f.site)) return false;
  if (f.host && !(e.host ?? '').toLowerCase().includes(f.host)) return false;
  return true;
}

/** CSV cell: quote, and neutralise spreadsheet formulas (=, +, -, @ prefixes). */
function csvCell(v: unknown): string {
  let s = v === undefined || v === null ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function toCsv(rows: ActivityEvent[]): string {
  const head = ['time', 'kind', 'host', 'type', 'site', 'thirdParty', 'list', 'rule', 'url'];
  const lines = [head.join(',')];
  for (const e of rows) {
    lines.push([new Date(e.t).toISOString(), e.kind, e.host, e.type, e.site, e.thirdParty ? 'yes' : 'no', e.list ?? '', e.rule ?? '', e.url].map(csvCell).join(','));
  }
  return `﻿${lines.join('\r\n')}\r\n`;
}

export function activityView(): View {
  let live: LiveConnection | null = null;
  let mode: Mode = 'live';
  let paused = false;
  let liveRows: ActivityEvent[] = [];
  let pending: ActivityEvent[] = [];
  let histRows: ActivityEvent[] = [];
  let histDone = false;
  let histLoading = false;
  const filters: Filters = { site: '', host: '', type: '', kind: '' };
  let paintQueued = false;
  // Nerd mode: «history ↗» on rows attributed to a static ruleset rule.
  let nerd = false;
  let meta: BuildMeta | null = null;

  const tbody = h('tbody');
  const countEl = h('span', { class: 'act-count num', attrs: { 'aria-live': 'polite' } });
  const emptyEl = h('div', { class: 'act-empty' });
  const moreBtn = h('button', { class: 'btn btn--secondary btn--sm', attrs: { type: 'button' }, text: t('actLoadOlder') });
  const pauseBtn = h('button', { class: 'btn btn--secondary btn--sm', attrs: { type: 'button', 'aria-pressed': 'false' } });
  const clearBtn = h('button', { class: 'btn btn--ghost btn--sm', attrs: { type: 'button' } });
  const logOff = h('div', { hidden: true });

  const visible = (): ActivityEvent[] => (mode === 'live' ? liveRows : histRows).filter((e) => matches(e, filters));

  const row = (e: ActivityEvent): HTMLElement =>
    h(
      'tr',
      null,
      h('td', { class: 'act-time mono' }, mode === 'history' ? h('span', { class: 'act-date', text: fmtDate(e.t) }) : null, fmtTime(e.t)),
      h('td', null, h('span', { class: `act-kind act-kind--${e.kind}`, text: kindLabel(e.kind) })),
      h('td', { class: 'act-host mono', attrs: { title: e.url } }, e.host),
      h('td', { class: 'act-type' }, typeLabel(e.type)),
      h('td', { class: 'act-site mono' }, e.site ?? ''),
      h('td', { class: 'act-list' }, e.list ? dir().name(e.list) : h('span', { class: 'db-muted', text: '–' }), nerd ? historyLink(e) : null),
    );

  const historyLink = (e: ActivityEvent): HTMLElement | null => {
    const rule = e.rule;
    // Dynamic and session rules (custom filters, Bastion's own) have no upstream history.
    if (!rule || rule.startsWith('_')) return null;
    return h(
      'button',
      { class: 'act-history', attrs: { type: 'button', title: t('nerdLabHistoryTitle'), 'aria-label': t('nerdLabHistoryTitle') }, on: { click: () => void openRuleHistory(rule, meta) } },
      t('nerdLabHistory'),
      icon('external', 11),
    );
  };

  const paintPause = (): void => {
    replace(pauseBtn, icon(paused ? 'play' : 'pause', 14), paused ? (pending.length ? t('actResumeN', fmtNumber(pending.length)) : t('actResume')) : t('actPause'));
    pauseBtn.setAttribute('aria-pressed', String(paused));
  };

  const paint = (): void => {
    paintQueued = false;
    const rows = visible();
    replace(tbody, ...rows.slice(0, RENDER_MAX).map(row));
    countEl.textContent = rows.length > RENDER_MAX ? t('actCountCapped', [fmtNumber(RENDER_MAX), fmtNumber(rows.length)]) : plural(rows.length, 'actCountOne', 'actCount');
    pauseBtn.hidden = mode !== 'live';
    moreBtn.hidden = mode !== 'history' || histDone;
    moreBtn.disabled = histLoading;
    replace(clearBtn, icon('trash', 14), mode === 'live' ? t('actClearView') : t('actClearHistory'));
    if (rows.length) {
      emptyEl.hidden = true;
    } else {
      emptyEl.hidden = false;
      const filtered = filters.site || filters.host || filters.type || filters.kind;
      replace(
        emptyEl,
        emptyState(
          filtered ? t('actEmptyFiltered') : mode === 'live' ? t('actEmptyLive') : t('actEmptyHistory'),
          filtered ? undefined : mode === 'live' ? t('actEmptyLiveText') : undefined,
        ),
      );
    }
    paintPause();
  };
  const schedule = (): void => {
    if (paintQueued) return;
    paintQueued = true;
    requestAnimationFrame(paint);
  };

  const loadHistory = async (reset: boolean): Promise<void> => {
    if (histLoading) return;
    histLoading = true;
    if (reset) {
      histRows = [];
      histDone = false;
    }
    schedule();
    const before = histRows.length ? histRows[histRows.length - 1].t : undefined;
    const r = await historyEvents(PAGE, before, filters.site, filters.host);
    histLoading = false;
    if (!r.ok) {
      toast(t('dashErrorTitle'), icon('alert', 15));
      schedule();
      return;
    }
    const seen = new Set(histRows.map((e) => `${e.t}|${e.url}|${e.kind}`));
    for (const e of r.data) if (!seen.has(`${e.t}|${e.url}|${e.kind}`)) histRows.push(e);
    histRows.sort((a, b) => b.t - a.t);
    if (r.data.length < PAGE) histDone = true;
    schedule();
  };

  const startLive = (): void => {
    if (live) return;
    live = connectLive('all', {
      backlog: (events) => {
        const seen = new Set(liveRows.map((e) => `${e.t}|${e.url}|${e.kind}|${e.tabId}`));
        for (const e of events) if (!seen.has(`${e.t}|${e.url}|${e.kind}|${e.tabId}`)) liveRows.push(e);
        liveRows.sort((a, b) => b.t - a.t);
        if (liveRows.length > LIVE_MAX) liveRows.length = LIVE_MAX;
        schedule();
      },
      event: (e) => {
        if (paused) {
          pending.unshift(e);
          if (pending.length > LIVE_MAX) pending.length = LIVE_MAX;
          paintPause();
          return;
        }
        liveRows.unshift(e);
        if (liveRows.length > LIVE_MAX) liveRows.length = LIVE_MAX;
        if (mode === 'live') schedule();
      },
      // List names the service worker attributes after the event was streamed.
      attributed: (updates) => {
        if (applyAttributed(updates, liveRows, pending, histRows)) schedule();
      },
    });
  };

  const exportRows = (fmt: 'csv' | 'json'): void => {
    const rows = visible();
    if (!rows.length) {
      toast(t('actExportEmpty'), icon('info', 15));
      return;
    }
    const stamp = new Date().toISOString().slice(0, 10);
    if (fmt === 'csv') downloadText(`bastion-shield-activity-${stamp}.csv`, toCsv(rows), 'text/csv;charset=utf-8');
    else downloadText(`bastion-shield-activity-${stamp}.json`, `${JSON.stringify({ format: 'bastion-shield-activity', version: 1, exportedAt: new Date().toISOString(), events: rows }, null, 2)}\n`, 'application/json');
  };

  return {
    async render(root) {
      const [cfgR, metaR] = await Promise.all([getConfig(), getMeta()]);
      const cfg = cfgR.ok ? cfgR.data : null;
      nerd = cfg?.settings.nerd?.enabled === true && cfg.settings.nerd.filterHistory !== false;
      meta = metaR;

      const modeSeg = segmented<Mode>({
        options: [
          { value: 'live', label: t('actModeLive') },
          { value: 'history', label: t('actModeHistory') },
        ],
        value: mode,
        label: t('actModeLabel'),
        onChange: (v) => {
          mode = v;
          if (v === 'history' && !histRows.length) void loadHistory(true);
          schedule();
        },
      });

      const siteIn = h('input', { class: 'input', attrs: { type: 'search', placeholder: t('actFilterSite'), 'aria-label': t('actFilterSite'), spellcheck: 'false', autocomplete: 'off' } });
      const hostIn = h('input', { class: 'input', attrs: { type: 'search', placeholder: t('actFilterHost'), 'aria-label': t('actFilterHost'), spellcheck: 'false', autocomplete: 'off' } });
      const typeSel = h('select', { class: 'select', attrs: { 'aria-label': t('actFilterType') } }, h('option', { attrs: { value: '' }, text: t('actAllTypes') }), ...RESOURCE_TYPES.map((ty) => h('option', { attrs: { value: ty }, text: typeLabel(ty) })));
      const kindSel = h('select', { class: 'select', attrs: { 'aria-label': t('actFilterKind') } }, h('option', { attrs: { value: '' }, text: t('actAllKinds') }), ...KINDS.map((k) => h('option', { attrs: { value: k }, text: kindLabel(k) })));

      const onText = debounce(() => {
        filters.site = siteIn.value.trim().toLowerCase();
        filters.host = hostIn.value.trim().toLowerCase();
        if (mode === 'history') void loadHistory(true);
        else schedule();
      }, 250);
      siteIn.addEventListener('input', onText);
      hostIn.addEventListener('input', onText);
      typeSel.addEventListener('change', () => {
        filters.type = typeSel.value;
        schedule();
      });
      kindSel.addEventListener('change', () => {
        filters.kind = kindSel.value;
        schedule();
      });

      pauseBtn.addEventListener('click', () => {
        paused = !paused;
        if (!paused && pending.length) {
          liveRows = pending.concat(liveRows).slice(0, LIVE_MAX);
          pending = [];
        }
        schedule();
      });
      clearBtn.addEventListener('click', async () => {
        if (mode === 'live') {
          liveRows = [];
          pending = [];
          schedule();
          return;
        }
        const ok = await confirmDialog({ title: t('actClearHistoryTitle'), body: t('actClearHistoryText'), confirmLabel: t('actClearHistory') });
        if (!ok) return;
        const r = await call<unknown>({ type: 'history:clear' });
        if (!r.ok) {
          toast(t('errorSaveFailed'), icon('alert', 15));
          return;
        }
        histRows = [];
        histDone = true;
        toast(t('actHistoryCleared'), icon('check', 15));
        schedule();
      });
      moreBtn.addEventListener('click', () => void loadHistory(false));

      const exportCsv = h('button', { class: 'btn btn--secondary btn--sm', attrs: { type: 'button' }, on: { click: () => exportRows('csv') } }, icon('download', 14), 'CSV');
      const exportJson = h('button', { class: 'btn btn--secondary btn--sm', attrs: { type: 'button' }, on: { click: () => exportRows('json') } }, icon('download', 14), 'JSON');

      if (cfg && !cfg.settings.ui.activityLog) {
        logOff.hidden = false;
        replace(logOff, notice(t('actLogOffTitle'), t('actLogOffText'), 'info'));
      }

      const table = h(
        'table',
        { class: 'act-table' },
        h('caption', { class: 'sr-only', text: t('actTableCaption') }),
        h(
          'thead',
          null,
          h(
            'tr',
            null,
            ...[t('actColTime'), t('actColKind'), t('actColHost'), t('actColType'), t('actColSite'), t('actColList')].map((c) => h('th', { text: c, attrs: { scope: 'col' } })),
          ),
        ),
        tbody,
      );

      mount(root, 
        pageHead(t('actTitle'), t('actLead')),
        logOff,
        h(
          'div',
          { class: 'act-toolbar', attrs: { role: 'toolbar', 'aria-label': t('actToolbar') } },
          modeSeg.el,
          h('div', { class: 'act-filters' }, h('span', { class: 'act-search' }, icon('search', 14), siteIn), h('span', { class: 'act-search' }, icon('search', 14), hostIn), typeSel, kindSel),
        ),
        h('div', { class: 'act-bar' }, countEl, h('div', { class: 'act-bar__actions' }, pauseBtn, clearBtn, h('span', { class: 'act-bar__sep', attrs: { 'aria-hidden': 'true' } }), exportCsv, exportJson)),
        h('div', { class: 'act-scroll' }, table),
        emptyEl,
        h('div', { class: 'act-more' }, moreBtn),
      );
      paint();
      startLive();
    },
    dispose() {
      live?.close();
      live = null;
    },
  };
}
