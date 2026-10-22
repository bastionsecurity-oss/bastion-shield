// Bastion Shield — dashboard «Aktivität» (Paper DB08–DB10, panel DB16): live
// log across all tabs (port subscription 'all') and the persisted history
// (history:events, 200 per page with «Ältere Einträge laden»), filters by
// site / host / type / kind, pause, «Ansicht leeren», «Verlauf löschen…»
// (confirm dialog, D01) and «Exportieren…» (CSV / JSON). Long hosts are cut in
// the middle; the full address stays in `title` and in the export. In nerd
// mode, rows with an attributed rule get a «history» link to the filter's
// upstream history (views/lab.ts openRuleHistory). Everything stays local.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ActivityEvent, BuildMeta } from '../../../shared/types.ts';
import { HISTORY_MAX_EVENTS } from '../../../shared/constants.ts';
import { debounce, downloadText, h, replace, toast } from '../../shared/dom.ts';
import { fmtDate, fmtDayAxis, fmtNumber, fmtTime, plural, t } from '../../shared/i18n.ts';
import { icon } from '../../shared/icons.ts';
import { applyAttributed, connectLive, call, type LiveConnection } from '../../shared/messaging.ts';
import { brandText, choiceDialog, confirmDialog, retryToast, segmented } from '../../shared/controls.ts';
import { truncateMiddle } from '../../shared/text.ts';
import { KINDS, kindLabel, RESOURCE_TYPES, typeLabel } from '../../shared/labels.ts';
import { errorState, lockedNote, pageHead, popupMode, retryView, withBusy, type View, mount } from '../common.ts';
import { dir, getConfig, getMeta, historyEvents, isLocked, saveSettings } from '../store.ts';
import { openRuleHistory } from './lab.ts';

type Mode = 'live' | 'history';

/** Live rows kept in memory; the table shows the newest RENDER_MAX of them. */
export const LIVE_MAX = 2000;
export const RENDER_MAX = 500;
/** History rows per «Ältere Einträge laden». */
export const PAGE = 200;
/** Host and site columns: cut in the middle past these lengths (full value in `title`). */
const HOST_MAX = popupMode ? 30 : 28;
const SITE_MAX = 18;

export interface Filters {
  site: string;
  host: string;
  /** Panel: one field that matches host or site. */
  any: string;
  type: string;
  kind: string;
}

export function emptyFilters(): Filters {
  return { site: '', host: '', any: '', type: '', kind: '' };
}

export function hasFilters(f: Filters): boolean {
  return !!(f.site || f.host || f.any || f.type || f.kind);
}

export function matches(e: ActivityEvent, f: Filters): boolean {
  if (f.kind && e.kind !== f.kind) return false;
  if (f.type && e.type !== f.type) return false;
  const site = (e.site ?? '').toLowerCase();
  const host = (e.host ?? '').toLowerCase();
  if (f.site && !site.includes(f.site)) return false;
  if (f.host && !host.includes(f.host)) return false;
  if (f.any && !site.includes(f.any) && !host.includes(f.any)) return false;
  return true;
}

/** The typed text filters, for «Keine Einträge für «…»» (empty when only selects filter). */
export function filterQuery(f: Filters): string {
  return [f.any, f.site, f.host].filter(Boolean).join(', ');
}

/** CSV cell: quote, and neutralise spreadsheet formulas (=, +, -, @ prefixes). */
function csvCell(v: unknown): string {
  let s = v === undefined || v === null ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(rows: ActivityEvent[]): string {
  const head = ['time', 'kind', 'host', 'type', 'site', 'thirdParty', 'list', 'rule', 'url'];
  const lines = [head.join(',')];
  for (const e of rows) {
    lines.push([new Date(e.t).toISOString(), e.kind, e.host, e.type, e.site, e.thirdParty ? 'yes' : 'no', e.list ?? '', e.rule ?? '', e.url].map(csvCell).join(','));
  }
  return `﻿${lines.join('\r\n')}\r\n`;
}

/** Host / site cell text: cut in the middle, the full value in `title`. */
function cutCell(value: string, max: number, cls: string, full = value): HTMLElement {
  const shown = truncateMiddle(value, max);
  return h('span', { class: cls, text: shown || '–', attrs: { translate: 'no', title: full && (shown !== full || full !== value) ? full : undefined } });
}

function kindBadge(kind: string): HTMLElement {
  return h('span', { class: `act-kind act-kind--${kind}`, text: kindLabel(kind) });
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
  let histError = false;
  let filters: Filters = emptyFilters();
  let paintQueued = false;
  // Nerd mode: «history ↗» on rows attributed to a static ruleset rule.
  let nerd = false;
  let meta: BuildMeta | null = null;

  const tbody = h('tbody');
  const list = h('ul', { class: 'act-list' });
  const countEl = h('span', { class: 'act-count num', attrs: { 'aria-live': 'polite' } });
  const emptyEl = h('div', { class: 'act-empty' });
  const tableWrap = h('div', { class: 'act-scroll' });
  const moreBtn = h('button', { class: 'btn btn--outline', attrs: { type: 'button' }, text: t('actLoadOlder') });
  const moreNote = h('p', { class: 'act-more__note', text: t('actFootHistory', [fmtNumber(PAGE), fmtNumber(HISTORY_MAX_EVENTS)]) });
  const moreWrap = h('div', { class: 'act-more' }, moreBtn, moreNote);
  const liveFoot = h(
    'div',
    { class: 'act-foot' },
    h('p', { class: 'act-foot__note', text: t('actFootTrunc') }),
    h('p', { class: 'act-foot__cap', text: t('actFootLive', fmtNumber(RENDER_MAX)) }),
  );
  const pauseBtn = h('button', { class: `btn btn--outline act-pause${popupMode ? ' act-pause--icon' : ''}`, attrs: { type: 'button', 'aria-pressed': 'false' } });
  const clearViewBtn = h('button', { class: 'btn btn--quiet', attrs: { type: 'button' }, text: t('actClearView') });
  const clearHistBtn = h('button', { class: 'btn btn--danger', attrs: { type: 'button' }, text: t('actClearHistoryOpen') });
  const exportBtn = h('button', { class: 'btn btn--outline', attrs: { type: 'button' } }, icon('download', 12), t('actExport'));
  const sep = h('span', { class: 'act-bar__sep', attrs: { 'aria-hidden': 'true' } });
  const logOff = h('div', { class: 'act-logoff-slot' });
  const inputs: HTMLInputElement[] = [];
  const selects: HTMLSelectElement[] = [];

  const visible = (): ActivityEvent[] => (mode === 'live' ? liveRows : histRows).filter((e) => matches(e, filters));

  const historyLink = (e: ActivityEvent): HTMLElement | null => {
    const rule = e.rule;
    // Dynamic and session rules (custom filters, Bastion's own) have no upstream history.
    if (!nerd || !rule || rule.startsWith('_')) return null;
    return h(
      'button',
      { class: 'act-history', attrs: { type: 'button', title: t('nerdLabHistoryTitle'), 'aria-label': t('nerdLabHistoryTitle') }, on: { click: () => void openRuleHistory(rule, meta) } },
      t('nerdLabHistory'),
      icon('external', 11),
    );
  };

  const listName = (e: ActivityEvent): HTMLElement => (e.list ? h('span', { class: 'act-list-name', text: dir().name(e.list), attrs: { title: dir().name(e.list) } }) : h('span', { class: 'db-muted', text: '–' }));

  const row = (e: ActivityEvent): HTMLElement =>
    h(
      'tr',
      null,
      h('td', { class: 'act-time mono' }, mode === 'history' ? h('span', { class: 'act-date', text: fmtDayAxis(e.t), attrs: { title: fmtDate(e.t) } }) : null, fmtTime(e.t)),
      h('td', { class: 'act-kind-cell' }, kindBadge(e.kind)),
      h('td', { class: 'act-host mono' }, cutCell(e.host, HOST_MAX, 'act-cut', e.url || e.host)),
      h('td', { class: 'act-type' }, typeLabel(e.type)),
      h('td', { class: 'act-site mono' }, cutCell(e.site ?? '', SITE_MAX, 'act-cut')),
      h('td', { class: 'act-list-cell' }, listName(e), historyLink(e)),
    );

  /** Panel (DB16): host and badge, then «site - type - time». */
  const item = (e: ActivityEvent): HTMLElement =>
    h(
      'li',
      { class: 'act-item' },
      h('div', { class: 'act-item__top' }, cutCell(e.host, HOST_MAX, 'act-item__host mono', e.url || e.host), kindBadge(e.kind)),
      h('p', { class: 'act-item__meta' }, [e.site ? truncateMiddle(e.site, SITE_MAX) : '', typeLabel(e.type), mode === 'history' ? `${fmtDate(e.t)} ${fmtTime(e.t)}` : fmtTime(e.t)].filter(Boolean).join(' - ')),
    );

  const paintPause = (): void => {
    const label = paused ? (pending.length ? t('actResumeN', fmtNumber(pending.length)) : t('actResume')) : t('actPause');
    if (popupMode) {
      replace(pauseBtn, icon(paused ? 'play' : 'pause', 14));
      pauseBtn.setAttribute('aria-label', label);
      pauseBtn.title = label;
    } else replace(pauseBtn, icon(paused ? 'play' : 'pause', 12), label);
    pauseBtn.setAttribute('aria-pressed', String(paused));
  };

  const resetFilters = (): void => {
    filters = emptyFilters();
    for (const i of inputs) i.value = '';
    for (const s of selects) s.value = '';
    if (mode === 'history') void loadHistory(true);
    else schedule();
    inputs[0]?.focus();
  };

  const emptyView = (): HTMLElement => {
    if (mode === 'history' && histError) return errorState(() => loadHistory(true));
    if (hasFilters(filters)) {
      const q = filterQuery(filters);
      return h(
        'div',
        { class: 'db-card act-nohits' },
        h('div', { class: 'act-nohits__text' }, h('p', { class: 'act-nohits__title', text: q ? t('actEmptyNoHits', q) : t('actEmptyFiltered') }), mode === 'live' ? h('p', { class: 'act-nohits__body', text: t('actEmptyNoHitsLive') }) : null),
        h('button', { class: 'btn btn--outline', attrs: { type: 'button' }, on: { click: resetFilters } }, t('actResetFilters')),
      );
    }
    const live = mode === 'live';
    return h(
      'div',
      { class: 'act-wait' },
      h('span', { class: 'act-wait__tile', attrs: { 'aria-hidden': 'true' } }, icon('activity', 18)),
      h('div', null, h('p', { class: 'act-wait__title', text: live ? t('actEmptyLive') : t('actEmptyHistory') }), h('p', { class: 'act-wait__text', text: live ? t('actEmptyLiveText') : t('actEmptyHistoryText') })),
    );
  };

  const paint = (): void => {
    paintQueued = false;
    tableWrap.querySelector('.act-table')?.classList.toggle('act-table--history', mode === 'history');
    const rows = visible();
    const shown = rows.slice(0, RENDER_MAX);
    if (popupMode) replace(list, ...shown.map(item));
    else replace(tbody, ...shown.map(row));
    if (mode === 'history') countEl.textContent = plural(rows.length, 'actCountLoadedOne', 'actCountLoaded');
    else if (rows.length > RENDER_MAX) countEl.textContent = t(popupMode ? 'actCountCappedShort' : 'actCountCapped', [fmtNumber(RENDER_MAX), fmtNumber(rows.length)]);
    else countEl.textContent = plural(rows.length, 'actCountOne', 'actCount');
    pauseBtn.hidden = mode !== 'live';
    clearViewBtn.hidden = mode !== 'live';
    clearHistBtn.hidden = mode !== 'history';
    moreWrap.hidden = mode !== 'history' || histDone || histError || (!rows.length && !histLoading);
    moreBtn.disabled = histLoading;
    liveFoot.hidden = mode !== 'live' || !rows.length;
    if (popupMode) list.hidden = !rows.length;
    else tableWrap.hidden = !rows.length;
    emptyEl.hidden = rows.length > 0 || (mode === 'history' && histLoading && !histError);
    if (!emptyEl.hidden) replace(emptyEl, emptyView());
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
    histError = false;
    if (reset) {
      histRows = [];
      histDone = false;
    }
    schedule();
    const before = histRows.length ? histRows[histRows.length - 1].t : undefined;
    // The panel's single field matches host or site: filter here, not in the worker.
    const r = await historyEvents(PAGE, before, popupMode ? '' : filters.site, popupMode ? '' : filters.host);
    histLoading = false;
    if (!r.ok) {
      histError = true;
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

  const exportRows = async (): Promise<void> => {
    const rows = visible();
    if (!rows.length) {
      toast(t('actExportEmpty'), icon('info', 15));
      return;
    }
    const fmt = await choiceDialog<'csv' | 'json'>({
      title: t('actExportTitle'),
      body: t('actExportText', fmtNumber(rows.length)),
      icon: 'download',
      choices: [
        { value: 'csv', label: t('actExportCsv'), primary: true },
        { value: 'json', label: t('actExportJson') },
      ],
    });
    if (!fmt) return;
    const stamp = new Date().toISOString().slice(0, 10);
    if (fmt === 'csv') downloadText(`bastion-shield-activity-${stamp}.csv`, toCsv(rows), 'text/csv;charset=utf-8');
    else downloadText(`bastion-shield-activity-${stamp}.json`, `${JSON.stringify({ format: 'bastion-shield-activity', version: 1, exportedAt: new Date().toISOString(), events: rows }, null, 2)}\n`, 'application/json');
  };

  const clearHistory = async (): Promise<void> => {
    const ok = await confirmDialog({
      title: t('actClearHistoryTitle'),
      body: t('actClearHistoryText'),
      confirmLabel: t('actClearHistory'),
      cancelLabel: t('actKeepHistory'),
      danger: true,
    });
    if (!ok) return;
    const r = await call<unknown>({ type: 'history:clear' });
    if (!r.ok) {
      retryToast(t('errorSaveFailed'), () => clearHistory());
      return;
    }
    histRows = [];
    histDone = true;
    toast(t('actHistoryCleared'), icon('check', 15));
    schedule();
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
      modeSeg.el.classList.add('act-mode');

      const search = (placeholder: string, key: 'site' | 'host' | 'any'): HTMLElement => {
        const input = h('input', { class: 'input act-search__input', attrs: { type: 'search', placeholder, 'aria-label': placeholder.replace(/…$/, ''), spellcheck: 'false', autocomplete: 'off', translate: 'no' } });
        inputs.push(input);
        const onText = debounce(() => {
          filters[key] = input.value.trim().toLowerCase();
          if (mode === 'history' && !popupMode) void loadHistory(true);
          else schedule();
        }, 250);
        input.addEventListener('input', onText);
        return h('span', { class: 'act-search' }, icon('search', 14), input);
      };
      const select = (label: string, all: string, values: readonly string[], text: (v: string) => string, key: 'type' | 'kind'): HTMLSelectElement => {
        const sel = h('select', { class: 'select act-select', attrs: { 'aria-label': label } }, h('option', { attrs: { value: '' }, text: all }), ...values.map((v) => h('option', { attrs: { value: v }, text: text(v) })));
        sel.addEventListener('change', () => {
          filters[key] = sel.value;
          schedule();
        });
        selects.push(sel);
        return sel;
      };

      pauseBtn.addEventListener('click', () => {
        paused = !paused;
        if (!paused && pending.length) {
          liveRows = pending.concat(liveRows).slice(0, LIVE_MAX);
          pending = [];
        }
        schedule();
      });
      clearViewBtn.addEventListener('click', () => {
        liveRows = [];
        pending = [];
        schedule();
      });
      clearHistBtn.addEventListener('click', () => void clearHistory());
      moreBtn.addEventListener('click', () => void withBusy(moreBtn, () => loadHistory(false)));
      exportBtn.addEventListener('click', () => void exportRows());

      // Log switched off (DB10): dark banner with «Protokoll einschalten».
      if (cfg && !cfg.settings.ui.activityLog) {
        const turnOn = isLocked(cfg, 'ui.activityLog')
          ? lockedNote()
          : h('button', { class: 'act-logoff__on', attrs: { type: 'button' }, text: t('actLogOn') });
        if (turnOn instanceof HTMLButtonElement) {
          turnOn.addEventListener('click', () =>
            void withBusy(turnOn, async () => {
              const r = await saveSettings({ ui: { activityLog: true } });
              if (r.ok && !r.data.ignored.length) retryView();
            }),
          );
        }
        replace(
          logOff,
          h(
            'div',
            { class: 'act-logoff', attrs: { role: 'status' } },
            h('span', { class: 'act-logoff__tile', attrs: { 'aria-hidden': 'true' } }, icon('pause', 14)),
            h('div', { class: 'act-logoff__text' }, h('p', { class: 'act-logoff__title', text: t('actLogOffTitle') }), h('p', { class: 'act-logoff__body' }, ...brandText(t('actLogOffText'))), turnOn),
          ),
        );
      }

      if (popupMode) {
        // DB16: one search field, the action filter, rows instead of a table.
        const head = pageHead(t('actTitle'), countEl, h('div', { class: 'act-head-tools' }, modeSeg.el, pauseBtn));
        const card = h(
          'section',
          { class: 'db-card db-card--flush act-panel' },
          h('div', { class: 'act-panel__tools' }, search(t('actFilterAnyPh'), 'any'), select(t('actFilterKind'), t('actAllKinds'), KINDS, kindLabel, 'kind')),
          list,
        );
        tableWrap.replaceChildren(card);
        mount(root, head, logOff, tableWrap, emptyEl, moreWrap);
        tableWrap.classList.add('act-scroll--panel');
      } else {
        const table = h(
          'table',
          { class: 'act-table' },
          h('caption', { class: 'sr-only', text: t('actTableCaption') }),
          h('colgroup', null, ...['time', 'kind', 'host', 'type', 'site', 'list'].map((c) => h('col', { class: `act-col--${c}` }))),
          h('thead', null, h('tr', null, ...[t('actColTime'), t('actColKind'), t('actColHost'), t('actColType'), t('actColSite'), t('actColList')].map((c) => h('th', { text: c, attrs: { scope: 'col' } })))),
          tbody,
        );
        tableWrap.replaceChildren(table);
        mount(
          root,
          pageHead(t('actTitle'), h('p', { class: 'db-head__lead' }, ...brandText(t('actLead')))),
          logOff,
          h(
            'div',
            { class: 'act-toolbar', attrs: { role: 'toolbar', 'aria-label': t('actToolbar') } },
            modeSeg.el,
            search(t('actFilterSitePh'), 'site'),
            search(t('actFilterHostPh'), 'host'),
            select(t('actFilterType'), t('actAllTypes'), RESOURCE_TYPES, typeLabel, 'type'),
            select(t('actFilterKind'), t('actAllKinds'), KINDS, kindLabel, 'kind'),
          ),
          h('div', { class: 'act-bar' }, countEl, h('div', { class: 'act-bar__actions' }, pauseBtn, clearViewBtn, clearHistBtn, sep, exportBtn)),
          tableWrap,
          emptyEl,
          liveFoot,
          moreWrap,
        );
      }
      paint();
      startLive();
    },
    dispose() {
      live?.close();
      live = null;
    },
  };
}
