// Bastion Shield — «Diese Website» (expanded popup only): protection switch
// for the current site, blocked count with the data and time estimate, the
// per-site blocking mode, fingerprinting level and script blocking, the DNR
// rules that matched on the page, and «Seite funktioniert nicht richtig?».
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BlockingMode, FingerprintLevel, PopupState, SiteSettings } from '../../../shared/types.ts';
import { h, replace } from '../../shared/dom.ts';
import { fmtNumber, t } from '../../shared/i18n.ts';
import { icon } from '../../shared/icons.ts';
import { call, connectLive, type LiveConnection } from '../../shared/messaging.ts';
import { lockIcon, notice, segmented, switchControl } from '../../shared/controls.ts';
import { estimateFromSample, fmtBytes, fmtDuration, savingsUnits } from '../../shared/savings.ts';
import { countEvent, eventKey, sampleType } from '../../shared/page-activity.ts';
import { createMatchedPanel } from '../../popup/matched.ts';
import { startReport } from '../../popup/report.ts';
import { setSiteSettings } from '../../popup/site-set.ts';
import { normalisePopupState } from '../../popup/state.ts';
import { errorState, nextId, popupTabId, statTile, type View, mount } from '../common.ts';
import { readHandoff } from '../../shared/handoff.ts';
import { dir, getConfig, getMeta, onStoreChange } from '../store.ts';
import { ListDirectory } from '../../shared/labels.ts';

async function resolveTabId(): Promise<number | null> {
  const fromQuery = popupTabId();
  if (fromQuery !== null) return fromQuery;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab?.id ?? null;
  } catch {
    return null;
  }
}

function row(label: string, labelId: string, control: HTMLElement, locked = false): HTMLElement {
  return h('div', { class: 'db-row' }, h('div', { class: 'db-row__text' }, h('div', { class: 'db-row__label', text: label, attrs: { id: labelId } })), h('div', { class: 'db-row__ctl' }, locked ? lockIcon() : null, control));
}

/** Latest state of «Diese Website» for the collapse hand-off (null until the view was shown). */
export let collapseState: (() => PopupState) | null = null;

export function siteView(): View {
  let live: LiveConnection | null = null;
  // Nerd mode: blame links in the matched-rules panel follow the switch live.
  let unsubscribe: (() => void) | null = null;
  return {
    async render(root) {
      // From the compact popup: its hand-off lets this view draw in the first frame (no
      // await before mount), so the view transition morphs the tiles into place.
      const handoff = readHandoff(popupTabId());
      let tabId: number;
      let raw: unknown;
      if (handoff) {
        tabId = handoff.tabId;
        raw = handoff.state;
      } else {
        const id = await resolveTabId();
        const res = id === null ? null : await call<PopupState>({ type: 'popup:state', tabId: id });
        if (id === null || !res || !res.ok || !res.data || typeof res.data !== 'object') {
          mount(root, errorState(() => location.reload()));
          return;
        }
        tabId = id;
        raw = res.data;
      }
      const s = normalisePopupState(raw, tabId);
      const site = s.site ?? s.host;
      const title = h('h1', { class: 'db-head__title', text: s.host ?? s.site ?? t('navSite'), attrs: { tabindex: -1 } });

      if (s.globallyDisabled || !s.filterable || !site) {
        mount(
          root,
          h('header', { class: 'db-head' }, h('div', { class: 'db-head__text' }, title)),
          s.globallyDisabled ? notice(t('popupGlobalOffTitle'), t('popupGlobalOffText')) : notice(t('popupUnfilterableTitle'), t('popupUnfilterableText')),
        );
        return;
      }

      // ---- Reload bar (after a per-site change) -----------------------------
      const reloadBar = h(
        'div',
        { class: 'site-reload', attrs: { role: 'status', hidden: true } },
        icon('reload', 15),
        h('span', { class: 'site-reload__text', text: t('popupReloadHint') }),
        h(
          'button',
          {
            class: 'btn btn--sm site-reload__btn',
            attrs: { type: 'button' },
            on: {
              click: async () => {
                try {
                  await chrome.tabs.reload(tabId);
                } catch {
                  /* tab may be gone */
                }
                reloadBar.hidden = true;
              },
            },
          },
          t('actionReload'),
        ),
      );

      const setSite = async (patch: SiteSettings): Promise<boolean> => {
        const ok = await setSiteSettings(s, tabId, patch);
        if (ok) reloadBar.hidden = false;
        return ok;
      };

      // ---- Header with the protection switch --------------------------------
      const ss = s.siteSettings;
      const toggleLabel = nextId('site');
      const controls: { setDisabled(d: boolean): void }[] = [];
      const paintEnabled = (): void => {
        const off = !s.siteSettings.enabled || s.locks.settings;
        for (const c of controls) c.setDisabled(off);
        document.body.dataset.site = s.siteSettings.enabled ? 'on' : 'off';
      };
      const protect = switchControl({
        checked: ss.enabled,
        labelledBy: toggleLabel,
        large: true,
        disabled: s.locks.siteToggle,
        onChange: async (v) => {
          const ok = await setSite({ enabled: v });
          paintEnabled();
          return ok;
        },
      });
      const head = h(
        'header',
        { class: 'db-head' },
        h('div', { class: 'db-head__text' }, title, h('span', { class: 'sr-only', text: t('popupSiteToggle'), attrs: { id: toggleLabel } })),
        h('div', { class: 'db-head__aside' }, s.locks.siteToggle ? lockIcon() : null, protect.el),
      );

      // ---- Tiles --------------------------------------------------------------
      const counts = { ...s.counts };
      const types: string[] = [];
      for (const e of s.recent) sampleType(types, e);
      const tiles = h('div', { class: 'site-tiles' });
      const paintTiles = (): void => {
        const blocked = counts.blocked + counts.redirected + counts.stripped + counts.debounced;
        const est = estimateFromSample(types, counts.blocked + counts.redirected);
        const data = fmtBytes(est.bytes);
        const time = fmtDuration(est.ms, savingsUnits());
        replace(
          tiles,
          statTile(fmtNumber(blocked), '', t('popupBlockedShort'), true),
          statTile(data.value, data.unit, t('popupDataSaved')),
          statTile(time.value, time.unit, t('popupTimeSaved')),
        );
        tiles.title = t('savingsEstimateNote');
      };
      paintTiles();
      if (s.counting) {
        const seen = new Set(s.recent.map(eventKey));
        live = connectLive(tabId, {
          event: (e) => {
            const key = eventKey(e);
            if (e.tabId !== tabId || seen.has(key)) return;
            seen.add(key);
            countEvent(counts, e);
            sampleType(types, e);
            paintTiles();
          },
          reset: (id) => {
            if (id === tabId) location.reload();
          },
        });
      }

      // ---- Per-site settings ------------------------------------------------
      const modeLabel = nextId('site');
      const mode = segmented<BlockingMode>({
        options: [
          { value: 'standard', label: t('modeStandard') },
          { value: 'aggressive', label: t('modeAggressive') },
        ],
        value: ss.mode,
        labelledBy: modeLabel,
        onChange: (v) => setSite({ mode: v }),
      });
      const fpLabel = nextId('site');
      const fp = segmented<FingerprintLevel>({
        options: [
          { value: 'off', label: t('fpOff') },
          { value: 'standard', label: t('fpStandard') },
          { value: 'strict', label: t('fpStrict') },
        ],
        value: ss.fingerprinting,
        labelledBy: fpLabel,
        onChange: (v) => setSite({ fingerprinting: v }),
      });
      const scriptsLabel = nextId('site');
      const scripts = switchControl({ checked: ss.blockScripts, labelledBy: scriptsLabel, onChange: (v) => setSite({ blockScripts: v }) });
      controls.push(scripts, fp, { setDisabled: (d) => mode.setDisabled(d || s.locks.mode) });

      const settings = h(
        'section',
        { class: 'db-group' },
        row(t('popupMode'), modeLabel, mode.el, s.locks.mode || s.locks.settings),
        row(t('popupFingerprinting'), fpLabel, fp.el, s.locks.settings),
        row(t('popupScripts'), scriptsLabel, scripts.el, s.locks.settings),
      );

      // ---- Matched rules and report -----------------------------------------
      const rulesBody = h('div', { class: 'site-rules__body' });
      const rulesCount = h('span', { class: 'site-rules__count num' });
      const matched = createMatchedPanel(rulesBody, rulesCount, tabId, dir());
      void getMeta().then((meta) => {
        if (meta) matched.setDirectory(new ListDirectory(meta));
      });
      // Nerd mode: upstream history links next to each filter, live with the switch.
      const nerdOn = async (): Promise<boolean> => {
        const c = await getConfig();
        return c.ok && c.data.settings.nerd?.enabled === true && c.data.settings.nerd.filterHistory !== false;
      };
      void nerdOn().then((on) => matched.setBlame(on));
      unsubscribe = onStoreChange(() => void nerdOn().then((on) => matched.setBlame(on)));
      const rules = h(
        'details',
        { class: 'site-rules' },
        h('summary', { class: 'db-row site-rules__summary' }, h('span', { class: 'db-row__label', text: t('siteRulesTitle') }), h('span', { class: 'db-row__ctl' }, rulesCount, icon('chevronRight', 14, 'site-rules__chev'))),
        rulesBody,
      );
      // getMatchedRules is quota-exempt in a user gesture: fetch when the user opens the list.
      rules.addEventListener('toggle', () => {
        if (rules.open) void matched.refresh();
      });
      void matched.refresh();

      const channel = s.managed.reportBrokenSite;
      const canReport = !(channel === 'none' || (channel === 'email' && !s.managed.supportEmail));
      const more = h(
        'section',
        { class: 'db-group' },
        rules,
        canReport
          ? h(
              'button',
              { class: 'db-row db-row--action', attrs: { type: 'button' }, on: { click: () => void startReport(s) } },
              h('span', { class: 'db-row__label', text: t('siteReport') }),
              h('span', { class: 'db-row__ctl' }, icon('chevronRight', 14)),
            )
          : null,
      );

      mount(root, head, tiles, settings, more, reloadBar);
      paintEnabled();
      // Keep the snapshot current for «Verkleinern» (the compact popup draws from it).
      collapseState = () => ({ ...s, counts: { ...counts } });
      if (handoff) {
        // The hand-off was a snapshot: catch up with blocks that happened meanwhile.
        void call<PopupState>({ type: 'popup:state', tabId }).then((fresh) => {
          if (!fresh.ok || !fresh.data || typeof fresh.data !== 'object') return;
          const f = normalisePopupState(fresh.data, tabId);
          Object.assign(counts, f.counts);
          types.length = 0;
          for (const e of f.recent) sampleType(types, e);
          paintTiles();
        });
      }
      if (!s.counting) tiles.replaceWith(notice(t('popupCountOff')));
    },
    dispose() {
      // collapseState stays: «Verkleinern» from another section still hands over the last numbers.
      live?.close();
      live = null;
      unsubscribe?.();
      unsubscribe = null;
      delete document.body.dataset.site;
    },
  };
}
