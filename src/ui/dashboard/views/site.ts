// Bastion Shield — «Diese Website» (expanded popup only; Paper DB05–DB07):
// protection switch for the current site, blocked count with the data and
// time estimate, the per-site blocking mode, fingerprinting level and script
// blocking, the DNR rules that matched on the page, «Seite defekt? Melden…»
// and the reload bar after a change. Long hosts wrap (cut in the middle past
// 64 characters, full host in `title`); rows locked by the organisation say so.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BlockingMode, FingerprintLevel, PopupState, SiteSettings } from '../../../shared/types.ts';
import { h, replace } from '../../shared/dom.ts';
import { fmtNumber, t } from '../../shared/i18n.ts';
import { icon } from '../../shared/icons.ts';
import { call, connectLive, type LiveConnection } from '../../shared/messaging.ts';
import { notice, segmented, switchControl } from '../../shared/controls.ts';
import { estimateFromSample, fmtBytes, fmtDuration, savingsUnits } from '../../shared/savings.ts';
import { countEvent, eventKey, sampleType } from '../../shared/page-activity.ts';
import { truncateMiddle, withUnit } from '../../shared/text.ts';
import { createMatchedPanel } from '../../popup/matched.ts';
import { startReport } from '../../popup/report.ts';
import { setSiteSettings } from '../../popup/site-set.ts';
import { normalisePopupState } from '../../popup/state.ts';
import { errorState, nextId, popupTabId, retryView, statTile, withBusy, type View, mount } from '../common.ts';
import { readHandoff } from '../../shared/handoff.ts';
import { dir, getConfig, getMeta, onStoreChange } from '../store.ts';
import { ListDirectory } from '../../shared/labels.ts';

/** Hosts longer than this are cut in the middle (the title wraps over at most two lines). */
export const SITE_HOST_MAX = 64;

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

function row(label: string, labelId: string, control: HTMLElement, hint?: string): HTMLElement {
  return h(
    'div',
    { class: 'db-row' },
    h('div', { class: 'db-row__text' }, h('div', { class: 'db-row__label', text: label, attrs: { id: labelId } }), hint ? h('p', { class: 'db-row__desc', text: hint }) : null),
    h('div', { class: 'db-row__ctl' }, control),
  );
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
          mount(root, h('header', { class: 'db-head' }, h('div', { class: 'db-head__text' }, h('h1', { class: 'db-head__title', text: t('navSite'), attrs: { tabindex: -1 } }))), errorState(retryView));
          return;
        }
        tabId = id;
        raw = res.data;
      }
      const s = normalisePopupState(raw, tabId);
      const site = s.site ?? s.host;
      const fullHost = s.host ?? s.site ?? '';
      const title = h('h1', {
        class: 'db-head__title site-host',
        text: fullHost ? truncateMiddle(fullHost, SITE_HOST_MAX) : t('navSite'),
        attrs: { tabindex: -1, translate: fullHost ? 'no' : undefined, title: fullHost.length > SITE_HOST_MAX ? fullHost : undefined },
      });
      const eyebrow = h('p', { class: 'site-eyebrow', text: t('navSite') });

      if (s.globallyDisabled || !s.filterable || !site) {
        mount(
          root,
          h('header', { class: 'db-head site-head' }, h('div', { class: 'db-head__text' }, fullHost ? eyebrow : null, title)),
          s.globallyDisabled ? notice(t('dashPausedTitle'), t('dashPausedText')) : notice(t('popupUnfilterableTitle'), t('popupUnfilterableText')),
        );
        return;
      }

      // ---- Reload bar (after a per-site change; DB06) ------------------------
      const reloadBtn = h('button', { class: 'btn site-reload__btn', attrs: { type: 'button' } }, t('siteReloadAction'));
      const reloadBar = h(
        'div',
        { class: 'site-reload', attrs: { role: 'status', hidden: true } },
        h('span', { class: 'site-reload__tile', attrs: { 'aria-hidden': 'true' } }, icon('reload', 15)),
        h('span', { class: 'site-reload__text', text: t('popupReloadBar') }),
        reloadBtn,
      );
      reloadBtn.addEventListener('click', () =>
        void withBusy(reloadBtn, async () => {
          try {
            await chrome.tabs.reload(tabId);
          } catch {
            /* tab may be gone */
          }
          reloadBar.hidden = true;
          document.body.classList.remove('has-reload-bar');
        }),
      );

      const setSite = async (patch: SiteSettings): Promise<boolean> => {
        const ok = await setSiteSettings(s, tabId, patch);
        if (ok) {
          reloadBar.hidden = false;
          // The bar must not cover the last rows: the content gets room below it.
          document.body.classList.add('has-reload-bar');
        }
        return ok;
      };

      // ---- Header with the protection switch --------------------------------
      const ss = s.siteSettings;
      const toggleLabel = nextId('site');
      const toggleState = h('span', { class: 'site-toggle__state', attrs: { id: toggleLabel, 'aria-hidden': 'true' } });
      const controls: { setDisabled(d: boolean): void }[] = [];
      const offSlot = h('div', { class: 'site-off-slot' });
      const protect = switchControl({
        checked: ss.enabled,
        label: t('popupSiteToggle'),
        large: true,
        disabled: s.locks.siteToggle,
        onChange: async (v) => {
          const ok = await setSite({ enabled: v });
          if (ok) s.siteSettings.enabled = v;
          paintEnabled();
          return ok;
        },
      });
      const head = h(
        'header',
        { class: 'db-head site-head' },
        h('div', { class: 'db-head__text' }, eyebrow, title),
        h('div', { class: 'db-head__aside site-toggle' }, toggleState, protect.el),
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
          statTile(withUnit(data.value, data.unit), '', t('popupDataSaved')),
          statTile(withUnit(time.value, time.unit), '', t('popupTimeSaved')),
        );
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
      controls.push(
        { setDisabled: (d) => scripts.setDisabled(d || s.locks.settings) },
        { setDisabled: (d) => fp.setDisabled(d || s.locks.settings) },
        { setDisabled: (d) => mode.setDisabled(d || s.locks.mode || s.locks.settings) },
      );
      const lockedAny = s.locks.mode || s.locks.settings;
      const lockNote = lockedAny
        ? h('p', { class: 'db-locked site-locked' }, icon('lock', 12), h('span', { text: t(s.locks.settings ? 'siteLockedAll' : 'siteLockedMode') }))
        : null;

      const settings = h(
        'section',
        { class: 'db-group site-settings', attrs: { 'aria-label': t('navSite') } },
        row(t('popupMode'), modeLabel, mode.el),
        row(t('popupFingerprinting'), fpLabel, fp.el),
        row(t('popupScripts'), scriptsLabel, scripts.el, t('siteScriptsHint')),
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
        h('summary', { class: 'db-row site-rules__summary' }, icon('chevronRight', 12, 'site-rules__chev'), h('span', { class: 'db-row__label site-rules__label', text: t('siteRulesTitle') }), rulesCount),
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
        { class: 'db-group site-more' },
        rules,
        canReport
          ? h(
              'button',
              { class: 'db-row db-row--action site-report', attrs: { type: 'button' }, on: { click: () => void startReport(s) } },
              icon('flag', 14),
              h('span', { class: 'db-row__label', text: t('siteReport') }),
              icon('chevronRight', 12, 'site-report__chev'),
            )
          : null,
      );

      const paintEnabled = (): void => {
        const on = s.siteSettings.enabled;
        for (const c of controls) c.setDisabled(!on);
        toggleState.textContent = t(on ? 'popupProtectionOn' : 'popupProtectionOff');
        document.body.dataset.site = on ? 'on' : 'off';
        settings.classList.toggle('site-settings--off', !on || lockedAny);
        // DB07: protection off replaces the figures with one quiet notice.
        tiles.hidden = !on || !s.counting;
        replace(
          offSlot,
          !on
            ? h(
                'div',
                { class: 'site-off', attrs: { role: 'status' } },
                h('span', { class: 'site-off__tile', attrs: { 'aria-hidden': 'true' } }, icon('privacy', 16)),
                h('div', null, h('p', { class: 'site-off__title', text: t('siteOffTitle') }), h('p', { class: 'site-off__text', text: t('siteOffText') })),
              )
            : !s.counting
              ? notice(t('popupCountOff'))
              : null,
        );
      };

      mount(root, head, tiles, offSlot, lockNote, settings, more, reloadBar);
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
    },
    dispose() {
      // collapseState stays: «Verkleinern» from another section still hands over the last numbers.
      live?.close();
      live = null;
      unsubscribe?.();
      unsubscribe = null;
      delete document.body.dataset.site;
      document.body.classList.remove('has-reload-bar');
    },
  };
}
