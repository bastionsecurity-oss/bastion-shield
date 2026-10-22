// Bastion Shield — dashboard «Website-Ausnahmen» (DB24–DB26, DB40): per-site
// settings (protection, blocking mode, script blocking, fingerprinting),
// add with an error under the field that names the fix, search with the
// counter «3 von 1'248», the limits (10'000 sites, 253 characters per host)
// shown before they are hit, remove with «Rückgängig», and import with a
// preview (D04). Sites forced by policy are read-only with a lock.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BlockingMode, EffectiveConfig, FingerprintLevel, SiteSettings, SitesMap } from '../../../shared/types.ts';
import { downloadText, h, pickNamedTextFile, replace, toast } from '../../shared/dom.ts';
import { fmtNumber, plural, t } from '../../shared/i18n.ts';
import { hostnameCandidates } from '../../../shared/hash.ts';
import { icon } from '../../shared/icons.ts';
import { confirmDialog, switchControl, undoToast } from '../../shared/controls.ts';
import { truncateMiddle } from '../../shared/text.ts';
import { emptyState, errorState, lockedNote, nextId, normaliseHost, openTabButton, pageHead, popupMode, retryView, type View, mount } from '../common.ts';
import { getConfig, getSites, isLocked, setSites } from '../store.ts';
import { tileEmpty } from './tile-empty.ts';
import { checkHost, MAX_HOST, MAX_SITES, nearLimit, parseSitesImport, searchHosts, summaryParts, type HostProblem } from '../sites-core.ts';

export { parseSitesImport } from '../sites-core.ts';

/** Rows drawn at once; «Weitere … anzeigen» adds the next batch. */
const PAGE = 200;

const PROBLEM_KEYS: Record<HostProblem, string> = {
  empty: 'sitesErrEmpty',
  long: 'sitesErrLong',
  chars: 'sitesErrChars',
  tld: 'sitesErrNoTld',
  scheme: 'sitesErrChars',
};

function fpLabel(level: FingerprintLevel): string {
  return t(level === 'off' ? 'fpOff' : level === 'strict' ? 'fpStrict' : 'fpStandard');
}
function modeLabel(mode: BlockingMode): string {
  return t(mode === 'aggressive' ? 'modeAggressive' : 'modeStandard');
}

/** Host cell text: cut in the middle (start and TLD stay), full host in the title. */
function hostEl(host: string, max: number): HTMLElement {
  return h('span', { class: 'sites-host__name mono', attrs: { title: host, translate: 'no' }, text: truncateMiddle(host, max) });
}

export function sitesView(): View {
  return {
    async render(root) {
      const [cfgR, sitesR] = await Promise.all([getConfig(), getSites()]);
      if (!cfgR.ok || !sitesR.ok) {
        mount(
          root,
          pageHead(t('sitesTitle'), popupMode ? undefined : t('sitesLead')),
          errorState(async () => {
            await getConfig(true);
            retryView();
          }),
        );
        return;
      }
      const cfg: EffectiveConfig = cfgR.data;
      let sites: SitesMap = sitesR.data;
      const policyOff = new Set((cfg.managed.disabledSites ?? []).map((s) => normaliseHost(s)).filter((s): s is string => !!s));
      const policyAggr = new Set((cfg.managed.aggressiveSites ?? []).map((s) => normaliseHost(s)).filter((s): s is string => !!s));
      // Pseudo-path 'sites.enabled': users may not switch protection off (allowUserSiteToggle: false).
      const userToggleLocked = cfg.locked.includes('sites.enabled') || cfg.managed.allowUserSiteToggle === false;
      const settingsLocked = isLocked(cfg, 'sites');
      const newHosts = new Set<string>();
      let query = '';
      let limit = PAGE;

      // sites:set answers { sites }: the user's map as stored (the SW may drop locked or no-op entries).
      const save = async (next: SitesMap): Promise<boolean> => {
        const r = await setSites(next);
        if (!r.ok) {
          toast(r.error === 'locked' ? t('lockedByPolicy') : t('errorSaveFailed'), icon(r.error === 'locked' ? 'lock' : 'alert', 15));
          return false;
        }
        sites = r.data;
        return true;
      };
      const patch = async (host: string, p: SiteSettings): Promise<boolean> => save({ ...sites, [host]: { ...(sites[host] ?? {}), ...p } });

      const allHosts = (): string[] => Array.from(new Set([...Object.keys(sites), ...policyOff, ...policyAggr])).sort((a, b) => a.localeCompare(b));
      const rowState = (host: string) => {
        const cands = hostnameCandidates(host);
        const forcedOff = cands.some((c) => policyOff.has(c));
        const forcedAggr = cands.some((c) => policyAggr.has(c));
        return { forcedOff, forcedAggr, locked: forcedOff || forcedAggr || cfg.locked.includes(`sites.${host}`) };
      };

      const listWrap = h('div', { class: 'sites-list-wrap' });
      const countEl = h('span', { class: 'sites-count', attrs: { 'aria-live': 'polite' } });
      const tools = h('div', { class: 'sites-tools' });
      const limitsNote = h('p', { class: 'sites-limits' });
      const resetBtn = h('button', { class: 'btn btn--quiet sites-reset', attrs: { type: 'button' }, text: t('sitesSearchReset') });
      const foot = h('div', { class: 'sites-foot' }, limitsNote, resetBtn);
      const exportBtn = h('button', { class: 'btn btn--outline', attrs: { type: 'button' } }, icon('download', 15), t('actionExport'));

      const remove = async (host: string): Promise<void> => {
        const prev = sites[host];
        if (!prev) return;
        const next = { ...sites };
        delete next[host];
        if (!(await save(next))) return;
        draw();
        undoToast(t('sitesRemoved', host), async () => {
          if (host in sites) return;
          if (await save({ ...sites, [host]: prev })) draw(host);
        });
      };

      const selectFor = <V extends string>(label: string, value: V | '', def: string, options: [V, string][], disabled: boolean, onChange: (v: V | '') => Promise<boolean>): HTMLSelectElement => {
        const sel = h(
          'select',
          { class: 'select sites-select', attrs: { 'aria-label': label, disabled } },
          h('option', { attrs: { value: '' }, text: t('sitesDefault', def) }),
          ...options.map(([v, text]) => h('option', { attrs: { value: v }, text })),
        );
        sel.value = value;
        let prev = value;
        sel.addEventListener('change', async () => {
          const v = sel.value as V | '';
          if (await onChange(v)) prev = v;
          else sel.value = prev;
        });
        return sel;
      };

      /** One row of the table (tab). */
      const tableRow = (host: string): HTMLElement => {
        const s = sites[host] ?? {};
        const st = rowState(host);
        const enabled = st.forcedOff ? false : s.enabled !== false;
        const sw = switchControl({
          checked: enabled,
          label: `${t('sitesColProtection')}: ${host}`,
          disabled: st.forcedOff || userToggleLocked || settingsLocked,
          onChange: (v) => patch(host, { enabled: v }),
        });
        const modeSel = selectFor<BlockingMode>(
          `${t('sitesColMode')}: ${host}`,
          st.forcedAggr ? 'aggressive' : (s.mode ?? ''),
          modeLabel(cfg.settings.defaultMode),
          [
            ['standard', t('modeStandard')],
            ['aggressive', t('modeAggressive')],
          ],
          st.forcedAggr || settingsLocked,
          (v) => {
            const next: SitesMap = { ...sites, [host]: { ...(sites[host] ?? {}) } };
            if (v) next[host].mode = v;
            else delete next[host].mode;
            return save(next);
          },
        );
        const scripts = switchControl({
          checked: !!s.blockScripts,
          label: `${t('sitesColScripts')}: ${host}`,
          disabled: settingsLocked,
          onChange: (v) => patch(host, { blockScripts: v }),
        });
        const fpSel = selectFor<FingerprintLevel>(
          `${t('sitesColFingerprinting')}: ${host}`,
          s.fingerprinting ?? '',
          fpLabel(cfg.settings.privacy.fingerprinting),
          [
            ['off', t('fpOff')],
            ['standard', t('fpStandard')],
            ['strict', t('fpStrict')],
          ],
          settingsLocked,
          (v) => {
            const next: SitesMap = { ...sites, [host]: { ...(sites[host] ?? {}) } };
            if (v) next[host].fingerprinting = v;
            else delete next[host].fingerprinting;
            return save(next);
          },
        );
        const removable = host in sites && !settingsLocked;
        const del = h('button', { class: 'icon-btn sites-del', attrs: { type: 'button', 'aria-label': t('sitesRemoveAria', host), title: t('actionRemove'), disabled: !removable } }, icon('trash', 16));
        del.addEventListener('click', () => void remove(host));
        return h(
          'tr',
          { class: newHosts.has(host) ? 'sites-row--new' : '', dataset: { host } },
          h(
            'th',
            { attrs: { scope: 'row' } },
            h(
              'span',
              { class: 'sites-host' },
              hostEl(host, 34),
              st.locked ? h('span', { class: 'sites-badge sites-badge--org', attrs: { title: t('lockedByPolicy') } }, icon('lock', 12), t('sitesOrgBadge')) : null,
              newHosts.has(host) ? h('span', { class: 'sites-badge sites-badge--new', text: t('sitesNewBadge') }) : null,
            ),
          ),
          h('td', null, sw.el),
          h('td', null, modeSel),
          h('td', null, scripts.el),
          h('td', null, fpSel),
          h('td', { class: 'sites-actions' }, del),
        );
      };

      /** One row of the compact list (expanded popup): host, one-line summary, protection switch. */
      const listRow = (host: string): HTMLElement => {
        const s = sites[host] ?? {};
        const st = rowState(host);
        const enabled = st.forcedOff ? false : s.enabled !== false;
        const sumId = nextId('site-sum');
        const sw = switchControl({
          checked: enabled,
          label: `${t('sitesColProtection')}: ${host}`,
          describedBy: sumId,
          disabled: st.forcedOff || userToggleLocked || settingsLocked,
          onChange: async (v) => {
            const ok = await patch(host, { enabled: v });
            if (ok) replace(summary, summaryText(host));
            return ok;
          },
        });
        const summaryText = (hst: string): string => {
          const cur = { ...(sites[hst] ?? {}), ...(rowState(hst).forcedAggr ? { mode: 'aggressive' as const } : {}), ...(rowState(hst).forcedOff ? { enabled: false } : {}) };
          return summaryParts(cur, cfg.settings.defaultMode)
            .map((p) => (p.key === 'off' ? t('sitesSumOff') : p.key === 'scripts' ? t('sitesSumScripts') : p.key === 'fp' ? t('sitesSumFp', fpLabel(p.level)) : modeLabel(p.mode)))
            .join(' - ');
        };
        const summary = st.locked ? lockedNote(sumId) : h('p', { class: 'sites-li__sum', attrs: { id: sumId }, text: summaryText(host) });
        return h('li', { class: `sites-li${st.locked ? ' sites-li--locked' : ''}`, dataset: { host } }, h('div', { class: 'sites-li__text' }, hostEl(host, 40), summary), sw.el);
      };

      const draw = (focusHost?: string): void => {
        const hosts = allHosts();
        const shown = searchHosts(hosts, query);
        const n = hosts.length;
        countEl.textContent = query
          ? t('sitesCountOf', [fmtNumber(shown.length), fmtNumber(n)])
          : popupMode
            ? fmtNumber(n)
          : nearLimit(n, MAX_SITES)
            ? t('sitesCountLimit', [fmtNumber(n), fmtNumber(MAX_SITES)])
            : plural(n, 'sitesCountOne', 'sitesCount');
        limitsNote.textContent = t('sitesLimits', [fmtNumber(MAX_SITES), fmtNumber(MAX_HOST)]);
        resetBtn.hidden = !query;
        exportBtn.disabled = Object.keys(sites).length === 0;
        tools.hidden = !n;
        if (!n) {
          foot.hidden = true;
          replace(listWrap, tileEmpty('sites', t('sitesEmptyTitle'), t('sitesEmptyText')));
          return;
        }
        foot.hidden = false;
        if (!shown.length) {
          replace(listWrap, emptyState(t('sitesNoMatch'), undefined, h('button', { class: 'btn btn--outline', attrs: { type: 'button' }, text: t('sitesSearchReset'), on: { click: clearSearch } })));
          return;
        }
        if (focusHost) {
          const at = shown.indexOf(focusHost);
          if (at >= limit) limit = Math.ceil((at + 1) / PAGE) * PAGE;
        }
        const page = shown.slice(0, limit);
        const more = shown.length - page.length;
        const moreBtn = more
          ? h('button', { class: 'btn btn--outline sites-more', attrs: { type: 'button' }, text: t('sitesShowMore', fmtNumber(Math.min(PAGE, more))) })
          : null;
        moreBtn?.addEventListener('click', () => {
          const first = page.length;
          limit += PAGE;
          draw();
          listWrap.querySelectorAll<HTMLElement>('[data-host]')[first]?.querySelector<HTMLElement>('button, [role="switch"], select')?.focus();
        });
        if (popupMode) {
          replace(listWrap, h('ul', { class: 'sites-list', attrs: { 'aria-label': t('sitesListTitle') } }, ...page.map(listRow)), moreBtn);
        } else {
          replace(
            listWrap,
            h(
              'div',
              { class: 'sites-scroll' },
              h(
                'table',
                { class: 'sites-table' },
                h('caption', { class: 'sr-only', text: t('sitesTitle') }),
                h(
                  'thead',
                  null,
                  h(
                    'tr',
                    null,
                    ...[t('sitesColSite'), t('sitesColProtection'), t('sitesColMode'), t('sitesColScripts'), t('sitesColFingerprinting')].map((c) => h('th', { text: c, attrs: { scope: 'col' } })),
                    h('th', { attrs: { scope: 'col' } }, h('span', { class: 'sr-only', text: t('actionRemove') })),
                  ),
                ),
                h('tbody', null, ...page.map(tableRow)),
              ),
            ),
            moreBtn,
          );
        }
        if (focusHost) {
          const row = listWrap.querySelector<HTMLElement>(`[data-host="${CSS.escape(focusHost)}"]`);
          row?.scrollIntoView({ block: 'nearest' });
          row?.querySelector<HTMLElement>('[role="switch"], .switch, button')?.focus();
        }
      };

      // ---- Search ------------------------------------------------------------------
      const search = h('input', { class: 'input sites-search__input', attrs: { type: 'search', placeholder: t('sitesSearch'), 'aria-label': t('sitesSearch'), spellcheck: 'false', autocomplete: 'off' } });
      search.addEventListener('input', () => {
        query = search.value;
        limit = PAGE;
        draw();
      });
      const clearSearch = (): void => {
        search.value = '';
        query = '';
        draw();
        search.focus();
      };
      resetBtn.addEventListener('click', clearSearch);
      const searchBox = h('label', { class: 'sites-search' }, icon('search', 16), search);

      // ---- Add form ------------------------------------------------------------------
      const addLabelId = nextId('sites-add');
      const msgId = nextId('sites-msg');
      const input = h('input', {
        class: 'input sites-add__input mono',
        attrs: { type: 'text', placeholder: t('sitesAddPlaceholder'), 'aria-labelledby': addLabelId, 'aria-describedby': msgId, spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off', inputmode: 'url', translate: 'no', disabled: settingsLocked },
      });
      const msg = h('p', { class: 'sites-add__msg', attrs: { id: msgId, 'aria-live': 'polite' } });
      const counter = h('span', { class: 'sites-add__count mono', attrs: { 'aria-live': 'polite' } });
      const showMsg = (text: string, error: boolean): void => {
        msg.textContent = text;
        msg.classList.toggle('sites-add__msg--error', error);
        input.setAttribute('aria-invalid', String(error));
      };
      const paintCounter = (): void => {
        const len = input.value.trim().length;
        counter.textContent = nearLimit(len, MAX_HOST) ? t('sitesCharCount', [fmtNumber(len), fmtNumber(MAX_HOST)]) : '';
        counter.classList.toggle('sites-add__count--over', len > MAX_HOST);
      };
      input.addEventListener('input', () => {
        paintCounter();
        if (input.getAttribute('aria-invalid') === 'true') showMsg(t('sitesAddHint'), false);
      });
      const addBtn = h('button', { class: 'btn btn--primary btn--h', attrs: { type: 'submit', disabled: settingsLocked } }, icon('plus', 15), t('sitesAdd'));
      const form = h(
        'form',
        { class: 'sites-add', attrs: { novalidate: true } },
        h('div', { class: 'sites-add__head' }, h('span', { class: 'sites-add__label', attrs: { id: addLabelId }, text: t('sitesAddTitle') }), counter),
        h('div', { class: 'sites-add__row' }, input, addBtn),
        msg,
      );
      showMsg(t('sitesAddHint'), false);
      form.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const c = checkHost(input.value);
        if (!c.ok) {
          showMsg(t(PROBLEM_KEYS[c.problem], fmtNumber(MAX_HOST)), true);
          input.focus();
          return;
        }
        const host = c.host;
        if (host in sites) {
          showMsg(t('sitesExists', host), true);
          draw(host);
          return;
        }
        if (Object.keys(sites).length >= MAX_SITES) {
          showMsg(t('sitesErrFull', fmtNumber(MAX_SITES)), true);
          return;
        }
        if (await save({ ...sites, [host]: { enabled: false } })) {
          input.value = '';
          paintCounter();
          showMsg(t('sitesAdded', host), false);
          newHosts.add(host);
          if (query && !host.includes(query.trim().toLowerCase())) {
            search.value = '';
            query = '';
          }
          draw(host);
          input.focus();
        }
      });

      // ---- Import / export ---------------------------------------------------------------
      exportBtn.addEventListener('click', () => {
        const stamp = new Date().toISOString().slice(0, 10);
        downloadText(`bastion-shield-sites-${stamp}.json`, `${JSON.stringify({ format: 'bastion-shield-sites', version: 1, exportedAt: new Date().toISOString(), sites }, null, 2)}\n`, 'application/json');
      });
      const importBtn = h('button', { class: 'btn btn--outline', attrs: { type: 'button', disabled: settingsLocked } }, icon('upload', 15), t('sitesImport'));
      importBtn.addEventListener('click', async () => {
        const file = await pickNamedTextFile('.json,.txt,application/json,text/plain', 20 * 1024 * 1024);
        if (file === null) return;
        const parsed = 'tooLarge' in file ? null : parseSitesImport(file.text);
        if (!parsed) {
          toast(t('sitesImportInvalid'), icon('alert', 15));
          return;
        }
        const hosts = Object.keys(parsed.sites);
        const n = hosts.length;
        const fresh = hosts.filter((x) => !(x in sites)).length;
        const over = Math.max(0, Object.keys(sites).length + fresh - MAX_SITES);
        const summary = (s: SiteSettings): string =>
          s.enabled === false ? t('sitesSumOff') : s.mode ? modeLabel(s.mode) : s.blockScripts ? t('sitesSumScripts') : s.fingerprinting ? t('sitesSumFp', fpLabel(s.fingerprinting)) : modeLabel(cfg.settings.defaultMode);
        const footParts: string[] = [];
        if (n > 3) footParts.push(t('sitesImportMore', fmtNumber(n - 3)));
        if (parsed.invalid) footParts.push(plural(parsed.invalid, 'sitesImportSkippedOne', 'sitesImportSkipped'));
        if (over) footParts.push(t('sitesImportOver', [fmtNumber(over), fmtNumber(MAX_SITES)]));
        const preview = h(
          'ul',
          { class: 'dialog-list' },
          ...hosts.slice(0, 3).map((x) => h('li', { class: 'dialog-list__row' }, h('span', { class: 'dialog-list__main mono', attrs: { title: x, translate: 'no' }, text: truncateMiddle(x, 32) }), h('span', { class: 'dialog-list__meta', text: summary(parsed.sites[x]) }))),
          footParts.length ? h('li', { class: 'dialog-list__row dialog-list__row--foot', text: footParts.join(' - ') }) : null,
        );
        const ok = await confirmDialog({
          title: plural(n, 'sitesImportTitleOne', 'sitesImportTitle'),
          body: t('sitesImportText'),
          icon: 'download',
          confirmLabel: t('sitesImportConfirm'),
          content: preview,
        });
        if (!ok) return;
        if (await save({ ...sites, ...parsed.sites })) {
          toast(plural(n, 'sitesImportedOne', 'sitesImported'), icon('check', 15));
          draw();
        }
      });

      const lockNotice = settingsLocked
        ? h(
            'div',
            { class: 'notice notice--lock', attrs: { role: 'status' } },
            icon('lock', 16),
            h('div', null, h('div', { class: 'notice__title', text: t('privLockedTitle') }), h('div', { class: 'notice__body', text: t('privLockedText') })),
          )
        : null;

      // Expanded popup: list and switches only. Adding, import and export happen in the tab
      // (typing and file dialogs do not survive the popup closing).
      if (!popupMode) tools.append(h('h2', { class: 'sites-title' }, h('span', { attrs: { id: 'sites-list-title' }, text: t('sitesListTitle') }), countEl), searchBox);
      if (popupMode) {
        const head = pageHead(t('sitesTitle'), undefined, openTabButton('sites', t('panelEditInTab')));
        head.querySelector('h1')?.append(' ', countEl);
        tools.append(searchBox);
        mount(root, head, lockNotice, tools, listWrap);
      } else {
        mount(
          root,
          pageHead(t('sitesTitle'), t('sitesLead'), h('div', { class: 'db-head__actions' }, importBtn, exportBtn)),
          lockNotice,
          form,
          h(
            'section',
            { class: 'sites-list-sec', attrs: { 'aria-labelledby': 'sites-list-title' } },
            tools,
            listWrap,
            foot,
          ),
        );
      }
      draw();
    },
  };
}
