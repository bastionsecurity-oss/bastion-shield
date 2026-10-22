// Bastion Shield — dashboard «Eigene Filter» (DB20–DB23): one bordered editor
// box (header with the counter «1'204 Zeilen - 38 KB von 1 MB», line gutter,
// monospace field, dark bar «3 Änderungen nicht angewendet» with «Verwerfen»
// and «Filter anwenden»), the result of a live check of every line (line
// number and reason, «Meinten Sie …?»), a short syntax reference, the
// guided builder behind a disclosure and the organisation's filters
// read-only. The editor applies at most 1 MB (as the service worker does);
// leaving with unapplied changes asks first (D06). Scriptlet filters (+js)
// need an extension release (MV3 forbids runtime code).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { CustomState } from '../../../shared/types.ts';
import { debounce, downloadText, h, pickNamedTextFile, replace, toast } from '../../shared/dom.ts';
import { fmtNumber, formatLocale, plural, t } from '../../shared/i18n.ts';
import { icon } from '../../shared/icons.ts';
import { choiceDialog } from '../../shared/controls.ts';
import { card, errorState, nextId, pageHead, retryView, type View, mount, withBusy } from '../common.ts';
import { getCustom, getMeta, setCustom } from '../store.ts';
import { shortcutLabel } from '../rail.ts';
import { appendLine, BUILDER_ACTIONS, buildFilter, type BuilderAction, type BuilderError, exportText, hasFilter, importedFilters, mergeFilters } from '../filter-builder.ts';
import { changeCount, checkFilters, ERRORS_LISTED, fmtLimit, fmtSize, LIVE_CHECK_MAX, lineCount, looksBinary, reasonFor, tooBig } from '../filters-core.ts';

const BUILDER_KEYS: Record<BuilderAction, { label: string; target: string; placeholder: string; hint: string; site: boolean }> = {
  'block-domain': { label: 'cfBuildBlockDomain', target: 'cfBuildDomain', placeholder: 'ads.example.com', hint: 'cfBuildBlockDomainHint', site: false },
  'block-script': { label: 'cfBuildBlockScript', target: 'cfBuildScript', placeholder: 'example.com/tracker.js', hint: 'cfBuildBlockScriptHint', site: true },
  'hide-element': { label: 'cfBuildHide', target: 'cfBuildSelector', placeholder: '.newsletter-popup', hint: 'cfBuildHideHint', site: true },
  'allow-site': { label: 'cfBuildAllow', target: 'cfBuildSite', placeholder: 'example.com', hint: 'cfBuildAllowHint', site: false },
};
const BUILDER_ERRORS: Record<BuilderError, string> = { domain: 'cfBuildErrDomain', script: 'cfBuildErrScript', selector: 'cfBuildErrSelector', site: 'cfBuildErrSite' };

const EXAMPLES: [string, string][] = [
  ['||ads.example.com^', 'cfExBlockDomain'],
  ['||example.com/t.js$script', 'cfExBlockFile'],
  ['example.com##.popup', 'cfExHide'],
  ['@@||example.com^$document', 'cfExAllow'],
];

/** Line height of the editor field and gutter (CSS .cf-field, .cf-gutter). */
const LINE_PX = 20;
const PAD_PX = 12;

type Report = CustomState['report'];

const units = (): { kb: string; mb: string } => ({ kb: t('cfUnitKB'), mb: t('cfUnitMB') });

/** «1'204 Zeilen - 38 KB von 1 MB» */
export function counterText(text: string): string {
  return t('cfCounter', [plural(lineCount(text), 'cfLinesOne', 'cfLines'), fmtSize(text.length, formatLocale, units()), fmtLimit(formatLocale, units())]);
}

function reasonText(code: string): string {
  const r = reasonFor(code);
  return t(r.key, r.subs);
}

export function filtersView(): View {
  let dirty = false;
  let changes = 0;
  /** Set while the view is shown: applies the editor (used by the leave dialog). */
  let applyNow: (() => Promise<boolean>) | null = null;
  const beforeUnload = (ev: BeforeUnloadEvent): void => {
    if (dirty) ev.preventDefault();
  };

  return {
    async render(root) {
      const r = await getCustom();
      if (!r.ok) {
        mount(root, pageHead(t('cfTitle'), t('cfLead')), errorState(retryView));
        return;
      }
      const meta = await getMeta();
      let state: CustomState = r.data;
      const locked = !!state.locked;
      const saved = (): string => state.text ?? '';

      // ---- Editor box --------------------------------------------------------
      const titleId = nextId('cf-title');
      const gutter = h('pre', { class: 'cf-gutter', attrs: { 'aria-hidden': 'true' } });
      const marks = h('div', { class: 'cf-marks', attrs: { 'aria-hidden': 'true' } });
      const area = h('textarea', {
        class: 'cf-field',
        attrs: {
          spellcheck: 'false',
          autocapitalize: 'off',
          autocomplete: 'off',
          wrap: 'off',
          translate: 'no',
          'aria-labelledby': titleId,
          'aria-describedby': 'cf-count cf-bar-text',
          readonly: locked,
        },
      });
      area.value = saved();
      const count = h('span', { class: 'cf-count mono', attrs: { id: 'cf-count' } });
      const head = h(
        'div',
        { class: 'cf-box__head' },
        h('span', { class: 'cf-box__title', attrs: { id: titleId }, text: locked ? t('cfEditorReadOnly') : t('cfEditorTitle') }),
        count,
      );

      const kbd = h('kbd', { class: 'cf-kbd', text: shortcutLabel('S').replace('+', '\u00a0') });
      const applyBtn = h('button', { class: 'btn cf-apply', attrs: { type: 'button' } }, icon('check', 15), h('span', { text: t('cfApply') }), kbd);
      const discardBtn = h('button', { class: 'btn btn--quiet cf-discard', attrs: { type: 'button' }, text: t('cfDiscard') });
      const barText = h('span', { class: 'cf-bar__text', attrs: { id: 'cf-bar-text', role: 'status' } });
      const bar = h('div', { class: 'cf-bar', hidden: true }, h('span', { class: 'cf-bar__dot', attrs: { 'aria-hidden': 'true' } }), barText, discardBtn, applyBtn);
      const box = h('div', { class: `cf-box${locked ? ' cf-box--locked' : ''}` }, head, h('div', { class: 'cf-box__body' }, gutter, h('div', { class: 'cf-box__field' }, marks, area)), bar);

      // ---- Result panel (live check; the service worker's report after «Filter anwenden») ----
      const resultSlot = h('div', { class: 'cf-result__body' });
      const result = h('section', { class: 'cf-result', attrs: { 'aria-labelledby': 'cf-result-title' } }, h('h2', { class: 'cf-side__title', attrs: { id: 'cf-result-title' }, text: t('cfReportTitle') }), resultSlot);
      const bannerSlot = h('div', { class: 'cf-banner' });

      let report: Report = state.report ?? { network: 0, cosmetic: 0, scriptletsIgnored: 0, errors: [] };
      let errorLines = new Set<number>();

      const jumpTo = (line: number): void => {
        const lines = area.value.split('\n');
        let pos = 0;
        for (let i = 0; i < line - 1 && i < lines.length; i++) pos += lines[i].length + 1;
        area.focus();
        area.setSelectionRange(pos, pos + (lines[line - 1]?.length ?? 0));
        area.scrollTop = Math.max(0, (line - 4) * LINE_PX);
        syncScroll();
      };

      const syncScroll = (): void => {
        gutter.scrollTop = area.scrollTop;
        marks.style.transform = `translateY(${-area.scrollTop}px)`;
      };

      const paintGutter = (): void => {
        const n = Math.max(1, lineCount(area.value));
        const frag = document.createDocumentFragment();
        let run = '';
        for (let i = 1; i <= n; i++) {
          if (errorLines.has(i)) {
            if (run) frag.append(run);
            run = '';
            frag.append(h('span', { class: 'cf-gutter__bad', text: `◆ ${i}` }));
            run += i < n ? '\n' : '';
          } else {
            run += i < n ? `${i}\n` : String(i);
          }
        }
        if (run) frag.append(run);
        gutter.replaceChildren(frag);
        const digits = String(n).length + (errorLines.size ? 2 : 0);
        gutter.style.width = `calc(${digits}ch + 24px)`;
        replace(marks, ...Array.from(errorLines).map((l) => h('div', { class: 'cf-mark', attrs: { style: `top:${PAD_PX + (l - 1) * LINE_PX}px` } })));
        syncScroll();
      };

      const paintResult = (): void => {
        errorLines = new Set(report.errors.map((e) => e.line).filter((l) => l > 0));
        paintGutter();
        const row = (label: string, value: number, bad = false): HTMLElement =>
          h('div', { class: `cf-stat${bad ? ' cf-stat--bad' : ''}` }, h('dt', { text: label }), h('dd', { class: 'mono', text: fmtNumber(value) }));
        const stats = h(
          'dl',
          { class: 'cf-stats' },
          row(t('cfReportNetwork'), report.network),
          row(t('cfReportCosmetic'), report.cosmetic),
          report.errors.length ? null : row(t('cfReportScriptlets'), report.scriptletsIgnored),
          row(t('cfReportErrors'), report.errors.length, report.errors.length > 0),
        );
        if (!report.errors.length) {
          replace(resultSlot, stats, h('p', { class: 'cf-ok' }, icon('check', 16), t('cfNoErrors')));
          return;
        }
        const list = h(
          'ol',
          { class: 'cf-errors' },
          ...report.errors.slice(0, ERRORS_LISTED).map((e) =>
            h(
              'li',
              { class: 'cf-err' },
              h('button', { class: 'cf-err__line', attrs: { type: 'button', 'aria-label': t('cfJumpToLine', fmtNumber(e.line)) }, on: { click: () => jumpTo(e.line) }, text: t('cfLine', fmtNumber(e.line)) }),
              h('code', { class: 'cf-err__text', attrs: { translate: 'no' }, text: e.text }),
              h('p', { class: 'cf-err__reason', text: reasonText(e.reason) }),
            ),
          ),
        );
        replace(resultSlot, stats, list, h('p', { class: 'cf-errors__note', text: t('cfErrorsNote', fmtNumber(ERRORS_LISTED)) }));
      };

      const paintState = (): void => {
        const text = area.value;
        const big = tooBig(text);
        count.textContent = counterText(text);
        count.classList.toggle('cf-count--bad', big);
        changes = changeCount(saved(), text);
        dirty = changes > 0;
        bar.hidden = !dirty || locked;
        const changesText = plural(changes, 'cfDirtyOne', 'cfDirty');
        const bad = report.errors.length;
        barText.textContent = big
          ? t('cfTooBigBar')
          : bad
            ? `${plural(changes, 'cfChangesOne', 'cfChanges')} - ${plural(bad, 'cfBadLinesOne', 'cfBadLines')}`
            : changesText;
        applyBtn.disabled = big || locked;
        replace(
          bannerSlot,
          big
            ? h(
                'div',
                { class: 'notice notice--danger', attrs: { role: 'alert' } },
                icon('alert', 16),
                h('div', null, h('div', { class: 'notice__title', text: t('cfTooLarge', [fmtSize(text.length, formatLocale, units()), fmtLimit(formatLocale, units())]) }), h('div', { class: 'notice__body', text: t('cfTooLargeText') })),
              )
            : null,
        );
      };

      // Live check while typing (debounced); large texts are checked on apply only.
      const check = (): void => {
        if (area.value.length <= LIVE_CHECK_MAX) {
          try {
            report = checkFilters(area.value, meta);
          } catch {
            /* keep the last report */
          }
        }
        paintResult();
        paintState();
      };
      const checkSoon = debounce(check, 250);

      area.addEventListener('input', () => {
        paintGutter();
        paintState();
        checkSoon();
      });
      area.addEventListener('scroll', syncScroll);
      area.addEventListener('keydown', (ev) => {
        // Ctrl/Cmd+S applies, as in any editor. Tab keeps its default (leave the field) for keyboard users.
        if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 's') {
          ev.preventDefault();
          if (dirty && !applyBtn.disabled) applyBtn.click();
        }
      });

      const apply = async (): Promise<boolean> => {
        if (locked || tooBig(area.value)) return false;
        const res = await setCustom(area.value);
        if (!res.ok) {
          toast(t('errorSaveFailed'), icon('alert', 15));
          return false;
        }
        state = { ...res.data, text: res.data.text ?? area.value };
        if (res.data.text !== undefined && res.data.text !== area.value) area.value = res.data.text;
        report = state.report ?? report;
        paintResult();
        paintState();
        const n = report.errors.length;
        toast(n ? plural(n, 'cfAppliedWithErrorsOne', 'cfAppliedWithErrors') : t('cfApplied'), icon('check', 15));
        return true;
      };
      applyNow = apply;
      applyBtn.addEventListener('click', () => {
        if (applyBtn.disabled) return;
        void withBusy(applyBtn, apply);
      });
      discardBtn.addEventListener('click', () => {
        area.value = saved();
        check();
        area.focus();
      });

      /** New text lands in the editor as an unsaved change; «Filter anwenden» stays the one way to save. */
      const setEditorText = (text: string): void => {
        area.value = text;
        check();
        area.scrollTop = area.scrollHeight;
        syncScroll();
      };

      // ---- Import / export (page head) ----------------------------------------
      const exportBtn = h('button', { class: 'btn btn--outline', attrs: { type: 'button', disabled: locked || saved() === '' } }, icon('download', 15), t('cfExport'));
      const importBtn = h('button', { class: 'btn btn--outline', attrs: { type: 'button', disabled: locked } }, icon('upload', 15), t('cfImport'));
      exportBtn.addEventListener('click', () => {
        const now = new Date();
        downloadText(`bastion-shield-filters-${now.toISOString().slice(0, 10)}.txt`, exportText(area.value, now), 'text/plain');
      });
      const importFile = async (): Promise<void> => {
        if (locked) return;
        const file = await pickNamedTextFile('.txt,.json,text/plain,application/json', 20 * 1024 * 1024);
        if (file === null) return;
        if ('tooLarge' in file) {
          toast(t('cfTooLarge', [`> ${fmtSize(20_000_000, formatLocale, units())}`, fmtLimit(formatLocale, units())]), icon('alert', 15));
          return;
        }
        const filters = looksBinary(file.text) ? null : importedFilters(file.text);
        if (filters === null) {
          toast(t('cfImportInvalid', file.name), icon('alert', 15), { action: { label: t('cfImportOther'), run: importFile } });
          return;
        }
        const merged = mergeFilters(area.value, filters);
        if (!merged.added) {
          toast(t('cfImportNothing'), icon('info', 15));
          return;
        }
        setEditorText(merged.text);
        toast(plural(merged.added, 'cfImportedOne', 'cfImported'), icon('check', 15));
      };
      importBtn.addEventListener('click', () => void importFile());

      // ---- Guided builder (behind a disclosure) ---------------------------------
      const actionId = nextId('cfb-action');
      const targetId = nextId('cfb-target');
      const siteId = nextId('cfb-site');
      const previewId = nextId('cfb-preview');
      const actionSel = h('select', { class: 'select', attrs: { id: actionId, disabled: locked } }, ...BUILDER_ACTIONS.map((a) => h('option', { attrs: { value: a }, text: t(BUILDER_KEYS[a].label) })));
      const targetLabel = h('label', { class: 'cfb-label', attrs: { for: targetId } });
      const fieldAttrs = { type: 'text', spellcheck: 'false', autocapitalize: 'off', autocomplete: 'off', disabled: locked, translate: 'no' };
      const targetIn = h('input', { class: 'input mono', attrs: { ...fieldAttrs, id: targetId, 'aria-describedby': previewId } });
      const siteIn = h('input', { class: 'input mono', attrs: { ...fieldAttrs, id: siteId, placeholder: t('cfBuildSiteAny') } });
      const siteField = h('div', { class: 'cfb-field' }, h('label', { class: 'cfb-label', attrs: { for: siteId }, text: t('cfBuildOnlyOn') }), siteIn);
      const addBtn = h('button', { class: 'btn btn--outline', attrs: { type: 'button', disabled: true } }, icon('plus', 15), t('cfBuildAdd'));
      const hint = h('p', { class: 'cfb-hint' });
      const preview = h('p', { class: 'cfb-preview', attrs: { id: previewId, 'aria-live': 'polite' } });

      const builderInput = () => ({ action: actionSel.value as BuilderAction, target: targetIn.value, site: siteIn.value });
      const paintBuilder = (): void => {
        const keys = BUILDER_KEYS[actionSel.value as BuilderAction];
        targetLabel.textContent = t(keys.target);
        targetIn.placeholder = keys.placeholder;
        siteField.hidden = !keys.site;
        hint.textContent = t(keys.hint);
        if (!targetIn.value.trim()) {
          addBtn.disabled = true;
          replace(preview);
          return;
        }
        const res = buildFilter(builderInput());
        addBtn.disabled = locked || !res.ok;
        if (res.ok) replace(preview, h('span', { class: 'cfb-preview__label', text: t('cfBuildPreview') }), h('code', { text: res.filter, attrs: { translate: 'no' } }));
        else replace(preview, h('span', { class: 'cfb-preview__err' }, icon('alert', 13), t(BUILDER_ERRORS[res.error])));
      };
      const addFilter = (): void => {
        const res = buildFilter(builderInput());
        if (!res.ok || locked) return;
        if (hasFilter(area.value, res.filter)) {
          toast(t('cfBuildDuplicate'), icon('info', 15));
          return;
        }
        setEditorText(appendLine(area.value, res.filter));
        toast(t('cfBuildAdded'), icon('check', 15));
        targetIn.value = '';
        paintBuilder();
        targetIn.focus();
      };
      actionSel.addEventListener('change', paintBuilder);
      targetIn.addEventListener('input', paintBuilder);
      siteIn.addEventListener('input', paintBuilder);
      for (const el of [targetIn, siteIn]) {
        el.addEventListener('keydown', (ev) => {
          if (ev.key !== 'Enter') return;
          ev.preventDefault();
          addFilter();
        });
      }
      addBtn.addEventListener('click', addFilter);
      paintBuilder();

      const builder = h(
        'details',
        { class: 'cfb' },
        h(
          'summary',
          { class: 'cfb__summary' },
          icon('chevronRight', 12, 'cfb__chev'),
          h('span', { class: 'cfb__titles' }, h('span', { class: 'cfb__title', text: t('cfBuildTitle') }), h('span', { class: 'cfb__sub', text: t('cfBuildSub') })),
        ),
        h(
          'div',
          { class: 'cfb__body' },
          h(
            'div',
            { class: 'cfb-row' },
            h('div', { class: 'cfb-field' }, h('label', { class: 'cfb-label', attrs: { for: actionId }, text: t('cfBuildAction') }), actionSel),
            h('div', { class: 'cfb-field cfb-field--grow' }, targetLabel, targetIn),
            siteField,
            addBtn,
          ),
          hint,
          preview,
        ),
      );

      window.addEventListener('beforeunload', beforeUnload);

      const admin = state.admin ?? [];
      const reference = h(
        'section',
        { class: 'cf-ref', attrs: { 'aria-labelledby': 'cf-ref-title' } },
        h('h2', { class: 'cf-side__title', attrs: { id: 'cf-ref-title' }, text: t('cfSyntaxTitle') }),
        h('dl', { class: 'cf-examples' }, ...EXAMPLES.map(([code, key]) => h('div', null, h('dt', null, h('code', { text: code, attrs: { translate: 'no' } })), h('dd', { text: t(key) })))),
        h('a', { class: 'ext-link cf-ref__link', attrs: { href: 'https://github.com/gorhill/uBlock/wiki/Static-filter-syntax', target: '_blank', rel: 'noopener noreferrer' } }, t('cfSyntaxLink'), icon('external', 12)),
      );

      mount(
        root,
        pageHead(t('cfTitle'), t('cfLead'), h('div', { class: 'db-head__actions' }, importBtn, exportBtn)),
        h(
          'div',
          { class: 'cf-layout' },
          h(
            'div',
            { class: 'cf-main' },
            locked
              ? h(
                  'div',
                  { class: 'notice notice--lock', attrs: { role: 'status' } },
                  icon('lock', 16),
                  h('div', null, h('div', { class: 'notice__title', text: t('cfLockedTitle') }), h('div', { class: 'notice__body', text: t('cfLockedText') })),
                )
              : null,
            bannerSlot,
            box,
            locked ? null : builder,
            admin.length
              ? card(
                  { title: t('cfAdminTitle'), aside: h('span', { class: 'cf-admin__count' }, icon('lock', 12), plural(admin.length, 'cfAdminCountOne', 'cfAdminCount')), class: 'cf-admin' },
                  h('pre', { class: 'cf-admin__pre', attrs: { translate: 'no', tabindex: 0, 'aria-label': t('cfAdminTitle') }, text: admin.join('\n') }),
                )
              : null,
          ),
          h('aside', { class: 'cf-side' }, result, reference),
        ),
      );
      check();
    },
    async canLeave() {
      if (!dirty) return true;
      const choice = await choiceDialog({
        title: t('cfLeaveTitle'),
        body: plural(changes, 'cfLeaveTextOne', 'cfLeaveText'),
        icon: 'filters',
        choices: [
          { value: 'apply', label: t('cfApply'), primary: true },
          { value: 'discard', label: t('cfRevert'), danger: true },
        ],
      });
      if (choice === 'discard') {
        dirty = false;
        return true;
      }
      if (choice === 'apply' && applyNow) {
        const ok = await applyNow();
        if (ok) dirty = false;
        return ok;
      }
      return false;
    },
    dispose() {
      applyNow = null;
      window.removeEventListener('beforeunload', beforeUnload);
    },
  };
}
