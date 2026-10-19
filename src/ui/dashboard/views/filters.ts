// Bastion Shield — dashboard «Eigene Filter»: monospace editor with line
// numbers for the user's own filters (uBO/ABP syntax), apply button, compile
// report with per-line errors, and the organisation's admin filters shown
// read-only. Below the editor a guided builder writes common filters for
// people who don't know the syntax; the list exports / imports as a plain .txt
// filter list. Scriptlet filters (+js) need an extension release (MV3 forbids
// runtime code), which the page says plainly.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { CustomState } from '../../../shared/types.ts';
import { downloadText, h, pickTextFile, replace, toast } from '../../shared/dom.ts';
import { fmtNumber, plural, t } from '../../shared/i18n.ts';
import { icon } from '../../shared/icons.ts';
import { confirmDialog, lockBadge, notice } from '../../shared/controls.ts';
import { errorState, nextId, pageHead, panel, type View, mount } from '../common.ts';
import { getCustom, setCustom } from '../store.ts';
import { appendLine, BUILDER_ACTIONS, buildFilter, type BuilderAction, type BuilderError, exportText, hasFilter, importedFilters, mergeFilters } from '../filter-builder.ts';

const BUILDER_KEYS: Record<BuilderAction, { label: string; target: string; placeholder: string; hint: string; site: boolean }> = {
  'block-domain': { label: 'cfBuildBlockDomain', target: 'cfBuildDomain', placeholder: 'ads.example.com', hint: 'cfBuildBlockDomainHint', site: false },
  'block-script': { label: 'cfBuildBlockScript', target: 'cfBuildScript', placeholder: 'example.com/tracker.js', hint: 'cfBuildBlockScriptHint', site: true },
  'hide-element': { label: 'cfBuildHide', target: 'cfBuildSelector', placeholder: '.newsletter-popup', hint: 'cfBuildHideHint', site: true },
  'allow-site': { label: 'cfBuildAllow', target: 'cfBuildSite', placeholder: 'example.com', hint: 'cfBuildAllowHint', site: false },
};
const BUILDER_ERRORS: Record<BuilderError, string> = { domain: 'cfBuildErrDomain', script: 'cfBuildErrScript', selector: 'cfBuildErrSelector', site: 'cfBuildErrSite' };

const MAX_CHARS = 2_000_000;

const EXAMPLES: [string, string][] = [
  ['||ads.example.com^', 'cfExBlockDomain'],
  ['||example.com/tracker.js$script', 'cfExBlockFile'],
  ['example.com##.newsletter-popup', 'cfExHide'],
  ['@@||example.com^$document', 'cfExAllow'],
];

export function filtersView(): View {
  let dirty = false;
  const beforeUnload = (ev: BeforeUnloadEvent): void => {
    if (dirty) ev.preventDefault();
  };

  return {
    async render(root) {
      const r = await getCustom();
      if (!r.ok) {
        mount(root, pageHead(t('cfTitle'), t('cfLead')), errorState(() => location.reload()));
        return;
      }
      let state: CustomState = r.data;
      const locked = !!state.locked;

      const gutter = h('pre', { class: 'cf-gutter', attrs: { 'aria-hidden': 'true' } });
      const area = h('textarea', {
        class: 'cf-area',
        attrs: { spellcheck: 'false', autocapitalize: 'off', autocomplete: 'off', wrap: 'off', 'aria-label': t('cfEditorLabel'), 'aria-describedby': 'cf-status', readonly: locked },
      });
      area.value = state.text ?? '';
      const status = h('span', { class: 'cf-status', attrs: { id: 'cf-status', role: 'status' } });
      const applyBtn = h('button', { class: 'btn btn--primary', attrs: { type: 'button', disabled: true } }, icon('check', 15), t('actionApply'));
      const revertBtn = h('button', { class: 'btn btn--ghost', attrs: { type: 'button', disabled: true }, text: t('cfRevert') });
      const exportBtn = h('button', { class: 'btn btn--ghost', attrs: { type: 'button' } }, icon('download', 15), t('cfExport'));
      const importBtn = h('button', { class: 'btn btn--ghost', attrs: { type: 'button', disabled: locked } }, icon('upload', 15), t('cfImport'));
      const reportSlot = h('div', { class: 'cf-report' });
      let errorLines = new Set<number>();

      const paintGutter = (): void => {
        const n = Math.max(1, area.value.split('\n').length);
        const parts: string[] = [];
        for (let i = 1; i <= n; i++) parts.push(errorLines.has(i) ? `◆ ${i}` : String(i));
        gutter.textContent = parts.join('\n');
        gutter.scrollTop = area.scrollTop;
      };
      const setDirty = (d: boolean): void => {
        dirty = d;
        applyBtn.disabled = !d || locked;
        revertBtn.disabled = !d;
        status.textContent = d ? t('cfUnsaved') : '';
      };

      const jumpTo = (line: number): void => {
        const lines = area.value.split('\n');
        let pos = 0;
        for (let i = 0; i < line - 1 && i < lines.length; i++) pos += lines[i].length + 1;
        area.focus();
        area.setSelectionRange(pos, pos + (lines[line - 1]?.length ?? 0));
        // Approximate scroll: line height is fixed in CSS (20px).
        area.scrollTop = Math.max(0, (line - 4) * 20);
      };

      const paintReport = (): void => {
        const rep = state.report ?? { network: 0, cosmetic: 0, scriptletsIgnored: 0, errors: [] };
        errorLines = new Set(rep.errors.map((e) => e.line));
        paintGutter();
        const stats = h(
          'dl',
          { class: 'cf-stats' },
          h('div', null, h('dt', { text: t('cfReportNetwork') }), h('dd', { class: 'num', text: fmtNumber(rep.network) })),
          h('div', null, h('dt', { text: t('cfReportCosmetic') }), h('dd', { class: 'num', text: fmtNumber(rep.cosmetic) })),
          h('div', null, h('dt', { text: t('cfReportScriptlets') }), h('dd', { class: 'num', text: fmtNumber(rep.scriptletsIgnored) })),
          h('div', null, h('dt', { text: t('cfReportErrors') }), h('dd', { class: 'num', text: fmtNumber(rep.errors.length) })),
        );
        const errs = rep.errors.length
          ? h(
              'ol',
              { class: 'cf-errors' },
              ...rep.errors.slice(0, 200).map((e) =>
                h(
                  'li',
                  null,
                  h(
                    'button',
                    { class: 'cf-errors__line', attrs: { type: 'button', 'aria-label': t('cfJumpToLine', String(e.line)) }, on: { click: () => jumpTo(e.line) } },
                    h('span', { class: 'mono', text: t('cfLine', String(e.line)) }),
                  ),
                  h('div', { class: 'cf-errors__body' }, h('code', { class: 'cf-errors__text', text: e.text }), h('span', { class: 'cf-errors__reason', text: e.reason })),
                ),
              ),
            )
          : h('p', { class: 'cf-ok' }, icon('check', 14), t('cfNoErrors'));
        replace(reportSlot, stats, errs);
      };

      area.addEventListener('input', () => {
        paintGutter();
        setDirty(area.value !== (state.text ?? ''));
      });
      area.addEventListener('scroll', () => {
        gutter.scrollTop = area.scrollTop;
      });
      area.addEventListener('keydown', (ev) => {
        // Ctrl/Cmd+S applies, as in any editor. Tab keeps its default (leave the field) for keyboard users.
        if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 's') {
          ev.preventDefault();
          if (!applyBtn.disabled) applyBtn.click();
        }
      });

      applyBtn.addEventListener('click', async () => {
        if (locked) return;
        if (area.value.length > MAX_CHARS) {
          toast(t('cfTooLarge'), icon('alert', 15));
          return;
        }
        applyBtn.disabled = true;
        status.textContent = t('cfApplying');
        const res = await setCustom(area.value);
        if (!res.ok) {
          status.textContent = '';
          applyBtn.disabled = false;
          toast(t('errorSaveFailed'), icon('alert', 15));
          return;
        }
        state = { ...res.data, text: res.data.text ?? area.value };
        if (res.data.text !== undefined && res.data.text !== area.value) area.value = res.data.text;
        setDirty(false);
        paintReport();
        const n = state.report?.errors.length ?? 0;
        status.textContent = n ? plural(n, 'cfAppliedWithErrorsOne', 'cfAppliedWithErrors') : t('cfApplied');
        toast(t('cfApplied'), icon('check', 15));
      });
      revertBtn.addEventListener('click', () => {
        area.value = state.text ?? '';
        paintGutter();
        setDirty(false);
      });

      /** New text lands in the editor as an unsaved change; Apply stays the one way to save. */
      const setEditorText = (text: string): void => {
        area.value = text;
        paintGutter();
        setDirty(area.value !== (state.text ?? ''));
        area.scrollTop = area.scrollHeight;
        gutter.scrollTop = area.scrollTop;
      };

      exportBtn.addEventListener('click', () => {
        const now = new Date();
        downloadText(`bastion-shield-filters-${now.toISOString().slice(0, 10)}.txt`, exportText(area.value, now), 'text/plain');
      });
      importBtn.addEventListener('click', async () => {
        if (locked) return;
        const raw = await pickTextFile('.txt,.json,text/plain,application/json');
        if (raw === null) return;
        const filters = importedFilters(raw);
        if (filters === null) {
          toast(t('cfImportInvalid'), icon('alert', 15));
          return;
        }
        const merged = mergeFilters(area.value, filters);
        if (!merged.added) {
          toast(t('cfImportNothing'), icon('info', 15));
          return;
        }
        if (merged.text.length > MAX_CHARS) {
          toast(t('cfTooLarge'), icon('alert', 15));
          return;
        }
        setEditorText(merged.text);
        toast(plural(merged.added, 'cfImportedOne', 'cfImported'), icon('check', 15));
      });

      // Guided builder: pick what to do, fill in the blank, the line goes into the editor.
      const actionId = nextId('cfb-action');
      const targetId = nextId('cfb-target');
      const siteId = nextId('cfb-site');
      const previewId = nextId('cfb-preview');
      const actionSel = h('select', { class: 'select', attrs: { id: actionId, disabled: locked } }, ...BUILDER_ACTIONS.map((a) => h('option', { attrs: { value: a }, text: t(BUILDER_KEYS[a].label) })));
      const targetLabel = h('label', { class: 'cfb-label', attrs: { for: targetId } });
      const fieldAttrs = { type: 'text', spellcheck: 'false', autocapitalize: 'off', autocomplete: 'off', disabled: locked };
      const targetIn = h('input', { class: 'input mono', attrs: { ...fieldAttrs, id: targetId, 'aria-describedby': previewId } });
      const siteIn = h('input', { class: 'input mono', attrs: { ...fieldAttrs, id: siteId, placeholder: t('cfBuildSiteAny') } });
      const siteField = h('div', { class: 'cfb-field' }, h('label', { class: 'cfb-label', attrs: { for: siteId }, text: t('cfBuildOnlyOn') }), siteIn);
      const addBtn = h('button', { class: 'btn btn--secondary', attrs: { type: 'button', disabled: true } }, icon('plus', 15), t('cfBuildAdd'));
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
        if (res.ok) replace(preview, h('span', { class: 'cfb-preview__label', text: t('cfBuildPreview') }), h('code', { text: res.filter }));
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
        status.textContent = t('cfBuildAdded');
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

      const builder = panel(
        { title: t('cfBuildTitle'), aside: locked ? lockBadge() : null, class: 'cfb' },
        h('p', { class: 'db-muted cfb-lead', text: t('cfBuildLead') }),
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
      );

      window.addEventListener('beforeunload', beforeUnload);

      const editor = h('div', { class: `cf-editor${locked ? ' cf-editor--locked' : ''}` }, gutter, area);
      const admin = state.admin ?? [];

      mount(root, 
        pageHead(t('cfTitle'), t('cfLead')),
        locked ? h('div', { class: 'db-gap' }, notice(t('cfLockedTitle'), t('cfLockedText'), 'info')) : null,
        h(
          'div',
          { class: 'cf-layout' },
          h(
            'div',
            { class: 'cf-main' },
            panel({ title: t('cfEditorTitle'), aside: locked ? lockBadge() : null, flush: true, class: 'cf-panel' }, editor, h('div', { class: 'cf-actions' }, applyBtn, revertBtn, status, h('span', { class: 'cf-actions__file' }, importBtn, exportBtn))),
            builder,
            admin.length
              ? panel(
                  { title: t('cfAdminTitle'), aside: lockBadge(), class: 'cf-admin' },
                  h('p', { class: 'db-muted', text: plural(admin.length, 'cfAdminTextOne', 'cfAdminText') }),
                  h('pre', { class: 'cf-admin__pre', text: admin.join('\n') }),
                )
              : null,
          ),
          h(
            'aside',
            { class: 'cf-side' },
            panel({ title: t('cfReportTitle') }, reportSlot),
            panel(
              { title: t('cfSyntaxTitle') },
              h(
                'dl',
                { class: 'cf-examples' },
                ...EXAMPLES.map(([code, key]) => h('div', null, h('dt', null, h('code', { text: code })), h('dd', { text: t(key) }))),
              ),
              h('p', { class: 'cf-note' }, icon('info', 14), h('span', { text: t('cfScriptletNote') })),
              h('a', { class: 'ext-link', attrs: { href: 'https://github.com/gorhill/uBlock/wiki/Static-filter-syntax', target: '_blank', rel: 'noopener noreferrer' } }, t('cfSyntaxLink'), icon('external', 12)),
            ),
          ),
        ),
      );
      paintReport();
    },
    async canLeave() {
      if (!dirty) return true;
      const leave = await confirmDialog({ title: t('cfLeaveTitle'), body: t('cfLeaveText'), confirmLabel: t('cfLeaveConfirm') });
      if (leave) dirty = false;
      return leave;
    },
    dispose() {
      window.removeEventListener('beforeunload', beforeUnload);
    },
  };
}
