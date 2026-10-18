// Bastion Shield — dashboard «Eigene Filter»: monospace editor with line
// numbers for the user's own filters (uBO/ABP syntax), apply button, compile
// report with per-line errors, and the organisation's admin filters shown
// read-only. Scriptlet filters (+js) need an extension release (MV3 forbids
// runtime code), which the page says plainly.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { CustomState } from '../../../shared/types.ts';
import { h, replace, toast } from '../../shared/dom.ts';
import { fmtNumber, plural, t } from '../../shared/i18n.ts';
import { icon } from '../../shared/icons.ts';
import { confirmDialog, lockBadge, notice } from '../../shared/controls.ts';
import { errorState, pageHead, panel, type View, mount } from '../common.ts';
import { getCustom, setCustom } from '../store.ts';

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
            panel({ title: t('cfEditorTitle'), aside: locked ? lockBadge() : null, flush: true, class: 'cf-panel' }, editor, h('div', { class: 'cf-actions' }, applyBtn, revertBtn, status)),
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
