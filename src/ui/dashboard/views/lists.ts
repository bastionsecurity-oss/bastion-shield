// Bastion Shield — dashboard «Filterlisten»: the default lists grouped by
// category, then «More lists» (vetted lists that are off by default, with
// the rules each would add), each with toggle, description, rule count,
// sources, licence, version and lock state, plus the static rule budget
// (30'000 guaranteed rules, 1'000 regex rules) and per-list errors reported
// by the service worker.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BuiltList, ListsState } from '../../../shared/types.ts';
import { LIMITS } from '../../../shared/constants.ts';
import { h, replace, toast } from '../../shared/dom.ts';
import { fmtDate, fmtNumber, localized, t } from '../../shared/i18n.ts';
import { icon } from '../../shared/icons.ts';
import { lockIcon, notice, switchControl } from '../../shared/controls.ts';
import { CATEGORY_ORDER, categoryLabel } from '../../shared/labels.ts';
import { meter } from '../chart.ts';
import { errorState, nextId, pageHead, panel, type View, mount } from '../common.ts';
import { getConfig, getLists, setList } from '../store.ts';

/** Only an administrator's policy locks a list; otherwise every list is the user's choice. */
function listLocked(state: ListsState, l: BuiltList, policyLockAll: boolean): boolean {
  return policyLockAll || state.locked.includes(l.id) || state.locked.includes(`lists.${l.id}`);
}

/**
 * Headline count of a list: the source filters that are in effect (network,
 * cosmetic and scriptlet filters; not unsupported or badfiltered lines). The
 * DNR rule count is much smaller for domain lists (thousands of hosts merge
 * into a couple of requestDomains rules) and would make them look empty; it is
 * shown in the details, where it matters for the rule budget. Network alone
 * would make cosmetic lists (cookie notices, annoyances) look nearly empty.
 */
export function listFilterCount(l: Pick<BuiltList, 'stats' | 'ruleCount'>): number {
  const s = l.stats;
  const n = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : 0);
  const applied = s ? n(s.network) + n(s.cosmetic) + n(s.scriptlets) : 0;
  return applied > 0 ? applied : n(l.ruleCount);
}

/** Rules a list takes from the static rule budget when it is on (plain + regex). */
export function listRuleCost(l: Pick<BuiltList, 'ruleCount' | 'regexRuleCount'>): number {
  const n = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : 0);
  return n(l.ruleCount) + n(l.regexRuleCount);
}

/**
 * «More lists»: vetted lists that are off by default. Regional lists stay in
 * their own group even when off, because the user's languages switch them on.
 */
export function isOptionalList(l: Pick<BuiltList, 'default' | 'category'>): boolean {
  return l.default !== true && l.category !== 'regional';
}

function lastUpdated(l: BuiltList): number | null {
  let best: number | null = null;
  for (const s of l.sources ?? []) {
    const ms = s.lastModified ? Date.parse(s.lastModified) : NaN;
    if (Number.isFinite(ms) && (best === null || ms > best)) best = ms;
  }
  return best;
}

function safeHttpUrl(u: string | undefined): string | null {
  if (!u) return null;
  try {
    const url = new URL(u);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null;
  } catch {
    return null;
  }
}

function extLink(href: string | null, text: string, mono = false): HTMLElement {
  if (!href) return h('span', { class: mono ? 'mono' : '', text });
  return h('a', { class: `ext-link${mono ? ' mono' : ''}`, attrs: { href, target: '_blank', rel: 'noopener noreferrer' } }, text, icon('external', 12));
}

function budgetPanel(state: ListsState): HTMLElement {
  const used = state.budget.used ?? 0;
  const regex = state.budget.regexUsed ?? 0;
  const guaranteed = LIMITS.GUARANTEED_STATIC_RULES;
  const over = used > guaranteed;
  return panel(
    { title: t('listsBudgetTitle'), class: 'lists-budget' },
    h(
      'div',
      { class: 'lists-budget__grid' },
      h(
        'div',
        { class: 'lists-budget__item' },
        h('div', { class: 'lists-budget__label', text: t('listsBudgetStatic') }),
        h('div', { class: 'lists-budget__figure' }, h('span', { class: 'lists-budget__value num', text: fmtNumber(used) }), h('span', { class: 'lists-budget__of', text: t('listsBudgetOfGuaranteed', fmtNumber(guaranteed)) })),
        meter({ value: used, max: guaranteed, label: t('listsBudgetStatic'), valueText: t('listsBudgetOfGuaranteed', fmtNumber(guaranteed)) }),
        h(
          'p',
          { class: 'lists-budget__note' },
          over ? t('listsBudgetOverNote') : t('listsBudgetNote', fmtNumber(guaranteed)),
          state.budget.available !== null && state.budget.available !== undefined ? ` ${t('listsBudgetAvailable', fmtNumber(state.budget.available))}` : '',
        ),
      ),
      h(
        'div',
        { class: 'lists-budget__item' },
        h('div', { class: 'lists-budget__label', text: t('listsBudgetRegex') }),
        h('div', { class: 'lists-budget__figure' }, h('span', { class: 'lists-budget__value num', text: fmtNumber(regex) }), h('span', { class: 'lists-budget__of', text: t('listsBudgetOf', fmtNumber(LIMITS.MAX_STATIC_REGEX_RULES)) })),
        meter({ value: regex, max: LIMITS.MAX_STATIC_REGEX_RULES, label: t('listsBudgetRegex'), valueText: t('listsBudgetOf', fmtNumber(LIMITS.MAX_STATIC_REGEX_RULES)) }),
        h('p', { class: 'lists-budget__note', text: t('listsBudgetRegexNote', fmtNumber(LIMITS.MAX_STATIC_REGEX_RULES)) }),
      ),
    ),
  );
}

function listRow(state: ListsState, l: BuiltList, policyLockAll: boolean, onChanged: (s: ListsState | null, listId: string) => void, optional = false): HTMLElement {
  const nameId = nextId('list-name');
  const descId = nextId('list-desc');
  const lock = listLocked(state, l, policyLockAll);
  const enabled = !!state.enabled[l.id];
  const sw = switchControl({
    checked: enabled,
    labelledBy: nameId,
    describedBy: descId,
    disabled: lock,
    onChange: async (v) => {
      const r = await setList(l.id, v);
      if (!r.ok) {
        toast(t('errorSaveFailed'), icon('alert', 15));
        return false;
      }
      toast(v ? t('listsEnabledToast', localized(l.name)) : t('listsDisabledToast', localized(l.name)), icon('check', 15));
      onChanged(r.data, l.id);
      return true;
    },
  });

  const filterCount = listFilterCount(l);
  const updated = lastUpdated(l);
  const version = l.sources?.find((s) => s.version)?.version;
  const metaBits: HTMLElement[] = [];
  if (optional) metaBits.push(h('span', null, h('span', { class: 'lists-row__k', text: t('listsRuleCost') }), ' ', h('span', { class: 'num', text: fmtNumber(listRuleCost(l)) })));
  metaBits.push(h('span', null, h('span', { class: 'lists-row__k', text: t('listsLicence') }), ' ', extLink(safeHttpUrl(l.licenseUrl), l.license)));
  if (version) metaBits.push(h('span', null, h('span', { class: 'lists-row__k', text: t('listsVersion') }), ' ', h('span', { class: 'mono', text: version })));
  if (updated) metaBits.push(h('span', null, h('span', { class: 'lists-row__k', text: t('listsUpdated') }), ' ', fmtDate(updated)));
  metaBits.push(extLink(safeHttpUrl(l.homepage), t('listsHomepage')));

  const details = h(
    'details',
    { class: 'lists-row__details' },
    h('summary', null, icon('chevronRight', 13, 'lists-row__chev'), t('listsDetails', fmtNumber(l.sources?.length ?? 0))),
    h(
      'div',
      { class: 'lists-row__more' },
      h(
        'dl',
        { class: 'lists-stats' },
        ...([
          [t('listsStatFilters'), l.stats?.filters],
          [t('listsStatNetwork'), l.stats?.network],
          [t('listsStatCosmetic'), l.stats?.cosmetic],
          [t('listsStatScriptlets'), l.stats?.scriptlets],
          [t('listsStatUnsupported'), l.stats?.unsupported],
          [t('listsStatRegex'), l.regexRuleCount],
          [t('listsStatDnrRules'), l.ruleCount],
        ] as [string, number | undefined][]).map(([k, v]) => h('div', null, h('dt', { text: k }), h('dd', { class: 'num', text: fmtNumber(v ?? 0) }))),
      ),
      h(
        'ol',
        { class: 'lists-sources' },
        ...(l.sources ?? []).map((s) =>
          h(
            'li',
            null,
            extLink(safeHttpUrl(s.url), s.url || '—', true),
            h('span', { class: 'lists-sources__meta mono' }, s.sha256 ? `sha256 ${s.sha256.slice(0, 12)}…` : '', s.bytes ? `  ${fmtNumber(Math.round(s.bytes / 1024))} KiB` : ''),
          ),
        ),
      ),
      h('p', { class: 'lists-row__attr', text: l.attribution }),
    ),
  );

  return h(
    'li',
    { class: `lists-row${enabled ? '' : ' lists-row--off'}`, dataset: { list: l.id } },
    h('div', { class: 'lists-row__switch' }, sw.el),
    h(
      'div',
      { class: 'lists-row__body' },
      h(
        'div',
        { class: 'lists-row__top' },
        h('h3', { class: 'lists-row__name', text: localized(l.name), attrs: { id: nameId } }),
        optional ? h('span', { class: 'lists-row__badge mono-label', text: categoryLabel(l.category) }) : null,
        lock ? lockIcon(t('lockedByPolicy')) : null,
        h('span', { class: 'lists-row__count' }, h('span', { class: 'num', text: fmtNumber(filterCount) }), ' ', t(filterCount === 1 ? 'listsFilterOne' : 'listsFilters')),
      ),
      h('p', { class: 'lists-row__desc', text: localized(l.description), attrs: { id: descId } }),
      state.errors[l.id] ? h('div', { class: 'lists-row__error' }, notice(t('listsErrorTitle'), state.errors[l.id], 'alert')) : null,
      h('div', { class: 'lists-row__meta' }, ...metaBits),
      details,
    ),
  );
}

export function listsView(): View {
  return {
    async render(root) {
      const [listsR, cfgR] = await Promise.all([getLists(), getConfig()]);
      if (!listsR.ok || !listsR.data.meta) {
        mount(root, pageHead(t('listsTitle'), t('listsLead')), errorState(() => location.reload()));
        return;
      }
      // Pseudo-path 'lists': every list is locked (lockLists, or lockSettings unless lockLists is false).
      const policyLockAll = cfgR.ok ? cfgR.data.locked.includes('lists') : false;
      const budgetSlot = h('div');
      const groupsSlot = h('div', { class: 'lists-groups' });

      const draw = (state: ListsState, focusListId?: string): void => {
        replace(budgetSlot, budgetPanel(state));
        const all = state.meta.lists ?? [];
        const lists = all.filter((l) => !isOptionalList(l));
        const cats = [...CATEGORY_ORDER, ...new Set(all.map((l) => l.category).filter((c) => !CATEGORY_ORDER.includes(c)))];
        const rank = (l: BuiltList): number => cats.indexOf(l.category);
        const optional = all.filter(isOptionalList).sort((a, b) => rank(a) - rank(b));
        const onChanged = (s: ListsState | null, id: string): void => {
          if (s) draw(s, id);
        };
        const optionalOn = optional.filter((l) => state.enabled[l.id]).length;
        replace(
          groupsSlot,
          ...cats
            .map((cat) => {
              const members = lists.filter((l) => l.category === cat);
              if (!members.length) return null;
              const on = members.filter((l) => state.enabled[l.id]).length;
              return panel(
                { title: categoryLabel(cat), aside: t('listsGroupActive', [fmtNumber(on), fmtNumber(members.length)]), flush: true },
                h('ul', { class: 'lists-list' }, ...members.map((l) => listRow(state, l, policyLockAll, onChanged))),
              );
            })
            .filter((x): x is HTMLElement => x !== null),
          optional.length
            ? panel(
                { title: t('listsMoreTitle'), aside: t('listsGroupActive', [fmtNumber(optionalOn), fmtNumber(optional.length)]), flush: true, class: 'lists-more' },
                h('p', { class: 'lists-more__lead', text: t('listsMoreLead') }),
                h('ul', { class: 'lists-list' }, ...optional.map((l) => listRow(state, l, policyLockAll, onChanged, true))),
              )
            : null,
        );
        // Re-rendering replaces the switch the user just pressed; keep keyboard focus on it.
        if (focusListId) {
          for (const row of Array.from(groupsSlot.querySelectorAll<HTMLElement>('.lists-row'))) {
            if (row.dataset.list === focusListId) row.querySelector<HTMLElement>('.switch')?.focus();
          }
        }
      };

      mount(root, 
        pageHead(t('listsTitle'), t('listsLead')),
        policyLockAll ? h('div', { class: 'db-gap' }, notice(t('listsLockedAllTitle'), t('listsLockedAllText'), 'info')) : null,
        budgetSlot,
        groupsSlot,
        h('p', { class: 'db-footnote', text: t('listsFootnote') }),
      );
      draw(listsR.data);
    },
  };
}
