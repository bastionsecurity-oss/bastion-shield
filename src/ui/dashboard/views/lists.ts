// Bastion Shield — dashboard «Filterlisten» (Paper DB11, DB12, panel DB17):
// the browser's rule budget (network and regex rules, «Was ist das?»
// disclosure), the default lists grouped by category as collapsible cards
// (the first one open), «Weitere Listen» (vetted lists that are off by
// default, with the rules each would take), each list with its switch,
// description, filter count, «Details und Quellen» (stats, sources, licence)
// and lock state, then «Meine Listen» (my-lists.ts). The panel shows a
// compact version and sends «Meine Listen» to the tab.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BuiltList, ListsState } from '../../../shared/types.ts';
import { LIMITS } from '../../../shared/constants.ts';
import { h, replace, toast } from '../../shared/dom.ts';
import { fmtDate, fmtNumber, localized, t } from '../../shared/i18n.ts';
import { icon } from '../../shared/icons.ts';
import { lockIcon, switchControl } from '../../shared/controls.ts';
import { truncateMiddle, withUnit } from '../../shared/text.ts';
import { CATEGORY_ORDER, categoryLabel } from '../../shared/labels.ts';
import { meter } from '../chart.ts';
import { errorState, lockedNote, nextId, openInTab, pageHead, popupMode, retryView, type View, mount } from '../common.ts';
import { getConfig, getLists, myLists, setList } from '../store.ts';
import { myListsPanel } from './my-lists.ts';

/** Budget share from which the meter and its note warn (DB12). */
export const BUDGET_HIGH = 0.9;

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
 * «Weitere Listen»: vetted lists that are off by default. Regional lists stay in
 * their own group even when off, because the user's languages switch them on.
 */
export function isOptionalList(l: Pick<BuiltList, 'default' | 'category'>): boolean {
  return l.default !== true && l.category !== 'regional';
}

/** Whole percent of `used` in `max` (0 when max is 0), capped at 999. */
export function budgetPercent(used: number, max: number): number {
  if (!(max > 0) || !(used > 0)) return 0;
  return Math.min(999, Math.round((used / max) * 100));
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

function extLink(href: string | null, text: string, mono = false, full?: string): HTMLElement {
  if (!href) return h('span', { class: mono ? 'mono' : '', text, attrs: { translate: mono ? 'no' : undefined } });
  return h('a', { class: `ext-link${mono ? ' mono' : ''}`, attrs: { href, target: '_blank', rel: 'noopener noreferrer', title: full ?? undefined, translate: mono ? 'no' : undefined } }, text, icon('external', 12));
}

/** A quiet underlined text button that shows / hides `panel` (aria-expanded). */
export function disclosure(label: () => string, panel: HTMLElement, cls = 'db-link'): HTMLButtonElement {
  const id = panel.id || nextId('disc');
  panel.id = id;
  panel.hidden = true;
  const btn = h('button', { class: cls, attrs: { type: 'button', 'aria-expanded': 'false', 'aria-controls': id }, text: label() });
  btn.addEventListener('click', () => {
    panel.hidden = !panel.hidden;
    btn.setAttribute('aria-expanded', String(!panel.hidden));
    btn.textContent = label();
  });
  return btn;
}

/** One meter of the budget card: label, «21'480 von 30'000», bar, percent note. */
function budgetMeter(label: string, used: number, max: number, note: (pct: string) => string): HTMLElement {
  const pct = budgetPercent(used, max);
  const high = used / Math.max(1, max) >= BUDGET_HIGH;
  const of = t('listsBudgetOf2', [fmtNumber(used), fmtNumber(max)]);
  return h(
    'div',
    { class: `lists-meter${high ? ' lists-meter--high' : ''}` },
    h('div', { class: 'lists-meter__head' }, h('span', { class: 'lists-meter__label', text: label }), h('span', { class: 'lists-meter__of num', text: of })),
    meter({ value: used, max, label, valueText: of }),
    h('p', { class: 'lists-meter__note', text: note(withUnit(fmtNumber(pct), '%')) }),
  );
}

function budgetCard(state: ListsState): HTMLElement {
  const used = state.budget.used ?? 0;
  const regex = state.budget.regexUsed ?? 0;
  const guaranteed = LIMITS.GUARANTEED_STATIC_RULES;
  const high = used / guaranteed >= BUDGET_HIGH;
  const more = h(
    'div',
    { class: 'lists-budget__more' },
    h('p', null, used > guaranteed ? t('listsBudgetOverNote') : t('listsBudgetNote', fmtNumber(guaranteed)), state.budget.available !== null && state.budget.available !== undefined ? ` ${t('listsBudgetAvailable', fmtNumber(state.budget.available))}` : ''),
    h('p', { text: t('listsBudgetRegexNote', fmtNumber(LIMITS.MAX_STATIC_REGEX_RULES)) }),
  );
  return h(
    'section',
    { class: 'lists-budget', attrs: { 'aria-labelledby': 'lists-budget-title' } },
    h('div', { class: 'db-card__head' }, h('h2', { class: 'db-card__title', text: t('listsBudgetTitle'), attrs: { id: 'lists-budget-title' } }), disclosure(() => (more.hidden ? t('listsBudgetWhat') : t('listsBudgetWhatHide')), more)),
    h(
      'div',
      { class: 'lists-budget__grid' },
      budgetMeter(t('listsBudgetNetwork'), used, guaranteed, (p) => (high ? t('listsBudgetPctHigh', p) : t('listsBudgetPct', p))),
      budgetMeter(t('listsBudgetRegex'), regex, LIMITS.MAX_STATIC_REGEX_RULES, (p) => p),
    ),
    more,
  );
}

function listDetails(l: BuiltList): HTMLElement {
  const stats: [string, number | undefined][] = [
    [t('listsStatFiltersN'), l.stats?.filters],
    [t('listsStatNetworkN'), l.stats?.network],
    [t('listsStatCosmeticN'), l.stats?.cosmetic],
    [t('listsStatUnsupportedN'), l.stats?.unsupported],
    [t('listsStatRegexN'), l.regexRuleCount],
    [t('listsStatDnrRulesN'), l.ruleCount],
  ];
  return h(
    'div',
    { class: 'lists-row__more' },
    h('ul', { class: 'lists-stats' }, ...stats.filter(([, v]) => (v ?? 0) > 0 || v === l.ruleCount).map(([k, v]) => h('li', null, h('span', { class: 'num', text: fmtNumber(v ?? 0) }), ` ${k}`))),
    h(
      'ol',
      { class: 'lists-sources' },
      ...(l.sources ?? []).map((s) =>
        h(
          'li',
          null,
          extLink(safeHttpUrl(s.url), truncateMiddle(s.url || '—', 64), true, s.url),
          h('span', { class: 'lists-sources__meta mono', attrs: { translate: 'no' } }, [s.sha256 ? `sha256 ${s.sha256.slice(0, 8)}…` : '', s.bytes ? withUnit(fmtNumber(Math.round(s.bytes / 1024)), 'KiB') : ''].filter(Boolean).join(' ')),
        ),
      ),
    ),
    h('p', { class: 'lists-row__attr' }, t('listsLicenceLine', [l.license, l.attribution].filter(Boolean).join(' - ')), ' ', extLink(safeHttpUrl(l.homepage), t('listsHomepage'))),
  );
}

function listRow(state: ListsState, l: BuiltList, policyLockAll: boolean, onChanged: (s: ListsState | null, listId: string) => void, refused: Map<string, string>, optional = false): HTMLElement {
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
        // DB12: the browser refused (budget full) or the worker did not answer: say so in the row.
        refused.set(l.id, r.error);
        onChanged(null, l.id);
        return false;
      }
      refused.delete(l.id);
      toast(v ? t('listsEnabledToast', localized(l.name)) : t('listsDisabledToast', localized(l.name)), icon('check', 15));
      onChanged(r.data, l.id);
      return true;
    },
  });

  const filterCount = listFilterCount(l);
  const name = h('h3', { class: 'lists-row__name', text: localized(l.name), attrs: { id: nameId } });
  if (popupMode) {
    const err = state.errors[l.id] || refused.get(l.id);
    return h(
      'li',
      { class: `lists-row lists-row--compact${enabled ? '' : ' lists-row--off'}`, dataset: { list: l.id } },
      h('div', { class: 'lists-row__top' }, name, lock ? lockIcon(t('lockedByPolicy')) : null, err ? h('span', { class: 'lists-row__err-icon', attrs: { role: 'img', 'aria-label': t('listsErrorTitle') } }, icon('alert', 14)) : null),
      h('span', { class: 'lists-row__count num', text: fmtNumber(filterCount) }),
      h('span', { class: 'sr-only', text: localized(l.description), attrs: { id: descId } }),
      h('div', { class: 'lists-row__switch' }, sw.el),
    );
  }

  const updated = lastUpdated(l);
  const version = l.sources?.find((s) => s.version)?.version;
  const more = listDetails(l);
  const meta = h(
    'div',
    { class: 'lists-row__meta' },
    updated ? h('span', { text: `${t('listsUpdated')} ${fmtDate(updated)}` }) : null,
    version ? h('span', { class: 'mono', text: version, attrs: { translate: 'no' } }) : null,
    disclosure(() => (more.hidden ? t('listsDetailsShow') : t('listsDetailsHide')), more),
  );
  const errText = state.errors[l.id];
  const refusal = refused.get(l.id);
  const errorBox = (title: string, text: string): HTMLElement =>
    h('div', { class: 'lists-row__error', attrs: { role: 'alert' } }, icon('alert', 16), h('div', null, h('p', { class: 'lists-row__error-title', text: title }), h('p', { class: 'lists-row__error-text', text })));

  return h(
    'li',
    { class: `lists-row${enabled ? '' : ' lists-row--off'}${lock ? ' lists-row--locked' : ''}`, dataset: { list: l.id } },
    h('div', { class: 'lists-row__switch' }, sw.el),
    h(
      'div',
      { class: 'lists-row__body' },
      h(
        'div',
        { class: 'lists-row__top' },
        h('div', { class: 'lists-row__title' }, name, optional ? h('span', { class: 'lists-row__badge', text: categoryLabel(l.category) }) : null, lock ? h('span', { class: 'lists-row__lock', attrs: { 'aria-hidden': 'true' } }, icon('lock', 12)) : null),
        h('span', { class: 'lists-row__count num', text: optional ? t('listsCostLine', fmtNumber(listRuleCost(l))) : t('listsFilterLine', fmtNumber(filterCount)) }),
      ),
      lock ? lockedNote(descId) : h('p', { class: 'lists-row__desc', text: localized(l.description), attrs: { id: descId } }),
      errText ? errorBox(t('listsErrorTitle'), errText) : null,
      refusal ? errorBox(t('listsRefusedTitle'), t('listsRefusedText')) : null,
      lock ? null : meta,
      lock ? null : more,
    ),
  );
}

export function listsView(): View {
  return {
    async render(root) {
      const [listsR, cfgR] = await Promise.all([getLists(true), getConfig()]);
      if (!listsR.ok || !listsR.data.meta) {
        mount(root, pageHead(t('listsTitle'), popupMode ? undefined : t('listsLead')), errorState(retryView));
        return;
      }
      // Pseudo-path 'lists': every list is locked (lockLists, or lockSettings unless lockLists is false).
      const policyLockAll = cfgR.ok ? cfgR.data.locked.includes('lists') : false;
      const refused = new Map<string, string>();
      const budgetSlot = h('div', { class: 'lists-budget-slot' });
      const groupsSlot = h('div', { class: 'lists-groups' });
      const lead = h('p', { class: 'db-head__lead' });
      // Which groups are open survives redraws (a switch redraws the view).
      const open = new Set<string>();
      let first = true;

      const draw = (state: ListsState, focusListId?: string): void => {
        const used = state.budget.used ?? 0;
        if (popupMode) {
          replace(lead, t('listsPanelLead', [fmtNumber(used), fmtNumber(LIMITS.GUARANTEED_STATIC_RULES)]));
          replace(budgetSlot, meter({ value: used, max: LIMITS.GUARANTEED_STATIC_RULES, label: t('listsBudgetNetwork'), valueText: t('listsBudgetOf2', [fmtNumber(used), fmtNumber(LIMITS.GUARANTEED_STATIC_RULES)]) }));
        } else replace(budgetSlot, budgetCard(state));
        const all = state.meta.lists ?? [];
        const lists = all.filter((l) => !isOptionalList(l));
        const cats = [...CATEGORY_ORDER, ...new Set(all.map((l) => l.category).filter((c) => !CATEGORY_ORDER.includes(c)))];
        const rank = (l: BuiltList): number => cats.indexOf(l.category);
        const optional = all.filter(isOptionalList).sort((a, b) => rank(a) - rank(b));
        const onChanged = (s: ListsState | null, id: string): void => {
          if (s) draw(s, id);
          else draw(state, id);
        };
        const groups: { key: string; title: string; aside: string; members: BuiltList[]; optional: boolean }[] = [];
        for (const cat of cats) {
          const members = lists.filter((l) => l.category === cat);
          if (!members.length) continue;
          const on = members.filter((l) => state.enabled[l.id]).length;
          groups.push({ key: cat, title: categoryLabel(cat), aside: t('listsGroupActive', [fmtNumber(on), fmtNumber(members.length)]), members, optional: false });
        }
        if (optional.length) {
          const on = optional.filter((l) => state.enabled[l.id]).length;
          const active = t('listsGroupActive', [fmtNumber(on), fmtNumber(optional.length)]);
          groups.push({ key: 'more', title: t('listsMoreTitle'), aside: popupMode ? active : t('listsMoreAside', active), members: optional, optional: true });
        }
        if (first && groups.length) open.add(groups[0].key);
        first = false;
        const group = (g: (typeof groups)[number]): HTMLElement => {
          const det = h(
            'details',
            { class: `lists-group${g.optional ? ' lists-group--more' : ''}`, dataset: { group: g.key } },
            h('summary', { class: 'lists-group__head' }, icon('chevronRight', 12, 'lists-group__chev'), h('h2', { class: 'lists-group__title', text: g.title }), h('span', { class: 'lists-group__aside', text: g.aside })),
            g.optional && !popupMode ? h('p', { class: 'lists-group__lead', text: t('listsMoreLead') }) : null,
            h('ul', { class: 'lists-list' }, ...g.members.map((l) => listRow(state, l, policyLockAll, onChanged, refused, g.optional))),
          );
          det.open = open.has(g.key);
          det.addEventListener('toggle', () => {
            if (det.open) open.add(g.key);
            else open.delete(g.key);
          });
          return det;
        };
        replace(groupsSlot, ...groups.map(group));
        // Re-rendering replaces the switch the user just pressed; keep keyboard focus on it.
        if (focusListId) {
          for (const row of Array.from(groupsSlot.querySelectorAll<HTMLElement>('.lists-row'))) {
            if (row.dataset.list === focusListId) row.querySelector<HTMLElement>('.switch')?.focus();
          }
        }
      };

      const lockedAll = policyLockAll
        ? h('div', { class: 'lists-locked', attrs: { role: 'status' } }, icon('lock', 16), h('div', null, h('p', { class: 'lists-locked__title', text: t('listsLockedAllTitle') }), h('p', { class: 'lists-locked__text', text: t('listsLockedAllText') })))
        : null;

      if (popupMode) {
        // DB17: compact groups in one card, «Meine Listen» opens the tab.
        const mine = h('div', { class: 'lists-mine' }, h('span', { class: 'lists-mine__label', text: t('myListsTitle') }));
        void myLists().then((r) => {
          if (r.ok) mine.firstChild!.textContent = `${t('myListsTitle')} - ${t('myListsCount', [fmtNumber(r.data.lists.length), fmtNumber(r.data.maxLists)])}`;
        });
        mine.append(h('button', { class: 'db-link lists-mine__open', attrs: { type: 'button', 'data-open-tab': 'lists' }, on: { click: () => void openInTab('lists') } }, t('listsEditInTab'), icon('openTab', 12)));
        mount(root, pageHead(t('listsTitle'), lead), budgetSlot, lockedAll, h('div', { class: 'db-card db-card--flush lists-panel-card' }, groupsSlot), mine);
      } else {
        mount(root, pageHead(t('listsTitle'), t('listsLead')), lockedAll, budgetSlot, groupsSlot, myListsPanel(), h('p', { class: 'db-footnote', text: t('listsFootnote') }));
      }
      draw(listsR.data);
    },
  };
}
