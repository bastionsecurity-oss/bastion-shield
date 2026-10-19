// Bastion Shield — "Filterregeln ausgelöst" panel of the popup. Asks the
// browser which DNR rules matched on the current document
// (declarativeNetRequest.getMatchedRules) and maps each rule id back to the
// original filter text through dist/rulesets/filters/<rulesetId>.json, which
// is only fetched when the user opens a list (the files can be large).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ListCategory, RuleSourceMap } from '../../shared/types.ts';
import { blameLinks } from '../../shared/blame.ts';
import { isSystemAllowRuleId } from '../../shared/constants.ts';
import { h, replace } from '../shared/dom.ts';
import { fmtNumber, plural, t } from '../shared/i18n.ts';
import { icon } from '../shared/icons.ts';
import { notice } from '../shared/controls.ts';
import { categoryLabel, dynamicRuleLabel, type ListDirectory } from '../shared/labels.ts';
import { fetchPackaged } from '../shared/messaging.ts';

interface RuleHit {
  rulesetId: string;
  ruleId: number;
  n: number;
}

export interface Group {
  key: string;
  name: string;
  category: ListCategory | 'unknown' | 'builtin';
  total: number;
  hits: RuleHit[];
  /** Static rulesets carry filter text; dynamic/session rules do not. */
  isStatic: boolean;
  /** Bastion's own allow / header rules (GPC, Standard first-party allow, protection off). */
  system?: boolean;
}

export interface GroupedMatches {
  /** Filter-list and custom-filter matches, most hits first. */
  filters: Group[];
  /** Sum of `filters` hits: the number shown on the tab badge. */
  total: number;
  /** System rules in one group, or null when none matched. Never counted. */
  system: Group | null;
}

type MatchInfo = { rule?: { rulesetId?: string; ruleId?: number } };

type FetchResult = { ok: true; infos: chrome.declarativeNetRequest.MatchedRuleInfo[] } | { ok: false; quota: boolean };

const SAFE_RULESET = /^[A-Za-z0-9._-]{1,80}$/;
const sourceCache = new Map<string, Promise<RuleSourceMap | null>>();

function loadSources(rulesetId: string): Promise<RuleSourceMap | null> {
  if (!SAFE_RULESET.test(rulesetId)) return Promise.resolve(null);
  let p = sourceCache.get(rulesetId);
  if (!p) {
    p = fetchPackaged<RuleSourceMap>(`rulesets/filters/${rulesetId}.json`);
    sourceCache.set(rulesetId, p);
  }
  return p;
}

async function fetchMatched(tabId: number): Promise<FetchResult> {
  try {
    const res = await chrome.declarativeNetRequest.getMatchedRules({ tabId });
    return { ok: true, infos: res?.rulesMatchedInfo ?? [] };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, quota: /quota|MAX_GETMATCHEDRULES|exceeded/i.test(msg) };
  }
}

function addHit(g: Group, rulesetId: string, ruleId: number): void {
  g.total++;
  const hit = g.hits.find((x) => x.rulesetId === rulesetId && x.ruleId === ruleId);
  if (hit) hit.n++;
  else g.hits.push({ rulesetId, ruleId, n: 1 });
}

/**
 * Group getMatchedRules results by list. Bastion's system rules (GPC header,
 * Standard-mode first-party allow, protection off, proceed-anyway) are not
 * filter matches: they go into one separate group that is excluded from the
 * total, so the panel never presents "Global Privacy Control" as a filter.
 */
export function groupMatches(infos: readonly MatchInfo[], dir: ListDirectory): GroupedMatches {
  const groups = new Map<string, Group>();
  let system: Group | null = null;
  for (const info of infos) {
    const rulesetId = info?.rule?.rulesetId ?? '';
    const ruleId = info?.rule?.ruleId ?? 0;
    if (isSystemAllowRuleId(rulesetId, ruleId)) {
      system ??= { key: 'sys', name: t('popupRulesSystem'), category: 'builtin', total: 0, hits: [], isStatic: false, system: true };
      addHit(system, rulesetId, ruleId);
      continue;
    }
    const dynamic = rulesetId === '_dynamic' || rulesetId === '_session';
    let g: Group | undefined;
    if (dynamic) {
      const name = dynamicRuleLabel(rulesetId, ruleId);
      const key = `dyn:${name}`;
      g = groups.get(key);
      if (!g) groups.set(key, (g = { key, name, category: 'builtin', total: 0, hits: [], isStatic: false }));
    } else {
      const listId = dir.listOfRuleset(rulesetId);
      const key = `list:${listId}`;
      g = groups.get(key);
      if (!g) groups.set(key, (g = { key, name: dir.name(listId), category: dir.category(listId), total: 0, hits: [], isStatic: true }));
    }
    addHit(g, rulesetId, ruleId);
  }
  const filters = Array.from(groups.values());
  for (const g of filters) g.hits.sort((a, b) => b.n - a.n || a.ruleId - b.ruleId);
  filters.sort((a, b) => b.total - a.total || a.name.localeCompare(b.name));
  system?.hits.sort((a, b) => b.n - a.n || a.ruleId - b.ruleId);
  return { filters, total: filters.reduce((n, g) => n + g.total, 0), system };
}

/** Max filter lines shown per merged rule before collapsing into "+N". */
const LINES_PER_RULE = 4;
/** Max rules listed per list (most frequent first). */
const RULES_PER_LIST = 40;

/**
 * Nerd mode: "history ↗" links to the upstream blame view or code search of
 * each shown filter line (shared/blame.ts), from the list's source URLs.
 */
export function blameRow(lines: readonly string[], sourceUrls: readonly string[]): HTMLElement | null {
  const links: HTMLElement[] = [];
  lines.forEach((line, i) => {
    const link = blameLinks(sourceUrls, line)[0];
    if (!link) return;
    const label = lines.length > 1 ? `${t('nerdPopupHistory')} ${i + 1}` : t('nerdPopupHistory');
    links.push(
      h(
        'a',
        { class: 'pp-rl__blame-link', attrs: { href: link.url, target: '_blank', rel: 'noopener noreferrer', title: `${link.repo}: ${line}` } },
        h('span', { text: label }),
        icon('external', 12),
      ),
    );
  });
  return links.length ? h('div', { class: 'pp-rl__blame' }, ...links) : null;
}

async function fillGroup(body: HTMLElement, g: Group, dir: ListDirectory, blame: boolean): Promise<void> {
  if (g.system) {
    replace(
      body,
      h('p', { class: 'pp-rl__hint', text: t('popupRulesSystemHint') }),
      ...g.hits.map((hit) =>
        h(
          'div',
          { class: 'pp-rl__rule' },
          h('div', { class: 'pp-rl__sys', text: dynamicRuleLabel(hit.rulesetId, hit.ruleId) }),
          h('div', { class: 'pp-rl__meta', text: t('popupRuleMeta', [fmtNumber(hit.n), String(hit.ruleId)]) }),
        ),
      ),
    );
    return;
  }
  if (!g.isStatic) {
    replace(
      body,
      ...g.hits.map((hit) =>
        h('div', { class: 'pp-rl__rule' }, h('div', { class: 'pp-rl__meta', text: t('popupRuleMeta', [fmtNumber(hit.n), String(hit.ruleId)]) })),
      ),
    );
    return;
  }
  replace(body, h('div', { class: 'pp-rl__loading', text: t('stateLoading') }));
  const rulesets = Array.from(new Set(g.hits.map((x) => x.rulesetId)));
  const maps = new Map<string, RuleSourceMap | null>();
  await Promise.all(rulesets.map(async (id) => maps.set(id, await loadSources(id))));

  const rows: HTMLElement[] = [];
  const sources = blame ? (dir.get(g.key.startsWith('list:') ? g.key.slice(5) : '')?.sources ?? []).map((src) => src.url) : [];
  for (const hit of g.hits.slice(0, RULES_PER_LIST)) {
    const texts = maps.get(hit.rulesetId)?.[hit.ruleId] ?? null;
    const lines = texts && texts.length ? texts : null;
    const pre = h('pre', { class: 'pp-rl__text' });
    if (lines) {
      const shown = lines.slice(0, LINES_PER_RULE);
      pre.textContent = shown.join('\n');
      const rest = lines.length - shown.length;
      if (rest > 0) pre.append('\n', h('span', { class: 'pp-rl__more', text: plural(rest, 'popupRuleMoreOne', 'popupRuleMore') }));
    } else {
      pre.append(h('span', { class: 'pp-rl__more', text: t('popupRuleNoText') }));
    }
    rows.push(
      h(
        'div',
        { class: 'pp-rl__rule' },
        pre,
        lines && sources.length ? blameRow(lines.slice(0, LINES_PER_RULE), sources) : null,
        h('div', { class: 'pp-rl__meta', text: t('popupRuleMeta', [fmtNumber(hit.n), String(hit.ruleId)]) }),
      ),
    );
  }
  if (g.hits.length > RULES_PER_LIST) rows.push(h('div', { class: 'pp-rl__meta', text: plural(g.hits.length - RULES_PER_LIST, 'popupRuleMoreRulesOne', 'popupRuleMoreRules') }));
  replace(body, ...rows);
}

export interface MatchedPanel {
  refresh(): Promise<void>;
  /** Re-render names once meta.json has loaded. */
  setDirectory(dir: ListDirectory): void;
  /** Nerd mode: show upstream history links under filter texts. */
  setBlame(on: boolean): void;
}

export interface MatchedPanelOptions {
  /** Nerd mode: "history ↗" links under each filter text. Default off. */
  blame?: boolean;
}

export function createMatchedPanel(container: HTMLElement, countEl: HTMLElement, tabId: number, initialDir: ListDirectory, opts: MatchedPanelOptions = {}): MatchedPanel {
  let dir = initialDir;
  let blame = opts.blame === true;
  let last: FetchResult | null = null;
  let inflight: Promise<void> | null = null;
  const openKeys = new Set<string>();

  const render = (): void => {
    if (!last) return;
    if (!last.ok) {
      countEl.textContent = '';
      replace(
        container,
        h(
          'div',
          { class: 'pp-empty' },
          notice(last.quota ? t('popupRulesQuotaTitle') : t('popupRulesErrorTitle'), last.quota ? t('popupRulesQuotaText') : t('popupRulesErrorText'), 'info', true),
        ),
      );
      return;
    }
    const { filters, total, system } = groupMatches(last.infos, dir);
    countEl.textContent = total ? fmtNumber(total) : '';
    const details = (g: Group): HTMLElement => {
      const body = h('div', { class: 'pp-rl__body' });
      const el = h(
        'details',
        { class: `pp-rl${g.system ? ' pp-rl--sys' : ''}` },
        h(
          'summary',
          null,
          icon('chevronRight', 14, 'pp-rl__chev'),
          h('span', { class: 'pp-rl__name', text: g.name }),
          g.category !== 'builtin' && g.category !== 'unknown' ? h('span', { class: 'pp-rl__cat', text: categoryLabel(g.category) }) : null,
          h('span', { class: 'pp-rl__n num', text: fmtNumber(g.total), attrs: { 'aria-label': plural(g.total, 'popupRulesHitsOne', 'popupRulesHits') } }),
        ),
        body,
      );
      let filled = false;
      el.addEventListener('toggle', () => {
        if (el.open) openKeys.add(g.key);
        else openKeys.delete(g.key);
        if (el.open && !filled) {
          filled = true;
          void fillGroup(body, g, dir, blame);
        }
      });
      if (openKeys.has(g.key)) el.open = true;
      return el;
    };
    replace(
      container,
      ...(filters.length ? filters.map(details) : [h('p', { class: 'pp-empty', text: t('popupRulesEmpty') })]),
      system ? details(system) : null,
    );
  };

  const refresh = (): Promise<void> => {
    if (inflight) return inflight;
    inflight = (async () => {
      if (!last) replace(container, h('p', { class: 'pp-empty', text: t('stateLoading') }));
      last = await fetchMatched(tabId);
      render();
    })().finally(() => {
      inflight = null;
    });
    return inflight;
  };

  return {
    refresh,
    setDirectory(d: ListDirectory) {
      dir = d;
      render();
    },
    setBlame(on: boolean) {
      if (on === blame) return;
      blame = on;
      render();
    },
  };
}
