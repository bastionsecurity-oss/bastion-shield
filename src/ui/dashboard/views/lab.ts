// Bastion Shield — dashboard «Entwicklertools» (developer tools) (nerd mode only): three tools for people
// who want to see the machinery.
//   1. Filter playground: compile filters with the custom-filter compiler and
//      dry-run the resulting DNR rules against recorded requests (history)
//      and / or pasted URLs, per filter: matches, winner, resource types.
//      Pasted URLs can also be explained against what is installed (enabled
//      rulesets, custom and admin filters, dynamic rules; lab-explain.ts).
//   2. Ruleset integrity: hash every packaged file under rulesets/ with
//      crypto.subtle and compare with integrity.json from the build, plus the
//      upstream sources the build fetched (BuildMeta).
//   3. Filter blame: GitHub history links for any filter text.
// Deep links from the context menu (background/nerd-menus.ts):
// #lab?url=…&site=…&type=…, #lab?filter=…, #lab/blame?filter=…. Keyboard:
// "/" focuses the main input, Ctrl+Enter runs, Esc leaves the field.
// Everything runs in this page; nothing is sent anywhere except when the user
// follows a GitHub link.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BuildMeta, EffectiveConfig, RuleSourceMap } from '../../../shared/types.ts';
import { MY_LISTS, RULE_ID } from '../../../shared/constants.ts';
import type { IntegrityManifest } from '../../../../tools/integrity.ts';
import { debounce, h, replace, toast, type Child } from '../../shared/dom.ts';
import { fmtDateTime, fmtNumber, plural, t } from '../../shared/i18n.ts';
import { icon } from '../../shared/icons.ts';
import { fetchPackaged } from '../../shared/messaging.ts';
import { notice, segmented } from '../../shared/controls.ts';
import { dynamicRuleLabel, typeLabel } from '../../shared/labels.ts';
import { emptyState, nextId, pageHead, panel, type View, mount } from '../common.ts';
import { dir, getConfig, getCustom, getMeta, historyEvents, myLists } from '../store.ts';
import {
  blameFor,
  compilePlayground,
  EXPLAIN_TYPES,
  dryRun,
  filtersOfRule,
  groupHits,
  integrityRows,
  integritySummary,
  isIntegrityManifest,
  linkRequestLine,
  packagedCandidates,
  parseLabHash,
  parseRuleRef,
  parseUrlList,
  provenance,
  requestsFromEvents,
  setRequestType,
  settleRow,
  toHex,
  type BlameGroup,
  type DryRequest,
  type FilterDryRun,
  type IntegrityRow,
  type LabLink,
  type LabSection,
  type PlaygroundFilter,
} from '../lab-core.ts';
import { allowReason, EXPLAIN_MAX_HITS, EXPLAIN_MAX_REQUESTS, explainInstalled, filterDisplay, type ActionKind, type ExplainHit, type ExplainResult, type ExplainRule } from '../lab-explain.ts';

type Section = LabSection;
type Source = 'history' | 'urls' | 'both';

const HISTORY_LIMITS = [500, 2000, 5000];
/** Grouped URLs listed per filter before "+N more". */
const URLS_SHOWN = 100;

/** A Lab tool: its panels, its main input and its main action (for the keyboard). */
interface Tool {
  el: HTMLElement;
  focus(): void;
  run(): void;
  /** Prefill from a deep link and run. */
  apply?(link: LabLink): void;
}

const shortHash = (hex: string | null): string => (hex ? `${hex.slice(0, 12)}…${hex.slice(-6)}` : '–');

function extLink(url: string, label: Child, cls = 'ext-link'): HTMLAnchorElement {
  return h('a', { class: cls, attrs: { href: url, target: '_blank', rel: 'noopener noreferrer' } }, label, icon('external', 12));
}

function badge(text: string, mod = ''): HTMLElement {
  return h('span', { class: `lab-badge${mod ? ` lab-badge--${mod}` : ''}`, text });
}

// ---------------------------------------------------------------------------
// Blame links (shared with the Activity view)
// ---------------------------------------------------------------------------

function blameList(groups: readonly BlameGroup[]): HTMLElement {
  return h(
    'ul',
    { class: 'lab-blame__list' },
    ...groups.map((g) =>
      h(
        'li',
        null,
        h('div', { class: 'lab-blame__list-head' }, h('span', { class: 'lab-blame__list-name', text: dir().name(g.listId) }), h('code', { class: 'lab-blame__filter', text: g.filter })),
        h(
          'div',
          { class: 'lab-blame__links' },
          ...g.links.map((l) =>
            extLink(l.url, h('span', null, badge(l.kind === 'blame' ? t('nerdLabBlameKindBlame') : t('nerdLabBlameKindSearch')), h('span', { class: 'mono', text: l.path ? `${l.repo}/${l.path}` : l.repo })), 'ext-link lab-blame__link'),
          ),
        ),
      ),
    ),
  );
}

/** A modal with links and a single close button. */
function linkDialog(title: string, content: Child): void {
  const titleId = nextId('lab-dlg');
  const close = h('button', { class: 'btn btn--secondary', text: t('nerdLabClose'), attrs: { type: 'button' } });
  const dlg = h('dialog', { class: 'dialog lab-dialog', attrs: { 'aria-labelledby': titleId } }, h('div', { class: 'dialog__body' }, h('h2', { class: 'dialog__title', text: title, attrs: { id: titleId } }), content), h('div', { class: 'dialog__actions' }, close));
  close.addEventListener('click', () => dlg.close());
  dlg.addEventListener('close', () => dlg.remove());
  document.body.appendChild(dlg);
  try {
    dlg.showModal();
  } catch {
    dlg.setAttribute('open', '');
  }
  close.focus();
}

const sourceMaps = new Map<string, Promise<RuleSourceMap | null>>();

/**
 * «GitHub ↗» of an attributed Activity row or an explain row: resolve
 * "rulesetId:ruleId" to its filter text through the transparency map (or take
 * the given texts, e.g. the one filter of a merged rule that matched), then
 * open the upstream history (one link directly, several in a dialog).
 */
export async function openRuleHistory(rule: string, meta: BuildMeta | null, texts?: readonly string[]): Promise<void> {
  const ref = parseRuleRef(rule);
  if (!ref || !meta) {
    toast(t('nerdLabBlameNone'), icon('info', 15));
    return;
  }
  let filters: string[];
  if (texts?.length) {
    filters = [...texts];
  } else {
    let p = sourceMaps.get(ref.rulesetId);
    if (!p) {
      p = fetchPackaged<RuleSourceMap>(`rulesets/filters/${ref.rulesetId}.json`);
      sourceMaps.set(ref.rulesetId, p);
    }
    filters = filtersOfRule(await p, ref.ruleId);
  }
  const listId = meta.rulesetToList?.[ref.rulesetId] ?? ref.rulesetId;
  const groups = filters.flatMap((f) => blameFor(meta, listId, f));
  const links = groups.flatMap((g) => g.links);
  if (links.length === 1) {
    window.open(links[0].url, '_blank', 'noopener,noreferrer');
    return;
  }
  if (!links.length) {
    toast(filters.length ? t('nerdLabBlameNone') : t('nerdLabBlameNoText'), icon('info', 15));
    return;
  }
  linkDialog(t('nerdLabBlameDialogTitle'), blameList(groups));
}

// ---------------------------------------------------------------------------
// 1. Filter playground
// ---------------------------------------------------------------------------

function kindBadge(f: PlaygroundFilter): HTMLElement {
  switch (f.kind) {
    case 'network':
      return badge(t('nerdLabKindNetwork'), 'strong');
    case 'cosmetic':
      return badge(t('nerdLabKindCosmetic'));
    case 'scriptlet':
      return badge(t('nerdLabKindScriptlet'));
    case 'error':
      return badge(t('nerdLabKindError'), 'alert');
    default:
      return badge(t('nerdLabKindInert'));
  }
}

function outcomeLabel(o: string): string {
  switch (o) {
    case 'block':
      return t('nerdLabOutcomeBlock');
    case 'allow':
      return t('nerdLabOutcomeAllow');
    case 'redirect':
      return t('nerdLabOutcomeRedirect');
    case 'upgradeScheme':
      return t('nerdLabOutcomeUpgrade');
    case 'modifyHeaders':
      return t('nerdLabOutcomeHeaders');
    default:
      return o;
  }
}

function filterResult(f: PlaygroundFilter, run: FilterDryRun | null): HTMLElement {
  const head = h(
    'div',
    { class: 'lab-res__head' },
    h('span', { class: 'lab-res__line mono', text: t('cfLine', String(f.line)) }),
    h('code', { class: 'lab-res__filter', text: f.text }),
    kindBadge(f),
  );
  const body: Child[] = [];
  if (f.errors.length) body.push(h('p', { class: 'lab-res__err' }, icon('alert', 13), h('span', { class: 'mono', text: f.errors.join(' · ') })));
  if (f.kind === 'cosmetic' || f.kind === 'scriptlet') body.push(h('p', { class: 'lab-res__note', text: f.kind === 'cosmetic' ? t('nerdLabCosmeticNote') : t('nerdLabScriptletNote') }));
  if (f.kind === 'inert' && !f.errors.length) body.push(h('p', { class: 'lab-res__note', text: t('nerdLabInertNote') }));
  if (f.kind === 'network') {
    body.push(
      h(
        'div',
        { class: 'lab-res__meta' },
        ...(run?.actions ?? []).map((a) => badge(a, 'mono')),
        h('span', { class: 'lab-res__rules', text: plural(f.rules.length, 'nerdLabRulesOne', 'nerdLabRules') }),
      ),
    );
    if (run?.uncertain.length) body.push(h('p', { class: 'lab-res__note', text: t('nerdLabUncertain', run.uncertain.join(', ')) }));
    if (run?.ruleErrors.length) body.push(h('p', { class: 'lab-res__err' }, icon('alert', 13), h('span', { class: 'mono', text: run.ruleErrors.join(' · ') })));
    if (run) {
      const n = run.matches;
      const stats = h(
        'div',
        { class: 'lab-res__stats' },
        h('span', { class: 'lab-res__count num', text: plural(n, 'nerdLabMatchesOne', 'nerdLabMatches') }),
        n && run.decided !== n ? h('span', { class: 'lab-res__sub', text: t('nerdLabDecided', [fmtNumber(run.decided), fmtNumber(n)]) }) : null,
        run.alreadyHandled ? h('span', { class: 'lab-res__sub', text: plural(run.alreadyHandled, 'nerdLabAlreadyOne', 'nerdLabAlready') }) : null,
      );
      body.push(stats);
      const types = Object.entries(run.types).sort((a, b) => b[1] - a[1]);
      if (types.length) body.push(h('div', { class: 'lab-res__types' }, ...types.map(([ty, c]) => h('span', { class: 'lab-chip' }, typeLabel(ty), h('span', { class: 'num', text: ` ${fmtNumber(c)}` })))));
      if (n) {
        const groups = groupHits(run.hits);
        const shown = groups.slice(0, URLS_SHOWN);
        const rows = h(
          'ul',
          { class: 'lab-urls' },
          ...shown.map((g) =>
            h(
              'li',
              { class: g.decided ? '' : 'lab-urls__lost' },
              h('span', { class: 'lab-urls__mark', attrs: { title: g.decided ? outcomeLabel(g.outcome) : t('nerdLabOverridden', outcomeLabel(g.outcome)) } }, g.decided ? icon('check', 12) : icon('close', 12)),
              h('span', { class: 'lab-urls__url mono', text: g.url, attrs: { title: g.url } }),
              h('span', { class: 'lab-urls__type', text: typeLabel(g.type) }),
              h('span', { class: 'lab-urls__site mono', text: g.site ?? '–' }),
              h('span', { class: 'lab-urls__n num', text: g.count > 1 ? `×${fmtNumber(g.count)}` : '' }),
            ),
          ),
        );
        const more = groups.length - shown.length + (run.matches > run.hits.length ? 1 : 0);
        body.push(
          h(
            'details',
            { class: 'lab-res__details' },
            h('summary', null, icon('chevronRight', 12, 'lab-chev'), t('nerdLabShowUrls', fmtNumber(groups.length))),
            rows,
            more > 0 ? h('p', { class: 'lab-res__note', text: t('nerdLabUrlsCapped') }) : null,
          ),
        );
      }
    }
  }
  return h('li', { class: `lab-res lab-res--${f.kind}` }, head, ...body);
}

// --- Explain: pasted URLs against what is installed --------------------------

/** Titles of the imported lists by rule-id slot, refreshed before every explain run. */
let myListTitles = new Map<number, string>();

/** Display name of an explain source: list, «My filters», admin, an imported list, or the system rule. */
function sourceName(hit: ExplainHit, meta: BuildMeta | null): string {
  if (hit.source === 'custom') return t('listCustom');
  if (hit.source === 'admin') return t('listAdmin');
  if (hit.source === '_dynamic' && hit.ruleId >= RULE_ID.MY_LISTS_START && hit.ruleId <= RULE_ID.MY_LISTS_END) {
    const title = myListTitles.get(Math.floor((hit.ruleId - RULE_ID.MY_LISTS_START) / MY_LISTS.SLOT_SIZE));
    if (title) return `${t('myListsTitle')}: ${title}`;
  }
  if (hit.source === '_dynamic' || hit.source === '_session') return dynamicRuleLabel(hit.source, hit.ruleId);
  return dir().name(meta?.rulesetToList?.[hit.source] ?? hit.source);
}

/** Packaged rule file of a static ruleset, from the manifest (the Edge package moves them). */
function rulesetPath(id: string): string | null {
  try {
    const res = (chrome.runtime.getManifest() as { declarative_net_request?: { rule_resources?: { id: string; path: string }[] } }).declarative_net_request?.rule_resources ?? [];
    return res.find((r) => r.id === id)?.path.replace(/^\/+/, '') ?? null;
  } catch {
    return null;
  }
}

const ACTION_KEYS: Record<ActionKind, string> = {
  block: 'nerdLabActBlock',
  allow: 'nerdLabActAllow',
  page: 'nerdLabActPage',
  strict: 'nerdLabActStrict',
  surrogate: 'nerdLabActSurrogate',
  params: 'nerdLabActParams',
  debounce: 'nerdLabActDebounce',
  redirect: 'nerdLabActRedirect',
  headers: 'nerdLabActHeaders',
  gpc: 'nerdLabActGpc',
  upgrade: 'nerdLabActUpgrade',
};

/** «Blockiert», «Sperrseite (Strict Block)», … for a matching rule. */
const actionLabel = (x: ExplainHit): string => t(ACTION_KEYS[x.kind] ?? 'nerdLabActRedirect');

const REASON_KEYS: Record<string, string> = {
  siteOff: 'nerdLabReasonSiteOff',
  proceed: 'nerdLabReasonProceed',
  bisect: 'nerdLabReasonBisect',
  standard1p: 'nerdLabReasonStandard1p',
};

/**
 * The words of a decision: what happens and why. An allow from Bastion's own
 * rules (protection off, «proceed anyway», bisect, Standard mode) says why in
 * plain words; everything else names its source.
 */
function decisionWords(x: ExplainHit, meta: BuildMeta | null): { what: string; why: string } {
  if (x.action === 'allow' || x.action === 'allowAllRequests') {
    const key = REASON_KEYS[allowReason(x)];
    if (key) return { what: t('nerdLabVerdictAllowed'), why: t(key) };
  }
  return { what: actionLabel(x), why: t('nerdLabReasonBy', sourceName(x, meta)) };
}

const isLineSource = (x: ExplainHit): boolean => x.source === 'custom' || x.source === 'admin';

/** «Ergebnis: Erlaubt – Schutz für diese Website ist ausgeschaltet (Regel #8000000, Priorität 1000)». */
function verdictText(r: ExplainResult, meta: BuildMeta | null): string {
  // The verdict follows the deciding rule; header rules that also apply
  // (e.g. the GPC header on every request) only decide when nothing else does.
  const decider = r.winner ?? r.headers[0];
  if (!decider) return t('nerdLabExplainNone');
  const { what, why } = decisionWords(decider, meta);
  return t(isLineSource(decider) ? 'nerdLabVerdictLine' : 'nerdLabVerdict', [what, why, String(decider.ruleId), String(decider.priority)]);
}

/** «Ohne diese Ausnahme: Sperrseite (Strict Block) durch EasyList, Priorität 29», or null when no exception decides. */
function counterfactualText(r: ExplainResult, meta: BuildMeta | null): string | null {
  const cf = r.counterfactual;
  if (!cf) return null;
  if (!cf.winner || cf.outcome === 'none' || cf.outcome === 'modifyHeaders') return t('nerdLabCounterfactualNone');
  const { what, why } = decisionWords(cf.winner, meta);
  return t('nerdLabCounterfactual', [what, why, String(cf.winner.priority)]);
}

const TYPE_KEYS: Record<string, string> = {
  main_frame: 'nerdLabTypeMainFrame',
  sub_frame: 'nerdLabTypeSubFrame',
  script: 'nerdLabTypeScript',
  image: 'nerdLabTypeImage',
  stylesheet: 'nerdLabTypeStylesheet',
  font: 'nerdLabTypeFont',
  xmlhttprequest: 'nerdLabTypeXhr',
  ping: 'nerdLabTypePing',
  media: 'nerdLabTypeMedia',
  websocket: 'nerdLabTypeWebsocket',
  other: 'nerdLabTypeOther',
};

/** «Seitennavigation (main_frame)»: readable name and the DNR type. */
const requestTypeLabel = (type: string): string => (TYPE_KEYS[type] ? `${t(TYPE_KEYS[type]!)} (${type})` : type);

/** The type a pasted URL is checked as, changeable per URL (reruns the check). */
function typeControl(r: ExplainResult, onType: ((req: DryRequest, type: string) => void) | null): HTMLElement {
  const req = r.request;
  const id = nextId('lab-type');
  const label = h('label', { class: 'lab-x__type-label', attrs: { for: id }, text: t('nerdLabExplainCheckedAs') });
  const types: string[] = [...EXPLAIN_TYPES];
  if (!types.includes(req.type)) types.push(req.type);
  const sel = h('select', { class: 'select select--sm lab-x__type', attrs: { id } }, ...types.map((ty) => h('option', { attrs: { value: ty }, text: requestTypeLabel(ty) })));
  sel.value = req.type;
  if (onType && req.line !== undefined) sel.addEventListener('change', () => onType(req, sel.value));
  else sel.disabled = true;
  return h(
    'span',
    { class: 'lab-x__meta' },
    label,
    sel,
    req.typeGuessed ? h('span', { class: 'lab-x__guess', text: t('nerdLabExplainTypeGuessed') }) : null,
    h('span', { class: 'lab-x__site', text: req.initiator ? t('nerdLabExplainOnPage', req.initiator) : t('nerdLabExplainNoPage') }),
  );
}

function explainItem(r: ExplainResult, meta: BuildMeta | null, onType: ((req: DryRequest, type: string) => void) | null): HTMLElement {
  const w = r.winner;
  const decider = w ?? r.headers[0];
  const outcome = !w ? r.outcome : w.action === 'allowAllRequests' ? 'allow' : (w.action as ExplainResult['outcome']);
  const cf = counterfactualText(r, meta);
  const head = h('div', { class: 'lab-x__head' }, h('code', { class: 'lab-x__url', text: r.request.url, attrs: { title: r.request.url } }), typeControl(r, onType));
  const rows = r.hits.map((x) => {
    const win = !!w && x.source === w.source && x.ruleId === w.ruleId && x.action === w.action && x.page === w.page;
    const isStatic = !x.source.startsWith('_') && x.source !== 'custom' && x.source !== 'admin';
    const fd = filterDisplay(x, x.page && r.request.initiator ? `https://${r.request.initiator}/` : r.request.url);
    const derivedTitle = t('nerdLabExplainDerived', fmtNumber(Math.max(x.filterCount, 2)));
    const codes: HTMLElement[] = fd.shown.map((f, i) =>
      h('code', { class: i < fd.relevant ? 'lab-x__hit' : '', text: f, attrs: fd.derived && i === 0 ? { title: derivedTitle } : {} }),
    );
    // A rebuilt text is not a line read from the list: say so visibly, not only in the tooltip.
    if (fd.derived && codes.length > 0) codes.splice(1, 0, h('span', { class: 'lab-x__derived', text: t('nerdLabExplainDerivedTag'), attrs: { title: derivedTitle } }));
    return h(
      'tr',
      { class: win ? 'lab-x__win' : '' },
      h('td', { class: 'lab-x__mark' }, win ? icon('check', 12) : null, win ? h('span', { class: 'sr-only', text: t('nerdLabExplainWinner') }) : null),
      h('td', { class: 'lab-x__action' }, h('span', { class: 'lab-x__act', text: actionLabel(x) }), h('span', { class: 'mono lab-x__raw', text: x.action })),
      h('td', { class: 'num', text: String(x.priority) }),
      h('td', { class: 'lab-x__src', text: sourceName(x, meta) }),
      h(
        'td',
        { class: 'lab-x__filter' },
        ...(codes.length ? codes : [h('span', { class: 'mono db-muted', text: `#${x.ruleId}` })]),
        fd.more ? h('span', { class: 'lab-x__more', text: t('nerdLabExplainMore', fmtNumber(fd.more)) }) : null,
        isStatic && fd.shown.length
          ? h(
              'button',
              {
                class: 'act-history',
                attrs: { type: 'button', title: t('nerdLabHistoryTitle'), 'aria-label': `${t('nerdLabHistory')}: ${t('nerdLabHistoryTitle')}` },
                on: { click: () => void openRuleHistory(`${x.source}:${x.ruleId}`, meta, fd.relevant ? fd.shown.slice(0, fd.relevant) : undefined) },
              },
              t('nerdLabHistory'),
              icon('external', 10),
            )
          : null,
      ),
    );
  });
  return h(
    'li',
    { class: 'lab-x' },
    head,
    h('p', { class: `lab-x__verdict lab-x__verdict--${decider ? outcome : 'none'}`, text: verdictText(r, meta) }),
    cf ? h('p', { class: 'lab-x__cf', text: cf }) : null,
    rows.length
      ? h(
          'div',
          { class: 'lab-int__scroll' },
          h(
            'table',
            { class: 'act-table lab-x__table' },
            h(
              'thead',
              null,
              h(
                'tr',
                null,
                h('th', { attrs: { scope: 'col' } }, h('span', { class: 'sr-only', text: t('nerdLabExplainWinner') })),
                ...[t('nerdLabExplainColAction'), t('nerdLabExplainColPriority'), t('nerdLabExplainColSource'), t('nerdLabExplainColFilter')].map((c) => h('th', { text: c, attrs: { scope: 'col' } })),
              ),
            ),
            h('tbody', null, ...rows),
          ),
        )
      : null,
    r.capped ? h('p', { class: 'lab-res__note', text: t('nerdLabExplainCapped', fmtNumber(EXPLAIN_MAX_HITS)) }) : null,
  );
}

function playgroundSection(meta: BuildMeta | null, cfg: EffectiveConfig): Tool {
  const historyOn = cfg.settings.history.enabled;
  const filtersId = nextId('lab');
  const filtersArea = h('textarea', {
    class: 'lab-area mono',
    attrs: { id: filtersId, spellcheck: 'false', autocapitalize: 'off', autocomplete: 'off', wrap: 'off', rows: 10, placeholder: '||ads.example.com^\n@@||ads.example.com/ok.js$script\n/banner/*/img^$image,3p' },
  });
  const urlsId = nextId('lab');
  const urlsArea = h('textarea', {
    class: 'lab-area mono',
    attrs: { id: urlsId, spellcheck: 'false', autocapitalize: 'off', autocomplete: 'off', wrap: 'off', rows: 6, placeholder: 'https://ads.example.com/a.js script news.example.ch\nhttps://cdn.example.net/pixel.gif' },
  });
  let source: Source = historyOn ? 'history' : 'urls';
  const sourceSeg = segmented<Source>({
    options: [
      { value: 'history', label: t('nerdLabSourceHistory') },
      { value: 'urls', label: t('nerdLabSourceUrls') },
      { value: 'both', label: t('nerdLabSourceBoth') },
    ],
    value: source,
    label: t('nerdLabSourceLabel'),
    onChange: (v) => {
      source = v;
      paintSource();
    },
  });
  const siteIn = h('input', { class: 'input', attrs: { type: 'search', placeholder: t('actFilterSite'), 'aria-label': t('actFilterSite'), spellcheck: 'false', autocomplete: 'off' } });
  const limitSel = h('select', { class: 'select', attrs: { 'aria-label': t('nerdLabHistoryLimit') } }, ...HISTORY_LIMITS.map((n) => h('option', { attrs: { value: String(n) }, text: t('nerdLabHistoryLast', fmtNumber(n)) })));
  limitSel.value = '2000';
  const historyCtl = h('div', { class: 'lab-hist' }, h('span', { class: 'act-search' }, icon('search', 14), siteIn), limitSel);
  const historyNote = historyOn ? null : h('div', { class: 'lab-gap' }, notice(t('nerdLabHistoryOffTitle'), t('nerdLabHistoryOffText'), 'info', true));
  // Explain the pasted URLs against the installed rules too ("why would this be blocked?").
  const listsBox = h('input', { attrs: { type: 'checkbox' } });
  const listsCheck = h('label', { class: 'lab-check' }, listsBox, h('span', { text: t('nerdLabExplainToggle') }));
  const urlsBlock = h('div', { class: 'lab-field' }, h('label', { class: 'lab-label', attrs: { for: urlsId }, text: t('nerdLabUrlsLabel') }), urlsArea, h('p', { class: 'lab-hint', text: t('nerdLabUrlsHint') }), listsCheck);
  // How many recorded requests a run would test: the history is only read on Run, so say up front what is there.
  const histCount = h('p', { class: 'lab-hint lab-hist__count', attrs: { role: 'status' } });
  const histBlock = h('div', { class: 'lab-field' }, h('div', { class: 'lab-label', text: t('nerdLabHistoryLabel') }), historyCtl, historyOn ? histCount : null, h('p', { class: 'lab-hint', text: t('nerdLabHistoryHint') }), historyNote);

  let countToken = 0;
  const paintCount = async (): Promise<void> => {
    if (!historyOn || source === 'urls') return;
    const token = ++countToken;
    const site = siteIn.value.trim().toLowerCase();
    const r = await historyEvents(Number(limitSel.value) || 2000, undefined, site);
    if (token !== countToken) return;
    if (!r.ok) {
      histCount.textContent = '';
      return;
    }
    const n = requestsFromEvents(r.data).length;
    histCount.textContent = n === 0 ? t(site ? 'nerdLabHistoryCountNoneSite' : 'nerdLabHistoryCountNone') : plural(n, 'nerdLabHistoryCountOne', 'nerdLabHistoryCount');
  };
  siteIn.addEventListener('input', debounce(() => void paintCount(), 250));
  limitSel.addEventListener('change', () => void paintCount());

  const paintSource = (): void => {
    histBlock.hidden = source === 'urls';
    urlsBlock.hidden = source === 'history';
    void paintCount();
  };

  const runBtn = h('button', { class: 'btn btn--secondary', attrs: { type: 'button' } }, icon('play', 14), t('nerdLabRun'));
  const status = h('span', { class: 'cf-status lab-status', attrs: { role: 'status' } });
  const results = h('div', { class: 'lab-results' });
  // Shown from the first run on: an empty results box is just noise.
  const resultsPanel = panel({ title: t('nerdLabResultsTitle'), class: 'lab-results-panel' }, results);
  resultsPanel.hidden = true;
  let runs = 0;

  /** The type select of an explain result: rewrite that line of the URL box and run again. */
  const onType = (req: DryRequest, type: string): void => {
    if (req.line === undefined) return;
    urlsArea.value = setRequestType(urlsArea.value, req.line, req, type);
    void run();
  };

  /** Pasted URLs against the enabled lists, custom and dynamic rules; progress goes to `status`. */
  const explain = async (requests: DryRequest[], token: number): Promise<HTMLElement | null> => {
    const dnr = chrome.declarativeNetRequest;
    const mine = await myLists();
    myListTitles = new Map(mine.ok ? mine.data.lists.map((l) => [l.slot, l.title]) : []);
    const out = await explainInstalled(requests, {
      meta,
      enabledRulesets: async () => (await dnr.getEnabledRulesets()) ?? [],
      rulesetPath,
      fetchJson: (path) => fetchPackaged(path),
      dynamicRules: async () => (await dnr.getDynamicRules()) as unknown as ExplainRule[],
      sessionRules: async () => (await dnr.getSessionRules()) as unknown as ExplainRule[],
      customText: async () => {
        const r = await getCustom();
        return r.ok ? r.data.text : '';
      },
      adminLines: () => cfg.managed.customFilters ?? [],
      progress: (done, total, src) => {
        if (token === runs) status.textContent = src ? t('nerdLabExplainProgress', [fmtNumber(Math.min(total, done + 1)), fmtNumber(total), src]) : '';
      },
      yieldNow: () => new Promise((r) => setTimeout(r, 0)),
      cancelled: () => token !== runs,
    });
    if (!out) return null;
    return h(
      'section',
      { class: 'lab-xs' },
      h('h3', { class: 'lab-xs__title', text: t('nerdLabExplainTitle') }),
      requests.length > EXPLAIN_MAX_REQUESTS ? h('p', { class: 'lab-res__note', text: t('nerdLabExplainMax', fmtNumber(EXPLAIN_MAX_REQUESTS)) }) : null,
      h('ul', { class: 'lab-xs__list' }, ...out.map((r) => explainItem(r, meta, onType))),
    );
  };

  const run = async (): Promise<void> => {
    const token = ++runs;
    const text = filtersArea.value;
    const explainOn = listsBox.checked && source !== 'history';
    resultsPanel.hidden = false;
    if (text.trim() === '' && !(explainOn && urlsArea.value.trim())) {
      replace(results, emptyState(t('nerdLabEmptyFilters')));
      return;
    }
    runBtn.disabled = true;
    status.textContent = t('nerdLabRunning');
    try {
      const parts: Child[] = [];
      let pasted: DryRequest[] = [];
      let invalid: number[] = [];
      if (source !== 'history') {
        const parsed = parseUrlList(urlsArea.value);
        pasted = parsed.requests;
        invalid = parsed.invalid;
      }
      if (invalid.length) parts.push(h('p', { class: 'lab-res__note', text: t('nerdLabUrlsInvalid', invalid.slice(0, 10).join(', ')) }));
      if (text.trim() !== '') {
        const compiled = compilePlayground(text, meta);
        const requests: DryRequest[] = [];
        let historyFailed = false;
        if (source !== 'urls') {
          const r = await historyEvents(Number(limitSel.value) || 2000, undefined, siteIn.value.trim().toLowerCase());
          if (r.ok) requests.push(...requestsFromEvents(r.data));
          else historyFailed = true;
        }
        requests.push(...pasted);
        const res = dryRun(compiled.filters, requests);
        const network = compiled.filters.filter((f) => f.kind === 'network').length;
        parts.push(
          h(
            'dl',
            { class: 'lab-summary' },
            h('div', null, h('dt', { text: t('nerdLabSumFilters') }), h('dd', { class: 'num', text: fmtNumber(compiled.filters.length) })),
            h('div', null, h('dt', { text: t('nerdLabSumNetwork') }), h('dd', { class: 'num', text: fmtNumber(network) })),
            h('div', null, h('dt', { text: t('nerdLabSumRequests') }), h('dd', { class: 'num', text: fmtNumber(res.requests) })),
            h('div', null, h('dt', { text: t('nerdLabSumMatched') }), h('dd', { class: 'num', text: fmtNumber(res.matched) })),
            ...Object.entries(res.outcomes).map(([o, n]) => h('div', null, h('dt', { text: outcomeLabel(o) }), h('dd', { class: 'num', text: fmtNumber(n ?? 0) }))),
          ),
          historyFailed ? notice(t('dashErrorTitle'), t('nerdLabHistoryFailed'), 'alert', true) : null,
          compiled.truncated ? h('p', { class: 'lab-res__note', text: t('nerdLabTruncated') }) : null,
          requests.length === 0 && network ? h('p', { class: 'lab-res__note', text: t('nerdLabNoRequests') }) : null,
          h('ol', { class: 'lab-res-list' }, ...compiled.filters.map((f) => filterResult(f, res.perFilter[f.index] ?? null))),
        );
      }
      // The dry run shows right away; the list check streams in below it.
      replace(results, ...parts);
      if (explainOn && pasted.length) {
        let block: HTMLElement | null = null;
        try {
          block = await explain(pasted, token);
        } catch (err) {
          console.error('[bastion] explain failed', err);
          block = notice(t('dashErrorTitle'), t('nerdLabExplainFailed'), 'alert', true);
        }
        if (token !== runs) return;
        if (block) results.append(block);
      }
      if (token === runs) status.textContent = '';
    } catch (err) {
      console.error('[bastion] playground failed', err);
      if (token === runs) status.textContent = '';
      replace(results, notice(t('dashErrorTitle'), t('dashErrorText'), 'alert'));
    } finally {
      if (token === runs) runBtn.disabled = false;
    }
  };
  runBtn.addEventListener('click', () => void run());
  paintSource();

  const el = h(
    'div',
    { class: 'lab-play' },
    panel(
      { title: t('nerdLabPlayTitle') },
      h('p', { class: 'db-muted lab-intro', text: t('nerdLabPlayLead') }),
      h(
        'div',
        { class: 'lab-play__grid' },
        h('div', { class: 'lab-field' }, h('label', { class: 'lab-label', attrs: { for: filtersId }, text: t('nerdLabFiltersLabel') }), filtersArea, h('p', { class: 'lab-hint', text: t('nerdLabFiltersHint') })),
        h('div', { class: 'lab-play__src' }, h('div', { class: 'lab-field' }, h('div', { class: 'lab-label', text: t('nerdLabSourceLabel') }), sourceSeg.el), histBlock, urlsBlock),
      ),
      h('div', { class: 'lab-actions' }, runBtn, status),
    ),
    resultsPanel,
  );
  return {
    el,
    focus: () => filtersArea.focus(),
    run: () => {
      if (!runBtn.disabled) void run();
    },
    apply(link) {
      if (link.url) {
        // "Why would this be blocked?": the URL against the playground and the installed rules.
        source = 'urls';
        sourceSeg.set('urls');
        paintSource();
        urlsArea.value = linkRequestLine(link);
        listsBox.checked = true;
      }
      if (link.filter !== undefined) filtersArea.value = link.filter;
      if (link.url || link.filter) void run();
    },
  };
}

// ---------------------------------------------------------------------------
// 2. Ruleset integrity and provenance
// ---------------------------------------------------------------------------

async function hashPackaged(path: string): Promise<string | null> {
  for (const p of packagedCandidates(path)) {
    try {
      const res = await fetch(chrome.runtime.getURL(p));
      if (!res.ok) continue;
      return toHex(await crypto.subtle.digest('SHA-256', await res.arrayBuffer()));
    } catch {
      /* try the next location */
    }
  }
  return null;
}

function integritySection(meta: BuildMeta | null): Tool {
  const verifyBtn = h('button', { class: 'btn btn--secondary', attrs: { type: 'button' } }, icon('shieldOn', 15), t('nerdLabVerify'));
  const progress = h('div', { class: 'lab-progress', hidden: true }, h('span', { class: 'meter' }, h('span', { class: 'meter__fill' })), h('span', { class: 'lab-progress__text num', attrs: { role: 'status' } }));
  const summary = h('div', { class: 'lab-int__summary' });
  const tbody = h('tbody');
  const table = h(
    'div',
    { class: 'lab-int__scroll', hidden: true },
    h(
      'table',
      { class: 'act-table lab-int__table' },
      h('caption', { class: 'sr-only', text: t('nerdLabIntegrityTitle') }),
      h('thead', null, h('tr', null, ...[t('nerdLabColFile'), t('nerdLabColExpected'), t('nerdLabColActual'), t('nerdLabColStatus')].map((c) => h('th', { text: c, attrs: { scope: 'col' } })))),
      tbody,
    ),
  );

  const statusCell = (r: IntegrityRow): HTMLElement => {
    if (r.status === 'ok') return h('span', { class: 'lab-ok' }, icon('check', 13), h('span', { class: 'sr-only', text: t('nerdLabStatusOk') }));
    if (r.status === 'pending') return h('span', { class: 'db-muted', text: '…' });
    return h('span', { class: 'lab-bad' }, icon('close', 13), h('span', { text: r.status === 'missing' ? t('nerdLabStatusMissing') : t('nerdLabStatusMismatch') }));
  };
  const rowEl = (r: IntegrityRow): HTMLElement =>
    h(
      'tr',
      { class: r.status === 'mismatch' || r.status === 'missing' ? 'lab-int__bad' : '' },
      h('td', { class: 'mono lab-int__file', text: r.path }),
      h('td', { class: 'mono lab-int__hash', text: shortHash(r.expected), attrs: { title: r.expected } }),
      h('td', { class: 'mono lab-int__hash', text: shortHash(r.actual), attrs: { title: r.actual ?? '' } }),
      h('td', null, statusCell(r)),
    );

  let running = false;
  const verify = async (): Promise<void> => {
    if (running) return;
    running = true;
    verifyBtn.disabled = true;
    replace(summary);
    const manifest = await fetchPackaged<IntegrityManifest>('rulesets/integrity.json');
    if (!isIntegrityManifest(manifest)) {
      replace(summary, notice(t('nerdLabIntegrityMissingTitle'), t('nerdLabIntegrityMissingText'), 'info', true));
      running = false;
      verifyBtn.disabled = false;
      return;
    }
    let rows = integrityRows(manifest);
    table.hidden = false;
    progress.hidden = false;
    const fill = progress.querySelector<HTMLElement>('.meter__fill')!;
    const text = progress.querySelector<HTMLElement>('.lab-progress__text')!;
    const repaint = debounce(() => replace(tbody, ...rows.map(rowEl)), 60);
    replace(tbody, ...rows.map(rowEl));
    let done = 0;
    // A few files at a time: the rulesets are large, but the page should stay responsive.
    const queue = rows.map((_, i) => i);
    const worker = async (): Promise<void> => {
      for (let i = queue.shift(); i !== undefined; i = queue.shift()) {
        const actual = await hashPackaged(rows[i].path);
        rows = rows.map((r, j) => (j === i ? settleRow(r, actual) : r));
        done++;
        fill.style.width = `${Math.round((done / rows.length) * 100)}%`;
        text.textContent = t('nerdLabHashing', [fmtNumber(done), fmtNumber(rows.length)]);
        repaint();
      }
    };
    await Promise.all([worker(), worker(), worker(), worker()]);
    replace(tbody, ...rows.map(rowEl));
    progress.hidden = true;
    const s = integritySummary(rows);
    const when = Date.parse(manifest.builtAt);
    const builtAt = Number.isFinite(when) ? fmtDateTime(when) : manifest.builtAt;
    const metaMatches = !meta || meta.builtAt === manifest.builtAt;
    replace(
      summary,
      s.mismatch || s.missing
        ? h('p', { class: 'lab-int__verdict lab-int__verdict--bad' }, icon('alert', 16), t('nerdLabIntegrityBad', [fmtNumber(s.mismatch + s.missing), fmtNumber(rows.length)]))
        : h('p', { class: 'lab-int__verdict' }, icon('check', 16), t('nerdLabIntegrityOk', [fmtNumber(s.ok), builtAt])),
      metaMatches ? null : h('p', { class: 'lab-res__note', text: t('nerdLabIntegrityOtherBuild') }),
    );
    // A clean result needs no table; mismatches stay visible.
    if (!s.mismatch && !s.missing) table.hidden = true;
    running = false;
    verifyBtn.disabled = false;
  };
  verifyBtn.addEventListener('click', () => void verify());

  // Provenance: exactly what the build fetched.
  const copyBtn = h('button', { class: 'btn btn--secondary btn--sm', attrs: { type: 'button', disabled: !meta }, text: t('nerdLabCopyJson') });
  copyBtn.addEventListener('click', async () => {
    if (!meta) return;
    try {
      await navigator.clipboard.writeText(`${JSON.stringify(provenance(meta), null, 2)}\n`);
      toast(t('nerdLabCopied'), icon('check', 15));
    } catch {
      toast(t('errorSaveFailed'), icon('alert', 15));
    }
  });
  const sources = meta
    ? h(
        'div',
        { class: 'lab-int__scroll lab-prov__scroll' },
        h(
          'table',
          { class: 'act-table lab-prov' },
          h('caption', { class: 'sr-only', text: t('nerdLabProvTitle') }),
          h('thead', null, h('tr', null, ...[t('aboutColList'), t('nerdLabColSource'), 'SHA-256', t('nerdLabColBytes'), t('aboutColVersion'), t('nerdLabColModified')].map((c) => h('th', { text: c, attrs: { scope: 'col' } })))),
          h(
            'tbody',
            null,
            ...meta.lists.flatMap((l) =>
              (l.sources ?? []).map((s, i) =>
                h(
                  'tr',
                  null,
                  h('td', { class: 'lab-prov__list' }, i === 0 ? dir().name(l.id) : ''),
                  h('td', { class: 'lab-prov__url' }, /^https?:\/\//.test(s.url) ? extLink(s.url, h('span', { class: 'mono', text: s.url })) : h('span', { class: 'mono', text: s.url })),
                  h('td', { class: 'mono lab-int__hash', text: shortHash(s.sha256), attrs: { title: s.sha256 } }),
                  h('td', { class: 'num', text: fmtNumber(s.bytes) }),
                  h('td', { class: 'mono', text: s.version ?? '–' }),
                  h('td', { class: 'mono', text: s.lastModified ?? '–' }),
                ),
              ),
            ),
          ),
        ),
      )
    : emptyState(t('dashErrorTitle'));

  const el = h(
    'div',
    { class: 'lab-int' },
    panel(
      { title: t('nerdLabIntegrityTitle') },
      h('p', { class: 'db-muted lab-intro', text: t('nerdLabIntegrityLead') }),
      h('div', { class: 'lab-actions' }, verifyBtn, progress),
      summary,
      table,
      h('p', { class: 'lab-caption' }, icon('info', 13), h('span', { text: t('nerdLabIntegrityCaption') })),
    ),
    panel(
      { title: t('nerdLabProvTitle'), aside: copyBtn },
      h('p', { class: 'db-muted lab-intro', text: meta ? t('nerdLabProvLead', [fmtDateTime(Date.parse(meta.builtAt) || 0), meta.extensionVersion]) : '' }),
      sources,
      meta ? h('p', { class: 'lab-caption mono', text: `uBO ${meta.vendor.ublock.slice(0, 12)} · brave-resources ${meta.vendor.braveResources.slice(0, 12)} · brave-lists ${meta.vendor.braveLists.slice(0, 12)}` }) : null,
    ),
  );
  return { el, focus: () => verifyBtn.focus(), run: () => void verify() };
}

// ---------------------------------------------------------------------------
// 3. Filter blame
// ---------------------------------------------------------------------------

function blameSection(meta: BuildMeta | null): Tool {
  const inId = nextId('lab');
  const input = h('input', { class: 'input mono lab-blame__input', attrs: { id: inId, type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: '||doubleclick.net^' } });
  const listSel = h(
    'select',
    { class: 'select', attrs: { 'aria-label': t('nerdLabBlameList') } },
    h('option', { attrs: { value: 'all' }, text: t('nerdLabBlameAll') }),
    ...(meta?.lists ?? []).map((l) => h('option', { attrs: { value: l.id }, text: dir().name(l.id) })),
  );
  const out = h('div', { class: 'lab-blame__out', attrs: { 'aria-live': 'polite' } });
  const go = (): void => {
    const filter = input.value.trim();
    if (!filter) {
      replace(out);
      return;
    }
    const groups = blameFor(meta, listSel.value, filter);
    replace(out, groups.length ? blameList(groups) : emptyState(t('nerdLabBlameNone'), t('nerdLabBlameNoneText')));
  };
  const btn = h('button', { class: 'btn btn--secondary', attrs: { type: 'button' } }, icon('search', 14), t('nerdLabBlameGo'));
  btn.addEventListener('click', go);
  input.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') {
      ev.preventDefault();
      go();
    }
  });
  listSel.addEventListener('change', () => {
    if (input.value.trim()) go();
  });
  const el = panel(
    { title: t('nerdLabBlameTitle') },
    h('p', { class: 'db-muted lab-intro', text: t('nerdLabBlameLead') }),
    h('div', { class: 'lab-blame__form' }, h('label', { class: 'sr-only', attrs: { for: inId }, text: t('nerdLabBlameInput') }), input, listSel, btn),
    out,
    h('p', { class: 'lab-caption' }, icon('info', 13), h('span', { text: t('nerdLabBlameCaption') })),
  );
  return {
    el,
    focus: () => input.focus(),
    run: go,
    apply(link) {
      if (link.filter === undefined) return;
      input.value = link.filter;
      go();
    },
  };
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

/** Keyboard hint: platform modifier for "run". */
const RUN_KEY = /Mac|iPhone|iPad/.test(navigator.platform) ? '⌘ Enter' : 'Ctrl+Enter';

function isField(el: Element | null): el is HTMLElement {
  return el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement || (el instanceof HTMLElement && el.isContentEditable);
}

export function labView(): View {
  const cleanup: (() => void)[] = [];
  return {
    async render(root) {
      const [cfgR, meta] = await Promise.all([getConfig(), getMeta()]);
      const cfg = cfgR.ok ? cfgR.data : null;
      if (!cfg?.settings.nerd?.enabled) {
        mount(root, pageHead(t('nerdLabTitle'), t('nerdLabLead')), emptyState(t('nerdLabOffTitle'), t('nerdLabOffText'), h('a', { class: 'btn btn--secondary', attrs: { href: '#settings' }, text: t('navSettings') })));
        return;
      }
      const sections: Record<Section, () => Tool> = {
        playground: () => playgroundSection(meta, cfg),
        integrity: () => integritySection(meta),
        blame: () => blameSection(meta),
      };
      // Tools are built once and kept, so switching back keeps the playground's text and results.
      const built = new Map<Section, Tool>();
      const slot = h('div', { class: 'lab-slot' });
      let current: Section = 'playground';
      const show = (s: Section): Tool => {
        current = s;
        for (const tool of built.values()) tool.el.hidden = true;
        let tool = built.get(s);
        if (!tool) {
          tool = sections[s]();
          built.set(s, tool);
          slot.append(tool.el);
        }
        tool.el.hidden = false;
        return tool;
      };
      const seg = segmented<Section>({
        options: [
          { value: 'playground', label: t('nerdLabTabPlayground') },
          { value: 'integrity', label: t('nerdLabTabIntegrity') },
          { value: 'blame', label: t('nerdLabTabBlame') },
        ],
        value: 'playground',
        label: t('nerdLabTabsLabel'),
        onChange: (s) => {
          // replaceState: no hashchange, so the router keeps this view.
          history.replaceState(null, '', s === 'playground' ? '#lab' : `#lab/${s}`);
          show(s);
        },
      });
      /** Open the tool of a #lab… hash and apply its deep-link values. */
      const follow = (hash: string): void => {
        const link = parseLabHash(hash);
        seg.set(link.section);
        const tool = show(link.section);
        if (link.url || link.filter !== undefined) tool.apply?.(link);
      };

      const kbd = (k: string): HTMLElement => h('kbd', { class: 'lab-kbd', text: k });
      const sep = (): HTMLElement => h('span', { class: 'lab-keys__sep', text: '·' });
      const keys = h('p', { class: 'lab-keys', attrs: { 'aria-hidden': 'true' } }, kbd('/'), ` ${t('nerdLabKeyFocus')}`, sep(), kbd(RUN_KEY), ` ${t('nerdLabKeyRun')}`, sep(), kbd('Esc'), ` ${t('nerdLabKeyBlur')}`);
      mount(root, pageHead(t('nerdLabTitle'), t('nerdLabLead'), seg.el), keys, slot);
      follow(location.hash);

      // "/" focuses the tool's main input, Ctrl/Cmd+Enter runs it, Esc leaves a field.
      const onKey = (ev: KeyboardEvent): void => {
        if (ev.defaultPrevented || ev.isComposing || !root.isConnected || document.querySelector('dialog[open]')) return;
        const tool = built.get(current);
        if (!tool) return;
        const active = document.activeElement;
        if (ev.key === '/' && !ev.ctrlKey && !ev.metaKey && !ev.altKey && !isField(active)) {
          ev.preventDefault();
          tool.focus();
        } else if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) {
          ev.preventDefault();
          tool.run();
        } else if (ev.key === 'Escape' && isField(active) && root.contains(active)) {
          active.blur();
        }
      };
      // The router does not re-render for #lab -> #lab?url=… (same view): follow it here.
      const onHash = (): void => {
        if (/^#lab(?:[/?]|$)/i.test(location.hash)) follow(location.hash);
      };
      document.addEventListener('keydown', onKey);
      window.addEventListener('hashchange', onHash);
      cleanup.push(() => document.removeEventListener('keydown', onKey), () => window.removeEventListener('hashchange', onHash));
    },
    dispose() {
      for (const fn of cleanup.splice(0)) fn();
    },
  };
}
