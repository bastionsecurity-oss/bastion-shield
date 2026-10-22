// Bastion Shield — popup nerd statusline (docs/NERD-MODE.md). Shown only
// while popup:state carries `nerd` (nerd mode on); with nerd mode off the
// popup is unchanged. One quiet mono row at the bottom of the popup:
//
//   ≠ microsoft.com   fp 11   clip 1   14 hosts                   Ctrl K
//   [Sieht aus wie microsoft.com - the explanation, inline]
//
// Ctrl+K, "/" or ":" turn it into a command line (commands.ts). A running
// filter bisect takes over the row and is answered with single keys (y / n /
// Esc, then k / b / Esc). The bisect lives in the service worker: the tab
// reloads after every answer and the popup may close, so everything here is
// re-rendered from popup:state / nerd:bisect 'state' when it opens again.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BisectCandidate, BisectView, BuildMeta, FpVector, MsgNerdBisect, NerdBlockedHost, PopupState } from '../../shared/types.ts';
import { h, replace } from '../shared/dom.ts';
import { fmtNumber, plural, t } from '../shared/i18n.ts';
import { ListDirectory } from '../shared/labels.ts';
import { call, fetchPackaged, type Result } from '../shared/messaging.ts';
import { buildReport, hostFrom, labPath, suggest, targetUrl, type CommandContext, type CommandId, type Suggestion } from './commands.ts';

type Described = BisectCandidate & { filters: string[]; lists: string[] };

/** Filter lines shown per culprit. */
const FILTERS_SHOWN = 3;
/** Blocked-host list refresh (rides on the popup's state poll). */
const HOSTS_MIN_MS = 2000;
const FLASH_MS = 2200;

// ------------------------------------------------------------------- pure --

/** Total fingerprinting calls and the vectors (most calls first, then name). */
export function fpSummary(fp: Partial<Record<FpVector, number>> | null | undefined, top = Infinity): { total: number; top: { vector: FpVector; n: number }[] } {
  const rows = Object.entries(fp ?? {})
    .filter((e): e is [FpVector, number] => typeof e[1] === 'number' && Number.isFinite(e[1]) && e[1] > 0)
    .map(([vector, n]) => ({ vector, n: Math.floor(n) }))
    .sort((a, b) => b.n - a.n || a.vector.localeCompare(b.vector));
  return { total: rows.reduce((s, r) => s + r.n, 0), top: rows.slice(0, top) };
}

const str = (v: unknown): v is string => typeof v === 'string';
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter(str) : []);
const count = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0);

function described(raw: unknown): Described | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  if (!str(r.host) || !r.host) return null;
  return { host: r.host, rules: strs(r.rules), count: count(r.count), filters: strs(r.filters), lists: strs(r.lists) };
}

/** Validate a BisectView from the service worker; anything unusable is null (no bisect shown). */
export function normaliseBisect(raw: unknown): BisectView | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  const phase = r.phase;
  if (phase !== 'testing' && phase !== 'found' && phase !== 'clean') return null;
  const v: BisectView = {
    tabId: count(r.tabId),
    site: str(r.site) ? r.site : '',
    phase,
    step: count(r.step),
    maxSteps: count(r.maxSteps),
    remaining: count(r.remaining),
    allowed: strs(r.allowed),
  };
  if (phase === 'found') {
    const c = described(r.culprit);
    if (!c) return null;
    v.culprit = c;
    const also = Array.isArray(r.also) ? r.also.map(described).filter((x): x is Described => x !== null) : [];
    if (also.length) v.also = also;
    if (r.partial === true) v.partial = true;
  }
  return v;
}

/** Validate the 'hosts' reply. */
export function normaliseHosts(raw: unknown): NerdBlockedHost[] {
  if (!Array.isArray(raw)) return [];
  return raw.map(described).filter((x): x is Described => x !== null);
}

/** "bisect 2/≤5": the total is the worst case (shared/bisect.ts), never below the step. */
export function stepLabel(v: Pick<BisectView, 'step' | 'maxSteps'>): string {
  const step = Math.max(1, v.step);
  const max = Math.max(step, v.maxSteps);
  return `bisect ${fmtNumber(step)}/${max === step ? '' : '≤'}${fmtNumber(max)}`;
}

/**
 * The visited host in runs that match the imitated domain and runs that do
 * not (longest common subsequence of characters): "rnicrosoft-login.com" vs
 * "microsoft.com" -> rn | icrosoft | -login | .com, with "rn" and "-login"
 * marked. The popup shows marked runs boxed (shape, not colour).
 */
export function lookalikeRuns(host: string, target: string): { text: string; diff: boolean }[] {
  const a = Array.from(host);
  const b = Array.from(target);
  // Hosts are at most 253 characters: a plain DP table is fine.
  const dp: number[][] = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) dp[i]![j] = a[i] === b[j] ? dp[i + 1]![j + 1]! + 1 : Math.max(dp[i + 1]![j]!, dp[i]![j + 1]!);
  }
  const marks: boolean[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length) {
    if (j < b.length && a[i] === b[j]) {
      marks.push(false);
      i++;
      j++;
    } else if (j < b.length && dp[i]![j + 1]! > dp[i + 1]![j]!) {
      j++;
    } else {
      marks.push(true);
      i++;
    }
  }
  const runs: { text: string; diff: boolean }[] = [];
  a.forEach((ch, k) => {
    const last = runs[runs.length - 1];
    if (last && last.diff === marks[k]) last.text += ch;
    else runs.push({ text: ch, diff: marks[k]! });
  });
  return runs;
}

/** "Alt+Shift+X" -> "alt+shift+x" (the manifest command as the user set it). */
export function shortcutLabel(s: string | undefined): string {
  return (s ?? '').toLowerCase();
}

// -------------------------------------------------------------- messaging --

export async function bisectCall(tabId: number, action: MsgNerdBisect['action'], works?: boolean): Promise<Result<BisectView | null>> {
  const msg: MsgNerdBisect = { type: 'nerd:bisect', action, tabId };
  if (works !== undefined) msg.works = works;
  const res = await call<{ bisect?: unknown }>(msg);
  if (!res.ok) return res;
  return { ok: true, data: normaliseBisect(res.data?.bisect) };
}

async function hostsCall(tabId: number, describe: boolean): Promise<NerdBlockedHost[] | null> {
  const res = await call<{ hosts?: unknown }>({ type: 'nerd:bisect', action: 'hosts', tabId, describe });
  return res.ok ? normaliseHosts(res.data?.hosts) : null;
}

let dirPromise: Promise<ListDirectory> | null = null;
/** List names (meta.json), loaded once and only for a found culprit. */
function listDirectory(): Promise<ListDirectory> {
  dirPromise ??= fetchPackaged<BuildMeta>('rulesets/meta.json').then((m) => new ListDirectory(m));
  return dirPromise;
}

const isMac = (): boolean => /mac/i.test(navigator.platform || navigator.userAgent);

function inField(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return target.isContentEditable || target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT';
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Clipboard API refused (no focus): the classic way.
    const ta = h('textarea', { class: 'sr-only' });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  }
}

// ----------------------------------------------------------------- render --

/** "Sieht aus wie microsoft.com" with the domain marked translate="no". */
function withTarget(target: string): (Node | string)[] {
  const MARK = '';
  const [before = '', after = ''] = t('nerdSlLookTitle', MARK).split(MARK);
  return [before, h('span', { attrs: { translate: 'no' }, text: target }), after];
}

export interface NerdStatuslineOptions {
  tabId: number;
  /** Bisect needs the activity log (it lists the hosts blocked on this page load). */
  logging: () => boolean;
  /** Live counters of this page load (for "copy report"). */
  counts: () => Record<string, number>;
  /** Fetch popup:state again (after "nerd off"). */
  refresh: () => void;
  /** Close the popup after opening a tab. */
  close: () => void;
}

export interface NerdStatusline {
  /** Re-render from a popup:state reply (null nerd hides the statusline). */
  update(state: PopupState): void;
  /** Ask the service worker for the authoritative bisect state. */
  refreshBisect(): Promise<void>;
}

export function createNerdStatusline(root: HTMLElement, opts: NerdStatuslineOptions): NerdStatusline {
  let state: PopupState | null = null;
  let bisect: BisectView | null = null;
  let busy = false;
  let dir: ListDirectory | null = null;
  let hosts: NerdBlockedHost[] | null = null;
  let hostsAt = 0;
  let hostsBusy = false;
  let fpOpen = false;
  let clipOpen = false;
  let flash = '';
  let flashTimer: ReturnType<typeof setTimeout> | undefined;
  const shortcuts: Partial<Record<CommandId, string>> = {};
  /** What the last render showed: polling must not rebuild (and drop focus from) an unchanged row. */
  let shown = '';

  // Command line.
  let cmdOpen = false;
  let items: Suggestion[] = [];
  let sel = 0;
  let prevFocus: Element | null = null;
  const input = h('input', {
    class: 'pp-sl__input',
    attrs: {
      type: 'text',
      role: 'combobox',
      'aria-autocomplete': 'list',
      'aria-expanded': 'true',
      'aria-controls': 'pp-sl-list',
      'aria-label': t('nerdCmdLabel'),
      placeholder: t('nerdCmdPlaceholder'),
      spellcheck: 'false',
      autocomplete: 'off',
    },
  });
  const list = h('div', { class: 'pp-sl__list', attrs: { id: 'pp-sl-list', role: 'listbox', 'aria-label': t('nerdCmdLabel') } });

  void (async () => {
    try {
      for (const c of (await chrome.commands?.getAll()) ?? []) {
        if (c.name === 'nerd-bisect' && c.shortcut) shortcuts.bisect = shortcuts['bisect cancel'] = shortcutLabel(c.shortcut);
      }
    } catch {
      /* no commands API (popup opened as a tab in tests) */
    }
  })();

  const visible = (): boolean => !root.hidden;

  const say = (text: string, ms = FLASH_MS): void => {
    flash = text;
    if (flashTimer !== undefined) clearTimeout(flashTimer);
    flashTimer = setTimeout(() => {
      flash = '';
      render();
    }, ms);
    render();
  };

  const openTab = async (path: string): Promise<void> => {
    try {
      await chrome.tabs.create({ url: chrome.runtime.getURL(path) });
      opts.close();
    } catch {
      say(t('nerdSlFailed'));
    }
  };

  const refreshHosts = async (force = false): Promise<void> => {
    if (hostsBusy || (!force && Date.now() - hostsAt < HOSTS_MIN_MS)) return;
    hostsBusy = true;
    const got = await hostsCall(opts.tabId, false);
    hostsBusy = false;
    hostsAt = Date.now();
    if (got) {
      hosts = got;
      render();
    }
  };

  // --- bisect ------------------------------------------------------------

  const act = async (action: MsgNerdBisect['action'], works?: boolean): Promise<void> => {
    if (busy) return;
    busy = true;
    render();
    const res = await bisectCall(opts.tabId, action, works);
    busy = false;
    if (res.ok) {
      bisect = res.data && res.data.phase !== 'cancelled' ? res.data : null;
      if (action === 'keep') say(t('nerdBisectKept'));
    } else {
      say(res.error === 'locked' ? t('nerdBisectLocked') : t('nerdBisectError'), 3500);
    }
    render();
  };

  const startBisect = (): void => {
    const s = state;
    if (!s) return;
    if (!s.siteSettings.enabled) return say(t('nerdBisectNeedsProtection'), 3500);
    if (!opts.logging()) return say(t('nerdBisectNeedsLog'), 3500);
    void act('start');
  };

  const blame = (filter: string | undefined): void => {
    if (filter) void openTab(labPath('blame', { filter }));
  };

  // --- commands ----------------------------------------------------------

  const ctx = (): CommandContext => ({ bisecting: bisect !== null, hosts: hosts ?? [], shortcuts });

  const run = async (s: Suggestion): Promise<void> => {
    closeCmd();
    const st = state;
    if (!st) return;
    switch (s.id) {
      case 'bisect':
        return startBisect();
      case 'bisect cancel':
        return act('cancel');
      case 'why': {
        const url = targetUrl(s.arg, st.url);
        if (!url) return say(t('nerdCmdBadHost'));
        return openTab(labPath('why', { url, site: st.site }));
      }
      case 'blame':
        return blame(s.arg.trim());
      case 'allow': {
        const host = hostFrom(s.arg);
        if (!host) return say(t('nerdCmdBadHost'));
        const res = await call<{ added?: unknown }>({ type: 'nerd:bisect', action: 'allow', tabId: opts.tabId, host });
        if (res.ok) return say(t('nerdSlAllowed', host), 3500);
        return say(res.error === 'locked' ? t('nerdBisectLocked') : res.error === 'invalid host' ? t('nerdCmdBadHost') : t('nerdSlFailed'), 3500);
      }
      case 'fp':
        if (!st.nerd?.fp) return say(t('nerdSlFpOff'));
        if (fpSummary(st.nerd.fp).total === 0) return say(t('nerdSlFpNone'));
        fpOpen = true;
        return render();
      case 'copy report': {
        const n = st.nerd;
        const report = buildReport({
          site: st.site,
          url: st.url,
          at: Date.now(),
          counts: opts.counts(),
          hosts: (await hostsCall(opts.tabId, true)) ?? hosts ?? [],
          fp: n?.fp ?? null,
          clipboardBlocked: n?.clipboardBlocked ?? 0,
          lookalike: n?.lookalike ?? null,
          version: st.version,
        });
        return say((await copyText(report)) ? t('nerdSlCopied') : t('nerdSlFailed'));
      }
      case 'lab':
        return openTab(labPath('lab'));
      case 'nerd off': {
        const res = await call<{ ignored?: unknown }>({ type: 'settings:set', patch: { nerd: { enabled: false } } });
        if (!res.ok) return say(t('nerdSlFailed'));
        if (Array.isArray(res.data?.ignored) && res.data.ignored.includes('nerd.enabled')) return say(t('nerdSlPolicy'), 3500);
        return opts.refresh();
      }
    }
  };

  const renderList = (): void => {
    if (sel >= items.length) sel = Math.max(0, items.length - 1);
    const rows = items.map((s, i) =>
      h(
        'div',
        {
          class: 'pp-sl__opt',
          attrs: { id: `pp-sl-opt-${i}`, role: 'option', 'aria-selected': String(i === sel) },
          on: {
            // Keep focus in the input.
            mousedown: (e) => e.preventDefault(),
            mousemove: () => {
              if (sel === i) return;
              sel = i;
              renderList();
            },
            click: () => void (s.ready ? run(s) : complete(s)),
          },
        },
        h('span', { class: 'pp-sl__name', text: s.arg ? `${s.name} ${s.arg}` : s.name }),
        h('span', { class: 'pp-sl__desc', text: s.count !== undefined ? plural(s.count, 'nerdCmdHostCountOne', 'nerdCmdHostCount') : t(s.desc) }),
        s.shortcut ? h('kbd', { text: s.shortcut }) : null,
      ),
    );
    replace(list, ...(rows.length ? rows : [h('div', { class: 'pp-sl__empty', text: t('nerdCmdNoMatch') })]));
    if (items.length) input.setAttribute('aria-activedescendant', `pp-sl-opt-${sel}`);
    else input.removeAttribute('aria-activedescendant');
  };

  const refreshList = (): void => {
    items = suggest(input.value, ctx());
    sel = 0;
    renderList();
  };

  function complete(s: Suggestion): void {
    input.value = s.complete;
    input.setSelectionRange(input.value.length, input.value.length);
    refreshList();
  }

  function openCmd(): void {
    if (cmdOpen || !state) return;
    cmdOpen = true;
    prevFocus = document.activeElement;
    input.value = '';
    replace(root, h('div', { class: 'pp-sl__cmd' }, h('span', { class: 'pp-sl__prompt', attrs: { 'aria-hidden': 'true' }, text: '>' }), input), list);
    refreshList();
    input.focus();
    // Completions for why / allow.
    void refreshHosts(true);
  }

  function closeCmd(): void {
    if (!cmdOpen) return;
    cmdOpen = false;
    shown = '';
    render();
    const back = prevFocus;
    prevFocus = null;
    if (back instanceof HTMLElement && back !== document.body && back.isConnected) back.focus();
    else if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
  }

  input.addEventListener('input', refreshList);
  input.addEventListener('keydown', (e) => {
    const key = e.key;
    const ctrl = e.ctrlKey && !e.altKey && !e.metaKey;
    const move = key === 'ArrowDown' || key === 'ArrowUp' || (ctrl && (key === 'n' || key === 'p'));
    let handled = true;
    if (key === 'Escape') closeCmd();
    else if (key === 'ArrowDown' || (ctrl && key === 'n')) sel = items.length ? (sel + 1) % items.length : 0;
    else if (key === 'ArrowUp' || (ctrl && key === 'p')) sel = items.length ? (sel - 1 + items.length) % items.length : 0;
    else if (key === 'Tab' && !e.shiftKey && items[sel]) complete(items[sel]!);
    else if (key === 'Enter' && items[sel]) {
      const s = items[sel]!;
      if (s.ready) void run(s);
      else complete(s);
    } else handled = false;
    if (!handled) return;
    e.preventDefault();
    e.stopPropagation();
    if (move) renderList();
  });

  // --- statusline ----------------------------------------------------------

  const sep = (): HTMLElement => h('span', { class: 'pp-sl__sep', attrs: { 'aria-hidden': 'true' }, text: '-' });

  const keyBtn = (k: string, label: string, onClick: () => void): HTMLButtonElement =>
    h('button', { class: 'pp-sl__key', attrs: { type: 'button', disabled: busy }, on: { click: onClick } }, h('kbd', { text: k }), h('span', { text: label }));

  const hint = (): HTMLElement =>
    flash
      ? h('span', { class: 'pp-sl__flash', attrs: { role: 'status' }, text: flash })
      : h(
          'button',
          { class: 'pp-sl__hint', attrs: { type: 'button', title: t('nerdSlCommands'), 'aria-label': t('nerdSlCommands') }, on: { click: openCmd } },
          h('kbd', { attrs: { translate: 'no' }, text: isMac() ? '⌘\u00a0K' : 'Ctrl\u00a0K' }),
        );

  const statusRows = (): HTMLElement[] => {
    const s = state!;
    const n = s.nerd!;
    const parts: HTMLElement[] = [];
    const fp = fpSummary(n.fp);
    if (fp.total > 0) {
      const breakdown = fp.top.map((x) => `${x.vector} ${fmtNumber(x.n)}`).join(' - ');
      parts.push(
        h('button', {
          class: 'pp-sl__item pp-sl__item--btn',
          attrs: { type: 'button', title: `${t('nerdSlFpTitle')}: ${breakdown}`, 'aria-expanded': String(fpOpen) },
          on: { click: () => ((fpOpen = !fpOpen), render()) },
          text: `fp ${fmtNumber(fp.total)}`,
        }),
      );
    }
    if (n.clipboardBlocked > 0) {
      parts.push(
        h('button', {
          class: 'pp-sl__item pp-sl__item--btn',
          attrs: { type: 'button', 'aria-expanded': String(clipOpen), 'aria-controls': 'pp-sl-clip' },
          on: { click: () => ((clipOpen = !clipOpen), render()) },
          text: `clip ${fmtNumber(n.clipboardBlocked)}`,
        }),
      );
    }
    const hostN = hosts?.length ?? 0;
    if (hostN > 0) parts.push(h('span', { class: 'pp-sl__item', text: plural(hostN, 'nerdSlHostsOne', 'nerdSlHosts') }));
    const l = n.lookalike;
    // Lookalike: a marker in the row and the explanation inline below (never a tooltip).
    if (l) parts.unshift(h('span', { class: 'pp-sl__item pp-sl__look', attrs: { translate: 'no' }, text: `≠ ${l.target}` }));
    const rows: HTMLElement[] = [h('div', { class: 'pp-sl__line' }, h('div', { class: 'pp-sl__items' }, ...parts), hint())];
    if (l) {
      const why = t(l.reason === 'homoglyph' ? 'nerdSlLookHomoglyph' : l.reason === 'typo' ? 'nerdSlLookTypo' : 'nerdSlLookCombo');
      rows.push(
        h(
          'div',
          { class: 'pp-sl__card', attrs: { role: 'note' } },
          h('p', { class: 'pp-sl__card-title' }, ...withTarget(l.target)),
          h(
            'p',
            { class: 'pp-sl__look-host', attrs: { translate: 'no', title: l.host } },
            ...lookalikeRuns(l.host, l.target).map((r) => (r.diff ? h('mark', { class: 'pp-sl__diff', text: r.text }) : r.text)),
          ),
          h('p', { class: 'pp-sl__card-text', text: `${why} ${t('nerdSlLookCheck')}` }),
          clipOpen && n.clipboardBlocked > 0 ? h('p', { class: 'pp-sl__card-note', attrs: { id: 'pp-sl-clip' }, text: t('nerdSlClipLegend', fmtNumber(n.clipboardBlocked)) }) : null,
        ),
      );
    } else if (clipOpen && n.clipboardBlocked > 0) {
      rows.push(h('div', { class: 'pp-sl__note', attrs: { id: 'pp-sl-clip' }, text: t('nerdSlClipLegend', fmtNumber(n.clipboardBlocked)) }));
    }
    if (fpOpen && fp.total > 0) {
      rows.push(h('div', { class: 'pp-sl__rows' }, ...fp.top.flatMap((x) => [h('span', { text: x.vector }), h('span', { class: 'pp-sl__num', text: fmtNumber(x.n) })])));
      if (s.siteSettings.enabled && s.siteSettings.fingerprinting !== 'off') rows.push(h('div', { class: 'pp-sl__note', text: t('nerdPopupFpNoise') }));
    }
    return rows;
  };

  const culpritRows = (c: Described, many: boolean): HTMLElement[] => {
    const names = c.lists.map((id) => (dir ? dir.name(id) : id)).filter(Boolean);
    return [
      ...(many ? [h('div', { class: 'pp-sl__host', text: c.host })] : []),
      ...c.filters.slice(0, FILTERS_SHOWN).map((f) => h('div', { class: 'pp-sl__code', attrs: { title: f }, text: f })),
      ...(c.filters.length === 0 ? [h('div', { class: 'pp-sl__note', text: t('nerdBisectNoFilterText') })] : []),
      ...(names.length ? [h('div', { class: 'pp-sl__note', text: names.join(' - ') })] : []),
    ];
  };

  const bisectRows = (v: BisectView): HTMLElement[] => {
    const tail = flash ? [h('div', { class: 'pp-sl__flash pp-sl__flash--line', attrs: { role: 'status' }, text: flash })] : [];
    if (v.phase === 'testing') {
      return [
        h(
          'div',
          { class: 'pp-sl__line pp-sl__wrap', attrs: { role: 'status' } },
          h('span', { class: 'pp-sl__strong', attrs: { title: t('nerdBisectMaxTitle', fmtNumber(Math.max(v.step, v.maxSteps))) }, text: stepLabel(v) }),
          sep(),
          h('span', { text: plural(v.allowed.length, 'nerdBisectAskOne', 'nerdBisectAsk') }),
        ),
        h('div', { class: 'pp-sl__note pp-sl__trunc', attrs: { title: v.allowed.join('\n') }, text: v.allowed.join(' ') }),
        h(
          'div',
          { class: 'pp-sl__keys' },
          keyBtn('y', t('nerdBisectYes'), () => void act('answer', true)),
          keyBtn('n', t('nerdBisectNo'), () => void act('answer', false)),
          keyBtn('esc', t('nerdBisectAbort'), () => void act('cancel')),
        ),
        ...tail,
      ];
    }
    if (v.phase === 'found' && v.culprit) {
      if (!dir) void listDirectory().then((d) => ((dir = d), render()));
      const all = [v.culprit, ...(v.also ?? [])] as Described[];
      const many = all.length > 1;
      return [
        h(
          'div',
          { class: 'pp-sl__line pp-sl__wrap', attrs: { role: 'status' } },
          h('span', { class: 'pp-sl__note', text: t(many ? 'nerdBisectFoundMany' : 'nerdBisectFound') }),
          many ? null : h('span', { class: 'pp-sl__host', text: v.culprit.host }),
        ),
        ...all.flatMap((c) => culpritRows(c, many)),
        ...(v.partial ? [h('div', { class: 'pp-sl__note', text: t('nerdBisectPartial') })] : []),
        h(
          'div',
          { class: 'pp-sl__keys' },
          keyBtn('k', t('nerdBisectKeep'), () => void act('keep')),
          v.culprit.filters.length ? keyBtn('b', t('nerdBisectBlame'), () => blame(v.culprit?.filters[0])) : null,
          keyBtn('esc', t('nerdBisectDiscard'), () => void act('cancel')),
        ),
        ...tail,
      ];
    }
    return [
      h('div', { class: 'pp-sl__line pp-sl__wrap', attrs: { role: 'status' } }, h('span', { class: 'pp-sl__strong', text: 'bisect' }), sep(), h('span', { text: t('nerdBisectClean') })),
      h('div', { class: 'pp-sl__keys' }, keyBtn('esc', t('nerdBisectOk'), () => void act('cancel'))),
      ...tail,
    ];
  };

  function render(): void {
    const s = state;
    if (!s || !s.nerd || !s.filterable || s.globallyDisabled) {
      shown = '';
      if (cmdOpen) closeCmd();
      root.hidden = true;
      replace(root);
      return;
    }
    root.hidden = false;
    if (cmdOpen) return;
    const n = s.nerd;
    const key = JSON.stringify([n.fp, n.clipboardBlocked, n.lookalike, hosts?.length ?? 0, bisect, busy, !!dir, fpOpen, clipOpen, flash, s.siteSettings.enabled, s.siteSettings.fingerprinting]);
    if (key === shown) return;
    shown = key;
    // A re-rendered button keeps focus (matched by its text).
    const active = document.activeElement;
    const focused = active instanceof HTMLElement && root.contains(active) ? active.textContent : null;
    replace(root, ...(bisect ? bisectRows(bisect) : statusRows()));
    if (focused !== null) Array.from(root.querySelectorAll<HTMLElement>('button')).find((b) => b.textContent === focused)?.focus();
  }

  // --- keys ----------------------------------------------------------------

  document.addEventListener('keydown', (e) => {
    if (!visible() || e.defaultPrevented || e.isComposing || document.querySelector('dialog[open]')) return;
    const key = e.key;
    const lower = key.length === 1 ? key.toLowerCase() : key;
    if ((e.ctrlKey || e.metaKey) && !e.altKey && lower === 'k') {
      e.preventDefault();
      if (cmdOpen) closeCmd();
      else openCmd();
      return;
    }
    if (cmdOpen || inField(e.target) || e.ctrlKey || e.metaKey || e.altKey) return;
    if (key === '/' || key === ':') {
      e.preventDefault();
      openCmd();
      return;
    }
    const v = bisect;
    let handled = true;
    if (v && !busy && v.phase === 'testing' && (lower === 'y' || lower === 'n')) void act('answer', lower === 'y');
    else if (v && !busy && v.phase === 'found' && lower === 'k') void act('keep');
    else if (v && v.phase === 'found' && lower === 'b') blame(v.culprit?.filters[0]);
    else if (v && !busy && key === 'Escape') void act('cancel');
    else if (key === 'Escape' && (fpOpen || clipOpen)) {
      fpOpen = false;
      clipOpen = false;
      render();
    } else handled = false;
    // A handled Escape must not close the popup.
    if (handled) e.preventDefault();
  });

  const refreshBisect = async (): Promise<void> => {
    if (!state?.nerd) return;
    const res = await bisectCall(opts.tabId, 'state');
    if (!res.ok || busy) return;
    bisect = res.data;
    render();
  };

  return {
    update(next: PopupState) {
      state = next;
      if (!busy) {
        const b = normaliseBisect(next.nerd?.bisect ?? null);
        // popup:state reads the worker's memory, which is empty for a moment
        // after a restart: confirm a vanished bisect instead of flickering.
        if (b || !bisect) bisect = b;
        else void refreshBisect();
      }
      render();
      if (next.nerd && next.filterable && !next.globallyDisabled) void refreshHosts();
    },
    refreshBisect,
  };
}
