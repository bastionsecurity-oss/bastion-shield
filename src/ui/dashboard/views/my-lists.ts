// Bastion Shield — «Filterlisten» › «Meine Listen» (Paper DB11, DB13, DB14):
// filter lists the user adds from a web address or a .txt / .list / .hosts
// file (also by dropping it on the card). Input is checked before anything is
// sent (type, size, empty, duplicate address, length) and each problem is
// named right below the field or the file. Each list has its switch, the
// daily update switch and «Jetzt aktualisieren» for addresses, «Umbenennen…»
// (inline, counter from 80 % of 120 characters), «Ersetzen…» (new file, same
// name and switch) and «Entfernen» with «Rückgängig». A file whose title is
// already taken asks «Inhalt ersetzen» or «Als neue Liste hinzufügen» (D05).
// Under the allowCustomLists policy the card is read-only and says why.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { MY_LISTS } from '../../../shared/constants.ts';
import { listTitle } from '../../../shared/list-title.ts';
import type { Message, MyListInfo, MyListsState } from '../../../shared/types.ts';
import { h, replace, toast } from '../../shared/dom.ts';
import { fmtDateTime, fmtNumber, t } from '../../shared/i18n.ts';
import { icon } from '../../shared/icons.ts';
import { choiceDialog, retryToast, switchControl, undoToast } from '../../shared/controls.ts';
import { truncateMiddle, withUnit } from '../../shared/text.ts';
import { errorState, nextId, withBusy } from '../common.ts';
import { myLists } from '../store.ts';

const ACCEPT = '.txt,.list,.hosts,text/plain';
const ALLOWED_EXT = ['txt', 'list', 'hosts'];
/** Rows shown before «Alle N anzeigen». */
export const ROWS_FIRST = 5;
const ERROR_CODES = ['locked', 'not-found', 'too-many', 'too-large', 'empty', 'not-a-list', 'invalid-url', 'duplicate-url', 'fetch-failed', 'invalid-title'];

/** Localised text for an error code from the service worker («fetch-failed: HTTP 404» keeps its detail). */
export function myListErrorText(error: string): string {
  const [code, ...rest] = error.split(':');
  const detail = rest.join(':').trim();
  if (!ERROR_CODES.includes(code)) return t('errorSaveFailed');
  if (code === 'too-many') return t('myListsFull', fmtNumber(MY_LISTS.MAX));
  if (code === 'too-large') return t('myListsErrSize', fmtNumber(Math.round(MY_LISTS.MAX_BYTES / 1_000_000)));
  if (code === 'fetch-failed') return t('myListsErrFetch', detail || '—');
  const key: Record<string, string> = {
    locked: 'myListsLocked',
    'not-found': 'myListsErrNotFound',
    empty: 'myListsErrEmpty',
    'not-a-list': 'myListsErrNotAList',
    'invalid-url': 'myListsErrUrl',
    'duplicate-url': 'myListsErrDuplicate',
    'invalid-title': 'myListsNameEmpty',
  };
  return t(key[code]);
}

/** Filter lines in the list; an older worker reply without `filters` falls back to rules + cosmetics. */
export function myListFilterCount(l: Pick<MyListInfo, 'report'> & { filters?: number }): number {
  if (typeof l.filters === 'number') return l.filters;
  return (l.report?.network ?? 0) + (l.report?.cosmetic ?? 0);
}

export type FileProblem = 'type' | 'size' | 'empty';

/**
 * What is wrong with a picked or dropped file before it is sent, or null:
 * not a text list (extension, or binary content), larger than MY_LISTS.MAX_BYTES,
 * or no filter line at all (only comments and blank lines).
 */
export function checkListFile(name: string, size: number, text?: string): FileProblem | null {
  const dot = name.lastIndexOf('.');
  const ext = dot > 0 ? name.slice(dot + 1).toLowerCase() : '';
  if (ext && !ALLOWED_EXT.includes(ext)) return 'type';
  if (size > MY_LISTS.MAX_BYTES) return 'size';
  if (text === undefined) return null;
  if (text.slice(0, 4096).includes('\u0000')) return 'type';
  const hasFilter = text.split(/\r?\n/).some((line) => {
    const s = line.trim();
    return s !== '' && !s.startsWith('!') && !s.startsWith('#') && !/^\[adblock/i.test(s);
  });
  return hasFilter ? null : 'empty';
}

export type UrlProblem = { code: 'empty' | 'scheme' | 'length' } | { code: 'duplicate'; title: string };

/** What is wrong with a typed list address, or null (https only, at most MAX_URL_LENGTH, not already added). */
export function checkListUrl(raw: string, lists: readonly Pick<MyListInfo, 'url' | 'title'>[]): UrlProblem | null {
  const s = raw.trim();
  if (!s) return { code: 'empty' };
  if (s.length > MY_LISTS.MAX_URL_LENGTH) return { code: 'length' };
  let url: URL;
  try {
    url = new URL(s);
  } catch {
    return { code: 'scheme' };
  }
  if (url.protocol !== 'https:' || !url.hostname) return { code: 'scheme' };
  const same = lists.find((l) => {
    if (!l.url) return false;
    try {
      return new URL(l.url).href === url.href;
    } catch {
      return l.url === s;
    }
  });
  return same ? { code: 'duplicate', title: same.title } : null;
}

/** «118 / 120» once `len` reaches 80 % of `max` (AGENTS.md), else null. */
export function counterText(len: number, max: number): string | null {
  if (len < Math.ceil(max * 0.8)) return null;
  return `${fmtNumber(len)} / ${fmtNumber(max)}`;
}

/** A name for a dialog title: cut at the end past `max` characters. */
export function shortName(name: string, max = 60): string {
  return name.length > max ? `${name.slice(0, max - 1).trimEnd()}…` : name;
}

function fileProblemText(p: FileProblem): string {
  if (p === 'type') return t('myListsErrType');
  if (p === 'size') return t('myListsErrSize', fmtNumber(Math.round(MY_LISTS.MAX_BYTES / 1_000_000)));
  return t('myListsErrEmpty');
}

function urlProblemText(p: UrlProblem): string {
  if (p.code === 'duplicate') return t('myListsErrDuplicateName', shortName(p.title, 40));
  if (p.code === 'length') return t('myListsErrUrlLong', fmtNumber(MY_LISTS.MAX_URL_LENGTH));
  return t('myListsErrUrl');
}

/** «1.2 MB», «820 kB» for a file size in the problem row. */
function sizeText(bytes: number): string {
  if (bytes >= 1e6) return withUnit((Math.round(bytes / 1e5) / 10).toFixed(1), 'MB');
  return withUnit(fmtNumber(Math.max(1, Math.round(bytes / 1e3))), 'kB');
}

/** Ask for one file (no reading yet: the size is checked first). */
function pickFile(): Promise<File | null> {
  return new Promise((resolve) => {
    const input = h('input', { attrs: { type: 'file', accept: ACCEPT } });
    input.addEventListener('change', () => resolve(input.files?.[0] ?? null), { once: true });
    input.addEventListener('cancel', () => resolve(null), { once: true });
    input.click();
  });
}

export function myListsPanel(): HTMLElement {
  const root = h('div', { class: 'my-lists-slot' });
  let state: MyListsState | null = null;
  let busy = false;
  let showAll = false;
  let renaming: string | null = null;
  /** Problems with the last picked files (DB13), newest first. */
  let fileIssues: { name: string; size: number; problem: FileProblem; replaceId?: string }[] = [];
  let urlValue = '';
  let urlError: string | null = null;
  let focusAfter: string | null = null;

  const run = async (msg: Message, okToast: (s: MyListsState) => string | null): Promise<boolean> => {
    if (busy) return false;
    busy = true;
    root.classList.add('is-busy');
    try {
      const r = await myLists(msg);
      if (!r.ok) {
        toast(myListErrorText(r.error), icon('alert', 15));
        // A failed download is recorded on the list: show it.
        const fresh = await myLists();
        if (fresh.ok) draw(fresh.data);
        return false;
      }
      draw(r.data);
      const text = okToast(r.data);
      if (text) toast(text, icon('check', 15));
      return true;
    } finally {
      busy = false;
      root.classList.remove('is-busy');
    }
  };

  /** Check a file and send it; a title that is taken asks «Inhalt ersetzen» or «Als neue Liste hinzufügen». */
  const addFile = async (file: File, replaceId?: string): Promise<void> => {
    const early = checkListFile(file.name, file.size);
    let problem = early;
    let text = '';
    if (!problem) {
      try {
        text = await file.text();
      } catch {
        problem = 'type';
      }
      problem ??= checkListFile(file.name, file.size, text);
    }
    fileIssues = fileIssues.filter((f) => f.name !== file.name);
    if (problem) {
      fileIssues.unshift({ name: file.name, size: file.size, problem, replaceId });
      fileIssues.length = Math.min(fileIssues.length, 3);
      if (state) draw(state);
      return;
    }
    if (state) draw(state);
    const picked = { name: file.name, text };
    if (replaceId) {
      const l = state?.lists.find((x) => x.id === replaceId);
      await run({ type: 'mylists:add', file: picked, replaceId }, () => t('myListsReplacedToast', l?.title ?? ''));
      return;
    }
    const title = listTitle(text, file.name);
    const same = state?.lists.find((l) => l.title.trim().toLowerCase() === title.trim().toLowerCase());
    let target: string | undefined;
    if (same) {
      const choice = await choiceDialog({
        title: t('myListsSameTitle', shortName(same.title)),
        body: t('myListsSameTitleText'),
        icon: 'lists',
        choices: [
          { value: 'replace', label: t('myListsReplaceIt'), primary: true },
          { value: 'new', label: t('myListsAddNew') },
        ],
      });
      if (choice === null) return;
      if (choice === 'replace') target = same.id;
    }
    await run({ type: 'mylists:add', file: picked, replaceId: target }, () => t(target ? 'myListsReplacedToast' : 'myListsAddedToast', same && target ? same.title : title));
  };

  const chooseFile = async (replaceId?: string): Promise<void> => {
    const file = await pickFile();
    if (file) await addFile(file, replaceId);
  };

  const removeList = async (l: MyListInfo): Promise<void> => {
    const ok = await run({ type: 'mylists:remove', id: l.id }, () => null);
    if (!ok) return;
    const restore = async (): Promise<void> => {
      const r = await myLists({ type: 'mylists:restore', id: l.id });
      if (!r.ok) {
        retryToast(myListErrorText(r.error), () => restore());
        return;
      }
      focusAfter = l.id;
      draw(r.data);
      toast(t('myListsRestoredToast', shortName(l.title, 40)), icon('check', 15));
    };
    undoToast(t('myListsRemovedToast', shortName(l.title, 40)), () => restore());
  };

  // ---------------------------------------------------------------- Rows --

  const renameForm = (l: MyListInfo): HTMLElement => {
    const max = MY_LISTS.MAX_TITLE_LENGTH;
    const inputId = nextId('my-list-name-input');
    const errId = nextId('my-list-name-err');
    const counter = h('span', { class: 'field__counter mono', attrs: { 'aria-live': 'polite' } });
    const err = h('p', { class: 'field__error', attrs: { id: errId, 'aria-live': 'polite' }, hidden: true });
    const input = h('input', { class: 'input field__input', attrs: { id: inputId, type: 'text', maxlength: max, autocomplete: 'off', spellcheck: 'false', 'aria-describedby': errId } });
    input.value = l.title;
    const paintCounter = (): void => {
      counter.textContent = counterText(input.value.length, max) ?? '';
    };
    paintCounter();
    input.addEventListener('input', () => {
      paintCounter();
      err.hidden = true;
      input.removeAttribute('aria-invalid');
    });
    const cancel = (): void => {
      renaming = null;
      focusAfter = l.id;
      if (state) draw(state);
    };
    const save = h('button', { class: 'btn btn--primary', attrs: { type: 'submit' }, text: t('myListsSaveName') });
    const form = h(
      'form',
      { class: 'my-lists__rename' },
      h('div', { class: 'field__head' }, h('label', { class: 'field__label', attrs: { for: inputId }, text: t('myListsNameLabel') }), counter),
      h('div', { class: 'field__row' }, input, save, h('button', { class: 'btn btn--quiet', attrs: { type: 'button' }, text: t('actionCancel'), on: { click: cancel } })),
      err,
    );
    input.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape') {
        ev.preventDefault();
        cancel();
      }
    });
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const title = input.value.trim();
      if (!title) {
        err.hidden = false;
        replace(err, icon('alert', 14), t('myListsNameEmpty'));
        input.setAttribute('aria-invalid', 'true');
        input.focus();
        return;
      }
      void withBusy(save, async () => {
        renaming = null;
        focusAfter = l.id;
        const ok = await run({ type: 'mylists:set', id: l.id, title }, () => null);
        if (!ok) renaming = l.id;
      });
    });
    requestAnimationFrame(() => {
      input.focus();
      input.select();
    });
    return form;
  };

  const row = (l: MyListInfo, locked: boolean): HTMLElement => {
    const nameId = nextId('my-list-name');
    // Under the policy the lists are not applied: show them off, whatever the user's switch says.
    const active = l.enabled && !locked;
    const sw = switchControl({
      checked: active,
      labelledBy: nameId,
      disabled: locked,
      onChange: (v) => run({ type: 'mylists:set', id: l.id, enabled: v }, () => null),
    });
    const count = myListFilterCount(l);
    const src = l.source === 'url' && l.url
      ? h('a', { class: 'my-lists__src mono', attrs: { href: l.url, target: '_blank', rel: 'noopener noreferrer', title: l.url, translate: 'no' } }, truncateMiddle(l.url, 64))
      : h('span', { class: 'my-lists__src mono', text: l.fileName ? truncateMiddle(l.fileName, 64) : '—', attrs: { title: l.fileName && l.fileName.length > 64 ? l.fileName : undefined, translate: 'no' } });

    const top = h(
      'div',
      { class: 'lists-row__top' },
      h(
        'div',
        { class: 'lists-row__title' },
        h('h3', { class: 'lists-row__name my-lists__name', text: l.title, attrs: { id: nameId, title: l.title.length > 48 ? l.title : undefined } }),
        h('span', { class: 'lists-row__badge', text: t(l.source === 'url' ? 'myListsSourceUrl' : 'myListsSourceFile') }),
      ),
      h('span', { class: 'lists-row__count num', text: locked ? t('myListsOff') : t('listsFilterLine', fmtNumber(count)) }),
    );
    if (locked) {
      return h('li', { class: 'lists-row lists-row--off lists-row--locked', dataset: { myList: l.id, listId: l.id } }, h('div', { class: 'lists-row__switch' }, sw.el), h('div', { class: 'lists-row__body' }, top));
    }

    const links: HTMLElement[] = [];
    if (l.source === 'url') {
      const auto = h('button', { class: 'db-link db-link--meta', attrs: { type: 'button', 'aria-pressed': String(l.autoUpdate) }, text: t(l.autoUpdate ? 'myListsAutoOn' : 'myListsAutoOff') });
      auto.addEventListener('click', () => void run({ type: 'mylists:set', id: l.id, autoUpdate: !l.autoUpdate }, () => null));
      const upd = h('button', { class: 'db-link', attrs: { type: 'button' }, text: t('myListsUpdateNow') });
      upd.addEventListener('click', () => void withBusy(upd, () => run({ type: 'mylists:update', id: l.id }, () => t('myListsUpdatedToast', shortName(l.title, 40)))));
      links.push(auto, upd);
    }
    const ren = h('button', { class: 'db-link', attrs: { type: 'button', 'data-action': 'rename' }, text: t('myListsRename') });
    ren.addEventListener('click', () => {
      renaming = l.id;
      if (state) draw(state);
    });
    const rep = h('button', { class: 'db-link', attrs: { type: 'button', 'data-action': 'replace' }, text: t('myListsReplace') });
    rep.addEventListener('click', () => void chooseFile(l.id));
    const del = h('button', { class: 'db-link db-link--danger', attrs: { type: 'button', 'data-action': 'remove' }, text: t('myListsRemove') });
    del.addEventListener('click', () => void removeList(l));
    links.push(ren, rep, del);

    const skipped = l.report?.errors?.length ?? 0;
    const stats: string[] = [];
    if (skipped) stats.push(t('myListsSkipped', fmtNumber(skipped)));
    if (l.report?.scriptletsIgnored) stats.push(t('myListsScriptlets', fmtNumber(l.report.scriptletsIgnored)));
    // Only lists that are applied are compiled, so only they take rules.
    if (active) stats.push(t('myListsRuleCost', fmtNumber(l.report?.network ?? 0)));

    const errBox = l.error
      ? h(
          'div',
          { class: 'lists-row__error', attrs: { role: 'alert' } },
          icon('alert', 16),
          h(
            'div',
            null,
            h('p', { class: 'lists-row__error-title', text: t('myListsDownloadFailed') }),
            h('p', { class: 'lists-row__error-text', text: myListErrorText(l.error) }),
            l.source === 'url' ? h('button', { class: 'db-link', attrs: { type: 'button' }, text: t('myListsUpdateNow'), on: { click: () => void run({ type: 'mylists:update', id: l.id }, () => t('myListsUpdatedToast', shortName(l.title, 40))) } }) : null,
          ),
        )
      : null;

    return h(
      'li',
      { class: `lists-row${active ? '' : ' lists-row--off'}`, dataset: { myList: l.id, listId: l.id } },
      h('div', { class: 'lists-row__switch' }, sw.el),
      h(
        'div',
        { class: 'lists-row__body' },
        renaming === l.id ? renameForm(l) : top,
        src,
        renaming === l.id ? null : h('div', { class: 'lists-row__meta' }, h('span', { text: t(l.source === 'url' ? 'myListsCheckedAt' : 'myListsAddedAt', fmtDateTime(l.source === 'url' ? l.checked : l.updated)) }), ...links),
        errBox,
        stats.length ? h('p', { class: 'my-lists__stats' }, ...stats.map((s) => h('span', { text: s }))) : null,
      ),
    );
  };

  // ---------------------------------------------------------------- Add --

  const addForm = (s: MyListsState): HTMLElement => {
    const full = s.lists.length >= s.maxLists;
    const inputId = nextId('my-lists-url');
    const errId = nextId('my-lists-err');
    const hintId = nextId('my-lists-hint');
    const counter = h('span', { class: 'field__counter mono', attrs: { 'aria-live': 'polite' } });
    const input = h('input', {
      class: 'input field__input mono',
      attrs: { id: inputId, type: 'url', placeholder: 'https://', 'aria-describedby': `${errId} ${hintId}`, spellcheck: 'false', autocomplete: 'off', inputmode: 'url', translate: 'no', disabled: full, maxlength: MY_LISTS.MAX_URL_LENGTH + 64 },
    });
    input.value = urlValue;
    const err = h('p', { class: 'field__error', attrs: { id: errId, 'aria-live': 'polite' }, hidden: !urlError }, urlError ? icon('alert', 14) : null, urlError ?? '');
    if (urlError) input.setAttribute('aria-invalid', 'true');
    const paintCounter = (): void => {
      counter.textContent = counterText(input.value.length, MY_LISTS.MAX_URL_LENGTH) ?? '';
    };
    paintCounter();
    input.addEventListener('input', () => {
      urlValue = input.value;
      paintCounter();
      if (urlError) {
        urlError = null;
        err.hidden = true;
        input.removeAttribute('aria-invalid');
      }
    });
    const add = h('button', { class: 'btn btn--primary', attrs: { type: 'submit', disabled: full }, text: t('myListsAdd') });
    const upload = h('button', { class: 'btn btn--outline', attrs: { type: 'button', disabled: full } }, icon('upload', 14), t('myListsUpload'));
    upload.addEventListener('click', () => void chooseFile());
    const form = h(
      'form',
      { class: 'my-lists__url', attrs: { novalidate: true } },
      h('div', { class: 'field__head' }, h('label', { class: 'field__label', attrs: { for: inputId }, text: t('myListsUrlField') }), counter),
      h('div', { class: 'field__row' }, input, add, h('span', { class: 'my-lists__or', text: t('myListsOr') }), upload),
      err,
      h('p', { class: 'field__hint', attrs: { id: hintId }, text: full ? t('myListsFull', fmtNumber(s.maxLists)) : t('myListsHint') }),
    );
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const problem = checkListUrl(input.value, state?.lists ?? []);
      if (problem) {
        urlError = urlProblemText(problem);
        replace(err, icon('alert', 14), urlError);
        err.hidden = false;
        input.setAttribute('aria-invalid', 'true');
        input.focus();
        return;
      }
      const url = input.value.trim();
      // Loading keeps the label and shows a spinner (the download can take a while).
      input.readOnly = true;
      void withBusy(add, () =>
        run({ type: 'mylists:add', url }, (st) => t('myListsAddedToast', st.lists[st.lists.length - 1]?.title ?? url)).then((ok) => {
          if (ok) urlValue = '';
        }),
      ).finally(() => {
        input.readOnly = false;
      });
    });
    return form;
  };

  const issues = (): HTMLElement | null => {
    if (!fileIssues.length) return null;
    return h(
      'ul',
      { class: 'my-lists__issues', attrs: { 'aria-live': 'polite' } },
      ...fileIssues.map((f) => {
        const soft = f.problem === 'empty';
        const again = h('button', { class: 'db-link', attrs: { type: 'button' }, text: t('myListsOtherFile') });
        again.addEventListener('click', () => void chooseFile(f.replaceId));
        return h(
          'li',
          { class: `my-lists__issue${soft ? ' my-lists__issue--info' : ''}` },
          icon(soft ? 'info' : 'alert', 18),
          h('div', { class: 'my-lists__issue-text' }, h('p', { class: 'my-lists__issue-name mono', text: f.problem === 'size' ? `${truncateMiddle(f.name, 48)} - ${sizeText(f.size)}` : truncateMiddle(f.name, 48), attrs: { title: f.name.length > 48 ? f.name : undefined, translate: 'no' } }), h('p', { class: 'my-lists__issue-why', text: fileProblemText(f.problem) })),
          soft ? null : again,
        );
      }),
    );
  };

  // --------------------------------------------------------------- Draw --

  const draw = (s: MyListsState): void => {
    state = s;
    const hadFocus = root.contains(document.activeElement) ? (document.activeElement as HTMLElement).dataset.action ?? null : null;
    const aside = s.locked
      ? h('span', { class: 'my-lists__lockaside' }, icon('lock', 12), t('lockedByPolicy'))
      : h('span', { class: `num${s.lists.length >= s.maxLists ? ' my-lists__count--full' : ''}`, text: t('myListsCount', [fmtNumber(s.lists.length), fmtNumber(s.maxLists)]) });
    const shown = showAll ? s.lists : s.lists.slice(0, ROWS_FIRST);
    const more = s.lists.length > ROWS_FIRST
      ? h('button', { class: 'db-link my-lists__all', attrs: { type: 'button', 'aria-expanded': String(showAll) }, text: showAll ? t('ovShowLess') : t('ovShowAll', fmtNumber(s.lists.length)) })
      : null;
    more?.addEventListener('click', () => {
      showAll = !showAll;
      draw(s);
      root.querySelector<HTMLElement>('.my-lists__all')?.focus();
    });
    const empty = !s.lists.length && !s.locked
      ? h(
          'div',
          { class: 'my-lists__empty' },
          h('span', { class: 'my-lists__empty-tile', attrs: { 'aria-hidden': 'true' } }, icon('upload', 18)),
          h('div', { class: 'my-lists__empty-text' }, h('p', { class: 'my-lists__empty-title', text: t('myListsEmptyTitle') }), h('p', { text: t('myListsEmptyText') })),
        )
      : null;
    const how = h('div', { class: 'my-lists__how' }, h('p', { text: t('myListsLead') }));
    const howBtn = h('button', { class: 'db-link', attrs: { type: 'button', 'aria-expanded': 'false', 'aria-controls': '' }, text: t('myListsHow') });
    how.id = nextId('my-lists-how');
    how.hidden = true;
    howBtn.setAttribute('aria-controls', how.id);
    howBtn.addEventListener('click', () => {
      how.hidden = !how.hidden;
      howBtn.setAttribute('aria-expanded', String(!how.hidden));
    });
    replace(
      root,
      h(
        'section',
        { class: 'db-card db-card--flush my-lists', attrs: { 'aria-labelledby': 'my-lists-title' } },
        h('div', { class: 'db-card__head' }, h('h2', { class: 'db-card__title', text: t('myListsTitle'), attrs: { id: 'my-lists-title' } }), h('div', { class: 'db-card__aside' }, aside)),
        s.locked
          ? h('div', { class: 'my-lists__add' }, h('p', { class: 'my-lists__locked', text: t('myListsLocked') }))
          : h('div', { class: 'my-lists__add' }, addForm(s), issues(), empty, h('div', { class: 'my-lists__howrow' }, howBtn), how),
        shown.length ? h('ul', { class: 'lists-list' }, ...shown.map((l) => row(l, s.locked))) : null,
        more ? h('div', { class: 'my-lists__more' }, more) : null,
      ),
    );
    if (focusAfter) {
      const target = root.querySelector<HTMLElement>(`[data-list-id="${CSS.escape(focusAfter)}"] .switch`);
      focusAfter = null;
      target?.focus();
    } else if (hadFocus) root.querySelector<HTMLElement>(`[data-action="${hadFocus}"]`)?.focus();
  };

  // Drop a file anywhere on the card (DB14: «Datei hierher ziehen»).
  root.addEventListener('dragover', (ev) => {
    if (!state || state.locked || !ev.dataTransfer?.types.includes('Files')) return;
    ev.preventDefault();
    root.classList.add('is-drop');
  });
  root.addEventListener('dragleave', (ev) => {
    if (!root.contains(ev.relatedTarget as Node | null)) root.classList.remove('is-drop');
  });
  root.addEventListener('drop', (ev) => {
    root.classList.remove('is-drop');
    const file = ev.dataTransfer?.files?.[0];
    if (!file || !state || state.locked) return;
    ev.preventDefault();
    void addFile(file);
  });

  const load = (): void => {
    void myLists().then((r) => {
      if (r.ok) draw(r.data);
      else replace(root, errorState(load, t('myListsLoadError'), t('dashErrorText')));
    });
  };
  load();
  return root;
}

