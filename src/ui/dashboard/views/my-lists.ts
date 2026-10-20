// Bastion Shield — dashboard «Filterlisten» › «My lists»: filter lists the
// user imports from a .txt file or an https address. Each list has its own
// switch, «Replace…» (new file, same name and switch state), «Update now»
// and a daily auto-update switch for web addresses, and «Remove». A file
// whose title matches an existing list asks «Replace» or «Add as new».
// Under the allowCustomLists policy the panel is read-only and says why.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { MY_LISTS } from '../../../shared/constants.ts';
import { listTitle } from '../../../shared/list-title.ts';
import type { Message, MyListInfo, MyListsState } from '../../../shared/types.ts';
import { h, pickNamedTextFile, replace, toast } from '../../shared/dom.ts';
import { fmtDate, fmtNumber, t } from '../../shared/i18n.ts';
import { icon } from '../../shared/icons.ts';
import { choiceDialog, confirmDialog, notice, switchControl } from '../../shared/controls.ts';
import { errorState, nextId, panel } from '../common.ts';
import { myLists } from '../store.ts';

const ACCEPT = '.txt,.list,.hosts,text/plain';
const ERROR_CODES = ['locked', 'not-found', 'too-many', 'too-large', 'empty', 'not-a-list', 'invalid-url', 'duplicate-url', 'fetch-failed'];

/** Localised text for an error code from the service worker («fetch-failed: HTTP 404» keeps its detail). */
export function myListErrorText(error: string): string {
  const [code, ...rest] = error.split(':');
  const detail = rest.join(':').trim();
  if (!ERROR_CODES.includes(code)) return t('errorSaveFailed');
  if (code === 'too-many') return t('myListsErrTooMany', fmtNumber(MY_LISTS.MAX));
  if (code === 'too-large') return t('myListsErrTooLarge', fmtNumber(Math.round(MY_LISTS.MAX_BYTES / 1_000_000)));
  if (code === 'fetch-failed') return t('myListsErrFetch', detail || '—');
  const key: Record<string, string> = {
    locked: 'myListsLocked',
    'not-found': 'myListsErrNotFound',
    empty: 'myListsErrEmpty',
    'not-a-list': 'myListsErrNotAList',
    'invalid-url': 'myListsErrUrl',
    'duplicate-url': 'myListsErrDuplicate',
  };
  return t(key[code]);
}

/** Filter lines in the list; an older worker reply without `filters` falls back to rules + cosmetics. */
export function myListFilterCount(l: Pick<MyListInfo, 'report'> & { filters?: number }): number {
  if (typeof l.filters === 'number') return l.filters;
  return (l.report?.network ?? 0) + (l.report?.cosmetic ?? 0);
}

function sourceLink(l: MyListInfo): HTMLElement {
  if (l.source === 'url' && l.url) {
    return h('a', { class: 'ext-link mono my-lists__src', attrs: { href: l.url, target: '_blank', rel: 'noopener noreferrer', title: l.url } }, l.url, icon('external', 12));
  }
  return h('span', { class: 'mono my-lists__src', text: l.fileName ?? '—' });
}

export function myListsPanel(): HTMLElement {
  const root = h('div', { class: 'my-lists-slot' });
  let state: MyListsState | null = null;
  let busy = false;

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

  const uploadFile = async (): Promise<void> => {
    const picked = await pickNamedTextFile(ACCEPT, MY_LISTS.MAX_BYTES);
    if (!picked) return;
    if ('tooLarge' in picked) {
      toast(myListErrorText('too-large'), icon('alert', 15));
      return;
    }
    const title = listTitle(picked.text, picked.name);
    const same = state?.lists.find((l) => l.title.trim().toLowerCase() === title.trim().toLowerCase());
    let replaceId: string | undefined;
    if (same) {
      const choice = await choiceDialog({
        title: t('myListsSameTitle', same.title),
        body: t('myListsSameTitleText'),
        choices: [
          { value: 'new', label: t('myListsAddNew') },
          { value: 'replace', label: t('myListsReplaceIt'), primary: true },
        ],
      });
      if (choice === null) return;
      if (choice === 'replace') replaceId = same.id;
    }
    await run({ type: 'mylists:add', file: picked, replaceId }, () => t(replaceId ? 'myListsReplacedToast' : 'myListsAddedToast', same && replaceId ? same.title : title));
  };

  const replaceFile = async (l: MyListInfo): Promise<void> => {
    const picked = await pickNamedTextFile(ACCEPT, MY_LISTS.MAX_BYTES);
    if (!picked) return;
    if ('tooLarge' in picked) {
      toast(myListErrorText('too-large'), icon('alert', 15));
      return;
    }
    await run({ type: 'mylists:add', file: picked, replaceId: l.id }, () => t('myListsReplacedToast', l.title));
  };

  const removeList = async (l: MyListInfo): Promise<void> => {
    const ok = await confirmDialog({ title: t('myListsRemoveTitle', l.title), body: t('myListsRemoveText'), confirmLabel: t('myListsRemove') });
    if (ok) await run({ type: 'mylists:remove', id: l.id }, () => t('myListsRemovedToast', l.title));
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
    const skipped = l.report?.errors?.length ?? 0;
    const meta: HTMLElement[] = [sourceLink(l)];
    // Only lists that are applied are compiled, so only they have a rule count.
    if (active) meta.push(h('span', null, h('span', { class: 'lists-row__k', text: t('listsRuleCost') }), ' ', h('span', { class: 'num', text: fmtNumber(l.report?.network ?? 0) })));
    meta.push(h('span', null, h('span', { class: 'lists-row__k', text: t('listsUpdated') }), ' ', fmtDate(l.updated)));
    if (l.source === 'url') meta.push(h('span', null, h('span', { class: 'lists-row__k', text: t('myListsChecked') }), ' ', fmtDate(l.checked)));
    if (l.report?.scriptletsIgnored) meta.push(h('span', { text: t('myListsScriptlets', fmtNumber(l.report.scriptletsIgnored)) }));
    if (skipped) meta.push(h('span', { text: t('myListsSkipped', fmtNumber(skipped)) }));

    const actions: HTMLElement[] = [];
    if (!locked) {
      if (l.source === 'url') {
        const auto = h('input', { attrs: { type: 'checkbox' } });
        auto.checked = l.autoUpdate;
        auto.addEventListener('change', () => void run({ type: 'mylists:set', id: l.id, autoUpdate: auto.checked }, () => null));
        actions.push(h('label', { class: 'my-lists__auto' }, auto, t('myListsAutoUpdate')));
        const upd = h('button', { class: 'btn btn--ghost btn--sm', attrs: { type: 'button' } }, icon('reload', 14), t('myListsUpdateNow'));
        upd.addEventListener('click', () => void run({ type: 'mylists:update', id: l.id }, () => t('myListsUpdatedToast', l.title)));
        actions.push(upd);
      }
      const rep = h('button', { class: 'btn btn--ghost btn--sm', attrs: { type: 'button', title: t('myListsReplaceHint') } }, icon('upload', 14), t('myListsReplace'));
      rep.addEventListener('click', () => void replaceFile(l));
      const del = h('button', { class: 'btn btn--ghost btn--sm', attrs: { type: 'button' } }, icon('trash', 14), t('myListsRemove'));
      del.addEventListener('click', () => void removeList(l));
      actions.push(rep, del);
    }

    return h(
      'li',
      { class: `lists-row${active ? '' : ' lists-row--off'}`, dataset: { myList: l.id } },
      h('div', { class: 'lists-row__switch' }, sw.el),
      h(
        'div',
        { class: 'lists-row__body' },
        h(
          'div',
          { class: 'lists-row__top' },
          h('h3', { class: 'lists-row__name', text: l.title, attrs: { id: nameId } }),
          h('span', { class: 'lists-row__badge mono-label', text: t(l.source === 'url' ? 'myListsSourceUrl' : 'myListsSourceFile') }),
          h('span', { class: 'lists-row__count' }, h('span', { class: 'num', text: fmtNumber(count) }), ' ', t(count === 1 ? 'listsFilterOne' : 'listsFilters')),
        ),
        l.error ? h('div', { class: 'lists-row__error' }, notice(t('myListsDownloadFailed'), myListErrorText(l.error), 'alert')) : null,
        h('div', { class: 'lists-row__meta' }, ...meta),
        actions.length ? h('div', { class: 'my-lists__actions' }, ...actions) : null,
      ),
    );
  };

  const addForm = (s: MyListsState): HTMLElement => {
    const full = s.lists.length >= s.maxLists;
    const upload = h('button', { class: 'btn btn--secondary', attrs: { type: 'button', disabled: full } }, icon('upload', 15), t('myListsUpload'));
    upload.addEventListener('click', () => void uploadFile());
    const hintId = nextId('my-lists-hint');
    const input = h('input', {
      class: 'input',
      attrs: { type: 'url', placeholder: 'https://', 'aria-label': t('myListsUrlLabel'), 'aria-describedby': hintId, spellcheck: 'false', autocomplete: 'off', inputmode: 'url', disabled: full },
    });
    const add = h('button', { class: 'btn btn--primary', attrs: { type: 'submit', disabled: full } }, icon('plus', 15), t('myListsAdd'));
    const form = h('form', { class: 'my-lists__url' }, input, add);
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const url = input.value.trim();
      if (!url.toLowerCase().startsWith('https://')) {
        toast(myListErrorText('invalid-url'), icon('alert', 15));
        input.focus();
        return;
      }
      add.textContent = t('myListsDownloading');
      // A new list is appended, so the added one is the last.
      void run({ type: 'mylists:add', url }, (st) => t('myListsAddedToast', st.lists[st.lists.length - 1]?.title ?? url)).then((ok) => {
        if (ok) input.value = '';
        replace(add, icon('plus', 15), t('myListsAdd'));
      });
    });
    return h(
      'div',
      { class: 'my-lists__add' },
      h('div', { class: 'my-lists__add-row' }, upload, h('span', { class: 'my-lists__or', text: t('myListsOr') }), form),
      h('p', { class: 'my-lists__hint', attrs: { id: hintId }, text: full ? t('myListsErrTooMany', fmtNumber(s.maxLists)) : t('myListsHint') }),
    );
  };

  const draw = (s: MyListsState): void => {
    state = s;
    replace(
      root,
      panel(
        { title: t('myListsTitle'), aside: t('myListsCount', [fmtNumber(s.lists.length), fmtNumber(s.maxLists)]), flush: true, class: 'lists-more my-lists' },
        h('p', { class: 'lists-more__lead', text: t('myListsLead') }),
        s.locked ? h('div', { class: 'my-lists__locked' }, notice(t('myListsLockedTitle'), t('myListsLocked'), 'info')) : addForm(s),
        s.lists.length
          ? h('ul', { class: 'lists-list' }, ...s.lists.map((l) => row(l, s.locked)))
          : h('p', { class: 'my-lists__empty', text: t('myListsEmpty') }),
      ),
    );
  };

  void myLists().then((r) => {
    if (r.ok) draw(r.data);
    else replace(root, errorState());
  });
  return root;
}
