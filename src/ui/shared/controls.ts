// Bastion Shield — accessible form controls shared by popup and dashboard:
// switch (role=switch), segmented control (radiogroup with roving tabindex),
// eyebrow labels, lock badges and a promise-based confirm dialog.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { h, toast, type Child, type ToastHandle } from './dom.ts';
import { icon, type IconName } from './icons.ts';
import { t } from './i18n.ts';

export interface SwitchOptions {
  checked: boolean;
  /** Accessible name: either the id of a visible label, or a plain label. */
  labelledBy?: string;
  label?: string;
  describedBy?: string;
  disabled?: boolean;
  large?: boolean;
  id?: string;
  /** Called with the new value. Return false (or a promise of false) to revert. */
  onChange: (checked: boolean) => unknown;
}

export interface SwitchHandle {
  el: HTMLButtonElement;
  set(checked: boolean): void;
  setDisabled(disabled: boolean): void;
  get(): boolean;
}

export function switchControl(opts: SwitchOptions): SwitchHandle {
  const el = h('button', {
    class: `switch${opts.large ? ' switch--lg' : ''}`,
    attrs: {
      type: 'button',
      role: 'switch',
      id: opts.id,
      'aria-checked': String(opts.checked),
      'aria-labelledby': opts.labelledBy,
      'aria-label': opts.labelledBy ? undefined : opts.label,
      'aria-describedby': opts.describedBy,
      disabled: !!opts.disabled,
    },
  });
  let busy = false;
  el.addEventListener('click', async () => {
    if (busy || el.disabled) return;
    const next = el.getAttribute('aria-checked') !== 'true';
    el.setAttribute('aria-checked', String(next));
    busy = true;
    try {
      const res = await opts.onChange(next);
      if (res === false) el.setAttribute('aria-checked', String(!next));
    } catch {
      el.setAttribute('aria-checked', String(!next));
    } finally {
      busy = false;
    }
  });
  return {
    el,
    set: (v) => el.setAttribute('aria-checked', String(v)),
    setDisabled: (d) => {
      el.disabled = d;
    },
    get: () => el.getAttribute('aria-checked') === 'true',
  };
}

export interface SegOption<V extends string> {
  value: V;
  label: string;
}

export interface SegHandle<V extends string> {
  el: HTMLDivElement;
  set(value: V): void;
  setDisabled(disabled: boolean): void;
  get(): V;
}

/** Segmented control as an ARIA radiogroup with arrow-key navigation. */
export function segmented<V extends string>(opts: {
  options: SegOption<V>[];
  value: V;
  label?: string;
  labelledBy?: string;
  disabled?: boolean;
  block?: boolean;
  onChange: (value: V) => unknown;
}): SegHandle<V> {
  let current = opts.value;
  let disabled = !!opts.disabled;
  const el = h('div', {
    class: `seg${opts.block ? ' seg--block' : ''}`,
    attrs: { role: 'radiogroup', 'aria-label': opts.labelledBy ? undefined : opts.label, 'aria-labelledby': opts.labelledBy },
  });
  const buttons = opts.options.map((o) =>
    h('button', {
      class: 'seg__opt',
      text: o.label,
      attrs: { type: 'button', role: 'radio', 'data-value': o.value },
      on: { click: () => choose(o.value, true) },
    }),
  );
  el.append(...buttons);

  const paint = (): void => {
    for (const b of buttons) {
      const on = b.dataset.value === current;
      b.setAttribute('aria-checked', String(on));
      b.tabIndex = on ? 0 : -1;
      b.disabled = disabled;
    }
    el.setAttribute('aria-disabled', String(disabled));
  };

  const choose = async (v: V, notify: boolean): Promise<void> => {
    if (disabled || v === current) return;
    const prev = current;
    current = v;
    paint();
    if (!notify) return;
    try {
      const res = await opts.onChange(v);
      if (res === false) {
        current = prev;
        paint();
      }
    } catch {
      current = prev;
      paint();
    }
  };

  el.addEventListener('keydown', (ev) => {
    const keys = ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'];
    if (!keys.includes(ev.key) || disabled) return;
    ev.preventDefault();
    const idx = opts.options.findIndex((o) => o.value === current);
    let next = idx;
    if (ev.key === 'ArrowLeft' || ev.key === 'ArrowUp') next = (idx - 1 + opts.options.length) % opts.options.length;
    else if (ev.key === 'ArrowRight' || ev.key === 'ArrowDown') next = (idx + 1) % opts.options.length;
    else if (ev.key === 'Home') next = 0;
    else next = opts.options.length - 1;
    void choose(opts.options[next].value, true);
    buttons[next].focus();
  });

  paint();
  return {
    el,
    set: (v) => {
      current = v;
      paint();
    },
    setDisabled: (d) => {
      disabled = d;
      paint();
    },
    get: () => current,
  };
}

/** Brand eyebrow: tick + mono caps label, with an optional trailing element. */
export function eyebrow(label: string, aside?: Child, tag: 'div' | 'h2' | 'h3' = 'div'): HTMLElement {
  return h(tag, { class: 'eyebrow' }, icon('tick', 11, 'eyebrow__tick'), h('span', { text: label }), aside ? h('span', { class: 'eyebrow__aside' }, aside) : null);
}

/** "Locked by your organisation" indicator. */
export function lockBadge(text = t('lockedByPolicy')): HTMLElement {
  return h('span', { class: 'lock', attrs: { title: text } }, icon('lock', 13), h('span', { text }));
}

/** Icon-only lock with an accessible name (for dense rows). */
export function lockIcon(text = t('lockedByPolicy')): HTMLElement {
  return h('span', { class: 'lock', attrs: { title: text, role: 'img', 'aria-label': text } }, icon('lock', 13));
}

/** Neutral notice: icon + title + body. Used for errors too (never red). */
export function notice(title: string, body?: string, kind: 'info' | 'alert' = 'info', quiet = false): HTMLElement {
  return h(
    'div',
    { class: `notice${quiet ? ' notice--quiet' : ''}`, attrs: { role: kind === 'alert' ? 'alert' : 'status' } },
    icon(kind === 'alert' ? 'alert' : 'info', 16),
    h('div', null, h('div', { class: 'notice__title', text: title }), body ? h('div', { class: 'notice__body', text: body }) : null),
  );
}

export interface ConfirmOptions {
  title: string;
  body?: Child;
  /** Names the outcome («Verlauf löschen»). */
  confirmLabel: string;
  /** Names the safe outcome («Verlauf behalten»); defaults to «Abbrechen». */
  cancelLabel?: string;
  /** Extra content between the text and the actions. */
  content?: Child;
  /** Pictogram in the 48px tile; defaults to «trash» for danger, else none. */
  icon?: IconName;
  /** Destructive outcome: danger tile and `.btn--danger` confirm button. */
  danger?: boolean;
  /** Heavy actions: a checkbox that must be ticked before confirming. */
  check?: { label: string; aside?: Child };
}

/** Header of a dialog: tile (decorative) + title + one sentence. */
function dialogHead(titleId: string, title: string, body: Child, iconName: IconName | undefined, danger: boolean): HTMLElement {
  return h(
    'div',
    { class: 'dialog__head' },
    iconName ? h('span', { class: `tile${danger ? ' tile--danger' : ''}`, attrs: { 'aria-hidden': 'true' } }, icon(iconName, 22)) : null,
    h(
      'div',
      { class: 'dialog__head-text' },
      h('h2', { class: 'dialog__title', text: title, attrs: { id: titleId } }),
      typeof body === 'string' ? h('p', { class: 'dialog__text', text: body }) : (body ?? null),
    ),
  );
}

/**
 * Shows a modal <dialog>, focuses `initial` (the safe action) and returns
 * focus to the element that opened it once it closes.
 */
function openDialog(dlg: HTMLDialogElement, initial: HTMLElement, onClose: () => void): void {
  const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  // Tab wraps inside the dialog instead of leaving for the browser toolbar.
  dlg.addEventListener('keydown', (ev) => {
    if (ev.key !== 'Tab') return;
    const focusable = Array.from(dlg.querySelectorAll<HTMLElement>('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])')).filter(
      (el) => !(el as HTMLButtonElement).disabled && el.getClientRects().length > 0,
    );
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (ev.shiftKey && document.activeElement === first) {
      ev.preventDefault();
      last.focus();
    } else if (!ev.shiftKey && document.activeElement === last) {
      ev.preventDefault();
      first.focus();
    }
  });
  dlg.addEventListener('close', () => {
    dlg.remove();
    if (opener?.isConnected) opener.focus({ preventScroll: true });
    onClose();
  });
  document.body.appendChild(dlg);
  try {
    dlg.showModal();
  } catch {
    dlg.setAttribute('open', '');
  }
  initial.focus();
}

/**
 * Modal confirmation (D01–D08). Escape and the cancel button resolve false.
 * Primary first, both buttons name their outcome; focus starts on the safe
 * (cancel) button so a stray Enter never confirms.
 */
export function confirmDialog(opts: ConfirmOptions): Promise<boolean> {
  return new Promise((resolve) => {
    const titleId = `dlg-${Math.random().toString(36).slice(2, 8)}`;
    const danger = !!opts.danger;
    const cancel = h('button', { class: 'btn btn--outline', text: opts.cancelLabel ?? t('actionCancel'), attrs: { type: 'button', 'data-dialog': 'cancel' } });
    const ok = h('button', { class: `btn ${danger ? 'btn--danger' : 'btn--primary'}`, text: opts.confirmLabel, attrs: { type: 'button', 'data-dialog': 'confirm' } });
    let checkRow: HTMLElement | null = null;
    if (opts.check) {
      const box = h('input', { class: 'check', attrs: { type: 'checkbox', id: `${titleId}-check` } });
      const sync = (): void => {
        ok.disabled = !box.checked;
      };
      box.addEventListener('change', sync);
      sync();
      checkRow = h(
        'div',
        { class: 'dialog__check' },
        h('label', { attrs: { for: box.id } }, box, h('span', { text: opts.check.label })),
        opts.check.aside ?? null,
      );
    }
    const dlg = h(
      'dialog',
      { class: 'dialog', attrs: { 'aria-labelledby': titleId } },
      h('div', { class: 'dialog__body' }, dialogHead(titleId, opts.title, opts.body, opts.icon ?? (danger ? 'trash' : undefined), danger), checkRow, opts.content ?? null),
      h('div', { class: 'dialog__actions' }, ok, cancel),
    );
    let result = false;
    const finish = (v: boolean): void => {
      result = v;
      try {
        dlg.close();
      } catch {
        dlg.remove();
        resolve(result);
      }
    };
    cancel.addEventListener('click', () => finish(false));
    ok.addEventListener('click', () => {
      if (!ok.disabled) finish(true);
    });
    openDialog(dlg, cancel, () => resolve(result));
  });
}

export interface Choice<V extends string> {
  value: V;
  label: string;
  primary?: boolean;
  danger?: boolean;
}

/**
 * Modal with several answers (for example «Inhalt ersetzen», «Als neue Liste
 * hinzufügen»). Resolves the chosen value, or null for «Abbrechen» and
 * Escape. With two or more answers «Abbrechen» moves below them as a quiet
 * button. Focus starts on «Abbrechen».
 */
export function choiceDialog<V extends string>(opts: { title: string; body?: string; icon?: IconName; choices: Choice<V>[]; cancelLabel?: string }): Promise<V | null> {
  return new Promise((resolve) => {
    const titleId = `dlg-${Math.random().toString(36).slice(2, 8)}`;
    let result: V | null = null;
    const quietCancel = opts.choices.length > 1;
    const cancel = h('button', { class: `btn ${quietCancel ? 'btn--quiet' : 'btn--outline'}`, text: opts.cancelLabel ?? t('actionCancel'), attrs: { type: 'button', 'data-dialog': 'cancel' } });
    const buttons = opts.choices.map((c) => {
      const b = h('button', {
        class: `btn ${c.danger ? 'btn--danger' : c.primary ? 'btn--primary' : 'btn--outline'}`,
        text: c.label,
        attrs: { type: 'button', 'data-dialog': c.value },
      });
      b.addEventListener('click', () => {
        result = c.value;
        close();
      });
      return b;
    });
    const dlg = h(
      'dialog',
      { class: 'dialog', attrs: { 'aria-labelledby': titleId } },
      h('div', { class: 'dialog__body' }, dialogHead(titleId, opts.title, opts.body, opts.icon, false)),
      h('div', { class: 'dialog__actions' }, ...buttons, cancel),
    );
    const close = (): void => {
      try {
        dlg.close();
      } catch {
        dlg.remove();
        resolve(result);
      }
    };
    cancel.addEventListener('click', close);
    openDialog(dlg, cancel, () => resolve(result));
  });
}

/** Toast for a reversible action (T01): «… entfernt» with «Rückgängig» for 6 s. */
export function undoToast(message: string, undo: () => unknown): ToastHandle {
  return toast(message, icon('check', 15), { action: { label: t('actionUndo'), run: undo } });
}

/** Error toast with «Erneut versuchen»: stays until closed (T01). */
export function retryToast(message: string, retry: () => unknown): ToastHandle {
  return toast(message, icon('alert', 15), { sticky: true, closeLabel: t('toastClose'), action: { label: t('actionRetry'), run: retry } });
}

/** Text with «Bastion Shield» wrapped in translate="no" (AGENTS.md: brand never translated). */
export function brandText(text: string): Node[] {
  return text.split(/(Bastion Shield)/).filter(Boolean).map((part) => (part === 'Bastion Shield' ? h('span', { text: part, attrs: { translate: 'no' } }) : document.createTextNode(part)));
}
