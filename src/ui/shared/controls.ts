// Bastion Shield — accessible form controls shared by popup and dashboard:
// switch (role=switch), segmented control (radiogroup with roving tabindex),
// eyebrow labels, lock badges and a promise-based confirm dialog.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { h, type Child } from './dom.ts';
import { icon } from './icons.ts';
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
  confirmLabel: string;
  cancelLabel?: string;
  /** Extra content between the text and the actions. */
  content?: Child;
}

/**
 * Modal confirmation using <dialog>. Escape and «Abbrechen» resolve false.
 * Focus starts on the cancel button so a stray Enter never confirms.
 */
export function confirmDialog(opts: ConfirmOptions): Promise<boolean> {
  return new Promise((resolve) => {
    const titleId = `dlg-${Math.random().toString(36).slice(2, 8)}`;
    const cancel = h('button', { class: 'btn btn--secondary', text: opts.cancelLabel ?? t('actionCancel'), attrs: { type: 'button' } });
    const ok = h('button', { class: 'btn btn--primary', text: opts.confirmLabel, attrs: { type: 'button' } });
    const dlg = h(
      'dialog',
      { class: 'dialog', attrs: { 'aria-labelledby': titleId } },
      h(
        'div',
        { class: 'dialog__body' },
        h('h2', { class: 'dialog__title', text: opts.title, attrs: { id: titleId } }),
        typeof opts.body === 'string' ? h('p', { class: 'dialog__text', text: opts.body }) : (opts.body ?? null),
        opts.content ?? null,
      ),
      h('div', { class: 'dialog__actions' }, cancel, ok),
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
    ok.addEventListener('click', () => finish(true));
    dlg.addEventListener('close', () => {
      dlg.remove();
      resolve(result);
    });
    document.body.appendChild(dlg);
    try {
      dlg.showModal();
    } catch {
      dlg.setAttribute('open', '');
    }
    cancel.focus();
  });
}

export interface Choice<V extends string> {
  value: V;
  label: string;
  primary?: boolean;
}

/**
 * Modal with several answers (for example «Replace», «Add as new»). Resolves
 * the chosen value, or null for «Cancel» and Escape. Focus starts on Cancel.
 */
export function choiceDialog<V extends string>(opts: { title: string; body?: string; choices: Choice<V>[] }): Promise<V | null> {
  return new Promise((resolve) => {
    const titleId = `dlg-${Math.random().toString(36).slice(2, 8)}`;
    let result: V | null = null;
    const cancel = h('button', { class: 'btn btn--secondary', text: t('actionCancel'), attrs: { type: 'button' } });
    const buttons = opts.choices.map((c) => {
      const b = h('button', { class: `btn ${c.primary ? 'btn--primary' : 'btn--secondary'}`, text: c.label, attrs: { type: 'button' } });
      b.addEventListener('click', () => {
        result = c.value;
        close();
      });
      return b;
    });
    const dlg = h(
      'dialog',
      { class: 'dialog', attrs: { 'aria-labelledby': titleId } },
      h(
        'div',
        { class: 'dialog__body' },
        h('h2', { class: 'dialog__title', text: opts.title, attrs: { id: titleId } }),
        opts.body ? h('p', { class: 'dialog__text', text: opts.body }) : null,
      ),
      h('div', { class: 'dialog__actions' }, cancel, ...buttons),
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
    dlg.addEventListener('close', () => {
      dlg.remove();
      resolve(result);
    });
    document.body.appendChild(dlg);
    try {
      dlg.showModal();
    } catch {
      dlg.setAttribute('open', '');
    }
    cancel.focus();
  });
}
