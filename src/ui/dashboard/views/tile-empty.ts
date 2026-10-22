// Bastion Shield — empty state with a 48px pictogram tile above a 17px title
// and one sentence (DB26 «Noch keine Ausnahmen», DB32 «Der Nerd-Modus ist
// aus»): a ground card for a view whose whole content is missing.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { h, type Child } from '../../shared/dom.ts';
import { icon, type IconName } from '../../shared/icons.ts';

export function tileEmpty(iconName: IconName, title: string, text: string, action?: Child): HTMLElement {
  return h(
    'div',
    { class: 'tile-empty' },
    h('span', { class: 'tile-empty__tile', attrs: { 'aria-hidden': 'true' } }, icon(iconName, 22)),
    h('div', { class: 'tile-empty__text' }, h('h2', { class: 'tile-empty__title', text: title }), h('p', { class: 'tile-empty__body', text })),
    action ?? null,
  );
}
