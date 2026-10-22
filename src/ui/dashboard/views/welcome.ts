// Bastion Shield — first-install welcome (#welcome, W01–W03). Opened by the
// service worker after installation unless a managed policy sets
// organizationName. States plainly that protection is already on and nothing
// leaves the device: mark tile, title, one sentence, three points with tiles,
// the pin tip, then «Übersicht öffnen» (primary) and «Filterlisten ansehen».
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { brandText } from '../../shared/controls.ts';
import { h } from '../../shared/dom.ts';
import { t } from '../../shared/i18n.ts';
import { icon, mark, type IconName } from '../../shared/icons.ts';
import { mount, type View } from '../common.ts';

const POINTS: [IconName, string, string][] = [
  ['check', 'welcomeOnTitle', 'welcomeOnText'],
  ['device', 'welcomeLocalTitle', 'welcomeLocalText'],
  ['eye', 'welcomeSeeTitle', 'welcomeSeeText'],
];

export function welcomeView(): View {
  return {
    render(root) {
      mount(
        root,
        h(
          'section',
          { class: 'welcome' },
          h(
            'div',
            { class: 'welcome__inner' },
            h('span', { class: 'welcome__mark', attrs: { 'aria-hidden': 'true' } }, mark(48)),
            h(
              'div',
              { class: 'welcome__head' },
              h('h1', { class: 'welcome__title', attrs: { tabindex: -1 } }, ...brandText(t('welcomeTitle'))),
              h('p', { class: 'welcome__lead', text: t('welcomeLead') }),
            ),
            h(
              'ul',
              { class: 'welcome__points' },
              ...POINTS.map(([ic, title, text]) =>
                h(
                  'li',
                  null,
                  h('span', { class: 'tile', attrs: { 'aria-hidden': 'true' } }, icon(ic, 22)),
                  h('div', null, h('h2', { class: 'welcome__point-title', text: t(title) }), h('p', { class: 'welcome__point-text', text: t(text) })),
                ),
              ),
            ),
            h(
              'div',
              { class: 'welcome__pin' },
              // Where to click: puzzle › pin › mark.
              h('span', { class: 'welcome__pin-path', attrs: { 'aria-hidden': 'true' } }, icon('puzzle', 16), icon('chevronRight', 10), icon('pin', 16), mark(18)),
              h('p', null, ...brandText(t('welcomePin'))),
            ),
            h(
              'div',
              { class: 'welcome__actions' },
              h('a', { class: 'btn btn--primary', attrs: { href: '#overview' }, text: t('welcomeStart') }),
              h('a', { class: 'btn btn--outline', attrs: { href: '#lists' }, text: t('welcomeLists') }),
            ),
          ),
        ),
      );
    },
  };
}
