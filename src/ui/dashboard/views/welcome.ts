// Bastion Shield — first-install welcome (#welcome). Opened by the service
// worker after installation unless a managed policy sets organizationName.
// States plainly that protection is already on and nothing leaves the device.
//
// SPDX-License-Identifier: GPL-3.0-or-later

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
      mount(root, 
        h(
          'section',
          { class: 'welcome' },
          h(
            'div',
            { class: 'welcome__inner' },
            mark(64),
            h('h1', { class: 'welcome__title', text: t('welcomeTitle'), attrs: { tabindex: -1 } }),
            h('p', { class: 'welcome__lead', text: t('welcomeLead') }),
            h(
              'ul',
              { class: 'welcome__points' },
              ...POINTS.map(([ic, title, text]) => h('li', null, icon(ic, 18, 'welcome__icon'), h('div', null, h('h2', { class: 'welcome__point-title', text: t(title) }), h('p', { class: 'welcome__point-text', text: t(text) })))),
            ),
            h('div', { class: 'welcome__pin' }, icon('pin', 16), h('p', { text: t('welcomePin') })),
            h(
              'div',
              { class: 'welcome__actions' },
              h('a', { class: 'btn btn--primary', attrs: { href: '#overview' }, text: t('welcomeStart') }),
              h('a', { class: 'btn btn--secondary', attrs: { href: '#lists' }, text: t('welcomeLists') }),
            ),
          ),
        ),
      );
    },
  };
}
