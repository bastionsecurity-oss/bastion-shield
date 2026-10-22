// Bastion Shield — dashboard «Über» (DB30, DB43): version and build date,
// privacy statement, licence and source code, contact (with the support of
// the user's organisation when the policy names one), and full attribution
// of every filter list, vendored component and font shipped in the package.
// Long list and licence names wrap inside their cells; names that are cut
// keep the full text in a title.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { LINKS } from '../../../shared/constants.ts';
import { h } from '../../shared/dom.ts';
import { fmtDate, fmtDateTime, localized, t } from '../../shared/i18n.ts';
import { icon, mark } from '../../shared/icons.ts';
import { extensionVersion } from '../../shared/messaging.ts';
import { truncateMiddle } from '../../shared/text.ts';
import { openTabButton, popupMode, settingRow, nextId, type View, mount } from '../common.ts';
import { getConfig, getMeta } from '../store.ts';

function ext(href: string, text: string, mono = false): HTMLElement {
  return h('a', { class: `ext-link${mono ? ' mono' : ''}`, attrs: { href, target: '_blank', rel: 'noopener noreferrer' } }, text, icon('external', 12));
}

function safeUrl(u: string | undefined): string | null {
  if (!u) return null;
  try {
    const url = new URL(u);
    return url.protocol === 'https:' || url.protocol === 'http:' || url.protocol === 'mailto:' ? url.href : null;
  } catch {
    return null;
  }
}

const LICENCE = 'GPL-3.0-or-later';

const VENDOR: { key: 'ublock' | 'braveResources' | 'braveLists'; name: string; repo: string; licence: string }[] = [
  { key: 'ublock', name: 'uBlock Origin (scriptlets, redirect resources)', repo: 'https://github.com/gorhill/uBlock', licence: 'GPL-3.0' },
  { key: 'braveResources', name: 'Brave adblock-resources', repo: 'https://github.com/brave/adblock-resources', licence: 'MPL-2.0' },
  { key: 'braveLists', name: 'Brave adblock-lists (debounce, query filter)', repo: 'https://github.com/brave/adblock-lists', licence: 'MPL-2.0' },
];

const FONTS: [string, string][] = [
  ['Inter', 'https://github.com/rsms/inter'],
  ['Inter Tight', 'https://github.com/rsms/inter'],
  ['IBM Plex Mono', 'https://github.com/IBM/plex'],
];

export function aboutView(): View {
  return {
    async render(root) {
      const [meta, cfgR] = await Promise.all([getMeta(), getConfig()]);
      const managed = cfgR.ok ? cfgR.data.managed : {};
      const version = extensionVersion() || meta?.extensionVersion || '–';
      const built = meta?.builtAt ? Date.parse(meta.builtAt) : NaN;

      const tile = h('span', { class: 'about-hero__tile', attrs: { 'aria-hidden': 'true' } }, mark(popupMode ? 26 : 44));
      const name = h('h1', { class: 'about-hero__name', text: t('extName'), attrs: { tabindex: -1, translate: 'no' } });
      const hero = popupMode
        ? h('section', { class: 'about-hero about-hero--panel' }, tile, h('div', null, name, h('p', { class: 'about-hero__line mono', attrs: { translate: 'no' }, text: `${version} - ${LICENCE}` })))
        : h(
            'section',
            { class: 'about-hero' },
            tile,
            h(
              'div',
              { class: 'about-hero__main' },
              name,
              h(
                'dl',
                { class: 'about-hero__facts' },
                h('div', null, h('dt', { text: t('aboutVersion') }), h('dd', { class: 'mono', attrs: { translate: 'no' }, text: version })),
                h('div', null, h('dt', { text: t('aboutBuilt') }), h('dd', { text: Number.isFinite(built) ? fmtDateTime(built) : '–' })),
                h('div', null, h('dt', { text: t('aboutLicence') }), h('dd', null, ext('https://www.gnu.org/licenses/gpl-3.0.html', LICENCE))),
                h('div', null, h('dt', { text: t('aboutSource') }), h('dd', null, ext(LINKS.REPO_URL, t('aboutRepoLink')))),
              ),
            ),
          );

      const privacy = h(
        'section',
        { class: 'about-privacy', attrs: { 'aria-labelledby': 'about-privacy-title' } },
        popupMode ? null : h('span', { class: 'about-privacy__tile', attrs: { 'aria-hidden': 'true' } }, icon('device', 22)),
        h(
          'div',
          { class: 'about-privacy__main' },
          h('h2', { class: 'about-privacy__title', attrs: { id: 'about-privacy-title' }, text: t('aboutPrivacyStatement') }),
          h('p', { class: 'about-privacy__text', text: popupMode ? t('aboutPrivacyShort') : t('aboutPrivacyText') }),
          popupMode ? null : ext(LINKS.PRIVACY, t('aboutPrivacyLink')),
        ),
      );

      const publisher = h('div', { class: 'about-kv__item' }, h('dt', { text: t('aboutPublisher') }), h('dd', { text: 'Bastion Security GmbH, Zürich' }));
      if (popupMode) {
        // The licence tables are long: in the popup they open in the dashboard tab.
        mount(
          root,
          hero,
          privacy,
          h('dl', { class: 'about-kv' }, publisher),
          settingRow({ label: t('aboutListsTitle'), control: openTabButton('about', t('panelOpenInTab')), labelId: nextId('about') }),
        );
        return;
      }

      // Support of the organisation, when the policy names it.
      let support: HTMLElement | null = null;
      if (managed.organizationName || managed.supportUrl || managed.supportEmail) {
        const url = safeUrl(managed.supportUrl);
        support = h(
          'div',
          { class: 'about-support' },
          h('p', { class: 'about-support__label', text: t('aboutSupport') }),
          managed.organizationName ? h('p', { class: 'about-support__org', text: managed.organizationName }) : null,
          url ? ext(url, truncateMiddle(url.replace(/^https?:\/\//, '').replace(/\/$/, ''), 40), true) : null,
          managed.supportEmail
            ? h('a', { class: 'about-support__mail mono', attrs: { href: `mailto:${encodeURIComponent(managed.supportEmail)}`, title: managed.supportEmail, translate: 'no' }, text: managed.supportEmail })
            : null,
        );
      }
      const contact = h(
        'section',
        { class: 'about-col', attrs: { 'aria-labelledby': 'about-contact' } },
        h('h2', { class: 'about-h2', attrs: { id: 'about-contact' }, text: t('aboutContactTitle') }),
        support,
        h(
          'dl',
          { class: 'about-kv' },
          h('div', { class: 'about-kv__item' }, h('dt', { text: t('aboutPublisher') }), h('dd', null, 'Bastion Security GmbH, Zürich', ' ', ext(LINKS.HOMEPAGE, LINKS.HOMEPAGE.replace(/^https:\/\//, '').replace(/\/$/, ''), true))),
          h('div', { class: 'about-kv__item' }, h('dt', { text: t('aboutCreator') }), h('dd', { text: 'Luca Seeberger' })),
        ),
        ext(`${LINKS.REPO_URL}/issues`, t('aboutIssuesLink')),
      );

      const vendorRow = (nameText: string, licence: string, link: HTMLElement): HTMLElement =>
        h('li', { class: 'about-vendor__row' }, h('span', { class: 'about-vendor__name', attrs: { title: nameText, translate: 'no' }, text: nameText }), h('span', { class: 'about-vendor__lic', attrs: { translate: 'no' }, text: licence }), link);
      const vendor = h(
        'ul',
        { class: 'about-vendor' },
        ...VENDOR.map((v) => {
          const commit = meta?.vendor?.[v.key] ?? '';
          const valid = /^[0-9a-f]{7,40}$/i.test(commit);
          return vendorRow(v.name, v.licence, valid ? ext(`${v.repo}/commit/${commit}`, commit.slice(0, 10), true) : h('span', { class: 'mono db-muted', text: '–' }));
        }),
        ...FONTS.map(([fontName, url]) => vendorRow(fontName, 'OFL 1.1', ext(url, url.replace(/^https:\/\/github\.com\//, ''), true))),
      );
      const components = h(
        'section',
        { class: 'about-col', attrs: { 'aria-labelledby': 'about-components' } },
        h('h2', { class: 'about-h2', attrs: { id: 'about-components' }, text: t('aboutComponentsTitle') }),
        vendor,
      );

      const listsTable = meta?.lists?.length
        ? h(
            'div',
            { class: 'about-scroll' },
            h(
              'table',
              { class: 'about-table' },
              h('caption', { class: 'sr-only', text: t('aboutListsTitle') }),
              h('thead', null, h('tr', null, ...[t('aboutColList'), t('aboutColVersion'), t('aboutColLicence'), t('aboutColAttribution')].map((c) => h('th', { text: c, attrs: { scope: 'col' } })))),
              h(
                'tbody',
                null,
                ...meta.lists.map((l) => {
                  const v = l.sources?.find((s) => s.version)?.version;
                  const lm = l.sources?.map((s) => (s.lastModified ? Date.parse(s.lastModified) : NaN)).filter((x) => Number.isFinite(x)).sort((a, b) => b - a)[0];
                  const lic = safeUrl(l.licenseUrl);
                  const home = safeUrl(l.homepage);
                  return h(
                    'tr',
                    null,
                    h('th', { attrs: { scope: 'row' } }, home ? ext(home, localized(l.name)) : localized(l.name)),
                    h('td', { class: 'mono', attrs: { translate: 'no' } }, v ?? (lm ? fmtDate(lm) : '–')),
                    h('td', { attrs: { translate: 'no' } }, lic ? ext(lic, l.license) : l.license),
                    h('td', { class: 'about-attr', text: l.attribution }),
                  );
                }),
              ),
            ),
          )
        : h('p', { class: 'db-muted', text: t('aboutNoMeta') });

      mount(
        root,
        hero,
        privacy,
        h('div', { class: 'about-grid' }, contact, components),
        h('section', { class: 'about-lists', attrs: { 'aria-labelledby': 'about-lists' } }, h('h2', { class: 'about-h2', attrs: { id: 'about-lists' }, text: t('aboutListsTitle') }), listsTable),
        h('p', { class: 'db-footnote', text: t('aboutFootnote') }),
      );
    },
  };
}
