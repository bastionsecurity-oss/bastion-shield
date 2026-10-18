// Bastion Shield — dashboard «Über»: version and build date, privacy
// statement, licence and source code, contact, and full attribution of every
// filter list, vendored component and font shipped in the package.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { LINKS } from '../../../shared/constants.ts';
import { h } from '../../shared/dom.ts';
import { fmtDate, fmtDateTime, localized, t } from '../../shared/i18n.ts';
import { icon, mark } from '../../shared/icons.ts';
import { extensionVersion } from '../../shared/messaging.ts';
import { panel, type View, mount } from '../common.ts';
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

const VENDOR: { key: 'ublock' | 'braveResources' | 'braveLists'; name: string; repo: string; licence: string }[] = [
  { key: 'ublock', name: 'uBlock Origin (scriptlets, redirect resources)', repo: 'https://github.com/gorhill/uBlock', licence: 'GPL-3.0-or-later' },
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

      const hero = h(
        'section',
        { class: 'about-hero' },
        mark(56),
        h(
          'div',
          null,
          h('h1', { class: 'about-hero__name', text: t('extName'), attrs: { tabindex: -1 } }),
          h(
            'dl',
            { class: 'about-hero__facts' },
            h('div', null, h('dt', { text: t('aboutVersion') }), h('dd', { class: 'mono', text: version })),
            h('div', null, h('dt', { text: t('aboutBuilt') }), h('dd', { text: Number.isFinite(built) ? fmtDateTime(built) : '–' })),
            h('div', null, h('dt', { text: t('aboutLicence') }), h('dd', null, ext('https://www.gnu.org/licenses/gpl-3.0.html', 'GPL-3.0-or-later'))),
            h('div', null, h('dt', { text: t('aboutSource') }), h('dd', null, ext(LINKS.REPO_URL, LINKS.REPO_URL.replace(/^https:\/\//, ''), true))),
          ),
        ),
      );

      const privacy = h(
        'section',
        { class: 'about-privacy', attrs: { 'aria-labelledby': 'about-privacy-title' } },
        h('h2', { class: 'about-privacy__title', attrs: { id: 'about-privacy-title' }, text: t('aboutPrivacyStatement') }),
        h('p', { class: 'about-privacy__text', text: t('aboutPrivacyText') }),
        ext(LINKS.PRIVACY, t('aboutPrivacyLink')),
      );

      const contactItems: HTMLElement[] = [
        h('div', null, h('dt', { text: t('aboutPublisher') }), h('dd', null, 'Bastion GmbH i. Gr., Zürich', h('br'), ext(LINKS.HOMEPAGE, LINKS.HOMEPAGE.replace(/^https:\/\//, '')))),
        h('div', null, h('dt', { text: t('aboutIssues') }), h('dd', null, ext(`${LINKS.REPO_URL}/issues`, t('aboutIssuesLink')))),
      ];
      if (managed.organizationName || managed.supportUrl || managed.supportEmail) {
        const support: (HTMLElement | string)[] = [];
        if (managed.organizationName) support.push(managed.organizationName);
        const url = safeUrl(managed.supportUrl);
        if (url) support.push(h('br'), ext(url, url.replace(/^https?:\/\//, '')));
        if (managed.supportEmail) support.push(h('br'), h('a', { attrs: { href: `mailto:${encodeURIComponent(managed.supportEmail)}` }, text: managed.supportEmail }));
        contactItems.unshift(h('div', null, h('dt', { text: t('aboutSupport') }), h('dd', null, ...support)));
      }

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
                    h('td', { class: 'mono' }, v ?? (lm ? fmtDate(lm) : '–')),
                    h('td', null, lic ? ext(lic, l.license) : l.license),
                    h('td', { class: 'about-attr', text: l.attribution }),
                  );
                }),
              ),
            ),
          )
        : h('p', { class: 'db-muted', text: t('aboutNoMeta') });

      const vendor = h(
        'ul',
        { class: 'about-vendor' },
        ...VENDOR.map((v) => {
          const commit = meta?.vendor?.[v.key] ?? '';
          const valid = /^[0-9a-f]{7,40}$/i.test(commit);
          return h(
            'li',
            null,
            h('span', { class: 'about-vendor__name', text: v.name }),
            h('span', { class: 'about-vendor__lic', text: v.licence }),
            valid ? ext(`${v.repo}/commit/${commit}`, commit.slice(0, 12), true) : h('span', { class: 'mono db-muted', text: '–' }),
          );
        }),
        ...FONTS.map(([name, url]) => h('li', null, h('span', { class: 'about-vendor__name', text: name }), h('span', { class: 'about-vendor__lic', text: 'SIL OFL 1.1' }), ext(url, url.replace(/^https:\/\//, ''), true))),
      );

      mount(root, 
        hero,
        privacy,
        h('div', { class: 'about-grid' }, panel({ title: t('aboutContactTitle') }, h('dl', { class: 'kv about-kv' }, ...contactItems)), panel({ title: t('aboutComponentsTitle') }, vendor)),
        panel({ title: t('aboutListsTitle'), flush: true }, listsTable),
        h('p', { class: 'db-footnote', text: t('aboutFootnote') }),
      );
    },
  };
}
