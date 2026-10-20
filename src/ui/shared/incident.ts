// Bastion Shield — «Cyber-Vorfall?» button: links to the incident contact
// form on bastionsecurity.ch in the UI language (German page for de, English
// page otherwise). The only Bundesrot button in the UI (.btn--cta).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { LINKS } from '../../shared/constants.ts';
import { h } from './dom.ts';
import { t, uiLang, type UiLang } from './i18n.ts';
import { icon, mark } from './icons.ts';

/** Incident contact page for a UI language. */
export function incidentUrl(lang: UiLang): string {
  return lang === 'de' ? LINKS.INCIDENT_DE : LINKS.INCIDENT_EN;
}

/**
 * The CTA as a real link (opens a new tab). `onOpen` runs after the click, e.g.
 * to close the popup once Chrome has the new tab.
 */
export function incidentButton(className = '', onOpen?: () => void): HTMLAnchorElement {
  const a = h(
    'a',
    {
      class: `btn btn--cta${className ? ` ${className}` : ''}`,
      attrs: { href: incidentUrl(uiLang), target: '_blank', rel: 'noopener noreferrer', 'data-cta': 'incident' },
    },
    icon('incident', 16),
    h('span', { text: t('ctaIncident') }),
  );
  if (onOpen) a.addEventListener('click', () => onOpen());
  return a;
}

/** What stands in for the CTA when it is switched off (setting ui.incidentCta): mark + name. */
export function brandPlate(className = ''): HTMLElement {
  return h('span', { class: `brand-plate${className ? ` ${className}` : ''}`, attrs: { 'data-cta': 'brand' } }, mark(22), h('span', { class: 'brand-plate__name', text: t('extName') }));
}

/** CTA or brand plate, depending on the setting. */
export function ctaOrBrand(show: boolean, className = '', onOpen?: () => void): HTMLElement {
  return show ? incidentButton(className, onOpen) : brandPlate(className);
}
