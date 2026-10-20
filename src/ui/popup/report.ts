// Bastion Shield — "Seite defekt? Melden". Builds a broken-site report that
// contains only the hostname (never path or query), versions and the enabled
// list ids, shows the user exactly that text, and only then opens a prefilled
// GitHub issue or an e-mail draft. Nothing is sent automatically.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ListsState, PopupState } from '../../shared/types.ts';
import { LINKS } from '../../shared/constants.ts';
import { h } from '../shared/dom.ts';
import { t } from '../shared/i18n.ts';
import { confirmDialog, eyebrow } from '../shared/controls.ts';
import { call, extensionVersion } from '../shared/messaging.ts';

interface UaBrand {
  brand: string;
  version: string;
}

/** "Google Chrome 155" / "Microsoft Edge 155" / "Brave 155" — major version only. */
export function browserName(): string {
  try {
    const brands = (navigator as Navigator & { userAgentData?: { brands?: UaBrand[] } }).userAgentData?.brands;
    if (brands && brands.length) {
      const real = brands.filter((b) => !/not.?a.?brand/i.test(b.brand));
      const pick = real.find((b) => b.brand !== 'Chromium') ?? real[0];
      if (pick) return `${pick.brand} ${pick.version}`;
    }
    const m = /(Edg|OPR|Chrome)\/(\d+)/.exec(navigator.userAgent);
    if (m) return `${m[1] === 'Edg' ? 'Microsoft Edge' : m[1] === 'OPR' ? 'Opera' : 'Chromium'} ${m[2]}`;
  } catch {
    /* fall through */
  }
  return 'Chromium';
}

/** Hostname only. state.host is already a hostname; this is a second line of defence. */
function hostOnly(state: PopupState): string {
  const raw = state.host ?? state.site ?? '';
  try {
    return new URL(`https://${raw}`).hostname;
  } catch {
    return raw.replace(/[/?#].*$/, '');
  }
}

export interface ReportData {
  site: string;
  version: string;
  browser: string;
  mode: string;
  protection: string;
  lists: string[];
}

async function collect(state: PopupState): Promise<ReportData> {
  const res = await call<ListsState>({ type: 'lists:get' });
  const lists = res.ok && res.data?.enabled ? Object.keys(res.data.enabled).filter((id) => res.data.enabled[id]).sort() : [];
  return {
    site: hostOnly(state),
    version: state.version || extensionVersion(),
    browser: browserName(),
    mode: state.siteSettings.mode,
    protection: state.siteSettings.enabled ? 'on' : 'off',
    lists,
  };
}

/** Plain-text body; identical to what the confirmation shows. */
export function reportText(d: ReportData): string {
  return [
    `Site: ${d.site}`,
    `Bastion Shield: ${d.version}`,
    `Browser: ${d.browser}`,
    `Mode: ${d.mode}`,
    `Protection on this site: ${d.protection}`,
    `Filter lists: ${d.lists.join(', ') || '-'}`,
  ].join('\n');
}

export function githubUrl(d: ReportData): string {
  const q = new URLSearchParams({
    template: 'broken-site.yml',
    title: `Broken site: ${d.site}`,
    site: d.site,
    version: d.version,
    browser: d.browser,
    mode: d.mode,
    lists: d.lists.join(', '),
  });
  return `${LINKS.REPO_URL}/issues/new?${q.toString()}`;
}

export function mailtoUrl(d: ReportData, email: string): string {
  const subject = t('reportMailSubject', d.site);
  const body = `${reportText(d)}\n\n${t('reportMailDescribe')}\n`;
  return `mailto:${encodeURIComponent(email)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

/** Show the confirmation and open the chosen channel. Resolves true when opened. */
export async function startReport(state: PopupState): Promise<boolean> {
  const channel = state.managed.reportBrokenSite;
  const email = state.managed.supportEmail;
  if (channel === 'none' || (channel === 'email' && !email)) return false;
  const data = await collect(state);

  const ok = await confirmDialog({
    title: t('reportTitle'),
    body: channel === 'github' ? t('reportGithubText') : t('reportEmailText', email ?? ''),
    content: h(
      'div',
      null,
      eyebrow(t('reportShared')),
      h('pre', { class: 'pp-report__pre mono', text: reportText(data), attrs: { style: 'margin-top:6px' } }),
      h('p', { class: 'dialog__text', text: t('reportNotShared'), attrs: { style: 'margin-top:8px' } }),
    ),
    confirmLabel: channel === 'github' ? t('reportOpenGithub') : t('reportOpenEmail'),
  });
  if (!ok) return false;

  if (channel === 'github') {
    const url = githubUrl(data);
    try {
      await chrome.tabs.create({ url });
    } catch {
      window.open(url, '_blank', 'noopener');
    }
  } else if (email) {
    // An anchor click hands mailto: to the OS mail client without leaving a blank tab.
    const a = h('a', { attrs: { href: mailtoUrl(data, email) } });
    document.body.appendChild(a);
    a.click();
    a.remove();
  }
  return true;
}
