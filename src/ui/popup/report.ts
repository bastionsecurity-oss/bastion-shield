// Bastion Shield — «Melden…» (P08–P11). Builds a broken-site report that
// contains only the hostname (never path or query), versions and the enabled
// list ids, shows exactly that in a bottom sheet («Was geteilt wird»), and
// only then opens a prefilled GitHub issue or an e-mail draft. Nothing is
// sent automatically. When GitHub cannot be opened the sheet stays with an
// inline error and «Erneut öffnen» (P11).
//
// The sheet is a modal <dialog>: the rest of the popup is inert (focus trap),
// focus starts on «Abbrechen» (the safe action), Escape closes it, and focus
// returns to «Melden…» afterwards.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ListsState, PopupState } from '../../shared/types.ts';
import { LINKS } from '../../shared/constants.ts';
import { h } from '../shared/dom.ts';
import { t } from '../shared/i18n.ts';
import { icon } from '../shared/icons.ts';
import { ListDirectory } from '../shared/labels.ts';
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

async function collect(state: PopupState): Promise<{ data: ReportData; names: string[] }> {
  const res = await call<ListsState>({ type: 'lists:get' });
  const lists = res.ok && res.data?.enabled ? Object.keys(res.data.enabled).filter((id) => res.data.enabled[id]).sort() : [];
  const dir = new ListDirectory(res.ok ? (res.data?.meta ?? null) : null);
  return {
    data: {
      site: hostOnly(state),
      version: state.version || extensionVersion(),
      browser: browserName(),
      mode: state.siteSettings.mode,
      protection: state.siteSettings.enabled ? 'on' : 'off',
      lists,
    },
    names: lists.map((id) => dir.name(id) || id),
  };
}

/** Plain-text body; the sheet shows the same facts as key/value rows. */
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

/** "EasyList, EasyPrivacy +4": the first `shown` names, then the rest as a count. */
export function listsSummary(names: readonly string[], shown = 2): string {
  if (names.length === 0) return '-';
  const head = names.slice(0, shown).join(', ');
  return names.length > shown ? `${head} +${names.length - shown}` : head;
}

/** Text with the host marked translate="no": "20min.ch melden". */
function withHost(key: string, host: string): HTMLElement {
  const MARK = '\u0001';
  const [before = '', after = ''] = t(key, MARK).split(MARK);
  return h('span', null, before, h('span', { attrs: { translate: 'no' }, text: host }), after);
}

let seq = 0;

/** Show the sheet and open the chosen channel. Resolves true when it was opened. */
export async function startReport(state: PopupState): Promise<boolean> {
  const channel = state.managed.reportBrokenSite;
  const email = state.managed.supportEmail;
  if (channel === 'none' || (channel === 'email' && !email)) return false;
  const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const { data, names } = await collect(state);
  const id = `pp-sheet-${++seq}`;

  return new Promise<boolean>((resolve) => {
    let opened = false;

    // ---- What gets shared (key/value disclosure) ----
    const modeText = `${t(data.mode === 'aggressive' ? 'modeAggressive' : 'modeStandard')}, ${t(data.protection === 'on' ? 'popupProtectionOn' : 'popupProtectionOff')}`;
    const row = (key: string, value: string, full = value): HTMLElement =>
      h('div', { class: 'pp-kv__row' }, h('dt', { class: 'pp-kv__key', text: t(key) }), h('dd', { class: 'pp-kv__val', attrs: { translate: 'no', title: full }, text: value }));
    const panel = h(
      'div',
      { class: 'pp-share__panel', attrs: { id: `${id}-share`, hidden: true } },
      h(
        'dl',
        { class: 'pp-kv' },
        row('reportKeySite', data.site),
        row('reportKeyVersion', `Bastion Shield ${data.version}`),
        row('reportKeyBrowser', data.browser),
        row('reportKeyMode', modeText),
        row('reportKeyLists', listsSummary(names), names.join(', ')),
      ),
      h('p', { class: 'pp-share__not', text: t('reportNotSharedShort') }),
    );
    const chevron = h('span', { class: 'pp-share__chev', attrs: { 'aria-hidden': 'true' } }, icon('chevronRight', 12));
    const aside = h('span', { class: 'pp-share__aside', text: t('reportSharedAside') });
    const toggle = h(
      'button',
      { class: 'pp-share__toggle', attrs: { type: 'button', 'aria-expanded': 'false', 'aria-controls': `${id}-share`, 'data-share': 'toggle' } },
      chevron,
      h('span', { class: 'pp-share__label', text: t('reportWhatShared') }),
      aside,
    );
    toggle.addEventListener('click', () => {
      const open = toggle.getAttribute('aria-expanded') !== 'true';
      toggle.setAttribute('aria-expanded', String(open));
      panel.hidden = !open;
      aside.hidden = open;
      fitBody();
    });
    const share = h('div', { class: 'pp-share' }, toggle, panel);

    // ---- Recipient (e-mail) ----
    const to =
      channel === 'email' && email
        ? h(
            'div',
            { class: 'pp-sheet__to' },
            h('span', { class: 'pp-sheet__to-key', text: t('reportSheetTo') }),
            h('span', { class: 'pp-sheet__to-val trunc', attrs: { translate: 'no', title: email }, text: email }),
          )
        : null;

    // ---- Inline error (P11) ----
    const error = h(
      'div',
      { class: 'pp-sheet__error', attrs: { role: 'alert', hidden: true } },
      icon('alert', 18),
      h('div', { class: 'pp-sheet__error-text' }, h('p', { class: 'pp-sheet__error-title', text: t('reportGithubFailTitle') }), h('p', { class: 'pp-sheet__error-body', text: t('reportGithubFailText') })),
    );

    // ---- Actions: primary first, focus starts on «Abbrechen» ----
    const primaryLabel = channel === 'github' ? t('reportOpenGithub') : t('reportOpenDraft');
    const ok = h('button', { class: 'btn btn--primary btn--h-popup pp-sheet__ok', text: primaryLabel, attrs: { type: 'button', 'data-dialog': 'confirm' } });
    const cancel = h('button', { class: 'btn btn--outline btn--h-popup pp-sheet__cancel', text: t('actionCancel'), attrs: { type: 'button', 'data-dialog': 'cancel' } });
    const close = h('button', { class: 'pp-sheet__close', attrs: { type: 'button', 'aria-label': t('reportCloseSheet'), 'data-dialog': 'close' } }, icon('close', 14));

    const dlg = h(
      'dialog',
      { class: 'pp-sheet', attrs: { 'aria-labelledby': `${id}-title`, 'aria-describedby': `${id}-text`, 'data-channel': channel } },
      h(
        'div',
        { class: 'pp-sheet__head' },
        h('span', { class: 'tile pp-sheet__tile', attrs: { 'aria-hidden': 'true' } }, icon('flag', 22)),
        h(
          'div',
          { class: 'pp-sheet__head-text' },
          h('h2', { class: 'pp-sheet__title', attrs: { id: `${id}-title`, title: t('reportSheetTitle', data.site) } }, withHost('reportSheetTitle', data.site)),
          h('p', { class: 'pp-sheet__text', attrs: { id: `${id}-text` }, text: channel === 'github' ? t('reportSheetGithub') : t('reportSheetEmail') }),
        ),
      ),
      to || null,
      share,
      error,
      h('div', { class: 'pp-sheet__actions' }, ok, cancel),
      close,
    ) as HTMLDialogElement;

    /** The popup grows so the sheet fits (a short popup would clip it). */
    function fitBody(): void {
      document.body.style.removeProperty('min-height');
      const need = dlg.offsetHeight + 16;
      if (need > document.body.offsetHeight) document.body.style.minHeight = `${need}px`;
    }

    const finish = (): void => {
      if (dlg.open) dlg.close();
    };
    dlg.addEventListener('close', () => {
      dlg.remove();
      document.body.style.removeProperty('min-height');
      document.body.classList.remove('pp-sheet-open');
      if (!opened && opener?.isConnected) opener.focus({ preventScroll: true });
      resolve(opened);
    });
    // A click on the scrim (outside the sheet) is a cancel too.
    dlg.addEventListener('click', (e) => {
      if (e.target === dlg) {
        const r = dlg.getBoundingClientRect();
        const inside = e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom;
        if (!inside) finish();
      }
    });
    cancel.addEventListener('click', finish);
    close.addEventListener('click', finish);
    // Keep Tab inside the sheet (a modal dialog would otherwise hand focus to the browser UI).
    dlg.addEventListener('keydown', (e) => {
      if (e.key !== 'Tab') return;
      const items = Array.from(dlg.querySelectorAll<HTMLElement>('button:not([disabled]), a[href]')).filter((el) => el.offsetParent !== null);
      const first = items[0];
      const last = items[items.length - 1];
      if (!first || !last) return;
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    });

    const showError = (): void => {
      error.hidden = false;
      share.hidden = true;
      ok.textContent = t('reportRetryOpen');
      fitBody();
    };

    ok.addEventListener('click', async () => {
      if (channel === 'github') {
        try {
          await chrome.tabs.create({ url: githubUrl(data) });
        } catch {
          showError();
          return;
        }
      } else if (email) {
        // An anchor click hands mailto: to the OS mail client without leaving a blank tab.
        const a = h('a', { attrs: { href: mailtoUrl(data, email) } });
        dlg.appendChild(a);
        a.click();
        a.remove();
      }
      opened = true;
      finish();
    });

    document.body.appendChild(dlg);
    document.body.classList.add('pp-sheet-open');
    try {
      dlg.showModal();
    } catch {
      dlg.setAttribute('open', '');
    }
    fitBody();
    cancel.focus();
  });
}
