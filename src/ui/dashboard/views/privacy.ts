// Bastion Shield — dashboard «Datenschutz»: GPC, tracking parameters, bounce
// tracking, AMP, ClickFix protection (clipboard), fingerprinting default,
// hyperlink auditing, Privacy Sandbox ad APIs, WebRTC policy and third-party
// cookies. Each setting carries a
// one-line plain-language explanation and a lock when managed by policy.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { DeepPartial, EffectiveConfig, FingerprintLevel, Settings, WebRtcPolicy } from '../../../shared/types.ts';
import { h, toast } from '../../shared/dom.ts';
import { t } from '../../shared/i18n.ts';
import { icon } from '../../shared/icons.ts';
import { segmented, switchControl } from '../../shared/controls.ts';
import { errorState, nextId, pageHead, panel, popupMode, retryView, settingRow, type View, mount } from '../common.ts';
import { getConfig, isLocked, saveSettings } from '../store.ts';

type PrivacyKey = keyof Settings['privacy'];

const PRIVACY_PATHS: readonly string[] = ['gpc', 'stripParams', 'debounce', 'deAmp', 'clipboardGuard', 'fingerprinting', 'blockHyperlinkAuditing', 'disablePrivacySandboxAds', 'webrtcPolicy', 'blockThirdPartyCookies'].map((k) => `privacy.${k}`);

/** Save one setting. Resolves false (the control reverts) when the service worker refused it. */
export async function persist(patch: DeepPartial<Settings>): Promise<boolean> {
  const r = await saveSettings(patch);
  if (!r.ok) {
    toast(t('errorSaveFailed'), icon('alert', 15));
    return false;
  }
  // settings:set answers EffectiveConfig & { ignored }: a locked path is dropped, not an error.
  const { ignored, config } = r.data;
  if (ignored.length) {
    const locked = ignored.some((p) => isLocked(config, p) || isLocked(config, p.split('.')[0]));
    toast(locked ? t('lockedByPolicy') : t('errorSaveFailed'), icon(locked ? 'lock' : 'alert', 15));
    return false;
  }
  toast(t('saved'), icon('check', 15));
  return true;
}

/** A row's one-sentence explanation; the expanded popup shows labels only (DB41, DB42). */
export function rowDesc(key: string): string | undefined {
  return popupMode ? undefined : t(key);
}

/** «Erneut versuchen» of an error banner: ask the service worker again, then render the view again. */
export async function retryConfig(): Promise<void> {
  await getConfig(true);
  retryView();
}

/**
 * «Von Ihrer Organisation verwaltet» above a settings view: fully when the
 * policy locks every setting, «teilweise» when only some rows carry a lock.
 */
export function lockNotice(cfg: EffectiveConfig, paths: readonly string[]): HTMLElement | null {
  const all = !!cfg.managed.lockSettings;
  if (!all && !paths.some((p) => isLocked(cfg, p))) return null;
  return h(
    'div',
    { class: 'notice notice--lock db-lock-notice', attrs: { role: 'status' } },
    icon('lock', 16),
    h('div', null, h('div', { class: 'notice__title', text: t(all ? 'privLockedTitle' : 'privLockedPartTitle') }), h('div', { class: 'notice__body', text: t('privLockedText') })),
  );
}

export function privacyView(): View {
  return {
    async render(root) {
      const r = await getConfig();
      if (!r.ok) {
        mount(root, pageHead(t('privTitle'), t('privLead')), errorState(retryConfig));
        return;
      }
      const cfg: EffectiveConfig = r.data;
      const p = cfg.settings.privacy;

      const toggle = (key: PrivacyKey, labelKey: string, descKey: string): HTMLElement => {
        const labelId = nextId('priv');
        const descId = nextId('priv-d');
        const locked = isLocked(cfg, `privacy.${key}`);
        const sw = switchControl({
          checked: !!p[key],
          labelledBy: labelId,
          describedBy: descId,
          disabled: locked,
          onChange: (v) => persist({ privacy: { [key]: v } as DeepPartial<Settings['privacy']> }),
        });
        return settingRow({ label: t(labelKey), desc: rowDesc(descKey), control: sw.el, locked, labelId, descId });
      };

      // Fingerprinting default level.
      const fpLabel = nextId('priv');
      const fpDesc = nextId('priv-d');
      const fpLocked = isLocked(cfg, 'privacy.fingerprinting');
      const fp = segmented<FingerprintLevel>({
        options: [
          { value: 'off', label: t('fpOff') },
          { value: 'standard', label: t('fpStandard') },
          { value: 'strict', label: t('fpStrict') },
        ],
        value: p.fingerprinting,
        labelledBy: fpLabel,
        disabled: fpLocked,
        onChange: (v) => persist({ privacy: { fingerprinting: v } }),
      });

      // WebRTC IP handling.
      const rtcLabel = nextId('priv');
      const rtcDesc = nextId('priv-d');
      const rtcLocked = isLocked(cfg, 'privacy.webrtcPolicy');
      const rtc = h(
        'select',
        { class: 'select', attrs: { 'aria-labelledby': rtcLabel, 'aria-describedby': rtcDesc, disabled: rtcLocked } },
        h('option', { attrs: { value: 'default' }, text: t('privWebrtcDefault') }),
        h('option', { attrs: { value: 'default_public_interface_only' }, text: t('privWebrtcPublic') }),
        h('option', { attrs: { value: 'disable_non_proxied_udp' }, text: t('privWebrtcProxy') }),
      );
      rtc.value = p.webrtcPolicy;
      rtc.addEventListener('change', async () => {
        const prev = p.webrtcPolicy;
        if (await persist({ privacy: { webrtcPolicy: rtc.value as WebRtcPolicy } })) p.webrtcPolicy = rtc.value as WebRtcPolicy;
        else rtc.value = prev;
      });

      // Third-party cookies: tri-state (browser default / block / allow).
      const ckLabel = nextId('priv');
      const ckDesc = nextId('priv-d');
      const ckLocked = isLocked(cfg, 'privacy.blockThirdPartyCookies');
      type Ck = 'browser' | 'block' | 'allow';
      const ckValue: Ck = p.blockThirdPartyCookies === null || p.blockThirdPartyCookies === undefined ? 'browser' : p.blockThirdPartyCookies ? 'block' : 'allow';
      const ck = segmented<Ck>({
        options: [
          { value: 'browser', label: t('privCookiesBrowser') },
          { value: 'block', label: t('privCookiesBlock') },
          { value: 'allow', label: t('privCookiesAllow') },
        ],
        value: ckValue,
        labelledBy: ckLabel,
        disabled: ckLocked,
        onChange: (v) => persist({ privacy: { blockThirdPartyCookies: v === 'browser' ? null : v === 'block' } as DeepPartial<Settings['privacy']> }),
      });

      mount(
        root,
        pageHead(t('privTitle'), popupMode ? undefined : t('privLead')),
        lockNotice(cfg, PRIVACY_PATHS),
        panel(
          { title: t('privGroupSignals'), flush: true },
          toggle('gpc', 'privGpc', 'privGpcDesc'),
          toggle('stripParams', 'privParams', 'privParamsDesc'),
          toggle('debounce', 'privDebounce', 'privDebounceDesc'),
          toggle('deAmp', 'privAmp', 'privAmpDesc'),
        ),
        panel(
          { title: t('privGroupClipboard'), flush: true },
          toggle('clipboardGuard', 'privClipboard', 'privClipboardDesc'),
          settingRow({ label: t('privFingerprint'), desc: rowDesc('privFingerprintDesc'), control: fp.el, locked: fpLocked, labelId: fpLabel, descId: fpDesc }),
          popupMode ? null : h('p', { class: 'priv-note' }, icon('info', 16), h('span', { text: t('privFingerprintNote') })),
        ),
        panel(
          { title: t('privGroupBrowser'), flush: true },
          toggle('blockHyperlinkAuditing', 'privPing', 'privPingDesc'),
          toggle('disablePrivacySandboxAds', 'privSandbox', 'privSandboxDesc'),
          settingRow({ label: t('privWebrtc'), desc: rowDesc('privWebrtcDesc'), control: rtc, locked: rtcLocked, labelId: rtcLabel, descId: rtcDesc }),
          settingRow({ label: t('privCookies'), desc: rowDesc('privCookiesDesc'), control: ck.el, locked: ckLocked, labelId: ckLabel, descId: ckDesc }),
        ),
        popupMode ? null : h('p', { class: 'db-footnote', text: t('privFootnote') }),
      );
    },
  };
}
