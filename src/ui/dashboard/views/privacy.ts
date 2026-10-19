// Bastion Shield — dashboard «Datenschutz»: GPC, tracking parameters, bounce
// tracking, AMP, ClickFix protection (clipboard), fingerprinting default,
// hyperlink auditing, Privacy Sandbox ad APIs, WebRTC policy and third-party
// cookies. Each setting carries a
// one-line plain-language explanation and a lock when managed by policy.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { DeepPartial, EffectiveConfig, FingerprintLevel, Settings, WebRtcPolicy } from '../../../shared/types.ts';
import { h, toast } from '../../shared/dom.ts';
import { t } from '../../shared/i18n.ts';
import { icon } from '../../shared/icons.ts';
import { notice, segmented, switchControl } from '../../shared/controls.ts';
import { errorState, nextId, pageHead, panel, settingRow, type View, mount } from '../common.ts';
import { getConfig, isLocked, saveSettings } from '../store.ts';

type PrivacyKey = keyof Settings['privacy'];

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

export function privacyView(): View {
  return {
    async render(root) {
      const r = await getConfig();
      if (!r.ok) {
        mount(root, pageHead(t('privTitle'), t('privLead')), errorState(() => location.reload()));
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
        return settingRow({ label: t(labelKey), desc: t(descKey), control: sw.el, locked, labelId, descId });
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

      mount(root, 
        pageHead(t('privTitle'), t('privLead')),
        cfg.managed.lockSettings ? h('div', { class: 'db-gap' }, notice(t('privLockedTitle'), t('privLockedText'), 'info')) : null,
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
        ),
        panel(
          { title: t('privGroupFingerprint'), flush: true },
          settingRow({ label: t('privFingerprint'), desc: t('privFingerprintDesc'), control: fp.el, locked: fpLocked, labelId: fpLabel, descId: fpDesc }),
          h('p', { class: 'db-row__aside', text: t('privFingerprintNote') }),
        ),
        panel(
          { title: t('privGroupBrowser'), flush: true },
          toggle('blockHyperlinkAuditing', 'privPing', 'privPingDesc'),
          toggle('disablePrivacySandboxAds', 'privSandbox', 'privSandboxDesc'),
          settingRow({ label: t('privWebrtc'), desc: t('privWebrtcDesc'), control: rtc, locked: rtcLocked, labelId: rtcLabel, descId: rtcDesc }),
          settingRow({ label: t('privCookies'), desc: t('privCookiesDesc'), control: ck.el, locked: ckLocked, labelId: ckLabel, descId: ckDesc }),
        ),
        h('p', { class: 'db-footnote', text: t('privFootnote') }),
      );
    },
  };
}
