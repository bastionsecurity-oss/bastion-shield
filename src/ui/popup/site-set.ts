// Bastion Shield — a per-site settings change from the compact popup and the
// expanded view («Diese Website»): site:set, the policy refusals it reports,
// and the settings the site resolves to afterwards.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { PopupState, SiteSettings } from '../../shared/types.ts';
import { toast } from '../shared/dom.ts';
import { t } from '../shared/i18n.ts';
import { icon } from '../shared/icons.ts';
import { call } from '../shared/messaging.ts';
import { normalisePopupState } from './state.ts';

interface SiteSetReply {
  ok?: boolean;
  ignored?: string[];
  siteSettings?: SiteSettings;
}

/**
 * Apply `patch` to the site of `s` and set `s.siteSettings` to what the site
 * now resolves to. False (after a toast) when saving failed or a policy
 * decides the field; the caller then keeps its control on the effective value.
 */
export async function setSiteSettings(s: PopupState, tabId: number, patch: SiteSettings): Promise<boolean> {
  const site = s.site ?? s.host;
  if (!site) return false;
  const res = await call<SiteSetReply>({ type: 'site:set', site, patch });
  if (!res.ok) {
    toast(t('errorSaveFailed'), icon('alert', 15));
    return false;
  }
  // The service worker drops fields that policy locks; revert the control and say why.
  const ignored = Array.isArray(res.data?.ignored) ? res.data.ignored : [];
  if (ignored.length && Object.keys(patch).every((k) => ignored.includes(k))) {
    toast(t('lockedByPolicy'), icon('lock', 15));
    return false;
  }
  // site:set answers { ok, ignored, siteSettings } with the settings the site now resolves to.
  const resolved = res.data?.siteSettings;
  if (resolved && typeof resolved === 'object') {
    const next = normalisePopupState({ siteSettings: resolved }, tabId).siteSettings;
    s.siteSettings = next;
    if ((Object.keys(patch) as (keyof SiteSettings)[]).some((k) => patch[k] !== undefined && next[k] !== patch[k])) {
      // A parent-domain policy decides this field: keep the control on the effective value.
      toast(t('lockedByPolicy'), icon('lock', 15));
      return false;
    }
  } else {
    Object.assign(s.siteSettings, patch);
  }
  return true;
}
