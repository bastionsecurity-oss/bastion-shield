// Bastion Shield — pure helpers for the popup: normalising the service
// worker's popup:state reply (so a partial or older reply never breaks
// rendering) and reading the optional ?tabId=<n> override. DOM-free so it can
// be unit tested.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { PopupState } from '../../shared/types.ts';

/**
 * Tab id from the popup URL (`popup.html?tabId=42`). Used when the popup is
 * opened as a normal tab (tests, keyboard-only users who open it from the
 * dashboard), where chrome.tabs.query would return the popup's own tab.
 */
export function tabIdFromSearch(search: string): number | null {
  try {
    const raw = new URLSearchParams(search).get('tabId');
    if (raw === null || !/^\d{1,10}$/.test(raw)) return null;
    const n = Number(raw);
    return Number.isSafeInteger(n) && n >= 0 ? n : null;
  } catch {
    return null;
  }
}

const num = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : 0);

/** Fill defaults so a partial or older service-worker reply can never break rendering. */
export function normalisePopupState(raw: unknown, fallbackTabId: number): PopupState {
  const r = (raw && typeof raw === 'object' ? raw : {}) as Partial<PopupState>;
  const c = (r.counts ?? {}) as Partial<PopupState['counts']>;
  const fp = r.siteSettings?.fingerprinting;
  const channel = r.managed?.reportBrokenSite;
  const supportEmail = typeof r.managed?.supportEmail === 'string' && r.managed.supportEmail ? r.managed.supportEmail : undefined;
  return {
    tabId: typeof r.tabId === 'number' ? r.tabId : fallbackTabId,
    url: typeof r.url === 'string' ? r.url : null,
    host: typeof r.host === 'string' ? r.host : null,
    site: typeof r.site === 'string' ? r.site : null,
    filterable: r.filterable !== false,
    siteSettings: {
      enabled: r.siteSettings?.enabled !== false,
      mode: r.siteSettings?.mode === 'aggressive' ? 'aggressive' : 'standard',
      blockScripts: !!r.siteSettings?.blockScripts,
      fingerprinting: fp === 'off' || fp === 'strict' ? fp : 'standard',
    },
    counts: { blocked: num(c.blocked), redirected: num(c.redirected), stripped: num(c.stripped), debounced: num(c.debounced), thirdPartyHosts: num(c.thirdPartyHosts) },
    totals: r.totals ?? { since: 0, blocked: 0, byKind: {} },
    recent: Array.isArray(r.recent) ? r.recent.filter((e) => e && typeof e === 'object' && typeof e.t === 'number') : [],
    // Older service workers did not report these: assume the documented defaults.
    logging: r.logging !== false,
    counting: r.counting !== false,
    globallyDisabled: r.globallyDisabled === true,
    locks: { siteToggle: !!r.locks?.siteToggle, mode: !!r.locks?.mode, settings: !!r.locks?.settings },
    managed: {
      organizationName: typeof r.managed?.organizationName === 'string' && r.managed.organizationName ? r.managed.organizationName : undefined,
      supportUrl: typeof r.managed?.supportUrl === 'string' && r.managed.supportUrl ? r.managed.supportUrl : undefined,
      supportEmail,
      // Documented default: e-mail when a helpdesk address is set, otherwise GitHub.
      reportBrokenSite: channel === 'github' || channel === 'email' || channel === 'none' ? channel : supportEmail ? 'email' : 'github',
    },
    incidentCta: r.incidentCta !== false,
    nerd: r.nerd && typeof r.nerd === 'object' ? r.nerd : null,
    version: typeof r.version === 'string' ? r.version : '',
  };
}
