// Bastion Shield — "Verwaltet von <Organisation>" name, linked to the managed
// supportUrl when the policy sets one (policy schema: "shown next to the
// organisation name"). Shared by the popup header and the dashboard nav.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { h } from './dom.ts';

/** https:// URL without credentials, or null. The service worker validates it as well. */
export function safeSupportUrl(raw: string | undefined | null): string | null {
  if (!raw || typeof raw !== 'string') return null;
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' && !u.username && !u.password ? u.href : null;
  } catch {
    return null;
  }
}

/** Organisation name as a link to the support page, or plain text when there is none. */
export function orgNameEl(name: string, supportUrl: string | undefined, cls: string, onOpen?: () => void): HTMLElement {
  const href = safeSupportUrl(supportUrl);
  if (!href) return h('span', { class: cls, text: name });
  return h('a', {
    class: `${cls} org-link`,
    text: name,
    attrs: { href, target: '_blank', rel: 'noopener noreferrer', title: href },
    on: onOpen ? { click: () => onOpen() } : undefined,
  });
}
