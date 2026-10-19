// Bastion Shield service worker — message sender validation (ARCHITECTURE §7).
// Only our own extension contexts are answered; content-script messages must
// come from a tab, UI messages from one of our extension pages, and the
// strict-block messages only from the top frame of pages/blocked.html.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { parseUrl } from './util.ts';

/** Minimal shape of chrome.runtime.MessageSender we rely on. */
export interface SenderInfo {
  id?: string;
  url?: string;
  origin?: string;
  frameId?: number;
  documentId?: string;
  tab?: { id?: number; url?: string };
}

export type SenderKind = 'content' | 'extension';

/** Messages from content scripts in web frames. */
export const CONTENT_TYPES: ReadonlySet<string> = new Set(['cosmetic:frame', 'cosmetic:tokens', 'cosmetic:procedural', 'nerd:signal', 'notice:clip']);
/** Messages from pages/blocked.html only (privileged: proceeding lifts a strict block). */
export const BLOCKED_TYPES: ReadonlySet<string> = new Set(['blocked:info', 'blocked:proceed']);
export const UI_TYPES: ReadonlySet<string> = new Set([
  'popup:state',
  'site:set',
  'config:get',
  'settings:set',
  'lists:get',
  'lists:set',
  'sites:get',
  'sites:set',
  'custom:get',
  'custom:set',
  'history:query',
  'history:events',
  'history:clear',
  'backup:export',
  'backup:import',
  'nerd:bisect',
]);

export function isKnownType(type: string): boolean {
  return CONTENT_TYPES.has(type) || BLOCKED_TYPES.has(type) || UI_TYPES.has(type);
}

/**
 * Who sent a message: one of our extension pages (popup, dashboard, the
 * blocked page when loaded from our static origin) or a content script in a
 * tab. Anything else (other extensions, web pages) is ignored.
 */
export function classifySender(sender: SenderInfo | undefined, runtimeId: string, extensionOrigin: string): SenderKind | null {
  if (!sender || !runtimeId || sender.id !== runtimeId) return null;
  if (typeof sender.url === 'string' && sender.url.startsWith(extensionOrigin)) return 'extension';
  if (sender.tab && typeof sender.tab.id === 'number' && sender.tab.id >= 0) return 'content';
  return null;
}

/**
 * True when the sender is the top frame of our strict-block page in a tab.
 * `pageUrls` are the page's URLs on the static and the dynamic
 * (use_dynamic_url) origin: chrome.runtime.getURL('pages/blocked.html') and
 * `${extensionOrigin}pages/blocked.html`. A web renderer cannot commit a
 * chrome-extension: URL, so this cannot be spoofed by a page or content script.
 */
export function isBlockedPageSender(sender: SenderInfo, pageUrls: readonly string[]): boolean {
  const u = parseUrl(sender.url);
  if (!u || (u.protocol !== 'chrome-extension:' && u.protocol !== 'extension:')) return false;
  if (sender.frameId !== 0) return false;
  if (typeof sender.tab?.id !== 'number' || sender.tab.id < 0) return false;
  return pageUrls.some((p) => {
    const want = parseUrl(p);
    return want !== null && want.protocol === u.protocol && want.hostname === u.hostname && want.pathname === u.pathname;
  });
}

/** Whether a sender of `kind` may send `type`. */
export function isAllowed(type: string, kind: SenderKind, sender: SenderInfo, blockedPageUrls: readonly string[] = []): boolean {
  if (CONTENT_TYPES.has(type)) return kind === 'content';
  if (BLOCKED_TYPES.has(type)) return isBlockedPageSender(sender, blockedPageUrls);
  if (UI_TYPES.has(type)) return kind === 'extension';
  return false;
}
