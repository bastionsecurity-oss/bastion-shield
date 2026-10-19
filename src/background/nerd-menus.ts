// Bastion Shield service worker — nerd-mode context menu (docs/NERD-MODE.md).
// Exists only while nerd mode is on: sync() removes every menu item and
// recreates them when the setting flips, and on the first call after the
// worker started (install, browser start, worker restart). The click handler
// is registered synchronously in index.ts and calls onClicked().
//
//   Bastion Shield ▸ Explain this URL           link, image, video, audio, frame
//                  ▸ Test selection as filter   selection
//                  ▸ Blame selection as filter  selection
//                  ▸ Find the breaking filter   page
//   Open Lab                                    toolbar icon (action)
//
// The menu specs and the Lab URLs are pure functions (unit-tested with a fake
// chrome); the bisect goes through NerdService like the popup's.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { MsgNerdBisect } from '../shared/types.ts';
import * as log from './log.ts';
import { webHostOf } from './util.ts';

export const MENU = {
  ROOT: 'nerd-root',
  EXPLAIN: 'nerd-explain-url',
  TEST: 'nerd-test-selection',
  BLAME: 'nerd-blame-selection',
  BISECT: 'nerd-bisect',
  LAB: 'nerd-open-lab',
} as const;

/** Longest selection passed to the Lab (keeps the URL reasonable; filters are short). */
export const MAX_SELECTION = 4000;
/** Longest URL passed to the Lab. */
export const MAX_URL = 8192;

type Context = 'link' | 'image' | 'video' | 'audio' | 'frame' | 'selection' | 'page' | 'action';

export interface MenuSpec {
  id: string;
  title: string;
  contexts: Context[];
  parentId?: string;
}

const EXPLAIN_CONTEXTS: Context[] = ['link', 'image', 'video', 'audio', 'frame'];

/** The menu items, in creation order (parents first). */
export function menuSpecs(msg: (key: string) => string): MenuSpec[] {
  return [
    { id: MENU.ROOT, title: msg('extName') || 'Bastion Shield', contexts: [...EXPLAIN_CONTEXTS, 'selection', 'page'] },
    { id: MENU.EXPLAIN, parentId: MENU.ROOT, title: msg('nerdMenuExplain'), contexts: EXPLAIN_CONTEXTS },
    { id: MENU.TEST, parentId: MENU.ROOT, title: msg('nerdMenuTestFilter'), contexts: ['selection'] },
    { id: MENU.BLAME, parentId: MENU.ROOT, title: msg('nerdMenuBlameFilter'), contexts: ['selection'] },
    { id: MENU.BISECT, parentId: MENU.ROOT, title: msg('nerdMenuBisect'), contexts: ['page'] },
    // Own top-level entry: the toolbar menu is already Bastion's.
    { id: MENU.LAB, title: msg('nerdMenuOpenLab'), contexts: ['action'] },
  ];
}

/** The parts of chrome.contextMenus.OnClickData and chrome.tabs.Tab used here. */
export interface ClickInfo {
  menuItemId: string | number;
  linkUrl?: string;
  srcUrl?: string;
  frameUrl?: string;
  pageUrl?: string;
  mediaType?: string;
  selectionText?: string;
}
export interface ClickTab {
  id?: number;
  index?: number;
  windowId?: number;
  url?: string;
}

/** DNR resource type the clicked element would load as. */
function typeOfClick(info: ClickInfo): string | null {
  if (info.linkUrl) return 'main_frame';
  if (info.srcUrl) return info.mediaType === 'image' ? 'image' : info.mediaType === 'video' || info.mediaType === 'audio' ? 'media' : null;
  if (info.frameUrl) return 'sub_frame';
  return null;
}

/**
 * Dashboard hash for a click, or null when the click carries nothing usable
 * (no http(s) URL, empty selection, other menu item).
 *   explain → #lab?url=<url>&site=<tab host>[&type=<dnr type>]
 *   test    → #lab?filter=<selection>
 *   blame   → #lab/blame?filter=<selection>
 *   lab     → #lab
 */
export function labHash(info: ClickInfo, tab: ClickTab | undefined): string | null {
  switch (info.menuItemId) {
    case MENU.EXPLAIN: {
      const url = (info.linkUrl || info.srcUrl || info.frameUrl || '').trim();
      if (!/^https?:\/\//i.test(url) || url.length > MAX_URL) return null;
      const q = new URLSearchParams({ url });
      const site = webHostOf(tab?.url ?? info.pageUrl);
      if (site) q.set('site', site);
      const type = typeOfClick(info);
      if (type) q.set('type', type);
      return `#lab?${q.toString()}`;
    }
    case MENU.TEST:
    case MENU.BLAME: {
      const filter = (info.selectionText ?? '').trim().slice(0, MAX_SELECTION);
      if (!filter) return null;
      const q = new URLSearchParams({ filter });
      return `${info.menuItemId === MENU.BLAME ? '#lab/blame' : '#lab'}?${q.toString()}`;
    }
    case MENU.LAB:
      return '#lab';
    default:
      return null;
  }
}

export interface MenusApi {
  removeAll(): Promise<void>;
  create(spec: MenuSpec): Promise<void>;
}

export interface NerdMenuDeps {
  menus: MenusApi;
  msg(key: string): string;
  /** Absolute dashboard URL (chrome.runtime.getURL('ui/dashboard.html')). */
  dashboardUrl: string;
  /** Open a tab next to `tab` (or a plain new tab). */
  openTab(url: string, tab: ClickTab | undefined): Promise<void>;
  bisect(msg: MsgNerdBisect): Promise<unknown>;
  /** Show the popup after the bisect started (best effort). */
  openPopup(): Promise<void>;
  nerdOn(): boolean;
}

export class NerdMenus {
  private readonly deps: NerdMenuDeps;
  /** Last state applied; null = unknown (fresh worker): the next sync rebuilds. */
  private shown: boolean | null = null;
  private chain: Promise<void> = Promise.resolve();

  constructor(deps: NerdMenuDeps) {
    this.deps = deps;
  }

  /** Show or hide the menus. Cheap when nothing changed; `force` rebuilds (install, startup). */
  sync(enabled: boolean, force = false): Promise<void> {
    if (!force && this.shown === enabled) return this.chain;
    this.shown = enabled;
    this.chain = this.chain.then(async () => {
      try {
        await this.deps.menus.removeAll();
        if (enabled) for (const spec of menuSpecs(this.deps.msg)) await this.deps.menus.create(spec);
      } catch (e) {
        log.warn('menus', e);
        this.shown = null; // retry on the next sync
      }
    });
    return this.chain;
  }

  async onClicked(info: ClickInfo, tab: ClickTab | undefined): Promise<void> {
    // A click can race the menus being removed.
    if (!this.deps.nerdOn()) return;
    if (info.menuItemId === MENU.BISECT) {
      if (typeof tab?.id !== 'number' || tab.id < 0) return;
      await this.deps.bisect({ type: 'nerd:bisect', action: 'start', tabId: tab.id });
      await this.deps.openPopup();
      return;
    }
    const hash = labHash(info, tab);
    if (hash !== null) await this.deps.openTab(`${this.deps.dashboardUrl}${hash}`, tab);
  }
}

/** NerdMenuDeps.menus over chrome.contextMenus (create reports errors through lastError). */
export function chromeMenus(): MenusApi {
  return {
    removeAll: () => chrome.contextMenus.removeAll(),
    create: (spec) =>
      new Promise<void>((resolve, reject) => {
        chrome.contextMenus.create(spec as chrome.contextMenus.CreateProperties, () => {
          const err = chrome.runtime.lastError;
          if (err) reject(new Error(err.message));
          else resolve();
        });
      }),
  };
}
