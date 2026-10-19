// Bastion Shield service worker — nerd mode keyboard shortcuts (manifest
// "commands", docs/NERD-MODE.md). `nerd-bisect` (no default key; set in
// Settings › Nerd mode)
// starts the filter bisect on the active tab and opens the popup, where it
// asks its questions, or ends the one shown there.
// It does nothing while nerd mode is off or the activity log (which lists the
// candidates) is off. `_execute_action` opens the popup and is handled by the
// browser itself.
//
// The listener is added synchronously from index.ts so Chrome can wake the
// worker for it; the work waits for the worker's `ready` promise.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BisectView, MsgNerdBisect } from '../shared/types.ts';
import * as log from './log.ts';

export const NERD_BISECT_COMMAND = 'nerd-bisect';

export interface NerdCommandDeps {
  /** Resolves once the worker is initialised. */
  ready: Promise<unknown>;
  /** nerd:bisect handler (NerdService.bisect). */
  bisect(msg: MsgNerdBisect): Promise<unknown>;
  /** Nerd mode and the activity log are on. */
  canBisect(): boolean;
  /** The worker is initialised, so canBisect() reads the real settings. */
  isReady(): boolean;
  /** Fallback when the command event carries no tab. */
  activeTabId(): Promise<number | null>;
  /**
   * Show the popup, where the bisect asks its questions. Called synchronously from
   * the command event when possible: after the awaits of a start the key press no
   * longer counts as a user action and the browser may refuse to open it.
   */
  openPopup(): Promise<void>;
}

export type NerdCommandResult = 'started' | 'cancelled' | 'ignored';

const viewOf = (r: unknown): BisectView | null => {
  const v = r && typeof r === 'object' && 'bisect' in r ? (r as { bisect: unknown }).bisect : null;
  return v && typeof v === 'object' ? (v as BisectView) : null;
};

/** Toggle: a bisect shown on the tab (testing or a result) is ended, otherwise one starts. */
export async function runNerdCommand(command: string, tabId: number | null | undefined, deps: NerdCommandDeps, popupOpened = false): Promise<NerdCommandResult> {
  if (command !== NERD_BISECT_COMMAND || !deps.canBisect()) return 'ignored';
  const id = typeof tabId === 'number' && tabId >= 0 ? tabId : await deps.activeTabId();
  if (id === null || id < 0) return 'ignored';
  const current = viewOf(await deps.bisect({ type: 'nerd:bisect', action: 'state', tabId: id }));
  if (current && current.phase !== 'cancelled') {
    await deps.bisect({ type: 'nerd:bisect', action: 'cancel', tabId: id });
    return 'cancelled';
  }
  await deps.bisect({ type: 'nerd:bisect', action: 'start', tabId: id });
  if (!popupOpened) await deps.openPopup();
  return 'started';
}

export function registerNerdCommands(deps: NerdCommandDeps): void {
  try {
    chrome.commands?.onCommand.addListener((command, tab) => {
      // Open the popup now, while the key press still counts as a user action; it picks
      // the bisect up once started. A cold worker cannot tell yet and opens it afterwards.
      const eager = command === NERD_BISECT_COMMAND && deps.isReady() && deps.canBisect();
      if (eager) void deps.openPopup();
      void deps.ready
        .then(() => runNerdCommand(command, tab?.id, deps, eager))
        .catch((e: unknown) => log.warn('commands', command, e));
    });
  } catch (e) {
    log.warn('commands', 'unavailable', e);
  }
}
