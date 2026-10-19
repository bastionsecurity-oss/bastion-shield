// Bastion Shield — extension shortcuts as the user's keyboard labels them.
// chrome.commands reports keys by physical position in US layout, so on a
// Swiss or German keyboard "Alt+Shift+Z" is the key printed Y. The Keyboard
// API's layout map names the printed key; without it the browser's label stays.
//
// SPDX-License-Identifier: GPL-3.0-or-later

/** The part of navigator.keyboard used here (not in the DOM typings). */
interface LayoutMap {
  get(code: string): string | undefined;
}

/** KeyboardEvent.code of a US-layout key name, for the keys that move between layouts. */
function codeOf(key: string): string | null {
  if (/^[A-Z]$/.test(key)) return `Key${key}`;
  if (/^[0-9]$/.test(key)) return `Digit${key}`;
  return null;
}

/** "Alt+Shift+Z" with a Swiss layout map -> "Alt+Shift+Y". Unknown keys pass through. */
export function localizeShortcut(shortcut: string, layout: LayoutMap | null): string {
  if (!layout || !shortcut) return shortcut;
  const parts = shortcut.split('+');
  const key = parts[parts.length - 1] ?? '';
  const code = codeOf(key);
  const printed = code ? layout.get(code) : undefined;
  if (!printed || printed.length !== 1) return shortcut;
  parts[parts.length - 1] = printed.toUpperCase();
  return parts.join('+');
}

let layoutPromise: Promise<LayoutMap | null> | null = null;

/** The keyboard layout map, or null where the Keyboard API is missing or refused. */
export function keyboardLayout(): Promise<LayoutMap | null> {
  layoutPromise ??= (async () => {
    try {
      const kb = (navigator as Navigator & { keyboard?: { getLayoutMap?: () => Promise<LayoutMap> } }).keyboard;
      return (await kb?.getLayoutMap?.()) ?? null;
    } catch {
      return null;
    }
  })();
  return layoutPromise;
}
