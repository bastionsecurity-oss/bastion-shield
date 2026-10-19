// Bastion Shield — title of an imported filter list, shared by the service
// worker (stores it) and the dashboard (asks "replace or add?" before an
// upload whose title is already taken).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { MY_LISTS } from './constants.ts';

/** `! Title:` (ABP/uBO) or `# Title:` (hosts files) from the list header. */
export function parseListTitle(text: string): string | null {
  const lines = text.slice(0, 8192).split(/\r?\n/, 60);
  for (const line of lines) {
    const m = /^\s*[!#]\s*Title\s*:\s*(.+?)\s*$/i.exec(line);
    if (m && m[1]) return m[1].slice(0, MY_LISTS.MAX_TITLE_LENGTH);
  }
  return null;
}

/** Title for a new list: its header, else the file name without extension, else the fallback as is. */
export function listTitle(text: string, fallback: string): string {
  const header = parseListTitle(text);
  if (header) return header;
  const base = fallback.replace(/^.*[\\/]/, '').replace(/\.(txt|list|hosts|conf)$/i, '').trim();
  return (base || fallback || 'List').slice(0, MY_LISTS.MAX_TITLE_LENGTH);
}
