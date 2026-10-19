// Bastion Shield — command palette (Ctrl+K) matching: normalisation, scoring
// and ranking. DOM-free so it can be unit tested; palette.ts draws the dialog.
//
// SPDX-License-Identifier: GPL-3.0-or-later

export type PaletteGroup = 'views' | 'settings' | 'lists' | 'actions';

export interface PaletteEntry {
  id: string;
  group: PaletteGroup;
  /** What the row shows and what matching runs against first. */
  label: string;
  /** Second line / right-hand context (e.g. the section a setting lives in). */
  hint?: string;
  /** Extra words that should find the entry (not shown). */
  keywords?: string;
  /** Only shown when the query matches (easter eggs, rare actions). */
  hidden?: boolean;
  /** Keyboard shortcut shown on the row. */
  shortcut?: string;
}

export interface PaletteHit {
  entry: PaletteEntry;
  score: number;
  /** [start, end) ranges in entry.label to highlight. */
  ranges: [number, number][];
}

/** Lower-case, without diacritics (ü → u, é → e), so «Datenschutz» and «datenschütz» meet. */
export function fold(s: string): string {
  return s.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
}

/**
 * Score `query` against `text`: a substring at a word start beats a substring
 * anywhere, which beats the letters in order (subsequence). Null when it does
 * not match. Ranges index into `text` (NFD folding never changes the length of
 * the Latin text the UI uses, but ranges are clamped anyway).
 */
export function matchText(query: string, text: string): { score: number; ranges: [number, number][] } | null {
  const q = fold(query.trim());
  if (!q) return { score: 0, ranges: [] };
  const f = fold(text);
  const at = f.indexOf(q);
  if (at !== -1) {
    const wordStart = at === 0 || /[\s\-–(/«»'".,:]/.test(f[at - 1]);
    const score = (at === 0 ? 1000 : wordStart ? 800 : 600) - Math.min(at, 100) - Math.min(f.length, 200) / 10;
    return { score, ranges: [[Math.min(at, text.length), Math.min(at + q.length, text.length)]] };
  }
  // Subsequence: every query letter in order; tighter runs score higher.
  const ranges: [number, number][] = [];
  let i = 0;
  let gaps = 0;
  let last = -1;
  for (const ch of q) {
    if (ch === ' ') continue;
    const j = f.indexOf(ch, i);
    if (j === -1) return null;
    if (last !== -1 && j !== last + 1) gaps += j - last - 1;
    const prev = ranges[ranges.length - 1];
    if (prev && prev[1] === j) prev[1] = j + 1;
    else ranges.push([j, j + 1]);
    last = j;
    i = j + 1;
  }
  if (ranges.length > Math.max(3, Math.ceil(q.length / 2))) return null; // scattered letters: noise
  return { score: 300 - gaps * 4 - ranges.length * 10, ranges };
}

const GROUP_ORDER: Record<PaletteGroup, number> = { views: 0, actions: 1, settings: 2, lists: 3 };

/**
 * Rank entries for a query. An empty query lists the visible entries in
 * their given order (views first); otherwise the best matches across label,
 * hint and keywords, best first, at most `limit`.
 */
export function rankEntries(entries: readonly PaletteEntry[], query: string, limit = 40): PaletteHit[] {
  const q = query.trim();
  if (!q) {
    return entries
      .filter((e) => !e.hidden && (e.group === 'views' || e.group === 'actions'))
      .sort((a, b) => GROUP_ORDER[a.group] - GROUP_ORDER[b.group])
      .slice(0, limit)
      .map((entry) => ({ entry, score: 0, ranges: [] }));
  }
  const hits: PaletteHit[] = [];
  for (const entry of entries) {
    const onLabel = matchText(q, entry.label);
    // Hint and keywords count, a little less than the label; they never highlight.
    const onOther = [entry.hint, entry.keywords]
      .filter((x): x is string => !!x)
      .map((x) => matchText(q, x))
      .filter((m): m is NonNullable<typeof m> => m !== null && m.score >= 600)
      .reduce<number | null>((best, m) => (best === null || m.score > best ? m.score : best), null);
    if (!onLabel && onOther === null) continue;
    // Hidden entries need a real substring match, not a few scattered letters.
    if (entry.hidden && !(onLabel && onLabel.score >= 600) && onOther === null) continue;
    const score = Math.max(onLabel?.score ?? -Infinity, onOther === null ? -Infinity : onOther - 250) - GROUP_ORDER[entry.group] * 5;
    hits.push({ entry, score, ranges: onLabel?.ranges ?? [] });
  }
  hits.sort((a, b) => b.score - a.score || GROUP_ORDER[a.entry.group] - GROUP_ORDER[b.entry.group]);
  return hits.slice(0, limit);
}
