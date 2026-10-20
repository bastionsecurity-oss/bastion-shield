// Bastion Shield — nerd mode «blame»: where to read the history of a filter
// line upstream. No API calls: we only build links. Lists that live in one
// GitHub file get a blame link with a text fragment (#:~:text=) that scrolls
// to the line; lists assembled from many files (EasyList) get a code search
// in the source repository.
//
// SPDX-License-Identifier: GPL-3.0-or-later

export interface BlameLink {
  /** 'blame': GitHub blame view of the file; 'search': GitHub code search in the repository. */
  kind: 'blame' | 'search';
  /** owner/repo */
  repo: string;
  /** Path in the repository (blame links only). */
  path?: string;
  url: string;
}

/** Hosted copies whose GitHub file is known: [URL prefix, owner/repo, branch, path prefix]. */
const FILE_HOSTS: readonly [string, string, string, string][] = [
  ['https://ublockorigin.github.io/uAssets/', 'uBlockOrigin/uAssets', 'master', ''],
  ['https://raw.githubusercontent.com/brave/adblock-lists/master/', 'brave/adblock-lists', 'master', ''],
  ['https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/', 'uBlockOrigin/uAssets', 'master', ''],
];

/** Lists built from many files: [URL prefix, owner/repo]. */
const SEARCH_HOSTS: readonly [string, string][] = [
  ['https://easylist.to/easylistgermany/', 'easylist/easylistgermany'],
  ['https://easylist.to/easylist/', 'easylist/easylist'],
  ['https://secure.fanboy.co.nz/', 'easylist/easylist'],
  ['https://easylist-downloads.adblockplus.org/easylistitaly', 'easylist/easylistitaly'],
];

/**
 * The part of a filter that is most likely to appear verbatim in the source.
 * Merged rules carry a "+N more" marker, after a filter or as an entry of its
 * own in the transparency map; a bare marker is no filter (empty needle).
 */
export function blameNeedle(filter: string): string {
  return filter.trim().replace(/(?:^|\s+)\+\d+ more$/, '');
}

/** Upstream history link for `filter` from the list source `sourceUrl`, or null when the source is not on GitHub. */
export function blameLink(sourceUrl: string, filter: string): BlameLink | null {
  const needle = blameNeedle(filter);
  if (needle === '') return null;
  for (const [prefix, repo, branch, base] of FILE_HOSTS) {
    if (!sourceUrl.startsWith(prefix)) continue;
    const path = base + sourceUrl.slice(prefix.length).replace(/[?#].*$/, '');
    if (path === '') return null;
    // Text fragments match whole words; a very long filter is cut to keep the URL sane.
    const text = encodeURIComponent(needle.slice(0, 200)).replace(/-/g, '%2D');
    return { kind: 'blame', repo, path, url: `https://github.com/${repo}/blame/${branch}/${path}#:~:text=${text}` };
  }
  for (const [prefix, repo] of SEARCH_HOSTS) {
    if (!sourceUrl.startsWith(prefix)) continue;
    const q = encodeURIComponent(`repo:${repo} "${needle.slice(0, 120)}"`);
    return { kind: 'search', repo, url: `https://github.com/search?q=${q}&type=code` };
  }
  return null;
}

/** Links for every GitHub-backed source of a list (deduplicated by URL). */
export function blameLinks(sourceUrls: readonly string[], filter: string): BlameLink[] {
  const out = new Map<string, BlameLink>();
  for (const u of sourceUrls) {
    const l = blameLink(u, filter);
    if (l && !out.has(l.url)) out.set(l.url, l);
  }
  return Array.from(out.values());
}
