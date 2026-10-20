// Bastion Shield bench — independent ad/tracker reference set used to judge
// what "got through". It is the hostname part of EasyList's adservers and
// EasyPrivacy's trackingservers sections (plain `||host^` filters), i.e. the
// domains both Brave and we are expected to block as third parties. It is
// deliberately not derived from our own DNR output.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const SOURCES = {
  easylist: 'https://easylist.to/easylist/easylist.txt',
  easyprivacy: 'https://easylist.to/easylist/easyprivacy.txt',
};

// Sections of the combined lists whose `||host^` entries are pure ad/tracking hosts.
const SECTION_RE = /^! \*\*\* easylist:(easylist\/easylist_adservers\.txt|easylist_adult\/adult_adservers\.txt|easyprivacy\/easyprivacy_trackingservers[a-z_]*\.txt) \*\*\*/;

export interface ReferenceSet {
  hosts: Set<string>;
  sources: { name: string; file: string; title: string; version: string; hosts: number }[];
  /** True when hostname or one of its parents is a reference ad/tracker host. */
  matches(hostname: string): boolean;
}

function header(text: string, key: string): string {
  const m = new RegExp(`^! ${key}: *(.+)$`, 'm').exec(text.slice(0, 4000));
  return m ? m[1].trim() : '';
}

function findCached(dirs: string[], title: RegExp): string | null {
  for (const dir of dirs) {
    if (!dir || !existsSync(dir)) continue;
    let files: string[] = [];
    try {
      files = readdirSync(dir).filter((f) => f.endsWith('.txt'));
    } catch {
      continue;
    }
    // Newest first, so a refreshed cache wins.
    files.sort((a, b) => statSync(path.join(dir, b)).mtimeMs - statSync(path.join(dir, a)).mtimeMs);
    for (const f of files) {
      const full = path.join(dir, f);
      try {
        const head = readFileSync(full, 'utf8').slice(0, 3000);
        if (title.test(header(head, 'Title')) && head.includes('! *** easylist:')) return full;
      } catch {
        /* unreadable */
      }
    }
  }
  return null;
}

async function obtain(name: 'easylist' | 'easyprivacy', dirs: string[], downloadDir: string, log: (s: string) => void): Promise<string> {
  const title = name === 'easylist' ? /^EasyList$/ : /^EasyPrivacy$/;
  const cached = findCached(dirs, title);
  if (cached) return cached;
  // Last resort: fetch the public list once (developer tool, not the extension).
  mkdirSync(downloadDir, { recursive: true });
  const file = path.join(downloadDir, `${name}.txt`);
  if (existsSync(file) && Date.now() - statSync(file).mtimeMs < 7 * 24 * 3600_000) return file;
  log(`reference: downloading ${SOURCES[name]}`);
  const res = await fetch(SOURCES[name]);
  if (!res.ok) throw new Error(`download ${SOURCES[name]}: HTTP ${res.status}`);
  writeFileSync(file, await res.text());
  return file;
}

export function parseReferenceHosts(text: string): Set<string> {
  const hosts = new Set<string>();
  let inSection = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith('! *** ')) {
      inSection = SECTION_RE.test(line);
      continue;
    }
    if (!inSection || !line.startsWith('||')) continue;
    const m = /^\|\|([a-z0-9.-]+)\^(?:\$(.*))?$/i.exec(line);
    if (!m) continue;
    const opts = m[2] ?? '';
    // Site-restricted entries ($domain=) are not "this host is an ad server".
    if (/(^|,)(domain|from|denyallow|to)=/.test(opts) || /(^|,)(popup|document|~third-party|first-party|1p)(,|$)/.test(opts)) continue;
    hosts.add(m[1].toLowerCase());
  }
  return hosts;
}

export async function loadReferenceSet(opts: { dirs: string[]; downloadDir: string; log: (s: string) => void }): Promise<ReferenceSet> {
  const hosts = new Set<string>();
  const sources: ReferenceSet['sources'] = [];
  for (const name of ['easylist', 'easyprivacy'] as const) {
    const file = await obtain(name, opts.dirs, opts.downloadDir, opts.log);
    const text = readFileSync(file, 'utf8');
    const set = parseReferenceHosts(text);
    for (const h of set) hosts.add(h);
    sources.push({ name, file, title: header(text, 'Title'), version: header(text, 'Version') || header(text, 'Last modified'), hosts: set.size });
  }
  const matches = (hostname: string) => {
    const labels = hostname.toLowerCase().replace(/\.$/, '').split('.');
    for (let i = 0; i < labels.length - 1; i++) if (hosts.has(labels.slice(i).join('.'))) return true;
    return false;
  };
  return { hosts, sources, matches };
}
