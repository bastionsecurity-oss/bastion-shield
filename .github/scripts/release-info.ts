// Release helpers for release.yml: decide whether the weekly run has anything
// new to ship (filter sources changed since the previous release), and write
// the GitHub release notes from the build metadata.
//
//   node .github/scripts/release-info.ts changed --lock filters/lock.json [--prev-lock prev/lock.json]
//   node .github/scripts/release-info.ts notes --meta dist/rulesets/meta.json --lock filters/lock.json
//        [--prev-lock prev/lock.json] [--report dist/build-report.json] --version 1.2.3.4 > notes.md
//
// filters/lock.json is read defensively (any object with "url" and "sha256"
// counts as a source entry) so the helper survives format tweaks in tools/.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import type { BuildMeta } from '../../src/shared/types.ts';

interface SourceLock {
  url: string;
  sha256: string;
  version?: string;
  lastModified?: string;
}

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

function readJson(path: string | undefined): unknown {
  if (!path || !existsSync(path)) return undefined;
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as unknown;
  } catch (e) {
    console.error(`warning: cannot parse ${path}: ${(e as Error).message}`);
    return undefined;
  }
}

/** Collect every {url, sha256} object anywhere in the lock file. */
function sources(lock: unknown): Map<string, SourceLock> {
  const out = new Map<string, SourceLock>();
  const walk = (v: unknown, keyHint?: string): void => {
    if (Array.isArray(v)) {
      for (const x of v) walk(x);
      return;
    }
    if (!v || typeof v !== 'object') return;
    const o = v as Record<string, unknown>;
    const url = typeof o.url === 'string' && o.url ? o.url : keyHint && /^(https?:|filters\/)/.test(keyHint) ? keyHint : undefined;
    if (url && typeof o.sha256 === 'string') {
      out.set(url, {
        url,
        sha256: o.sha256,
        version: typeof o.version === 'string' ? o.version : undefined,
        lastModified: typeof o.lastModified === 'string' ? o.lastModified : undefined,
      });
      return;
    }
    for (const [k, x] of Object.entries(o)) walk(x, k);
  };
  walk(lock);
  return out;
}

function diff(prev: Map<string, SourceLock>, cur: Map<string, SourceLock>): { added: string[]; removed: string[]; changed: string[] } {
  const added = [...cur.keys()].filter((u) => !prev.has(u));
  const removed = [...prev.keys()].filter((u) => !cur.has(u));
  const changed = [...cur.keys()].filter((u) => prev.has(u) && prev.get(u)!.sha256 !== cur.get(u)!.sha256);
  return { added, removed, changed };
}

function output(name: string, value: string): void {
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
}

function cmdChanged(): void {
  const cur = sources(readJson(arg('--lock')));
  const prevLock = readJson(arg('--prev-lock'));
  if (cur.size === 0) {
    console.error('error: no sources found in the current lock file');
    process.exit(1);
  }
  if (prevLock === undefined) {
    console.log('No previous lock file: treating filter sources as changed.');
    output('lists_changed', 'true');
    return;
  }
  const d = diff(sources(prevLock), cur);
  const n = d.added.length + d.removed.length + d.changed.length;
  console.log(`Filter sources: ${d.changed.length} changed, ${d.added.length} added, ${d.removed.length} removed.`);
  for (const u of [...d.changed, ...d.added, ...d.removed]) console.log(`  ${u}`);
  output('lists_changed', n > 0 ? 'true' : 'false');
}

const fmt = (n: number): string => n.toLocaleString('en-US');

function cmdNotes(): void {
  const version = arg('--version') ?? '?';
  const meta = readJson(arg('--meta')) as BuildMeta | undefined;
  const lock = sources(readJson(arg('--lock')));
  const prevLock = readJson(arg('--prev-lock'));
  const lines: string[] = [];
  lines.push(`Bastion Shield ${version}`, '');
  lines.push('Automated release with the current filter lists. Install from the Chrome Web Store or Microsoft Edge Add-ons; managed devices update on their own.', '');
  if (prevLock !== undefined) {
    const d = diff(sources(prevLock), lock);
    lines.push(`Filter sources since the previous release: ${d.changed.length} updated, ${d.added.length} added, ${d.removed.length} removed.`, '');
  }
  if (meta && Array.isArray(meta.lists)) {
    lines.push('| List | Default | DNR rules | Regex rules | Cosmetic | Scriptlets | Unsupported |', '|---|---|---:|---:|---:|---:|---:|');
    let total = 0;
    let defaults = 0;
    for (const l of meta.lists) {
      const n = (l.ruleCount ?? 0) + (l.regexRuleCount ?? 0);
      total += n;
      if (l.default) defaults += n;
      lines.push(`| ${l.name?.en ?? l.id} (\`${l.id}\`) | ${l.default ? 'on' : 'off'} | ${fmt(l.ruleCount ?? 0)} | ${fmt(l.regexRuleCount ?? 0)} | ${fmt(l.stats?.cosmetic ?? 0)} | ${fmt(l.stats?.scriptlets ?? 0)} | ${fmt(l.stats?.unsupported ?? 0)} |`);
    }
    lines.push('', `Static DNR rules (plain + regex, without the built-in parameter list): ${fmt(defaults)} in the lists enabled by default, ${fmt(total)} with all optional lists. Vendored code: uBlock Origin ${meta.vendor?.ublock?.slice(0, 12) ?? '?'}, Brave resources ${meta.vendor?.braveResources?.slice(0, 12) ?? '?'}, Brave lists ${meta.vendor?.braveLists?.slice(0, 12) ?? '?'}.`, '');
  } else {
    lines.push('(dist/rulesets/meta.json not found: per-list numbers unavailable.)', '');
  }
  lines.push('### Corresponding source', '');
  lines.push('- Extension source: the tagged commit of this release.');
  lines.push('- Filter inputs: `filters/lock.json` (URL, SHA-256, size and version of every fetched list) and `bastion-shield-' + version + '-filter-sources.tar.gz` (the raw list snapshots) are attached below. The compiled rulesets are generated from exactly these files.');
  lines.push('- Checksums of all assets: `SHA256SUMS.txt`.', '');
  lines.push('Filter lists are the work of their authors (EasyList, uBlock Origin/uAssets, Brave, AdGuard, Peter Lowe, malware-filter/abuse.ch and others); see THIRD_PARTY_NOTICES.md. Converted to Chromium DNR format by Bastion Shield.');
  console.log(lines.join('\n'));
}

const cmd = process.argv[2];
if (cmd === 'changed') cmdChanged();
else if (cmd === 'notes') cmdNotes();
else {
  console.error('usage: node .github/scripts/release-info.ts changed|notes [options]');
  process.exit(2);
}
