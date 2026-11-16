// Bastion Shield — guard against remotely hosted code (Chrome Web Store,
// "Additional Requirements for Manifest V3", violation "Blue Argon").
//
// Some vendored resources are rewritten copies of third-party scripts (Brave
// "sugarcoat": Google analytics.js, Bing bat.js) or evaluate code fetched at
// run time (Twitch worker hooks). Shipping them gets the item rejected, so
// they are never packaged: tools/resources.ts skips such Brave resources and
// tools/build.ts fails when a shipped script still contains one of these
// constructs.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { readFile } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { walkFiles } from './util.ts';

const PATTERNS: readonly [RegExp, string][] = [
  [/createElement\(\s*(['"`])script\1\s*\)/, 'creates a <script> element'],
  [/document\.write(?:ln)?\(/, 'calls document.write()'],
  [/(?<![\w$.])eval\(/, 'calls eval()'],
  [/new\s+Function\(/, 'calls new Function()'],
  [/(?<![\w$.])importScripts\(/, 'calls importScripts()'],
  [/(?<![\w$.])import\(/, 'uses dynamic import()'],
];

/** Why `code` can load or evaluate code that is not in the package, or null. */
export function remoteCodeReason(code: string): string | null {
  for (const [re, reason] of PATTERNS) if (re.test(code)) return reason;
  return null;
}

/**
 * Scripts in `distDir` that can load or evaluate foreign code. The per-list
 * scriptlet data files are skipped: they hold filter-list arguments (strings
 * such as "document.createElement('script')" used as match needles), no code.
 */
export async function findRemoteCode(distDir: string): Promise<{ file: string; reason: string }[]> {
  const out: { file: string; reason: string }[] = [];
  for (const abs of await walkFiles(distDir)) {
    const file = relative(distDir, abs).split(sep).join('/');
    if (!/\.(?:js|mjs|html)$/.test(file)) continue;
    if (file.startsWith('scriptlets/') && !/^scriptlets\/scriptlet-(?:core|end)-/.test(file)) continue;
    const reason = remoteCodeReason(await readFile(join(distDir, file), 'utf8'));
    if (reason !== null) out.push({ file, reason });
  }
  return out.sort((a, b) => (a.file < b.file ? -1 : 1));
}
