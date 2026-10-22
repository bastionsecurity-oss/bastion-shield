// Guards for the four UI locales (AGENTS.md «Copy»): every locale has the
// same keys, every key the code names statically exists, placeholders
// resolve, and UI strings never use the middle dot «·» as a separator or
// three dots instead of «…».
//
// Static references: t('key'), plural(n, 'one', 'other'), data-i18n*="key"
// and __MSG_key__ in src/. Keys built at run time are covered by the e2e
// specs, which fail on raw keys left in the rendered page.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC = fileURLToPath(new URL('../../src', import.meta.url));
const LOCALES = ['de', 'en', 'fr', 'it'] as const;

interface Entry {
  message: string;
  placeholders?: Record<string, { content: string }>;
}
const bundles = Object.fromEntries(
  LOCALES.map((l) => [l, JSON.parse(readFileSync(join(SRC, '_locales', l, 'messages.json'), 'utf8')) as Record<string, Entry>]),
) as Record<(typeof LOCALES)[number], Record<string, Entry>>;

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name !== '_locales' && name !== 'fonts') walk(p, out);
    } else if (/\.(ts|html|json)$/.test(name)) out.push(p);
  }
  return out;
}

/** Keys the source names literally, with one file where each is used. */
function referencedKeys(): Map<string, string> {
  const keys = new Map<string, string>();
  const patterns = [
    /\bt\(\s*'([A-Za-z0-9_]+)'/g,
    /\bt\(\s*"([A-Za-z0-9_]+)"/g,
    /\bplural\([^,()]+,\s*'([A-Za-z0-9_]+)',\s*'([A-Za-z0-9_]+)'/g,
    /data-i18n[a-z-]*="([A-Za-z0-9_]+)"/g,
    /__MSG_([A-Za-z0-9_]+)__/g,
  ];
  for (const file of walk(SRC)) {
    const text = readFileSync(file, 'utf8');
    for (const re of patterns) {
      for (const m of text.matchAll(re)) {
        for (const k of m.slice(1)) if (k && !keys.has(k)) keys.set(k, file.slice(SRC.length + 1));
      }
    }
  }
  return keys;
}

test('all four locales define the same keys', () => {
  const de = new Set(Object.keys(bundles.de));
  for (const l of LOCALES) {
    const keys = new Set(Object.keys(bundles[l]));
    const missing = [...de].filter((k) => !keys.has(k));
    const extra = [...keys].filter((k) => !de.has(k));
    assert.deepEqual(missing, [], `${l} lacks keys that de has`);
    assert.deepEqual(extra, [], `${l} has keys that de lacks`);
  }
});

test('every message is a non-empty string and its placeholders resolve', () => {
  for (const l of LOCALES) {
    for (const [k, v] of Object.entries(bundles[l])) {
      assert.equal(typeof v.message, 'string', `${l}/${k}`);
      assert.notEqual(v.message.trim(), '', `${l}/${k} is empty`);
      for (const m of v.message.matchAll(/\$([A-Za-z0-9_@]+)\$/g)) {
        const name = m[1].toLowerCase();
        assert.ok(v.placeholders && (name in v.placeholders || m[1] in v.placeholders), `${l}/${k}: placeholder $${m[1]}$ undefined`);
      }
    }
  }
});

test('every key the source names exists in all four locales', () => {
  const missing: string[] = [];
  for (const [k, file] of referencedKeys()) {
    for (const l of LOCALES) if (!(k in bundles[l])) missing.push(`${l}/${k} (${file})`);
  }
  assert.deepEqual(missing, []);
});

test('UI strings never use «·» as a separator or three dots for «…»', () => {
  const bad: string[] = [];
  for (const l of LOCALES) {
    for (const [k, v] of Object.entries(bundles[l])) {
      if (v.message.includes('·')) bad.push(`${l}/${k}: middle dot`);
      if (v.message.includes('...')) bad.push(`${l}/${k}: three dots`);
    }
  }
  assert.deepEqual(bad, []);
});

test('UI source has no «·» separators in visible text', () => {
  const bad: string[] = [];
  for (const file of walk(SRC)) {
    if (!/[\\/](ui|pages|content)[\\/]/.test(file)) continue;
    const lines = readFileSync(file, 'utf8').split('\n');
    lines.forEach((line, i) => {
      const code = line.replace(/\/\/.*$/, '').replace(/^\s*\*.*$/, '').replace(/<!--.*?-->/g, '');
      if (code.includes('·')) bad.push(`${file.slice(SRC.length + 1)}:${i + 1}`);
    });
  }
  assert.deepEqual(bad, []);
});

test('in-page notice fallbacks exist in the locales', () => {
  const text = readFileSync(join(SRC, 'content', 'notice.ts'), 'utf8');
  const block = /const FALLBACK[^{]*\{([\s\S]*?)\n\};/.exec(text);
  assert.ok(block, 'FALLBACK map not found in content/notice.ts');
  const keys = [...block[1].matchAll(/^\s*([A-Za-z0-9_]+):/gm)].map((m) => m[1]);
  assert.ok(keys.length > 0);
  for (const k of keys) for (const l of LOCALES) assert.ok(k in bundles[l], `${l}/${k}`);
});
