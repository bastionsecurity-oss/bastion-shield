// Tests for «Website-Ausnahmen» and «Einstellungen» logic
// (src/ui/dashboard/sites-core.ts, settings-core.ts): limits shared with the
// service worker, host errors that name the fix, import counting, search,
// row summaries, backup summary and protected domains with line numbers.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { checkHost, MAX_HOST, MAX_SITES, nearLimit, parseSitesImport, searchHosts, summaryParts } from '../../src/ui/dashboard/sites-core.ts';
import { backupSummary, defaultSettings, MAX_PROTECTED_DOMAINS, parseProtectedDomains, validateBackup } from '../../src/ui/dashboard/settings-core.ts';

test('limits match the service worker', () => {
  const sites = readFileSync(new URL('../../src/background/sites.ts', import.meta.url), 'utf8');
  assert.match(sites, new RegExp(`MAX_SITES = ${MAX_SITES.toLocaleString('en').replace(/,/g, '_')}`));
  assert.equal(MAX_SITES, 10_000);
  assert.equal(MAX_HOST, 253);
  const settings = readFileSync(new URL('../../src/background/settings.ts', import.meta.url), 'utf8');
  assert.match(settings, new RegExp(`MAX_PROTECTED_DOMAINS = ${MAX_PROTECTED_DOMAINS}`));
});

test('counters appear from 80 % of a limit', () => {
  assert.equal(nearLimit(7_999, MAX_SITES), false);
  assert.equal(nearLimit(8_000, MAX_SITES), true);
  assert.equal(nearLimit(202, MAX_HOST), false);
  assert.equal(nearLimit(203, MAX_HOST), true);
});

test('host check normalises and names what is wrong', () => {
  assert.deepEqual(checkHost(' https://www.Beispiel.ch/seite?x=1 '), { ok: true, host: 'beispiel.ch' });
  assert.deepEqual(checkHost('localhost'), { ok: true, host: 'localhost' });
  assert.deepEqual(checkHost(''), { ok: false, problem: 'empty' });
  assert.deepEqual(checkHost('https://bank-login'), { ok: false, problem: 'tld' });
  assert.deepEqual(checkHost('meine bank.ch'), { ok: false, problem: 'chars' });
  assert.deepEqual(checkHost('ftp://example.com'), { ok: false, problem: 'scheme' });
  assert.deepEqual(checkHost(`${'a'.repeat(60)}.${'b'.repeat(60)}.${'c'.repeat(60)}.${'d'.repeat(60)}.${'e'.repeat(60)}.ch`), { ok: false, problem: 'long' });
});

test('import: JSON map, backup, host list; invalid lines are counted', () => {
  const list = parseSitesImport('# my sites\n20min.ch\nnot a host\nhttps://www.nzz.ch/x\n');
  assert.deepEqual(list, { sites: { '20min.ch': { enabled: false }, 'nzz.ch': { enabled: false } }, invalid: 1 });
  const json = parseSitesImport(JSON.stringify({ format: 'bastion-shield-sites', sites: { 'srf.ch': { mode: 'aggressive', bogus: 1 }, 'bad host': {} } }));
  assert.deepEqual(json, { sites: { 'srf.ch': { mode: 'aggressive' } }, invalid: 1 });
  assert.equal(parseSitesImport('[]'), null);
  assert.equal(parseSitesImport('not a host'), null);
});

test('search finds parts of names and subdomains, ignores scheme and www', () => {
  const hosts = ['bank-now.ch', 'e-banking.zkb.ch', 'nzz.ch'];
  assert.deepEqual(searchHosts(hosts, 'bank'), ['bank-now.ch', 'e-banking.zkb.ch']);
  assert.deepEqual(searchHosts(hosts, 'https://www.nzz.ch/'), ['nzz.ch']);
  assert.deepEqual(searchHosts(hosts, ''), hosts);
});

test('row summary of the expanded popup', () => {
  assert.deepEqual(summaryParts({}, 'standard'), [{ key: 'mode', mode: 'standard' }]);
  assert.deepEqual(summaryParts({ enabled: false }, 'standard'), [{ key: 'off' }]);
  assert.deepEqual(summaryParts({ enabled: false, mode: 'aggressive' }, 'standard'), [{ key: 'mode', mode: 'aggressive' }, { key: 'off' }]);
  assert.deepEqual(summaryParts({ blockScripts: true, fingerprinting: 'strict' }, 'aggressive'), [{ key: 'mode', mode: 'aggressive' }, { key: 'scripts' }, { key: 'fp', level: 'strict' }]);
});

test('backup: validation and the summary of the restore dialog', () => {
  assert.equal(validateBackup({ format: 'x' }), null);
  const b = validateBackup({ format: 'bastion-shield-backup', version: 1, exportedAt: '2026-10-14T08:00:00Z', settings: defaultSettings(), sites: { 'a.ch': {}, 'b.ch': {} }, customFilters: '! title\n||ads.example^\n\nexample.com##.x\n# comment' });
  assert.ok(b);
  assert.deepEqual(backupSummary(b), { created: Date.parse('2026-10-14T08:00:00Z'), sites: 2, filters: 2 });
  assert.equal(backupSummary({ ...b, exportedAt: '' }).created, null);
});

test('protected domains keep the line of each entry left out', () => {
  const r = parseProtectedDomains('postfinance.ch\nubs.com, raiffeisen.ch\nmeine bank\nzkb.ch\nzkb.ch\n#note');
  assert.deepEqual(r.domains, ['postfinance.ch', 'ubs.com', 'raiffeisen.ch', 'zkb.ch']);
  assert.deepEqual(r.invalid, [{ text: 'meine bank', line: 3 }]);
});

test('strings of the rule and system views: no middle dot, single ellipsis', () => {
  for (const lang of ['de', 'en', 'fr', 'it']) {
    const m = JSON.parse(readFileSync(new URL(`../../src/_locales/${lang}/messages.json`, import.meta.url), 'utf8')) as Record<string, { message: string }>;
    for (const [k, v] of Object.entries(m)) {
      if (!/^(cf|sites|set|priv|about|nerdSettings|nerdLabOff|nerdLabOpen)/.test(k)) continue;
      assert.ok(!v.message.includes('·'), `${lang}: ${k} has a middle dot`);
      assert.ok(!v.message.includes('...'), `${lang}: ${k} has three dots`);
    }
  }
});
