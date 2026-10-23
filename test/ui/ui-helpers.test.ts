// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Unit tests for the UI pure helpers (bounce decoding, host normalisation,
// site import, backup validation, broken-site report). Run with npm test.
import test from 'node:test';
import assert from 'node:assert/strict';

const ROOT = new URL('../../src', import.meta.url).href;
const { decodeBounceTarget, parseTarget } = await import(`${ROOT}/pages/bounce-decode.ts`);
const { normaliseHost, dayKey } = await import(`${ROOT}/ui/dashboard/common.ts`);
const { parseSitesImport } = await import(`${ROOT}/ui/dashboard/views/sites.ts`);
const { validateBackup, defaultSettings } = await import(`${ROOT}/ui/dashboard/views/settings.ts`);
const { githubUrl, reportText, mailtoUrl } = await import(`${ROOT}/ui/popup/report.ts`);

test('bounce: plain and percent-encoded targets', () => {
  assert.equal(decodeBounceTarget('#https://www.digitec.ch/de/s1/product/123')?.href, 'https://www.digitec.ch/de/s1/product/123');
  assert.equal(decodeBounceTarget('https%3A%2F%2Fwww.digitec.ch%2Fde%3Fa%3D1%26b%3D2')?.href, 'https://www.digitec.ch/de?a=1&b=2');
  // double-encoded
  assert.equal(decodeBounceTarget('https%253A%252F%252Fexample.com%252Fx')?.href, 'https://example.com/x');
  // inner encoding preserved once the outer layer parses
  assert.equal(decodeBounceTarget('https%3A%2F%2Fexample.com%2F%3Fq%3Da%2520b')?.href, 'https://example.com/?q=a%20b');
  // a '#' inside the target is kept
  assert.equal(decodeBounceTarget('https://example.com/page#section')?.href, 'https://example.com/page#section');
});

test('bounce: base64 targets', () => {
  const b64 = Buffer.from('https://shop.example.ch/p?id=7').toString('base64');
  assert.equal(decodeBounceTarget(`b64:${b64}`)?.href, 'https://shop.example.ch/p?id=7');
  const url = Buffer.from('https://shop.example.ch/ü').toString('base64url');
  assert.equal(decodeBounceTarget(`b64:${url}`)?.hostname, 'shop.example.ch');
  // percent-encoded padding
  assert.equal(decodeBounceTarget(`b64:${encodeURIComponent(Buffer.from('http://a.example/').toString('base64'))}`)?.href, 'http://a.example/');
  assert.equal(decodeBounceTarget('b64:!!!'), null);
});

test('bounce: rejects unsafe or invalid input', () => {
  for (const bad of ['', '#', 'javascript:alert(1)', 'javascript%3Aalert(1)', 'data:text/html,hi', 'chrome://settings', 'ftp://x.example/', '//example.com', 'example.com', 'https://user:pass@bank.example/', `b64:${Buffer.from('javascript:alert(1)').toString('base64')}`, 'https://', 'x'.repeat(9000)]) {
    assert.equal(decodeBounceTarget(bad), null, bad.slice(0, 40));
  }
  assert.equal(parseTarget('HTTPS://EXAMPLE.com')?.hostname, 'example.com');
});

test('normaliseHost', () => {
  assert.equal(normaliseHost('www.Example.CH'), 'example.ch');
  assert.equal(normaliseHost('https://www.nzz.ch/zuerich/artikel?x=1'), 'nzz.ch');
  assert.equal(normaliseHost('bücher.ch'), 'xn--bcher-kva.ch');
  assert.equal(normaliseHost('sub.domain.example.com.'), 'sub.domain.example.com');
  assert.equal(normaliseHost('localhost'), 'localhost');
  assert.equal(normaliseHost('192.168.1.10'), '192.168.1.10');
  for (const bad of ['', '   ', 'nodot', 'javascript:alert(1)', 'ftp://x.example', 'a b.ch']) assert.equal(normaliseHost(bad), null, bad);
});

test('parseSitesImport', () => {
  const ours = JSON.stringify({ format: 'bastion-shield-sites', version: 1, sites: { 'www.a.ch': { enabled: false, mode: 'aggressive', bogus: 1 }, 'b.ch': { fingerprinting: 'nope' }, 'not a host': {} } });
  // { sites, invalid }: the import dialog (D04) says how many lines it skips.
  assert.deepEqual(parseSitesImport(ours), { sites: { 'a.ch': { enabled: false, mode: 'aggressive' }, 'b.ch': {} }, invalid: 1 });
  assert.deepEqual(parseSitesImport('# comment\nwww.x.ch\nhttps://y.ch/path\n\n!z\n'), { sites: { 'x.ch': { enabled: false }, 'y.ch': { enabled: false } }, invalid: 0 });
  assert.equal(parseSitesImport('[1,2,3]'), null);
  assert.equal(parseSitesImport(''), null);
});

test('validateBackup', () => {
  const ok = { format: 'bastion-shield-backup', version: 1, exportedAt: '2026-10-18T10:00:00Z', settings: defaultSettings(), sites: { 'a.ch': { enabled: false } }, customFilters: '||x^' };
  assert.deepEqual(validateBackup(ok), ok);
  assert.equal(validateBackup({ ...ok, format: 'other' }), null);
  assert.equal(validateBackup({ ...ok, settings: { version: 2 } }), null);
  assert.equal(validateBackup({ ...ok, sites: [] }), null);
  assert.equal(validateBackup(null), null);
});

test('broken-site report never contains path or query', () => {
  const d = { site: 'www.20min.ch', version: '0.1.0.2910', browser: 'Google Chrome 155', mode: 'standard', protection: 'on', lists: ['easylist', 'ublock'] };
  const url = new URL(githubUrl(d));
  assert.equal(url.origin + url.pathname, 'https://github.com/bastionsecurity-oss/bastion-shield/issues/new');
  assert.equal(url.searchParams.get('template'), 'broken-site.yml');
  assert.equal(url.searchParams.get('site'), 'www.20min.ch');
  assert.match(reportText(d), /^Site: www\.20min\.ch$/m);
  assert.ok(mailtoUrl(d, 'it@example.ch').startsWith('mailto:it%40example.ch?subject='));
});

test('dayKey uses local calendar day', () => {
  assert.equal(dayKey(new Date(2026, 0, 5, 23, 59)), '2026-01-05');
});
