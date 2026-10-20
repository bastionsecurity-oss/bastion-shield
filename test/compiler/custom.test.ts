// compileCustom(): user / admin filters at runtime (dynamic rules).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collectBadfilters, compileCustom } from '../../src/compiler/index.ts';
import { REDIRECTS, SCRIPTLETS, ruleProblems } from './helpers.ts';
import { PRIORITY } from '../../src/shared/constants.ts';

const base = { redirectResources: REDIRECTS, scriptlets: SCRIPTLETS };

test('custom filters use the always-apply band and never strict-block', () => {
  const out = compileCustom('||ads.example^\n@@||ok.example^\n/x.js$script,redirect=noop.js\n||imp.example^$important', base);
  const prio = Object.fromEntries(out.rules.map((r) => [r.action.type + (r.priority === 40 ? '!' : ''), r.priority]));
  assert.deepEqual(prio, { block: 21, allow: 30, redirect: 22, 'block!': 40 });
  assert.ok(out.rules.every((r) => r.priority !== 29));
  for (const r of out.rules) assert.deepEqual(ruleProblems(r), []);
});

test('@@…$important in custom filters: allow at IMPORTANT_ALLOW, above $important blocks', () => {
  const out = compileCustom('||imp.example^$important\n@@||imp.example/ok.js^$important\n@@||site.example^$document,important', base);
  assert.deepEqual(out.errors, []);
  const allows = out.rules.filter((r) => r.action.type !== 'block');
  assert.deepEqual(allows.map((r) => [r.action.type, r.priority]), [['allow', PRIORITY.IMPORTANT_ALLOW], ['allowAllRequests', PRIORITY.IMPORTANT_ALLOW]]);
  assert.ok(PRIORITY.IMPORTANT_ALLOW > (out.rules.find((r) => r.action.type === 'block')?.priority ?? Infinity));
  for (const r of out.rules) assert.deepEqual(ruleProblems(r), []);
});

test('@@…$important cannot be combined with modifiers', () => {
  const out = compileCustom('@@||a.example^$removeparam=x,important\n@@||a.example^$csp=script-src none,important', base);
  assert.deepEqual(out.errors.map((e) => e.reason), ['invalid-option', 'invalid-option']);
  assert.equal(out.rules.length, 0);
});

test('regex rules are included in the rules array', () => {
  const out = compileCustom('/^https:\\/\\/[a-z]+\\.example\\/ad/$script', base);
  assert.equal(out.rules.length, 1);
  assert.ok(out.rules[0].condition.regexFilter !== undefined);
});

test('scriptlets are ignored and counted, trusted resources are refused', () => {
  const out = compileCustom('a.com##+js(set, x, 1)\nb.com##+js(nope)\n/x.js$script,redirect=google-ima-dai.js', base);
  assert.equal(out.scriptletsIgnored, 2);
  assert.deepEqual(out.errors, [{ line: 3, text: '/x.js$script,redirect=google-ima-dai.js', reason: 'untrusted-redirect-resource' }]);
});

test('errors carry 1-based line numbers (blank and comment lines count)', () => {
  const out = compileCustom('! my filters\n\n||ok.example^\n/ads.$popup\nexample.com##div[\n/x.$foo=bar,script', base);
  assert.deepEqual(out.errors, [
    { line: 4, text: '/ads.$popup', reason: 'unsupported-type:popup' },
    { line: 5, text: 'example.com##div[', reason: 'invalid-selector:invalid-selector' },
    { line: 6, text: '/x.$foo=bar,script', reason: 'unknown-option:foo' },
  ]);
});

test('cosmetic filters come back as specific / generic entries', () => {
  const out = compileCustom('example.com##.ad\n##.banner-ad\n@@||site.example^$generichide', base);
  assert.deepEqual(out.specific, [
    { kind: 0, hosts: ['example.com'], excludedHosts: [], payload: '.ad', raw: 'example.com##.ad' },
    { kind: 4, hosts: ['site.example'], excludedHosts: [], payload: 'generichide', raw: '@@||site.example^$generichide' },
  ]);
  assert.deepEqual(out.generic, [{ selector: '.banner-ad', token: '.banner-ad', excludedHosts: [], raw: '##.banner-ad' }]);
});

test('global cosmetic exceptions are reported as unsupported in custom filters', () => {
  const out = compileCustom('#@#.ad', base);
  assert.deepEqual(out.errors.map((e) => e.reason), ['unsupported-in-custom:generic-exception']);
});

test('badfilters from lists and from the custom text both apply', () => {
  const lists = collectBadfilters('||b.example^$badfilter');
  const out = compileCustom('||a.example^\n||b.example^\n||c.example^\n||c.example^$badfilter', { ...base, badfilters: lists });
  assert.deepEqual(out.rules.map((r) => r.condition.requestDomains), [['a.example']]);
});

test('custom modifiers get a first-party copy above the Standard 1p allow (BS-2)', () => {
  const out = compileCustom('||site-a.example.com^$removeparam=foo', base);
  assert.deepEqual(out.rules.map((r) => [r.priority, r.condition.domainType, r.condition.resourceTypes]), [
    [1, undefined, ['image', 'main_frame', 'sub_frame', 'xmlhttprequest']],
    [20, 'firstParty', ['image', 'sub_frame', 'xmlhttprequest']],
  ]);
  const csp = compileCustom("||site-a.example.com^$csp=script-src 'none'", base);
  assert.deepEqual(csp.rules.map((r) => [r.priority, r.action.type, r.condition.domainType, r.condition.resourceTypes]), [
    [1, 'modifyHeaders', undefined, ['main_frame', 'sub_frame']],
    [20, 'modifyHeaders', 'firstParty', ['sub_frame']],
  ]);
  for (const r of [...out.rules, ...csp.rules]) assert.deepEqual(ruleProblems(r), []);
});

test("custom @@ modifier exceptions are copied too, so they cancel the user's 1p copies", () => {
  const out = compileCustom('||a.example^$removeparam=foo\n@@||a.example/keep^$removeparam=foo\n@@||a.example^$csp', base);
  const allows = out.rules.filter((r) => r.action.type === 'allow').map((r) => [r.priority, r.condition.domainType, r.condition.resourceTypes]);
  assert.deepEqual(allows, [
    [1, undefined, ['image', 'main_frame', 'sub_frame', 'xmlhttprequest']],
    [20, 'firstParty', ['image', 'sub_frame', 'xmlhttprequest']],
    [1, undefined, ['main_frame', 'sub_frame']],
    [20, 'firstParty', ['sub_frame']],
  ]);
});

test('custom $3p modifiers and custom blocks get no first-party copy', () => {
  const out = compileCustom('||a.example^$3p,removeparam=foo\n||b.example^', base);
  assert.deepEqual(out.rules.map((r) => r.priority), [1, 21]);
});

test('custom text is never trusted, whatever !#trusted lines it contains', () => {
  const out = compileCustom('!#trusted on s3cret\n/x.js$script,redirect=google-ima-dai.js', { ...base, trustSecret: 's3cret' });
  assert.deepEqual(out.errors.map((e) => e.reason), ['untrusted-redirect-resource']);
});

test('never throws on junk input', () => {
  const junk = ['$$$', '@@', '##', '#@#', '||', '|', '$', ',', '/', '//', '/(/', '!#if', 'a.com##+js(', '\u0000', '##:has-text(', '@@$document'];
  assert.doesNotThrow(() => compileCustom(junk.join('\n'), base));
});
