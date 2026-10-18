// `!#trusted off|on <secret>`: per-source trust inside a trusted list
// (CompileOptions.trustSecret, ENT-3).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compileList, preprocess } from '../../src/compiler/index.ts';
import type { CompileOptions } from '../../src/compiler/types.ts';
import { opts } from './helpers.ts';

const SECRET = '7f3a9c1e5b';
const SCRIPTLET = 'a.example##+js(trusted-set-cookie, x, 1)';
const REDIRECT = '/ima.js$script,redirect=google-ima-dai.js';

function compile(lines: string[], over: Partial<CompileOptions> = {}) {
  return compileList(lines.join('\n'), opts({ trusted: true, trustSecret: SECRET, ...over }));
}
const rejected = (out: ReturnType<typeof compile>): string[] => out.stats.rejected.map((r) => `${r.reason} ${r.filter}`);

test('an untrusted span rejects trusted scriptlets and trusted-only redirects like an untrusted list', () => {
  const out = compile([
    SCRIPTLET,
    REDIRECT,
    `!#trusted off ${SECRET}`,
    'b.example##+js(trusted-set-cookie, y, 2)',
    '/ima2.js$script,redirect=google-ima-dai.js',
    'c.example##+js(set-constant, z, 1)',
    '/noop.js$script,redirect=noop.js',
    'c.example#@#+js(trusted-set-cookie, x, 1)',
    `!#trusted on ${SECRET}`,
    'd.example##+js(trusted-set-cookie, w, 3)',
  ]);
  assert.deepEqual(rejected(out), [
    'untrusted-scriptlet b.example##+js(trusted-set-cookie, y, 2)',
    'untrusted-redirect-resource /ima2.js$script,redirect=google-ima-dai.js',
  ]);
  assert.deepEqual(out.scriptlets.map((s) => s.hosts[0]), ['a.example', 'c.example', 'c.example', 'd.example']);
  assert.ok(out.rules.some((r) => r.rule.action.redirect?.extensionPath === '/war/google-ima-dai.js'));
  assert.ok(out.rules.some((r) => r.rule.action.redirect?.extensionPath === '/war/noop.js'));
});

test('toggles with another secret, without a secret or with junk are ignored', () => {
  const out = compile([
    `!#trusted off ${SECRET}`,
    '!#trusted on',
    '!#trusted on wrong-secret',
    `!#trusted on ${SECRET}x`,
    `!#trusted maybe ${SECRET}`,
    SCRIPTLET,
  ]);
  assert.deepEqual(rejected(out), [`untrusted-scriptlet ${SCRIPTLET}`]);
  // Upstream text cannot turn trust off either.
  assert.deepEqual(rejected(compile(['!#trusted off wrong-secret', SCRIPTLET])), []);
});

test('without trustSecret every !#trusted line is a comment', () => {
  const out = compile([`!#trusted off ${SECRET}`, SCRIPTLET], { trustSecret: undefined });
  assert.deepEqual(rejected(out), []);
  assert.deepEqual(rejected(compile([`!#trusted off `, SCRIPTLET], { trustSecret: '' })), []);
});

test('trust never rises above the list: an untrusted list stays untrusted', () => {
  const out = compile([`!#trusted on ${SECRET}`, SCRIPTLET, REDIRECT], { trusted: false });
  assert.deepEqual(rejected(out).map((r) => r.split(' ')[0]), ['untrusted-scriptlet', 'untrusted-redirect-resource']);
});

test('markers survive an !#if block left open by the previous source', () => {
  const text = ['!#if false', 'x.example##.ad', `!#trusted off ${SECRET}`, '!#endif', SCRIPTLET].join('\n');
  assert.ok(preprocess(text).includes(`!#trusted off ${SECRET}`));
  const out = compile(['!#if false', 'x.example##.ad', `!#trusted off ${SECRET}`, '!#endif', SCRIPTLET]);
  assert.deepEqual(rejected(out), [`untrusted-scriptlet ${SCRIPTLET}`]);
  assert.equal(out.specific.length, 0);
});

test('CRLF and extra spaces around the marker are tolerated', () => {
  const out = compileList([`!#trusted  off  ${SECRET}  `, SCRIPTLET, ''].join('\r\n'), opts({ trusted: true, trustSecret: SECRET }));
  assert.deepEqual(out.stats.rejected.map((r) => r.reason), ['untrusted-scriptlet']);
});
