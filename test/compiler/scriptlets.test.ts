// Scriptlet filter tests: argument parsing, aliases, trust, exceptions, hosts.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { compileList, parseScriptletArgs } from '../../src/compiler/index.ts';
import type { CompileOptions, CompiledList } from '../../src/compiler/types.ts';
import { opts } from './helpers.ts';

const compile = (text: string, over: Partial<CompileOptions> = {}): CompiledList => compileList(text, opts(over));

describe('parseScriptletArgs', () => {
  test('splits on commas and trims', () => {
    assert.deepEqual(parseScriptletArgs('set, foo.bar,  true '), ['set', 'foo.bar', 'true']);
  });
  test('quoted arguments may contain commas', () => {
    assert.deepEqual(parseScriptletArgs(`rmnt, script, "a, b", 'c,d', \`e,f\``), ['rmnt', 'script', 'a, b', 'c,d', 'e,f']);
  });
  test('escaped commas in unquoted arguments', () => {
    assert.deepEqual(parseScriptletArgs('acs, document.write, /a\\,b/'), ['acs', 'document.write', '/a,b/']);
  });
  test('escaped quotes inside quotes; other escapes kept', () => {
    assert.deepEqual(parseScriptletArgs('x, "say \\"hi\\"", "a\\nb"'), ['x', 'say "hi"', 'a\\nb']);
  });
  test('a quote not followed by a comma is literal', () => {
    assert.deepEqual(parseScriptletArgs(`x, "a"b, c`), ['x', '"a"b', 'c']);
  });
  test('empty middle arguments are kept, a trailing comma adds nothing', () => {
    assert.deepEqual(parseScriptletArgs('set-cookie, GPC, 1, , reload'), ['set-cookie', 'GPC', '1', '', 'reload']);
    assert.deepEqual(parseScriptletArgs('set, a, 1,'), ['set', 'a', '1']);
  });
  test('empty input', () => {
    assert.deepEqual(parseScriptletArgs(''), []);
    assert.deepEqual(parseScriptletArgs('  '), []);
  });
  test('regex arguments with parentheses and pipes', () => {
    assert.deepEqual(parseScriptletArgs('aost, decodeURI, /(?=^(?!.*\\.js))/'), ['aost', 'decodeURI', '/(?=^(?!.*\\.js))/']);
  });
});

describe('scriptlet filters', () => {
  test('aliases resolve to the canonical name and world', () => {
    assert.deepEqual(compile('example.com##+js(set, foo, 1)').scriptlets, [
      { name: 'set-constant.js', world: 'MAIN', args: ['foo', '1'], hosts: ['example.com'], excludedHosts: [], exception: false, raw: 'example.com##+js(set, foo, 1)' },
    ]);
    assert.equal(compile('a.com##+js(rc.js, x)').scriptlets[0].world, 'ISOLATED');
    assert.equal(compile('a.com##+js(set-constant, x, 1)').scriptlets[0].name, 'set-constant.js');
  });
  test('unknown scriptlets are rejected', () => {
    assert.deepEqual(compile('a.com##+js(nope, x)').stats.rejected, [{ filter: 'a.com##+js(nope, x)', reason: 'unknown-scriptlet:nope' }]);
  });
  test('trusted scriptlets need a trusted list', () => {
    assert.deepEqual(compile('a.com##+js(trusted-set-cookie, x, 1)').stats.rejected.map((r) => r.reason), ['untrusted-scriptlet']);
    assert.equal(compile('a.com##+js(trusted-set-cookie, x, 1)', { trusted: true }).scriptlets.length, 1);
  });
  test('exceptions of trusted scriptlets are fine in untrusted lists', () => {
    assert.equal(compile('a.com#@#+js(trusted-set-cookie, x, 1)').scriptlets[0].exception, true);
  });
  test('hosts: entities, regex hostnames, exclusions, "*"', () => {
    const s = compile('google.*,/^x\\.example$/,~www.google.com##+js(aopr, ads)').scriptlets[0];
    assert.deepEqual(s.hosts, ['/^x\\.example$/', 'google.*']);
    assert.deepEqual(s.excludedHosts, ['www.google.com']);
    assert.deepEqual(compile('*##+js(aopr, ads)').scriptlets[0].hosts, ['*']);
  });
  test('generic scriptlets need "*##"', () => {
    assert.deepEqual(compile('##+js(aopr, ads)').stats.rejected.map((r) => r.reason), ['unsupported:generic-scriptlet']);
    assert.deepEqual(compile('~a.com##+js(aopr, ads)').stats.rejected.map((r) => r.reason), ['unsupported:negated-only-scriptlet']);
  });
  test('#@#+js() is the broad exception', () => {
    assert.deepEqual(compile('a.com#@#+js()').scriptlets[0], {
      name: '', world: 'MAIN', args: [], hosts: ['a.com'], excludedHosts: [], exception: true, raw: 'a.com#@#+js()',
    });
  });
  test('exceptions without hostname apply everywhere and ignore negated hosts', () => {
    assert.deepEqual(compile('#@#+js(set, foo, 1)').scriptlets[0].hosts, ['*']);
    assert.deepEqual(compile('a.com,~b.a.com#@#+js(set, foo, 1)').scriptlets[0].excludedHosts, []);
  });
  test('+js without arguments is not a filter', () => {
    assert.deepEqual(compile('a.com##+js()').stats.rejected.map((r) => r.reason), ['invalid-scriptlet']);
  });
  test('arguments with commas survive the full pipeline', () => {
    assert.deepEqual(compile('a.com##+js(json-prune, "a.b, c.d", [].x)').scriptlets[0].args, ['a.b, c.d', '[].x']);
  });
});
