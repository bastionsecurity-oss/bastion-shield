// Preprocessor tests: !#if / !#else / !#endif with uBO token semantics, and
// !#include through a caller-supplied resolver.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_ENV, compileList, evaluateExpression, preprocess } from '../../src/compiler/index.ts';
import { opts } from './helpers.ts';

const lines = (s: string): string[] => s.split('\n').filter((l) => l !== '');

describe('DEFAULT_ENV', () => {
  test('behaves like uBO Lite on Chromium', () => {
    for (const t of ['ext_ublock', 'ext_ubol', 'env_chromium', 'env_mv3', 'adguard_ext_chromium', 'adguard_ext_chromium_mv3']) {
      assert.equal(evaluateExpression(t, DEFAULT_ENV), true, t);
    }
    for (const t of ['env_firefox', 'env_safari', 'env_mobile', 'env_edge', 'env_brave', 'ext_abp', 'adguard', 'cap_html_filtering', 'cap_ipaddress', 'false', 'adguard_app_windows', 'ext_devbuild']) {
      assert.equal(evaluateExpression(t, DEFAULT_ENV), false, t);
    }
  });
  test('unknown tokens are undefined; unknown cap_* tokens are false', () => {
    assert.equal(evaluateExpression('env_whatever', DEFAULT_ENV), undefined);
    assert.equal(evaluateExpression('cap_something_new', DEFAULT_ENV), false);
  });
  test('negation, && and || (left to right), outer parentheses', () => {
    assert.equal(evaluateExpression('!env_firefox', DEFAULT_ENV), true);
    assert.equal(evaluateExpression('!false', DEFAULT_ENV), true);
    assert.equal(evaluateExpression('env_chromium && !env_mobile', DEFAULT_ENV), true);
    assert.equal(evaluateExpression('env_firefox || env_chromium', DEFAULT_ENV), true);
    assert.equal(evaluateExpression('(env_firefox || env_safari)', DEFAULT_ENV), false);
    assert.equal(evaluateExpression('env_firefox && env_chromium || ext_ubol', DEFAULT_ENV), true);
    assert.equal(evaluateExpression('&& ext_ubol', DEFAULT_ENV), undefined);
  });
  test('env may also name uBO states ("chromium", "mobile")', () => {
    assert.equal(evaluateExpression('env_mobile', new Set(['mobile'])), true);
  });
});

describe('preprocess', () => {
  test('keeps true branches, drops false ones, preserves line numbers', () => {
    const text = 'a\n!#if env_firefox\nb\n!#else\nc\n!#endif\nd';
    const out = preprocess(text);
    assert.deepEqual(lines(out), ['a', 'c', 'd']);
    assert.equal(out.split('\n').length, text.split('\n').length);
  });
  test('nested blocks', () => {
    const text = '!#if ext_ubol\n1\n!#if env_firefox\n2\n!#else\n3\n!#endif\n4\n!#endif\n!#if !ext_ubol\n5\n!#endif';
    assert.deepEqual(lines(preprocess(text)), ['1', '3', '4']);
  });
  test('unknown tokens keep the block (uBO)', () => {
    assert.deepEqual(lines(preprocess('!#if env_unknown_thing\nx\n!#endif')), ['x']);
  });
  test('stray !#else / !#endif are harmless', () => {
    assert.deepEqual(lines(preprocess('!#endif\na\n!#else\nb')), ['a', 'b']);
  });
  test('!#ifdef-like lines are not directives', () => {
    assert.deepEqual(lines(preprocess('!#ifdef foo\na')), ['!#ifdef foo', 'a']);
  });
  test('custom env', () => {
    assert.deepEqual(lines(preprocess('!#if env_firefox\nx\n!#endif', new Set(['env_firefox']))), ['x']);
  });
  test('!#include via resolver, recursively preprocessed', () => {
    const files: Record<string, string> = { 'sub.txt': 'inc1\n!#if env_firefox\nno\n!#endif\n!#include deeper.txt', 'deeper.txt': 'inc2' };
    const out = preprocess('a\n!#include sub.txt\nb', DEFAULT_ENV, (p) => files[p]);
    assert.deepEqual(lines(out), ['a', 'inc1', 'inc2', 'b']);
  });
  test('includes inside a discarded block are not resolved', () => {
    let called = 0;
    preprocess('!#if false\n!#include x.txt\n!#endif', DEFAULT_ENV, () => {
      called += 1;
      return 'x';
    });
    assert.equal(called, 0);
  });
  test('include cycles and resolver errors are contained', () => {
    const out = preprocess('!#include a.txt\nend', DEFAULT_ENV, (p) => {
      if (p === 'a.txt') return 'A\n!#include a.txt';
      throw new Error('boom');
    });
    assert.deepEqual(lines(out), ['A', 'end']);
    assert.deepEqual(lines(preprocess('!#include b.txt\nz', DEFAULT_ENV, () => {
      throw new Error('boom');
    })), ['z']);
  });
  test('without a resolver !#include stays a comment', () => {
    const out = compileList('!#include sub.txt\n||a.example^', opts());
    assert.equal(out.stats.filters, 1);
  });
  test('compileList applies opts.env', () => {
    const text = '!#if env_firefox\n||ff.example^\n!#endif\n!#if ext_ubol\n||ubol.example^\n!#endif';
    assert.deepEqual(compileList(text, opts()).rules[0].rule.condition.requestDomains, ['ubol.example']);
    assert.deepEqual(compileList(text, opts({ env: new Set(['env_firefox']) })).rules[0].rule.condition.requestDomains, ['ff.example']);
  });
});
