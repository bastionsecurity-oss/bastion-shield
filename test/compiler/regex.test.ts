// RE2 compatibility checks and regex -> urlFilter conversion.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { isRe2Compatible, regexToUrlFilter, toRe2 } from '../../src/compiler/index.ts';

describe('isRe2Compatible', () => {
  test('accepts ordinary filter regexes', () => {
    for (const re of [
      '^https?:\\/\\/[a-z]{8,15}\\.(?:com|net)\\/',
      '\\.com\\/[0-9a-f]{32}\\.js$',
      '[^a-z]ads?[0-9]*\\.',
      '^https:\\/\\/[a-z]+\\.example\\/\\d{2,4}\\?[\\w=&-]+$',
      '(?:^|[^a-z])track(?:er)?[^a-z]',
    ]) {
      assert.equal(isRe2Compatible(re), true, re);
    }
  });
  test('rejects lookaround, backreferences, named backreferences', () => {
    for (const re of ['(?=a)b', '(?!www)\\w+', '(?<=x)y', '(?<!x)y', '(a)\\1', '(?<n>a)\\k<n>']) {
      assert.equal(isRe2Compatible(re), false, re);
    }
  });
  test('rejects repetitions over 1000 and non-ASCII', () => {
    assert.equal(isRe2Compatible('a{1001}'), false);
    assert.equal(isRe2Compatible('[%0-9a-z]{200,1300}'), false);
    assert.equal(isRe2Compatible('a{2,1000}'), true);
    assert.equal(isRe2Compatible('wérbung'), false);
  });
  test('rejects invalid JS regexes', () => {
    assert.equal(isRe2Compatible('(a'), false);
    assert.equal(isRe2Compatible('a**'), false);
  });
  test('lookaround-looking text inside a class is fine', () => {
    assert.equal(isRe2Compatible('[(?=]x'), true);
  });
});

describe('toRe2', () => {
  test('translates JS-only escapes', () => {
    assert.equal(toRe2('\\u00e9'), '\\x{00e9}');
    assert.equal(toRe2('a\\0b'), 'a\\x00b');
    assert.equal(toRe2('[\\b]'), '[\\x08]');
    assert.equal(toRe2('[^]'), '[\\s\\S]');
    assert.equal(toRe2('(?<name>a)'), '(?P<name>a)');
    assert.equal(toRe2('\\e\\z'), 'ez');
    assert.equal(toRe2('a{x'), 'a\\{x');
  });
  test('keeps escapes that mean the same', () => {
    assert.equal(toRe2('\\d\\w\\s\\b\\/\\.\\-'), '\\d\\w\\s\\b\\/\\.\\-');
  });
  test('an empty class differs between engines', () => {
    assert.equal(toRe2('a[]b'), null);
  });
});

describe('regexToUrlFilter', () => {
  test('literal regexes become urlFilters', () => {
    assert.equal(regexToUrlFilter('\\/ads\\/'), '/ads/');
    assert.equal(regexToUrlFilter('^https:\\/\\/x\\.example\\/'), '|https://x.example/');
    assert.equal(regexToUrlFilter('\\.js$'), '.js|');
    assert.equal(regexToUrlFilter('banner_ad'), 'banner_ad');
  });
  test('anything with regex semantics or urlFilter syntax stays a regex', () => {
    for (const re of ['ads?', 'a.b', 'a|b', '[0-9]', 'a\\d', 'x\\*y', 'x\\^y', 'x\\|y', 'a+', '(ab)', '^a']) {
      assert.equal(regexToUrlFilter(re), null, re);
    }
  });
});
