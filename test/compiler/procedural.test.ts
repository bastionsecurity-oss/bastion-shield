// Procedural selector parsing (uBO #?# / ABP :-abp-*) into ProceduralFilter.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseProceduralSelector, analyzeSelector } from '../../src/compiler/index.ts';

const p = parseProceduralSelector;

describe('parseProceduralSelector', () => {
  test('plain CSS is not procedural', () => {
    assert.equal(p('div.ad > span'), null);
    assert.equal(p('div:has(> .sponsor)'), null);
    assert.equal(p('div:not(.x)'), null);
  });
  test('invalid selectors return null', () => {
    assert.equal(p('div:has-text('), null);
    assert.equal(p('div:unknown-op(x)'), null);
    assert.equal(p('div:has-text(a) {'), null);
  });
  test(':has-text with plain text and regex literal', () => {
    assert.deepEqual(p('div.ad:has-text(Sponsored)'), { raw: 'div.ad:has-text(Sponsored)', selector: 'div.ad', tasks: [['has-text', 'Sponsored']] });
    assert.deepEqual(p('span:has-text(/^Ad$/i)')?.tasks, [['has-text', '/^Ad$/i']]);
    assert.deepEqual(p('span:has-text("a, b")')?.tasks, [['has-text', 'a, b']]);
  });
  test(':-abp-contains / :contains -> has-text, :-abp-has -> has', () => {
    assert.deepEqual(p('div:-abp-contains(Ad)')?.tasks, [['has-text', 'Ad']]);
    assert.deepEqual(p('div:contains(Ad)')?.tasks, [['has-text', 'Ad']]);
    assert.deepEqual(p('div:-abp-has(span:-abp-contains(Ad))'), {
      raw: 'div:has(span:has-text(Ad))',
      selector: 'div',
      tasks: [['has', { raw: 'span:has-text(Ad)', selector: 'span', tasks: [['has-text', 'Ad']] }]],
    });
  });
  test(':has() becomes procedural when its argument is (or nests :has)', () => {
    assert.deepEqual(p('article:has(> .label:has-text(Promoted))'), {
      raw: 'article:has(> .label:has-text(Promoted))',
      selector: 'article',
      tasks: [['has', { raw: '> .label:has-text(Promoted)', selector: '> .label', tasks: [['has-text', 'Promoted']] }]],
    });
    assert.deepEqual(p('div:has(.a:has(.b))')?.tasks, [['has', { raw: '.a:has(.b)', selector: '.a:has(.b)', tasks: [] }]]);
  });
  test(':not() with a procedural argument', () => {
    assert.deepEqual(p('div.post:not(:has-text(Keep))')?.tasks, [['not', { raw: ':has-text(Keep)', selector: '', tasks: [['has-text', 'Keep']] }]]);
  });
  test(':upward with a number or a selector; :nth-ancestor alias', () => {
    assert.deepEqual(p('.ad-label:upward(2)')?.tasks, [['upward', 2]]);
    assert.deepEqual(p('.ad-label:upward(.card)')?.tasks, [['upward', '.card']]);
    assert.deepEqual(p('.ad-label:nth-ancestor(3)')?.tasks, [['upward', 3]]);
    assert.equal(p('.ad-label:upward(0)'), null);
    assert.equal(p('.ad-label:upward(256)'), null);
  });
  test('spath for plain CSS between operators keeps uBO spelling', () => {
    assert.deepEqual(p('div:has-text(Ad) > span.x')?.tasks, [['has-text', 'Ad'], ['spath', ' > span.x']]);
    assert.deepEqual(p('div:has-text(Ad) .x')?.tasks, [['has-text', 'Ad'], ['spath', ' .x']]);
    assert.equal(p('div > :has-text(Ad)')?.selector, 'div > *');
  });
  test('selector may be empty when the filter starts with an operator', () => {
    assert.deepEqual(p(':xpath(//div[@class="ad"])'), { raw: ':xpath(//div[@class="ad"])', selector: '', tasks: [['xpath', '//div[@class="ad"]']] });
  });
  test('the other operators', () => {
    assert.deepEqual(p('div:matches-css(position: fixed)')?.tasks, [['matches-css', 'position: fixed']]);
    assert.deepEqual(p('div:matches-css-before(content: /Ad/)')?.tasks, [['matches-css-before', 'content: /Ad/']]);
    assert.deepEqual(p('div:matches-css-after(content: x)')?.tasks, [['matches-css-after', 'content: x']]);
    assert.deepEqual(p('div:matches-attr("data-ad"="/^1/")')?.tasks, [['matches-attr', '"data-ad"="/^1/"']]);
    assert.deepEqual(p('div:matches-prop(adsbygoogle)')?.tasks, [['matches-prop', 'adsbygoogle']]);
    assert.deepEqual(p('div:matches-media((max-width: 600px))')?.tasks, [['matches-media', '(max-width: 600px)']]);
    assert.deepEqual(p('div:matches-path(/^\\/news/)')?.tasks, [['matches-path', '/^\\/news/']]);
    assert.deepEqual(p('p:min-text-length(200)')?.tasks, [['min-text-length', 200]]);
    assert.deepEqual(p('#main:others()')?.tasks, [['others']]);
    assert.deepEqual(p('#host:shadow(.inner)')?.tasks, [['shadow', '.inner']]);
    assert.deepEqual(p('div:watch-attr(class, style)')?.tasks, [['watch-attr', 'class,style']]);
    assert.deepEqual(p('div:watch-attrs(class)')?.tasks, [['watch-attr', 'class']]);
    assert.deepEqual(p('div:if(.ad)')?.tasks, [['if', { raw: '.ad', selector: '.ad', tasks: [] }]]);
    assert.deepEqual(p('div:if-not(.content)')?.tasks, [['if-not', { raw: '.content', selector: '.content', tasks: [] }]]);
  });
  test('actions: style, remove, remove-attr, remove-class', () => {
    assert.deepEqual(p('div:has-text(Ad):remove()'), { raw: 'div:has-text(Ad):remove()', selector: 'div', tasks: [['has-text', 'Ad']], action: ['remove'] });
    assert.deepEqual(p('img:remove-attr(srcset)')?.action, ['remove-attr', 'srcset']);
    assert.deepEqual(p('body:remove-class("no-scroll")')?.action, ['remove-class', 'no-scroll']);
    assert.deepEqual(p('body:style(overflow: auto !important)'), {
      raw: 'body:style(overflow: auto !important)', selector: 'body', tasks: [], action: ['style', 'overflow: auto !important'],
    });
  });
  test('nothing may follow an action; actions are not allowed inside :has()', () => {
    assert.equal(p('div:remove() .x'), null);
    assert.equal(p('div:has(.x:remove())'), null);
  });
  test('a leading selector list is the subject of the operators', () => {
    assert.deepEqual(p('#a, .b:others()'), { raw: '#a, .b:others()', selector: '#a, .b', tasks: [['others']] });
    assert.equal(p('div:has-text(a), span'), null);
  });
  test('AdGuard [-ext-has=…] / [-ext-contains=…] syntax', () => {
    // A plain :has() argument is native CSS (Chrome supports :has).
    assert.equal(p('div[-ext-has=".ad"]'), null);
    const a = analyzeSelector('div[-ext-has=".ad"]', true);
    assert.equal(a.kind, 'css');
    assert.equal(a.kind === 'css' ? a.selector : '', 'div:has(.ad)');
    assert.deepEqual(p('div[-ext-contains="Ad"]')?.tasks, [['has-text', 'Ad']]);
  });
  test(':-abp-properties is not supported', () => {
    assert.equal(p('div:-abp-properties(width: 300px)'), null);
  });
});

describe('analyzeSelector', () => {
  test('classifies css / style / procedural', () => {
    assert.equal(analyzeSelector('.ad', false).kind, 'css');
    assert.equal(analyzeSelector('.ad:style(color: red)', false).kind, 'style');
    assert.equal(analyzeSelector('.ad:has-text(x)', false).kind, 'procedural');
    assert.equal(analyzeSelector('> .ad', false).kind, 'invalid');
  });
});
