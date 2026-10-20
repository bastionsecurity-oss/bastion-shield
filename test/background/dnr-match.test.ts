// Tests for the pure DNR matcher (src/shared/dnr-match.ts) used by the nerd-
// mode filter playground: Chrome's documented urlFilter examples, regexFilter,
// domain lists, party, types, methods, tabs, and the winner among several
// matching rules (priority, then allow > allowAllRequests > block >
// upgradeScheme > redirect; modifyHeaders above the winning allow).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  compileCondition,
  decide,
  domainListMatches,
  isThirdParty,
  prepareRequest,
  ruleMatches,
  urlFilterMatches,
  type MatchRule,
} from '../../src/shared/dnr-match.ts';

const uf = (filter: string, yes: string[], no: string[], cs = false): void => {
  for (const u of yes) assert.equal(urlFilterMatches(filter, u, cs), true, `${filter} should match ${u}`);
  for (const u of no) assert.equal(urlFilterMatches(filter, u, cs), false, `${filter} should not match ${u}`);
};

test('urlFilter: Chrome documentation examples', () => {
  uf('abc', ['https://abcd.com', 'https://example.com/abcd'], ['https://ab.com']);
  uf('abc*d', ['https://abcd.com', 'https://example.com/abcxyzd'], ['https://abc.com']);
  uf('||a.example.com', ['https://a.example.com/', 'https://b.a.example.com/xyz', 'https://a.example.company'], ['https://example.com/']);
  uf('|https*', ['https://example.com'], ['http://example.com/', 'http://https.com']);
  uf('example*^123|', ['https://example.com/123', 'http://abc.com/example?123'], ['https://example.com/1234', 'https://abc.com/example0123']);
});

test('urlFilter: domain anchor only at a label boundary of the host', () => {
  uf('||example.com^', ['https://example.com/', 'https://sub.example.com/x', 'http://example.com:8080/'], ['https://notexample.com/', 'https://a.com/?u=example.com', 'https://a.com/example.com/']);
  // `||` cannot start inside the path even after a dot there.
  uf('||js', [], ['https://a.com/x.js']);
  // The pattern can run past the host into the path.
  uf('||ads.example.com/banner', ['https://ads.example.com/banner.png'], ['https://ads.example.com/x/banner.png']);
  // userinfo before the host does not shift the anchor.
  uf('||tracker.example^', ['https://user:pw@tracker.example/p'], []);
});

test('urlFilter: separator semantics', () => {
  // ^ matches anything but letters, digits and _ - . %, and the end of the URL.
  uf('||ex.com^', ['https://ex.com', 'https://ex.com/', 'https://ex.com:443/', 'https://ex.com?x'], ['https://ex.com.evil.net/', 'https://ex.com-x.net/', 'https://ex.com_x/']);
  uf('/ad^', ['https://a.com/ad?x=1', 'https://a.com/ad/', 'https://a.com/ad'], ['https://a.com/ad%20', 'https://a.com/ads']);
  uf('^ad=', ['https://a.com/?ad=1', 'https://a.com/x&ad=2'], ['https://a.com/?bad=1']);
});

test('urlFilter: anchors, wildcards and case', () => {
  uf('|https://a.com/x|', ['https://a.com/x'], ['https://a.com/xy', 'https://b.com/?https://a.com/x']);
  uf('/banner/*/img', ['https://a.com/banner/x/y/img.png'], ['https://a.com/banner/img']);
  uf('*', ['https://a.com/'], []);
  uf('/AdServer/', ['https://a.com/adserver/x', 'https://a.com/ADSERVER/'], []);
  uf('/AdServer/', ['https://a.com/AdServer/x'], ['https://a.com/adserver/x'], true);
  // Fragments never reach the network stack.
  uf('#frag', [], ['https://a.com/page#frag']);
  // Regex metacharacters in a urlFilter are literal.
  uf('/a.b(c)+', ['https://x.com/a.b(c)+'], ['https://x.com/aXb(c)']);
});

test('regexFilter: JS approximation, (?i), case sensitivity, invalid patterns', () => {
  const rule = (regexFilter: string, cs?: boolean): MatchRule => ({ action: { type: 'block' }, condition: { regexFilter, isUrlFilterCaseSensitive: cs } });
  assert.equal(ruleMatches(rule('^https://[a-z]+\\.example\\.com/ad'), { url: 'https://cdn.example.com/ads.js', type: 'script' }), true);
  assert.equal(ruleMatches(rule('/AD[0-9]+\\.js'), { url: 'https://x.com/ad12.js', type: 'script' }), true);
  assert.equal(ruleMatches(rule('/AD[0-9]+\\.js', true), { url: 'https://x.com/ad12.js', type: 'script' }), false);
  assert.equal(ruleMatches(rule('(?i)/AD[0-9]+\\.js', true), { url: 'https://x.com/ad12.js', type: 'script' }), true);
  const bad = compileCondition({ regexFilter: '(unclosed' });
  assert.ok(bad.error);
  assert.equal(bad.test(prepareRequest({ url: 'https://x.com/', type: 'script' })!), false);
});

test('domain lists: subdomains, most specific entry wins, tie goes to the exclusion', () => {
  assert.equal(domainListMatches('a.example.com', ['example.com']), true);
  assert.equal(domainListMatches('example.com', ['a.example.com']), false);
  assert.equal(domainListMatches('badexample.com', ['example.com']), false);
  assert.equal(domainListMatches('x.example.com', ['example.com'], ['x.example.com']), false);
  assert.equal(domainListMatches('y.x.example.com', ['y.x.example.com'], ['example.com']), true);
  assert.equal(domainListMatches('example.com', ['example.com'], ['example.com']), false);
  assert.equal(domainListMatches('other.org', undefined, ['example.com']), true);
  assert.equal(domainListMatches(null, ['example.com']), false, 'no initiator never matches an include list');
  assert.equal(domainListMatches(null, undefined, ['example.com']), true);
  assert.equal(domainListMatches(null), true);
});

test('initiator, request and top domains', () => {
  const r: MatchRule = { action: { type: 'block' }, condition: { urlFilter: '||cdn.net^', initiatorDomains: ['news.ch'], excludedRequestDomains: ['safe.cdn.net'] } };
  assert.equal(ruleMatches(r, { url: 'https://cdn.net/a.js', type: 'script', initiator: 'www.news.ch' }), true);
  assert.equal(ruleMatches(r, { url: 'https://cdn.net/a.js', type: 'script', initiator: 'https://shop.ch/page' }), false);
  assert.equal(ruleMatches(r, { url: 'https://cdn.net/a.js', type: 'script' }), false);
  assert.equal(ruleMatches(r, { url: 'https://safe.cdn.net/a.js', type: 'script', initiator: 'news.ch' }), false);
  const top: MatchRule = { action: { type: 'block' }, condition: { urlFilter: 'x', topDomains: ['top.ch'] } };
  assert.equal(ruleMatches(top, { url: 'https://a.com/x', type: 'image', initiator: 'frame.net', top: 'top.ch' }), true);
  assert.equal(ruleMatches(top, { url: 'https://a.com/x', type: 'image', initiator: 'top.ch', top: 'other.ch' }), false);
  assert.equal(ruleMatches(top, { url: 'https://a.com/x', type: 'image', initiator: 'top.ch' }), true, 'top defaults to the initiator');
});

test('domainType: registrable domain, no initiator counts as third party', () => {
  assert.equal(isThirdParty('cdn.example.com', 'www.example.com'), false);
  assert.equal(isThirdParty('a.example.co.uk', 'b.example.co.uk'), false);
  assert.equal(isThirdParty('example.co.uk', 'other.co.uk'), true);
  assert.equal(isThirdParty('tracker.net', 'example.com'), true);
  assert.equal(isThirdParty('example.com', null), true);
  assert.equal(isThirdParty('10.0.0.1', '10.0.0.1'), false);
  const third: MatchRule = { action: { type: 'block' }, condition: { urlFilter: '||example.com^', domainType: 'thirdParty' } };
  assert.equal(ruleMatches(third, { url: 'https://img.example.com/a.png', type: 'image', initiator: 'example.com' }), false);
  assert.equal(ruleMatches(third, { url: 'https://img.example.com/a.png', type: 'image', initiator: 'news.ch' }), true);
  const first: MatchRule = { action: { type: 'block' }, condition: { domainType: 'firstParty' } };
  assert.equal(ruleMatches(first, { url: 'https://img.example.com/a.png', type: 'image', initiator: 'example.com' }), true);
  assert.equal(ruleMatches(first, { url: 'https://img.example.com/a.png', type: 'image' }), false);
});

test('resource types: default excludes main_frame; excluded-only matches main_frame', () => {
  const any: MatchRule = { action: { type: 'block' }, condition: { urlFilter: '||ex.com^' } };
  assert.equal(ruleMatches(any, { url: 'https://ex.com/', type: 'script' }), true);
  assert.equal(ruleMatches(any, { url: 'https://ex.com/', type: 'main_frame' }), false);
  const excl: MatchRule = { action: { type: 'block' }, condition: { urlFilter: '||ex.com^', excludedResourceTypes: ['image'] } };
  assert.equal(ruleMatches(excl, { url: 'https://ex.com/', type: 'main_frame' }), true);
  assert.equal(ruleMatches(excl, { url: 'https://ex.com/', type: 'image' }), false);
  const only: MatchRule = { action: { type: 'block' }, condition: { urlFilter: '||ex.com^', resourceTypes: ['main_frame', 'script'] } };
  assert.equal(ruleMatches(only, { url: 'https://ex.com/', type: 'main_frame' }), true);
  assert.equal(ruleMatches(only, { url: 'https://ex.com/', type: 'image' }), false);
});

test('methods and tabs', () => {
  const get: MatchRule = { action: { type: 'block' }, condition: { urlFilter: 'x', requestMethods: ['get'] } };
  assert.equal(ruleMatches(get, { url: 'https://a.com/x', type: 'xmlhttprequest' }), true, 'method defaults to GET');
  assert.equal(ruleMatches(get, { url: 'https://a.com/x', type: 'xmlhttprequest', method: 'POST' }), false);
  const noPost: MatchRule = { action: { type: 'block' }, condition: { urlFilter: 'x', excludedRequestMethods: ['post'] } };
  assert.equal(ruleMatches(noPost, { url: 'https://a.com/x', type: 'xmlhttprequest', method: 'POST' }), false);
  const tabless: MatchRule = { action: { type: 'allow' }, condition: { tabIds: [-1] } };
  assert.equal(ruleMatches(tabless, { url: 'https://a.com/x', type: 'script', tabless: true }), true);
  assert.equal(ruleMatches(tabless, { url: 'https://a.com/x', type: 'script' }), false);
  assert.equal(ruleMatches(tabless, { url: 'https://a.com/x', type: 'script', tabId: 4 }), false);
});

test('responseHeaders conditions are reported as uncertain', () => {
  const m = compileCondition({ urlFilter: 'x', responseHeaders: [{ header: 'content-type' }] });
  assert.deepEqual(m.uncertain, ['responseHeaders']);
  assert.equal(m.test(prepareRequest({ url: 'https://a.com/x', type: 'script' })!), true);
});

test('prepareRequest: canonical URL, no fragment, unparsable input', () => {
  const r = prepareRequest({ url: 'HTTPS://Ex.COM/Path#frag', type: 'script', initiator: 'https://Page.ch/x' })!;
  assert.equal(r.spec, 'https://ex.com/Path');
  assert.equal(r.host, 'ex.com');
  assert.equal(r.spec.slice(r.hostStart, r.hostEnd), 'ex.com');
  assert.equal(r.initiator, 'page.ch');
  assert.equal(prepareRequest({ url: 'not a url', type: 'script' }), null);
});

test('decide: priority first, then Chrome action order', () => {
  const R = (type: string, priority: number, id = 0): MatchRule & { id: number } => ({ id, priority, action: { type }, condition: {} });
  assert.equal(decide([]).outcome, 'none');
  assert.equal(decide([R('block', 21), R('allow', 30)]).outcome, 'allow');
  assert.equal(decide([R('block', 40), R('allow', 30)]).outcome, 'block');
  // equal priority: allow > allowAllRequests > block > upgradeScheme > redirect
  assert.equal(decide([R('redirect', 5, 1), R('block', 5, 2)]).winner?.id, 2);
  assert.equal(decide([R('block', 5, 1), R('allow', 5, 2)]).winner?.id, 2);
  assert.equal(decide([R('allowAllRequests', 5, 1), R('allow', 5, 2)]).winner?.id, 2);
  assert.equal(decide([R('block', 5, 1), R('allowAllRequests', 5, 2)]).winner?.id, 2);
  assert.equal(decide([R('redirect', 5, 1), R('upgradeScheme', 5, 2)]).winner?.id, 2);
  assert.equal(decide([R('redirect', 22, 1), R('block', 21, 2)]).outcome, 'redirect');
  // priority defaults to 1
  assert.equal(decide<MatchRule>([{ id: 1, action: { type: 'block' }, condition: {} }, R('redirect', 2, 9)]).winner?.id, 9);
});

test('decide: modifyHeaders apply only above the winning allow and never with a block', () => {
  const R = (type: string, priority: number, id = 0): MatchRule & { id: number } => ({ id, priority, action: { type }, condition: {} });
  const alone = decide([R('modifyHeaders', 1, 1), R('modifyHeaders', 5000, 2)]);
  assert.equal(alone.outcome, 'modifyHeaders');
  assert.deepEqual(alone.headers.map((r) => r.id), [2, 1]);
  const allowed = decide([R('allow', 30, 1), R('modifyHeaders', 1, 2), R('modifyHeaders', 5000, 3)]);
  assert.equal(allowed.winner?.id, 1);
  assert.deepEqual(allowed.headers.map((r) => r.id), [3]);
  assert.equal(allowed.outcome, 'modifyHeaders');
  assert.equal(decide([R('allow', 30, 1), R('modifyHeaders', 1, 2)]).outcome, 'allow');
  const blocked = decide([R('block', 21, 1), R('modifyHeaders', 5000, 2)]);
  assert.equal(blocked.outcome, 'block');
  assert.deepEqual(blocked.headers, []);
});
