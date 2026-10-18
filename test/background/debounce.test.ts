// Tests for converting Brave's debounce.json to DNR regexSubstitution rules
// (src/background/debounce.ts). The generated regexes use only RE2 syntax,
// which JavaScript RegExp also understands, so we can test matching here.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { bounceSubstitution, convertDebounceRules, debounceRegex, matchPatternPrefix, patternFixedHost } from '../../src/background/debounce.ts';
import { DEBOUNCE_PRIORITY } from '../../src/background/rules.ts';

const BOUNCE = 'chrome-extension://abcdefghijklmnop/pages/bounce.html';

/** Apply a rule like DNR would: match, then substitute \1 into the redirect. */
function apply(regex: string, url: string): string | null {
  const m = new RegExp(regex).exec(url);
  return m ? `${BOUNCE}#${m[1]}` : null;
}

test('match pattern prefixes', () => {
  assert.deepEqual(matchPatternPrefix('*://*.example.com/r?*'), { prefix: '^https?://(?:[^/?#]*\\.)?example\\.com(?::[0-9]+)?/r\\?', queryOpen: true });
  assert.ok('error' in matchPatternPrefix('*://www.tkqlhce.com/click-'));
  assert.ok('error' in matchPatternPrefix('ftp://x.com/*'));
  assert.ok('error' in matchPatternPrefix('*://a.*.com/*'));
});

test('query parameter extraction', () => {
  const r = debounceRegex('*://*.prsm1.com/r?*', 'url');
  assert.ok('regex' in r);
  const re = (r as { regex: string }).regex;
  assert.equal(apply(re, 'https://x.prsm1.com/r?url=https%3A%2F%2Fshop.ch%2Fp&x=1'), `${BOUNCE}#https%3A%2F%2Fshop.ch%2Fp`);
  assert.equal(apply(re, 'https://prsm1.com/r?a=1&url=https://shop.ch/p#frag'), `${BOUNCE}#https://shop.ch/p`);
  // First occurrence wins (as in Brave).
  assert.equal(apply(re, 'https://prsm1.com/r?url=https://a.ch/&url=https://b.ch/'), `${BOUNCE}#https://a.ch/`);
  // Not a URL value, a different parameter, another host, another path.
  assert.equal(apply(re, 'https://prsm1.com/r?url=foo'), null);
  assert.equal(apply(re, 'https://prsm1.com/r?xurl=https://a.ch/'), null);
  assert.equal(apply(re, 'https://notprsm1.com/r?url=https://a.ch/'), null);
  assert.equal(apply(re, 'https://prsm1.com/q?url=https://a.ch/'), null);
});

test('wildcard in the path before the query', () => {
  const re = (debounceRegex('*://*.dttq.net/c/*', 'u') as { regex: string }).regex;
  assert.equal(apply(re, 'https://a.dttq.net/c/123/456?u=https%3A%2F%2Fx.ch'), `${BOUNCE}#https%3A%2F%2Fx.ch`);
  assert.equal(apply(re, 'https://a.dttq.net/d/123?u=https%3A%2F%2Fx.ch'), null);
  const mid = (debounceRegex('*://backerkit.com/ahoy/messages/*/click?*', 'url') as { regex: string }).regex;
  assert.equal(apply(mid, 'https://backerkit.com/ahoy/messages/abc/click?url=https://k.ch/'), `${BOUNCE}#https://k.ch/`);
});

test('parameter names are case-sensitive', () => {
  const re = (debounceRegex('*://t.cfjump.com/*', 'Url') as { regex: string }).regex;
  assert.notEqual(apply(re, 'https://t.cfjump.com/1?Url=https://a.ch'), null);
  assert.equal(apply(re, 'https://t.cfjump.com/1?url=https://a.ch'), null);
});

test('conversion skips what DNR cannot express', () => {
  const { rules, skipped } = convertDebounceRules(
    [
      { include: ['*://*.a.com/r?*', '*://*.a.com/r?*'], exclude: [], action: 'redirect', param: 'url' },
      { include: ['*://b.com/*'], exclude: [], action: 'base64,redirect', param: 'cr' },
      { include: ['*://c.com/*'], exclude: [], action: 'regex-path', param: '^/(.*)$', pref: 'brave.de_amp.enabled' },
      { include: ['*://d.com/*'], exclude: [], action: 'redirect', param: 'u', prepend_scheme: 'https' },
      { include: ['*://e.com/*'], exclude: ['*://e.com/x*'], action: 'redirect', param: 'u' },
      { include: ['*://f.com/click-'], exclude: [], action: 'redirect', param: 'u' },
      'garbage',
    ],
    BOUNCE,
  );
  assert.equal(rules.length, 3, 'duplicate include deduplicated; de-AMP rule off by default');
  assert.deepEqual(rules[0].action, { type: 'redirect', redirect: { regexSubstitution: `${BOUNCE}?from=a.com#\\1` } });
  assert.equal(rules[0].priority, DEBOUNCE_PRIORITY);
  assert.deepEqual(rules[0].condition.resourceTypes, ['main_frame']);
  assert.equal(rules[0].condition.isUrlFilterCaseSensitive, true);
  assert.deepEqual(rules[1].action, { type: 'redirect', redirect: { regexSubstitution: `${BOUNCE}?from=b.com#b64:\\1` } });
  assert.deepEqual(rules[2].action, { type: 'redirect', redirect: { regexSubstitution: `${BOUNCE}?from=d.com#https://\\1` } });
  assert.deepEqual(
    skipped.map((s) => s.pattern),
    ['*://e.com/*', '*://f.com/click-'],
  );
  const withAmp = convertDebounceRules([{ include: ['*://c.com/*'], exclude: [], action: 'regex-path', param: '^/(.*)$', pref: 'brave.de_amp.enabled' }], BOUNCE, { deAmp: true });
  assert.equal(withAmp.rules.length, 1);
  const unknownPref = convertDebounceRules([{ include: ['*://c.com/*'], exclude: [], action: 'regex-path', param: '^/(.*)$', pref: 'brave.other' }], BOUNCE, { deAmp: true });
  assert.equal(unknownPref.rules.length, 0);
  assert.equal(unknownPref.skipped.length, 1);
});

test('fixed include hosts are passed to the bounce page as ?from=', () => {
  assert.equal(patternFixedHost('*://*.example.com/r?*'), 'example.com');
  assert.equal(patternFixedHost('https://t.example.com/*'), 't.example.com');
  assert.equal(patternFixedHost('*://t.example.com:8080/*'), 't.example.com');
  assert.equal(patternFixedHost('*://*/*'), null);
  assert.equal(patternFixedHost('*://a.*.com/*'), null);
  assert.equal(patternFixedHost('garbage'), null);
  assert.equal(bounceSubstitution(BOUNCE, '*://*.a.com/*', '\\1'), `${BOUNCE}?from=a.com#\\1`);
  assert.equal(bounceSubstitution(BOUNCE, '*://*/*', '\\1'), `${BOUNCE}#\\1`);
  // Wildcard hosts still convert, just without the hint.
  const { rules } = convertDebounceRules([{ include: ['*://*/out?*'], exclude: [], action: 'redirect', param: 'u' }], BOUNCE);
  assert.equal(rules[0].action.redirect!.regexSubstitution, `${BOUNCE}#\\1`);
});

/** Apply a converted rule like DNR: regex match, then substitute \N in the redirect. */
function applyRule(r: { condition: { regexFilter?: string }; action: { redirect?: { regexSubstitution?: string } } }, url: string): string | null {
  const m = new RegExp(r.condition.regexFilter!).exec(url);
  if (!m) return null;
  return r.action.redirect!.regexSubstitution!.replace(/\\(\d)/g, (_, n: string) => m[Number(n)] ?? '');
}

test('prepend_scheme captures only scheme-less values', () => {
  const { rules } = convertDebounceRules([{ include: ['*://www.shareasale.com/r.cfm?*'], exclude: [], action: 'redirect', param: 'urllink', prepend_scheme: 'https' }], BOUNCE);
  assert.equal(applyRule(rules[0], 'https://www.shareasale.com/r.cfm?b=1&urllink=www.shop.ch%2Fp'), `${BOUNCE}?from=www.shareasale.com#https://www.shop.ch%2Fp`);
  assert.equal(applyRule(rules[0], 'https://www.shareasale.com/r.cfm?urllink=https%3A%2F%2Fwww.shop.ch'), null);
});

test('regex-path rules: path regex cannot leak into query; captures concatenated', () => {
  const amp = convertDebounceRules(
    [{ include: ['*://*.cdn.ampproject.org/c/s/*'], exclude: [], action: 'regex-path', param: '^/c/s/(.*)$', prepend_scheme: 'https', pref: 'brave.de_amp.enabled' }],
    BOUNCE,
    { deAmp: true },
  ).rules[0];
  assert.equal(applyRule(amp, 'https://www-nzz-ch.cdn.ampproject.org/c/s/www.nzz.ch/artikel?amp_js_v=0.1#x'), `${BOUNCE}?from=cdn.ampproject.org#https://www.nzz.ch/artikel`);
  assert.equal(applyRule(amp, 'https://www-nzz-ch.cdn.ampproject.org/v/s/www.nzz.ch/'), null);
  const turbo = convertDebounceRules(
    [{ include: ['*://*.turbopages.org/*/s/*'], exclude: [], action: 'regex-path', param: '^/([^/]+)/s(/.*)$', prepend_scheme: 'https' }],
    BOUNCE,
  ).rules[0];
  assert.equal(applyRule(turbo, 'https://x.turbopages.org/example.ru/s/news/1?turbo=1'), `${BOUNCE}?from=turbopages.org#https://example.ru/news/1`);
  const reddit = convertDebounceRules([{ include: ['*://click.redditmail.com/*'], exclude: [], action: 'regex-path', param: '^/CL0/([^/]+)/.*$' }], BOUNCE).rules[0];
  assert.equal(applyRule(reddit, 'https://click.redditmail.com/CL0/https:%2F%2Fwww.reddit.com%2Fr%2Fx/1/abc?q=1'), `${BOUNCE}?from=click.redditmail.com#https:%2F%2Fwww.reddit.com%2Fr%2Fx`);
});

test('regex-path-template fills the template', () => {
  const { rules, skipped } = convertDebounceRules(
    [
      { include: ['*://y2u.be/*'], exclude: [], action: 'regex-path-template', param: '^/([^/]+)$', redirect_url_template: 'https://www.youtube.com/watch?v=$1' },
      { include: ['*://bad.example/*'], exclude: [], action: 'regex-path-template', param: '^/([^/]+)/(x)$', redirect_url_template: 'https://a.ch/$1' },
      { include: ['*://bad2.example/*'], exclude: [], action: 'regex-path', param: '/no-anchor/(x)' },
    ],
    BOUNCE,
  );
  assert.equal(rules.length, 1);
  assert.equal(applyRule(rules[0], 'https://y2u.be/dQw4w9WgXcQ'), `${BOUNCE}?from=y2u.be#https://www.youtube.com/watch?v=dQw4w9WgXcQ`);
  assert.equal(applyRule(rules[0], 'https://y2u.be/a/b'), null);
  assert.deepEqual(
    skipped.map((s) => s.reason),
    ['template placeholders do not match capture groups', 'path regex must be anchored'],
  );
});

test('base64 parameters are captured only when they encode an http(s) URL', () => {
  const re = (debounceRegex('*://*.ouo.today/*', 'cr', 'base64') as { regex: string }).regex;
  const target = Buffer.from('https://example.org/x').toString('base64url');
  const m = new RegExp(re).exec(`https://a.ouo.today/go?cr=${target}&x=1`);
  assert.equal(m?.[1], target);
  assert.equal(new RegExp(re).exec(`https://a.ouo.today/go?cr=${Buffer.from('not a url').toString('base64')}`), null);
  const padded = Buffer.from('http://a.ch/?').toString('base64');
  assert.ok(padded.endsWith('='));
  assert.equal(new RegExp(re).exec(`https://ouo.today/?cr=${padded.replace(/=/g, '%3D')}`)?.[1], padded.replace(/=/g, '%3D'));
});

test('the vendored Brave list converts within the regex budget', () => {
  const path = fileURLToPath(new URL('../../vendor/brave-lists/debounce.json', import.meta.url));
  const data = JSON.parse(readFileSync(path, 'utf8')) as unknown;
  const { rules, skipped } = convertDebounceRules(data, BOUNCE, { deAmp: true });
  assert.ok(skipped.length < 10, JSON.stringify(skipped));
  assert.ok(rules.length > 50, `expected many rules, got ${rules.length}`);
  assert.ok(rules.length < 1000 - 200, 'leaves room for custom regex rules');
  for (const r of rules) {
    const re = r.condition.regexFilter!;
    assert.doesNotThrow(() => new RegExp(re));
    assert.ok(re.length < 400, 'small enough for the 2 KB RE2 memory limit');
    assert.ok(!/\(\?[=!<]/.test(re), 'no lookaround');
  }
  // A real example from the list.
  const hit = rules.some((r) => apply(r.condition.regexFilter!, 'https://go.skimresources.com/?id=1&url=https%3A%2F%2Fwww.galaxus.ch%2F') !== null);
  assert.ok(hit);
});
