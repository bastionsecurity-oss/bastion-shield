// Tests for nerd mode lookalike-domain detection: the RFC 3492 decoder,
// the confusable skeleton, the capped edit distance and findLookalike's
// homoglyph / typo / combo rules with their false-positive guards
// (src/shared/lookalike.ts).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { domainToASCII, domainToUnicode } from 'node:url';
import { decodeLabel, DEFAULT_PROTECTED, editDistance, findLookalike, punycodeDecode, skeleton } from '../../src/shared/lookalike.ts';

const P = DEFAULT_PROTECTED;
const hit = (host: string, list: readonly string[] = P) => findLookalike(host, list);
const reason = (host: string, list: readonly string[] = P) => hit(host, list)?.reason ?? null;
const target = (host: string, list: readonly string[] = P) => hit(host, list)?.target ?? null;

test('punycode decoder matches the platform for real IDN labels', () => {
  for (const u of ['pаypal', 'аррӏе', 'gооgle', 'münchen', 'bücher', 'zürich', '日本語', 'ελληνικά', 'ü', 'a-ü-b']) {
    const ascii = domainToASCII(`${u}.com`).split('.')[0];
    assert.ok(ascii.startsWith('xn--'), ascii);
    assert.equal(punycodeDecode(ascii.slice(4)), domainToUnicode(`${ascii}.com`).split('.')[0], u);
    assert.equal(decodeLabel(ascii), u.normalize('NFC').toLowerCase());
  }
  // RFC 3492 sample (7.1 L: Japanese "3年B組金八先生")
  assert.equal(punycodeDecode('3B-ww4c5e180e575a65lsy2b'), '3年B組金八先生');
});

test('punycode decoder rejects malformed input instead of throwing', () => {
  for (const bad of ['', '-', '99999999999', 'abc-!!!', 'zzzzzzzzzzzzzzzzzz', 'ü-abc']) {
    const r = punycodeDecode(bad);
    assert.ok(r === null || typeof r === 'string');
  }
  assert.equal(punycodeDecode('ü-abc'), null);
  assert.equal(punycodeDecode('abc-!!'), null);
  assert.equal(decodeLabel('xn--!!'), 'xn--!!');
  assert.equal(decodeLabel('example'), 'example');
});

test('skeleton folds confusables, diacritics, digits and letter pairs', () => {
  assert.equal(skeleton('pаypal'), 'paypal'); // Cyrillic а
  assert.equal(skeleton('аррӏе'), 'apple');
  assert.equal(skeleton('gοοgle'), 'google'); // Greek omicron
  assert.equal(skeleton('paypa1'), 'paypal');
  assert.equal(skeleton('g00gle'), 'google');
  assert.equal(skeleton('rnicrosoft'), 'microsoft');
  assert.equal(skeleton('vvikipedia'), 'wikipedia');
  assert.equal(skeleton('pöstfinance'), 'postfinance');
  assert.equal(skeleton('example'), 'example');
});

test('edit distance: substitutions, insertions, transpositions, cap', () => {
  assert.equal(editDistance('google', 'google'), 0);
  assert.equal(editDistance('google', 'gogle'), 1);
  assert.equal(editDistance('google', 'googel'), 1); // transposition
  assert.equal(editDistance('paypal', 'paypai'), 1);
  assert.equal(editDistance('microsoft', 'micorsfot'), 2);
  assert.equal(editDistance('microsoft', 'example', 2), 3);
  assert.equal(editDistance('a', 'abcdef', 2), 3);
});

test('never flags protected domains, their subdomains, or the brand under another TLD', () => {
  for (const h of [
    'paypal.com', 'www.paypal.com', 'login.microsoftonline.com', 'accounts.google.com', 'mail.google.com',
    'google.ch', 'google.de', 'google.com.au', 'accounts.google.co.uk', 'amazon.de', 'www.amazon.co.uk',
    'apple.ch', 'ebanking.raiffeisen.ch', 'www.postfinance.ch', 'e-finance.postfinance.ch', 'www.post.ch',
    'paypal.co', 'outlook.live.com', 'zkb.ch', 'www.zkb.ch',
  ]) {
    assert.equal(hit(h), null, h);
  }
});

test('ordinary sites stay quiet (false-positive guard)', () => {
  for (const h of [
    'example.com', 'github.com', 'wikipedia.org', 'nzz.ch', 'srf.ch', 'admin.ch', 'migros.ch', 'coop.ch',
    'cloud.com', 'apply.com', 'apples.com', 'twin.com', 'email.com', 'paypay.ne.jp', 'officer.com',
    'offices.com', 'live-stream.tv', 'livescore.com', 'office-depot.com', 'google-analytics.com',
    'googleapis.com', 'amazonaws.com', 'microsoftedge.com', 'post.com', 'postbank.de', 'postnord.se',
    'ubs-arena.com', 'zkb-cup.ch', 'raiffeisen.at', 'netflixtechblog.com', 'facebookmail.com',
    'localhost', '192.168.1.1', '[::1]', '', 'münchen.de', 'xn--mnchen-3ya.de',
  ]) {
    assert.equal(hit(h), null, h);
  }
});

test('homoglyphs: punycode IDN and ASCII lookalikes', () => {
  assert.deepEqual(hit('xn--pypal-4ve.com'), { host: 'xn--pypal-4ve.com', target: 'paypal.com', reason: 'homoglyph' });
  assert.equal(target('xn--80ak6aa92e.com'), 'apple.com'); // аррӏе.com
  assert.equal(reason('xn--ggle-55da.com'), 'homoglyph'); // gооgle.com
  assert.equal(target('xn--microsft-sbh.com'), 'microsoft.com');
  assert.equal(target('xn--postfinnce-5qi.ch'), 'postfinance.ch');
  assert.equal(target(domainToASCII('ubѕ.com')), 'ubs.com'); // Cyrillic dze, short label still matched by skeleton
  assert.equal(reason('paypa1.com'), 'homoglyph');
  assert.equal(reason('g00gle.com'), 'homoglyph');
  assert.equal(reason('rnicrosoft.com'), 'homoglyph');
  assert.equal(reason('www.rnicrosoft.net'), 'homoglyph');
  assert.equal(reason('1ive.com'), 'homoglyph');
  // IDN one edit away from the skeleton (Cyrillic а plus a dropped letter)
  assert.equal(reason(domainToASCII('pаypl.com')), 'homoglyph');
});

test('typos: distance 1, or 2 for long labels; other TLDs too', () => {
  assert.deepEqual(hit('gogle.com'), { host: 'gogle.com', target: 'google.com', reason: 'typo' });
  assert.equal(reason('googel.com'), 'typo');
  assert.equal(reason('paypai.com'), 'typo');
  assert.equal(reason('paypal-.net'), 'typo');
  assert.equal(reason('pay-pal.com'), 'typo');
  assert.equal(reason('amazom.de'), 'typo');
  assert.equal(reason('netfix.com'), 'typo');
  assert.equal(reason('micosoft.com'), 'typo');
  assert.equal(reason('micorsfot.com'), 'typo'); // 9+ letters: two edits
  assert.equal(reason('postfinanz.ch'), 'typo');
  assert.equal(reason('raifeisen.ch'), 'typo');
  assert.equal(reason('swissom.ch'), 'typo');
  assert.equal(reason('appel.com'), 'typo'); // 5 letters: transposition still counts
  assert.equal(reason('gmaill.com'), 'typo'); // 5 letters: insertion still counts
  assert.equal(reason('www.faceboook.com'), 'typo');
  // Short labels never get a typo check.
  assert.equal(hit('zkbb.ch'), null);
  assert.equal(hit('ubss.com'), null);
  assert.equal(hit('lve.com'), null);
});

test('combo-squatting: brand token plus phishing words, or the brand domain spelled inside', () => {
  assert.deepEqual(hit('paypal-login-secure.com'), { host: 'paypal-login-secure.com', target: 'paypal.com', reason: 'combo' });
  assert.equal(target('microsoft.account-verify.net'), 'microsoft.com');
  assert.equal(reason('microsoft.account-verify.net'), 'combo');
  assert.equal(reason('secure-ubs-login.com'), 'combo');
  assert.equal(reason('ubs.ebanking-help.ch'), 'combo');
  assert.equal(reason('paypallogin.net'), 'combo');
  assert.equal(reason('paypal.com.evil.net'), 'combo');
  assert.equal(reason('paypal-com.xyz'), 'combo');
  assert.equal(reason('post-ch-paket.com'), 'combo');
  assert.equal(reason('post-paket-zustellung.com'), 'combo');
  assert.equal(reason('twint-konto-verifizierung.ch'), 'combo');
  assert.equal(reason('apple-support-id.com'), 'combo');
  assert.equal(reason('amazon-delivery-tracking.info'), 'combo');
  assert.equal(reason('live.com.signin.top'), 'combo');
  assert.equal(reason('office.com-secure.app'), 'combo');
  // Everyday words alone are not a brand.
  assert.equal(hit('live-login.tv'), null);
  assert.equal(hit('office-support.org'), null);
});

test('user and policy domains extend the list; bad entries are ignored', () => {
  const list = [...P, 'MyBank.CH', 'www.example-bank.com', '', ' ', '10.0.0.1', 'localhost', 42 as unknown as string];
  assert.equal(target('mybnk.ch', list), 'mybank.ch');
  assert.equal(reason('mybank-login.ch', list), 'combo');
  assert.equal(target('exarnple-bank.com', list), 'example-bank.com');
  assert.equal(hit('ebanking.mybank.ch', list), null);
  assert.equal(findLookalike('paypa1.com', []), null);
  assert.equal(findLookalike(undefined as unknown as string, P), null);
  assert.equal(findLookalike('paypa1.com', null as unknown as string[]), null);
  // Case, trailing dot and www. are normalised.
  assert.equal(reason('WWW.PAYPA1.COM.'), 'homoglyph');
  assert.equal(hit('WWW.PAYPA1.COM.')?.host, 'www.paypa1.com', 'the visited hostname is reported');
});

test('the default list is small, lower-case and registrable', () => {
  assert.ok(P.length >= 15 && P.length <= 30);
  for (const d of P) assert.match(d, /^[a-z0-9-]+\.[a-z]{2,}$/);
  for (const d of P) assert.equal(hit(d), null, d);
});
