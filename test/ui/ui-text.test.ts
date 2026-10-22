// Tests for the text helpers that keep long content inside its box
// (src/ui/shared/text.ts).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hasInvisible, markInvisible, truncateMiddle, withUnit } from '../../src/ui/shared/text.ts';

test('truncateMiddle keeps short hosts unchanged', () => {
  assert.equal(truncateMiddle('20min.ch', 24), '20min.ch');
  assert.equal(truncateMiddle('20min.ch', 8), '20min.ch');
});

test('truncateMiddle keeps the start and the last two labels', () => {
  const out = truncateMiddle('secure-login-ubs.ch-verify.top', 22);
  assert.equal(out, 'secure-l…ch-verify.top');
  assert.equal(out.length, 22);
});

test('truncateMiddle cuts evenly when the tail alone is too long', () => {
  const host = 'portal.kunden-service.sparkasse-mittelland-emmental.ch';
  const out = truncateMiddle(host, 24);
  assert.equal(out.length, 24);
  assert.equal(out, 'portal.kunde…emmental.ch');
});

test('truncateMiddle never returns more than max characters', () => {
  for (const max of [3, 5, 10, 17, 30]) {
    assert.ok(truncateMiddle('a'.repeat(60) + '.example.com', max).length <= max);
  }
});

test('withUnit joins with a non-breaking space', () => {
  assert.equal(withUnit("1'248", 'Zeichen'), "1'248 Zeichen");
  assert.equal(withUnit(1.2, 'MB'), '1.2 MB');
});

test('markInvisible shows bidi and zero-width characters', () => {
  assert.equal(markInvisible('iex‮)1(gpj.exe'), 'iex⟨U+202E⟩)1(gpj.exe');
  assert.equal(markInvisible('a​b'), 'a⟨U+200B⟩b');
  assert.equal(markInvisible('plain command'), 'plain command');
});

test('hasInvisible detects hidden characters repeatedly', () => {
  assert.equal(hasInvisible('x⁦y'), true);
  assert.equal(hasInvisible('x⁦y'), true);
  assert.equal(hasInvisible('xy'), false);
});
