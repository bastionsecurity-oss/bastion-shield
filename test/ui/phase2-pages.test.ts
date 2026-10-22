// Bastion Shield — pure logic of the extension pages (phase 2: blocked.html,
// bounce.html): category variants, host slot splitting, chip length, brand.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { SLOT, blockCopyKeys, blockKind, chipMaxChars, splitAtSlot, splitBrand } from '../../src/pages/pages-core.ts';
import { formatMessage } from '../../src/ui/shared/i18n.ts';
import { truncateMiddle } from '../../src/ui/shared/text.ts';

const LOCALES = ['de', 'en', 'fr', 'it'] as const;
const bundle = (l: string) =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`../../src/_locales/${l}/messages.json`, import.meta.url)), 'utf8')) as Record<
    string,
    { message: string; placeholders?: Record<string, { content: string }> }
  >;

test('blockKind maps list categories to the three page variants', () => {
  assert.equal(blockKind('security'), 'security');
  for (const c of ['ads', 'privacy', 'regional']) assert.equal(blockKind(c), 'tracking');
  for (const c of ['annoyances', 'custom', null, undefined, '']) assert.equal(blockKind(c), 'other');
});

test('every variant names keys that exist in all locales; texts carry the host slot', () => {
  for (const l of LOCALES) {
    const b = bundle(l);
    for (const kind of ['security', 'tracking', 'other'] as const) {
      const keys = blockCopyKeys(kind);
      for (const k of Object.values(keys)) assert.ok(b[k], `${l}: ${k} exists`);
      const text = formatMessage(b[keys.text], [SLOT]);
      assert.ok(text.includes(SLOT), `${l}: ${keys.text} has the host placeholder`);
      assert.ok(!text.includes('·'), `${l}: no middle dot`);
    }
    for (const k of ['bounceOpening', 'bounceSameSiteText']) assert.ok(formatMessage(b[k], [SLOT]).includes(SLOT), `${l}: ${k} has $1`);
  }
  assert.equal(formatMessage(bundle('de').blockedTitleSecurity), 'Gefährliche Seite blockiert');
  assert.equal(formatMessage(bundle('de').blockedProceed), 'Trotzdem öffnen…');
});

test('splitAtSlot splits around the host', () => {
  assert.deepEqual(splitAtSlot(`${SLOT} ist bekannt für Betrug.`), { before: '', after: 'ist bekannt für Betrug.', hasSlot: true });
  assert.deepEqual(splitAtSlot(`Weiter zu ${SLOT}`), { before: 'Weiter zu', after: '', hasSlot: true });
  assert.deepEqual(splitAtSlot(`Kein Tracking. Ziel: ${SLOT}`), { before: 'Kein Tracking. Ziel:', after: '', hasSlot: true });
  assert.deepEqual(splitAtSlot('ohne Platzhalter'), { before: '', after: 'ohne Platzhalter', hasSlot: false });
});

test('chipMaxChars: two lines of a mono chip, never below 12', () => {
  assert.equal(chipMaxChars(536, 9.6, 2), 110);
  assert.equal(chipMaxChars(318, 9.6, 2), 66);
  assert.equal(chipMaxChars(40, 9.6, 2), 12);
  assert.equal(chipMaxChars(0, 9.6), Number.POSITIVE_INFINITY);
  assert.equal(chipMaxChars(500, 0), Number.POSITIVE_INFINITY);
  const host = 'secure-login-ubs.ch-verify-kundenportal-session-7731-2208-4410-authentification-service-check.top';
  const cut = truncateMiddle(host, chipMaxChars(318, 9.6, 2));
  assert.ok(cut.length <= 66 && cut.includes('…') && cut.endsWith('service-check.top') && cut.startsWith('secure-login'));
});

test('splitBrand marks every «Bastion Shield»', () => {
  assert.deepEqual(splitBrand('Bastion Shield prüft lokal.'), [
    { text: 'Bastion Shield', brand: true },
    { text: ' prüft lokal.', brand: false },
  ]);
  assert.deepEqual(splitBrand('Le module Bastion Shield vérifie.'), [
    { text: 'Le module ', brand: false },
    { text: 'Bastion Shield', brand: true },
    { text: ' vérifie.', brand: false },
  ]);
  assert.deepEqual(splitBrand('kein Name'), [{ text: 'kein Name', brand: false }]);
});
