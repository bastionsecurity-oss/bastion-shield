// Unit tests for the dashboard command palette matching (palette-core.ts).
// Run with npm test.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import test from 'node:test';
import assert from 'node:assert/strict';

const ROOT = new URL('../../src', import.meta.url).href;
const { fold, matchText, rankEntries } = await import(`${ROOT}/ui/dashboard/palette-core.ts`);

const E = [
  { id: 'view:privacy', group: 'views', label: 'Datenschutz' },
  { id: 'view:settings', group: 'views', label: 'Einstellungen' },
  { id: 'set:clip', group: 'settings', label: 'ClickFix-Schutz', hint: 'Datenschutz › Zwischenablage', keywords: 'Verhindert, dass Websites heimlich Befehle in die Zwischenablage legen' },
  { id: 'set:gpc', group: 'settings', label: 'Global Privacy Control', hint: 'Datenschutz › Signale' },
  { id: 'list:easy', group: 'lists', label: 'EasyList' },
  { id: 'act:rail', group: 'actions', label: 'Seitenleiste einklappen' },
  { id: 'act:nerd', group: 'actions', label: 'Nerd-Modus einschalten', hidden: true },
];

test('fold drops case and diacritics', () => {
  assert.equal(fold('Über Größe'), 'uber große');
  assert.equal(fold('Éèü'), 'eeu');
});

test('matchText: prefix > word start > substring > subsequence; ranges point into the label', () => {
  const prefix = matchText('daten', 'Datenschutz')!;
  const word = matchText('schutz', 'ClickFix-Schutz')!;
  const inner = matchText('schutz', 'Datenschutz')!;
  const subseq = matchText('dnsch', 'Datenschutz')!;
  assert.ok(prefix.score > word.score && word.score > inner.score && inner.score > subseq.score);
  assert.deepEqual(prefix.ranges, [[0, 5]]);
  assert.deepEqual(word.ranges, [[9, 15]]);
  assert.equal(matchText('xyz', 'Datenschutz'), null);
  // Umlauts typed without them still match, highlighted in place.
  assert.deepEqual(matchText('uber', 'Über')!.ranges, [[0, 4]]);
});

test('rankEntries: empty query lists sections and visible actions only', () => {
  const ids = rankEntries(E, '').map((h: { entry: { id: string } }) => h.entry.id);
  assert.deepEqual(ids, ['view:privacy', 'view:settings', 'act:rail']);
});

test('rankEntries: settings are found by what they do (keywords), not only by name', () => {
  const top = rankEntries(E, 'zwischenablage')[0];
  assert.equal(top.entry.id, 'set:clip');
  assert.deepEqual(top.ranges, []); // matched on hint/keywords: nothing to highlight in the label
  assert.equal(rankEntries(E, 'clickfix')[0].entry.id, 'set:clip');
});

test('rankEntries: hidden entries need a real substring match', () => {
  assert.ok(rankEntries(E, 'nerd').some((h: { entry: { id: string } }) => h.entry.id === 'act:nerd'));
  assert.ok(!rankEntries(E, 'nmd').some((h: { entry: { id: string } }) => h.entry.id === 'act:nerd'));
  assert.ok(!rankEntries(E, '').some((h: { entry: { id: string } }) => h.entry.id === 'act:nerd'));
});

test('rankEntries: best match first, limit respected', () => {
  assert.equal(rankEntries(E, 'easy')[0].entry.id, 'list:easy');
  assert.equal(rankEntries(E, 'e', 2).length, 2);
});
