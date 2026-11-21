// Store listing descriptions (store/listing/<lang>.txt) and the Chrome Web
// Store keyword-spam rules: no list of third-party brands in the text (the
// store allows five at most and asks for a link instead), and no key phrase
// five times or more. The list names live in docs/FILTER-LISTS.md.
// https://developer.chrome.com/docs/webstore/program-policies/spam-faq#keyword-spam
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const LISTING_DIR = join(import.meta.dirname, '..', '..', 'store', 'listing');
const FILTER_LISTS_URL = 'https://github.com/bastionsecurity-oss/bastion-shield/blob/main/docs/FILTER-LISTS.md';

/** Third-party filter projects and products: named in the docs, not in the store text. */
const THIRD_PARTY = /uBlock|uBO\b|EasyList|EasyPrivacy|Peter Lowe|URLhaus|AdGuard|Fanboy|Brave Shields/i;

/** The phrase for «filter list» per language, singular and plural. */
const FILTER_LIST: Record<string, RegExp> = {
  en: /filter lists?/gi,
  de: /filterlisten?/gi,
  fr: /listes? de filtres/gi,
  it: /list[ae] di filtri/gi,
};

for (const [lang, phrase] of Object.entries(FILTER_LIST)) {
  const text = readFileSync(join(LISTING_DIR, `${lang}.txt`), 'utf8');

  test(`store listing ${lang}: names no third-party filter projects`, () => {
    assert.equal(THIRD_PARTY.exec(text)?.[0], undefined);
    assert.ok(text.includes(FILTER_LISTS_URL), 'links to docs/FILTER-LISTS.md for the full list');
  });

  test(`store listing ${lang}: says «filter list» fewer than five times`, () => {
    const count = text.match(phrase)?.length ?? 0;
    assert.ok(count < 5, `${count} times`);
  });
}
