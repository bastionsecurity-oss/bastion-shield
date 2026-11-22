// Store listing descriptions (store/listing/<lang>.txt) and the Chrome Web
// Store keyword-spam rules: no list of third-party brands in the text (the
// store allows five at most and asks for a link instead), and no key term
// five times or more, counted by word stem. The list names live in
// docs/FILTER-LISTS.md.
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

/** The product's key terms per language, as word stems (so «blocks» and «blocked» count together). */
const KEY_TERMS: Record<string, Record<string, RegExp>> = {
  en: { block: /block/gi, list: /\blist/gi, filter: /filter/gi, track: /track/gi, protect: /protect/gi, privacy: /privacy/gi, ads: /\bads?\b|advertis/gi },
  de: { block: /blockier/gi, list: /liste/gi, filter: /filter/gi, track: /track/gi, protect: /schutz|schütz/gi, ads: /werb/gi },
  fr: { block: /bloqu|blocage/gi, list: /liste/gi, filter: /filtre/gi, track: /traqueur|pistage/gi, protect: /protec|protég/gi, ads: /publicit/gi },
  it: { block: /blocc/gi, list: /\blist[ae]/gi, filter: /filtr/gi, track: /tracc|tracker/gi, protect: /protez|protett/gi, ads: /pubblicit/gi },
};

for (const [lang, terms] of Object.entries(KEY_TERMS)) {
  const text = readFileSync(join(LISTING_DIR, `${lang}.txt`), 'utf8');

  test(`store listing ${lang}: names no third-party filter projects`, () => {
    assert.equal(THIRD_PARTY.exec(text)?.[0], undefined);
    assert.ok(text.includes(FILTER_LISTS_URL), 'links to docs/FILTER-LISTS.md for the full list');
  });

  test(`store listing ${lang}: uses no key term five times or more`, () => {
    const prose = text.replace(/https?:\S+/g, '');
    const counts = Object.fromEntries(Object.entries(terms).map(([name, stem]) => [name, prose.match(stem)?.length ?? 0]));
    const over = Object.entries(counts).filter(([, n]) => n >= 5);
    assert.deepEqual(over, [], JSON.stringify(counts));
  });
}
