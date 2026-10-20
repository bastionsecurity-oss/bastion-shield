// Unit tests for the «Cyber-Vorfall?» link and the data / time saved estimate.
// Run with npm test.
import test from 'node:test';
import assert from 'node:assert/strict';

const ROOT = new URL('../../src', import.meta.url).href;
const { incidentUrl } = await import(`${ROOT}/ui/shared/incident.ts`);
const { estimateSavings, estimateFromSample, fmtBytes, fmtDuration, savedRequestsByType } = await import(`${ROOT}/ui/shared/savings.ts`);
const { countEvent, eventKey, sampleType } = await import(`${ROOT}/ui/shared/page-activity.ts`);
const { normalizeDomain } = await import(`${ROOT}/shared/domains.ts`);
const { normalisePopupState } = await import(`${ROOT}/ui/popup/state.ts`);

test('incident CTA links to the contact form in the UI language', () => {
  assert.equal(incidentUrl('de'), 'https://www.bastionsecurity.ch/kontakt#vorfall');
  for (const lang of ['en', 'fr', 'it']) assert.equal(incidentUrl(lang), 'https://www.bastionsecurity.ch/en/contact#vorfall', lang);
});

test('savings: estimate by resource type, unknown types count as other', () => {
  assert.deepEqual(estimateSavings(null), { bytes: 0, ms: 0 });
  assert.deepEqual(estimateSavings({ script: 0, image: -3, xmlhttprequest: Number.NaN }), { bytes: 0, ms: 0 });
  const a = estimateSavings({ script: 2, image: 5 });
  assert.equal(a.bytes, 2 * 40_000 + 5 * 10_000);
  assert.equal(a.ms, 2 * 60 + 5 * 4);
  assert.deepEqual(estimateSavings({ 'made-up': 1 }), estimateSavings({ other: 1 }));
  // Requests that never load save nothing measurable as a page.
  assert.deepEqual(estimateSavings({ main_frame: 3, websocket: 2 }), { bytes: 0, ms: 0 });
});

test('savings: a typed sample scales up to the counted total', () => {
  assert.deepEqual(estimateFromSample(['script'], 0), { bytes: 0, ms: 0 });
  const one = estimateFromSample(['script', 'image'], 2);
  const four = estimateFromSample(['script', 'image'], 4);
  assert.equal(four.bytes, one.bytes * 2);
  assert.equal(four.ms, one.ms * 2);
  // No typed events yet: fall back to "other" for every counted block.
  assert.deepEqual(estimateFromSample([], 3), estimateSavings({ other: 3 }));
});

test('savings: stripped and debounced requests save nothing (history days)', () => {
  const day = { total: 8, byKind: { blocked: 4, stripped: 3, debounced: 1 }, byType: { script: 6, main_frame: 2 } };
  // Days recorded before savedByType: byType scaled by the share of requests that never loaded.
  assert.deepEqual(savedRequestsByType(day), { script: 3, main_frame: 1 });
  assert.deepEqual(savedRequestsByType({ ...day, savedByType: { script: 6 } }), { script: 6 });
  assert.deepEqual(savedRequestsByType({ total: 0, byKind: {}, byType: {} }), {});
});

test('page counters: kinds, third-party hosts once, savings sample without stripped requests', () => {
  const counts = { blocked: 0, redirected: 0, stripped: 0, debounced: 0, thirdPartyHosts: 0 };
  const third = new Set<string>();
  const types: string[] = [];
  const ev = (kind: string, type: string, host: string) => ({ t: 1, kind, frameId: 0, url: `https://${host}/x`, host, type, thirdParty: true, tabId: 1 });
  for (const e of [ev('blocked', 'script', 'a.net'), ev('strict', 'main_frame', 'a.net'), ev('stripped', 'sub_frame', 'b.net'), ev('redirected', 'image', 'c.net')]) {
    countEvent(counts, e, third);
    sampleType(types, e);
  }
  assert.deepEqual(counts, { blocked: 2, redirected: 1, stripped: 1, debounced: 0, thirdPartyHosts: 3 });
  assert.deepEqual(types, ['script', 'main_frame', 'image']);
  assert.equal(eventKey(ev('blocked', 'script', 'a.net')), '1|blocked|0|https://a.net/x');
});

test('protected domains: one normaliser for the dashboard and the service worker', () => {
  assert.equal(normalizeDomain(' https://www.PostFinance.ch/de/login?x=1 '), 'postfinance.ch');
  assert.equal(normalizeDomain('ubs.com.'), 'ubs.com');
  assert.equal(normalizeDomain('zürich.ch'), 'xn--zrich-kva.ch');
  for (const bad of ['', 'localhost', 'not a domain', '192.168.1.10', '999999', 'a..b']) assert.equal(normalizeDomain(bad), null, bad);
});

test('savings: formatting picks a readable unit', () => {
  assert.deepEqual(fmtBytes(0), { value: '0', unit: 'kB' });
  assert.equal(fmtBytes(820_000).unit, 'kB');
  assert.deepEqual(fmtBytes(1_234_567), { value: '1.2', unit: 'MB' });
  assert.deepEqual(fmtBytes(86_000_000), { value: '86', unit: 'MB' });
  assert.equal(fmtBytes(140_000_000).unit, 'MB');
  assert.equal(fmtBytes(2_500_000_000).unit, 'GB');
  const u = { s: 's', min: 'Min.', h: 'Std.' };
  assert.deepEqual(fmtDuration(400, u), { value: '0.4', unit: 's' });
  assert.deepEqual(fmtDuration(42_000, u), { value: '42', unit: 's' });
  assert.deepEqual(fmtDuration(4 * 60_000, u), { value: '4', unit: 'Min.' });
  assert.equal(fmtDuration(3 * 3_600_000, u).unit, 'Std.');
});

test('popup state: incident CTA is on unless the service worker says off', () => {
  assert.equal(normalisePopupState({}, 1).incidentCta, true);
  assert.equal(normalisePopupState({ incidentCta: true }, 1).incidentCta, true);
  assert.equal(normalisePopupState({ incidentCta: false }, 1).incidentCta, false);
});

const { formatMessage, resolveLanguage } = await import(`${ROOT}/ui/shared/i18n.ts`);

test('i18n: chrome.i18n message format with placeholders', () => {
  const ph = { p1: { content: '$1' }, p2: { content: '$2' } };
  assert.equal(formatMessage({ message: '$P1$ Hosts', placeholders: ph }, ['17']), '17 Hosts');
  assert.equal(formatMessage({ message: 'von $P1$ bis $p2$', placeholders: ph }, ['a', 'b']), 'von a bis b');
  assert.equal(formatMessage({ message: 'kostet $$5' }), 'kostet $5');
  assert.equal(formatMessage({ message: '$P1$ fehlt', placeholders: ph }), ' fehlt');
  assert.equal(formatMessage({ message: '$UNKNOWN$ bleibt' }), '$UNKNOWN$ bleibt');
});

test('i18n: language preference, browser language by default', () => {
  assert.equal(resolveLanguage(undefined, 'en'), 'en');
  assert.equal(resolveLanguage('nonsense', 'fr'), 'fr');
  assert.equal(resolveLanguage('de', 'en'), 'de');
  assert.equal(resolveLanguage('en', 'de'), 'en');
  assert.equal(resolveLanguage('it', 'en'), 'it');
  assert.equal(resolveLanguage('auto', 'fr'), 'fr');
});

test('hand-off between compact and expanded popup: same tab and fresh only', async () => {
  const mem = new Map<string, string>();
  (globalThis as { sessionStorage?: unknown }).sessionStorage = { getItem: (k: string) => mem.get(k) ?? null, setItem: (k: string, v: string) => void mem.set(k, v), removeItem: (k: string) => void mem.delete(k) };
  const { writeHandoff, readHandoff, HANDOFF_MAX_AGE_MS } = await import(`${ROOT}/ui/shared/handoff.ts`);
  const state = normalisePopupState({ host: 'example.ch' }, 7);
  assert.equal(readHandoff(7), null, 'nothing stored yet');
  writeHandoff(7, state);
  assert.equal(readHandoff(7)?.state.host, 'example.ch');
  assert.equal(readHandoff(8), null, 'another tab');
  assert.equal(readHandoff(null), null);
  assert.equal(readHandoff(7, Date.now() + HANDOFF_MAX_AGE_MS + 1), null, 'stale');
  mem.set('bastion.handoff', '{broken');
  assert.equal(readHandoff(7), null, 'corrupt');
  delete (globalThis as { sessionStorage?: unknown }).sessionStorage;
});
