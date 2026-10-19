// Tests for content-script registration planning: cosmetic script, the
// single generic-high CSS registration, the per-world scriptlet bundles and
// privacy scripts with per-site scopes, the bounded size of the set (review
// PERF-1/PERF-2), and the diff against Chrome's registered scripts
// (src/background/registrations.ts).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { CosmeticMeta, ScriptletIndex } from '../../src/shared/types.ts';
import { SEED_FILES_PER_SET, SEED_SETS } from '../../src/shared/constants.ts';
import {
  CLIPGUARD_ID,
  COSMETIC_SCRIPT_ID,
  FPMETER_SCRIPT_FILE,
  GENERIC_HIGH_ID,
  NERD_RELAY_ID,
  computeRegistrations,
  diffRegistrations,
  genericHighExcludedUnion,
  intersectPatterns,
  packagePath,
  privacyScripts,
  registrationStats,
  relevantSites,
} from '../../src/background/registrations.ts';
import type { DesiredScript, RegisteredScript } from '../../src/background/registrations.ts';
import { defaultSettings, normalizeSettings } from '../../src/background/settings.ts';
import { currentSeedFiles, pickSeeds, seedFilePaths, validSeedPick } from '../../src/background/install.ts';

/** One seed file per set, as the service worker registers them (SEED_SETS sets). */
const SEEDS = Array.from({ length: SEED_SETS }, (_, set) => `main/seeds/s${set}-${(set * 7 + 1) % SEED_FILES_PER_SET}.js`);
const META: CosmeticMeta = {
  shards: 256,
  genericHighCss: { easylist: 'cosmetic/generic-high/easylist.css', ublock: '/cosmetic/generic-high/ublock.css', annoyances: 'cosmetic/generic-high/annoyances.css', empty: null },
  genericHighExcludedHosts: { easylist: ['exc.example', 'google.*'], annoyances: ['annoy.example'], ublock: [] },
  genericHideHosts: ['generichide.example', 'localhost', 'bad host'],
  genericHighSelectorsFile: 'cosmetic/generic-high.json',
};
const INDEX: ScriptletIndex = {
  registrations: [
    { id: 'sl-annoyances-main', listId: 'annoyances', world: 'MAIN', file: 'scriptlets/annoyances-main.js', matches: ['<all_urls>'] },
    { id: 'sl-easylist-main', listId: 'easylist', world: 'MAIN', file: 'scriptlets/easylist-main.js', matches: ['<all_urls>'] },
    { id: 'sl-ublock-isolated', listId: 'ublock', world: 'ISOLATED', file: 'scriptlets/ublock-isolated.js', matches: ['<all_urls>'] },
    { id: 'sl-ublock-main', listId: 'ublock', world: 'MAIN', file: 'scriptlets/ublock-main.js', matches: ['<all_urls>'] },
  ],
  bundles: [
    { world: 'MAIN', core: 'scriptlets/scriptlet-core-main.js', end: 'scriptlets/scriptlet-end-main.js' },
    { world: 'ISOLATED', core: 'scriptlets/scriptlet-core-isolated.js', end: 'scriptlets/scriptlet-end-isolated.js' },
  ],
  merged: [{ world: 'MAIN', lists: ['easylist', 'ublock'], file: 'scriptlets/scriptlet-merged-main.js' }],
};

function byId(list: DesiredScript[]): Map<string, DesiredScript> {
  return new Map(list.map((d) => [d.id, d]));
}

const plan = (enabled: string[], sites = {}, extra: Partial<Parameters<typeof computeRegistrations>[0]> = {}) =>
  computeRegistrations({
    settings: normalizeSettings({}),
    sites,
    enabledListIds: new Set(enabled),
    cosmeticMeta: META,
    scriptletIndex: INDEX,
    seedFiles: SEEDS,
    ...extra,
  });

test('packagePath normalizes metadata paths', () => {
  assert.equal(packagePath('/cosmetic/a.css'), 'cosmetic/a.css');
  assert.equal(packagePath('dist/cosmetic/a.css'), 'cosmetic/a.css');
  assert.equal(packagePath('cosmetic\\a.css'), 'cosmetic/a.css');
});

test('pattern intersection', () => {
  assert.deepEqual(intersectPatterns(['<all_urls>'], ['a.ch']), ['*://*.a.ch/*']);
  assert.deepEqual(intersectPatterns(['*://*.example.com/*', '*://*.news.ch/*'], ['shop.example.com']), ['*://*.shop.example.com/*']);
  assert.deepEqual(intersectPatterns(['*://*.shop.example.com/*'], ['example.com']), ['*://*.shop.example.com/*']);
  assert.deepEqual(intersectPatterns(['*://*.news.ch/*'], ['example.com']), []);
  assert.deepEqual(intersectPatterns(['*://10.0.0.1/*'], ['10.0.0.1']), ['*://10.0.0.1/*']);
});

test('relevantSites keeps only sites that can intersect the matches (SW-5)', () => {
  assert.deepEqual(relevantSites(['<all_urls>'], ['a.ch', 'b.ch']), ['a.ch', 'b.ch']);
  assert.deepEqual(relevantSites(['*://*.example.com/*'], ['shop.example.com', 'example.org', 'com']), ['shop.example.com', 'com']);
  assert.deepEqual(relevantSites(['*://shop.example.com/*'], ['example.com', 'x.shop.example.com']), ['example.com']);
  assert.deepEqual(relevantSites(['https://example.com/path*'], ['x.ch']), ['x.ch'], 'unanalysable pattern keeps everything');
});

test('default registrations: cosmetic, one generic-high CSS, one scriptlet bundle per world, privacy, ClickFix protection', () => {
  const out = plan(['easylist', 'ublock']);
  const m = byId(out);
  assert.deepEqual(
    out.map((d) => d.id),
    [COSMETIC_SCRIPT_ID, GENERIC_HIGH_ID, 'sl-main', 'sl-isolated', 'bs-privacy', CLIPGUARD_ID, NERD_RELAY_ID],
  );
  assert.deepEqual(m.get(COSMETIC_SCRIPT_ID), {
    id: COSMETIC_SCRIPT_ID,
    js: ['content/cosmetic.js'],
    matches: ['<all_urls>'],
    world: 'ISOLATED',
    runAt: 'document_start',
    allFrames: true,
    matchOriginAsFallback: true,
    persistAcrossSessions: true,
  });
  const gh = m.get(GENERIC_HIGH_ID)!;
  assert.deepEqual(gh.css, ['cosmetic/generic-high/easylist.css', 'cosmetic/generic-high/ublock.css'], 'enabled lists, sorted');
  // Union of enabled lists' exclusions plus generichide hosts; entities and invalid hosts are left out.
  assert.deepEqual(gh.excludeMatches, ['*://*.exc.example/*', '*://*.generichide.example/*', '*://*.localhost/*']);
  // Merged data replaces the files of the lists it covers.
  assert.deepEqual(m.get('sl-main')!.js, ['scriptlets/scriptlet-core-main.js', 'scriptlets/scriptlet-merged-main.js', 'scriptlets/scriptlet-end-main.js']);
  assert.equal(m.get('sl-main')!.world, 'MAIN');
  assert.deepEqual(m.get('sl-main')!.matches, ['<all_urls>']);
  assert.deepEqual(m.get('sl-isolated')!.js, ['scriptlets/scriptlet-core-isolated.js', 'scriptlets/ublock-isolated.js', 'scriptlets/scriptlet-end-isolated.js']);
  assert.equal(m.get('sl-isolated')!.world, 'ISOLATED');
  const privacy = m.get('bs-privacy')!;
  assert.deepEqual(privacy.js, [...SEEDS, 'main/cfg-standard-gpc1.js', 'main/privacy.js']);
  assert.equal(privacy.world, 'MAIN');
  assert.deepEqual(privacy.matches, ['<all_urls>']);
});

test('scriptlet bundles follow the enabled lists', () => {
  // Merged set incomplete: each list's own file, sorted by id.
  const a = byId(plan(['annoyances', 'ublock']));
  assert.deepEqual(a.get('sl-main')!.js, ['scriptlets/scriptlet-core-main.js', 'scriptlets/annoyances-main.js', 'scriptlets/ublock-main.js', 'scriptlets/scriptlet-end-main.js']);
  // Merged set plus another list.
  const b = byId(plan(['annoyances', 'easylist', 'ublock']));
  assert.deepEqual(b.get('sl-main')!.js, ['scriptlets/scriptlet-core-main.js', 'scriptlets/scriptlet-merged-main.js', 'scriptlets/annoyances-main.js', 'scriptlets/scriptlet-end-main.js']);
  // No list with data in a world: no bundle for it.
  const c = byId(plan(['easylist']));
  assert.ok(c.has('sl-main'));
  assert.ok(!c.has('sl-isolated'));
  assert.ok(!byId(plan([])).has('sl-main'));
  // Generic-high: nothing to inject without an enabled list that has CSS.
  assert.ok(!byId(plan([])).has(GENERIC_HIGH_ID));
  assert.ok(!byId(plan(['ublock'], {}, { cosmeticMeta: null })).has(GENERIC_HIGH_ID));
  // Old index without bundles: no scriptlet registrations.
  assert.ok(!byId(plan(['ublock'], {}, { scriptletIndex: { registrations: INDEX.registrations } })).has('sl-main'));
});

test('custom generichide hosts are excluded from the generic-high CSS', () => {
  const m = byId(plan(['easylist'], {}, { extraGenericHideHosts: ['mine.example', 'google.*'] }));
  assert.deepEqual(m.get(GENERIC_HIGH_ID)!.excludeMatches, ['*://*.exc.example/*', '*://*.generichide.example/*', '*://*.localhost/*', '*://*.mine.example/*']);
  assert.deepEqual(genericHighExcludedUnion(META, new Set(['annoyances'])), ['annoy.example', 'generichide.example', 'localhost']);
});

test('the set stays small whatever the size of the lists (PERF-1/PERF-2)', () => {
  const many: ScriptletIndex = {
    registrations: Array.from({ length: 30 }, (_, i) => ({ id: `sl-l${i}-main`, listId: `l${i}`, world: 'MAIN' as const, file: `scriptlets/l${i}-main.js`, matches: ['<all_urls>'] })),
    bundles: INDEX.bundles,
  };
  const out = plan(Array.from({ length: 30 }, (_, i) => `l${i}`).concat(['easylist', 'ublock']), {}, { scriptletIndex: many });
  const st = registrationStats(out);
  // + ClickFix protection (clipboard guard and its relay), on by default.
  assert.equal(st.registrations, 6);
  assert.equal(st.matches, 6);
  assert.equal(st.excludeMatches, 3);
  assert.equal(byId(out).get('sl-main')!.js!.length, 32);
});

test('sites with protection off are excluded everywhere; re-enabled subdomains get companions', () => {
  const sites = { 'example.com': { enabled: false }, 'shop.example.com': { enabled: true }, 'off.ch': { enabled: false } };
  const out = computeRegistrations({
    settings: defaultSettings(),
    sites,
    enabledListIds: new Set(['easylist', 'ublock']),
    cosmeticMeta: META,
    scriptletIndex: INDEX,
    seedFiles: SEEDS,
  });
  const m = byId(out);
  for (const d of out) {
    if (d.id.includes('~') || d.id.startsWith('bs-privacy-')) continue;
    assert.ok(d.excludeMatches?.includes('*://*.example.com/*'), `${d.id} excludes example.com`);
    assert.ok(d.excludeMatches?.includes('*://*.off.ch/*'), `${d.id} excludes off.ch`);
  }
  assert.deepEqual(m.get(`${COSMETIC_SCRIPT_ID}~1`)!.matches, ['*://*.shop.example.com/*']);
  assert.deepEqual(m.get('sl-main~1')!.matches, ['*://*.shop.example.com/*']);
  assert.deepEqual(m.get('sl-main~1')!.js, m.get('sl-main')!.js);
  assert.equal(m.get('sl-main~1')!.excludeMatches, undefined);
  assert.deepEqual(m.get(`${GENERIC_HIGH_ID}~1`)!.excludeMatches, ['*://*.exc.example/*', '*://*.generichide.example/*', '*://*.localhost/*']);
  // Privacy: one registration for the re-enabled subtree, none for "off".
  const privacy = out.filter((d) => d.id.startsWith('bs-privacy'));
  assert.equal(privacy.length, 2);
  assert.deepEqual(privacy[1].matches, ['*://*.shop.example.com/*']);
});

test('a site toggle only updates the registrations it can affect, in place (SW-5)', () => {
  const sites = { 'bank.ch': { fingerprinting: 'strict' as const } };
  const before = plan(['easylist', 'ublock'], sites);
  const current: RegisteredScript[] = before.map((d) => ({ ...d }));
  const after = plan(['easylist', 'ublock'], { ...sites, 'unrelated.org': { enabled: false } });
  const diff = diffRegistrations(current, after);
  assert.deepEqual(diff.register, []);
  assert.deepEqual(diff.unregister, []);
  // The host-scoped privacy registration for bank.ch is untouched.
  assert.deepEqual(diff.update.map((d) => d.id).sort(), [COSMETIC_SCRIPT_ID, GENERIC_HIGH_ID, CLIPGUARD_ID, NERD_RELAY_ID, 'bs-privacy', 'sl-isolated', 'sl-main'].sort());
  for (const d of diff.update) assert.ok(d.excludeMatches?.includes('*://*.unrelated.org/*'));
  const strict = after.find((d) => d.id === 'bs-privacy-1')!;
  assert.deepEqual(strict.matches, ['*://*.bank.ch/*']);
  assert.equal(strict.excludeMatches, undefined);
  // Toggling a list updates only the registrations whose files change, in place.
  const lists = diffRegistrations(current, plan(['easylist', 'ublock', 'annoyances'], sites));
  assert.deepEqual(lists.update.map((d) => d.id).sort(), [GENERIC_HIGH_ID, 'sl-main']);
  assert.deepEqual(lists.register, []);
  assert.deepEqual(lists.unregister, []);
  // Switching the last disabled site back on clears excludeMatches, which an
  // update cannot express (apply.ts omits empty lists): re-register those.
  const off: RegisteredScript[] = after.map((d) => ({ ...d }));
  const back = diffRegistrations(off, before);
  assert.deepEqual(back.register.map((d) => d.id).sort(), [COSMETIC_SCRIPT_ID, CLIPGUARD_ID, NERD_RELAY_ID, 'sl-isolated', 'sl-main'].sort());
  assert.deepEqual(back.unregister.sort(), [COSMETIC_SCRIPT_ID, CLIPGUARD_ID, NERD_RELAY_ID, 'sl-isolated', 'sl-main'].sort());
  // These keep other exclusions (generichide hosts; bank.ch's own privacy level).
  assert.deepEqual(back.update.map((d) => d.id).sort(), [GENERIC_HIGH_ID, 'bs-privacy']);
  for (const d of back.register) assert.equal(d.excludeMatches, undefined);
});

test('per-site fingerprinting levels get their own cfg file', () => {
  const settings = normalizeSettings({ privacy: { fingerprinting: 'standard', gpc: false } });
  const sites = {
    'bank.ch': { fingerprinting: 'off' as const },
    'tracker-heavy.com': { fingerprinting: 'strict' as const },
    'sub.tracker-heavy.com': { fingerprinting: 'standard' as const },
    'disabled.ch': { enabled: false, fingerprinting: 'strict' as const },
  };
  const out = privacyScripts(settings, sites, SEEDS);
  const root = out.find((d) => d.id === 'bs-privacy')!;
  assert.deepEqual(root.excludeMatches, ['*://*.bank.ch/*', '*://*.disabled.ch/*', '*://*.tracker-heavy.com/*']);
  assert.ok(root.js!.includes('main/cfg-standard-gpc0.js'));
  const strict = out.find((d) => d.js!.includes('main/cfg-strict-gpc0.js'))!;
  assert.deepEqual(strict.matches, ['*://*.tracker-heavy.com/*']);
  assert.deepEqual(strict.excludeMatches, ['*://*.sub.tracker-heavy.com/*']);
  const nested = out.find((d) => d.id !== 'bs-privacy' && d.js!.includes('main/cfg-standard-gpc0.js'))!;
  assert.deepEqual(nested.matches, ['*://*.sub.tracker-heavy.com/*']);
  // Fingerprinting off globally and GPC off: only sites that opt in get the script.
  const off = privacyScripts(normalizeSettings({ privacy: { fingerprinting: 'off', gpc: false } }), { 'x.ch': { fingerprinting: 'strict' } }, SEEDS);
  assert.equal(off.length, 1);
  assert.deepEqual(off[0].matches, ['*://*.x.ch/*']);
  // With GPC on, fingerprinting-off hosts still get cfg-off-gpc1 (navigator.globalPrivacyControl).
  const gpcOnly = privacyScripts(normalizeSettings({ privacy: { fingerprinting: 'off' } }), { 'x.ch': { fingerprinting: 'strict' }, 'y.ch': { enabled: false } }, SEEDS);
  const gpcRoot = gpcOnly.find((d) => d.id === 'bs-privacy')!;
  assert.ok(gpcRoot.js!.includes('main/cfg-off-gpc1.js'));
  assert.deepEqual(gpcRoot.excludeMatches, ['*://*.x.ch/*', '*://*.y.ch/*']);
  assert.equal(gpcOnly.length, 2);
});

test('diff: unchanged, in-place updates, structural re-registration, removals', () => {
  const base = { runAt: 'document_start', allFrames: true, matchOriginAsFallback: true, persistAcrossSessions: true } as const;
  const desired: DesiredScript[] = [
    { id: 'a', js: ['a.js'], matches: ['<all_urls>'], excludeMatches: ['*://*.x.ch/*'], world: 'ISOLATED', ...base },
    { id: 'b', js: ['b.js'], matches: ['*://*.b.ch/*', '*://*.c.ch/*'], world: 'MAIN', ...base },
    { id: 'c', js: ['c2.js'], matches: ['<all_urls>'], world: 'MAIN', ...base },
    { id: 'd', css: ['d.css'], matches: ['<all_urls>'], world: 'ISOLATED', ...base },
    { id: 'e', js: ['e.js'], matches: ['<all_urls>'], world: 'MAIN', ...base },
    { id: 'f', js: ['f.js'], matches: ['<all_urls>'], world: 'MAIN', ...base, runAt: 'document_start' },
    { id: 'new', css: ['n.css'], matches: ['<all_urls>'], world: 'ISOLATED', ...base },
  ];
  const current: RegisteredScript[] = [
    { id: 'a', js: ['a.js'], matches: ['<all_urls>'], excludeMatches: ['*://*.x.ch/*'], runAt: 'document_start', allFrames: true, matchOriginAsFallback: true, persistAcrossSessions: true },
    { id: 'b', js: ['b.js'], matches: ['*://*.c.ch/*'], world: 'MAIN', runAt: 'document_start', allFrames: true, matchOriginAsFallback: true },
    // Files changed: updated in place.
    { id: 'c', js: ['c1.js'], matches: ['<all_urls>'], world: 'MAIN', runAt: 'document_start', allFrames: true, matchOriginAsFallback: true },
    // js -> css cannot be expressed by an update.
    { id: 'd', js: ['d.js'], matches: ['<all_urls>'], runAt: 'document_start', allFrames: true, matchOriginAsFallback: true },
    // Exclusions removed: an update would keep them.
    { id: 'e', js: ['e.js'], matches: ['<all_urls>'], excludeMatches: ['*://*.x.ch/*'], world: 'MAIN', runAt: 'document_start', allFrames: true, matchOriginAsFallback: true },
    { id: 'f', js: ['f.js'], matches: ['<all_urls>'], world: 'MAIN', runAt: 'document_idle', allFrames: true, matchOriginAsFallback: true },
    { id: 'old', js: ['o.js'], matches: ['<all_urls>'] },
  ];
  const d = diffRegistrations(current, desired);
  assert.deepEqual(d.unregister.sort(), ['d', 'e', 'f', 'old']);
  assert.deepEqual(d.update.map((x) => x.id), ['b', 'c']);
  assert.deepEqual(d.register.map((x) => x.id), ['d', 'e', 'f', 'new']);
  assert.deepEqual(diffRegistrations(current.slice(0, 1), desired.slice(0, 1)), { unregister: [], update: [], register: [] });
});

test('seed picks: one file per set, stable paths, validation', () => {
  const pick = pickSeeds(() => 0.999999);
  assert.deepEqual(pick.files, Array(SEED_SETS).fill(SEED_FILES_PER_SET - 1));
  const files = Array.from({ length: SEED_SETS }, (_, set) => set % SEED_FILES_PER_SET);
  assert.deepEqual(seedFilePaths({ files, at: 0 }), files.map((n, set) => `main/seeds/s${set}-${n}.js`));
  assert.equal(seedFilePaths(pick).length, SEED_SETS);
  assert.equal(validSeedPick(pick), true);
  assert.equal(validSeedPick({ files: [1, 2, 3] }), false);
  assert.equal(validSeedPick({ files: Array(SEED_SETS).fill(SEED_FILES_PER_SET) }), false);
  const r = pickSeeds();
  assert.ok(r.files.every((n) => n >= 0 && n < SEED_FILES_PER_SET));
  assert.equal(typeof currentSeedFiles, 'function');
});

// ---------------------------------------------------------------------------
// Nerd mode (clipboard guard, fingerprinting meter, relay)
// ---------------------------------------------------------------------------

const nerd = (nerdPatch: Record<string, unknown>, privacy: Record<string, unknown> = {}) =>
  normalizeSettings({ nerd: nerdPatch, privacy });
const planWith = (settings: ReturnType<typeof normalizeSettings>, sites = {}) =>
  computeRegistrations({
    settings,
    sites,
    enabledListIds: new Set(['easylist', 'ublock']),
    cosmeticMeta: META,
    scriptletIndex: INDEX,
    seedFiles: SEEDS,
  });

test('nerd mode off (default): ClickFix protection still on, no meter', () => {
  const out = planWith(nerd({}));
  const m = byId(out);
  // ClickFix protection is a privacy default, independent of nerd mode.
  assert.ok(m.has(CLIPGUARD_ID) && m.has(NERD_RELAY_ID));
  assert.ok(!out.some((d) => d.js?.includes(FPMETER_SCRIPT_FILE)));
  // The meter flag alone does nothing while the master switch is off.
  assert.deepEqual(planWith(nerd({ enabled: false, fingerprintMeter: true })), out);
  // Guard off and nerd mode off: neither script.
  const none = planWith(nerd({}, { clipboardGuard: false }));
  assert.ok(!none.some((d) => d.id === CLIPGUARD_ID || d.id === NERD_RELAY_ID));
});

test('an earlier nerd.clipboardGuard choice carries over to privacy.clipboardGuard', () => {
  assert.equal(nerd({ clipboardGuard: false }).privacy.clipboardGuard, false);
  assert.equal(nerd({}).privacy.clipboardGuard, true);
  assert.equal(nerd({ clipboardGuard: false }, { clipboardGuard: true }).privacy.clipboardGuard, true);
});

test('nerd mode on: clipboard guard (MAIN), relay (ISOLATED), meter after privacy.js', () => {
  const out = planWith(nerd({ enabled: true }));
  const m = byId(out);
  assert.deepEqual(m.get(CLIPGUARD_ID), {
    id: CLIPGUARD_ID,
    js: ['main/clipguard.js'],
    matches: ['<all_urls>'],
    world: 'MAIN',
    runAt: 'document_start',
    allFrames: true,
    matchOriginAsFallback: true,
    persistAcrossSessions: true,
  });
  assert.deepEqual(m.get(NERD_RELAY_ID), {
    id: NERD_RELAY_ID,
    js: ['content/nerd-relay.js'],
    matches: ['<all_urls>'],
    world: 'ISOLATED',
    runAt: 'document_start',
    allFrames: true,
    matchOriginAsFallback: true,
    persistAcrossSessions: true,
  });
  // The meter rides on the privacy registration, right after privacy.js.
  assert.deepEqual(m.get('bs-privacy')!.js, [...SEEDS, 'main/cfg-standard-gpc1.js', 'main/privacy.js', FPMETER_SCRIPT_FILE]);
});

test('nerd feature flags select the scripts', () => {
  const clipOnly = byId(planWith(nerd({ enabled: true, fingerprintMeter: false })));
  assert.ok(clipOnly.has(CLIPGUARD_ID) && clipOnly.has(NERD_RELAY_ID));
  assert.ok(!clipOnly.get('bs-privacy')!.js!.includes(FPMETER_SCRIPT_FILE));

  const meterOnly = byId(planWith(nerd({ enabled: true }, { clipboardGuard: false })));
  assert.ok(!meterOnly.has(CLIPGUARD_ID));
  assert.ok(meterOnly.has(NERD_RELAY_ID));
  assert.ok(meterOnly.get('bs-privacy')!.js!.includes(FPMETER_SCRIPT_FILE));

  const none = planWith(nerd({ enabled: true, fingerprintMeter: false }, { clipboardGuard: false }));
  assert.ok(!none.some((d) => d.id === CLIPGUARD_ID || d.id === NERD_RELAY_ID || d.js?.includes(FPMETER_SCRIPT_FILE)));
});

test('meter without a privacy script (fingerprinting and GPC off) gets its own MAIN registration', () => {
  const out = privacyScripts(nerd({ enabled: true }, { fingerprinting: 'off', gpc: false }), { 'x.ch': { fingerprinting: 'strict' }, 'y.ch': { enabled: false } }, SEEDS, true);
  const root = out.find((d) => d.id === 'bs-privacy')!;
  assert.deepEqual(root.js, [FPMETER_SCRIPT_FILE]);
  assert.equal(root.world, 'MAIN');
  assert.deepEqual(root.excludeMatches, ['*://*.x.ch/*', '*://*.y.ch/*']);
  const strict = out.find((d) => d.js!.includes('main/cfg-strict-gpc0.js'))!;
  assert.deepEqual(strict.js!.slice(-2), ['main/privacy.js', FPMETER_SCRIPT_FILE]);
  assert.deepEqual(strict.matches, ['*://*.x.ch/*']);
  // Protection off: nothing at all.
  assert.ok(!out.some((d) => d.matches.includes('*://*.y.ch/*')));
});

test('nerd scripts are excluded where protection is off, with companions for re-enabled subtrees', () => {
  const sites = { 'example.com': { enabled: false }, 'shop.example.com': { enabled: true } };
  const m = byId(planWith(nerd({ enabled: true }), sites));
  for (const id of [CLIPGUARD_ID, NERD_RELAY_ID, 'bs-privacy']) {
    assert.ok(m.get(id)!.excludeMatches?.includes('*://*.example.com/*'), id);
  }
  assert.deepEqual(m.get(`${CLIPGUARD_ID}~1`)!.matches, ['*://*.shop.example.com/*']);
  assert.deepEqual(m.get(`${NERD_RELAY_ID}~1`)!.matches, ['*://*.shop.example.com/*']);
  assert.ok(m.get('bs-privacy-1')!.js!.includes(FPMETER_SCRIPT_FILE));
});

test('toggling nerd mode is a small diff: the meter rides on privacy (updated in place), ClickFix protection stays', () => {
  const off = planWith(nerd({}));
  const on = planWith(nerd({ enabled: true }));
  const up = diffRegistrations(off.map((d) => ({ ...d })), on);
  assert.deepEqual(up.register, []);
  assert.deepEqual(up.update.map((d) => d.id), ['bs-privacy']);
  assert.deepEqual(up.unregister, []);
  const down = diffRegistrations(on.map((d) => ({ ...d })), off);
  assert.deepEqual(down.unregister, []);
  // Without ClickFix protection, nerd mode brings the relay along on its own.
  const bare = planWith(nerd({}, { clipboardGuard: false }));
  const bareUp = diffRegistrations(bare.map((d) => ({ ...d })), planWith(nerd({ enabled: true }, { clipboardGuard: false })));
  assert.deepEqual(bareUp.register.map((d) => d.id), [NERD_RELAY_ID]);
  assert.deepEqual(down.update.map((d) => d.id), ['bs-privacy']);
  assert.deepEqual(down.register, []);
});
