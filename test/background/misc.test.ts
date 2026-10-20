// Tests for small service-worker helpers: the debounced apply runner, LRU,
// canonical JSON, sender validation, privacy-API decisions, per-site script
// blocking and blocked-page helpers.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RULE_ID, SEED_FILES_PER_SET, SEED_SETS } from '../../src/shared/constants.ts';
import type { BuildMeta } from '../../src/shared/types.ts';
import { canonicalJson, createDebouncedRunner, dayKey, deepEqual, Lru, startOfDayOffset, stripQueryAndFragment, webHostOf } from '../../src/background/util.ts';
import { classifySender, isAllowed, isBlockedPageSender, isKnownType } from '../../src/background/sender.ts';
import { desiredPrivacy, desiredScriptSettings, privacyAction } from '../../src/background/privacy-api.ts';
import { isBlockedPageUrl, listName, nextProceedId, sameBlockedHost } from '../../src/background/blocked.ts';
import { pickSeeds, seedFilePaths, validSeedPick } from '../../src/background/install.ts';
import { defaultSettings, normalizeSettings } from '../../src/background/settings.ts';

test('LRU evicts least recently used', () => {
  const l = new Lru<string, number>(2);
  l.set('a', 1);
  l.set('b', 2);
  assert.equal(l.get('a'), 1);
  l.set('c', 3);
  assert.equal(l.has('b'), false);
  assert.equal(l.get('a'), 1);
  assert.equal(l.size, 2);
});

test('canonical JSON ignores key order and undefined', () => {
  assert.equal(canonicalJson({ b: 1, a: { d: undefined, c: [2, { z: 1, y: 2 }] } }), '{"a":{"c":[2,{"y":2,"z":1}]},"b":1}');
  assert.ok(deepEqual({ a: 1, b: undefined }, { a: 1 }));
  assert.ok(!deepEqual([1, 2], [2, 1]));
});

test('url and day helpers', () => {
  assert.equal(webHostOf('https://WWW.Example.com/x'), 'www.example.com');
  assert.equal(webHostOf('about:blank'), null);
  assert.equal(stripQueryAndFragment('https://a.ch/p?q=1#f'), 'https://a.ch/p');
  assert.equal(stripQueryAndFragment('https://a.ch/p#f?x'), 'https://a.ch/p');
  const t = new Date(2026, 0, 31, 23, 59).getTime();
  assert.equal(dayKey(t), '2026-01-31');
  assert.equal(dayKey(startOfDayOffset(t, 31)), '2025-12-31');
  assert.equal(new Date(startOfDayOffset(t, 0)).getHours(), 0);
});

/** Manual timers so the debounce can be driven deterministically. */
function fakeTimers() {
  let seq = 0;
  const pending = new Map<number, { fn: () => void; ms: number }>();
  return {
    timers: {
      setTimeout: (fn: () => void, ms: number) => {
        pending.set(++seq, { fn, ms });
        return seq;
      },
      clearTimeout: (h: unknown) => {
        pending.delete(h as number);
      },
    },
    fire() {
      const all = Array.from(pending.entries());
      pending.clear();
      for (const [, t] of all) t.fn();
    },
    delays: () => Array.from(pending.values()).map((p) => p.ms),
  };
}

const tick = () => new Promise((r) => setTimeout(r, 0));

test('debounced runner coalesces, serializes and never rejects', async () => {
  const ft = fakeTimers();
  let runs = 0;
  let inFlight = 0;
  let maxInFlight = 0;
  let release: (() => void) | null = null;
  const runner = createDebouncedRunner(
    async () => {
      runs++;
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      if (runs === 1) await new Promise<void>((r) => (release = r));
      inFlight--;
      if (runs === 3) throw new Error('boom');
    },
    300,
    () => {},
    ft.timers,
  );
  const p1 = runner.schedule();
  const p2 = runner.schedule();
  assert.deepEqual(ft.delays(), [300]);
  ft.fire();
  await tick();
  assert.equal(runs, 1);
  // Requests during a run wait for a follow-up run.
  let p3done = false;
  const p3 = runner.schedule().then(() => (p3done = true));
  release!();
  await Promise.all([p1, p2]);
  assert.equal(p3done, false);
  ft.fire();
  await p3;
  assert.equal(runs, 2);
  // now() skips the delay; a failing task still resolves its waiters.
  const p4 = runner.now();
  assert.deepEqual(ft.delays(), [0]);
  ft.fire();
  await p4;
  assert.equal(runs, 3);
  assert.equal(maxInFlight, 1);
  assert.equal(runner.busy(), false);
});

test('sender validation', () => {
  const id = 'abcdefghijklmnopabcdefghijklmnop';
  const origin = `chrome-extension://${id}/`;
  const popup = { id, url: `${origin}ui/popup.html` };
  const content = { id, url: 'https://www.nzz.ch/', tab: { id: 3 }, frameId: 0 };
  assert.equal(classifySender(popup, id, origin), 'extension');
  assert.equal(classifySender(content, id, origin), 'content');
  assert.equal(classifySender({ ...content, id: 'other' }, id, origin), null);
  assert.equal(classifySender({ id, url: 'https://x.ch/' }, id, origin), null);
  assert.equal(classifySender(undefined, id, origin), null);
  assert.equal(isAllowed('popup:state', 'extension', popup), true);
  assert.equal(isAllowed('popup:state', 'content', content), false);
  assert.equal(isAllowed('settings:set', 'content', content), false);
  assert.equal(isAllowed('cosmetic:frame', 'content', content), true);
  assert.equal(isAllowed('cosmetic:frame', 'extension', popup), false);
  assert.equal(isAllowed('made:up', 'extension', popup), false);
  assert.equal(isKnownType('blocked:proceed'), true);
  assert.equal(isKnownType('made:up'), false);
});

test('blocked:* only from the top frame of pages/blocked.html (SEC-2)', () => {
  const id = 'abcdefghijklmnopabcdefghijklmnop';
  const origin = `chrome-extension://${id}/`;
  const pages = [`${origin}pages/blocked.html`, 'chrome-extension://3f1e2d6a-dynamic/pages/blocked.html'];
  const blockedDynamic = { id, url: 'chrome-extension://3f1e2d6a-dynamic/pages/blocked.html?list=x', tab: { id: 5 }, frameId: 0 };
  const blockedStatic = { id, url: `${origin}pages/blocked.html?list=ublock-badware`, tab: { id: 6 }, frameId: 0 };
  for (const type of ['blocked:info', 'blocked:proceed']) {
    assert.equal(isAllowed(type, classifySender(blockedDynamic, id, origin)!, blockedDynamic, pages), true, `${type} dynamic origin`);
    assert.equal(isAllowed(type, classifySender(blockedStatic, id, origin)!, blockedStatic, pages), true, `${type} static origin`);
    // A content script in any web frame is refused, whatever it claims.
    const cs = { id, url: 'https://site-a.example.com/', tab: { id: 3 }, frameId: 0 };
    assert.equal(isAllowed(type, 'content', cs, pages), false, `${type} from a content script`);
    // Not the top frame, no tab, another page of ours, another extension's origin.
    assert.equal(isAllowed(type, 'content', { ...blockedDynamic, frameId: 2 }, pages), false);
    assert.equal(isAllowed(type, 'extension', { id, url: `${origin}pages/blocked.html` }, pages), false, 'needs a tab');
    assert.equal(isAllowed(type, 'extension', { id, url: `${origin}ui/popup.html`, tab: { id: 1 }, frameId: 0 }, pages), false);
    assert.equal(isAllowed(type, 'content', { id, url: 'chrome-extension://otherotherother/pages/blocked.html', tab: { id: 1 }, frameId: 0 }, pages), false);
    assert.equal(isAllowed(type, 'content', blockedDynamic, []), false, 'no page URLs configured');
  }
  assert.equal(isBlockedPageSender(blockedStatic, pages), true);
  assert.equal(isBlockedPageUrl('chrome-extension://abc/pages/blocked.html?list=x'), true);
  assert.equal(isBlockedPageUrl('https://evil.example/pages/blocked.html'), false);
  assert.equal(sameBlockedHost('https://Evil.example/x', 'https://evil.example/y?z=1'), true);
  assert.equal(sameBlockedHost('https://1980s.click/', 'https://evil.example/'), false);
  assert.equal(sameBlockedHost('javascript:alert(1)', 'https://evil.example/'), false);
});

test('seed picks: one file per set, stable paths, validation', () => {
  const pick = pickSeeds(() => 0.999999);
  assert.equal(pick.files.length, SEED_SETS);
  assert.ok(pick.files.every((n) => n === SEED_FILES_PER_SET - 1));
  assert.deepEqual(seedFilePaths({ files: [0, 1, 2], at: 0 }), ['main/seeds/s0-0.js', 'main/seeds/s1-1.js', 'main/seeds/s2-2.js']);
  assert.equal(seedFilePaths(pick).length, SEED_SETS);
  assert.equal(validSeedPick(pick), true);
  assert.equal(validSeedPick({ files: [1, 2, 3] }), false);
  assert.equal(validSeedPick({ files: [...pick.files.slice(1), SEED_FILES_PER_SET] }), false);
  const r = pickSeeds();
  assert.ok(r.files.every((n) => Number.isInteger(n) && n >= 0 && n < SEED_FILES_PER_SET));
});

test('privacy API: set while controllable, release when off, never fight policy', () => {
  const targets = desiredPrivacy(defaultSettings());
  const byKey = new Map(targets.map((t) => [t.key, t.value]));
  assert.equal(byKey.get('websites.hyperlinkAuditingEnabled'), false);
  assert.equal(byKey.get('websites.topicsEnabled'), false);
  assert.equal(byKey.get('network.webRTCIPHandlingPolicy'), null);
  assert.equal(byKey.get('websites.thirdPartyCookiesAllowed'), null);
  const strict = desiredPrivacy(normalizeSettings({ privacy: { webrtcPolicy: 'disable_non_proxied_udp', blockThirdPartyCookies: true } }));
  assert.equal(strict.find((t) => t.key === 'network.webRTCIPHandlingPolicy')!.value, 'disable_non_proxied_udp');
  assert.equal(strict.find((t) => t.key === 'websites.thirdPartyCookiesAllowed')!.value, false);

  const t = { key: 'websites.hyperlinkAuditingEnabled', value: false };
  assert.equal(privacyAction(t, { value: true, levelOfControl: 'controllable_by_this_extension' }), 'set');
  assert.equal(privacyAction(t, { value: false, levelOfControl: 'controlled_by_this_extension' }), 'none');
  assert.equal(privacyAction(t, { value: true, levelOfControl: 'not_controllable' }), 'none');
  assert.equal(privacyAction(t, { value: true, levelOfControl: 'controlled_by_other_extensions' }), 'none');
  const off = { key: t.key, value: null };
  assert.equal(privacyAction(off, { value: false, levelOfControl: 'controlled_by_this_extension' }), 'clear');
  assert.equal(privacyAction(off, { value: false, levelOfControl: 'not_controllable' }), 'none');
  // Fleet kill switch: release everything we control, set nothing.
  const released = desiredPrivacy(normalizeSettings({ privacy: { webrtcPolicy: 'disable_non_proxied_udp', blockThirdPartyCookies: true } }), true);
  assert.equal(released.length, strict.length);
  assert.ok(released.every((x) => x.value === null));
});

test('per-site script blocking: block, and allow only below a blocked parent', () => {
  assert.deepEqual(
    desiredScriptSettings({
      'example.com': { blockScripts: true },
      'app.example.com': { blockScripts: false },
      'other.ch': { blockScripts: false },
      'x.ch': { enabled: false },
    }),
    [
      { pattern: '*://*.app.example.com/*', setting: 'allow' },
      { pattern: '*://*.example.com/*', setting: 'block' },
    ],
  );
});

test('blocked page helpers', () => {
  const meta = { lists: [{ id: 'ublock-badware', name: { en: 'Badware risks', de: 'Schadsoftware-Risiken' } }] } as unknown as BuildMeta;
  assert.equal(listName(meta, 'ublock-badware', 'de-CH'), 'Schadsoftware-Risiken');
  assert.equal(listName(meta, 'ublock-badware', 'fr'), 'Badware risks');
  assert.equal(listName(meta, 'nope', 'de'), null);
  assert.equal(nextProceedId([]), RULE_ID.SESSION_PROCEED_START);
  assert.equal(nextProceedId([RULE_ID.SESSION_PROCEED_START, RULE_ID.SESSION_PROCEED_START + 1]), RULE_ID.SESSION_PROCEED_START + 2);
});
