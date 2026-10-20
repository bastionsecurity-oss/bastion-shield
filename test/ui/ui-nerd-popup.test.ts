// Unit tests for the popup nerd statusline (src/ui/popup/nerd.ts) and its
// command line (src/ui/popup/commands.ts): the fingerprinting summary,
// BisectView validation, the step label, the nerd:bisect call, fuzzy command
// matching and completion, argument parsing, dashboard deep links, the
// "copy report" JSON, the bisect rule label, and the nerd locale keys in all
// four languages. Runs with a minimal chrome.* stub (i18n returns the key
// and its substitutions).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const sent: unknown[] = [];
let reply: unknown = undefined;
(globalThis as Record<string, unknown>).chrome = {
  i18n: { getMessage: (key: string, subs?: string[]) => (subs?.length ? `${key}(${subs.join(',')})` : key) },
  runtime: {
    sendMessage: async (msg: unknown) => {
      sent.push(msg);
      return reply;
    },
  },
};

const ROOT = new URL('../../src', import.meta.url).href;
const { fpSummary, normaliseBisect, normaliseHosts, stepLabel, bisectCall, shortcutLabel } = await import(`${ROOT}/ui/popup/nerd.ts`);
const { fuzzyScore, suggest, hostFrom, targetUrl, labPath, buildReport, commandHelp, MAX_SUGGESTIONS } = await import(`${ROOT}/ui/popup/commands.ts`);
const { dynamicRuleLabel } = await import(`${ROOT}/ui/shared/labels.ts`);
const { RULE_ID } = await import(`${ROOT}/shared/constants.ts`);

type Sug = { id: string; name: string; arg: string; complete: string; ready: boolean; count?: number; shortcut?: string };
const names = (xs: Sug[]): string[] => xs.map((s) => (s.arg ? `${s.name} ${s.arg}` : s.name));
const ctx = (over: Record<string, unknown> = {}) => ({ bisecting: false, hosts: [], ...over });

test('statusline: fingerprinting summary', () => {
  assert.deepEqual(fpSummary({ canvas: 6, webgl: 3, audio: 2, fonts: 1 }, 3), {
    total: 12,
    top: [
      { vector: 'canvas', n: 6 },
      { vector: 'webgl', n: 3 },
      { vector: 'audio', n: 2 },
    ],
  });
  assert.equal(fpSummary({ canvas: 6, webgl: 3, audio: 2, fonts: 1 }).top.length, 4, 'all vectors by default');
  assert.deepEqual(fpSummary(null), { total: 0, top: [] });
  // Junk from an older or broken worker is ignored; ties sort by name.
  assert.deepEqual(fpSummary({ canvas: -1, webgl: Number.NaN, timing: 2, audio: 2 } as Record<string, number>), {
    total: 4,
    top: [
      { vector: 'audio', n: 2 },
      { vector: 'timing', n: 2 },
    ],
  });
});

test('statusline: bisect views and host lists are validated', () => {
  assert.equal(normaliseBisect(null), null);
  assert.equal(normaliseBisect({ phase: 'cancelled' }), null, 'cancelled shows the normal statusline');
  assert.equal(normaliseBisect({ phase: 'found' }), null, 'found without a culprit is unusable');
  const t = normaliseBisect({ tabId: 3, site: 'shop.example', phase: 'testing', step: 2, maxSteps: 4, remaining: 3, allowed: ['a.example', 7] });
  assert.deepEqual(t, { tabId: 3, site: 'shop.example', phase: 'testing', step: 2, maxSteps: 4, remaining: 3, allowed: ['a.example'] });
  const f = normaliseBisect({
    tabId: 3,
    site: 'shop.example',
    phase: 'found',
    step: 4,
    maxSteps: 4,
    remaining: 2,
    allowed: [],
    culprit: { host: 'cdn.example', rules: ['easylist:1'], count: 2, filters: ['||cdn.example^'], lists: ['easylist'] },
    also: [{ host: 'x.example' }, { nope: 1 }],
    partial: true,
  });
  assert.equal(f?.culprit?.host, 'cdn.example');
  assert.deepEqual(f?.also, [{ host: 'x.example', rules: [], count: 0, filters: [], lists: [] }]);
  assert.equal(f?.partial, true);
  assert.deepEqual(normaliseHosts([{ host: 'a.example', count: 3, rules: ['x:1'] }, { count: 1 }, null]), [{ host: 'a.example', rules: ['x:1'], count: 3, filters: [], lists: [] }]);
  assert.deepEqual(normaliseHosts('junk'), []);
});

test('statusline: step label is an honest bound and never below the step', () => {
  assert.equal(stepLabel({ step: 2, maxSteps: 5 }), 'bisect 2/≤5');
  assert.equal(stepLabel({ step: 5, maxSteps: 5 }), 'bisect 5/5', 'the last possible step is certain');
  assert.equal(stepLabel({ step: 6, maxSteps: 5 }), 'bisect 6/6');
  assert.equal(stepLabel({ step: 0, maxSteps: 0 }), 'bisect 1/1');
  assert.equal(shortcutLabel('Alt+Shift+X'), 'alt+shift+x');
  assert.equal(shortcutLabel(undefined), '');
});

test('statusline: nerd:bisect call', async () => {
  reply = { bisect: { tabId: 9, site: 's.example', phase: 'clean', step: 1, maxSteps: 1, remaining: 0, allowed: [] } };
  const r = await bisectCall(9, 'answer', false);
  assert.deepEqual(sent.at(-1), { type: 'nerd:bisect', action: 'answer', tabId: 9, works: false });
  assert.equal(r.ok, true);
  assert.equal(r.data?.phase, 'clean');
  reply = { error: 'locked' };
  assert.deepEqual(await bisectCall(9, 'keep'), { ok: false, error: 'locked' });
  assert.deepEqual(sent.at(-1), { type: 'nerd:bisect', action: 'keep', tabId: 9 });
});

test('command line: fuzzy subsequence scoring', () => {
  assert.equal(fuzzyScore('xyz', 'bisect'), null);
  assert.equal(fuzzyScore('tsb', 'bisect'), null, 'order matters');
  assert.ok(fuzzyScore('bis', 'bisect')! > fuzzyScore('bct', 'bisect')!, 'a run beats gaps');
  assert.equal(fuzzyScore('cr', 'nerd off'), null);
  assert.equal(fuzzyScore('', 'lab'), 0);
});

test('command line: suggestions', () => {
  const all = names(suggest('', ctx()));
  assert.equal(all.length, MAX_SUGGESTIONS);
  assert.deepEqual(all.slice(0, 3), ['bisect', 'why', 'blame']);
  assert.ok(!all.includes('bisect cancel'), 'no cancel without a bisect');
  assert.equal(names(suggest('', ctx({ bisecting: true })))[0], 'bisect cancel');
  assert.equal(names(suggest('cr', ctx()))[0], 'copy report');
  assert.equal(names(suggest('nof', ctx()))[0], 'nerd off');
  assert.equal(names(suggest('  fp', ctx()))[0], 'fp');
  assert.deepEqual(names(suggest('zzz', ctx())), []);

  // Commands with an argument complete with a trailing space; "allow" is not ready without a host.
  const allow = suggest('allo', ctx())[0] as Sug;
  assert.deepEqual([allow.complete, allow.ready], ['allow ', false]);
  const why = suggest('why', ctx())[0] as Sug;
  assert.deepEqual([why.complete, why.ready], ['why ', true], 'why alone explains the page');

  // After "allow ": the blocked hosts, best match first; a typed host that is not listed comes last.
  const hosts = [
    { host: 'ads.example', count: 5 },
    { host: 'cdn.shop.example', count: 2 },
    { host: 'track.example', count: 1 },
  ];
  assert.deepEqual(names(suggest('allow ', ctx({ hosts }))), ['allow ads.example', 'allow cdn.shop.example', 'allow track.example']);
  const c = suggest('allow cdn', ctx({ hosts })) as Sug[];
  assert.deepEqual(names(c), ['allow cdn.shop.example', 'allow cdn']);
  assert.equal(c[0]!.count, 2);
  assert.equal(c[0]!.complete, 'allow cdn.shop.example');
  const many = Array.from({ length: 9 }, (_, i) => ({ host: `n${i}.new.example.net`, count: 1 }));
  const typed = names(suggest('allow new.example', ctx({ hosts: many })));
  assert.equal(typed.length, MAX_SUGGESTIONS);
  assert.equal(typed.at(-1), 'allow new.example', 'the typed host keeps its row');
  assert.deepEqual(names(suggest('allow cdn.shop.example', ctx({ hosts }))), ['allow cdn.shop.example']);
  // Filter text keeps its case and spaces.
  const b = suggest('blame ||Ads.example^$Script', ctx())[0] as Sug;
  assert.deepEqual([b.id, b.arg, b.ready], ['blame', '||Ads.example^$Script', true]);
  assert.equal((suggest('blame ', ctx())[0] as Sug).ready, false);
  // Shortcuts appear on their command.
  assert.equal((suggest('bis', ctx({ shortcuts: { bisect: 'alt+shift+x' } }))[0] as Sug).shortcut, 'alt+shift+x');
});

test('command line: arguments and deep links', () => {
  assert.equal(hostFrom('CDN.Example.'), 'cdn.example');
  assert.equal(hostFrom('https://cdn.example:8443/x?y'), 'cdn.example');
  assert.equal(hostFrom('bücher.ch'), 'xn--bcher-kva.ch');
  assert.equal(hostFrom('two words'), null);
  assert.equal(hostFrom(''), null);
  assert.equal(targetUrl('', 'https://shop.example/a'), 'https://shop.example/a');
  assert.equal(targetUrl('cdn.example', null), 'https://cdn.example/');
  assert.equal(targetUrl('http://cdn.example/x.js', null), 'http://cdn.example/x.js');
  assert.equal(targetUrl('not a url', null), null);
  assert.equal(labPath('why', { url: 'https://cdn.example/x.js?a=1&b', site: 'shop.example' }), 'ui/dashboard.html#lab?url=https%3A%2F%2Fcdn.example%2Fx.js%3Fa%3D1%26b&site=shop.example');
  assert.equal(labPath('blame', { filter: '||ads.example^$third-party' }), 'ui/dashboard.html#lab/blame?filter=%7C%7Cads.example%5E%24third-party');
  assert.equal(labPath('lab'), 'ui/dashboard.html#lab');
});

test('command line: copy report JSON', () => {
  const json = buildReport({
    site: 'shop.example',
    url: 'https://shop.example/',
    at: Date.UTC(2026, 9, 18, 12, 0, 0),
    counts: { blocked: 3, redirected: 1 },
    hosts: [{ host: 'ads.example', count: 3, rules: ['easylist:1'], filters: ['||ads.example^'], lists: ['easylist'], extra: 1 }],
    fp: { canvas: 2 },
    clipboardBlocked: 1,
    lookalike: { host: 'rnicrosoft.com', target: 'microsoft.com', reason: 'homoglyph' },
    version: '1.2.3',
  });
  const r = JSON.parse(json);
  assert.deepEqual(Object.keys(r), ['site', 'url', 'at', 'counts', 'blockedHosts', 'fp', 'clipboardBlocked', 'lookalike', 'version']);
  assert.equal(r.at, '2026-10-18T12:00:00.000Z');
  assert.deepEqual(r.blockedHosts, [{ host: 'ads.example', count: 3, rules: ['easylist:1'], filters: ['||ads.example^'], lists: ['easylist'] }]);
});

test('bisect session rules have their own label', () => {
  assert.equal(dynamicRuleLabel('_session', RULE_ID.SESSION_BISECT_START), 'nerdBisectRuleLabel');
  assert.equal(dynamicRuleLabel('_session', RULE_ID.SESSION_BISECT_END), 'nerdBisectRuleLabel');
  assert.equal(dynamicRuleLabel('_session', RULE_ID.SESSION_PROCEED_END), 'ruleProceed');
});

test('nerd popup locale keys exist in every language, Swiss spelling in German, none unused', () => {
  const load = (lang: string) =>
    JSON.parse(readFileSync(new URL(`../../src/_locales/${lang}/messages.json`, import.meta.url), 'utf8')) as Record<string, { message: string; placeholders?: object }>;
  const de = load('de');
  const prefixes = /^(nerdBisect|nerdPopup|nerdSl|nerdCmd|cmdNerd)/;
  const keys = Object.keys(de).filter((k) => prefixes.test(k));
  assert.ok(keys.length >= 40);
  for (const k of keys) assert.ok(!de[k]!.message.includes('ß'), `${k}: no sharp s in de-CH`);
  for (const lang of ['en', 'fr', 'it']) {
    const other = load(lang);
    for (const k of keys) {
      assert.ok(other[k]?.message, `${lang}: ${k}`);
      assert.deepEqual(Object.keys(other[k]!.placeholders ?? {}), Object.keys(de[k]!.placeholders ?? {}), `${lang}: ${k} placeholders`);
    }
  }
  // Every key the popup uses is defined, and every key with these prefixes is used somewhere.
  const read = (p: string) => readFileSync(new URL(`../../src/${p}`, import.meta.url), 'utf8');
  const src = ['ui/popup/nerd.ts', 'ui/popup/commands.ts', 'ui/popup/matched.ts', 'ui/popup/popup.html', 'ui/shared/labels.ts', 'manifest.base.json'].map(read).join('\n');
  for (const m of src.matchAll(/['"_](nerd(?:Bisect|Popup|Sl|Cmd)[A-Za-z]*|cmdNerd[A-Za-z]*)['"_]/g)) assert.ok(de[m[1]!], `missing ${m[1]}`);
  for (const k of keys) assert.ok(src.includes(k), `unused ${k}`);
});

test('command reference: usage with argument hints, no bisect cancel', () => {
  const help = commandHelp() as { usage: string; desc: string }[];
  const usage = help.map((c) => c.usage);
  assert.ok(usage.includes('why <url>'));
  assert.ok(usage.includes('blame <filter>'));
  assert.ok(usage.includes('allow <host>'));
  assert.ok(usage.includes('bisect'));
  assert.ok(!usage.includes('bisect cancel'));
  assert.ok(help.every((c) => c.desc.startsWith('nerdCmd')));
});
