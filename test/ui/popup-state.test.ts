// Unit tests for the Phase 3 popup logic (src/ui/popup/state.ts, report.ts,
// nerd.ts): the «Keine Verbindung» retry state machine, the delayed / minimum
// loading indicator, Swiss count formatting per UI language, fitting a host
// into its tile, the «Was geteilt wird» list summary, the lookalike diff runs
// and the new popup strings in all four locales.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

(globalThis as Record<string, unknown>).chrome = {
  i18n: { getMessage: (key: string, subs?: string[]) => (subs?.length ? `${key}(${subs.join(',')})` : key) },
  runtime: { sendMessage: async () => undefined },
};

const ROOT = new URL('../../src', import.meta.url).href;
const { CONN_INITIAL, CONN_HINT_AFTER, connReduce, withBusy, fmtCount, fitText } = await import(`${ROOT}/ui/popup/state.ts`);
const { listsSummary } = await import(`${ROOT}/ui/popup/report.ts`);
const { lookalikeRuns } = await import(`${ROOT}/ui/popup/nerd.ts`);
const { truncateMiddle } = await import(`${ROOT}/ui/shared/text.ts`);

type Conn = { phase: string; retrying: boolean; failures: number };
type Run = { text: string; diff: boolean };
const run = (events: string[], from: Conn = CONN_INITIAL): Conn => events.reduce((s, e) => connReduce(s, e), from);

test('connection: first load ok / fail', () => {
  assert.deepEqual(run(['request']), { phase: 'loading', retrying: false, failures: 0 });
  assert.deepEqual(run(['request', 'ok']), { phase: 'ready', retrying: false, failures: 0 });
  assert.deepEqual(run(['request', 'fail']), { phase: 'error', retrying: false, failures: 1 });
});

test('connection: retry keeps the error tile while it runs, counts failures, resets on success', () => {
  const failed = run(['request', 'fail']);
  const retrying = connReduce(failed, 'request');
  assert.deepEqual(retrying, { phase: 'error', retrying: true, failures: 1 }, 'the tile stays, the button is busy');
  const again = run(['fail', 'request', 'fail'], retrying);
  assert.equal(again.phase, 'error');
  assert.equal(again.retrying, false);
  assert.equal(again.failures, 3);
  assert.ok(again.failures >= CONN_HINT_AFTER, 'third failure emphasises the restart hint');
  assert.deepEqual(run(['request', 'ok'], again), { phase: 'ready', retrying: false, failures: 0 });
});

test('connection: a failed refresh of a drawn popup keeps it', () => {
  const ready = run(['request', 'ok']);
  assert.deepEqual(run(['request', 'fail'], ready), { phase: 'ready', retrying: false, failures: 0 });
});

/** Manual clock for withBusy. */
function fakeTimers() {
  let now = 0;
  let seq = 0;
  const pending = new Map<number, { at: number; fn: () => void }>();
  const flush = async () => {
    for (let i = 0; i < 5; i++) await Promise.resolve();
  };
  return {
    timers: {
      set: (fn: () => void, ms: number) => {
        const id = ++seq;
        pending.set(id, { at: now + ms, fn });
        return id;
      },
      clear: (id: unknown) => void pending.delete(id as number),
      now: () => now,
    },
    async advance(ms: number) {
      const end = now + ms;
      await flush();
      for (;;) {
        const next = [...pending.entries()].filter(([, t]) => t.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
        if (!next) break;
        pending.delete(next[0]);
        now = next[1].at;
        next[1].fn();
        await flush();
      }
      now = end;
      await flush();
    },
  };
}

test('busy: a fast task never shows the spinner', async () => {
  const clock = fakeTimers();
  const log: string[] = [];
  let finish!: (v: string) => void;
  const p = withBusy(() => new Promise<string>((r) => (finish = r)), (b: boolean) => log.push(`${clock.timers.now()}:${b}`), {}, clock.timers);
  await clock.advance(100);
  finish('ok');
  assert.equal(await p, 'ok');
  await clock.advance(500);
  assert.deepEqual(log, []);
});

test('busy: spinner after 150 ms, kept for at least 300 ms', async () => {
  const clock = fakeTimers();
  const log: string[] = [];
  let finish!: (v: number) => void;
  let done = false;
  const p = withBusy(() => new Promise<number>((r) => (finish = r)), (b: boolean) => log.push(`${clock.timers.now()}:${b}`), {}, clock.timers).then((v: number) => {
    done = true;
    return v;
  });
  await clock.advance(200);
  assert.deepEqual(log, ['150:true']);
  finish(7); // answer at 200 ms: the spinner stays until 450 ms
  await clock.advance(100);
  assert.deepEqual(log, ['150:true']);
  assert.equal(done, false, 'still busy at 300 ms');
  await clock.advance(200);
  assert.equal(await p, 7);
  assert.deepEqual(log, ['150:true', '450:false']);
});

test('busy: a slow task ends the spinner right away and rethrows errors', async () => {
  const clock = fakeTimers();
  const log: string[] = [];
  let fail!: (e: Error) => void;
  const p = withBusy(() => new Promise<never>((_, r) => (fail = r)), (b: boolean) => log.push(`${clock.timers.now()}:${b}`), {}, clock.timers);
  await clock.advance(1000);
  fail(new Error('boom'));
  await assert.rejects(p, /boom/);
  assert.deepEqual(log, ['150:true', '1000:false']);
});

test('counts: Swiss grouping per UI language', () => {
  assert.match(fmtCount(12847, 'de'), /^12[’']847$/);
  assert.equal(fmtCount(999, 'de'), '999');
  assert.match(fmtCount(1000, 'de'), /^1[’']000$/, 'groups from 1000 on');
  assert.match(fmtCount(1234567, 'it'), /^1[’'.]234[’'.]567$/);
  assert.match(fmtCount(12847, 'fr'), /^12[   ’']847$/, 'narrow space or apostrophe, depending on the ICU data');
  assert.match(fmtCount(12847, 'en'), /^12[’',]847$/);
  assert.equal(fmtCount(3.6, 'de'), '4');
  assert.equal(fmtCount(Number.NaN, 'de'), '0');
});

test('host fitting: keeps the full host when it fits, else the longest middle cut', () => {
  const host = 'portal.kundenservice-verwaltung.beispiel-versicherung.ch';
  assert.equal(fitText('20min.ch', () => true, truncateMiddle), '20min.ch');
  const fit18 = fitText(host, (c: string) => c.length <= 18, truncateMiddle);
  assert.equal(fit18.length, 18);
  assert.ok(fit18.includes('…'));
  assert.ok(fit18.startsWith('portal'));
  assert.ok(fit18.endsWith('.ch'));
  // Nothing fits: the shortest cut.
  assert.equal(fitText(host, () => false, truncateMiddle), truncateMiddle(host, 4));
});

test('report: list summary', () => {
  assert.equal(listsSummary([]), '-');
  assert.equal(listsSummary(['EasyList']), 'EasyList');
  assert.equal(listsSummary(['EasyList', 'EasyPrivacy']), 'EasyList, EasyPrivacy');
  assert.equal(listsSummary(['EasyList', 'EasyPrivacy', 'a', 'b', 'c', 'd']), 'EasyList, EasyPrivacy +4');
});

test('lookalike runs mark what differs from the imitated domain', () => {
  const runs: Run[] = lookalikeRuns('rnicrosoft-login.com', 'microsoft.com');
  assert.equal(runs.map((r) => r.text).join(''), 'rnicrosoft-login.com');
  assert.deepEqual(runs.filter((r) => r.diff).map((r) => r.text), ['rn', '-login']);
  assert.deepEqual(lookalikeRuns('microsoft.com', 'microsoft.com'), [{ text: 'microsoft.com', diff: false }]);
  assert.deepEqual((lookalikeRuns('paypa1.com', 'paypal.com') as Run[]).filter((r) => r.diff), [{ text: '1', diff: true }]);
});

test('popup strings: present in all four locales, no middle dots, single ellipsis', () => {
  const keys = [
    'popupReport', 'popupNotActiveTitle', 'popupNotActiveText', 'popupPausedTitle', 'popupPausedText', 'popupContactIt',
    'popupNoConnTitle', 'popupNoConnText', 'popupNoConnHint', 'popupSiteOffNote', 'popupCounterOff', 'popupCounterOn',
    'popupLegendBlocked', 'popupLegendReplaced', 'popupReloadBar', 'reportSheetTitle', 'reportSheetGithub', 'reportSheetEmail',
    'reportSheetTo', 'reportWhatShared', 'reportSharedAside', 'reportNotSharedShort', 'reportKeySite', 'reportKeyVersion',
    'reportKeyBrowser', 'reportKeyMode', 'reportKeyLists', 'reportOpenDraft', 'reportGithubFailTitle', 'reportGithubFailText',
    'reportRetryOpen', 'reportCloseSheet', 'nerdSlLookTitle', 'nerdSlLookHomoglyph', 'nerdSlLookTypo', 'nerdSlLookCombo',
    'nerdSlLookCheck', 'nerdSlClipLegend',
  ];
  for (const lang of ['de', 'en', 'fr', 'it']) {
    const msgs = JSON.parse(readFileSync(new URL(`../../src/_locales/${lang}/messages.json`, import.meta.url), 'utf8')) as Record<string, { message: string }>;
    for (const k of keys) {
      const m = msgs[k]?.message;
      assert.ok(m, `${lang}: ${k}`);
      assert.ok(!m.includes('·'), `${lang}: ${k} has no middle dot`);
      assert.ok(!m.includes('...'), `${lang}: ${k} uses the ellipsis character`);
    }
    assert.ok(msgs.popupReport!.message.endsWith('…'), `${lang}: «Melden…» opens a further step`);
    for (const gone of ['popupErrorTitle', 'popupErrorText', 'popupCountOffSiteOff', 'actionDismiss', 'reportTitle', 'nerdSlLookalike']) {
      assert.equal(msgs[gone], undefined, `${lang}: ${gone} removed`);
    }
  }
});
