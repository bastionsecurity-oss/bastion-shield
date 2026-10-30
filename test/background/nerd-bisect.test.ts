// Tests for the nerd-mode filter bisect: the pure state machine
// (src/shared/bisect.ts) driven by simulated users, and the service-worker
// Bisector (src/background/nerd-bisect.ts) against in-memory chrome.* fakes.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isSystemAllowRuleId, PRIORITY, RULE_ID } from '../../src/shared/constants.ts';
import {
  allowConditions,
  answerBisect,
  badgeStep,
  bisectProgress,
  halvingSteps,
  isBisectableHost,
  cosmeticExceptionBody,
  isBisectRuleId,
  isImportantFilter,
  keepCosmeticLines,
  keepFilterLines,
  MAX_CANDIDATES,
  MAX_ROUNDS,
  startBisect,
} from '../../src/shared/bisect.ts';
import type { BisectMachine } from '../../src/shared/bisect.ts';
import type { BisectView } from '../../src/shared/types.ts';
import { Bisector, collectCandidates, cosmeticOverrideOf } from '../../src/background/nerd-bisect.ts';
import type { BisectDeps } from '../../src/background/nerd-bisect.ts';
import { NERD_BISECT_COMMAND, runNerdCommand } from '../../src/background/nerd-commands.ts';
import type { NerdCommandDeps } from '../../src/background/nerd-commands.ts';

const hostsN = (n: number): string[] => Array.from({ length: n }, (_, i) => `h${i}.example`);

/** Run the machine with a user who answers truthfully: the page works iff every host in `needed` is let through. */
function simulate(hosts: string[], needed: string[]): { m: BisectMachine; tests: number; maxSeen: number } {
  let m = startBisect(hosts);
  let tests = 0;
  let maxSeen = 0;
  while (m.result === 'testing') {
    const p = bisectProgress(m);
    assert.equal(p.step, tests + 1);
    maxSeen = Math.max(maxSeen, p.maxSteps);
    const allowed = new Set(m.allowed);
    m = answerBisect(m, needed.every((h) => allowed.has(h)));
    tests++;
    assert.ok(tests <= 64, 'terminates');
  }
  return { m, tests, maxSeen };
}

test('bisect: first step lets everything through; still broken means clean', () => {
  const m = startBisect(['a.example', 'b.example', 'c.example']);
  assert.equal(m.result, 'testing');
  assert.equal(m.test, 'all');
  assert.deepEqual(m.allowed, ['a.example', 'b.example', 'c.example']);
  const clean = answerBisect(m, false);
  assert.equal(clean.result, 'clean');
  assert.deepEqual(clean.allowed, []);
  // Finished machines ignore further answers.
  assert.equal(answerBisect(clean, true), clean);
});

test('bisect: no candidates is clean right away', () => {
  const m = startBisect([]);
  assert.equal(m.result, 'clean');
  assert.deepEqual(bisectProgress(m), { step: 0, maxSteps: 0 });
});

test('bisect: a single candidate is found after the verify step', () => {
  const m = startBisect(['only.example']);
  assert.deepEqual(bisectProgress(m), { step: 1, maxSteps: 1 });
  const f = answerBisect(m, true);
  assert.equal(f.result, 'found');
  assert.deepEqual(f.culprits, ['only.example']);
  assert.equal(f.partial, false);
});

test('bisect: one culprit takes at most 2 + ceil(log2 n) steps (verify, halving, check), for every n and position', () => {
  for (let n = 2; n <= 40; n++) {
    const hosts = hostsN(n);
    for (const culprit of hosts) {
      const { m, tests, maxSeen } = simulate(hosts, [culprit]);
      assert.equal(m.result, 'found', `n=${n} ${culprit}`);
      assert.deepEqual(m.culprits, [culprit], `n=${n} ${culprit}`);
      assert.ok(tests <= 2 + halvingSteps(n), `n=${n}: ${tests} tests`);
      assert.equal(maxSeen, 2 + Math.ceil(Math.log2(n)), `announced worst case for n=${n}`);
    }
  }
});

test('bisect: halving keeps the suspects and pins straight', () => {
  const hosts = hostsN(8);
  let m = answerBisect(startBisect(hosts), true);
  assert.equal(m.test, 'half');
  assert.deepEqual(m.allowed, hosts.slice(0, 4));
  // Broken with the first half let through: the culprit is in the second half, the first half is pinned.
  m = answerBisect(m, false);
  assert.deepEqual(m.pinned, hosts.slice(0, 4));
  assert.deepEqual(m.suspects, hosts.slice(4));
  assert.deepEqual(m.allowed, [...hosts.slice(0, 4), ...hosts.slice(4, 6)]);
  assert.deepEqual(bisectProgress(m), { step: 3, maxSteps: 5 });
});

test('bisect: two interacting hosts are both found', () => {
  const hosts = hostsN(8);
  for (let i = 0; i < hosts.length; i++) {
    for (let j = i + 1; j < hosts.length; j++) {
      const needed = [hosts[i]!, hosts[j]!];
      const { m } = simulate(hosts, needed);
      assert.equal(m.result, 'found');
      assert.equal(m.partial, false);
      assert.deepEqual([...m.culprits].sort(), [...needed].sort(), `pair ${needed.join('+')}`);
    }
  }
});

test('bisect: too many interacting hosts end in a working superset (best effort)', () => {
  const hosts = hostsN(16);
  const needed = [hosts[1]!, hosts[5]!, hosts[9]!, hosts[13]!, hosts[15]!];
  assert.ok(needed.length > MAX_ROUNDS);
  const { m } = simulate(hosts, needed);
  assert.equal(m.result, 'found');
  assert.equal(m.partial, true);
  for (const h of needed) assert.ok(m.culprits.includes(h), h);
});

test('bisect: inconsistent answers still terminate', () => {
  const hosts = hostsN(20);
  for (let seed = 0; seed < 50; seed++) {
    let m = startBisect(hosts);
    let x = seed + 1;
    let n = 0;
    while (m.result === 'testing') {
      x = (x * 1103515245 + 12345) & 0x7fffffff;
      m = answerBisect(m, (x & 4) === 0);
      assert.ok(++n < 60);
    }
    if (m.result === 'found') assert.ok(m.culprits.length > 0);
  }
});

test('bisect: candidates are capped', () => {
  const m = startBisect(hostsN(MAX_CANDIDATES + 10));
  assert.equal(m.hosts.length, MAX_CANDIDATES);
});

test('bisect: allow conditions exclude still-blocked subdomains', () => {
  const all = ['a.com', 'x.a.com', 'y.x.a.com', 'b.net'];
  assert.deepEqual(allowConditions(['b.net'], all), [{ requestDomains: ['b.net'] }]);
  assert.deepEqual(allowConditions(['a.com', 'b.net'], all), [{ requestDomains: ['b.net'] }, { requestDomains: ['a.com'], excludedRequestDomains: ['x.a.com', 'y.x.a.com'] }]);
  // y.x.a.com stays allowed by its own rule even though a.com's rule excludes it.
  assert.deepEqual(allowConditions(['a.com', 'y.x.a.com'], all), [
    { requestDomains: ['y.x.a.com'] },
    { requestDomains: ['a.com'], excludedRequestDomains: ['x.a.com'] },
  ]);
  assert.deepEqual(allowConditions([], all), []);
});

test('bisect: host filter, rule ids, keep lines', () => {
  assert.ok(isBisectableHost('cdn.example.com'));
  assert.ok(isBisectableHost('xn--bcher-kva.ch'));
  assert.ok(isBisectableHost('10.0.0.1'));
  assert.ok(!isBisectableHost('[::1]'));
  assert.ok(!isBisectableHost('Example.com'));
  assert.ok(!isBisectableHost(''));
  assert.ok(isBisectRuleId(RULE_ID.SESSION_BISECT_START));
  assert.ok(!isBisectRuleId(RULE_ID.SESSION_PROCEED_END));
  assert.ok(isSystemAllowRuleId('_session', RULE_ID.SESSION_BISECT_START + 5));
  assert.ok(PRIORITY.BISECT_ALLOW > PRIORITY.SITE_USER_BLOCK && PRIORITY.BISECT_ALLOW < PRIORITY.SITE_DISABLED);
  assert.deepEqual(keepFilterLines([{ host: 'cdn.shop.example' }, { host: 'cdn.shop.example' }], 'shop.example', '2026-10-18'), [
    '! Bastion bisect 2026-10-18: shop.example',
    '@@||cdn.shop.example^$domain=shop.example',
  ]);
});

test('bisect: an $important block gets an important exception', () => {
  assert.ok(isImportantFilter('||ads.example^$important'));
  assert.ok(isImportantFilter('||ads.example^$script,Important,third-party'));
  assert.ok(!isImportantFilter('||ads.example^$third-party'));
  assert.ok(!isImportantFilter('||important.example^'));
  assert.ok(!isImportantFilter('/ads$important/'), 'a $ inside a regex is not an option');
  assert.ok(!isImportantFilter('example.com##.ad'));
  assert.deepEqual(
    keepFilterLines(
      [
        { host: 'cdn.shop.example', filters: ['||cdn.shop.example^$third-party', '||cdn.shop.example^$important,script'] },
        { host: 'img.shop.example', filters: ['||img.shop.example^'] },
      ],
      'shop.example',
      '2026-10-18',
    ),
    ['! Bastion bisect 2026-10-18: shop.example', '@@||cdn.shop.example^$domain=shop.example,important', '@@||img.shop.example^$domain=shop.example'],
  );
  assert.deepEqual(keepFilterLines([{ host: 'a.example' }], 'shop.example', '2026-10-18', 'allow'), ['! Bastion allow 2026-10-18: shop.example', '@@||a.example^$domain=shop.example']);
});

test('bisect: progress bound is honest (never below the step) and fits the badge', () => {
  for (let n = 1; n <= MAX_CANDIDATES; n += 5) {
    const hosts = hostsN(n);
    let m = startBisect(hosts);
    const first = bisectProgress(m).maxSteps;
    assert.equal(first, n === 1 ? 1 : 2 + Math.ceil(Math.log2(n)), `n=${n}`);
    // The culprit is the last host: always the longer half.
    while (m.result === 'testing') {
      const p = bisectProgress(m);
      assert.ok(p.step <= p.maxSteps && p.maxSteps <= first, `n=${n} step ${p.step}/${p.maxSteps}`);
      const b = badgeStep(m)!;
      assert.ok(b.length <= 4, b);
      m = answerBisect(m, m.allowed.includes(hosts[n - 1]!));
    }
    assert.equal(badgeStep(m), null);
  }
});

test('collectCandidates groups by host, most blocked first', () => {
  const { candidates, lists } = collectCandidates([
    { host: 'a.example', rule: 'easylist:4', list: 'easylist' },
    { host: 'b.example', rule: 'easyprivacy:9' },
    { host: 'b.example', rule: 'easyprivacy:9', list: 'easyprivacy' },
    { host: 'B.example.' },
    { host: '[::1]' },
  ]);
  assert.deepEqual(candidates, [
    { host: 'b.example', rules: ['easyprivacy:9'], count: 3 },
    { host: 'a.example', rules: ['easylist:4'], count: 1 },
  ]);
  assert.deepEqual(lists, { 'b.example': ['easyprivacy'], 'a.example': ['easylist'] });
});

// ---------------------------------------------------------------- Bisector --

interface Fake {
  session: Map<string, unknown>;
  rules: chrome.declarativeNetRequest.Rule[];
  reloads: number[];
  liveTabs: Set<number>;
}

function installChrome(): Fake {
  const fake: Fake = { session: new Map(), rules: [], reloads: [], liveTabs: new Set([7]) };
  (globalThis as unknown as { chrome: unknown }).chrome = {
    storage: {
      session: {
        get: async (keys: string | string[] | null) => {
          const out: Record<string, unknown> = {};
          const list = keys === null ? Array.from(fake.session.keys()) : Array.isArray(keys) ? keys : [keys];
          for (const k of list) if (fake.session.has(k)) out[k] = structuredClone(fake.session.get(k));
          return out;
        },
        set: async (items: Record<string, unknown>) => {
          for (const [k, v] of Object.entries(items)) fake.session.set(k, structuredClone(v));
        },
        remove: async (keys: string | string[]) => {
          for (const k of Array.isArray(keys) ? keys : [keys]) fake.session.delete(k);
        },
      },
    },
    declarativeNetRequest: {
      getSessionRules: async () => structuredClone(fake.rules),
      updateSessionRules: async (u: { removeRuleIds?: number[]; addRules?: chrome.declarativeNetRequest.Rule[] }) => {
        fake.rules = fake.rules.filter((r) => !(u.removeRuleIds ?? []).includes(r.id));
        for (const r of u.addRules ?? []) {
          if (fake.rules.some((x) => x.id === r.id)) throw new Error(`duplicate id ${r.id}`);
          fake.rules.push(structuredClone(r));
        }
      },
    },
    tabs: {
      get: async (tabId: number) => {
        if (!fake.liveTabs.has(tabId)) throw new Error('No tab');
        return { id: tabId, url: 'https://www.shop.example/' };
      },
      reload: async (tabId: number) => {
        fake.reloads.push(tabId);
      },
    },
  };
  return fake;
}

function deps(over: Partial<BisectDeps> = {}): BisectDeps & { added: string[][] } {
  const added: string[][] = [];
  return {
    added,
    blockedOnTab: async () => [
      { host: 'ads.example', rule: 'easylist:1', list: 'easylist' },
      { host: 'ads.example', rule: 'easylist:1' },
      { host: 'cdn.shop.example', rule: 'easyprivacy:7' },
      { host: 'track.example', rule: 'easyprivacy:8' },
      { host: 'pixel.example' },
    ],
    siteOf: async () => 'shop.example',
    describeRules: async (rules) => ({ filters: rules.map((r) => `||filter-for-${r}^`), lists: rules.map((r) => r.split(':')[0]!) }),
    addCustomFilters: async (lines) => {
      added.push([...lines]);
    },
    ...over,
  };
}

const bisectOf = (r: unknown): BisectView => {
  assert.ok(r && typeof r === 'object' && 'bisect' in r, JSON.stringify(r));
  const v = (r as { bisect: BisectView | null }).bisect;
  assert.ok(v);
  return v;
};

const allowedBy = (fake: Fake, tabId: number): string[] =>
  fake.rules
    .filter((r) => isBisectRuleId(r.id))
    .flatMap((r) => {
      assert.equal(r.priority, PRIORITY.BISECT_ALLOW);
      assert.equal(r.action.type, 'allow');
      assert.deepEqual(r.condition.tabIds, [tabId]);
      assert.equal(r.condition.resourceTypes, undefined, 'main_frame is never let through');
      return r.condition.requestDomains ?? [];
    })
    .sort();

test('Bisector: start, answers, found culprit, keep', async () => {
  const fake = installChrome();
  fake.rules.push({ id: RULE_ID.SESSION_PROCEED_START, priority: 900, action: { type: 'allow' }, condition: {} } as chrome.declarativeNetRequest.Rule);
  const d = deps();
  const b = new Bisector(d);
  const tabId = 7;

  let v = bisectOf(await b.handle({ type: 'nerd:bisect', action: 'start', tabId }));
  assert.equal(v.phase, 'testing');
  assert.equal(v.site, 'shop.example');
  assert.deepEqual({ step: v.step, maxSteps: v.maxSteps, remaining: v.remaining }, { step: 1, maxSteps: 4, remaining: 4 });
  assert.deepEqual(allowedBy(fake, tabId), ['ads.example', 'cdn.shop.example', 'pixel.example', 'track.example']);
  assert.deepEqual(fake.reloads, [tabId]);
  // Starting again while testing is idempotent.
  assert.equal(bisectOf(await b.handle({ type: 'nerd:bisect', action: 'start', tabId })).step, 1);

  // The page needs cdn.shop.example. Answer truthfully until found.
  while (v.phase === 'testing') {
    v = bisectOf(await b.handle({ type: 'nerd:bisect', action: 'answer', tabId, works: v.allowed.includes('cdn.shop.example') }));
  }
  assert.equal(v.phase, 'found');
  assert.equal(v.culprit?.host, 'cdn.shop.example');
  assert.deepEqual(v.culprit?.filters, ['||filter-for-easyprivacy:7^']);
  assert.deepEqual(v.culprit?.lists, ['easyprivacy']);
  assert.equal(v.also, undefined);
  // Found: only the culprit stays let through.
  assert.deepEqual(allowedBy(fake, tabId), ['cdn.shop.example']);
  assert.deepEqual(b.view(tabId)?.phase, 'found');

  // The proceed rule was never touched.
  assert.ok(fake.rules.some((r) => r.id === RULE_ID.SESSION_PROCEED_START));

  const kept = await b.handle({ type: 'nerd:bisect', action: 'keep', tabId });
  assert.deepEqual(kept, { bisect: null });
  assert.equal(d.added.length, 1);
  assert.match(d.added[0]![0]!, /^! Bastion bisect \d{4}-\d{2}-\d{2}: shop\.example$/);
  assert.equal(d.added[0]![1], '@@||cdn.shop.example^$domain=shop.example');
  assert.deepEqual(allowedBy(fake, tabId), []);
  assert.equal(fake.session.size, 0);
  assert.equal(b.view(tabId), null);
  assert.ok(fake.rules.some((r) => r.id === RULE_ID.SESSION_PROCEED_START));
});

test('Bisector: still broken with everything allowed is clean; cancel; errors', async () => {
  const fake = installChrome();
  const b = new Bisector(deps());
  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'answer', tabId: 7, works: true }), { error: 'not testing' });
  await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 });
  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'answer', tabId: 7 }), { error: 'invalid answer' });
  const v = bisectOf(await b.handle({ type: 'nerd:bisect', action: 'answer', tabId: 7, works: false }));
  assert.equal(v.phase, 'clean');
  assert.deepEqual(allowedBy(fake, 7), [], 'clean removes the test rules');
  assert.deepEqual(fake.reloads, [7, 7]);
  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'keep', tabId: 7 }), { error: 'nothing found' });
  // Dismissing a clean result does not reload again.
  assert.equal(bisectOf(await b.handle({ type: 'nerd:bisect', action: 'cancel', tabId: 7 })).phase, 'cancelled');
  assert.deepEqual(fake.reloads, [7, 7]);
  assert.equal(b.view(7), null);

  // Cancel mid-test: rules gone, page reloaded.
  await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 });
  assert.ok(allowedBy(fake, 7).length > 0);
  assert.equal(bisectOf(await b.handle({ type: 'nerd:bisect', action: 'cancel', tabId: 7 })).phase, 'cancelled');
  assert.deepEqual(allowedBy(fake, 7), []);
  assert.equal(fake.reloads.length, 4);
});

test('Bisector: nothing blocked is clean without touching the tab', async () => {
  const fake = installChrome();
  const b = new Bisector(deps({ blockedOnTab: async () => [] }));
  assert.equal(bisectOf(await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 })).phase, 'clean');
  assert.deepEqual(fake.reloads, []);
  assert.deepEqual(fake.rules, []);
});

test('Bisector: keep is refused while custom filters are locked', async () => {
  installChrome();
  const b = new Bisector(
    deps({
      blockedOnTab: async () => [{ host: 'cdn.shop.example', rule: 'easylist:3' }],
      addCustomFilters: async () => {
        throw new Error('locked');
      },
    }),
  );
  await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 });
  assert.equal(bisectOf(await b.handle({ type: 'nerd:bisect', action: 'answer', tabId: 7, works: true })).phase, 'found');
  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'keep', tabId: 7 }), { error: 'locked' });
  assert.equal(b.view(7)?.phase, 'found', 'the result stays so the user can still cancel');
});

test('Bisector: state survives a service-worker restart; stale tabs and orphans are cleaned', async () => {
  const fake = installChrome();
  const first = new Bisector(deps());
  await first.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 });
  const owned = allowedBy(fake, 7);
  // An orphan rule nobody owns, and a stored bisect for a tab that is gone.
  fake.rules.push({ id: RULE_ID.SESSION_BISECT_END, priority: 950, action: { type: 'allow' }, condition: { tabIds: [99], requestDomains: ['x.example'] } } as chrome.declarativeNetRequest.Rule);
  fake.session.set('nerd:bisect:42', { ...(fake.session.get('nerd:bisect:7') as object), tabId: 42 });

  const second = new Bisector(deps());
  const v = bisectOf(await second.handle({ type: 'nerd:bisect', action: 'state', tabId: 7 }));
  assert.equal(v.phase, 'testing');
  assert.equal(v.step, 1);
  assert.deepEqual(allowedBy(fake, 7), owned);
  assert.ok(!fake.rules.some((r) => r.id === RULE_ID.SESSION_BISECT_END), 'orphan removed');
  assert.ok(!fake.session.has('nerd:bisect:42'), 'closed tab dropped');
  // The restored bisect goes on.
  assert.equal(bisectOf(await second.handle({ type: 'nerd:bisect', action: 'answer', tabId: 7, works: true })).step, 2);
});

test('Bisector: navigation to another site and tab close end the bisect', async () => {
  const fake = installChrome();
  const b = new Bisector(deps());
  await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 });
  // The test reload itself keeps it.
  b.onCommitted(7, 'https://www.shop.example/cart');
  await b.handle({ type: 'nerd:bisect', action: 'state', tabId: 7 });
  assert.equal(b.view(7)?.phase, 'testing');
  b.onCommitted(7, 'https://elsewhere.example/');
  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'state', tabId: 7 }), { bisect: null });
  assert.deepEqual(allowedBy(fake, 7), []);

  await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 });
  b.onTabGone(7);
  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'state', tabId: 7 }), { bisect: null });
  assert.deepEqual(allowedBy(fake, 7), []);
  assert.equal(fake.session.size, 0);
});

test('Bisector: DNR failures become errors, never throws', async () => {
  const fake = installChrome();
  (chrome.declarativeNetRequest as unknown as { updateSessionRules: () => Promise<void> }).updateSessionRules = async () => {
    throw new Error('quota');
  };
  const b = new Bisector(deps());
  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 }), { error: 'quota' });
  assert.equal(b.view(7), null);
  assert.deepEqual(fake.reloads, []);
  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'bogus' as 'state', tabId: 7 }), { error: 'invalid action' });
});

test('Bisector: the badge shows the step while testing and is handed back afterwards', async () => {
  installChrome();
  const badges: [number, string | null][] = [];
  const b = new Bisector(deps({ badge: (tabId, text) => badges.push([tabId, text]) }));
  let v = bisectOf(await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 }));
  assert.deepEqual(badges.at(-1), [7, `1/${v.maxSteps}`]);
  assert.ok(b.holdsBadge(7));
  // The test reload resets the badge in the browser: it is set again on commit.
  badges.length = 0;
  b.onCommitted(7, 'https://www.shop.example/');
  await b.handle({ type: 'nerd:bisect', action: 'state', tabId: 7 });
  assert.deepEqual(badges[0], [7, `1/${v.maxSteps}`]);
  while (v.phase === 'testing') {
    v = bisectOf(await b.handle({ type: 'nerd:bisect', action: 'answer', tabId: 7, works: v.allowed.includes('cdn.shop.example') }));
    if (v.phase === 'testing') assert.deepEqual(badges.at(-1), [7, `${v.step}/${v.maxSteps}`]);
  }
  assert.deepEqual(badges.at(-1), [7, null], 'found: the normal badge comes back');
  assert.ok(!b.holdsBadge(7));
  const n = badges.length;
  await b.handle({ type: 'nerd:bisect', action: 'cancel', tabId: 7 });
  assert.equal(badges.length, n, 'nothing to hand back twice');

  // Cancel mid-test hands the badge back too.
  await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 });
  assert.ok(b.holdsBadge(7));
  await b.handle({ type: 'nerd:bisect', action: 'cancel', tabId: 7 });
  assert.deepEqual(badges.at(-1), [7, null]);
  assert.ok(!b.holdsBadge(7));
});

test('Bisector: cancelAll (nerd mode off) removes every bisect without reloading', async () => {
  const fake = installChrome();
  fake.liveTabs.add(8);
  const badges: [number, string | null][] = [];
  const b = new Bisector(deps({ badge: (tabId, text) => badges.push([tabId, text]) }));
  await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 });
  await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 8 });
  const tabsWithRules = new Set(fake.rules.filter((r) => isBisectRuleId(r.id)).flatMap((r) => r.condition.tabIds ?? []));
  assert.deepEqual([...tabsWithRules].sort(), [7, 8]);
  const reloads = fake.reloads.length;
  await b.cancelAll();
  assert.equal(fake.rules.filter((r) => isBisectRuleId(r.id)).length, 0);
  assert.equal(fake.session.size, 0);
  assert.equal(fake.reloads.length, reloads, 'no reload');
  assert.equal(b.view(7), null);
  assert.deepEqual(badges.slice(-2).sort(), [
    [7, null],
    [8, null],
  ]);
  // Also after a worker restart (state only in storage).
  await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 });
  const fresh = new Bisector(deps());
  await fresh.cancelAll();
  assert.equal(fake.rules.filter((r) => isBisectRuleId(r.id)).length, 0);
  assert.equal(fake.session.size, 0);
});

test('Bisector: hosts lists the blocked hosts, allow adds a narrow exception', async () => {
  installChrome();
  const d = deps({
    describeRules: async (rules) => ({ filters: rules.map((r) => (r === 'easylist:1' ? '||ads.example^$important' : `||x-${r}^`)), lists: rules.map((r) => r.split(':')[0]!) }),
  });
  const b = new Bisector(d);
  type Hosts = { hosts: { host: string; count: number; filters: string[]; lists: string[] }[] };
  const plain = (await b.handle({ type: 'nerd:bisect', action: 'hosts', tabId: 7 })) as Hosts;
  assert.deepEqual(
    plain.hosts.map((x) => [x.host, x.count, x.filters.length]),
    [
      ['ads.example', 2, 0],
      ['cdn.shop.example', 1, 0],
      ['pixel.example', 1, 0],
      ['track.example', 1, 0],
    ],
  );
  const full = (await b.handle({ type: 'nerd:bisect', action: 'hosts', tabId: 7, describe: true })) as Hosts;
  assert.deepEqual(full.hosts[0], { host: 'ads.example', rules: ['easylist:1'], count: 2, filters: ['||ads.example^$important'], lists: ['easylist'] });

  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'allow', tabId: 7, host: 'ADS.example.' }), { added: ['@@||ads.example^$domain=shop.example,important'] });
  assert.match(d.added[0]![0]!, /^! Bastion allow \d{4}-\d{2}-\d{2}: shop\.example$/);
  // A host that was not blocked here still gets a plain exception.
  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'allow', tabId: 7, host: 'cdn.other.example' }), { added: ['@@||cdn.other.example^$domain=shop.example'] });
  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'allow', tabId: 7, host: 'not a host' }), { error: 'invalid host' });
  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'allow', tabId: 7 }), { error: 'invalid host' });

  const locked = new Bisector(
    deps({
      addCustomFilters: async () => {
        throw new Error('locked');
      },
    }),
  );
  assert.deepEqual(await locked.handle({ type: 'nerd:bisect', action: 'allow', tabId: 7, host: 'ads.example' }), { error: 'locked' });
});

test('Bisector: keep writes an important exception for an $important culprit', async () => {
  installChrome();
  const d = deps({
    blockedOnTab: async () => [{ host: 'cdn.shop.example', rule: 'bastion:3' }],
    describeRules: async () => ({ filters: ['||cdn.shop.example^$important'], lists: ['bastion'] }),
  });
  const b = new Bisector(d);
  await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 });
  assert.equal(bisectOf(await b.handle({ type: 'nerd:bisect', action: 'answer', tabId: 7, works: true })).phase, 'found');
  await b.handle({ type: 'nerd:bisect', action: 'keep', tabId: 7 });
  assert.equal(d.added[0]![1], '@@||cdn.shop.example^$domain=shop.example,important');
});

test('Bisector: a dynamic $important block (no filter text) still gets an important exception', async () => {
  installChrome();
  const d = deps({
    blockedOnTab: async () => [{ host: 'cdn.shop.example', rule: `_dynamic:${RULE_ID.MY_LISTS_START + 5}` }],
    describeRules: async () => ({ filters: [], lists: [], important: true }),
  });
  const b = new Bisector(d);
  await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 });
  assert.equal(bisectOf(await b.handle({ type: 'nerd:bisect', action: 'answer', tabId: 7, works: true })).phase, 'found');
  await b.handle({ type: 'nerd:bisect', action: 'keep', tabId: 7 });
  assert.equal(d.added[0]![1], '@@||cdn.shop.example^$domain=shop.example,important');
  assert.deepEqual(keepFilterLines([{ host: 'a.example', important: true }], 'shop.example', '2026-10-18', 'allow')[1], '@@||a.example^$domain=shop.example,important');
});

test('nerd-bisect command: toggles start/cancel, only with nerd mode and the log on', async () => {
  const sent: string[] = [];
  let shown: string | null = null;
  let popups = 0;
  const cmdDeps = (can: boolean): NerdCommandDeps => ({
    ready: Promise.resolve(),
    canBisect: () => can,
    isReady: () => true,
    activeTabId: async () => 5,
    openPopup: async () => {
      popups++;
    },
    bisect: async (msg) => {
      sent.push(`${msg.action}:${msg.tabId}`);
      if (msg.action === 'state') return { bisect: shown ? { phase: shown } : null };
      shown = msg.action === 'start' ? 'testing' : null;
      return { bisect: null };
    },
  });
  assert.equal(await runNerdCommand(NERD_BISECT_COMMAND, 3, cmdDeps(false)), 'ignored');
  assert.equal(await runNerdCommand('other', 3, cmdDeps(true)), 'ignored');
  assert.deepEqual(sent, []);
  assert.equal(await runNerdCommand(NERD_BISECT_COMMAND, 3, cmdDeps(true)), 'started');
  assert.equal(await runNerdCommand(NERD_BISECT_COMMAND, 3, cmdDeps(true)), 'cancelled');
  // No tab in the event: the active tab.
  assert.equal(await runNerdCommand(NERD_BISECT_COMMAND, undefined, cmdDeps(true)), 'started');
  assert.deepEqual(sent, ['state:3', 'start:3', 'state:3', 'cancel:3', 'state:5', 'start:5']);
  // The popup opens after each start, not after a cancel.
  assert.equal(popups, 2);
  // Already opened from the command event: not again.
  shown = null;
  assert.equal(await runNerdCommand(NERD_BISECT_COMMAND, 9, cmdDeps(true), true), 'started');
  assert.equal(popups, 2);
});

// ------------------------------------------------------- cosmetic phase --

/** The 20min.ch case: two lists hide the same in-feed aside, which breaks the grid. */
const ASIDE = 'section aside:has(> div > div > div[data-ad-unit-id])';
const COSMETIC = {
  lists: ['ublock', 'regional-fr', 'easylist', 'custom'],
  selectors: {
    ublock: [ASIDE, '.teaser-ad', '#skyscraper'],
    'regional-fr': [ASIDE, '.pub { min-height: 0 }'],
    easylist: ['.banner'],
  } as Record<string, string[]>,
};

/** Clean network bisect on tab 7 (nothing blocked), ready for the cosmetic phase. */
async function cleanBisect(over: Partial<BisectDeps> = {}) {
  const fake = installChrome();
  const d = deps({ blockedOnTab: async () => [], cosmeticCandidates: async () => structuredClone(COSMETIC), ...over });
  const b = new Bisector(d);
  assert.equal(bisectOf(await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 })).phase, 'clean');
  return { fake, d, b };
}

/** The page is broken while a culprit list still applies one of its breaking selectors. */
async function brokenBy(b: Bisector, culprits: Record<string, string[]>): Promise<boolean> {
  const ov = await b.cosmeticOverride(7);
  const listsOff = new Set(ov?.lists ?? []);
  const selOff = new Set(ov?.selectors ?? []);
  return Object.entries(culprits).some(([list, sels]) => !listsOff.has(list) && sels.some((x) => !selOff.has(x)));
}

test('bisect: cosmetic keep lines turn style rules back into :style()', () => {
  assert.equal(cosmeticExceptionBody('.x'), '.x');
  assert.equal(cosmeticExceptionBody('.pub { min-height: 0 }'), '.pub:style(min-height: 0)');
  const lines = keepCosmeticLines([ASIDE, '.pub { min-height: 0 }', ASIDE], '20min.ch', '2026-10-27');
  assert.deepEqual(lines, ['! Bastion bisect 2026-10-27: 20min.ch', `20min.ch#@#${ASIDE}`, '20min.ch#@#.pub:style(min-height: 0)']);
});

test('Bisector cosmetic: lists, then selectors, find the aside two lists hide; keep adds #@# exceptions', async () => {
  const { fake, d, b } = await cleanBisect();
  assert.equal(await b.cosmeticOverride(7), null, 'nothing switched off before the phase starts');
  const reloads = fake.reloads.length;
  let v = bisectOf(await b.handle({ type: 'nerd:bisect', action: 'cosmetic', tabId: 7 }));
  assert.equal(v.kind, 'cosmetic');
  assert.equal(v.stage, 'lists');
  assert.equal(v.phase, 'testing');
  assert.deepEqual(v.allowed, COSMETIC.lists, 'first test: every list off');
  assert.deepEqual(await b.cosmeticOverride(7), { lists: COSMETIC.lists, selectors: [] });
  assert.equal(fake.reloads.length, reloads + 1);
  assert.deepEqual(fake.rules, [], 'no DNR rules in the cosmetic phase');
  // Starting again while testing keeps the phase.
  assert.equal(bisectOf(await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 })).kind, 'cosmetic');

  const culprits = { ublock: [ASIDE], 'regional-fr': [ASIDE] };
  let answers = 0;
  while (v.phase === 'testing') {
    v = bisectOf(await b.handle({ type: 'nerd:bisect', action: 'answer', tabId: 7, works: !(await brokenBy(b, culprits)) }));
    assert.ok(++answers < 20);
    if (v.phase === 'testing' && v.stage === 'selectors') assert.equal((await b.cosmeticOverride(7))?.lists.length, 0, 'selector stage: lists back on');
  }
  assert.equal(v.phase, 'found');
  assert.equal(v.stage, 'selectors');
  assert.deepEqual([...(v.lists ?? [])].sort(), ['regional-fr', 'ublock']);
  assert.deepEqual(v.selectors, [ASIDE]);
  assert.deepEqual(await b.cosmeticOverride(7), { lists: [], selectors: [ASIDE] }, 'the result stays applied, like a found host');
  // One reload per test; none when the result switches off what the last test did.
  const tested = fake.reloads.length;
  assert.ok(tested >= reloads + answers && tested <= reloads + 1 + answers, `${tested - reloads} reloads for ${answers} answers`);

  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'keep', tabId: 7 }), { bisect: null });
  assert.equal(d.added.length, 1);
  assert.match(d.added[0]![0]!, /^! Bastion bisect \d{4}-\d{2}-\d{2}: shop\.example$/);
  assert.deepEqual(d.added[0]!.slice(1), [`shop.example#@#${ASIDE}`]);
  assert.equal(await b.cosmeticOverride(7), null);
  assert.equal(fake.session.size, 0);
  assert.equal(fake.reloads.length, tested + 1, 'keep reloads back to normal protection');
});

test('Bisector cosmetic: still broken with every list off is clean; no selector found names the list', async () => {
  const { fake, b } = await cleanBisect();
  await b.handle({ type: 'nerd:bisect', action: 'cosmetic', tabId: 7 });
  const reloads = fake.reloads.length;
  const clean = bisectOf(await b.handle({ type: 'nerd:bisect', action: 'answer', tabId: 7, works: false }));
  assert.deepEqual({ kind: clean.kind, phase: clean.phase, allowed: clean.allowed }, { kind: 'cosmetic', phase: 'clean', allowed: [] });
  assert.equal(await b.cosmeticOverride(7), null);
  assert.equal(fake.reloads.length, reloads + 1, 'back to normal filtering');
  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'answer', tabId: 7, works: true }), { error: 'not testing' });
  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'keep', tabId: 7 }), { error: 'nothing found' });
  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'cosmetic', tabId: 7 }), { bisect: clean }, 'the phase runs once');
  // Dismissing does not reload again.
  assert.equal(bisectOf(await b.handle({ type: 'nerd:bisect', action: 'cancel', tabId: 7 })).phase, 'cancelled');
  assert.equal(fake.reloads.length, reloads + 1);

  // A generic filter of easylist: its host-specific selectors do not help.
  const second = await cleanBisect();
  let v = bisectOf(await second.b.handle({ type: 'nerd:bisect', action: 'cosmetic', tabId: 7 }));
  while (v.phase === 'testing') {
    const ov = await second.b.cosmeticOverride(7);
    v = bisectOf(await second.b.handle({ type: 'nerd:bisect', action: 'answer', tabId: 7, works: ov?.lists.includes('easylist') === true }));
  }
  assert.equal(v.phase, 'found');
  assert.deepEqual(v.lists, ['easylist']);
  assert.equal(v.selectors, undefined);
  assert.deepEqual(await second.b.cosmeticOverride(7), { lists: ['easylist'], selectors: [] });
  assert.deepEqual(await second.b.handle({ type: 'nerd:bisect', action: 'keep', tabId: 7 }), { error: 'nothing found' });
});

test('Bisector cosmetic: only after a clean network result; the custom filters are a candidate too', async () => {
  installChrome();
  const b = new Bisector(deps({ cosmeticCandidates: async () => structuredClone(COSMETIC) }));
  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'cosmetic', tabId: 7 }), { error: 'not clean' });
  await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 });
  assert.deepEqual(await b.handle({ type: 'nerd:bisect', action: 'cosmetic', tabId: 7 }), { error: 'not clean' });

  const { b: c } = await cleanBisect();
  let v = bisectOf(await c.handle({ type: 'nerd:bisect', action: 'cosmetic', tabId: 7 }));
  while (v.phase === 'testing') {
    const ov = await c.cosmeticOverride(7);
    v = bisectOf(await c.handle({ type: 'nerd:bisect', action: 'answer', tabId: 7, works: ov?.lists.includes('custom') === true }));
  }
  assert.deepEqual(v.lists, ['custom']);

  // Nothing to switch off: clean at once, without a reload.
  const { fake, b: e } = await cleanBisect({ cosmeticCandidates: async () => ({ lists: [], selectors: {} }) });
  const n = fake.reloads.length;
  assert.equal(bisectOf(await e.handle({ type: 'nerd:bisect', action: 'cosmetic', tabId: 7 })).phase, 'clean');
  assert.equal(fake.reloads.length, n);
});

test('Bisector cosmetic: cancel, navigation, restart, tab close and nerd mode off clean the override up', async () => {
  const { fake, b, d } = await cleanBisect();
  await b.handle({ type: 'nerd:bisect', action: 'cosmetic', tabId: 7 });
  let reloads = fake.reloads.length;
  assert.equal(bisectOf(await b.handle({ type: 'nerd:bisect', action: 'cancel', tabId: 7 })).phase, 'cancelled');
  assert.equal(await b.cosmeticOverride(7), null);
  assert.equal(fake.reloads.length, reloads + 1, 'cancel reloads to normal filtering');

  // Restart: the override comes back from storage.session.
  await b.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 });
  await b.handle({ type: 'nerd:bisect', action: 'cosmetic', tabId: 7 });
  const fresh = new Bisector(d);
  assert.deepEqual((await fresh.cosmeticOverride(7))?.lists, COSMETIC.lists);
  assert.equal(fresh.view(7)?.kind, 'cosmetic');

  // The test reload keeps it, another site ends it.
  fresh.onCommitted(7, 'https://www.shop.example/');
  assert.ok(await fresh.cosmeticOverride(7));
  fresh.onCommitted(7, 'https://elsewhere.example/');
  assert.deepEqual(await fresh.handle({ type: 'nerd:bisect', action: 'state', tabId: 7 }), { bisect: null });
  assert.equal(await fresh.cosmeticOverride(7), null);
  assert.equal(fake.session.size, 0);

  await fresh.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 });
  await fresh.handle({ type: 'nerd:bisect', action: 'cosmetic', tabId: 7 });
  fresh.onTabGone(7);
  await fresh.handle({ type: 'nerd:bisect', action: 'state', tabId: 7 });
  assert.equal(await fresh.cosmeticOverride(7), null);

  await fresh.handle({ type: 'nerd:bisect', action: 'start', tabId: 7 });
  await fresh.handle({ type: 'nerd:bisect', action: 'cosmetic', tabId: 7 });
  reloads = fake.reloads.length;
  await fresh.cancelAll();
  assert.equal(await fresh.cosmeticOverride(7), null);
  assert.equal(fake.reloads.length, reloads, 'nerd mode off does not reload');
  assert.equal(fake.session.size, 0);
});

test('Bisector cosmetic: the badge follows the cosmetic stage', async () => {
  const badges: [number, string | null][] = [];
  const { b } = await cleanBisect({ badge: (tabId, text) => badges.push([tabId, text]) });
  const v = bisectOf(await b.handle({ type: 'nerd:bisect', action: 'cosmetic', tabId: 7 }));
  assert.deepEqual(badges.at(-1), [7, `1/${v.maxSteps}`]);
  await b.handle({ type: 'nerd:bisect', action: 'answer', tabId: 7, works: false });
  assert.deepEqual(badges.at(-1), [7, null]);
});

test('cosmeticOverrideOf: what each stage switches off', () => {
  assert.equal(cosmeticOverrideOf(undefined), null);
  const lists = startBisect(['a', 'b']);
  assert.deepEqual(cosmeticOverrideOf({ stage: 'lists', lists }), { lists: ['a', 'b'], selectors: [] });
  let found = lists;
  while (found.result === 'testing') found = answerBisect(found, found.allowed.includes('a'));
  assert.deepEqual(found.culprits, ['a']);
  const selectors = startBisect(['.x']);
  assert.deepEqual(cosmeticOverrideOf({ stage: 'selectors', lists: found, selectors }), { lists: [], selectors: ['.x'] });
  assert.deepEqual(cosmeticOverrideOf({ stage: 'selectors', lists: found, selectors: answerBisect(selectors, false) }), { lists: ['a'], selectors: [] });
});
