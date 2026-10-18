// Tests for tools/scriptlets.ts: generated files are parsed and executed in a
// vm context that mimics a document_start frame, in the order the service
// worker registers them ([core, data files of the enabled lists, end]),
// checking hostname matching (parents, entities, regex hostnames,
// about:blank fallback), exceptions across lists (specific, broad, generic),
// ~host exclusions, trust, dedupe across lists, the merged data file, the
// trusted-click-element collapse (review PERF-4) and the ScriptletIndex.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import vm from 'node:vm';
import type { ScriptletFilter } from '../../src/compiler/types.ts';
import type { ScriptletIndex } from '../../src/shared/types.ts';
import { loadResources, specializeTemplate, escapeForJsString, type ResourceSet } from '../../tools/resources.ts';
import { emitScriptlets, regexPrefilter, type EmitScriptletsResult, type ScriptletListInput } from '../../tools/scriptlets.ts';
import { createLogger } from '../../tools/lib/util.ts';

const GLOBAL = '__bastionSlTestGlobal0001';

const sf = (name: string, args: string[], hosts: string[], extra: Partial<ScriptletFilter> = {}): ScriptletFilter => ({
  name,
  world: 'MAIN',
  args,
  hosts,
  excludedHosts: [],
  exception: false,
  raw: `${hosts.join(',')}##+js(${[name, ...args].join(', ')})`,
  ...extra,
});

let resources: ResourceSet;
let outDir: string;
let result: EmitScriptletsResult;

const LISTS: ScriptletListInput[] = [
  {
    listId: 'alpha',
    trusted: false,
    scriptlets: [
      sf('set-constant.js', ['bstA', 'true'], ['example.com']),
      sf('set-constant.js', ['bstB', 'true'], ['example.com', 'other.org'], { excludedHosts: ['skip.example.com'] }),
      sf('set-constant.js', ['bstC', 'true'], ['google.*']),
      sf('set-constant.js', ['bstD', 'true'], ['/^re\\d+\\.test$/']),
      sf('set-constant.js', ['bstE', 'true'], ['quiet.example.com', 'loud.example.com']),
      // Same (scriptlet, args) as in beta: one key id, runs once.
      sf('set-constant.js', ['bstS', 'true'], ['shared.net']),
      // ~host of this list only: beta still applies on sub.tag.net.
      sf('set-constant.js', ['bstX', 'true'], ['tag.net'], { excludedHosts: ['sub.tag.net'] }),
      sf('set-constant.js', ['bstG', 'true'], []),
      // Non-ASCII and "*/" in arguments survive the comment-encoded tables.
      sf('set-constant.js', ['bstU', 'Zustimmen ä */ end'], ['umlaut.ch']),
      // Untrusted list: trusted-* must be refused.
      sf('trusted-set-constant.js', ['bstT', '1'], ['example.com']),
      sf('no-such-scriptlet.js', [], ['example.com']),
    ],
  },
  {
    listId: 'beta',
    trusted: true,
    scriptlets: [
      // Exceptions: specific, broad, generic (apply while beta is enabled).
      sf('set-constant.js', ['bstE', 'true'], ['quiet.example.com'], { exception: true }),
      sf('', [], ['off.example.com'], { exception: true }),
      sf('set-constant.js', ['bstG', 'true'], [], { exception: true }),
      sf('trusted-set-constant.js', ['bstT', '1'], ['example.com']),
      sf('set-constant.js', ['bstI', 'true'], ['example.com'], { world: 'MAIN' }),
      sf('set-constant.js', ['bstS', 'true'], ['shared.net']),
      sf('set-constant.js', ['bstX', 'true'], ['sub.tag.net']),
      sf('remove-class.js', ['ad', 'div'], ['example.com'], { world: 'ISOLATED' }),
      // PERF-4: same selectors twice for x.com; only the longest delay stays there.
      sf('trusted-click-element.js', ['button.ok'], ['click.com']),
      sf('trusted-click-element.js', ['button.ok', '', '1500'], ['click.com', 'other-click.com']),
    ],
  },
];

before(async () => {
  resources = await loadResources(createLogger('test', true));
  outDir = await mkdtemp(join(tmpdir(), 'bastion-sl-'));
  result = await emitScriptlets({ outDir, resources, log: createLogger('test', true), globalName: GLOBAL, mergedLists: ['alpha', 'beta'], lists: LISTS });
});

test.after(async () => {
  if (outDir) await rm(outDir, { recursive: true, force: true });
});

/** The js array the service worker registers for `world` (registrations.ts scriptletScripts). */
function bundleFiles(index: ScriptletIndex, enabled: string[], world: 'MAIN' | 'ISOLATED' = 'MAIN', useMerged = false): string[] {
  const b = index.bundles!.find((x) => x.world === world)!;
  const merged = useMerged ? index.merged!.find((m) => m.world === world && m.lists.every((l) => enabled.includes(l))) : undefined;
  const data = index.registrations.filter((r) => r.world === world && enabled.includes(r.listId) && !merged?.lists.includes(r.listId)).map((r) => r.file);
  return [b.core, ...(merged ? [merged.file] : []), ...data, b.end];
}

interface Frame {
  g: Record<string, unknown>;
  /** Calls per scriptlet function name with their arguments. */
  calls: { fn: string; args: unknown[] }[];
}

/** Run files in a fresh context resembling a frame at document_start. */
async function runIn(
  files: string[],
  loc: { hostname: string; origin?: string; ancestorOrigins?: string[] },
  spy = false,
  globals: Record<string, unknown> = {},
): Promise<Frame> {
  const sandbox: Record<string, unknown> = { ...globals };
  const ctx = vm.createContext(sandbox);
  vm.runInContext('globalThis.self = globalThis; globalThis.window = globalThis;', ctx);
  sandbox.location = { hostname: loc.hostname, ancestorOrigins: loc.ancestorOrigins ?? [] };
  sandbox.origin = loc.origin ?? (loc.hostname ? `https://${loc.hostname}` : 'null');
  sandbox.document = { readyState: 'loading', addEventListener() {}, removeEventListener() {}, currentScript: null, querySelectorAll: () => [] };
  sandbox.EventTarget = class {
    addEventListener() {}
    removeEventListener() {}
  };
  sandbox.Request = class {
    clone() {
      return this;
    }
  };
  sandbox.XMLHttpRequest = class {};
  sandbox.MutationObserver = class {
    observe() {}
    disconnect() {}
  };
  sandbox.fetch = () => Promise.reject(new Error('no network'));
  sandbox.console = { log() {}, info() {}, warn() {}, error() {} };
  const calls: Frame['calls'] = [];
  for (const [i, f] of files.entries()) {
    if (spy && i === files.length - 1) {
      // Wrap every function before the runner calls it.
      const B = (sandbox as Record<string, { F: ((...a: unknown[]) => unknown)[] }>)[GLOBAL];
      B.F = B.F.map((fn) => (...args: unknown[]) => {
        calls.push({ fn: fn.name, args });
        return fn(...args);
      });
    }
    const code = await readFile(join(outDir, ...f.split('/')), 'utf8');
    vm.runInContext(code, ctx, { filename: f });
  }
  return { g: sandbox, calls };
}

const ALL = ['alpha', 'beta'];

test('files parse, carry a licence header and are ASCII-only', async () => {
  assert.ok(result.files.length >= 6);
  for (const f of result.files) {
    const code = await readFile(join(outDir, ...f.path.split('/')), 'utf8');
    assert.doesNotThrow(() => new vm.Script(code), f.path);
    assert.match(code, /^\/\*! Bastion Shield scriptlet/);
    assert.ok(!/[^\x00-\x7f]/.test(code), `${f.path} is ASCII-only`);
    if (f.kind === 'core') assert.match(code, /GPL-3\.0-or-later/);
  }
});

test('index: one data file per (list, world), one bundle per world, merged data', () => {
  const ids = result.index.registrations.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, 'unique ids');
  for (const r of result.index.registrations) {
    assert.match(r.id, /^sl-[a-z0-9-]+-(main|isolated)$/);
    assert.equal(r.file, `scriptlets/${r.listId}-${r.world.toLowerCase()}.js`);
    assert.deepEqual(r.matches, ['<all_urls>']);
  }
  assert.deepEqual(ids, ['sl-alpha-main', 'sl-beta-isolated', 'sl-beta-main']);
  assert.deepEqual(
    result.index.bundles!.map((b) => [b.world, b.core, b.end]),
    [
      ['MAIN', 'scriptlets/scriptlet-core-main.js', 'scriptlets/scriptlet-end-main.js'],
      ['ISOLATED', 'scriptlets/scriptlet-core-isolated.js', 'scriptlets/scriptlet-end-isolated.js'],
    ],
  );
  // Only MAIN has data from both lists.
  assert.deepEqual(result.index.merged, [{ world: 'MAIN', lists: ['alpha', 'beta'], file: 'scriptlets/scriptlet-merged-main.js' }]);
});

for (const merged of [false, true]) {
  const label = merged ? ' (merged data)' : '';
  const files = (host: string, enabled = ALL, world: 'MAIN' | 'ISOLATED' = 'MAIN') => bundleFiles(result.index, enabled, world, merged);

  test(`applies on the hostname and its subdomains${label}`, async () => {
    const { g } = await runIn(files('www.example.com'), { hostname: 'www.example.com' });
    assert.equal(g.bstA, true);
    assert.equal(g.bstB, true);
    assert.equal(g.bstI, true);
    assert.equal(g.bstC, undefined);
    const o = await runIn(files('other.org'), { hostname: 'other.org' });
    assert.equal(o.g.bstB, true);
    assert.equal(o.g.bstA, undefined);
  });

  test(`does nothing on unrelated hosts and removes the hand-over global${label}`, async () => {
    const { g } = await runIn(files('unrelated.net'), { hostname: 'unrelated.net' });
    for (const k of ['bstA', 'bstB', 'bstC', 'bstD', 'bstE', 'bstI', 'bstT', 'bstS', 'bstX']) assert.equal(g[k], undefined, k);
    assert.equal(Object.prototype.hasOwnProperty.call(g, GLOBAL), false, 'global deleted before page scripts run');
  });

  test(`~host exclusion applies to its own list only${label}`, async () => {
    const { g } = await runIn(files('skip.example.com'), { hostname: 'skip.example.com' });
    assert.equal(g.bstA, true);
    assert.equal(g.bstB, undefined);
    const t = await runIn(files('sub.tag.net'), { hostname: 'sub.tag.net' });
    assert.equal(t.g.bstX, true, "beta's sub.tag.net filter is not cancelled by alpha's ~sub.tag.net");
    const t2 = await runIn(files('www.tag.net'), { hostname: 'www.tag.net' });
    assert.equal(t2.g.bstX, true);
  });

  test(`exceptions of an enabled list apply to every list${label}`, async () => {
    const q = await runIn(files('quiet.example.com'), { hostname: 'quiet.example.com' });
    assert.equal(q.g.bstE, undefined, 'specific exception from list beta');
    assert.equal(q.g.bstA, true);
    const l = await runIn(files('loud.example.com'), { hostname: 'loud.example.com' });
    assert.equal(l.g.bstE, true);
    const off = await runIn(files('off.example.com'), { hostname: 'off.example.com' });
    for (const k of ['bstA', 'bstB', 'bstI', 'bstT', 'bstG']) assert.equal(off.g[k], undefined, `broad exception cancels ${k}`);
    const gen = await runIn(files('unrelated.net'), { hostname: 'unrelated.net' });
    assert.equal(gen.g.bstG, undefined, 'generic #@#+js(set, bstG, true) from beta');
  });

  test(`entity and regex hostnames${label}`, async () => {
    const g = await runIn(files('www.google.co.uk'), { hostname: 'www.google.co.uk' });
    assert.equal(g.g.bstC, true);
    const r = await runIn(files('re42.test'), { hostname: 're42.test' });
    assert.equal(r.g.bstD, true);
    const n = await runIn(files('re42x.test'), { hostname: 're42x.test' });
    assert.equal(n.g.bstD, undefined);
  });

  test(`about:blank frames fall back to the inherited origin / ancestorOrigins${label}`, async () => {
    const inherited = await runIn(files('example.com'), { hostname: '', origin: 'https://example.com' });
    assert.equal(inherited.g.bstA, true);
    const ancestors = await runIn(files('example.com'), { hostname: '', origin: 'null', ancestorOrigins: ['https://www.example.com'] });
    assert.equal(ancestors.g.bstA, true);
  });

  test(`the same (scriptlet, args) from two lists runs once${label}`, async () => {
    const { g, calls } = await runIn(files('shared.net'), { hostname: 'shared.net' }, true);
    assert.equal(g.bstS, true);
    assert.equal(calls.filter((c) => c.args[0] === 'bstS').length, 1);
  });

  test(`arguments with non-ASCII text and "*/" round-trip${label}`, async () => {
    const { calls } = await runIn(files('umlaut.ch'), { hostname: 'umlaut.ch' }, true);
    const c = calls.find((x) => x.args[0] === 'bstU');
    assert.deepEqual(c?.args, ['bstU', 'Zustimmen ä */ end']);
  });
}

test('regex hostnames: literal prefilter, conservative, no regex compiled on unrelated frames', async () => {
  assert.deepEqual(regexPrefilter('^re\\d+\\.test$'), ['.test']);
  assert.deepEqual(regexPrefilter('^https?:\\/\\/[a-z]{8,15}\\.(com|xyz)\\/$'), ['http', '://', ['com', 'xyz']]);
  assert.deepEqual(regexPrefilter('^file-[a-z0-9]+(-[a-z0-9]+)*-(moon|embed)\\.com$'), ['file-', ['moon', 'embed'], '.com']);
  assert.deepEqual(regexPrefilter('^moon(?:-[a-z0-9]+)?-embed\\.com$'), ['moon', '-embed.com']);
  assert.deepEqual(regexPrefilter('abcd{0,2}efg'), ['abc', 'efg']);
  for (const x of ['abc|def', 'x(?=abc)yz', 'a\\x41bcd', 'ab)c', '[abc', '(abc', 'ab{c', 'ab\\1cd']) assert.equal(regexPrefilter(x), null, x);
  // Every hostname a regex matches passes its prefilter.
  const cases: [string, string[]][] = [
    ['(\\d{0,1})?tamilprint(\\d{1,2})?\\.[a-z]{3,7}', ['tamilprint.com', '1tamilprint22.cool', 'www.tamilprint9.xyz']],
    ['^[0-9a-z]{5,8}\\.(art|cfd|fun|icu|info|live|pro|sbs|world)$', ['abcde.art', 'a1b2c3d4.world']],
    ['^filemoon-[a-z0-9]+(?:-[a-z0-9]+)*\\.(?:com|xyz)$', ['filemoon-a.com', 'filemoon-a-b-c.xyz']],
    ['^fle-[a-z0-9]+(-[a-z0-9]+)*-moo\\.com$', ['fle-x-moo.com', 'fle-x-y-moo.com']],
    ['^ab+c(de|fg)?h{2,}[0-9]$', ['abch' + 'h1', 'abbbcdehhh2']],
  ];
  for (const [src, hosts] of cases) {
    const pf = regexPrefilter(src);
    for (const h of hosts) {
      assert.ok(new RegExp(src).test(h), `${src} matches ${h}`);
      assert.ok(pf === null || pf.every((x) => (typeof x === 'string' ? h.includes(x) : x.some((y) => h.includes(y)))), `${src}: prefilter keeps ${h}`);
    }
  }
  let compiled = 0;
  const Counting = class extends RegExp {
    constructor(p: string, f?: string) {
      super(p, f);
      compiled++;
    }
  };
  const files = bundleFiles(result.index, ALL);
  const n = await runIn(files, { hostname: 'unrelated.net' }, false, { RegExp: Counting });
  assert.equal(n.g.bstD, undefined);
  assert.equal(compiled, 0, 'no hostname regex compiled where its literals are absent');
  const r = await runIn(files, { hostname: 're7.test' }, false, { RegExp: Counting });
  assert.equal(r.g.bstD, true);
  assert.ok(compiled >= 1);
});

test('exceptions of a disabled list do not apply', async () => {
  const q = await runIn(bundleFiles(result.index, ['alpha']), { hostname: 'quiet.example.com' });
  assert.equal(q.g.bstE, true);
  const off = await runIn(bundleFiles(result.index, ['alpha']), { hostname: 'off.example.com' });
  assert.equal(off.g.bstA, true);
  const gen = await runIn(bundleFiles(result.index, ['alpha']), { hostname: 'unrelated.net' });
  assert.equal(gen.g.bstG, true, 'generic scriptlet runs everywhere');
  const t = await runIn(bundleFiles(result.index, ['alpha']), { hostname: 'sub.tag.net' });
  assert.equal(t.g.bstX, undefined, "alpha's own ~sub.tag.net");
});

test('trust: trusted-* only from trusted lists; unknown names rejected', async () => {
  assert.equal(result.perList.alpha.rejected['requires trust (list is not trusted)'], 1);
  assert.equal(result.perList.alpha.rejected['unknown scriptlet no-such-scriptlet.js'], 1);
  const { g } = await runIn(bundleFiles(result.index, ALL), { hostname: 'example.com' });
  assert.equal(g.bstT, 1, 'trusted-set-constant from the trusted list ran');
});

test('ISOLATED world bundle', async () => {
  const files = bundleFiles(result.index, ALL, 'ISOLATED');
  assert.deepEqual(files, ['scriptlets/scriptlet-core-isolated.js', 'scriptlets/beta-isolated.js', 'scriptlets/scriptlet-end-isolated.js']);
  const { calls } = await runIn(files, { hostname: 'www.example.com' }, true);
  assert.deepEqual(calls.map((c) => [c.fn, c.args]), [['removeClass', ['ad', 'div']]]);
});

test('PERF-4: duplicate trusted-click-element selectors keep the longest delay per host', async () => {
  assert.equal(result.perList.beta.collapsedClicks, 1);
  const files = bundleFiles(result.index, ALL, 'ISOLATED');
  const a = await runIn(files, { hostname: 'click.com' }, true);
  assert.deepEqual(a.calls.map((c) => c.args), [['button.ok', '', '1500']]);
  const b = await runIn(files, { hostname: 'other-click.com' }, true);
  assert.deepEqual(b.calls.map((c) => c.args), [['button.ok', '', '1500']]);
});

test('Brave templates are specialized with escaped arguments', () => {
  const code = "function x() { const a = '{{1}}'; const b = \"{{2}}\"; const c = `{{3}}`; return [a, b, c, '{{4}}']; }";
  const out = specializeTemplate(code, ["it's", 'say "hi"\\n', '${evil}`']);
  assert.doesNotThrow(() => new vm.Script(out));
  const ctx = vm.createContext({});
  vm.runInContext(`${out}\nglobalThis.r = x();`, ctx);
  assert.deepEqual([...(ctx as { r: string[] }).r], ["it's", 'say "hi"\\n', '${evil}`', '']);
  assert.equal(escapeForJsString('</script>'), '<\\/script>');
});

test('resource maps: names, aliases and .js-less keys', () => {
  assert.equal(resources.scriptletMap.get('set')?.name, 'set-constant.js');
  assert.equal(resources.scriptletMap.get('set.js')?.name, 'set-constant.js');
  assert.equal(resources.scriptletMap.get('set-constant')?.name, 'set-constant.js');
  assert.equal(resources.scriptletMap.get('remove-class')?.world, 'ISOLATED');
  assert.equal(resources.scriptletMap.get('trusted-set-constant')?.requiresTrust, true);
  assert.equal(resources.scriptletMap.get('brave-fix')?.name, 'brave-fix.js');
  assert.equal(resources.redirectMap.get('noopjs')?.path, '/war/noop.js');
  assert.equal(resources.redirectMap.get('abp-resource:blank-js')?.path, '/war/noop.js');
  assert.equal(resources.redirectMap.get('google-ima-dai.js')?.requiresTrust, true);
  assert.equal(resources.redirectMap.has('click2load.html'), false);
  assert.ok(resources.skipped.some((s) => s.name === 'de-amp.js'));
});

test('the hand-over global is random per build unless given', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bastion-slg-'));
  try {
    const lists = [{ listId: 'alpha', trusted: false, scriptlets: [sf('set-constant.js', ['bstM', 'true'], ['example.com'])] }];
    const a = await emitScriptlets({ outDir: join(dir, 'a'), resources, log: createLogger('test', true), lists });
    const b = await emitScriptlets({ outDir: join(dir, 'b'), resources, log: createLogger('test', true), lists });
    assert.notEqual(a.globalName, b.globalName);
    assert.match(a.globalName, /^__bastionSl[0-9a-f]{24}$/);
    await assert.rejects(emitScriptlets({ outDir: join(dir, 'c'), resources, log: createLogger('test', true), lists, globalName: 'x' }));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('release minification keeps files valid and behaviour identical', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bastion-slmin-'));
  try {
    const lists = [{ listId: 'alpha', trusted: false, scriptlets: [sf('set-constant.js', ['bstM', 'true'], ['example.com']), sf('set-constant.js', ['bstN', 'true'], ['google.*'])] }];
    const min = await emitScriptlets({ outDir: dir, resources, minify: true, log: createLogger('test', true), lists, globalName: GLOBAL });
    const plain = await emitScriptlets({ outDir: join(dir, 'plain'), resources, log: createLogger('test', true), lists, globalName: GLOBAL });
    const core = (r: EmitScriptletsResult) => r.files.filter((f) => f.kind === 'core').reduce((a, f) => a + f.bytes, 0);
    assert.ok(core(min) < core(plain) * 0.8, 'minified core is smaller');
    for (const [host, prop] of [['www.example.com', 'bstM'], ['www.google.de', 'bstN']] as const) {
      const ctx = vm.createContext({});
      vm.runInContext('globalThis.self = globalThis; globalThis.window = globalThis;', ctx);
      Object.assign(ctx, {
        location: { hostname: host, ancestorOrigins: [] },
        origin: `https://${host}`,
        document: { readyState: 'loading', addEventListener() {}, removeEventListener() {} },
        EventTarget: class { addEventListener() {} removeEventListener() {} },
        Request: class { clone() { return this; } },
        XMLHttpRequest: class {},
        console: { log() {} },
      });
      for (const f of bundleFiles(min.index, ['alpha'])) {
        const code = await readFile(join(dir, ...f.split('/')), 'utf8');
        if (f.includes('scriptlet-core')) assert.match(code, /^\/\*! Bastion Shield scriptlets/, 'licence header survives minification');
        vm.runInContext(code, ctx);
      }
      assert.equal((ctx as Record<string, unknown>)[prop], true, `${prop} on ${host}`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
