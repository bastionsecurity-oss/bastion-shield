// Tests for per-source trust in tools/fetch-lists.ts (review ENT-3): upstream
// `!#trusted` directives are removed from every source, an untrusted source of
// a trusted list is wrapped in `!#trusted off/on <secret>`, and the compiler
// honours only markers with the build's secret.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CompileOptions } from '../../src/compiler/types.ts';
import type { Catalog } from '../../src/shared/types.ts';
import { compileList } from '../../src/compiler/index.ts';
import { fetchLists, stripTrustDirectives, wrapUntrusted } from '../../tools/fetch-lists.ts';
import { createLogger } from '../../tools/lib/util.ts';

type Src = { url?: string; path?: string; format?: 'abp' | 'hosts'; trusted?: boolean };

const files: Record<string, string> = {
  '/fanboy.txt': [
    '! Title: Fanboy test',
    '!#trusted on',
    '||fanboy-redirect.example^$script,redirect=trusted-stub.js',
    'fanboy.example##+js(trusted-set-cookie, a, b)',
    '!#include fanboy-sub.txt',
    '!#if env_never',
    '||open-if.example^',
    '',
  ].join('\n'),
  '/fanboy-sub.txt': ['!#trusted on SOMEGUESS', '||sub-redirect.example^$script,redirect=trusted-stub.js', ''].join('\n'),
  '/uassets.txt': ['||uassets-redirect.example^$script,redirect=trusted-stub.js', 'uassets.example##+js(trusted-set-cookie, a, b)', ''].join('\n'),
};

let server: Server;
let base = '';
let cacheDir = '';

before(async () => {
  cacheDir = await mkdtemp(join(tmpdir(), 'bastion-trust-'));
  server = createServer((req, res) => {
    const body = files[(req.url ?? '/').split('?')[0]];
    if (body === undefined) res.writeHead(404).end('not found');
    else res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' }).end(body);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const a = server.address();
  if (a && typeof a === 'object') base = `http://127.0.0.1:${a.port}`;
});

after(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  await rm(cacheDir, { recursive: true, force: true });
});

function list(id: string, trusted: boolean, sources: Src[]) {
  return {
    id,
    name: { en: id, de: id },
    description: { en: id, de: id },
    category: 'annoyances',
    default: true,
    firstPartyProtected: false,
    trusted,
    strictBlock: false,
    sources,
    homepage: 'https://example.invalid',
    license: 'test',
    attribution: 'test',
  };
}

const SECRET = 'test-secret-0123456789abcdef';

test('stripTrustDirectives turns every directive into a comment, keeping line count', () => {
  const t = 'a\n!#trusted on\n  !#trusted off x\nb\n';
  const out = stripTrustDirectives(t);
  assert.equal(out.split('\n').length, t.split('\n').length);
  assert.ok(!/^\s*!#trusted/m.test(out));
  assert.equal(wrapUntrusted('x\n\n', SECRET), `!#trusted off ${SECRET}\nx\n!#trusted on ${SECRET}`);
});

test('untrusted source of a trusted list is wrapped; upstream directives removed everywhere', async () => {
  const catalog = {
    version: 1,
    lists: [
      list('cookies', true, [{ url: `${base}/fanboy.txt`, trusted: false }, { url: `${base}/uassets.txt` }]),
      list('plain', false, [{ url: `${base}/fanboy.txt`, trusted: false }]),
    ],
  };
  const r = await fetchLists({ catalog: catalog as unknown as Catalog, cacheDir, writeLock: false, log: createLogger('t', true), trustSecret: SECRET });
  assert.equal(r.trustSecret, SECRET);
  const cookies = r.lists.find((l) => l.listId === 'cookies')!;
  const [fan, ua] = cookies.parts;
  assert.equal(fan.trustedOff, true);
  assert.ok(fan.text.startsWith(`!#trusted off ${SECRET}\n`));
  assert.ok(fan.text.endsWith(`\n!#trusted on ${SECRET}`));
  // Exactly our two markers survive; the upstream ones (incl. the included file's) are gone.
  assert.equal((fan.text.match(/^!#trusted/gm) ?? []).length, 2);
  assert.ok(fan.text.includes('||sub-redirect.example^'), 'include expanded inside the markers');
  // The open !#if is closed before the closing marker.
  assert.ok(fan.text.indexOf('!#endif') < fan.text.lastIndexOf('!#trusted on'));
  assert.ok(!ua.trustedOff && !ua.text.includes('!#trusted'));
  // An untrusted list needs no markers.
  const plain = r.lists.find((l) => l.listId === 'plain')!;
  assert.ok(!plain.text.includes(`!#trusted off`));

  // Compile: only the uAssets part keeps trusted filters.
  const redirectResources = new Map([['trusted-stub.js', { path: '/war/trusted-stub.js', requiresTrust: true }]]);
  const scriptlets = new Map([['trusted-set-cookie.js', { name: 'trusted-set-cookie.js', world: 'MAIN', requiresTrust: true }], ['trusted-set-cookie', { name: 'trusted-set-cookie.js', world: 'MAIN', requiresTrust: true }]]);
  const opts = { listId: 'cookies', trusted: true, firstPartyProtected: false, strictBlock: false, redirectResources, scriptlets } as unknown as CompileOptions;
  const withSecret = compileList(cookies.text, { ...opts, trustSecret: SECRET });
  const redirectHosts = (c: { rules: { rule: { action: { type: string }; condition: { urlFilter?: string; requestDomains?: string[] } } }[] }) =>
    c.rules.filter((x) => x.rule.action.type === 'redirect').map((x) => x.rule.condition.urlFilter ?? (x.rule.condition.requestDomains ?? []).join(','));
  const hosts = redirectHosts(withSecret).join(' ');
  assert.ok(hosts.includes('uassets-redirect.example'), `trusted part keeps its redirect: ${hosts}`);
  assert.ok(!hosts.includes('fanboy-redirect.example'), 'untrusted part loses trusted redirects');
  assert.ok(!hosts.includes('sub-redirect.example'), 'included file of the untrusted part loses trusted redirects');
  const sl = withSecret.scriptlets.map((s: { hosts: string[] }) => s.hosts.join(',')).join(' ');
  assert.ok(sl.includes('uassets.example') && !sl.includes('fanboy.example'), `scriptlets: ${sl}`);

  // A wrong secret never raises trust; markers with another secret are ignored.
  const forged = compileList(cookies.text.replaceAll(SECRET, 'other-secret-0123456789'), { ...opts, trusted: false, trustSecret: SECRET });
  assert.equal(redirectHosts(forged).length, 0, 'untrusted list stays untrusted');
});
