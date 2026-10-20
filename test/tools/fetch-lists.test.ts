// Tests for tools/fetch-lists.ts against a local HTTP server: include
// expansion rules (same origin, same directory, depth, conditional blocks),
// HTML refusal, retries, ETag revalidation, offline mode and lock entries.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Catalog, CatalogList } from '../../src/shared/types.ts';
import { fetchLists, parseListHeaders, resolveInclude, type LockFile } from '../../tools/fetch-lists.ts';
import { createLogger } from '../../tools/lib/util.ts';

const files: Record<string, { body: string; type?: string }> = {
  '/a/list.txt': {
    body: [
      '! Title: Test',
      '! Version: 202610181200',
      '! Last modified: Sun, 18 Oct 2026 10:00:00 +0000',
      '||a.com^',
      '!#include sub.txt',
      '!#if env_mobile',
      '!#include missing.txt',
      '!#endif',
      '!#include ../escape.txt',
      '!#include https://other.example/x.txt',
      '!#include sub.txt',
      '',
    ].join('\r\n'),
  },
  '/a/sub.txt': { body: '||b.com^\n!#include d1.txt\n' },
  '/a/d1.txt': { body: '||d1.com^\n!#include d2.txt\n' },
  '/a/d2.txt': { body: '||d2.com^\n!#include d3.txt\n' },
  '/a/d3.txt': { body: '||d3.com^\n!#include d4.txt\n' },
  '/a/d4.txt': { body: '||d4.com^\n' },
  '/html.txt': { body: '<!DOCTYPE html><html><body>Captive portal</body></html>', type: 'text/html' },
  '/hosts.txt': { body: '# hosts\n0.0.0.0 ads.example\n127.0.0.1 t.example # c\n' },
  '/flaky.txt': { body: '||flaky.com^\n' },
};

let server: Server;
let base = '';
let cacheDir = '';
const hits = { notModified: 0, flaky: 0 };

before(async () => {
  cacheDir = await mkdtemp(join(tmpdir(), 'bastion-fetch-'));
  server = createServer((req, res) => {
    const path = (req.url ?? '/').split('?')[0];
    if (path === '/flaky.txt' && hits.flaky++ === 0) {
      res.writeHead(503).end('busy');
      return;
    }
    const f = files[path];
    if (!f) {
      res.writeHead(404).end('not found');
      return;
    }
    const etag = `"${Buffer.from(f.body).length}-${path.length}"`;
    if (req.headers['if-none-match'] === etag) {
      hits.notModified++;
      res.writeHead(304).end();
      return;
    }
    res.writeHead(200, { 'content-type': f.type ?? 'text/plain; charset=utf-8', etag }).end(f.body);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const addr = server.address();
  if (addr && typeof addr === 'object') base = `http://127.0.0.1:${addr.port}`;
});

after(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  await rm(cacheDir, { recursive: true, force: true });
});

function list(id: string, sources: CatalogList['sources']): CatalogList {
  return {
    id,
    name: { en: id, de: id },
    description: { en: id, de: id },
    category: 'ads',
    default: true,
    firstPartyProtected: true,
    trusted: false,
    strictBlock: false,
    sources,
    homepage: 'https://example.invalid',
    license: 'test',
    attribution: 'test',
  };
}

const quiet = () => createLogger('test', true);

test('resolveInclude: same origin, same directory or below', () => {
  assert.deepEqual(resolveInclude('sub.txt', 'https://x.example/f/list.txt'), { url: 'https://x.example/f/sub.txt' });
  assert.deepEqual(resolveInclude('deeper/s.txt', 'https://x.example/f/list.txt'), { url: 'https://x.example/f/deeper/s.txt' });
  assert.ok('error' in resolveInclude('../s.txt', 'https://x.example/f/list.txt'));
  assert.ok('error' in resolveInclude('https://evil.example/s.txt', 'https://x.example/f/list.txt'));
  assert.ok('error' in resolveInclude('/other/s.txt', 'https://x.example/f/list.txt'));
  assert.ok('error' in resolveInclude('//evil.example/s.txt', 'https://x.example/f/list.txt'));
});

test('parseListHeaders', () => {
  assert.deepEqual(parseListHeaders('! Version: 1\n! Last modified: x y\n'), { version: '1', lastModified: 'x y' });
  assert.deepEqual(parseListHeaders('# last updated:   Fri, 16 Oct 2026\n'), { version: undefined, lastModified: 'Fri, 16 Oct 2026' });
  assert.deepEqual(parseListHeaders('! Updated: 2026-10-18T00:10:10Z\n'), { version: undefined, lastModified: '2026-10-18T00:10:10Z' });
});

test('fetch, expand includes, write lock; then revalidate with ETag; then offline', async () => {
  const lockFile = join(cacheDir, 'lock.json');
  const catalog: Catalog = {
    version: 1,
    lists: [list('one', [{ url: `${base}/a/list.txt` }]), list('pgl', [{ url: `${base}/hosts.txt`, format: 'hosts' }]), list('flaky', [{ url: `${base}/flaky.txt` }])],
  };
  const r1 = await fetchLists({ catalog, cacheDir, lockFile, log: quiet() });
  const one = r1.lists.find((l) => l.listId === 'one')!;
  assert.equal(one.format, 'abp');
  const t = one.text;
  assert.ok(t.startsWith(`! --- source: ${base}/a/list.txt\n`));
  assert.ok(!t.includes('\r'), 'CRLF normalized');
  // sub.txt, d1.txt and d2.txt are include levels 1-3; d3.txt would be level 4.
  for (const h of ['a.com', 'b.com', 'd1.com', 'd2.com']) assert.ok(t.includes(`||${h}^`), h);
  assert.ok(!t.includes('||d3.com^'), 'include depth is capped at 3');
  assert.match(t, /include skipped \(path traversal/);
  assert.match(t, /include skipped \(cross-origin/);
  assert.match(t, /include failed: .*missing\.txt/, 'conditional include may fail');
  assert.match(t, /include already inlined/);
  // Order: included content replaces the directive in place.
  assert.ok(t.indexOf('||a.com^') < t.indexOf('||b.com^'));

  const pgl = r1.lists.find((l) => l.listId === 'pgl')!;
  assert.equal(pgl.format, 'hosts');
  assert.equal(pgl.text, `# --- source: ${base}/hosts.txt\n${files['/hosts.txt'].body}`, 'hosts text kept as-is');
  assert.ok(r1.lists.find((l) => l.listId === 'flaky')!.text.includes('||flaky.com^'), 'retried after 503');

  const lock = JSON.parse(await readFile(lockFile, 'utf8')) as LockFile;
  const top = lock.sources.find((s) => s.url === `${base}/a/list.txt`)!;
  assert.equal(top.version, '202610181200');
  assert.equal(top.lastModified, 'Sun, 18 Oct 2026 10:00:00 +0000');
  assert.match(top.sha256, /^[0-9a-f]{64}$/);
  assert.equal(top.bytes, Buffer.byteLength(files['/a/list.txt'].body));
  const sub = lock.sources.find((s) => s.url === `${base}/a/sub.txt`)!;
  assert.equal(sub.includedFrom, `${base}/a/list.txt`);

  const before304 = hits.notModified;
  const r2 = await fetchLists({ catalog, cacheDir, lockFile, log: quiet() });
  assert.ok(hits.notModified - before304 >= 6, 'conditional requests answered with 304');
  assert.equal(r2.lists[0].text, r1.lists[0].text);
  assert.equal(r2.lock.sources[0].fetchedAt, r1.lock.sources[0].fetchedAt, 'fetchedAt stable on 304');

  const r3 = await fetchLists({ catalog, cacheDir, lockFile, offline: true, log: quiet() });
  assert.equal(r3.lists[0].text, r1.lists[0].text);
});

test('HTML responses are refused', async () => {
  const catalog: Catalog = { version: 1, lists: [list('html', [{ url: `${base}/html.txt` }])] };
  await assert.rejects(fetchLists({ catalog, cacheDir, writeLock: false, log: quiet() }), /refusing HTML/);
});

test('offline mode fails clearly when the cache is missing', async () => {
  const catalog: Catalog = { version: 1, lists: [list('nope', [{ url: `${base}/never-fetched.txt` }])] };
  await assert.rejects(fetchLists({ catalog, cacheDir, writeLock: false, offline: true, log: quiet() }), /--offline: no cached copy/);
});

test('404 at top level fails without retrying forever', async () => {
  const catalog: Catalog = { version: 1, lists: [list('gone', [{ url: `${base}/gone.txt` }])] };
  await assert.rejects(fetchLists({ catalog, cacheDir, writeLock: false, log: quiet() }), /HTTP 404/);
});
