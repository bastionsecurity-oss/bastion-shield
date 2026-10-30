// Tests for tools/lib/http-get.ts: redirects, compressed bodies, size cap,
// truncated responses and timeouts, plus the server pattern that crashes
// Node 24's fetch (nodejs/undici#5360: body paused under backpressure when
// the server sends FIN), which must resolve here.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { createServer as createNetServer, type Server as NetServer } from 'node:net';
import { gzipSync } from 'node:zlib';
import { HttpBodyTooLargeError, httpGet } from '../../tools/lib/http-get.ts';

let server: Server;
let base = '';
let raw: NetServer;
let rawBase = '';
/** What the raw socket server sends for the next request. */
let rawReply: (sock: import('node:net').Socket) => void = () => {};

before(async () => {
  server = createServer((req, res) => {
    const path = (req.url ?? '/').split('?')[0];
    if (path === '/redirect') return void res.writeHead(302, { location: '/plain' }).end();
    if (path === '/loop') return void res.writeHead(301, { location: '/loop' }).end();
    if (path === '/plain') return void res.writeHead(200, { 'content-type': 'text/plain', etag: '"e1"' }).end('||a.com^\n');
    if (path === '/gzip') return void res.writeHead(200, { 'content-encoding': 'gzip' }).end(gzipSync('||gz.com^\n'));
    if (path === '/big') return void res.writeHead(200).end(Buffer.alloc(4096, 0x61));
    if (path === '/bomb') return void res.writeHead(200, { 'content-encoding': 'gzip' }).end(gzipSync(Buffer.alloc(1024 * 1024, 0x61)));
    if (path === '/304') return void res.writeHead(304).end();
    if (path === '/hang') return; // never answers
    res.writeHead(404).end('not found');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const a = server.address();
  if (a && typeof a === 'object') base = `http://127.0.0.1:${a.port}`;

  raw = createNetServer((sock) => sock.once('data', () => rawReply(sock)));
  await new Promise<void>((r) => raw.listen(0, '127.0.0.1', r));
  const b = raw.address();
  if (b && typeof b === 'object') rawBase = `http://127.0.0.1:${b.port}`;
});

after(async () => {
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
  await new Promise<void>((r) => raw.close(() => r()));
});

const opts = { timeoutMs: 5000, maxBytes: 64 * 1024 };

test('plain 200 with headers', async () => {
  const r = await httpGet(`${base}/plain`, opts);
  assert.equal(r.status, 200);
  assert.equal(r.body.toString(), '||a.com^\n');
  assert.equal(r.headers.etag, '"e1"');
});

test('follows redirects and reports the final URL', async () => {
  const r = await httpGet(`${base}/redirect`, opts);
  assert.equal(r.status, 200);
  assert.equal(r.url, `${base}/plain`);
  assert.equal(r.body.toString(), '||a.com^\n');
});

test('redirect loops end with an error', async () => {
  await assert.rejects(httpGet(`${base}/loop`, { ...opts, maxRedirects: 3 }), /too many redirects/);
});

test('gzip bodies are decoded', async () => {
  const r = await httpGet(`${base}/gzip`, opts);
  assert.equal(r.body.toString(), '||gz.com^\n');
});

test('304 and 404 resolve with their status and an empty body', async () => {
  assert.equal((await httpGet(`${base}/304`, opts)).status, 304);
  const nf = await httpGet(`${base}/missing`, opts);
  assert.equal(nf.status, 404);
  assert.equal(nf.body.length, 0);
});

test('bodies over maxBytes are refused, compressed or not', async () => {
  await assert.rejects(httpGet(`${base}/big`, { ...opts, maxBytes: 1024 }), HttpBodyTooLargeError);
  await assert.rejects(httpGet(`${base}/bomb`, opts), HttpBodyTooLargeError);
});

test('timeouts reject instead of hanging', async () => {
  await assert.rejects(httpGet(`${base}/hang`, { ...opts, timeoutMs: 300 }), /timed out/);
});

test('server FIN while the body is unread (undici#5360 pattern) resolves', async () => {
  // 64 KiB is undici's body highWaterMark: the smallest body that pauses its
  // parser in one socket read. Block the event loop meanwhile, as hashing
  // and include expansion of other lists do during a build.
  const body = Buffer.alloc(256 * 1024, 0x61);
  rawReply = (sock) => {
    sock.write(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`);
    sock.write(body);
    sock.end();
  };
  const p = httpGet(`${rawBase}/`, { ...opts, maxBytes: 1024 * 1024 });
  const t = Date.now();
  while (Date.now() - t < 200) {
    /* busy */
  }
  const r = await p;
  assert.equal(r.status, 200);
  assert.equal(r.body.length, body.length);
});

test('a connection closed before Content-Length is reached rejects', async () => {
  rawReply = (sock) => {
    sock.write('HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n||cut');
    sock.end();
  };
  await assert.rejects(httpGet(`${rawBase}/`, opts), /complete|aborted|ECONNRESET|socket hang up/);
});
