// Bastion Shield build tools — a small HTTP(S) GET on node:http / node:https
// for downloading filter lists.
//
// Why not the global fetch(): Node's bundled undici 7 (Node 24) crashes the
// whole process with an uncatchable `AssertionError: assert(!this.paused)`
// from `Parser.finish` when a server closes the connection (FIN) while the
// response body is paused under backpressure (nodejs/undici#5360, fixed in
// undici 8.4.1, not backported to 7.x). The list fetcher downloads six lists
// at a time and hashes/expands them on the same thread, so a body can sit
// unread long enough to hit it; CI died twice on 2026-10-30 that way. Errors
// from node:http always reach the returned promise, so the caller's retry
// loop sees them.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { request as httpRequest, type IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { brotliDecompressSync, gunzipSync, inflateSync } from 'node:zlib';

export interface HttpGetOptions {
  headers?: Record<string, string>;
  /** Deadline for the whole exchange, redirects and body included. */
  timeoutMs: number;
  /** Abort when the (compressed or decoded) body grows beyond this. */
  maxBytes: number;
  /** Redirects to follow (default 5). */
  maxRedirects?: number;
}

export interface HttpGetResponse {
  status: number;
  /** URL after redirects. */
  url: string;
  headers: IncomingMessage['headers'];
  /** Decoded body; empty for 304 and other bodiless answers. */
  body: Buffer;
}

export class HttpGetError extends Error {}

/** The body exceeded `maxBytes`; retrying will not help. */
export class HttpBodyTooLargeError extends HttpGetError {}

const REDIRECTS = new Set([301, 302, 303, 307, 308]);

/** GET `url`, following redirects; rejects on network errors, timeouts, truncated or oversized bodies. */
export async function httpGet(url: string, opts: HttpGetOptions): Promise<HttpGetResponse> {
  const deadline = Date.now() + opts.timeoutMs;
  let current = new URL(url);
  for (let hop = 0; ; hop++) {
    const res = await getOnce(current, opts, deadline);
    const location = res.headers.location;
    if (!REDIRECTS.has(res.status) || !location) return res;
    if (hop >= (opts.maxRedirects ?? 5)) throw new HttpGetError(`too many redirects (last: ${current.href})`);
    const next = new URL(location, current);
    if (next.protocol !== 'https:' && next.protocol !== 'http:') throw new HttpGetError(`redirect to unsupported URL ${next.href}`);
    if (current.protocol === 'https:' && next.protocol === 'http:') throw new HttpGetError(`refusing HTTPS to HTTP redirect (${next.href})`);
    current = next;
  }
}

function getOnce(url: URL, opts: HttpGetOptions, deadline: number): Promise<HttpGetResponse> {
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return Promise.reject(new HttpGetError(`unsupported URL ${url.href}`));
  const request = url.protocol === 'https:' ? httpsRequest : httpRequest;
  return new Promise<HttpGetResponse>((resolve, reject) => {
    let settled = false;
    const fail = (e: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      req.destroy();
      reject(e instanceof Error ? e : new HttpGetError(String(e)));
    };
    const remaining = deadline - Date.now();
    const timer = setTimeout(() => fail(new HttpGetError(`timed out after ${opts.timeoutMs} ms`)), Math.max(0, remaining));
    const req = request(url, {
      method: 'GET',
      headers: { 'accept-encoding': 'gzip, deflate, br', ...opts.headers },
      // A fresh connection per request: no pooled socket the server may already have closed.
      agent: false,
    });
    req.on('error', fail);
    req.on('response', (res) => {
      res.on('error', fail);
      const status = res.statusCode ?? 0;
      if (status === 304 || REDIRECTS.has(status) || status >= 400) {
        // Body not needed: drain it so the socket can close.
        res.resume();
        res.on('end', () => done(Buffer.alloc(0)));
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (c: Buffer) => {
        size += c.length;
        if (size > opts.maxBytes) fail(new HttpBodyTooLargeError(`response larger than ${opts.maxBytes} bytes`));
        else chunks.push(c);
      });
      res.on('end', () => {
        // A connection closed before Content-Length (or the last chunk) arrived.
        if (!res.complete) return fail(new HttpGetError('connection closed before the response was complete'));
        try {
          done(decodeBody(Buffer.concat(chunks), res.headers['content-encoding'], opts.maxBytes));
        } catch (e) {
          if ((e as NodeJS.ErrnoException).code === 'ERR_BUFFER_TOO_LARGE') fail(new HttpBodyTooLargeError(`decoded response larger than ${opts.maxBytes} bytes`));
          else fail(new HttpGetError(`cannot decode ${res.headers['content-encoding']} body: ${(e as Error).message}`));
        }
      });
      function done(body: Buffer) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ status, url: url.href, headers: res.headers, body });
      }
    });
    req.end();
  });
}

function decodeBody(raw: Buffer, encoding: string | undefined, maxBytes: number): Buffer {
  const enc = (encoding ?? '').trim().toLowerCase();
  // maxOutputLength makes a decompression bomb throw instead of filling memory.
  const limit = { maxOutputLength: maxBytes + 1 };
  if (enc === '' || enc === 'identity') return raw;
  if (enc === 'gzip' || enc === 'x-gzip') return gunzipSync(raw, limit);
  if (enc === 'br') return brotliDecompressSync(raw, limit);
  if (enc === 'deflate') return inflateSync(raw, limit);
  throw new Error(`unsupported content-encoding "${enc}"`);
}
