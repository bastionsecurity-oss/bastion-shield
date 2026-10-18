// Bastion Shield e2e — local fixture server.
//
// One TCP port on 127.0.0.1 speaks both HTTP and HTTPS (the first byte of a
// connection tells a TLS ClientHello apart from a plain request). Chromium
// maps every hostname to 127.0.0.1, so a single server can impersonate the
// fixture sites and every ad/tracker host; routing is by Host header. Speaking
// TLS on the same port matters because HSTS-preloaded hosts (Google's ad
// domains, youtube.com, ...) are upgraded to https:// on the same port by the
// network stack before we ever see them.
//
// Every request is recorded, so a test can tell "blocked by the extension"
// (never reached us) from "loaded" without trusting page-side signals alone.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { existsSync, readFileSync, statSync } from 'node:fs';
import http from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import https from 'node:https';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { FIXTURES_DIR } from './paths.ts';
import { createSelfSigned } from './selfsigned.ts';

export interface Hit {
  t: number;
  secure: boolean;
  host: string;
  method: string;
  /** Path including the query string. */
  path: string;
  pathname: string;
  query: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
}

export type Handler = (req: IncomingMessage, res: ServerResponse, hit: Hit) => void | Promise<void>;

interface PageEntry {
  body: string | Buffer;
  type: string;
  headers?: Record<string, string>;
}

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.htm': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.gif': 'image/gif',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.mp4': 'video/mp4',
  '.xml': 'application/xml',
};

// Smallest valid transparent GIF; served for any image-like path we synthesize.
const GIF_1X1 = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');

function stripPort(hostHeader: string | undefined): string {
  if (!hostHeader) return '';
  const h = hostHeader.trim().toLowerCase();
  if (h.startsWith('[')) return h.slice(0, h.indexOf(']') + 1);
  const i = h.lastIndexOf(':');
  return i === -1 ? h : h.slice(0, i);
}

/** Body synthesized for any path we do not know: lets lists' URL patterns "exist" on any host. */
function synthesize(hit: Hit): PageEntry {
  const ext = path.extname(hit.pathname).toLowerCase();
  const tag = JSON.stringify(hit.url);
  switch (ext) {
    case '.js':
    case '.mjs':
      return { type: TYPES['.js'], body: `(self.__bastionLoaded = self.__bastionLoaded || []).push(${tag});\n` };
    case '.css':
      return { type: TYPES['.css'], body: `/* ${hit.host}${hit.pathname} */\n` };
    case '.json':
      return { type: TYPES['.json'], body: JSON.stringify({ ok: true, url: hit.url }) };
    case '.html':
    case '.htm':
    case '.php':
    case '':
      return {
        type: TYPES['.html'],
        body: `<!doctype html><meta charset="utf-8"><title>${hit.host}</title><p id="fixture-default">${hit.host}${hit.pathname.replace(/</g, '&lt;')}</p>`,
      };
    default:
      if (/^\.(gif|png|jpe?g|webp|ico|bmp|svg)$/.test(ext) || /pixel|track|collect|beacon/i.test(hit.pathname)) {
        return { type: 'image/gif', body: GIF_1X1 };
      }
      return { type: 'text/plain; charset=utf-8', body: 'ok' };
  }
}

export class FixtureServer {
  port = 0;
  readonly tls: boolean;
  readonly hits: Hit[] = [];
  private readonly pages = new Map<string, PageEntry>();
  private readonly handlers: { host: string; path: string | RegExp; fn: Handler }[] = [];
  private tcp: net.Server | null = null;
  private httpServer: http.Server;
  private httpsServer: https.Server | null = null;
  private readonly sockets = new Set<net.Socket>();

  constructor(opts: { tls?: boolean } = {}) {
    const onRequest = (secure: boolean) => (req: IncomingMessage, res: ServerResponse) => {
      void this.handle(req, res, secure).catch((err) => {
        try {
          if (!res.headersSent) res.writeHead(500, { 'content-type': 'text/plain' });
          res.end(String(err?.stack || err));
        } catch {
          /* socket already gone */
        }
      });
    };
    this.httpServer = http.createServer(onRequest(false));
    let tls = opts.tls !== false;
    if (tls) {
      try {
        const { key, cert } = createSelfSigned([
          '*.example.com', 'example.com', '*.example.net', 'example.net', '*.example.org', 'example.org', 'localhost',
        ]);
        this.httpsServer = https.createServer({ key, cert }, onRequest(true));
      } catch {
        tls = false; // fall back to plain HTTP; tests use the http:// origin then
      }
    }
    this.tls = tls;
    for (const s of [this.httpServer, this.httpsServer]) {
      if (!s) continue;
      s.keepAliveTimeout = 1000;
      s.on('clientError', (_err, socket) => socket.destroy());
    }
  }

  async start(): Promise<this> {
    this.tcp = net.createServer((socket) => {
      this.sockets.add(socket);
      socket.on('close', () => this.sockets.delete(socket));
      socket.on('error', () => socket.destroy());
      socket.once('data', (first) => {
        socket.pause();
        socket.unshift(first);
        // 0x16 = TLS handshake record. Anything else is treated as plain HTTP.
        const target = first[0] === 0x16 && this.httpsServer ? this.httpsServer : this.httpServer;
        target.emit('connection', socket);
        process.nextTick(() => socket.resume());
      });
    });
    await new Promise<void>((resolve, reject) => {
      this.tcp!.once('error', reject);
      this.tcp!.listen(0, '127.0.0.1', () => resolve());
    });
    this.port = (this.tcp.address() as AddressInfo).port;
    return this;
  }

  async stop(): Promise<void> {
    for (const s of this.sockets) s.destroy();
    await new Promise<void>((resolve) => (this.tcp ? this.tcp.close(() => resolve()) : resolve()));
    this.httpServer.close();
    this.httpsServer?.close();
  }

  get scheme(): 'https' | 'http' {
    return this.tls ? 'https' : 'http';
  }

  /**
   * Origin as the browser sees it. Chromium maps every host:port to this
   * server (hermeticArgs), so URLs use default ports; `withPort` is for clients
   * that connect directly (curl, Node).
   */
  origin(host: string, scheme: 'https' | 'http' = this.scheme, withPort = false): string {
    return withPort ? `${scheme}://${host}:${this.port}` : `${scheme}://${host}`;
  }

  url(host: string, p = '/'): string {
    return this.origin(host) + (p.startsWith('/') ? p : '/' + p);
  }

  /** Serve `body` at host+path (host '*' = any host). The query string is ignored when matching. */
  setPage(host: string, p: string, body: string | Buffer, type = 'text/html; charset=utf-8', headers?: Record<string, string>): string {
    this.pages.set(`${host.toLowerCase()}|${p}`, { body, type, headers });
    return host === '*' ? p : this.url(host, p);
  }

  /** Custom handler for host ('*' = any) and exact path or RegExp on the path+query. */
  route(host: string, p: string | RegExp, fn: Handler): void {
    this.handlers.unshift({ host: host.toLowerCase(), path: p, fn });
  }

  clearHits(): void {
    this.hits.length = 0;
  }

  hitsFor(host: string, pathPrefix = '', since = 0): Hit[] {
    const h = host.toLowerCase();
    return this.hits.filter((x) => x.host === h && x.t >= since && (pathPrefix === '' || x.path.startsWith(pathPrefix)));
  }

  async waitForHit(pred: (h: Hit) => boolean, timeoutMs = 5000): Promise<Hit | null> {
    const end = Date.now() + timeoutMs;
    for (;;) {
      const found = this.hits.find(pred);
      if (found) return found;
      if (Date.now() > end) return null;
      await new Promise((r) => setTimeout(r, 50));
    }
  }

  private async handle(req: IncomingMessage, res: ServerResponse, secure: boolean): Promise<void> {
    const host = stripPort(req.headers.host);
    const rawPath = req.url || '/';
    const qi = rawPath.indexOf('?');
    const pathname = qi === -1 ? rawPath : rawPath.slice(0, qi);
    const hit: Hit = {
      t: Date.now(),
      secure,
      host,
      method: req.method || 'GET',
      path: rawPath,
      pathname,
      query: qi === -1 ? '' : rawPath.slice(qi + 1),
      url: `${secure ? 'https' : 'http'}://${req.headers.host}${rawPath}`,
      headers: { ...req.headers },
    };
    this.hits.push(hit);
    // Fixtures must never be cached: the same URL is loaded with different settings.
    res.setHeader('cache-control', 'no-store');
    res.setHeader('access-control-allow-origin', '*');
    res.setHeader('timing-allow-origin', '*');

    for (const h of this.handlers) {
      if (h.host !== '*' && h.host !== host) continue;
      const ok = typeof h.path === 'string' ? h.path === pathname : h.path.test(rawPath);
      if (ok) return void (await h.fn(req, res, hit));
    }

    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'access-control-allow-methods': 'GET, POST, OPTIONS',
        'access-control-allow-headers': '*',
      });
      return void res.end();
    }

    const page = this.pages.get(`${host}|${pathname}`) || this.pages.get(`*|${pathname}`);
    if (page) return this.send(res, page);

    if (pathname === '/__echo') {
      return this.send(res, {
        type: TYPES['.json'],
        body: JSON.stringify({ host, secure, method: hit.method, path: rawPath, headers: req.headers }),
      });
    }
    if (pathname === '/__redirect') {
      const to = new URLSearchParams(hit.query).get('to') || '/';
      res.writeHead(302, { location: to });
      return void res.end();
    }

    const file = this.staticFile(pathname);
    if (file) {
      return this.send(res, { type: TYPES[path.extname(file).toLowerCase()] || 'application/octet-stream', body: readFileSync(file) });
    }
    return this.send(res, synthesize(hit));
  }

  private staticFile(pathname: string): string | null {
    let decoded: string;
    try {
      decoded = decodeURIComponent(pathname);
    } catch {
      return null;
    }
    const resolved = path.resolve(FIXTURES_DIR, '.' + path.posix.normalize(decoded));
    if (resolved !== FIXTURES_DIR && !resolved.startsWith(FIXTURES_DIR + path.sep)) return null;
    try {
      if (!existsSync(resolved)) return null;
      const st = statSync(resolved);
      if (st.isDirectory()) {
        const idx = path.join(resolved, 'index.html');
        return existsSync(idx) ? idx : null;
      }
      return st.isFile() ? resolved : null;
    } catch {
      return null;
    }
  }

  private send(res: ServerResponse, page: PageEntry): void {
    const body = typeof page.body === 'string' ? Buffer.from(page.body, 'utf8') : page.body;
    res.writeHead(200, { 'content-type': page.type, 'content-length': body.length, ...(page.headers || {}) });
    res.end(body);
  }
}
