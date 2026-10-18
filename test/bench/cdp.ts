// Bastion Shield bench — minimal Chrome DevTools Protocol client over the
// browser WebSocket (Node's built-in WebSocket), in flatten mode so one
// connection can drive the page and every auto-attached out-of-process
// iframe. Playwright's CDPSession cannot address child sessions, and ad
// iframes are almost always cross-site OOPIFs, so we need this to see all
// requests.
//
// SPDX-License-Identifier: GPL-3.0-or-later

type Listener = (params: any, sessionId: string | undefined) => void;

export class CdpError extends Error {
  readonly code: number | undefined;
  constructor(method: string, message: string, code?: number) {
    super(`${method}: ${message}`);
    this.code = code;
  }
}

export class Cdp {
  private ws: WebSocket;
  private nextId = 1;
  private pending = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void; method: string; timer: ReturnType<typeof setTimeout> }>();
  private listeners = new Map<string, Set<Listener>>();
  closed = false;

  private constructor(ws: WebSocket) {
    this.ws = ws;
    ws.addEventListener('message', (ev: MessageEvent) => this.onMessage(String(ev.data)));
    ws.addEventListener('close', () => {
      this.closed = true;
      for (const [, p] of this.pending) {
        clearTimeout(p.timer);
        p.reject(new CdpError(p.method, 'connection closed'));
      }
      this.pending.clear();
    });
    ws.addEventListener('error', () => {
      /* surfaced through close */
    });
  }

  static connect(wsUrl: string, timeoutMs = 15_000): Promise<Cdp> {
    return new Promise((resolve, reject) => {
      let ws: WebSocket;
      try {
        ws = new WebSocket(wsUrl);
      } catch (e) {
        reject(e as Error);
        return;
      }
      const timer = setTimeout(() => {
        try {
          ws.close();
        } catch {
          /* ignore */
        }
        reject(new Error(`CDP connect timeout: ${wsUrl}`));
      }, timeoutMs);
      ws.addEventListener('open', () => {
        clearTimeout(timer);
        resolve(new Cdp(ws));
      });
      ws.addEventListener('error', () => {
        clearTimeout(timer);
        reject(new Error(`CDP connect failed: ${wsUrl}`));
      });
    });
  }

  private onMessage(data: string): void {
    let msg: any;
    try {
      msg = JSON.parse(data);
    } catch {
      return;
    }
    if (typeof msg.id === 'number') {
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      clearTimeout(p.timer);
      if (msg.error) p.reject(new CdpError(p.method, msg.error.message ?? 'error', msg.error.code));
      else p.resolve(msg.result ?? {});
      return;
    }
    if (typeof msg.method === 'string') {
      const set = this.listeners.get(msg.method);
      if (set) for (const l of [...set]) {
        try {
          l(msg.params ?? {}, msg.sessionId);
        } catch {
          /* listener bugs must not kill the connection */
        }
      }
      const any = this.listeners.get('*');
      if (any) for (const l of [...any]) {
        try {
          l({ method: msg.method, params: msg.params ?? {} }, msg.sessionId);
        } catch {
          /* ignore */
        }
      }
    }
  }

  send<T = any>(method: string, params: object = {}, sessionId?: string, timeoutMs = 30_000): Promise<T> {
    if (this.closed) return Promise.reject(new CdpError(method, 'connection closed'));
    const id = this.nextId++;
    const msg: Record<string, unknown> = { id, method, params };
    if (sessionId) msg.sessionId = sessionId;
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new CdpError(method, `timeout after ${timeoutMs} ms`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, method, timer });
      try {
        this.ws.send(JSON.stringify(msg));
      } catch (e) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(e as Error);
      }
    });
  }

  /** send() that resolves to null instead of throwing (optional/unsupported commands). */
  async trySend<T = any>(method: string, params: object = {}, sessionId?: string, timeoutMs = 10_000): Promise<T | null> {
    try {
      return await this.send<T>(method, params, sessionId, timeoutMs);
    } catch {
      return null;
    }
  }

  on(method: string, l: Listener): () => void {
    let set = this.listeners.get(method);
    if (!set) this.listeners.set(method, (set = new Set()));
    set.add(l);
    return () => set!.delete(l);
  }

  waitFor(method: string, pred: (params: any, sessionId: string | undefined) => boolean, timeoutMs: number): Promise<any | null> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        off();
        resolve(null);
      }, timeoutMs);
      const off = this.on(method, (p, s) => {
        if (pred(p, s)) {
          clearTimeout(timer);
          off();
          resolve(p);
        }
      });
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.ws.close();
    } catch {
      /* ignore */
    }
  }
}
