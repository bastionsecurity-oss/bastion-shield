// Bastion Shield e2e — launch Chromium with the unpacked build and talk to it.
//
// The unpacked load doubles as a strict validator: Chromium refuses to load an
// unpacked extension whose static rulesets contain a semantically invalid rule,
// so "the service worker came up" is already a meaningful assertion.
//
// Runtime messages are sent from an extension page (the SW only accepts UI
// messages whose sender.url is on the extension origin, see ARCHITECTURE §7).
// chrome.* reads that do not need the SW (DNR state, registered scripts) are
// also done from that page, which avoids racing the SW's idle shutdown.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { spawn, spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { chromium } from '@playwright/test';
import type { BrowserContext, Page, Worker } from '@playwright/test';
import { RULE_ID } from '../../../src/shared/constants.ts';
import { hermeticArgs } from './hosts.ts';
import { DIST_DIR } from './paths.ts';
import { seedChromiumProfile } from '../../../tools/lib/chromium-profile.ts';
import { installManagedShim } from './managed.ts';

export interface ConsoleEntry {
  t: number;
  source: string;
  type: string;
  text: string;
}

export interface LaunchOptions {
  /** Fixture server port: every host:port is mapped to 127.0.0.1:<port>. */
  port: number;
  /** Load the extension (false = plain Chromium for baselines). */
  extension?: boolean;
  distDir?: string;
  headless?: boolean;
  extraArgs?: string[];
  /** Stage the build with the simulated chrome.storage.managed (support/managed.ts). */
  managedShim?: boolean;
}

/**
 * Copy the build to a throw-away directory and load that instead: Chromium
 * writes indexed rulesets into an unpacked extension's folder
 * (_metadata/generated_indexed_rulesets), and a store package must not
 * contain them. The copy leaves dist/ exactly as the build produced it.
 */
export function stageExtension(dist: string, prefix = 'bastion-e2e-ext-'): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), prefix));
  cpSync(dist, dir, { recursive: true, filter: (src) => path.basename(src) !== '_metadata' });
  return dir;
}

export interface StateSnapshot {
  enabledRulesets: string[];
  dynamicRules: unknown[];
  sessionRules: unknown[];
  scripts: unknown[];
}

export class ExtensionHarness {
  readonly context: BrowserContext;
  readonly userDataDir: string;
  readonly browserLog: string[];
  readonly console: ConsoleEntry[] = [];
  id = '';
  /** Staged copy of the build that Chromium actually loads (removed on close). */
  extensionDir: string | null = null;
  private helperPage: Page | null = null;
  private watched = new WeakSet<Worker>();

  private constructor(context: BrowserContext, userDataDir: string, browserLog: string[]) {
    this.context = context;
    this.userDataDir = userDataDir;
    this.browserLog = browserLog;
  }

  get origin(): string {
    return `chrome-extension://${this.id}`;
  }

  static async launch(opts: LaunchOptions): Promise<ExtensionHarness> {
    const withExt = opts.extension !== false;
    const dist = opts.distDir ?? DIST_DIR;
    const userDataDir = mkdtempSync(path.join(os.tmpdir(), withExt ? 'bastion-e2e-' : 'bastion-e2e-plain-'));
    // Developer mode makes chrome://extensions collect runtime errors (best effort;
    // we also flip it through developerPrivate once the browser is up).
    mkdirSync(path.join(userDataDir, 'Default'), { recursive: true });
    // Never let Chromium probe the Windows password (it locks the account): see tools/lib/chromium-profile.ts.
    seedChromiumProfile(userDataDir);
    writeFileSync(path.join(userDataDir, 'Default', 'Preferences'), JSON.stringify({ extensions: { ui: { developer_mode: true } } }));
    const browserLog: string[] = [];
    const args = [...hermeticArgs(opts.port), ...(opts.extraArgs ?? [])];
    const staged = withExt ? stageExtension(dist) : null;
    if (staged && opts.managedShim) installManagedShim(staged);
    if (staged) args.push(`--disable-extensions-except=${staged}`, `--load-extension=${staged}`);
    const headless = opts.headless ?? !process.env.HEADED;
    const context = await chromium.launchPersistentContext(userDataDir, {
      channel: 'chromium',
      headless,
      ignoreHTTPSErrors: true,
      viewport: { width: 1280, height: 900 },
      args,
    });
    const h = new ExtensionHarness(context, userDataDir, browserLog);
    h.extensionDir = staged;
    if (withExt) {
      context.on('serviceworker', (w) => h.watchWorker(w));
      for (const w of context.serviceWorkers()) h.watchWorker(w);
      let sw: Worker;
      try {
        sw = await h.waitForServiceWorker(20_000);
      } catch {
        await h.close();
        // Playwright no longer forwards browser stderr to its logger, so ask a
        // separate Chromium process for the load error it reports there.
        const lines = await diagnoseLoadFailure(dist);
        throw new Error(
          `Extension at ${dist} did not start a service worker within 20 s.\n` +
            (lines.length ? lines.join('\n') : '(Chromium reported no load error; check background.js for an exception at startup)'),
        );
      }
      h.id = new URL(sw.url()).host;
    }
    return h;
  }

  async close(): Promise<void> {
    try {
      await this.context.close();
    } catch {
      /* already closed */
    }
    for (const dir of [this.userDataDir, this.extensionDir]) {
      if (!dir) continue;
      try {
        rmSync(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 200 });
      } catch {
        /* Windows may still hold a lock on a profile file; the OS temp cleaner gets it */
      }
    }
  }

  private watchWorker(w: Worker): void {
    if (this.watched.has(w)) return;
    if (!w.url().startsWith('chrome-extension://')) return;
    this.watched.add(w);
    w.on('console', (m) => this.console.push({ t: Date.now(), source: 'sw', type: m.type(), text: m.text() }));
    // Uncaught SW errors do not surface as console messages; surface them ourselves.
    void w
      .evaluate(() => {
        const g = self as unknown as { __bxErrHooks?: boolean };
        if (g.__bxErrHooks) return;
        g.__bxErrHooks = true;
        self.addEventListener('error', (e: ErrorEvent) => console.error('[e2e] uncaught error:', e.message, e.filename + ':' + e.lineno));
        self.addEventListener('unhandledrejection', (e: PromiseRejectionEvent) =>
          console.error('[e2e] unhandled rejection:', String((e.reason && (e.reason.stack || e.reason.message)) || e.reason)),
        );
      })
      .catch(() => {});
  }

  /** Errors logged by the SW or by extension pages since `since`. */
  errors(since = 0): ConsoleEntry[] {
    return this.console.filter((c) => c.t >= since && (c.type === 'error' || c.text.startsWith('[e2e] uncaught')));
  }

  async waitForServiceWorker(timeoutMs = 10_000): Promise<Worker> {
    const existing = this.context.serviceWorkers().find((w) => w.url().startsWith('chrome-extension://'));
    if (existing) return existing;
    const w = await this.context.waitForEvent('serviceworker', {
      timeout: timeoutMs,
      predicate: (x) => x.url().startsWith('chrome-extension://'),
    });
    return w;
  }

  /** Current SW, woken by a message if Chromium stopped it while idle. */
  async sw(): Promise<Worker> {
    const live = this.context.serviceWorkers().find((w) => w.url().startsWith(this.origin));
    if (live) return live;
    const p = this.waitForServiceWorker(10_000);
    await this.helper().then((pg) => pg.evaluate(() => chrome.runtime.sendMessage({ type: 'config:get' }).catch(() => null))).catch(() => null);
    return p;
  }

  /**
   * Stop the extension's service worker (CDP ServiceWorker.stopAllWorkers), as
   * Chromium does after 30 s idle. The next event or message starts it again.
   * Returns false when it was still running after 5 s.
   */
  async stopServiceWorker(): Promise<boolean> {
    const page = await this.helper();
    const cdp = await this.context.newCDPSession(page);
    try {
      await cdp.send('ServiceWorker.enable');
      await cdp.send('ServiceWorker.stopAllWorkers');
    } finally {
      await cdp.detach().catch(() => {});
    }
    // Playwright keeps the Worker object (the DevTools target survives a
    // restart), so ask the extension whether its background context is gone.
    const end = Date.now() + 5000;
    while (Date.now() < end) {
      if ((await this.backgroundContexts()) === 0) return true;
      await new Promise((r) => setTimeout(r, 100));
    }
    return false;
  }

  /** Number of running background (service worker) contexts of the extension (chrome.runtime.getContexts). */
  async backgroundContexts(): Promise<number> {
    return this.api(async () => {
      const rt = chrome.runtime as unknown as { getContexts?: (f: { contextTypes: string[] }) => Promise<unknown[]> };
      return rt.getContexts ? (await rt.getContexts({ contextTypes: ['BACKGROUND'] })).length : -1;
    });
  }

  /** A long-lived extension page used for messaging and chrome.* calls. */
  async helper(): Promise<Page> {
    if (this.helperPage && !this.helperPage.isClosed()) return this.helperPage;
    const page = await this.context.newPage();
    page.on('console', (m) => this.console.push({ t: Date.now(), source: 'helper', type: m.type(), text: m.text() }));
    // manifest.json renders as a document on the extension origin with full API
    // access, without running any product UI code that could interfere.
    await page.goto(`${this.origin}/manifest.json`);
    this.helperPage = page;
    return page;
  }

  /** Evaluate in the helper extension page (chrome.* available). */
  async api<R, A = undefined>(fn: (arg: A) => R | Promise<R>, arg?: A): Promise<R> {
    const page = await this.helper();
    // Playwright's generic Unboxed<A> does not unify with a free A; the args we pass are plain JSON.
    return page.evaluate(fn as unknown as (arg: unknown) => R | Promise<R>, arg as unknown);
  }

  /** chrome.runtime.sendMessage from an extension page; resolves with the SW's response. */
  async send<T = unknown>(msg: object): Promise<T> {
    return this.api(async (m: object) => {
      try {
        return (await chrome.runtime.sendMessage(m)) as unknown;
      } catch (e) {
        return { __sendError: String((e as Error)?.message || e) };
      }
    }, msg) as Promise<T>;
  }

  async snapshot(): Promise<StateSnapshot> {
    return this.api(async () => {
      const dnr = chrome.declarativeNetRequest;
      const [enabledRulesets, dynamicRules, sessionRules] = await Promise.all([dnr.getEnabledRulesets(), dnr.getDynamicRules(), dnr.getSessionRules()]);
      let scripts: unknown[] = [];
      try {
        scripts = await chrome.scripting.getRegisteredContentScripts();
      } catch {
        /* scripting unavailable */
      }
      return { enabledRulesets: enabledRulesets.sort(), dynamicRules, sessionRules, scripts };
    });
  }

  /**
   * Wait until the SW's debounced applyAll() changed DNR/script state relative to
   * `before` and the state has been stable for a moment. Returns false on timeout
   * (the caller's assertion then reports what is wrong).
   */
  async waitForApply(before: StateSnapshot, timeoutMs = 6000): Promise<boolean> {
    const end = Date.now() + timeoutMs;
    const b = JSON.stringify(before);
    let last = '';
    let stableSince = 0;
    let changed = false;
    while (Date.now() < end) {
      const cur = JSON.stringify(await this.snapshot());
      if (cur !== b) changed = true;
      if (cur === last) {
        if (changed && Date.now() - stableSince > 500) return true;
      } else {
        last = cur;
        stableSince = Date.now();
      }
      await new Promise((r) => setTimeout(r, 120));
    }
    return changed;
  }

  /** Send a settings-changing message and wait for the resulting apply. */
  async sendAndApply<T = unknown>(msg: object, timeoutMs = 6000): Promise<{ response: T; applied: boolean }> {
    const before = await this.snapshot();
    const response = await this.send<T>(msg);
    const applied = await this.waitForApply(before, timeoutMs);
    // Content-script registration changes only affect documents created afterwards.
    await new Promise((r) => setTimeout(r, 200));
    return { response, applied };
  }

  /**
   * Fresh-install readiness: the Standard-mode first-party allow rule and the
   * content-script registrations exist (both written by applyAll on install).
   */
  async waitUntilReady(timeoutMs = 20_000): Promise<{ ready: boolean; snapshot: StateSnapshot }> {
    const end = Date.now() + timeoutMs;
    let snap = await this.snapshot();
    while (Date.now() < end) {
      const hasStd = (snap.dynamicRules as { id: number }[]).some((r) => r.id === RULE_ID.STANDARD_1P_ALLOW);
      if (hasStd && snap.scripts.length > 0) {
        // Let the tail of the install work (seed pick, badge, privacy APIs) settle.
        await new Promise((r) => setTimeout(r, 500));
        return { ready: true, snapshot: await this.snapshot() };
      }
      await new Promise((r) => setTimeout(r, 200));
      snap = await this.snapshot();
    }
    return { ready: false, snapshot: snap };
  }

  async tabIdOf(page: Page): Promise<number> {
    const url = page.url();
    const id = await this.api(async (u: string) => {
      const tabs = await chrome.tabs.query({});
      const t = tabs.find((x) => x.url === u) || tabs.find((x) => (x.url || '').split('#')[0] === u.split('#')[0]);
      return t?.id ?? -1;
    }, url);
    return id;
  }

  /** chrome://extensions view of this extension (manifest/install/runtime errors). */
  async extensionErrors(): Promise<{ manifestErrors: unknown[]; runtimeErrors: unknown[]; installWarnings: unknown[]; developerMode: boolean } | { error: string }> {
    const page = await this.context.newPage();
    try {
      await page.goto('chrome://extensions/');
      return await page.evaluate(async (id: string) => {
        // developerPrivate is the private API behind chrome://extensions.
        const dp = (chrome as unknown as { developerPrivate: any }).developerPrivate;
        // Developer mode makes the error console record runtime errors from now on.
        if (!(await dp.getProfileConfiguration()).inDeveloperMode) await dp.updateProfileConfiguration({ inDeveloperMode: true });
        const cfg = await dp.getProfileConfiguration();
        const info = await dp.getExtensionInfo(id);
        return {
          manifestErrors: info.manifestErrors ?? [],
          runtimeErrors: (info.runtimeErrors ?? []).map((e: any) => ({ severity: e.severity, message: e.message, source: e.source, context: e.contextUrl })),
          installWarnings: info.installWarnings ?? [],
          developerMode: !!cfg.inDeveloperMode,
        };
      }, this.id);
    } catch (e) {
      return { error: String((e as Error)?.message || e) };
    } finally {
      await page.close().catch(() => {});
    }
  }

  /** Load errors/warnings Chromium printed for this build (filled by checkLoadWarnings()). */
  loadErrorLines(): string[] {
    return this.browserLog;
  }

  /** Re-load the build in a throw-away Chromium and keep what it reports on stderr. */
  async checkLoadWarnings(dist: string = DIST_DIR): Promise<string[]> {
    const lines = await diagnoseLoadFailure(dist);
    this.browserLog.splice(0, this.browserLog.length, ...lines);
    return lines;
  }
}

/**
 * Start Chromium with the build and stderr logging, collect the lines of the
 * extensions load_error_reporter (the text chrome://extensions would show),
 * then kill it. Diagnostics only, so it never throws.
 */
export async function diagnoseLoadFailure(dist: string, waitMs = 6000): Promise<string[]> {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'bastion-e2e-diag-'));
  seedChromiumProfile(dir);
  const lines: string[] = [];
  let staged: string | null = null;
  try {
    staged = stageExtension(dist, 'bastion-e2e-diag-ext-');
    const child = spawn(
      chromium.executablePath(),
      ['--headless=new', `--user-data-dir=${dir}`, '--no-first-run', '--enable-logging=stderr', '--v=0', `--disable-extensions-except=${staged}`, `--load-extension=${staged}`, 'about:blank'],
      { stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true },
    );
    child.stderr?.setEncoding('utf8');
    child.stderr?.on('data', (d: string) => {
      for (const l of d.split(/\r?\n/)) {
        if (/load_error_reporter|Extension error|Failed to load extension|install_warning/i.test(l)) lines.push(l.trim());
      }
    });
    await new Promise((r) => setTimeout(r, waitMs));
    try {
      if (process.platform === 'win32' && child.pid) spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
      else child.kill('SIGKILL');
    } catch {
      /* already gone */
    }
    await new Promise((r) => setTimeout(r, 300));
  } catch (e) {
    lines.push(`diagnostic launch failed: ${String(e)}`);
  } finally {
    for (const d of [dir, staged]) {
      if (!d) continue;
      try {
        rmSync(d, { recursive: true, force: true, maxRetries: 3, retryDelay: 200 });
      } catch {
        /* ignore */
      }
    }
  }
  return lines;
}
