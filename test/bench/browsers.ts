// Bastion Shield bench — launch Chromium-family browsers as plain processes
// with --remote-debugging-port on 127.0.0.1 (REA needs that HTTP discovery
// endpoint, and Playwright's pipe transport has none), each with a fresh
// --user-data-dir, and make sure every process tree is gone afterwards.
//
// Kinds: chromium (Playwright's Chromium, no extension), bastion (the same
// Chromium with Bastion Shield), brave (installed Brave, Shields at defaults)
// and edge (installed Microsoft Edge with Bastion Shield, tracking prevention
// at its default "Balanced").
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { spawn, spawnSync } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { Cdp } from './cdp.ts';
import { seedChromiumProfile } from '../../tools/lib/chromium-profile.ts';

export type BrowserKind = 'chromium' | 'bastion' | 'brave' | 'edge';

export interface BrowserSpec {
  kind: BrowserKind;
  executable: string;
  userDataDir: string;
  headless: boolean;
  /** Unpacked extension to load (any kind; the bench passes it for bastion and edge). */
  extensionDir?: string;
  extraArgs?: string[];
  /** Initial Default/Preferences, e.g. developer mode or Brave's per-site Shields setting. */
  prefs?: Record<string, unknown>;
}

export interface LaunchedBrowser {
  spec: BrowserSpec;
  proc: ChildProcess;
  port: number;
  httpEndpoint: string;
  wsUrl: string;
  product: string;
  cdp: Cdp;
  stderrTail: string[];
  close(): Promise<void>;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function defaultBravePath(): string | null {
  const candidates =
    process.platform === 'win32'
      ? [
          'C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe',
          path.join(process.env.LOCALAPPDATA || '', 'BraveSoftware', 'Brave-Browser', 'Application', 'brave.exe'),
        ]
      : process.platform === 'darwin'
        ? ['/Applications/Brave Browser.app/Contents/MacOS/Brave Browser']
        : ['/usr/bin/brave-browser', '/usr/bin/brave', '/snap/bin/brave'];
  return candidates.find((c) => c && existsSync(c)) ?? null;
}

export function defaultEdgePath(): string | null {
  const candidates =
    process.platform === 'win32'
      ? [
          path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
          path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
        ]
      : process.platform === 'darwin'
        ? ['/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge']
        : ['/usr/bin/microsoft-edge', '/usr/bin/microsoft-edge-stable', '/opt/microsoft/msedge/msedge'];
  return candidates.find((c) => c && existsSync(c)) ?? null;
}

export function commonArgs(spec: BrowserSpec): string[] {
  const args = [
    '--remote-debugging-port=0',
    '--remote-debugging-address=127.0.0.1',
    `--user-data-dir=${spec.userDataDir}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-sync',
    '--disable-features=Translate,MediaRouter,OptimizationHints,AutofillServerCommunication',
    '--window-size=1366,900',
    '--lang=de-CH',
    '--accept-lang=de-CH,de,en-US,en',
    '--password-store=basic',
    '--use-mock-keychain',
    'about:blank',
  ];
  if (spec.headless) args.unshift('--headless=new');
  if (spec.extensionDir) {
    args.unshift(`--disable-extensions-except=${spec.extensionDir}`, `--load-extension=${spec.extensionDir}`);
  }
  // Brave and Edge must keep component updates on (Brave's filter lists and Edge's tracking
  // prevention lists are components); plain Chromium should not run component extensions,
  // so the only extension SW is ours.
  if (spec.kind === 'chromium' || spec.kind === 'bastion') args.unshift('--disable-component-update', '--disable-component-extensions-with-background-pages');
  return [...(spec.extraArgs ?? []), ...args];
}

async function readDevToolsActivePort(dir: string, proc: ChildProcess, timeoutMs: number): Promise<{ port: number; path: string }> {
  const file = path.join(dir, 'DevToolsActivePort');
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (proc.exitCode !== null) throw new Error(`browser exited early with code ${proc.exitCode}`);
    try {
      const [port, p] = readFileSync(file, 'utf8').split(/\r?\n/);
      if (port && p) return { port: Number(port), path: p };
    } catch {
      /* not yet written */
    }
    await sleep(150);
  }
  throw new Error(`DevToolsActivePort did not appear in ${dir} within ${timeoutMs} ms`);
}

/** Kill a process and all its children (Chromium spawns many). */
export function killTree(pid: number | undefined): void {
  if (!pid) return;
  try {
    if (process.platform === 'win32') spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
    else process.kill(-pid, 'SIGKILL');
  } catch {
    try {
      process.kill(pid, 'SIGKILL');
    } catch {
      /* already gone */
    }
  }
}

/** Empty the profile directory, seed it and write the initial Preferences. */
export function prepareProfile(spec: BrowserSpec): void {
  rmSync(spec.userDataDir, { recursive: true, force: true });
  mkdirSync(spec.userDataDir, { recursive: true });
  // Chromium, Brave and Edge probe the Windows password on a fresh profile, and repeated
  // probes lock the account. Seed the cached answer first: tools/lib/chromium-profile.ts.
  seedChromiumProfile(spec.userDataDir);
  if (spec.prefs) {
    mkdirSync(path.join(spec.userDataDir, 'Default'), { recursive: true });
    writeFileSync(path.join(spec.userDataDir, 'Default', 'Preferences'), JSON.stringify(spec.prefs));
  }
}

export async function launchBrowser(spec: BrowserSpec, timeoutMs = 45_000): Promise<LaunchedBrowser> {
  prepareProfile(spec);
  const proc = spawn(spec.executable, commonArgs(spec), {
    stdio: ['ignore', 'ignore', 'pipe'],
    detached: process.platform !== 'win32', // own process group for killTree on POSIX
    windowsHide: true,
  });
  const stderrTail: string[] = [];
  proc.stderr?.setEncoding('utf8');
  proc.stderr?.on('data', (d: string) => {
    for (const line of d.split(/\r?\n/)) if (line.trim()) stderrTail.push(line);
    if (stderrTail.length > 400) stderrTail.splice(0, stderrTail.length - 400);
  });
  proc.on('error', (e) => stderrTail.push('spawn error: ' + String(e)));
  let cdp: Cdp | null = null;
  try {
    const { port, path: wsPath } = await readDevToolsActivePort(spec.userDataDir, proc, timeoutMs);
    const httpEndpoint = `http://127.0.0.1:${port}`;
    let product = '';
    let wsUrl = `ws://127.0.0.1:${port}${wsPath}`;
    try {
      const v = (await (await fetch(`${httpEndpoint}/json/version`)).json()) as { Browser?: string; webSocketDebuggerUrl?: string };
      product = v.Browser ?? '';
      if (v.webSocketDebuggerUrl) wsUrl = v.webSocketDebuggerUrl;
    } catch {
      /* HTTP discovery missing: fall back to the file's path */
    }
    cdp = await Cdp.connect(wsUrl);
    const c = cdp;
    let closed = false;
    const close = async () => {
      if (closed) return;
      closed = true;
      await c.trySend('Browser.close', {}, undefined, 5000);
      c.close();
      const end = Date.now() + 6000;
      while (proc.exitCode === null && Date.now() < end) await sleep(100);
      killTree(proc.pid); // also reaps renderer/GPU children on Windows
      await sleep(300);
      for (let i = 0; i < 5; i++) {
        try {
          rmSync(spec.userDataDir, { recursive: true, force: true });
          break;
        } catch {
          await sleep(500);
        }
      }
    };
    return { spec, proc, port, httpEndpoint, wsUrl, product, cdp, stderrTail, close };
  } catch (e) {
    cdp?.close();
    killTree(proc.pid);
    throw new Error(`${spec.kind}: launch failed: ${(e as Error).message}\n${stderrTail.slice(-15).join('\n')}`);
  }
}
