// Renders the Bastion shield-and-diamond mark into the PNG sizes Chromium needs
// for the toolbar action and the extensions page. Run: node tools/gen-icons.ts
// Output is committed (src/icons/*.png) so normal builds need no browser.
import { chromium } from '@playwright/test';
import { rmSync } from 'node:fs';
import { freshProfileDir } from './lib/chromium-profile.ts';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const RING = 'M 55.00 76.50 L 60.55 76.50 L 76.50 60.55 L 76.50 39.45 L 60.55 23.50 L 39.45 23.50 L 23.50 39.45 L 23.50 60.55 L 39.45 76.50 L 45.00 76.50 L 45.00 83.50 L 36.55 83.50 L 16.50 63.45 L 16.50 36.55 L 36.55 16.50 L 63.45 16.50 L 83.50 36.55 L 83.50 63.45 L 63.45 83.50 L 55.00 83.50 Z';
const CORE = 'M 50 40 L 60 50 L 50 60 L 40 50 Z';

// Mid-tone ring (#6E7A80, midpoint Fels/Nebel) stays legible on light and dark
// toolbars, same choice as the bastionsecurity.ch favicon.
const VARIANTS: Record<string, { ring: string; core: string }> = {
  on: { ring: '#6E7A80', core: '#DA291C' },
  off: { ring: '#A9B6BA', core: '#A9B6BA' },
};
const SIZES = [16, 19, 24, 32, 38, 48, 64, 128];

function svg(v: { ring: string; core: string }) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="13 13 74 74"><path fill="${v.ring}" fill-rule="evenodd" d="${RING}"/><path fill="${v.core}" d="${CORE}"/></svg>`;
}

const out = join(import.meta.dirname, '..', 'src', 'icons');
await mkdir(out, { recursive: true });
// Persistent context with a seeded profile: a bare chromium.launch() makes
// Chromium probe the Windows password (see tools/lib/chromium-profile.ts).
const profile = freshProfileDir('bastion-icons-');
const browser = await chromium.launchPersistentContext(profile, { deviceScaleFactor: 1 });
const page = browser.pages()[0] ?? (await browser.newPage());
for (const [name, v] of Object.entries(VARIANTS)) {
  await writeFile(join(out, `mark-${name}.svg`), svg(v) + '\n');
  for (const size of SIZES) {
    await page.setViewportSize({ width: size, height: size });
    await page.setContent(`<html><body style="margin:0;background:transparent">${svg(v).replace('<svg ', `<svg width="${size}" height="${size}" `)}</body></html>`);
    await writeFile(join(out, `icon-${name}-${size}.png`), await page.screenshot({ omitBackground: true }));
  }
}
await browser.close();
rmSync(profile, { recursive: true, force: true });
console.log('icons written to', out);
