// Bastion Shield e2e — (h) scriptlet injection: a hostname from the shipped
// scriptlet data gets its abort-on-property-read / set-constant applied in the
// MAIN world before page scripts run; an unrelated host does not.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { expect, test } from '../support/fixtures.ts';
import { HOSTS } from '../support/hosts.ts';
import { listTextDirs, pickScriptlets } from '../support/pickers.ts';
import type { ScriptletPick } from '../support/pickers.ts';

interface Probe {
  threw: boolean;
  errName?: string;
  type?: string;
  value?: string;
}

function probePage(p: ScriptletPick): string {
  const prop = JSON.stringify(p.prop);
  // Read only: assigning a value of another type would make set-constant
  // stand down by design (uBO "mustAbort"), which is not what we test here.
  // The inline script runs after the document_start scriptlets.
  return `<!doctype html><html><head><meta charset="utf-8"><title>scriptlet probe</title>
<script>
(function () {
  var r = { threw: false };
  try { var v = window[${prop}]; r.type = typeof v; r.value = String(v); }
  catch (e) { r.threw = true; r.errName = String(e && e.name); }
  window.__probe = r;
})();
</script></head><body><p>probe</p></body></html>`;
}

function expectedValue(v: string): { type: string; value?: string } {
  switch (v) {
    case 'true':
    case 'false':
      return { type: 'boolean', value: v };
    case 'null':
      return { type: 'object', value: 'null' };
    case '0':
    case '1':
      return { type: 'number', value: v };
    case 'undefined':
      return { type: 'undefined', value: 'undefined' };
    case '""':
    case "''":
    case 'emptyStr':
      return { type: 'string', value: '' };
    default:
      return { type: 'function' };
  }
}

test.describe('scriptlets', () => {
  test('(h) shipped scriptlets run on their hostname and nowhere else', async ({ page, server, dist }, testInfo) => {
    const picks = pickScriptlets(dist, 3);
    await testInfo.attach('scriptlet-picks', { body: JSON.stringify({ picks, listDirs: listTextDirs() }, null, 2), contentType: 'application/json' });
    expect(picks.length, `abort-on-property-read/set-constant filters found in list texts (${listTextDirs().join(', ')}) and in dist/scriptlets`).toBeGreaterThan(0);
    for (const [i, p] of picks.entries()) {
      const html = probePage(p);
      await page.goto(server.setPage(p.host, `/e2e/scriptlet-${i}.html`, html));
      expect(new URL(page.url()).hostname, `page loaded on ${p.host}`).toBe(p.host);
      const probe = (await page.evaluate(() => (window as unknown as { __probe?: unknown }).__probe)) as Probe | undefined;
      const label = `${p.filter}  [${p.registrationId} -> ${p.file}]`;
      if (p.name === 'abort-on-property-read') {
        expect.soft(probe?.threw, `${label}: reading ${p.prop} throws`).toBe(true);
        expect.soft(probe?.errName, `${label}: ReferenceError`).toBe('ReferenceError');
      } else {
        const exp = expectedValue(p.value!);
        expect.soft(probe?.type, `${label}: typeof ${p.prop}`).toBe(exp.type);
        if (exp.value !== undefined) expect.soft(probe?.value, `${label}: value of ${p.prop}`).toBe(exp.value);
      }
      // Same probe on a host without scriptlets: the property does not exist.
      await page.goto(server.setPage(HOSTS.C, `/e2e/scriptlet-control-${i}.html`, html));
      const ctl = (await page.evaluate(() => (window as unknown as { __probe?: unknown }).__probe)) as Probe | undefined;
      expect.soft(ctl, `control on ${HOSTS.C}: ${p.prop} untouched`).toMatchObject({ threw: false, type: 'undefined' });
    }
  });
});
