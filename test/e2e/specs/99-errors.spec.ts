// Bastion Shield e2e — runs last in the worker: after every feature has been
// exercised, neither the service worker nor chrome://extensions may have
// collected errors.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { expect, test } from '../support/fixtures.ts';

test('no service-worker or extension errors accumulated during the run', async ({ ext }, testInfo) => {
  const sw = ext.errors();
  const info = await ext.extensionErrors();
  await testInfo.attach('errors', { body: JSON.stringify({ sw, info }, null, 2), contentType: 'application/json' });
  expect(sw.map((e) => `${e.source}: ${e.text}`), 'service worker console errors').toEqual([]);
  if (!('error' in info)) expect(info.runtimeErrors, 'chrome://extensions runtime errors').toEqual([]);
});
