// Tests for the nerd mode per-tab signals (src/background/nerd.ts): the
// clipboard counter counts blocks by uBlock filters' prevent-clipboard-write
// too, which happen with Bastion's own ClickFix protection switched off.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { defaultSettings } from '../../src/background/settings.ts';
import { NerdService } from '../../src/background/nerd.ts';
import type { Settings } from '../../src/shared/types.ts';

function service(patch: (s: Settings) => void): NerdService {
  const s = defaultSettings();
  s.nerd.enabled = true;
  patch(s);
  return new NerdService({
    settings: () => s,
    blockedOnTab: async () => [],
    siteOf: async () => null,
    describeRules: async () => ({ filters: [], lists: [] }),
    addCustomFilters: async () => undefined,
  });
}

test('clip signals count with ClickFix protection off (uBO blocks them)', () => {
  const n = service((s) => {
    s.privacy.clipboardGuard = false;
  });
  assert.deepEqual(n.onSignal({ type: 'nerd:signal', kind: 'clip', sample: 'powershell -enc …' }, 4), { ok: true });
  assert.equal(n.tabState(4)?.clipboardBlocked, 1);
});

test('clip signals are ignored while nerd mode is off', () => {
  const n = service((s) => {
    s.nerd.enabled = false;
  });
  n.onSignal({ type: 'nerd:signal', kind: 'clip', sample: 'x' }, 4);
  assert.equal(n.tabState(4), null);
});
