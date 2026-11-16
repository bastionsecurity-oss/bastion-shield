// Tests for the remotely-hosted-code guard (Chrome Web Store MV3 policy).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { findRemoteCode, remoteCodeReason } from '../../tools/lib/remote-code.ts';
import { loadResources } from '../../tools/resources.ts';
import { createLogger } from '../../tools/lib/util.ts';

test('remoteCodeReason flags code that loads or evaluates foreign code', () => {
  assert.match(remoteCodeReason('(n=P.createElement("script")).src=t')!, /script/);
  assert.match(remoteCodeReason("P.write(C.createHTML('<script src=x>'));document.write(x)")!, /document\.write/);
  assert.match(remoteCodeReason('try { eval(workerString); } catch {}')!, /eval/);
  assert.match(remoteCodeReason('const f = new Function("return 1")')!, /Function/);
  assert.match(remoteCodeReason('importScripts(url)')!, /importScripts/);
  assert.match(remoteCodeReason('await import(u)')!, /import/);
});

test('remoteCodeReason accepts plain stubs', () => {
  assert.equal(remoteCodeReason('(function(){ window.ga = function(){}; })();'), null);
  assert.equal(remoteCodeReason('x.retrieval(1); y.reimport(2); a.eval(3)'), null);
  assert.equal(remoteCodeReason('const u = "https://www.google-analytics.com/analytics.js";'), null);
});

test('no vendored resource that loads foreign code is offered to the compiler', async () => {
  const set = await loadResources(createLogger('test', true));
  const names = [...set.redirectMap.keys(), ...set.scriptletMap.keys()];
  assert.deepEqual(names.filter((n) => /sugarcoat|vaft-ublock-origin|video-swap-new/.test(n)), []);
  const skipped = set.skipped.map((s) => s.name);
  assert.ok(skipped.some((n) => n.startsWith('async-sugarcoat-')), 'sugarcoat resources are reported as skipped');
  for (const s of set.scriptlets.values()) {
    if (s.origin !== 'ubo') assert.equal(remoteCodeReason(s.code), null, `${s.name} loads foreign code`);
  }
});

test('findRemoteCode scans shipped scripts but not scriptlet data files', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bastion-remote-'));
  try {
    await mkdir(join(dir, 'war'));
    await mkdir(join(dir, 'scriptlets'));
    await writeFile(join(dir, 'war', 'noop.js'), '(function(){})();');
    await writeFile(join(dir, 'war', 'tracker.js'), 'var s=document.createElement("script");s.src="//x/y.js"');
    await writeFile(join(dir, 'scriptlets', 'ublock-main.js'), '[0,"JSON.parse","document.createElement(\'script\')"]');
    await writeFile(join(dir, 'scriptlets', 'scriptlet-core-main.js'), 'eval(x)');
    assert.deepEqual(
      (await findRemoteCode(dir)).map((f) => f.file),
      ['scriptlets/scriptlet-core-main.js', 'war/tracker.js'],
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
