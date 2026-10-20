// Bastion Shield e2e — (a) the unpacked build loads cleanly and (b) the DNR
// state after install matches the build: default rulesets, static rule budget,
// RE2 support of every shipped regexFilter. Also checks package integrity that
// only shows up at runtime (redirect targets, WAR entries, transparency maps).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { LIMITS } from '../../../src/shared/constants.ts';
import { expect, test } from '../support/fixtures.ts';

test.describe('load and static rules', () => {
  test('(a) unpacked extension loads with a running service worker and no errors', async ({ ext, dist, installState }, testInfo) => {
    const sw = await ext.sw();
    const bg = dist.manifest.background?.service_worker ?? 'background.js';
    expect(sw.url(), 'service worker URL').toBe(`${ext.origin}/${bg.replace(/^\//, '')}`);
    await testInfo.attach('install', {
      body: JSON.stringify({ launchMs: installState.launchMs, ready: installState.ready, extensionId: ext.id }, null, 2),
      contentType: 'application/json',
    });
    expect(installState.ready, 'applyAll() on install wrote the Standard 1P allow rule and content-script registrations').toBe(true);

    // What Chromium's load_error_reporter prints for this build (would be shown on chrome://extensions).
    const loadErrors = await ext.checkLoadWarnings(dist.dir);
    expect(loadErrors, 'Chromium load errors/warnings for the unpacked build').toEqual([]);

    const info = await ext.extensionErrors();
    await testInfo.attach('chrome-extensions-info', { body: JSON.stringify(info, null, 2), contentType: 'application/json' });
    expect('error' in info ? info.error : null, 'chrome://extensions developerPrivate reachable').toBeNull();
    if (!('error' in info)) {
      expect(info.manifestErrors, 'manifest errors').toEqual([]);
      expect(info.installWarnings, 'install warnings (unknown keys, permissions, ...)').toEqual([]);
      expect(info.runtimeErrors, 'runtime errors collected by chrome://extensions').toEqual([]);
    }
    const errs = ext.errors();
    expect(errs.map((e) => `${e.source}: ${e.text}`), 'console errors from the service worker during install').toEqual([]);
  });

  test('(b) enabled rulesets equal the defaults and the static rule budget is respected', async ({ ext, dist }, testInfo) => {
    const sw = await ext.sw();
    const state = await sw.evaluate(async () => ({
      enabled: (await chrome.declarativeNetRequest.getEnabledRulesets()).sort(),
      available: await chrome.declarativeNetRequest.getAvailableStaticRuleCount(),
    }));
    const manifestEnabled = dist.manifestEnabledRulesets();
    const expected = dist.expectedDefaultRulesets() ?? manifestEnabled;
    const declared = dist.ruleResources();
    const ruleCount = (id: string) => dist.rules(id).length;
    const enabledRules = state.enabled.reduce((n, id) => n + ruleCount(id), 0);
    const regexEnabled = state.enabled.filter((id) => id.endsWith('.regex')).reduce((n, id) => n + ruleCount(id), 0);
    const report = {
      enabled: state.enabled,
      expected,
      manifestEnabled,
      missing: expected.filter((x) => !state.enabled.includes(x)),
      unexpected: state.enabled.filter((x) => !expected.includes(x)),
      availableStaticRuleCount: state.available,
      enabledStaticRules: enabledRules,
      enabledRegexRules: regexEnabled,
      declaredRulesets: declared.length,
    };
    await testInfo.attach('rulesets', { body: JSON.stringify(report, null, 2), contentType: 'application/json' });
    console.log(`[rulesets] enabled=${state.enabled.length} rules=${enabledRules} regex=${regexEnabled} available=${state.available}`);

    expect(declared.length, 'declared static rulesets').toBeLessThanOrEqual(LIMITS.MAX_STATIC_RULESETS);
    expect(state.enabled.length, 'enabled static rulesets').toBeLessThanOrEqual(LIMITS.MAX_ENABLED_STATIC_RULESETS);
    expect(manifestEnabled, 'manifest enabled flags mirror the catalog defaults').toEqual(expected);
    // A missing ".regex" companion here usually means Chromium silently skipped it (regex budget).
    expect(report.missing, 'default rulesets that are not enabled').toEqual([]);
    expect(report.unexpected, 'rulesets enabled although not default').toEqual([]);
    expect(regexEnabled, 'regex rules across enabled static rulesets').toBeLessThanOrEqual(LIMITS.MAX_STATIC_REGEX_RULES);
    expect(typeof state.available).toBe('number');
    expect(state.available, 'getAvailableStaticRuleCount').toBeGreaterThanOrEqual(0);
  });

  test('(b) content-script registrations stay within the per-frame budget', async ({ ext, installState }, testInfo) => {
    // tools/build.ts REGISTRATION_BUDGET (review PERF-1/PERF-2): Chromium matches
    // every registered pattern in every frame and keeps them in every renderer.
    const BUDGET = { patterns: 2500, registrations: 30 };
    type Reg = { id: string; matches?: string[]; excludeMatches?: string[]; js?: string[]; css?: string[]; world?: string; allFrames?: boolean };
    const measure = (scripts: unknown[]) => {
      const regs = scripts as Reg[];
      return {
        registrations: regs.length,
        patterns: regs.reduce((n, r) => n + (r.matches?.length ?? 0) + (r.excludeMatches?.length ?? 0), 0),
        ids: regs.map((r) => r.id).sort(),
        perId: Object.fromEntries(regs.map((r) => [r.id, { matches: r.matches?.length ?? 0, excludeMatches: r.excludeMatches?.length ?? 0, js: r.js?.length ?? 0, css: r.css?.length ?? 0 }])),
      };
    };
    const atInstall = measure(installState.snapshot.scripts);
    const live = measure((await ext.api(() => chrome.scripting.getRegisteredContentScripts())) as unknown[]);
    await testInfo.attach('registrations', { body: JSON.stringify({ atInstall, live }, null, 2), contentType: 'application/json' });
    console.log(`[registrations] install: ${atInstall.registrations} registrations, ${atInstall.patterns} patterns (${atInstall.ids.join(', ')})`);
    for (const [label, m] of [['install', atInstall], ['now', live]] as const) {
      expect(m.registrations, `${label}: registrations`).toBeGreaterThan(0);
      expect(m.registrations, `${label}: registrations below ${BUDGET.registrations}`).toBeLessThan(BUDGET.registrations);
      expect(m.patterns, `${label}: matches + excludeMatches below ${BUDGET.patterns}`).toBeLessThan(BUDGET.patterns);
    }
    // One scriptlet registration per world, covering every page.
    for (const id of ['sl-main', 'sl-isolated']) {
      expect.soft(atInstall.ids, `scriptlet registration ${id}`).toContain(id);
      expect.soft(atInstall.perId[id]?.matches, `${id} has a single <all_urls> match`).toBe(1);
    }
  });

  test('(b) every shipped regexFilter is supported by Chromium RE2', async ({ ext, dist }, testInfo) => {
    const regex = dist.regexRules();
    const items = regex.map((lr) => ({
      rulesetId: lr.rulesetId,
      id: lr.rule.id,
      regex: lr.rule.condition.regexFilter!,
      cs: !!lr.rule.condition.isUrlFilterCaseSensitive,
      capturing: !!lr.rule.action.redirect?.regexSubstitution,
    }));
    const sw = await ext.sw();
    const unsupported: { rulesetId: string; id: number; regex: string; reason?: string; filters: string[] }[] = [];
    for (let i = 0; i < items.length; i += 250) {
      const chunk = items.slice(i, i + 250);
      const res = await sw.evaluate(async (list) => {
        const out: { ok: boolean; reason?: string }[] = [];
        for (const it of list) {
          try {
            // isCaseSensitive must mirror the rule (DNR's isUrlFilterCaseSensitive defaults to false).
            const r = await chrome.declarativeNetRequest.isRegexSupported({ regex: it.regex, isCaseSensitive: it.cs, requireCapturing: it.capturing });
            out.push({ ok: r.isSupported, reason: r.reason });
          } catch (e) {
            out.push({ ok: false, reason: String(e) });
          }
        }
        return out;
      }, chunk);
      res.forEach((r, j) => {
        if (!r.ok) unsupported.push({ ...chunk[j], reason: r.reason, filters: dist.sourceOf(chunk[j].rulesetId, chunk[j].id) });
      });
    }
    console.log(`[regex] checked=${items.length} unsupported=${unsupported.length}`);
    await testInfo.attach('regex-report', { body: JSON.stringify({ checked: items.length, unsupported }, null, 2), contentType: 'application/json' });
    expect(unsupported, `${unsupported.length} of ${items.length} regexFilter rules are not RE2-supported`).toEqual([]);
  });

  test('package integrity: rule ids, redirect targets, WAR and transparency maps', async ({ dist }) => {
    const problems: string[] = [];
    const war = new Set<string>();
    for (const w of dist.manifest.web_accessible_resources ?? []) for (const r of w.resources) war.add('/' + r.replace(/^\//, ''));
    for (const res of dist.ruleResources()) {
      if (!dist.has(res.path)) {
        problems.push(`${res.id}: ruleset file ${res.path} missing`);
        continue;
      }
      const rules = dist.rules(res.id);
      const ids = new Set<number>();
      const map = dist.filtersOf(res.id);
      for (const r of rules) {
        if (!Number.isInteger(r.id) || r.id < 1) problems.push(`${res.id}: invalid id ${r.id}`);
        if (ids.has(r.id)) problems.push(`${res.id}: duplicate id ${r.id}`);
        ids.add(r.id);
        const ep = r.action.redirect?.extensionPath;
        if (ep) {
          const file = ep.split('?')[0].split('#')[0];
          if (!dist.has(file)) problems.push(`${res.id}#${r.id}: redirect target ${file} missing from dist`);
          if (!war.has(file) && ![...war].some((w) => w.endsWith('/*') && file.startsWith(w.slice(0, -1)))) {
            problems.push(`${res.id}#${r.id}: redirect target ${file} is not web_accessible`);
          }
        }
        if (Array.isArray(map) && map.length && !(map[r.id] && map[r.id]!.length)) problems.push(`${res.id}#${r.id}: no source filter text in rulesets/filters/${res.id}.json`);
      }
      // ARCHITECTURE §4.1: ids start at 1 and are dense.
      let maxId = 0;
      for (const id of ids) if (id > maxId) maxId = id;
      if (rules.length && maxId !== rules.length) problems.push(`${res.id}: ids are not dense (max id ${maxId}, ${rules.length} rules)`);
      if (problems.length > 50) break;
    }
    expect(problems.slice(0, 50), `${problems.length} integrity problems`).toEqual([]);
  });
});
