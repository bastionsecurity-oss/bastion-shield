// Bastion Shield e2e — (c) network blocking of real list hostnames, kept
// third-party copies of protected-list redirects (stub instead of a hard
// block), and (d) Brave "Standard" first-party semantics vs "Aggressive".
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { PRIORITY } from '../../../src/shared/constants.ts';
import { expect, test } from '../support/fixtures.ts';
import type { ExtensionHarness } from '../support/extension.ts';
import { HOSTS, KNOWN_TRACKERS } from '../support/hosts.ts';
import { describeResults, loadResources } from '../support/pages.ts';
import type { ResSpec } from '../support/pages.ts';
import { pickProtectedPathRules, pickStrictHosts } from '../support/pickers.ts';
import type { PathRulePick } from '../support/pickers.ts';
import type { Dist } from '../support/dist.ts';
import type { FixtureServer } from '../support/server.ts';

async function resetSites(ext: ExtensionHarness): Promise<void> {
  await ext.sendAndApply({ type: 'sites:set', sites: {} }, 3000);
  await ext.sendAndApply({ type: 'settings:set', patch: { defaultMode: 'standard' } }, 3000);
}

test.describe('network blocking', () => {
  test('(c) list hostnames are blocked as third parties, neutral resources load', async ({ page, server, dist }) => {
    const specs: ResSpec[] = [];
    const listed: string[] = [];
    for (const t of KNOWN_TRACKERS) {
      const rules = dist.rulesForHost(t.host).filter((lr) => lr.rule.action.type === 'block' || lr.rule.action.type === 'redirect');
      if (rules.length) listed.push(t.host);
      specs.push({ url: server.url(t.host, t.path), kind: t.kind, label: `tracker ${t.host} (${rules.length} rules)` });
    }
    const strict = pickStrictHosts(dist, ['urlhaus', 'ublock-badware'], 1)[0];
    if (strict) specs.push({ url: server.url(strict.host, '/dl/payload.gif'), kind: 'img', label: `${strict.listId} host ${strict.host}` });
    const controls: ResSpec[] = [
      { url: server.url(HOSTS.CDN, '/lib/framework.js'), kind: 'script', label: 'neutral third party' },
      { url: server.url(HOSTS.CDN, '/css/site.css'), kind: 'css', label: 'neutral third party css' },
      { url: server.url(HOSTS.A, '/static/app.js'), kind: 'script', label: 'first party' },
      { url: server.url(HOSTS.A_SUB, '/img/logo.png'), kind: 'img', label: 'same-site subdomain' },
      { url: server.url(HOSTS.B, '/api/data.json'), kind: 'fetch', label: 'neutral cross-site fetch' },
    ];
    const rs = await loadResources(page, server, HOSTS.A, [...specs, ...controls]);
    const msg = describeResults(rs);
    console.log('[network]\n' + msg);
    expect(listed.length, `at least 3 of ${KNOWN_TRACKERS.map((t) => t.host).join(', ')} appear in the shipped rules`).toBeGreaterThanOrEqual(3);
    for (const r of rs.slice(0, specs.length)) expect.soft(r.blocked, `blocked: ${r.label}\n${msg}`).toBe(true);
    for (const r of rs.slice(specs.length)) expect.soft(r.loaded, `loaded: ${r.label}\n${msg}`).toBe(true);
  });
});

async function validatedProtectedPicks(ext: ExtensionHarness, dist: Dist, server: FixtureServer, want = 2): Promise<PathRulePick[]> {
  const candidates = pickProtectedPathRules(dist, 40);
  const chosen: PathRulePick[] = [];
  for (const p of candidates) {
    // Cross-site request: Standard's first-party allow does not apply, so the
    // candidate's own protected-band rule must be what DNR picks. Anything
    // else (an always-apply block, an exception) would make the test ambiguous.
    const out = await ext.api(
      async (a: { url: string; type: string; initiator: string }) => {
        try {
          return await chrome.declarativeNetRequest.testMatchOutcome({ url: a.url, type: a.type as chrome.declarativeNetRequest.ResourceType, initiator: a.initiator, method: 'get' as chrome.declarativeNetRequest.RequestMethod, tabId: -1 });
        } catch (e) {
          return { error: String(e) };
        }
      },
      { url: server.url(HOSTS.CDN, p.path), type: p.dnrType, initiator: server.origin(HOSTS.A) },
    );
    if ('error' in out) {
      // testMatchOutcome is unpacked-only; without it we trust the static pick.
      chosen.push(p);
    } else {
      const top = out.matchedRules ?? [];
      const isOwn = top.some((m) => m.rulesetId === p.rulesetId && m.ruleId === p.ruleId);
      const onlyProtected = top.length > 0 && top.every((m) => {
        const r = dist.rules(m.rulesetId).find((x) => x.id === m.ruleId);
        return r && r.action.type === 'block' && (r.priority ?? 1) === PRIORITY.BLOCK_PROTECTED;
      });
      if (isOwn && onlyProtected) chosen.push(p);
    }
    if (chosen.length >= want) break;
  }
  return chosen;
}

test.describe('Standard vs Aggressive', () => {
  test.afterEach(async ({ ext }) => {
    await resetSites(ext);
  });

  test('(d) first-party resources matched by protected lists load in Standard and are blocked in Aggressive', async ({ page, server, dist, ext }) => {
    const picks = await validatedProtectedPicks(ext, dist, server, 2);
    expect(picks.length, 'found generic protected-list block filters to build first-party URLs from').toBeGreaterThan(0);
    const specsFor = (p: PathRulePick): ResSpec[] => [
      { url: server.url(HOSTS.A, p.path), kind: p.kind, label: `1p ${p.rulesetId}#${p.ruleId} ${p.sources[0] ?? p.urlFilter}` },
      { url: server.url(HOSTS.A_SUB, p.path), kind: p.kind, label: `same-site ${p.rulesetId}#${p.ruleId}` },
      { url: server.url(HOSTS.CDN, p.path), kind: p.kind, label: `3p ${p.rulesetId}#${p.ruleId}` },
    ];
    const specs = picks.flatMap(specsFor);

    // Standard (fresh-install default)
    const std = await loadResources(page, server, HOSTS.A, specs, { title: 'standard' });
    const stdMsg = describeResults(std);
    console.log('[standard]\n' + stdMsg);
    for (let i = 0; i < std.length; i += 3) {
      expect.soft(std[i].loaded, `Standard: first-party allowed\n${stdMsg}`).toBe(true);
      expect.soft(std[i + 1].loaded, `Standard: same-site subdomain allowed\n${stdMsg}`).toBe(true);
      expect.soft(std[i + 2].blocked, `Standard: third party blocked\n${stdMsg}`).toBe(true);
    }

    // Per-site Aggressive
    const r1 = await ext.sendAndApply<{ error?: string }>({ type: 'site:set', site: HOSTS.A, patch: { mode: 'aggressive' } });
    expect(r1.response?.error, 'site:set response').toBeUndefined();
    expect(r1.applied, 'site:set mode=aggressive changed the dynamic rules').toBe(true);
    const agg = await loadResources(page, server, HOSTS.A, specs, { title: 'aggressive (site)' });
    const aggMsg = describeResults(agg);
    console.log('[aggressive site]\n' + aggMsg);
    for (let i = 0; i < agg.length; i += 3) {
      expect.soft(agg[i].blocked, `Aggressive site: first-party blocked\n${aggMsg}`).toBe(true);
      expect.soft(agg[i + 2].blocked, `Aggressive site: third party blocked\n${aggMsg}`).toBe(true);
    }
    // Other sites stay in Standard.
    const other = await loadResources(page, server, HOSTS.C, picks.map((p) => ({ url: server.url(HOSTS.C, p.path), kind: p.kind, label: `1p on C ${p.rulesetId}#${p.ruleId}` })), { title: 'standard (other site)' });
    for (const r of other) expect.soft(r.loaded, `Standard still applies to other sites\n${describeResults(other)}`).toBe(true);

    // Back to Standard for the site, then global Aggressive default.
    await ext.sendAndApply({ type: 'site:set', site: HOSTS.A, patch: { mode: 'standard' } });
    const r2 = await ext.sendAndApply<{ error?: string }>({ type: 'settings:set', patch: { defaultMode: 'aggressive' } });
    expect(r2.response?.error, 'settings:set response').toBeUndefined();
    const gAgg = await loadResources(page, server, HOSTS.C, picks.map((p) => ({ url: server.url(HOSTS.C, p.path), kind: p.kind, label: `1p on C ${p.rulesetId}#${p.ruleId}` })), { title: 'aggressive (global)' });
    for (const r of gAgg) expect.soft(r.blocked, `Global Aggressive: first-party blocked on any site\n${describeResults(gAgg)}`).toBe(true);
    // ... except the site explicitly set to Standard.
    const siteStd = await loadResources(page, server, HOSTS.A, picks.map((p) => ({ url: server.url(HOSTS.A, p.path), kind: p.kind, label: `1p on A (site=standard)` })), { title: 'standard site under global aggressive' });
    for (const r of siteStd) expect.soft(r.loaded, `Site set to Standard keeps first-party resources under global Aggressive\n${describeResults(siteStd)}`).toBe(true);
  });
});

interface CopyPick {
  rulesetId: string;
  ruleId: number;
  priority: number;
  url: string;
  pageHost: string;
  kind: 'script' | 'img' | 'fetch' | 'css';
  dnrType: string;
  target: string;
}

/** Third-party copies of protected-list redirects that the build kept (PRIORITY.REDIRECT_ALWAYS band, BS-1). */
function pickRedirectCopies(dist: Dist, server: FixtureServer): CopyPick[] {
  const protectedLists = new Set((dist.meta?.lists ?? []).filter((l) => l.firstPartyProtected && l.default).map((l) => l.id));
  const enabled = new Set(dist.expectedDefaultRulesets() ?? dist.manifestEnabledRulesets());
  const kinds: [string, CopyPick['kind']][] = [['script', 'script'], ['image', 'img'], ['stylesheet', 'css'], ['xmlhttprequest', 'fetch']];
  const out: CopyPick[] = [];
  for (const res of dist.ruleResources()) {
    if (!enabled.has(res.id) || res.id.endsWith('.regex')) continue;
    const list = dist.listOfRuleset(res.id);
    if (!list || !protectedLists.has(list.id)) continue;
    for (const rule of dist.rules(res.id)) {
      const p = rule.priority ?? 1;
      const c = rule.condition;
      if (rule.action.type !== 'redirect' || p < PRIORITY.REDIRECT_ALWAYS || p >= PRIORITY.STRICT_BLOCK || c.domainType !== 'thirdParty') continue;
      const uf = c.urlFilter;
      if (!uf || !uf.startsWith('||') || c.requestDomains || c.regexFilter || c.requestMethods || c.tabIds) continue;
      const m = /^\|\|([a-z0-9.-]+)([/^|].*)?$/.exec(uf);
      if (!m) continue;
      const host = m[1];
      let rest = (m[2] ?? '/').replace(/\|$/, '');
      if (/[|]/.test(rest)) continue;
      rest = rest.replace(/\^/g, '/').replace(/\*/g, 'x');
      if (!rest.startsWith('/')) rest = '/' + rest;
      if (rest.endsWith('-')) rest += 'e2e';
      const initiators = (c.initiatorDomains ?? []).filter((d) => /^[a-z0-9.-]+$/.test(d) && !d.startsWith('xn--'));
      if (c.initiatorDomains && initiators.length === 0) continue;
      const pageHost = initiators[0] ?? HOSTS.A;
      if ((c.excludedInitiatorDomains ?? []).some((d) => pageHost === d || pageHost.endsWith('.' + d))) continue;
      const kind = kinds.find(([t]) => (c.resourceTypes ? c.resourceTypes.includes(t) : true) && !(c.excludedResourceTypes ?? []).includes(t));
      if (!kind) continue;
      out.push({ rulesetId: res.id, ruleId: rule.id, priority: p, url: server.url(host, rest), pageHost, kind: kind[1], dnrType: kind[0], target: rule.action.redirect?.extensionPath ?? '' });
    }
  }
  // Generic copies (any initiator) first: they matter on every site.
  return out.sort((a, b) => Number(a.pageHost !== HOSTS.A) - Number(b.pageHost !== HOSTS.A) || Number(a.kind !== 'script') - Number(b.kind !== 'script'));
}

test.describe('protected-list redirects vs always-apply blocks (BS-1)', () => {
  test('(c) a kept third-party redirect copy serves the stub instead of a hard block', async ({ page, server, dist, ext }) => {
    const candidates = pickRedirectCopies(dist, server);
    test.skip(candidates.length === 0, 'the build kept no simple third-party redirect copy');
    const confirmed: CopyPick[] = [];
    for (const c of candidates) {
      const out = await ext.api(
        async (a: { url: string; type: string; initiator: string }) => {
          try {
            return await chrome.declarativeNetRequest.testMatchOutcome({ url: a.url, type: a.type as chrome.declarativeNetRequest.ResourceType, initiator: a.initiator, method: 'get' as chrome.declarativeNetRequest.RequestMethod, tabId: -1 });
          } catch (e) {
            return { error: String(e) };
          }
        },
        { url: c.url, type: c.dnrType, initiator: server.origin(c.pageHost) },
      );
      if ('error' in out) {
        confirmed.push(c); // testMatchOutcome is unpacked-only; trust the static pick
      } else if ((out.matchedRules ?? []).some((m) => m.rulesetId === c.rulesetId && m.ruleId === c.ruleId)) {
        confirmed.push(c);
      }
      if (confirmed.length >= 3) break;
    }
    expect(confirmed.length, `testMatchOutcome picks a kept copy (candidates: ${candidates.map((c) => `${c.rulesetId}#${c.ruleId}`).join(', ')})`).toBeGreaterThan(0);
    for (const c of confirmed) {
      const [r] = await loadResources(page, server, c.pageHost, [{ url: c.url, kind: c.kind, label: `${c.rulesetId}#${c.ruleId} -> ${c.target}` }], { title: 'redirect copy' });
      console.log(`[BS-1] on ${c.pageHost}: ${describeResults([r])}`);
      expect.soft(r.serverHit, `${r.label}: never reaches the server`).toBe(false);
      expect.soft(r.failure, `${r.label}: not hard-blocked`).not.toBe('net::ERR_BLOCKED_BY_CLIENT');
      const to = r.redirectedTo ?? '';
      expect.soft(to.startsWith('chrome-extension://') && to.includes(c.target.split('?')[0]), `${r.label}: redirected to the surrogate (got ${to || 'no redirect'})`).toBe(true);
    }
  });
});
