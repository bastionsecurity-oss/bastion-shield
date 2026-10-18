// Network filter -> DNR mapping tests (ARCHITECTURE §4.2–§4.4).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { compileList, collectBadfilters } from '../../src/compiler/index.ts';
import type { CompileOptions, DnrRule } from '../../src/compiler/types.ts';
import { opts, ruleProblems, rulesOf } from './helpers.ts';

function compile(text: string, over: Partial<CompileOptions> = {}): DnrRule[] {
  const out = compileList(text, opts(over));
  const rules = rulesOf(out);
  for (const r of rules) assert.deepEqual(ruleProblems(r), [], JSON.stringify(r));
  return rules;
}
function one(text: string, over: Partial<CompileOptions> = {}): DnrRule {
  const rules = compile(text, over);
  assert.equal(rules.length, 1, JSON.stringify(rules));
  return rules[0];
}
function reasons(text: string, over: Partial<CompileOptions> = {}): Record<string, number> {
  const r = compileList(text, opts(over)).stats.reasons;
  return Object.fromEntries(Object.entries(r).filter(([k]) => !k.startsWith('warn:')));
}

describe('patterns', () => {
  test('||host^ becomes requestDomains', () => {
    assert.deepEqual(one('||ads.example.com^'), {
      priority: 10,
      action: { type: 'block' },
      condition: { requestDomains: ['ads.example.com'] },
    });
  });
  test('hostname with options keeps requestDomains', () => {
    const r = one('||ads.example.com^$script,third-party');
    assert.deepEqual(r.condition, { requestDomains: ['ads.example.com'], resourceTypes: ['script'], domainType: 'thirdParty' });
  });
  test('IP address hostnames', () => {
    assert.deepEqual(one('||1.2.3.4^').condition, { requestDomains: ['1.2.3.4'] });
  });
  test('plain and generic patterns map 1:1 onto urlFilter', () => {
    assert.equal(one('/banner/ad.').condition.urlFilter, '/banner/ad.');
    assert.equal(one('||example.com/ads/*.js|').condition.urlFilter, '||example.com/ads/*.js|');
    assert.equal(one('|https://ads.').condition.urlFilter, '|https://ads.');
    assert.equal(one('&ad_type=^').condition.urlFilter, '&ad_type=^');
  });
  test('||host without ^ stays a prefix pattern (uBO parity)', () => {
    assert.deepEqual(one('||example.com').condition, { urlFilter: '||example.com' });
  });
  test('leading and trailing wildcards are dropped', () => {
    assert.equal(one('*/ads/*').condition.urlFilter, '/ads/');
    assert.equal(one('*ad_frame*').condition.urlFilter, 'ad_frame');
  });
  test('||* is rewritten (DNR forbids it)', () => {
    const r = one('||*.cdn-ads.com^');
    assert.equal(r.condition.urlFilter, '.cdn-ads.com^');
  });
  test('upper case is lower-cased, unicode hostnames are punycoded', () => {
    assert.deepEqual(one('||Ads.Example.COM^').condition, { requestDomains: ['ads.example.com'] });
    assert.deepEqual(one('||bücher.de^').condition, { requestDomains: ['xn--bcher-kva.de'] });
    assert.equal(one('||bücher.de/wérbung').condition.urlFilter, '||xn--bcher-kva.de/w%c3%a9rbung');
  });
  test('|http: is normalized to |http://', () => {
    assert.equal(one('|http:$domain=example.com').condition.urlFilter, '|http://');
  });
  test('bare hostnames (hosts style) are hostname filters', () => {
    assert.deepEqual(one('ads.example.com').condition, { requestDomains: ['ads.example.com'] });
  });
  test('hosts-file lines inside ABP lists', () => {
    const rules = compile('0.0.0.0 tracker.example\n127.0.0.1 ads.example\n0.0.0.0 localhost\n');
    assert.deepEqual(rules, [{ priority: 10, action: { type: 'block' }, condition: { requestDomains: ['ads.example', 'tracker.example'] } }]);
  });
  test('inline comments are stripped', () => {
    assert.deepEqual(one('0.0.0.0 ads.example # tracking').condition, { requestDomains: ['ads.example'] });
  });
  test('too short patterns are rejected', () => {
    assert.deepEqual(compile('*\na\n'), []);
  });
  test('$$ HTML filters are rejected', () => {
    assert.deepEqual(reasons('example.com$$script[src*="ads"]'), { 'html-filtering': 1 });
  });
});

describe('regex filters', () => {
  test('RE2-compatible regexes become regexFilter (in regexRules)', () => {
    const out = compileList('/^https?:\\/\\/[a-z]{8}\\.com\\/ads/$script', opts());
    assert.equal(out.rules.length, 0);
    assert.equal(out.regexRules.length, 1);
    assert.equal(out.regexRules[0].rule.condition.regexFilter, '^https?:\\/\\/[a-z]{8}\\.com\\/ads');
    assert.deepEqual(out.regexRules[0].rule.condition.resourceTypes, ['script']);
  });
  test('literal regexes become urlFilter (no regex budget)', () => {
    assert.equal(one('/\\/ads\\/banner\\./').condition.urlFilter, '/ads/banner.');
    assert.equal(one('/^https:\\/\\/ads\\.example\\.com\\//').condition.urlFilter, '|https://ads.example.com/');
  });
  test('lookaround and backreferences are rejected with a reason', () => {
    assert.deepEqual(reasons('/^https:\\/\\/(?!www\\.)[a-z]+\\.com/'), { 'regex-not-re2': 1 });
    assert.deepEqual(reasons('/(ab)\\1/$script'), { 'regex-not-re2': 1 });
  });
  test('$match-case sets isUrlFilterCaseSensitive', () => {
    const out = compileList('/[A-Z]{4}\\.js$/$script,match-case', opts());
    assert.equal(out.regexRules[0].rule.condition.isUrlFilterCaseSensitive, true);
    assert.equal(one('/Ads/Banner.$match-case').condition.isUrlFilterCaseSensitive, true);
    assert.equal(one('/Ads/Banner.$match-case').condition.urlFilter, '/Ads/Banner.');
  });
});

describe('types and party', () => {
  test('every type option maps to a DNR resource type', () => {
    const map: Record<string, string> = {
      script: 'script', image: 'image', stylesheet: 'stylesheet', css: 'stylesheet', xmlhttprequest: 'xmlhttprequest',
      xhr: 'xmlhttprequest', subdocument: 'sub_frame', frame: 'sub_frame', font: 'font', media: 'media',
      object: 'object', 'object-subrequest': 'object', websocket: 'websocket', ping: 'ping', beacon: 'ping',
      other: 'other', document: 'main_frame', doc: 'main_frame',
    };
    for (const [opt, type] of Object.entries(map)) {
      assert.deepEqual(one(`/ads.$${opt}`).condition.resourceTypes, [type], opt);
    }
  });
  test('negated types use excludedResourceTypes and always exclude main_frame', () => {
    assert.deepEqual(one('/ads.$~image,~script').condition, {
      urlFilter: '/ads.',
      excludedResourceTypes: ['image', 'main_frame', 'script'],
    });
  });
  test('positive and negated types combine into resourceTypes only', () => {
    assert.deepEqual(one('/ads.$script,~image').condition.resourceTypes, ['script']);
    assert.deepEqual(reasons('/ads.$image,~image'), { 'duplicate-option': 1 });
  });
  test('$all includes documents', () => {
    const r = one('||evil.example^$all');
    assert.equal(r.condition.resourceTypes?.length, 15);
    assert.ok(r.condition.resourceTypes?.includes('main_frame'));
  });
  test('party options and their aliases', () => {
    assert.equal(one('/ads.$third-party').condition.domainType, 'thirdParty');
    assert.equal(one('/ads.$3p').condition.domainType, 'thirdParty');
    assert.equal(one('/ads.$first-party').condition.domainType, 'firstParty');
    assert.equal(one('/ads.$1p').condition.domainType, 'firstParty');
    assert.equal(one('/ads.$~third-party').condition.domainType, 'firstParty');
    assert.equal(one('/ads.$~1p').condition.domainType, 'thirdParty');
    assert.equal(one('/ads.$1p,3p').condition.domainType, undefined);
  });
  test('$popup alone is unsupported, mixed with other types it is dropped', () => {
    assert.deepEqual(reasons('/ads.$popup'), { 'unsupported-type:popup': 1 });
    assert.deepEqual(one('/ads.$popup,script').condition.resourceTypes, ['script']);
  });
  test('$inline-script / $popunder are unsupported', () => {
    assert.deepEqual(reasons('||x.example^$inline-script'), { 'unsupported-type:inline-script': 1 });
    assert.deepEqual(reasons('*$popunder,domain=x.example'), { 'unsupported-type:popunder': 1 });
  });
});

describe('domain options', () => {
  test('$domain / $from -> initiatorDomains (+ excluded)', () => {
    assert.deepEqual(one('/ads.$domain=a.example|~sub.a.example|b.example').condition, {
      urlFilter: '/ads.',
      initiatorDomains: ['a.example', 'b.example'],
      excludedInitiatorDomains: ['sub.a.example'],
    });
    assert.deepEqual(one('/ads.$from=a.example').condition.initiatorDomains, ['a.example']);
  });
  test('$to -> requestDomains, $denyallow -> excludedRequestDomains', () => {
    assert.deepEqual(one('*$script,to=cdn.example|~ok.cdn.example').condition, {
      requestDomains: ['cdn.example'],
      excludedRequestDomains: ['ok.cdn.example'],
      resourceTypes: ['script'],
    });
    assert.deepEqual(one('*$script,3p,denyallow=x.example|y.example,domain=site.example').condition, {
      initiatorDomains: ['site.example'],
      excludedRequestDomains: ['x.example', 'y.example'],
      domainType: 'thirdParty',
      resourceTypes: ['script'],
    });
  });
  test('$denyallow needs $domain', () => {
    assert.deepEqual(reasons('*$script,denyallow=x.example'), { 'denyallow-without-domain': 1 });
  });
  test('||host^ with $to intersects the domains', () => {
    assert.deepEqual(one('||example.com^$to=a.example.com|other.org').condition.requestDomains, ['a.example.com']);
  });
  test('entities: dropped from includes, rejected when nothing remains', () => {
    assert.deepEqual(one('/ads.$domain=google.*|a.example').condition.initiatorDomains, ['a.example']);
    assert.deepEqual(reasons('/ads.$domain=google.*'), { 'unsupported-domain:entity-or-regex': 1 });
    const r = one('/ads.$domain=~google.*|~b.example');
    assert.deepEqual(r.condition.excludedInitiatorDomains, ['b.example']);
    const out = compileList('/ads.$domain=~google.*', opts());
    assert.equal(out.stats.reasons['warn:excluded-entity-dropped'], 1);
  });
  test('regex domains are treated like entities', () => {
    assert.deepEqual(reasons('/ads.$domain=/^a\\.(com|net)$/'), { 'unsupported-domain:entity-or-regex': 1 });
  });
  test('unicode domains are punycoded, invalid ones reject the filter', () => {
    assert.deepEqual(one('/ads.$domain=bücher.de').condition.initiatorDomains, ['xn--bcher-kva.de']);
    assert.deepEqual(reasons('/ads.$domain=a..b'), { 'invalid-domain': 1 });
    assert.deepEqual(reasons('/ads.$domain=a.example||b.example'), { 'invalid-domain': 1 });
  });
  test('$method', () => {
    assert.deepEqual(one('/api/track$xhr,method=post|put').condition.requestMethods, ['post', 'put']);
    assert.deepEqual(one('/api/track$xhr,method=~get').condition.excludedRequestMethods, ['get']);
  });
});

describe('priorities and actions', () => {
  test('block bands: protected 10, always 21, important 40', () => {
    assert.equal(one('/ads.').priority, 10);
    assert.equal(one('/ads.', { firstPartyProtected: false }).priority, 21);
    assert.equal(one('/ads.$important').priority, 40);
    assert.equal(one('/ads.$important', { firstPartyProtected: false }).priority, 40);
  });
  test('@@ exceptions are allow at 30', () => {
    assert.deepEqual(one('@@||cdn.example^$script'), {
      priority: 30,
      action: { type: 'allow' },
      condition: { requestDomains: ['cdn.example'], resourceTypes: ['script'] },
    });
  });
  test('@@…$document -> allowAllRequests on main_frame and sub_frame', () => {
    assert.deepEqual(one('@@||site.example^$document'), {
      priority: 30,
      action: { type: 'allowAllRequests' },
      condition: { requestDomains: ['site.example'], resourceTypes: ['main_frame', 'sub_frame'] },
    });
  });
  test('$important on an exception is invalid', () => {
    assert.deepEqual(reasons('@@/ads.$important'), { 'invalid-option': 1 });
  });
  test('unknown and duplicate options reject the filter', () => {
    assert.deepEqual(reasons('/ads.$script,sitekey=abc'), { 'unknown-option:sitekey': 1 });
    assert.deepEqual(reasons('/ads.$script,script'), { 'duplicate-option': 1 });
  });
  test('unsupported options are rejected with a reason', () => {
    const list = [
      '/a.$redirect-rule=noop.js', '/a.$replace=/x/y/', '/a.$ipaddress=1.2.3.4', '||a.example^$cname',
      '/a.$script,strict1p', '/a.$script,strict3p', '/a.$header=x-ad', '/a.$requestheader=x:y', '@@||a.example^$genericblock',
      '$webrtc,domain=a.example', '||a.example/x$doc,urlskip=?url', '||a.example/x$doc,uritransform=/a/b/',
      '/a.$script,top=x.example',
    ];
    const r = reasons(list.join('\n'), { trusted: true });
    assert.deepEqual(Object.keys(r).sort(), [
      'unsupported-option:cname', 'unsupported-option:genericblock', 'unsupported-option:header',
      'unsupported-option:ipaddress', 'unsupported-option:redirect-rule', 'unsupported-option:replace',
      'unsupported-option:requestheader', 'unsupported-option:strict1p', 'unsupported-option:strict3p',
      'unsupported-option:top', 'unsupported-option:uritransform', 'unsupported-option:urlskip',
      'unsupported-option:webrtc',
    ]);
  });
});

describe('redirects', () => {
  /** [priority, domainType] of every rule. */
  const bands = (text: string, over: Partial<CompileOptions> = {}): [number | undefined, string | undefined][] =>
    compile(text, over).map((r) => [r.priority, r.condition.domainType]);
  test('$redirect -> extensionPath with redirect band, plus the third-party copy (BS-1)', () => {
    const out = compileList('||ads.example/x.js$script,redirect=noop.js', opts());
    assert.deepEqual(rulesOf(out), [
      {
        priority: 11,
        action: { type: 'redirect', redirect: { extensionPath: '/war/noop.js' } },
        condition: { urlFilter: '||ads.example/x.js', resourceTypes: ['script'] },
      },
      {
        priority: 22,
        action: { type: 'redirect', redirect: { extensionPath: '/war/noop.js' } },
        condition: { urlFilter: '||ads.example/x.js', resourceTypes: ['script'], domainType: 'thirdParty' },
      },
    ]);
    assert.deepEqual(out.rules[1].sources, ['||ads.example/x.js$script,redirect=noop.js']);
    assert.deepEqual(out.usedRedirectResources, ['/war/noop.js']);
    assert.equal(out.stats.network, 1);
  });
  test('priority suffix :N, capped per band', () => {
    assert.deepEqual(bands('/a.js$script,redirect=noop.js:3'), [[14, undefined], [25, 'thirdParty']]);
    assert.deepEqual(bands('/a.js$script,redirect=noop.js:99'), [[18, undefined], [28, 'thirdParty']]);
    assert.equal(one('/a.js$script,redirect=noop.js:99', { firstPartyProtected: false }).priority, 28);
    assert.equal(one('/a.js$script,redirect=noop.js', { firstPartyProtected: false }).priority, 22);
    assert.equal(one('/a.js$script,redirect=noop.js:2,important').priority, 43);
    assert.equal(one('/a.js$script,redirect=noop.js:99,important').priority, 49);
  });
  test('the copy depends on the party: $3p gets one, $1p does not', () => {
    assert.deepEqual(bands('/a.js$script,3p,redirect=noop.js:1'), [[12, 'thirdParty'], [23, 'thirdParty']]);
    assert.deepEqual(bands('/a.js$script,1p,redirect=noop.js'), [[11, 'firstParty']]);
  });
  test('no copy in always-apply lists or for $important', () => {
    assert.deepEqual(bands('/a.js$script,redirect=noop.js', { firstPartyProtected: false }), [[22, undefined]]);
    assert.deepEqual(bands('/a.js$script,redirect=noop.js,important'), [[41, undefined]]);
  });
  test('the copy keeps the domain options of the original', () => {
    const rules = compile('||widgets.outbrain.com/outbrain.js$script,redirect=noop.js:5,domain=~vice.com');
    assert.equal(rules.length, 2);
    assert.deepEqual(rules[1], {
      priority: 27,
      action: { type: 'redirect', redirect: { extensionPath: '/war/noop.js' } },
      condition: {
        urlFilter: '||widgets.outbrain.com/outbrain.js',
        excludedInitiatorDomains: ['vice.com'],
        resourceTypes: ['script'],
        domainType: 'thirdParty',
      },
    });
  });
  test('aliases: $rewrite=abp-resource:, $empty, $mp4', () => {
    const first = (t: string): DnrRule => compile(t)[0];
    assert.equal(first('/v.mp4$media,rewrite=abp-resource:blank-mp4').action.redirect?.extensionPath, '/war/noop-1s.mp4');
    assert.equal(first('/x.txt$xhr,empty').action.redirect?.extensionPath, '/war/empty');
    const mp4 = first('/v.mp4$mp4');
    assert.equal(mp4.action.redirect?.extensionPath, '/war/noop-1s.mp4');
    assert.deepEqual(mp4.condition.resourceTypes, ['media']);
  });
  test('unknown and untrusted resources are rejected', () => {
    assert.deepEqual(reasons('/a.js$script,redirect=nope.js'), { 'unknown-redirect-resource:nope.js': 1 });
    assert.deepEqual(reasons('/a.js$script,redirect=google-ima-dai.js'), { 'untrusted-redirect-resource': 1 });
    assert.equal(compile('/a.js$script,redirect=google-ima-dai.js', { trusted: true })[0].action.type, 'redirect');
  });
  test('redirect to unredirectable types is invalid', () => {
    assert.deepEqual(reasons('/a.$ping,redirect=noop.txt'), { 'invalid-option': 1 });
  });
  test('@@…$redirect is rejected', () => {
    assert.deepEqual(reasons('@@/a.js$script,redirect=noop.js'), { 'unsupported:redirect-exception': 1 });
  });
});

describe('$removeparam', () => {
  test('named parameter: queryTransform + ^name= urlFilter + default types', () => {
    assert.deepEqual(one('$removeparam=utm_source'), {
      priority: 1,
      action: { type: 'redirect', redirect: { transform: { queryTransform: { removeParams: ['utm_source'] } } } },
      condition: { urlFilter: '^utm_source=', resourceTypes: ['image', 'main_frame', 'sub_frame', 'xmlhttprequest'] },
    });
  });
  test('host-anchored pattern gets the parameter appended', () => {
    assert.equal(one('||example.com/path$removeparam=ref').condition.urlFilter, '||example.com/path*^ref=');
    assert.equal(one('||example.com/?ref=$removeparam=ref').condition.urlFilter, '||example.com/?ref=');
  });
  test('no value clears the whole query', () => {
    const r = one('||tracker.example^$removeparam');
    assert.deepEqual(r.action.redirect, { transform: { query: '' } });
  });
  test('regex and negated values are rejected', () => {
    assert.deepEqual(reasons('$removeparam=/^utm_/'), { 'unsupported:removeparam-regex': 1 });
    assert.deepEqual(reasons('$removeparam=~keep'), { 'unsupported:removeparam-negated': 1 });
  });
  test('regex value with an escaped comma is one option value', () => {
    assert.deepEqual(reasons('$removeparam=/^(a\\,b)$/,xhr'), { 'unsupported:removeparam-regex': 1 });
  });
  test('exceptions become allow at priority 1', () => {
    const r = one('@@||example.com^$removeparam=ref');
    assert.equal(r.priority, 1);
    assert.equal(r.action.type, 'allow');
  });
  test('$domain= on the main_frame part maps to requestDomains', () => {
    const rules = compile('$removeparam=fbclid,domain=news.example');
    const mf = rules.find((r) => r.condition.resourceTypes?.includes('main_frame'));
    const rest = rules.find((r) => !r.condition.resourceTypes?.includes('main_frame'));
    assert.deepEqual(mf?.condition.requestDomains, ['news.example']);
    assert.equal(mf?.condition.initiatorDomains, undefined);
    assert.deepEqual(rest?.condition.initiatorDomains, ['news.example']);
  });
});

describe('$csp / $permissions', () => {
  test('$csp appends Content-Security-Policy on documents', () => {
    assert.deepEqual(one('||site.example^$csp=worker-src \'none\''), {
      priority: 1,
      action: { type: 'modifyHeaders', responseHeaders: [{ header: 'content-security-policy', operation: 'append', value: "worker-src 'none'" }] },
      condition: { requestDomains: ['site.example'], resourceTypes: ['main_frame', 'sub_frame'] },
    });
  });
  test('$csp exception is a priority-1 allow', () => {
    const r = one('@@||site.example^$csp');
    assert.deepEqual([r.priority, r.action.type], [1, 'allow']);
  });
  test('report-uri CSP and request types are invalid', () => {
    assert.deepEqual(reasons('||a.example^$csp=report-uri https://x'), { 'invalid-csp': 1 });
    assert.deepEqual(reasons('||a.example^$script,csp=script-src none'), { 'invalid-option': 1 });
  });
  test('$permissions joins | with ", "', () => {
    const r = one('||a.example^$permissions=browsing-topics=()|join-ad-interest-group=()');
    assert.equal(r.action.responseHeaders?.[0].header, 'permissions-policy');
    assert.equal(r.action.responseHeaders?.[0].value, 'browsing-topics=(), join-ad-interest-group=()');
  });
  test('main_frame part of $csp,domain= uses requestDomains', () => {
    const rules = compile('*$csp=worker-src \'none\',domain=site.example');
    const mf = rules.find((r) => r.condition.resourceTypes?.join() === 'main_frame');
    const sf = rules.find((r) => r.condition.resourceTypes?.join() === 'sub_frame');
    assert.deepEqual(mf?.condition.requestDomains, ['site.example']);
    assert.deepEqual(sf?.condition.initiatorDomains, ['site.example']);
  });
});

describe('first-party modifier copies (modifiers1p, BS-2)', () => {
  const m1p = { firstPartyProtected: false, modifiers1p: true };
  const removeFoo = { type: 'redirect', redirect: { transform: { queryTransform: { removeParams: ['foo'] } } } } as const;
  test('$removeparam gets a firstParty copy at 20 without main_frame', () => {
    assert.deepEqual(compile('||site-a.example.com^$removeparam=foo', m1p), [
      {
        priority: 1,
        action: removeFoo,
        condition: { requestDomains: ['site-a.example.com'], urlFilter: '^foo=', resourceTypes: ['image', 'main_frame', 'sub_frame', 'xmlhttprequest'] },
      },
      {
        priority: 20,
        action: removeFoo,
        condition: { requestDomains: ['site-a.example.com'], urlFilter: '^foo=', resourceTypes: ['image', 'sub_frame', 'xmlhttprequest'], domainType: 'firstParty' },
      },
    ]);
  });
  test('$csp / $permissions copies cover sub_frame only', () => {
    const rules = compile("||a.example^$csp=script-src 'none'", m1p);
    assert.deepEqual(rules.map((r) => [r.priority, r.condition.resourceTypes, r.condition.domainType]), [
      [1, ['main_frame', 'sub_frame'], undefined],
      [20, ['sub_frame'], 'firstParty'],
    ]);
    assert.deepEqual(compile('||a.example^$permissions=browsing-topics=()', m1p).map((r) => r.priority), [1, 20]);
  });
  test('$3p modifiers, document-only modifiers, blocks and redirects get no copy', () => {
    assert.deepEqual(compile('||a.example^$3p,removeparam=foo', m1p).map((r) => r.priority), [1]);
    assert.deepEqual(compile('||a.example^$doc,removeparam=foo', m1p).map((r) => r.priority), [1]);
    assert.deepEqual(compile('||a.example^\n/x.js$script,redirect=noop.js', m1p).map((r) => r.priority), [21, 22]);
  });
  test('$1p modifiers: the copy repeats the first-party subresource part above 19', () => {
    const rules = compile('||a.example^$1p,removeparam=foo', m1p);
    assert.deepEqual(rules.map((r) => [r.priority, r.condition.resourceTypes, r.condition.domainType]), [
      [1, ['image', 'sub_frame', 'xmlhttprequest'], 'firstParty'],
      [1, ['main_frame'], undefined],
      [20, ['image', 'sub_frame', 'xmlhttprequest'], 'firstParty'],
    ]);
  });
  test('negated types keep main_frame excluded in the copy', () => {
    const rules = compile('||a.example^$~image,removeparam=foo', m1p);
    assert.deepEqual(rules.map((r) => [r.priority, r.condition.excludedResourceTypes, r.condition.domainType]), [
      [1, ['image', 'main_frame'], undefined],
      [20, ['image', 'main_frame'], 'firstParty'],
    ]);
  });
  test('static lists copy no exceptions; the option is off by default', () => {
    assert.deepEqual(compile('@@||a.example^$removeparam=foo', m1p).map((r) => r.priority), [1]);
    assert.deepEqual(compile('||a.example^$removeparam=foo', { firstPartyProtected: false }).map((r) => r.priority), [1]);
  });
  test('##^responseheader() gets a sub_frame copy', () => {
    const rules = compile('example.com##^responseheader(location)', m1p);
    const shape = rules.map((r) => [r.priority, r.condition.resourceTypes, r.condition.domainType, r.condition.initiatorDomains, r.condition.requestDomains]);
    assert.deepEqual(shape, [
      [1, ['sub_frame'], undefined, ['example.com'], undefined],
      [1, ['main_frame'], undefined, undefined, ['example.com']],
      [20, ['sub_frame'], 'firstParty', ['example.com'], undefined],
    ]);
  });
});

describe('$1p / $3p on documents (BS-5)', () => {
  test('a document is first-party to itself: $doc,1p drops domainType on main_frame', () => {
    assert.deepEqual(one('||a.example/x$doc,1p'), {
      priority: 10,
      action: { type: 'block' },
      condition: { urlFilter: '||a.example/x', resourceTypes: ['main_frame'] },
    });
  });
  test('$3p never matches a document: the main_frame part is dropped', () => {
    const rules = compile('||a.example^$3p,removeparam=p');
    assert.deepEqual(rules.map((r) => [r.condition.resourceTypes, r.condition.domainType]), [
      [['image', 'sub_frame', 'xmlhttprequest'], 'thirdParty'],
    ]);
    assert.deepEqual(compile('||a.example/x$doc,3p'), []);
    const all = one('||a.example^$all,3p');
    assert.ok(!all.condition.resourceTypes?.includes('main_frame'));
    assert.equal(all.condition.domainType, 'thirdParty');
  });
  test('@@$doc,1p: allowAllRequests split into main_frame (no domainType) and sub_frame (firstParty)', () => {
    const rules = compile('@@||a.example/x$doc,1p');
    assert.deepEqual(rules.map((r) => [r.action.type, r.condition.resourceTypes, r.condition.domainType]), [
      ['allowAllRequests', ['sub_frame'], 'firstParty'],
      ['allowAllRequests', ['main_frame'], undefined],
    ]);
  });
  test('strict-block document rules drop domainType too', () => {
    assert.deepEqual(compile('||a.example/x$doc,1p', { strictBlock: true, listId: 'malware' }), [
      {
        priority: 29,
        action: { type: 'redirect', redirect: { extensionPath: '/pages/blocked.html?list=malware' } },
        condition: { urlFilter: '||a.example/x', resourceTypes: ['main_frame'] },
      },
    ]);
  });
  test('$domain= with $1p: requestDomains and no domainType on main_frame, initiator party elsewhere', () => {
    const rules = compile('/x.$doc,image,1p,domain=a.example');
    const shape = rules.map((r) => [r.condition.resourceTypes, r.condition.domainType, r.condition.initiatorDomains, r.condition.requestDomains]);
    assert.deepEqual(shape, [
      [['image'], 'firstParty', ['a.example'], undefined],
      [['main_frame'], undefined, undefined, ['a.example']],
    ]);
  });
});

describe('cosmetic network options', () => {
  test('$generichide / $specifichide / $elemhide fill the host lists', () => {
    const out = compileList('@@||a.example^$generichide\n@@||b.example^$specifichide\n@@||c.example^$elemhide\n@@*$ghide,domain=d.example|e.example', opts());
    assert.deepEqual(out.generichideHosts, ['a.example', 'c.example', 'd.example', 'e.example']);
    assert.deepEqual(out.specifichideHosts, ['b.example', 'c.example']);
    assert.equal(rulesOf(out).length, 0);
  });
  test('entities go to kind-4 flag entries', () => {
    const out = compileList('@@*$ghide,domain=google.*', opts());
    assert.deepEqual(out.specific, [{ kind: 4, hosts: ['google.*'], excludedHosts: [], payload: 'generichide', raw: '@@*$ghide,domain=google.*' }]);
  });
  test('path patterns apply to the whole host (with a warning)', () => {
    const out = compileList('@@||search.example/results?$generichide', opts());
    assert.deepEqual(out.generichideHosts, ['search.example']);
    assert.equal(out.stats.reasons['warn:cosmetic-flag-path-broadened'], 1);
  });
  test('block-side $generichide is meaningless', () => {
    assert.deepEqual(reasons('||a.example^$generichide'), { 'unsupported-option:generichide-block': 1 });
  });
});

describe('strict block (§4.4)', () => {
  const sb = { strictBlock: true, listId: 'malware' };
  test('plain hostname filters also yield a main_frame redirect to the blocked page', () => {
    const rules = compile('||evil.example^\n||bad.example^', sb);
    assert.deepEqual(rules, [
      { priority: 10, action: { type: 'block' }, condition: { requestDomains: ['bad.example', 'evil.example'] } },
      {
        priority: 29,
        action: { type: 'redirect', redirect: { extensionPath: '/pages/blocked.html?list=malware' } },
        condition: { requestDomains: ['bad.example', 'evil.example'], resourceTypes: ['main_frame'] },
      },
    ]);
  });
  test('filters with type, party or domain options do not', () => {
    for (const f of ['||a.example^$script', '||a.example^$3p', '||a.example^$domain=b.example', '@@||a.example^']) {
      assert.ok(compile(f, sb).every((r) => r.priority !== 29), f);
    }
  });
  test('$document filters become strict-block redirects in strict lists', () => {
    const rules = compile('||phish.example/login$document', sb);
    assert.deepEqual(rules, [
      {
        priority: 29,
        action: { type: 'redirect', redirect: { extensionPath: '/pages/blocked.html?list=malware' } },
        condition: { urlFilter: '||phish.example/login', resourceTypes: ['main_frame'] },
      },
    ]);
  });
  test('$document blocks main_frame in lists without strict block', () => {
    assert.deepEqual(one('||phish.example/login$document').condition.resourceTypes, ['main_frame']);
  });
  test('custom blocked page path', () => {
    const r = compile('||evil.example^', { ...sb, blockedPagePath: '/x/blocked.html' }).find((x) => x.priority === 29);
    assert.equal(r?.action.redirect?.extensionPath, '/x/blocked.html?list=malware');
  });
});

describe('$badfilter', () => {
  test('cancels the matching filter across lists', () => {
    const bad = collectBadfilters(['||ads.example^$badfilter\n/track.$script,domain=a.example|b.example,badfilter']);
    const out = compileList('||ads.example^\n||keep.example^\n/track.$script,domain=b.example|a.example', opts({ badfilters: bad }));
    assert.deepEqual(rulesOf(out), [{ priority: 10, action: { type: 'block' }, condition: { requestDomains: ['keep.example'] } }]);
    assert.equal(out.stats.badfiltered, 2);
  });
  test('only the cancelled type bucket is removed', () => {
    const bad = collectBadfilters('||x.example^$script,badfilter');
    assert.deepEqual(one('||x.example^$script,image', { badfilters: bad }).condition.resourceTypes, ['image']);
  });
  test('typeless badfilter does not cancel typed filters', () => {
    const bad = collectBadfilters('||x.example^$badfilter');
    assert.deepEqual(one('||x.example^$script', { badfilters: bad }).condition.resourceTypes, ['script']);
  });
  test('aliases and option order do not matter', () => {
    const bad = collectBadfilters('||x.example^$third-party,xmlhttprequest,badfilter');
    assert.deepEqual(compile('||x.example^$xhr,3p', { badfilters: bad }), []);
  });
  test('just-origin filters can be cancelled per hostname (uBO)', () => {
    const bad = collectBadfilters('*$script,3p,domain=b.example,badfilter');
    assert.deepEqual(one('*$script,3p,domain=a.example|b.example|c.example', { badfilters: bad }).condition.initiatorDomains, ['a.example', 'c.example']);
  });
  test("a list's own badfilters apply when no global set is given", () => {
    assert.deepEqual(compile('||ads.example^\n||ads.example^$badfilter'), []);
  });
});

describe('merging', () => {
  test('domain-only filters merge into one rule; subdomains are pruned', () => {
    const r = one('||a.example^\n||b.example^\n||sub.a.example^\n||c.example^');
    assert.deepEqual(r.condition.requestDomains, ['a.example', 'b.example', 'c.example']);
  });
  test('*$domain= filters merge on initiatorDomains', () => {
    const r = one('*$script,3p,domain=a.example\n*$script,3p,domain=b.example');
    assert.deepEqual(r.condition.initiatorDomains, ['a.example', 'b.example']);
  });
  test('rules identical except resourceTypes merge', () => {
    assert.deepEqual(one('/ads.$script\n/ads.$image').condition.resourceTypes, ['image', 'script']);
  });
  test('a typeless rule absorbs typed twins', () => {
    assert.deepEqual(one('/ads.\n/ads.$script').condition, { urlFilter: '/ads.' });
  });
  test('typed rules with documents are not absorbed by typeless ones', () => {
    assert.equal(compile('/ads.\n/ads.$document').length, 2);
  });
  test('different exclusions do not merge', () => {
    assert.equal(compile('||a.example^$domain=~x.example\n||b.example^$domain=~y.example').length, 2);
  });
  test('sources are kept (max 20) with a count', () => {
    const lines = Array.from({ length: 25 }, (_, i) => `||h${i}.example^`).join('\n');
    const out = compileList(lines, opts());
    assert.equal(out.rules.length, 1);
    assert.equal(out.rules[0].sources.length, 20);
    assert.equal(out.rules[0].sourceCount, 25);
  });
  test('duplicates collapse', () => {
    const out = compileList('/ads.\n/ads.\n/ads.', opts());
    assert.equal(out.rules.length, 1);
    assert.deepEqual(out.rules[0].sources, ['/ads.']);
    assert.equal(out.rules[0].sourceCount, 3);
  });
  test('a rule whose inclusions are all excluded is dropped', () => {
    assert.deepEqual(compile('/ads.$domain=x.a.example|~a.example'), []);
  });
});

describe('hosts format', () => {
  test('format "hosts" parses every host on a line and ignores localhost', () => {
    const out = compileList('# comment\n0.0.0.0 a.example b.example\n127.0.0.1 localhost\n::1 ip6-localhost\nc.example\n', opts({ format: 'hosts' }));
    assert.deepEqual(rulesOf(out), [{ priority: 10, action: { type: 'block' }, condition: { requestDomains: ['a.example', 'b.example', 'c.example'] } }]);
    assert.equal(out.stats.network, 2);
  });
  test('invalid hosts lines are reported', () => {
    const out = compileList('0.0.0.0 bad_host!.example\n', opts({ format: 'hosts' }));
    assert.equal(out.stats.unsupported, 1);
  });
});

describe('stats', () => {
  test('counts', () => {
    const out = compileList('! comment\n||a.example^\n##.ad\nexample.com##+js(set, a, 1)\n/x.$popup\n', opts());
    assert.equal(out.stats.lines, 5);
    assert.equal(out.stats.filters, 4);
    assert.equal(out.stats.network, 1);
    assert.equal(out.stats.cosmetic, 1);
    assert.equal(out.stats.scriptlets, 1);
    assert.equal(out.stats.unsupported, 1);
    assert.deepEqual(out.stats.rejected, [{ filter: '/x.$popup', reason: 'unsupported-type:popup' }]);
  });
  test('maxRejectedSamples caps samples, not counts', () => {
    const out = compileList('/a.$popup\n/b.$popup\n/c.$popup', opts({ maxRejectedSamples: 1 }));
    assert.equal(out.stats.rejected.length, 1);
    assert.equal(out.stats.unsupported, 3);
  });
});

describe('DNR validity guards', () => {
  test('non-ASCII $removeparam values and header values are rejected', () => {
    assert.deepEqual(reasons('$removeparam=épk'), { 'unsupported:removeparam-value': 1 });
    assert.deepEqual(reasons("||a.example^$csp=script-src 'sélf'"), { 'invalid-csp': 1 });
  });
  test('unknown methods only are rejected instead of broadening the filter', () => {
    assert.deepEqual(reasons('/x.$xhr,method=foo'), { 'invalid-method': 1 });
  });
  test('host:port patterns are strict-blocked by urlFilter', () => {
    const rules = compile('||1.2.3.4:8080^', { strictBlock: true, listId: 'm' });
    assert.deepEqual(rules.find((r) => r.priority === 29)?.condition, { urlFilter: '||1.2.3.4:8080^', resourceTypes: ['main_frame'] });
  });
  test('just-origin |http*:// has no urlFilter', () => {
    assert.deepEqual(one('|http*://$image,3p,domain=a.example').condition, { initiatorDomains: ['a.example'], domainType: 'thirdParty', resourceTypes: ['image'] });
  });
  test('a $removeparam value starting with "/" but not a regex is a plain name', () => {
    assert.deepEqual(one('||x.example/c?$script,removeparam=/a/b.js').action.redirect?.transform?.queryTransform?.removeParams, ['/a/b.js']);
  });
});
