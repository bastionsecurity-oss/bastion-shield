# Bastion Shield — Architecture

Bastion Shield is a Manifest V3 content blocker for Chromium browsers: Chrome, Microsoft Edge and Brave. It aims to block as well as Brave Shields' default ("Standard") mode, stay lean at runtime, and remain fully transparent. This document is the contract between the build tools, the filter compiler, the service worker, the content scripts and the UI. Types live in `src/shared/types.ts` and `src/compiler/types.ts`, and constants in `src/shared/constants.ts`. When this document and the code disagree, fix one of them; never silently diverge.

## 1. Principles

1. **The browser does the heavy lifting.** Network blocking is declarative (DNR static rulesets compiled at build time), so no JavaScript runs per request. Content scripts are registered with the browser, and the service worker (SW) sleeps when nothing happens.
2. **Small, bounded work per frame.** Chrome checks every registered content-script URL pattern in every frame, so Bastion registers few scripts with few patterns (§3, §6). Scriptlets look the current hostname up in sorted tables inside the injected script. Site-specific cosmetic data is sharded and looked up by the SW per frame. Generic cosmetic filtering costs one message per batch of new class/id tokens.
3. **Brave-equivalent defaults.** Bastion ships the same list stack as Brave Shields (uBO filters, EasyList, EasyPrivacy, Brave lists, URLhaus, cookie notices, app promos, plus regional lists) and Brave's "Standard" first-party semantics.
4. **Transparent.** Every DNR rule maps back to the filter text it came from (`dist/rulesets/filters/*.json`). The UI shows which list blocked what. Nothing leaves the device: no telemetry, no remote config, and all history stays local.
5. **Fire and forget.** Users and admins configure nothing. Admins can configure everything through `chrome.storage.managed` (Intune), including a fleet-wide emergency switch (§10.5). Filter data refreshes through automated extension releases.
6. **Least trust for page-facing code.** Filters that can run code on pages are accepted only from trusted sources (§11.2). Messages are accepted only from the contexts that need them (§7). Hot paths never throw: every step catches its own failures and falls back to the original behaviour.

## 2. Repository layout

```
filters/catalog.json        list catalog (CatalogList[]), source of truth for lists
filters/bastion.txt         Bastion's own community list
filters/lock.json           written by the build: sha256/version/size of every fetched source
src/shared/                 constants.ts, types.ts, hash/hostname helpers
src/compiler/               filter compiler (pure TS, no Node/DOM APIs) — build time + runtime
src/background/             service worker (ESM, bundled to dist/background.js)
src/content/                isolated-world content scripts (cosmetic.ts, procedural.ts)
src/main/                   MAIN-world privacy script (GPC + fingerprint farbling)
src/ui/                     popup, dashboard, shared design tokens/fonts
src/pages/                  blocked.html (strict-block interstitial), bounce.html (debounce)
src/_locales/{en,de,fr,it}  chrome.i18n messages (default_locale en; de is the primary copy)
tools/                      build pipeline (Node >= 22.18, TypeScript run natively)
vendor/                     pinned third-party sources (uBO scriptlets/resources, Brave resources/lists)
policy/                     managed_schema.json + Intune/registry/plist examples
test/                       unit tests (node:test), e2e (Playwright + Chromium), benchmark
docs/                       this file, FILTER-LISTS.md, DEPLOYMENT-INTUNE.md, PRIVACY.md, ...
.cache/                     (not committed) fetched lists, regex-unsupported.json, build counter
```

## 3. Platform limits we design against (Chrome/Edge 155)

- **Static rules:**
  - 30,000 guaranteed per extension. Rules beyond that come from a 300,000 per-profile pool shared by all extensions.
  - At most 100 rulesets declared and 50 enabled.
  - At most 1,000 regex rules across all enabled static rulesets. A ruleset that would push the total over the limit is **silently skipped**.
  - At load, rulesets are added greedily in manifest order.
- **Dynamic rules:** 30,000 "safe" (block/allow/allowAllRequests/upgradeScheme), of which at most 5,000 may be "unsafe" (redirect/modifyHeaders). Dynamic and session regex rules **share** one budget of 1,000.
- **Session rules:** 5,000.
- Redirect and modifyHeaders rules need host permission. We request `<all_urls>`.
- **Validation.** Unpacked extensions treat semantically invalid static rules as **hard load errors**; packed ones skip them, so CI loads the unpacked build as a strict validator. Regexes over RE2's program-size limit (`memoryLimitExceeded`) are skipped silently in both cases and can only be detected in a browser (`isRegexSupported`), hence the validate pass (§11.4).
- **Extension update.** The enabled-ruleset set is **reset to the manifest defaults**, and dynamically registered content scripts are **dropped**, despite `persistAcrossSessions`. Dynamic and session rules survive. The SW re-applies everything (§10.6).
- **Content scripts.** Chrome matches every registered pattern (`matches` and `excludeMatches`) in every frame, at `document_start` and again after DOMContentLoaded, and keeps the parsed set in every renderer. Any `updateContentScripts` re-sends the whole set to every renderer. Pattern count therefore costs page-load time and memory in every tab (§6).
- **`webRequest`** (non-blocking) still fires for DNR-handled requests:
  - a DNR block produces `onErrorOccurred` with `net::ERR_BLOCKED_BY_CLIENT`;
  - a DNR redirect produces `onBeforeRedirect`.

  This is the live log source.
- **`getMatchedRules`** is available with `declarativeNetRequestFeedback`. It returns rule ids only, with a quota of 20 calls per 10 minutes unless there is a user gesture. When a tab navigates, the matches of the old document are re-tagged to `tabId: -1` (kept for about 5 minutes).
- **Action count.** `displayActionCountAsBadgeText` counts every matched non-allow action, including `modifyHeaders` (our GPC rule), so the browser counter is wrong while GPC is on (§8.5).
- **`use_dynamic_url`** only protects web-accessible resources against direct probing. DNR `redirect.extensionPath` targets resolve to the **static** extension id, and the response URL of a redirected `fetch`/`XMLHttpRequest` exposes it (§12).
- `topDomains` / `excludedTopDomains` need Chrome 145+; the SW checks `RuleConditionKeys` before using them.
- **Brave:** Shields blocks before extensions see a request. On Brave, our counters are therefore lower and our per-site "off" cannot unblock what Shields blocks. Documented, not worked around.

## 4. Network filtering (DNR)

### 4.1 Rulesets

- Each catalog list becomes static ruleset `<listId>`, with plain rules in `dist/rulesets/net/<listId>.json`.
- If the list has regexFilter rules, they go into a companion ruleset `<listId>.regex` (`dist/rulesets/net/<listId>.regex.json`). If the regex budget is exceeded, only the companion is skipped, never the main list.
- Built-in ruleset `bastion-params` holds Brave's query-filter parameter stripping (`vendor/brave-lists/query-filter.json`):
  - one rule per parameter, `redirect.transform.queryTransform.removeParams`, `urlFilter: "^<param>="`, `resourceTypes: ["main_frame","sub_frame"]`, `domainType: "thirdParty"`, `requestMethods: ["get"]` (Brave strips only on GET), `excludedRequestDomains: ["urldefense.com"]` (Brave's exempt host), priority `PARAMS`;
  - site-scoped parameters use `requestDomains`;
  - brave-core's hard-coded conditional parameters (`ck_subscriber_id`, `h_sid`, `h_slt`, `mkt_tok`) are kept on their pages by `urlFilter` allow rules at priority 1.
- Rule ids inside a static ruleset start at 1 and are dense. `dist/rulesets/filters/<rulesetId>.json[id]` holds the original filter text(s).
- Manifest `rule_resources` order:
  1. `bastion`
  2. security lists (`ublock-badware`, `urlhaus`)
  3. `ublock`, `easylist`, `easyprivacy`, `ublock-privacy`, `brave`, `brave-firstparty`, `peter-lowe`, `url-tracking`
  4. regional lists
  5. annoyances (`cookies`, `app-promos`, `annoyances`, `social`)
  6. `bastion-params`
  7. all `.regex` companions last

  Each ruleset's `enabled` flag mirrors the catalog default.
- The Edge package moves the rule files to the package root (§11.5). Runtime code therefore never fetches `rulesets/net/*.json`; it reads `rulesets/meta.json` and `rulesets/filters/*.json` only.

### 4.2 Priority bands (`PRIORITY` in constants.ts)

| Band | Priority | Emitted for |
|---|---|---|
| MODIFIER / PARAMS | 1 | `$removeparam`, `$csp`, `$permissions`, `##^responseheader()`; `@@` exceptions of those (as `allow` at 1, so they only cancel modifiers); Brave parameter stripping and its conditional-parameter allows |
| BLOCK_PROTECTED | 10 | block filters of lists with `firstPartyProtected: true` |
| REDIRECT_PROTECTED | 11–18 | `$redirect=res[:N]` in protected lists (11 + min(7, N)) |
| STANDARD_1P_ALLOW | 19 | dynamic `allow` with `domainType: firstParty` (Standard mode, §4.3) |
| MODIFIER_1P | 20 | first-party copy of modifiers from always-apply lists and custom filters (§4.3); for custom filters also the copy of their `@@` modifier exceptions (`allow` at 20) |
| BLOCK_ALWAYS | 21 | block filters of lists with `firstPartyProtected: false`, and custom filters |
| REDIRECT_ALWAYS | 22–28 | `$redirect` in always-apply lists (22 + min(6, N)); the third-party copy of protected-list redirects |
| STRICT_BLOCK | 29 | `main_frame` redirect to `/pages/blocked.html?list=<id>` (§4.5) |
| ALLOW | 30 | `@@` exceptions (`allow`); `@@…$document` → `allowAllRequests` on main_frame+sub_frame |
| DEBOUNCE | 35 | dynamic `regexSubstitution` redirects to `pages/bounce.html` (§4.6) |
| IMPORTANT | 40 | `$important` block |
| IMPORTANT_REDIRECT | 41–49 | `$important` + `$redirect` (41 + min(8, N)) |
| SITE_USER_BLOCK | 50 | reserved (per-site user blocks) |
| PROCEED_ANYWAY | 900 | session `allow` after "proceed anyway" (§4.5) |
| SITE_DISABLED | 1000 | dynamic `allowAllRequests` (main_frame) for sites with protection off, its session `allow` for `tabIds:[-1]`, and the global allow of the emergency switch (§10.5) |
| GPC_HEADER | 5000 | dynamic `modifyHeaders` set `Sec-GPC: 1` (applies everywhere) |

Equal-priority tie-break (Chromium): allow > allowAllRequests > block > upgradeScheme > redirect > modifyHeaders. A `modifyHeaders` rule, and a redirect that only transforms the URL, applies only when its priority is higher than the highest-priority matching allow or allowAllRequests rule.

What follows from the bands:

- **Protected-list redirects.** uBO and Brave serve a redirect stub whatever filter blocked the request. A protected-list redirect at 11–18 would lose to an always-apply block at 21, so the compiler also emits a copy with `domainType: thirdParty` at 22 + min(6, N) (not for `$1p` filters; a `$3p` filter keeps its base rule too, so the copy is always a higher-priority duplicate the build may drop). The Standard 1p allow (19) never matches a third-party request, so Standard semantics are unchanged, and `@@` (30) still wins. To save static-rule budget the build keeps only copies that an always-apply block can actually meet (`restrictRedirectCopies` in `src/compiler/copies.ts`, a conservative overlap test). A tie between a copy and an always-apply redirect is harmless: both serve stubs.
- **`$important`.** An `$important` block (40) still beats a non-important redirect, as in uBO Lite.
- **Debounce** (35) beats list exceptions (30) and strict blocks (29): a known bounce tracker is skipped entirely, as Brave debounces before its ad-block engine. It stays below `$important`.
- **GPC** (5000) is above every allow, including protection off (1000). Only the emergency switch removes it.

### 4.3 Standard vs Aggressive (Brave semantics)

- **Standard (default).** Block and redirect rules from first-party-protected lists do not apply to same-site requests. Implemented as dynamic rules (ids 8,000,010–8,000,019, one per nesting group of sites):

  `{priority: 19, action: allow, condition: {domainType: "firstParty", excludedResourceTypes: ["main_frame"]}}`

  plus `excludedInitiatorDomains` (and `excludedTopDomains` when `RuleConditionKeys` reports support) listing the sites set to Aggressive. Deeper per-site overrides get their own group with `initiatorDomains` and `excluded…Domains` for the next level.
- **Aggressive** as the global default: the same rule with `initiatorDomains` listing the sites set to Standard. It is omitted when that list is empty.
- **Policy `aggressiveSites`** covers subdomains: a user mode on a subdomain of such a site is ignored, and the popup's mode control is locked there (`PopupState.locks.mode`).
- **Always-apply lists** (Brave's "additional engine": first-party lists, cookie notices, app promos, Bastion list, security lists, custom filters): their blocks and redirects (≥ 21) are not affected by the allow at 19. Their **modifiers** sit at 1 and would be masked on same-site subresources, so the compiler adds a first-party copy (`domainType: firstParty`, main_frame removed) at MODIFIER_1P = 20 when `CompileOptions.modifiers1p` is set: for every always-apply list except `url-tracking` (2,100+ modifier rules, which would double; its modifiers apply to same-site subresources only in Aggressive), and always for custom filters. For custom filters, `@@` modifier exceptions get the same copy, so a user's own `@@…$removeparam` cancels the user's copy. Documents are never masked (the allow excludes main_frame).
- `$important` (40) always applies, which is uBO-like and slightly stricter than Brave.
- Cosmetic filtering is the same in both modes and applies uBO-style (generic and specific). Lists are maintained against uBO behaviour, so this is the better-tested choice.

### 4.4 Filter → DNR mapping (compiler contract)

- **Patterns.**
  - ABP patterns map 1:1 onto `urlFilter` (`||`, `|`, `^`, `*`). Patterns are lower-cased.
  - A leading or trailing `*` is dropped. `||*` is invalid in DNR, so it is rewritten.
  - Non-ASCII hostnames are converted to punycode; other non-ASCII characters are percent-encoded.
  - A `/regex/` that is really a literal becomes a `urlFilter`. Other regexes become `regexFilter` **only if** RE2-compatible and ASCII: lookaround, backreferences, atomic/possessive forms and repeats over 1,000 are rejected; `\uXXXX`, `\0`, `[^]` and `(?<name>` are translated. Chromium's RE2 memory limit is enforced by the validate pass (§11.4).
  - uBO's hosts-file and bare-hostname forms are understood, as is line continuation. `||host` without `^` is always the prefix pattern (uBO's LF reading).
- **Domain options.**
  - `$domain=` / `$from=` → `initiatorDomains` / `excludedInitiatorDomains`.
  - `$to=` / `$denyallow=` → `requestDomains` / `excludedRequestDomains`.
  - Entity values (`google.*`) and regex domains are dropped from included lists. If no domains remain, the filter is rejected (otherwise the rule would be broadened). Excluded entity values are also dropped and recorded as a warning.
- **Documents (main_frame).** uBO evaluates a document in its own context, so every rule that can match main_frame is split (`splitMainFrame`):
  - for the main_frame part, `$domain=` becomes `requestDomains` (intersected with the pattern host); the other types keep `initiatorDomains`;
  - `$1p` drops `domainType` on the main_frame part (a document is first-party to itself), and `$3p` drops the main_frame part entirely; the other types keep `domainType`.

  This applies to blocks, strict-block rules, allows and allowAllRequests, `$csp`, `$permissions`, `$removeparam` and `##^responseheader()`.
- **Party and type options.**
  - `$third-party` / `$3p` → `domainType: thirdParty`; `$first-party` / `$1p` → `firstParty`.
  - Types: `script image stylesheet|css xmlhttprequest|xhr subdocument|frame font media object websocket ping other` and `document|doc` (→ main_frame). `$all` maps to all 15 DNR types.
  - Negated types → `excludedResourceTypes`.
  - Without any type, DNR matches everything except `main_frame`. A rule listing every type except documents becomes typeless.
  - **Beware:** if only `excludedResourceTypes` is set, DNR *does* match main_frame. The compiler adds `main_frame` to `excludedResourceTypes` unless the filter is meant to block documents.
- **Other options.**
  - `$method=` → `requestMethods`. `$match-case` → `isUrlFilterCaseSensitive: true` (the DNR default is false). `$important` → IMPORTANT band.
  - `$badfilter` is cancelled globally, across all lists (`collectBadfilters` pre-pass), by a normalized identity per type bucket, so `||x^$script,badfilter` cancels only the script part of `||x^$script,css`. Filters with only a `$domain` list are cancelled per hostname, as in uBO.
  - `$redirect=` / `$rewrite=abp-resource:` / `$empty` / `$mp4` → `redirect.extensionPath: "/war/<file>"`. The resource must exist in `vendor/ublock/web_accessible_resources` or `vendor/brave-resources` (Brave resources are redirect targets too, with `.js`-less aliases). A resource that `requiresTrust` needs a trusted source (§11.2).
  - `$removeparam=name` → `redirect.transform.queryTransform.removeParams:[name]` plus `urlFilter` containing `^name=` when the pattern is generic. `$removeparam` with no value → `transform.query: ""`. Regex `$removeparam` is rejected. Default types: main_frame, sub_frame, xmlhttprequest, image.
  - `$csp=` → `modifyHeaders` append `Content-Security-Policy` on main_frame/sub_frame. `$permissions=` → append `Permissions-Policy`.
  - `##^responseheader(name)` → `modifyHeaders` remove, priority 1, for `location`, `refresh`, `report-to` and `set-cookie` only.
  - `$generichide` / `$ghide`, `$specifichide` / `$shide`, `$elemhide` / `$ehide` on `@@` filters → cosmetic flags for the hosts in the pattern (`CompiledList.generichideHosts` …). They produce no DNR rule.
  - Unsupported (rejected with reason): `$popup`, `$popunder`, `$redirect-rule`, `$replace`, `$ipaddress`, `$cname`, `$strict1p`/`$strict3p`, `$header=`, `$requestheader`, `$genericblock`, `$webrtc`, `$inline-script`, `$inline-font`, `$urlskip`, `$uritransform`, `$urltransform`, `$top=` (needs Chrome 145; minimum is 128), `@@…$redirect`. A filter whose first option is unknown is rejected (uBO would treat it as pattern text).
- **Preprocessor.** `!#if` uses uBO's token semantics: unknown tokens keep the block, unknown `cap_*` tokens are false, `&&` and `||` evaluate left to right. `DEFAULT_ENV` = `ext_ublock`, `ext_ubol`, `env_chromium`, `env_mv3`, `adguard_ext_chromium`, `adguard_ext_chromium_mv3`, `adguard_ext_opera`. Discarded lines become empty, so line numbers stay stable. `!#trusted off|on <secret>` marker lines survive discarded blocks (§11.2).
- **Hosts files.** `0.0.0.0 host` / `127.0.0.1 host` / bare `host` lines → `||host^`.
- **Merging.**
  - Rules are merged only when they are identical except for one array, so a merged rule matches exactly the union of its inputs. Multi-type rules are split first so domain lists merge per type.
  - Plain `||hostname^` filters with identical remaining conditions become one rule with `requestDomains`. Domains already covered by a listed parent, or by an exclusion, are pruned; a rule that can no longer match is dropped.
  - Each merged rule keeps up to 20 source filters plus a count.
- **Strict block.** For lists with `strictBlock: true`, every plain-hostname block filter without type, party or domain options also yields a main_frame rule:
  - `redirect` to `extensionPath: "/pages/blocked.html?list=" + encodeURIComponent(listId)` at STRICT_BLOCK priority;
  - merged per list into one rule with `requestDomains`; host-only patterns such as `||1.2.3.4:8080^` keep their `urlFilter`; `$document` filters of strict lists become strict-block redirects too.

  An `@@…$document` exception (ALLOW 30) wins.
- **Robustness.** Each line is processed in its own try/catch; a failure is reported as `internal-error` and never aborts the list. Every emitted rule passes a validator that mirrors Chromium's load-time checks (`tools/lib/dnr.ts` at build time).

### 4.5 Strict-block page

- `pages/blocked.html` (web_accessible: `matches: ["<all_urls>"]`, `use_dynamic_url: true`).
- The SW records `tabId → originalUrl` from the main-frame `webRequest.onBeforeRedirect` listener (always registered) whenever `redirectUrl` points at `/pages/blocked.html` of our extension. The records live in memory and in `storage.session` under the single key `blocked:records` (one object keyed by tab id). A record is forgotten on the next top-frame commit that is not the blocked page, after a proceed, and when the tab closes.
- The page asks `blocked:info`. Both `blocked:*` messages are accepted **only** from the top frame (`frameId 0`) of `pages/blocked.html` in a tab, on the static or the dynamic extension origin (§7). The page hides its actions when it is framed or when no URL is known.
- "Back" → `history.back()` (a new-tab page when there is no history). "Proceed anyway" → `blocked:proceed {url}` after an inline confirmation. The SW requires a record for that tab whose host equals the URL's host, then adds a session rule

  `{priority: 900, action: allow, condition: {requestDomains: [host], tabIds: [tabId], resourceTypes: <every type, including main_frame>}}`

  (ids 9,100,000–9,199,999) and navigates the tab. Only requests **to** that host are unblocked in that tab; other ads and trackers on the page stay filtered. Proceed rules are removed when their tab closes and are kept across SW restarts, except on a fresh install.

### 4.6 Dynamic and session rules (runtime)

| Rule | Kind | Id |
|---|---|---|
| Sites with protection off | dynamic `allowAllRequests`, `resourceTypes:["main_frame"]`, `requestDomains:[...]` (+ `excludedRequestDomains` for re-enabled subdomains), one rule per nesting level | 8,000,000–8,000,009 |
| Same sites, requests without a tab | session `allow`, `tabIds:[-1]`, `initiatorDomains:[...]` (+ exclusions), one per level | 9,000,000–9,000,009 |
| Standard 1p allow | dynamic, one per group (§4.3) | 8,000,010–8,000,019 |
| GPC | dynamic `modifyHeaders` `Sec-GPC: 1`, every resource type the browser reports, when `privacy.gpc` | 8,000,020 |
| Custom filters (user) | dynamic | 1..999,999 |
| Custom filters (admin policy) | dynamic | 1,000,000..1,999,999 |
| Debounce | dynamic `redirect.regexSubstitution` → `chrome-extension://<id>/pages/bounce.html[?from=<host>]#<target>`, priority 35, from `data/debounce.json` | 2,000,000..2,000,999 |
| Proceed anyway | session `allow` (§4.5) | 9,100,000..9,199,999 |
| Emergency switch (§10.5) | replaces every rule above: dynamic `allowAllRequests` with only `resourceTypes:["main_frame"]` (every site) and a session `allow` for `tabIds:[-1]` | 8,000,000 and 9,000,000 |

- **Protection off is keyed to the top-level site**, as in uBO, uBO Lite and Brave: `allowAllRequests` on the top document covers its whole frame tree, including the disabled site's own iframes. The same site embedded as an iframe in another site stays filtered. Content scripts are excluded per frame (`excludeMatches` with `allFrames`), so cosmetic filtering, scriptlets and the privacy script are still skipped inside such embeds; the content script itself decides `off` by the tab's URL.
- **Debounce conversion** (`src/background/debounce.ts`, Brave's `debounce.json`, MPL-2.0, packaged as `data/debounce.json`):
  - `redirect`: the target is a query parameter; only values that start with an http(s) scheme (raw or percent-encoded) are captured. With `prepend_scheme`, scheme-less values are captured and the scheme is added (fragment `#https://<value>`).
  - `base64,redirect`: base64 values that encode `http…`, as fragment `#b64:<value>`.
  - `regex-path` / `regex-path-template`: Brave's path regex, rewritten so it cannot run into the query, captures concatenated or put into the template.
  - Skipped with a reason: non-empty `exclude` lists (RE2 has no negative lookahead), unknown prefs, closed query patterns. The de-AMP rules (pref `brave.de_amp.enabled`) follow `privacy.deAmp`.
  - When the include pattern names a fixed host, the redirect carries `?from=<host>`, and `bounce.html` refuses targets on the tracker's own registrable domain (Brave only debounces cross-site). The page decodes the fragment (repeated percent-decoding, or base64/base64url after `b64:`), requires an http(s) URL with a hostname and without credentials, and calls `location.replace`.
- **Validation and budgets.** Every regex rule is checked with `isRegexSupported` first; then the budgets are enforced (30,000 total, 5,000 unsafe, 1,000 regex shared with session rules). If Chrome rejects the update, the offending rule id is parsed from the error and dropped, then sources are dropped in the order user filters, debounce, admin filters. Bastion's system rules always stay. IPv6 site keys cannot appear in DNR domain conditions and are left out of the DNR rules (content-script exclusion still covers them).
- `updateDynamicRules` is atomic, so removals and additions are always batched in a single, diffed call.

## 5. Cosmetic filtering

### 5.1 Data produced by the build

- `dist/cosmetic/specific/NNN.json` (`CosmeticShard`):
  - A hostKey goes to shard `fnv1a32(hostKey) % 256` (`shardOf` in `src/shared/hash.ts`).
  - Entries are `[kind, payload, listMask]`, where `listMask` has bit `BuiltList.bit` set for every list that contains the entry. Kinds are listed at `CosmeticHostEntry` in types.ts.
  - hostKeys are hostnames (`example.com`) or entities (`google.*`).
  - `~host` on a hide filter becomes a kind-1 entry at the excluded host; on a `:style()` filter, a kind-1 entry whose payload is the kind-3 rule text; on a procedural filter, a kind-5 entry whose payload is `ProceduralFilter.raw`.
  - List-level `generichideHosts` and `specifichideHosts` are written as kind-4 flag entries (`generichide` / `specifichide`) with the list's mask, so the SW gets them through the normal shard lookup.
- `dist/cosmetic/generic.json` (`GenericIndex`): lowly-generic selectors keyed by their first `#id` / `.class` token.
  - A selector is keyed only if it *requires* that token: the token appears in the selector's subject compound or a leading compound, outside `:not()`, `:is()` and `:has()`.
  - Keys are **unescaped** identifiers (selector `.a\:b` → key `.a:b`), because the content script sends raw tokens.
  - Selectors excepted by `#@#sel` without a hostname are removed at build time.
- `dist/cosmetic/generic-high/<listId>.css`: highly generic selectors, grouped 1,000 selectors per rule, each group closed by `{display:none!important}`.
- `dist/cosmetic/meta.json` (`CosmeticMeta`): per-list CSS file, the hosts where that CSS must not be injected statically (`genericHighExcludedHosts`, plain hostnames only, because one invalid `excludeMatches` pattern fails the whole registration), and the selector file for the filtered copy. Paths are package-relative.
- `dist/cosmetic/generic-high.json`: listId → highly generic selectors (used for the filtered copy).

### 5.2 Runtime

1. **`content/cosmetic.js`** is registered by the SW as `bs-cosmetic`: ISOLATED world, `document_start`, `allFrames`, `matchOriginAsFallback`, `<all_urls>`, `excludeMatches` = sites with protection off.

   It sends `cosmetic:frame` once:
   - `url`: `location.href` for http(s) frames; for about:blank, srcdoc, blob: and data: frames their real origin when there is one, otherwise `ancestorOrigins[0]`, plus `/`. The SW uses `msg.url`, not `sender.url` (which is `about:blank` there).
   - `topUrl`: the top page as the frame sees it (`ancestorOrigins[last]`, origin only, in subframes).
   - On a rejected send or an `undefined` reply the script retries once after 120 ms; an `{error}` reply is final. The SW always answers with an object.
2. **The SW**:
   1. decides `off` from the tab's URL (protection off for the top-level site);
   2. computes candidate hostKeys for the frame hostname: the hostname, each parent down to two labels, and entity forms `label.*` obtained by stripping the last 1 or 2 labels from each candidate;
   3. loads the needed shards (fetch from the package, LRU of 64 shards, plus a per-host result cache);
   4. merges entries of enabled lists (`mask & enabledMask`) and the custom cosmetic filters;
   5. applies exceptions: kind 1 removes kind 0 with the same selector (including generic ones) and kind 3 with an identical payload; kind 5 removes kind 2 whose `raw` equals the payload;
   6. applies the flags `generichide`, `specifichide`, `elemhide`;
   7. builds CSS (`sel1,\nsel2{display:none!important}` in groups of 1,000, plus `:style()` rules);
   8. calls `scripting.insertCSS({target: {tabId, documentIds: [documentId]} (or frameIds), css, origin: "USER"})` without delaying the reply;
   9. answers `MsgCosmeticFrameResponse`.

   The content script also pushes the CSS into a constructed stylesheet in `document.adoptedStyleSheets` (fallback: a `<style>` element) for zero-latency hiding.
3. **Generic cosmetic surveyor** (in `content/cosmetic.js`, only if `response.generic`):
   - starts when the response arrives (earlier than DOMContentLoaded): an initial snapshot of `[id],[class]`, then a `MutationObserver` on `document` (child lists and `class`/`id` attributes); `<html>`/`<body>` are scanned once;
   - scans in 4 ms slices; a raw `class` string that was already tokenised is skipped, because most class strings on a page repeat;
   - batches new tokens and flushes at most every 100 ms in the top frame and 250 ms in subframes, with one message in flight and at most 2,000 tokens per message; tokens are deduplicated per frame;
   - stops after 30 s without a new token, after 20 consecutive empty flushes (a `cosmetic:tokens` round trip whose reply has no CSS), or above 30,000 tokens; a backlog of more than 20,000 nodes collapses into one rescan.

   The SW looks up `generic.json` (loaded once per SW lifetime), filters by the enabled mask and by the host's exceptions, then calls insertCSS and replies with the CSS.
4. **Highly generic CSS** is one registration, `bs-gh-all`: `css` lists the file of every enabled list that has one, sorted by list id; `document_start`, `allFrames`, `<all_urls>`. `excludeMatches` = sites with protection off ∪ the `genericHighExcludedHosts` of every enabled list ∪ hosts where custom filters set `generichide`/`elemhide`. For a host that any enabled list excludes, and where generic hiding is allowed, the SW injects on `cosmetic:frame` the filtered copy: the highly generic selectors of every enabled list, minus that host's exceptions. Entity and bare-label hosts cannot become match patterns; for them only the SW lookup honours the exception.
5. **Procedural filters:**
   - If `response.procedural` is non-empty, the content script parks the filters in `self.bastionProceduralPending` and sends `cosmetic:procedural`. The SW `executeScript`s `content/procedural.js` (ISOLATED world) into that document (`documentIds: [sender.documentId]`, or `frameIds`). The engine consumes the parked filters when it loads, and the content script calls `self.bastionProcedural.apply(filters)` after the reply, so the order of injection and reply does not matter.
   - The engine is a port of uBO Lite's `css-procedural-api.js` (THIRD_PARTY_NOTICES §1). It supports every `ProceduralTask` in types.ts, with uBO's time budget (200 ms, refilled by 50 ms every 2 s), re-evaluates on element additions and removals (throttled to 100 ms + rAF) and does not stop, like uBO.
   - Actions: hide sets the attribute `bastion-hide-<random>` covered by one `[attr]{display:none!important}` rule; `:style()` uses `bastion-style-<random>` (declarations checked against uBO's blocklist plus `{}<`); `remove`, `remove-attr`, `remove-class`. Plain-selector filters and `:matches-media()` (with an optional `:spath`) become plain CSS. The sheet is re-adopted when the page resets `adoptedStyleSheets` and is also adopted into shadow roots that contain hidden nodes.
   - `:has()` with a plain CSS argument is compiled to native CSS, not procedural.
   - Compiler output conventions: nested filters (`has`, `not`, `if`, `if-not`) may start with a combinator relative to the subject (a leading `:scope` is stripped); `spath` uses uBO's spelling; `raw` is set on every filter and is the dedupe and exception key; text arguments are raw filter text (see the comments at `ProceduralTask`).
6. **De-AMP** (top frame only, if `response.deAmp`): on `<html amp>` / `<html ⚡>` (not `⚡4ads`), wait for `link[rel~=canonical i]`, then `location.replace(canonical)`: http(s) only, never https→http, never to the page itself or the referrer, with a 10 s `sessionStorage` loop guard.

## 6. Scriptlets

- **Vendoring.** uBO's scriptlet library (`vendor/ublock/resources/*.js`, GPL-3.0) is imported **at build time** by `tools/scriptlets.ts`. It evaluates `scriptlets.js` with Node, reads `builtinScriptlets` (`name`, `aliases`, `fn`, `dependencies`, `world`, `requiresTrust`) and serializes functions with `fn.toString()` in dependency order. uBO web-accessible resources with inline data are injectable as `+js()` too, as in uBO Lite. Brave resources (`vendor/brave-resources/resources/*.js` + `metadata.json`, MPL-2.0) are added where compatible; argument placeholders are substituted at build time and escaped for any JS string context. `de-amp.js` is skipped (it needs a Brave-injected global; de-AMP is native, §5.2.6).
- **Files** (`tools/scriptlets.ts`, per world, MAIN and ISOLATED):
  - `scriptlets/scriptlet-core-<world>.js`, the **core**: every scriptlet function (with its helper dependencies) that any list of that world uses, declared once, plus the runner;
  - `scriptlets/<listId>-<world>.js`, the **data** of one list: hostname records (hostnames and entities), regex hostnames, generic (`*##+js`) entries, arglists and exceptions;
  - `scriptlets/scriptlet-merged-<world>.js`: the data of the default lists (catalog default, not regional) in one file, so the default configuration needs one data file and one lookup per frame;
  - `scriptlets/scriptlet-end-<world>.js`: one call that starts the **runner**;
  - `scriptlets/index.json` (`ScriptletIndex`): the data files (`registrations`), the core and end file per world (`bundles`) and the merged files (`merged`).
- **Registration model: one registration per world: core + per-list data + runner.** Ids `sl-main` and `sl-isolated`. The `js` array is `[core, data file of every enabled list, end]`; the merged file replaces the files of its lists when all of them are enabled. `world`, `runAt: document_start`, `allFrames: true`, `matchOriginAsFallback: true`, `matches: ["<all_urls>"]`, `excludeMatches` = sites with protection off, `persistAcrossSessions: true`. Toggling a list changes only the `js` array of that world's registration.
- **Runtime.**
  - The core hands its functions to the data files and the end file on a global whose name is random per build; the runner deletes it first. No page script can run between the files of one registration, so pages never see it.
  - Hostname candidates: the frame's hostname, every parent, entity forms (`label.*`, only for lists that have entities) and `*` (generic entries). `about:blank`, srcdoc and blob frames use `self.origin`; opaque frames fall back to `location.ancestorOrigins[0]`.
  - Every frame compiles every data file, so the tables sit inside a comment of an otherwise empty function, which V8 only skips over. The runner reads them back with `Function.prototype.toString` only for the frame's lookups: the records are sorted by host and binary-searched in place; the arglist payload is parsed per hit.
  - Key ids are global per world, so the same (scriptlet, args) from two enabled lists runs once. Each matching scriptlet runs in its own try/catch before page scripts (uBO's `safeSelf()`); scriptlet priority is respected.
- **Exceptions.** `host#@#+js(name, args)`, the broad `host#@#+js()` and the filter's own `~host` apply when the list that defines them is enabled (uBO semantics).
- **Duplicate cookie clicks.** Within one list, `trusted-click-element` entries with the same selectors and extra-match keep a host only in the entry with the longest delay, so the host gets one `MutationObserver` instead of several (review PERF-4). The click can then happen up to that delay later. Never across lists: lists are toggled independently.
- **Why.** Host-sharded registrations (168 registrations with up to 400 `*://*.host/*` patterns each, about 49,000 patterns with the generic-high excludes) cost 9–13 ms of parser-blocking main-thread time per frame, the same again after DOMContentLoaded, and about 20 MB per renderer (review findings PERF-1/PERF-2). In-script lookup is uBO Lite's model. The trade-off is that every frame compiles the data of every enabled list, mostly as comment text.
- **Budget.** The default configuration must stay below 2,500 `matches` + `excludeMatches` patterns and below 30 registrations in total (`REGISTRATION_BUDGET` in `tools/build.ts`); the build fails otherwise (`--keep-going` only reports it). `build-report.json` (`contentScripts`) lists the registrations, the pattern counts and the bytes of scriptlet files that every frame loads per world.
- **Trust.** `requiresTrust` scriptlets are compiled only from trusted sources (§11.2). Custom filters cannot add scriptlets (no runtime code generation in MV3 without the userScripts toggle); this is documented in the UI.

## 7. Messages

All messages are defined in `src/shared/types.ts` (`Message`). The SW handles them in `src/background/messaging.ts`, with sender checks in `src/background/sender.ts`:

- Only senders with `sender.id === chrome.runtime.id` are answered.
- `cosmetic:frame`, `cosmetic:tokens`, `cosmetic:procedural` must come from a content script in a tab.
- `blocked:info`, `blocked:proceed` must come from the top frame of `pages/blocked.html` in a tab: `sender.url` parses to the extension scheme, its host is the static or the dynamic (`use_dynamic_url`) extension id, its path is `/pages/blocked.html`, `frameId === 0` and the tab id is ≥ 0. A web renderer cannot commit an extension URL, so a page or a compromised content-script context cannot lift a strict block.
- UI messages must come from an extension page (`sender.url` starts with the extension origin).
- Unknown types get `{error}`. Every request receives a JSON reply; every handler may answer `{error: string}` instead of its normal shape.

**Response shapes** (also documented above `Message` in types.ts):

| Message | Reply |
|---|---|
| `cosmetic:frame` | `MsgCosmeticFrameResponse` |
| `cosmetic:tokens` | `MsgCosmeticTokensResponse` |
| `cosmetic:procedural`, `blocked:proceed`, `history:clear` | `{ok: true}` (`history:clear` also resets `Totals`) |
| `blocked:info` | `MsgBlockedInfoResponse` |
| `popup:state` | `PopupState` |
| `site:set` | `{ok: true, ignored: string[], siteSettings}`; locked fields are dropped and listed in `ignored` |
| `config:get` | `EffectiveConfig` |
| `settings:set`, `backup:import` | `EffectiveConfig & {ignored: string[]}` |
| `lists:get`, `lists:set` | `ListsState`; `errors` values are `rule-limit`, `regex-limit`, `ruleset-limit`, `missing-ruleset` or the browser's error text |
| `custom:get`, `custom:set` | `CustomState` |
| `sites:get`, `sites:set` | `{sites: SitesMap}`, the user's own map; policy entries are reported through `EffectiveConfig.managed` |
| `history:query` | `HistoryResult` |
| `history:events` | `{events: ActivityEvent[]}` |
| `backup:export` | `BackupFile` |

`sites:set` keeps policy-owned fields (`enabled` of `disabledSites`, `mode` of `aggressiveSites`, and `enabled` everywhere when `allowUserSiteToggle` is false) at their previous user value, and answers `{error: "locked"}` under `lockSettings`. Locked paths are listed in §10.3.

**Live port** (`PORT_LIVE`). The client sends `{subscribe: tabId | 'all'}`; the SW posts `LivePortMessage`: `backlog` (without gaps), `event`, `reset` (navigation commit) and `attributed` (list attribution that arrived after the event was streamed, §8.3).

`ActivityEvent.list` uses the pseudo ids `custom` (user filters) and `admin` (policy filters), both in category `custom`.

## 8. Activity log and history

### 8.1 Listeners

All listeners are added synchronously at the SW top level; those the current settings do not need are removed after init, so the SW is not woken for every blocked request:

- `webRequest.onErrorOccurred` (`<all_urls>`), keeping only `net::ERR_BLOCKED_BY_CLIENT`, and `webRequest.onBeforeRedirect` (`<all_urls>`), keeping redirects to our extension origin and redirects that only changed the query: registered while the activity log is on **or** the badge is in `self` mode (§8.5).
- The main-frame `webRequest.onBeforeRedirect` listener is always registered: the strict-block page depends on it (§4.5).
- `webNavigation.onCommitted` (top frame): resets per-tab state, sets the grey icon, and forgets strict-block records; registered while any of those is needed.

Event kinds (`ActivityKind`): `blocked` (DNR block), `redirected` (redirect to a stub in `/war/`), `stripped` (query parameters removed), `debounced` (redirect to `pages/bounce.html`), `strict` (main_frame sent to `pages/blocked.html`).

### 8.2 Per tab

- Each tab has an in-memory ring buffer of `LIVE_EVENTS_PER_TAB` (300) events and counts. Live ports receive each event.
- Every second while it changes, a mirror is written to `storage.session` key `tab:<id>`: the counts, up to 500 third-party hostnames and the newest 50 events without query strings (about 10–15 KiB per busy tab). On a quota error the write is retried without events, so the counts survive. A restarted SW restores tabs from the mirror.
- **Activity log off** (`ui.activityLog: false`): no events are kept, streamed, attributed or written to the history, and no hostnames are kept. While the badge is in `self` mode the SW still counts blocked requests per tab (counts and totals only) for the badge (PRIVACY.md).
- **Popup.** `PopupState.counts` holds `blocked` (blocks and strict blocks), `redirected` (stubs served), `stripped`, `debounced` and `thirdPartyHosts` (distinct blocked third-party hosts, not a blocked count). `PopupState.logging` is the activity log setting and `PopupState.counting` is true while per-tab counters run (log on, or badge in `self` mode); the popup says the log or the counters are off instead of reporting «nothing blocked».

### 8.3 Attribution

At most once per `GET_MATCHED_RULES_MIN_INTERVAL_MS` (35 s, persisted across SW restarts), and only when there are unattributed events and someone is listening or history is on, the SW calls `getMatchedRules({minTimeStamp})`. It maps `rulesetId` to a list and joins on the tab and the nearest match with `|Δt| ≤ 1500 ms`. When the event's own tab has no match, the `tabId: -1` bucket is searched the same way, because Chromium moves a navigated-away document's matches there. Bastion's system rules (`isSystemAllowRuleId` in constants.ts: protection off, Standard allow, GPC, proceed) are never attributed; the popup's rule panel shows them apart, in one collapsed group, and leaves them out of its count. Chromium keeps matches for about five minutes, so events older than `MATCHED_RULES_HORIZON_MS` (4 minutes) are given up. Late attributions correct the stored history records and category counts and are streamed as `attributed` updates. The popup calls `getMatchedRules` itself when it opens and shares the quota, so the SW pauses its own polling for 60 s after each `popup:state`.

### 8.4 History

- IndexedDB `bastion-activity`:
  - `events` (keyPath auto, index `t`): stored without query or fragment, capped at `HISTORY_MAX_EVENTS` (50,000);
  - `daily` (keyPath `day`): `DailyAggregate`, `byHost`/`bySite` trimmed to the top 500.
- Pruned to `retentionDays` daily via `chrome.alarms`. `retentionDays: 0` keeps only today's aggregate. History off → nothing persisted except `Totals`. `Totals.blocked` = blocked + strict + redirected; `byKind` holds every kind.
- **Private windows** (split mode): nothing about private browsing is persisted. The incognito instance writes no history and no daily aggregates and keeps its totals in memory only.

### 8.5 Badge

`badgeModeFor(settings)`:

- `self` when `ui.badge` and `privacy.gpc` are on (the defaults): the SW keeps the per-tab count from the observed events and sets it with `action.setBadgeText({tabId})`. Chromium's built-in counter counts every matched non-allow action, including the GPC `modifyHeaders` rule, so it would count every request.
- `browser` when the badge is on and GPC is off: `declarativeNetRequest.setExtensionActionOptions({displayActionCountAsBadgeText: true})`.
- `off` otherwise.

The badge colour is Schiefer (#2A3134) with white text. Tabs with protection off get the grey icon via `action.setIcon({tabId})` on navigation commit; it is reset when protection comes back on.

## 9. Privacy features

| Feature | Default | Mechanism |
|---|---|---|
| Global Privacy Control | on | dynamic modifyHeaders `Sec-GPC: 1` + MAIN-world `navigator.globalPrivacyControl = true` |
| Tracking-parameter stripping (Brave list) | on | static ruleset `bastion-params` (enable/disable via updateEnabledRulesets) |
| Debouncing | on | dynamic regexSubstitution → `pages/bounce.html` (§4.6) |
| De-AMP | on | content script (§5.2.6) |
| Fingerprinting protection | standard | MAIN-world `main/privacy.js` |
| Block hyperlink auditing (`<a ping>`) | on | `chrome.privacy.websites.hyperlinkAuditingEnabled=false` |
| Privacy Sandbox ad APIs off | on | `chrome.privacy.websites.{topicsEnabled,fledgeEnabled,adMeasurementEnabled}=false` |
| WebRTC IP handling | browser default | `chrome.privacy.network.webRTCIPHandlingPolicy` |
| Third-party cookies | browser default | `chrome.privacy.websites.thirdPartyCookiesAllowed` |
| Block scripts per site | off | `chrome.contentSettings.javascript.set({primaryPattern:"*://*.<site>/*", setting:"block"})`, with an allow below a blocked parent |

`chrome.privacy` settings are changed only while `levelOfControl` allows it, and control is released when a feature is off; browser policies and other extensions are never fought. `blockThirdPartyCookies: false` releases control instead of forcing cookies on. Content settings apply to the regular profile only.

**Fingerprinting (`main/privacy.js`).**

- **Registration.** MAIN world, `document_start`, `allFrames`, `matchOriginAsFallback`, `persistAcrossSessions`. One registration per fingerprinting level that is in use, scoped with the per-site groups (§10.2): `js: [16 seed files, one per set, "main/cfg-<level>-gpc<0|1>.js", "main/privacy.js"]`. Sites with fingerprinting off but protection on still get the script with `cfg-off-gpc<0|1>.js`, so `navigator.globalPrivacyControl` matches the `Sec-GPC` header. Only sites with protection off are excluded entirely.
- **File contract.** Each seed file `main/seeds/s<set>-<n>.js` is exactly `(self.__bastionSeeds||(self.__bastionSeeds=[]))[<set>]=<uint32>;`, and each config file is `self.__bastionCfg={fp:"<off|standard|strict>",gpc:<true|false>};`. Plain property assignment on `self`, never `var`/`let`/`const`, so privacy.js can delete both globals before any page script runs. Missing seeds fall back to random seeds; a missing config falls back to standard + GPC.
- **Session seed.** `SEED_SETS` = 16 sets of `SEED_FILES_PER_SET` = 16 files, each holding one random 32-bit word that the build regenerates on every build. The SW picks one file per set on install and on browser startup (`runtime.onStartup`), stores the pick in `storage.local` (`seedPick`) and renews a pick that has the wrong shape. That gives 16^16 = 2^64 session seeds. Delivery needs no runtime code generation.
- **Per-site key.** The site is the registrable domain of the top-level page (`ancestorOrigins[last]` in frames). The key is the first 16 bytes, read as 4 little-endian uint32 words, of HMAC-SHA-256(key = every seed word as 4 little-endian bytes, message = `"bastion-farble-v1\0" + site`), implemented as pure synchronous JS in `src/main/farble.ts` (no `crypto.subtle`: it is asynchronous and page-patchable). Every key word depends on every seed word and on the site, so a page cannot solve the seed set by set and cannot derive a cross-site identifier. Known residual: if the non-cryptographic per-pixel hash ever reveals one site's key, that only strips the noise on that site. A xoshiro128** PRNG seeded from the key drives shuffles.
- **Standard.**
  - Canvas 2D and OffscreenCanvas (`getImageData`, `toDataURL`, `toBlob`, `convertToBlob`): an LSB flip of one RGB channel on a sparse pixel subset chosen per pixel from a hash of (key, x, y, RGBA). Reads are deterministic, tile reads agree with full reads, and noise learnt from a test image does not transfer. About 16 flips per canvas (1/256 of eligible pixels from 4,096 px, more for small canvases, at least 3 for whole-canvas reads). Alpha is never changed; transparent pixels and uniform regions are never touched. `toDataURL`/`toBlob` encode a farbled scratch copy, so the visible canvas is never mutated.
  - WebGL `readPixels` (RGBA/UNSIGNED_BYTE): the same noise.
  - Exact on purpose: `getImageData` reads under 16 px, `readPixels` under 64 px, from framebuffer objects or with custom pack layouts, canvases above 16.7 MP, AudioBuffers above 4M samples per channel.
  - Web Audio: `AnalyserNode` float data × (0.999 + up to 1e-4 of per-index noise), byte data with about 1 in 8 values moved one step toward the centre; `AudioBuffer.getChannelData` is farbled once, in place, per channel array, and `copyFromChannel` agrees with it.
  - `navigator.hardwareConcurrency` in [ceil(real/2), real]; `navigator.deviceMemory` real or real/2 (at least 1).
- **Strict** = Standard plus:
  - WebGL `UNMASKED_VENDOR`/`UNMASKED_RENDERER` return the masked strings ("WebKit" / "WebKit WebGL");
  - `navigator.languages` is a frozen `[navigator.language]`;
  - `speechSynthesis.getVoices()` returns `[]`;
  - `enumerateDevices` is shuffled deterministically with empty labels;
  - `hardwareConcurrency` in [2, real]; `deviceMemory` any power of two in [1, real].
- **Rules.** Patched functions are Proxy wrappers that keep `name`, `length`, prototype and `toString()` output native; `Function.prototype.toString` masks them, a `setPrototypeOf` trap emulates the native cycle check, our frames are removed from `error.stack` (unless the page set `Error.prepareStackTrace`), all call-time built-ins are captured at load, and a per-key sentinel prevents double patching without a page-visible marker. Every feature is patched in its own try/catch and every hook falls back to the original: never throw, never break on exotic receivers. Workers, lossy encodings (JPEG/WebP quantise the noise away), fonts, screen metrics, plugins and WebGPU are not covered (documented gaps, PARITY.md).

## 10. Settings, sites and managed policy

### 10.1 Storage and effective configuration

- `chrome.storage.local` with `setAccessLevel({accessLevel: "TRUSTED_CONTEXTS"})` at SW start. Keys are in `STORAGE`.
- The `ManagedPolicy` from `chrome.storage.managed` is overlaid onto user settings (`EffectiveConfig`). Parsing is tolerant: registry-style values (0/1, JSON strings, comma lists) are accepted; `supportUrl` must be http(s); `historyRetentionDays` is clamped to 0–3650; policy hostnames are lower-cased and punycoded, and one bad entry never drops the whole list.
- `PopupState.managed.reportBrokenSite` defaults to `email` when `supportEmail` is set, otherwise `github`.

### 10.2 Sites

- **Site key.** The lower-case punycode hostname with a leading `www.` removed. DNR `requestDomains` covers subdomains, and the cosmetic lookup walks parents.
- **Nesting.** Per-site overrides may nest (a subdomain switched back on below a disabled site, a different mode or fingerprinting level below a parent). `layerScopes` in `sites.ts` turns them into include/exclude groups: content-script registrations are exact at any depth; DNR uses at most 10 groups each for protection off and Standard mode.
- Policy `disabledSites` and `aggressiveSites` are applied on top, including their subdomains. `sites:get` and `sites:set` exchange only the user's own map (§7).
- A site entry that ends up equal to the defaults (for example protection switched off and on again, with no parent override) is deleted.

### 10.3 Locks

`EffectiveConfig.locked` lists the locked paths the UI greys out:

| Policy | Locked |
|---|---|
| a key that maps to a setting (`gpc`, `defaultMode`, `showBadge`, …) | that path: `defaultMode`, `privacy.<key>`, `ui.badge`, `ui.activityLog`, `ui.incidentCta`, `history.enabled`, `history.retentionDays` |
| `lists: {id: bool}` | `lists.<id>` |
| catalog `locked: true` | `lists.<id>` |
| `lockLists: true` | pseudo-path `lists` plus every `lists.<id>`; lists not named in `lists` use their catalog default |
| `allowUserSiteToggle: false` | pseudo-path `sites.enabled` (per-site protection switch) |
| `allowUserFilters: false` | pseudo-path `customFilters` (user filters read-only) |
| `lockSettings: true` | every setting path above; **and** `lists` + every `lists.<id>` unless `lockLists` is explicitly `false`; **and** `customFilters` unless `allowUserFilters` is explicitly `true`; **and** per-site mode, script blocking and fingerprinting (`site:set` drops them into `ignored`, `sites:set` answers `{error: "locked"}`) |
| `disabledSites` / `aggressiveSites` | per host and its subdomains: `PopupState.locks.siteToggle` / `PopupState.locks.mode` |

The SW enforces every lock in its handlers; the UI only mirrors them. `ListsState.locked` may contain `<id>` or `lists.<id>`.

### 10.4 Apply

`src/background/apply.ts` is the single idempotent `applyAll()`. It is debounced at 300 ms, strictly serial, and diffed against the browser's current state; each step catches and reports its own failures and never stops the others:

1. content-script registrations (cosmetic, generic-high CSS, scriptlets, privacy). First, because Chrome drops dynamic registrations on every extension update, and pages loaded before this step get no cosmetics, scriptlets or fingerprinting protection. A data file that fails to load never unregisters what it describes. Existing registrations are updated rather than re-registered where possible; a failed batch is retried one registration at a time.
2. enabled static rulesets: lists in manifest order, each with its `.regex` companion, plus `bastion-params` when `privacy.stripParams` is on. Before enabling it checks the rule budget (enabled count plus `getAvailableStaticRuleCount`), the regex limit (only the companion is dropped) and the 50-ruleset limit. If `updateEnabledRulesets` rejects, it disables first, then enables list by list, then retries a list without its companion; per-list errors go to `ListsState.errors`.
3. dynamic rules (§4.6);
4. session rules: the no-tab allows for sites with protection off; proceed rules are kept;
5. `chrome.privacy` settings;
6. badge;
7. content settings for blocked scripts.

In an incognito (split mode) instance, steps 5 and 7 are left to the regular instance.

### 10.5 Emergency switch (`protectionEnabled: false`)

A fleet-wide kill switch for administrators (DEPLOYMENT-INTUNE.md §9). While the policy sets `protectionEnabled: false`:

- the dynamic and session rules are replaced by the global allow (§4.6): dynamic 8,000,000 `allowAllRequests` on every top document and session 9,000,000 `allow` for `tabIds:[-1]`; custom filters, debounce, Standard-mode and GPC rules are removed;
- every content-script registration is removed, so new pages get no cosmetic filtering, scriptlets or privacy script;
- every `chrome.privacy` and content setting that Bastion controls is released;
- static rulesets stay enabled (the allow at 1000 outranks them), so restoring is instant;
- `PopupState.globallyDisabled` is true and the popup says protection is off everywhere.

User settings, sites, custom filters and history are not touched. Missing or `true` = normal operation.

### 10.6 Lifecycle and triggers

- All async setup sits behind one `ready` promise; events that arrive earlier are chained onto it in order.
- `applyAll` runs on install and update (`runtime.onInstalled`; an update resets the enabled rulesets and drops dynamic content scripts, §3), on browser startup, when the `storage.session` marker (`applied:marker`, with the extension version) is missing or from another version (browser restart, extension re-enabled), and on settings, sites, custom-filter and policy changes.
- `storage.onChanged`:
  - `managed`: always reload the policy, recompile the admin filters and apply. Policy changes are rare and never echoes of our own writes, and the event that wakes an idle SW must still be applied (init already loaded the new values, so an in-memory diff would see no change).
  - `local` (`settings`, `sites`, `customFilters`): apply when the new value differs from memory and is not an echo of one of this SW's own writes (echoes can arrive after a newer write), or when the event is the one that started the SW. This keeps writes by other trusted contexts working.
- **First install.** Fill defaults from the catalog. EasyList Germany is on for everyone; lists with `langs` (French, Italian) are also on by default when the browser UI language or any `navigator.languages` entry matches their primary subtag (`languageMatches` in `src/background/store.ts`, evaluated on every service-worker start; explicit user or policy choices win). Open the dashboard's welcome view unless the policy sets `organizationName` or the extension was installed by policy (`installType: admin`); the policy is read a second time after 1.5 s because managed storage can arrive late.

## 11. Build pipeline (`npm run build`)

### 11.1 Vendor (`tools/vendor.ts`)

Only when `vendor/` is missing or on `--update`: fetch the pinned commits listed in `vendor/VENDOR.json` (uBO resources, Brave resources/lists) from codeload tarballs. `--check` verifies `vendor/` against upstream without writing.

### 11.2 Fetch lists (`tools/fetch-lists.ts`)

- Downloads every catalog source (or reads a local `path`), 6 at a time, with 3 retries (1/2/4 s backoff) on network errors, 5xx and 429, a 30 s timeout, and refuses HTML responses.
- Expands `!#include` in place: same origin, same directory or below, no `..`, at most 3 levels; duplicates are inlined once. A failing include inside an `!#if` block is skipped with a warning; a failing top-level include stops the build.
- Caches in `.cache/lists/<sha1(url)>.txt` + `.json`, revalidated with ETag / Last-Modified; a truncated cache file is detected by its SHA-256. `--offline` uses the cache only and fails clearly when a source is missing.
- Writes `filters/lock.json` (`{version, sources: [{list, url, sha256, bytes, version, lastModified, fetchedAt, includedFrom?}]}`); `fetchedAt` stays the same when a source was only revalidated. Combined texts also go to `.cache/lists/combined/<id>.txt`.
- Hosts sources are kept byte-for-byte behind a `# --- source:` marker; ABP sources get `! --- source:`. Each ABP source has its unclosed `!#if` blocks closed at its end, so one source's conditionals cannot swallow the next source.
- **Trust per source** (uBO's model: only first-party-maintained sources may run arbitrary page code). Every upstream `!#trusted` directive is replaced by a comment. A source marked `"trusted": false` inside a list with `"trusted": true` (the Fanboy sources of `cookies` and `annoyances`) is wrapped in `!#trusted off <secret>` … `!#trusted on <secret>`. The secret is random per build (`FetchOptions.trustSecret`, returned as `FetchResult.trustSecret`) and is passed to `compileList` as `CompileOptions.trustSecret`. The compiler honours only markers with that exact secret and never raises trust above the list's own, so `trusted-*` scriptlets and trusted redirect resources from the wrapped source are rejected at compile time.

### 11.3 Build (`tools/build.ts`)

1. builds the redirect-resource map (uBO and Brave resources, with aliases and `requiresTrust`) and the scriptlet map from `vendor/`;
2. preprocesses every list and runs `collectBadfilters` over all of them;
3. runs `compileList` per list with the catalog flags (`trusted`, `firstPartyProtected`, `strictBlock`), `modifiers1p` (every `firstPartyProtected: false` list except `url-tracking`) and the trust secret;
4. keeps only the protected-list redirect copies an always-apply block can meet (`restrictRedirectCopies`, §4.2);
5. drops the regexes recorded in `.cache/regex-unsupported.json` (§11.4);
6. validates every rule against a port of Chromium's `indexed_rule.cc` checks (`tools/lib/dnr.ts`), assigns dense ids and writes `dist/rulesets/net/*.json`, the transparency maps `dist/rulesets/filters/*.json` (up to 20 filters plus "+N more") and `bastion-params`;
7. writes the cosmetic shards / generic / generic-high data (§5.1);
8. writes the scriptlet core, data, merged and end files plus `scriptlets/index.json` (§6); every file is parse-checked with `vm.Script`, release builds minify the core and end files;
9. copies the used redirect resources to `dist/war/`;
10. writes the seed files (16 × 16 fresh random words) and the six config files (§9);
11. writes `meta.json` (`BuildMeta`, with vendor commits and lock data) and `manifest.json` (rule_resources in §4.1 order, web_accessible_resources, version);
12. bundles TS with esbuild (`background.js` as ESM; content, main, ui and pages as IIFE; target chrome128);
13. copies `_locales`, icons, fonts, pages, `data/debounce.json`, `managed_schema.json` and licences;
14. checks the content-script budget of the default configuration (§6) and prints a report (rule counts, budgets, unsupported reasons) that it also writes to `dist/build-report.json`.

A compile failure stops the build and leaves the old `dist/` untouched; `--keep-going` ships that list empty instead.

### 11.4 Validate (`tools/validate-dist.ts`, `npm run validate`)

Loads a staged copy of `dist/` in Playwright's Chromium with every ruleset enabled and runs a probe service worker:

- every regex rule goes through `isRegexSupported`; rejected ones (mostly `memoryLimitExceeded`) are merged into `.cache/regex-unsupported.json`, which is never pruned;
- rulesets that fail to enable, registrations Chromium rejects and selectors that do not parse are errors (exit code 1). Unsupported regexes are not, unless `--strict` is passed.

Because the RE2 limit can only be checked in a browser, CI and the release build in two passes from the same inputs: `npm run build` (or `build:release`), `npm run validate`, then `node tools/build.ts --offline` (`--release --offline`), which reads the recorded regexes and the cached lists. `.cache/regex-unsupported.json` is cached between CI runs together with `.cache/lists`.

### 11.5 Package (`tools/package.ts`)

- `dist-pkg/bastion-shield-<version>-chromium.zip` (stores), written by a deterministic ZIP writer;
- the Edge variant (rulesets moved to the package root, as uBOL does for the Edge store validator);
- optional CRX3 signing with a PEM key from `BASTION_CRX_KEY` (self-hosting) + `update.xml`;
- never packaged: `_metadata/` (Chromium writes it into any unpacked folder it loads, so tests load a staged copy), `.map` files and `build-report.json`.

**Versioning.** `MAJOR.MINOR.PATCH.BUILD`, where BUILD = days since 2026-01-01 × 10 + same-day counter (`BASTION_BUILD_COUNTER` in CI). Releases are weekly via CI, plus on demand (RELEASING.md).

## 12. Permissions (manifest)

- `permissions`:
  - `declarativeNetRequest`, `declarativeNetRequestFeedback`
  - `scripting`, `storage`, `unlimitedStorage`, `alarms`
  - `webRequest`, `webNavigation`
  - `privacy`, `contentSettings`, `tabs`
- `host_permissions`: `<all_urls>`.
- `incognito: "split"` (WAR navigation in incognito).
- `minimum_chrome_version: "128"`, `default_locale: "en"`, `background: {service_worker: "background.js", type: "module"}`, CSP `script-src 'self'; object-src 'self'` for extension pages.
- `storage.managed_schema: "managed_schema.json"`.
- `web_accessible_resources`: `pages/blocked.html`, `pages/bounce.html` and the used redirect resources, with `matches:["<all_urls>"]`, `use_dynamic_url: true`.
- `action.default_popup: ui/popup.html`, `options_page: ui/dashboard.html`.
- The gear in the compact popup navigates the same popup to `ui/panel.html?tabId=<n>#site` (760×560): the dashboard app in popup mode (`body.db--popup`) with «Diese Website» first. Sections where closing the popup would lose work (Eigene Filter, adding or importing site exceptions, backup files, the licence table) open `ui/dashboard.html` in a tab instead.

**Limitation of `use_dynamic_url`.** It only stops direct probing: a page cannot fetch `chrome-extension://<static id>/war/noop.js` or frame our pages, and `chrome.runtime.getURL()` returns the dynamic id used for the bounce and blocked pages. DNR redirects with `extensionPath` resolve to the **static** id, and for `xmlhttprequest`/`other` resource types the page can read the result: `Response.url` / `XMLHttpRequest.responseURL` show `chrome-extension://<static id>/war/<stub>`. A page can therefore detect Bastion Shield and read its id with one `fetch` of a stubbed script. Script-type redirects (`<script>`) do not expose it. Most of these redirects are compatibility stubs that must succeed (anti-adblock checks), so they are kept; PRIVACY.md states the limitation.

## 13. Testing

- **`npm test`** (node:test, TypeScript run natively; globs, because Node 26 does not expand directory arguments) covers:
  - compiler unit tests: parser, every option mapping, merging, badfilter, cosmetic/scriptlet extraction, procedural parsing, trust markers, and the real cached lists when `.cache/lists` (or `BASTION_TEST_LISTS`) exists;
  - build tools: fetch-lists (local HTTP server), scriptlet files executed in a `vm` frame emulation, CRX3/ZIP, rule validation;
  - service worker planners: settings and locks, site layering, rules, registrations, debounce conversion, activity and attribution, sender validation;
  - content: farbling (including HMAC known-answer tests and key independence per seed word), stealth, tokens, procedural engine.
- **`npm run validate`** (§11.4): the browser-side rule and registration check.
- **`npm run test:e2e`** (Playwright, bundled Chromium in new headless mode, `launchPersistentContext`):
  - loads a **staged copy** of `dist/` (never `dist/` itself);
  - one local fixture server answers HTTP and HTTPS (self-signed certificate) for every host; Chromium runs with `--host-resolver-rules=MAP * 127.0.0.1:<port>`, so fixture URLs carry no port and nothing leaves the machine. Fixture sites live on `example.com`, `example.net` and `example.org`, which are on the Public Suffix List, so first-party/third-party checks behave as on real sites;
  - test subjects (filters, hosts, selectors, scriptlets) are picked from the built `dist/`;
  - covers: clean load and no errors, enabled rulesets and `isRegexSupported`, the content-script budget as registered in Chromium (fewer than 30 registrations and 2,500 match + exclude patterns), blocking and stubs (including a kept third-party redirect copy beating an always-apply block), Standard vs Aggressive, per-site off and on (keyed to the top-level site: a disabled site's embeds stay filtered elsewhere), the strict-block page and proceed (only the blocked host is allowed in that tab), generic/specific/procedural cosmetics, scriptlets, parameter stripping, GPC, fingerprinting, popup (also `?tabId=`) and dashboard, a load-time sanity bound, custom filters (also a `$removeparam` on a same-site request in Standard mode), script blocking, debouncing, and a settings write that wakes a stopped service worker;
  - managed policy (`10-managed.spec.ts`): a test cannot write `chrome.storage.managed`, so this spec stages the build with a test-only service-worker entry (`test/e2e/support/managed.ts`) that serves `storage.managed.get()` from a `storage.session` key and delivers `storage.onChanged(…, 'managed')` to the shipped listeners, as a real policy push does. It covers the kill switch (off everywhere, kept across a worker restart, restored) and `lockSettings` with `lockLists: false` / `allowUserFilters: true`. Product code is unchanged.
- **`npm run bench`** (`-- --rea` for the REA cross-check). Parity and performance against Brave on real sites (`--browsers chromium,bastion,edge` adds Bastion Shield in the installed Edge): third-party ad/tracker requests that got through, load timings and memory; results in PARITY.md.
