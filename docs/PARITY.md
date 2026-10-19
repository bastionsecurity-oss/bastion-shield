# Parity with Brave Shields

Bastion Shield aims to block as well as Brave Shields in its default ("Standard") mode, as a Manifest V3 extension for Chrome, Edge and Brave. This page lists, feature by feature, what matches, what is partial and what an extension cannot do, and holds the measured comparison.

Status legend: **Parity**: same behaviour. **Partial**: same goal, narrower or different mechanism. **Policy**: best done with a browser policy, documented in [DEPLOYMENT-INTUNE.md §6](DEPLOYMENT-INTUNE.md#6-complementary-browser-policies). **Planned**: not yet implemented, possible. **Gap**: not possible for an MV3 extension. **Extra**: Bastion Shield has it, Brave does not.

Brave facts refer to brave-core master and Brave's list catalog as of October 2026 (see the research notes behind [ARCHITECTURE.md](ARCHITECTURE.md)).

## Feature matrix

| Feature | Brave Shields (Standard) | Bastion Shield | Status |
|---|---|---|---|
| **Network blocking** | adblock-rust engine in the browser process, two engines (default and "additional") | Chromium's declarativeNetRequest engine with static rulesets compiled at build time; same lists | **Parity** for list content and matching speed (both native code). Lower ceiling: 30,000 guaranteed static rules ([FILTER-LISTS.md §4](FILTER-LISTS.md#4-rule-budget)). |
| **Standard vs Aggressive** | Standard: results of the default engine are discarded for same-site requests; additional engine always applies. Aggressive: everything applies | Same split by list (`firstPartyProtected`), implemented as one dynamic allow rule for first-party requests; per-site and global mode. `$removeparam`/`$csp`/`$permissions` of the always-apply lists (Brave's first-party list, cookie notices, Bastion's list and the other lists without first-party protection) and of custom filters get a first-party copy, so they also apply to same-site subresources, as in Brave's additional engine | **Parity** for network blocking. Brave forces Aggressive on youtube.com; we do not (yet). `$important` always applies in Bastion Shield (slightly stricter). Modifiers of the optional `url-tracking` list apply to same-site subresources only in Aggressive mode (rule budget). |
| **Cosmetic filtering** | Specific and generic hiding; in Standard, default-engine selectors are un-hidden when the hidden element is first-party or contains significant text; no default-engine hiding on search engines | Specific hiding per site, generic hiding by class/id survey, highly generic CSS, procedural filters, `:style()`; same in both modes (uBO behaviour) | **Partial**: hides at least as much as Brave; Brave's first-party un-hiding heuristic and search-engine exemption are not reproduced (lists are tested against uBO behaviour, which hides more). |
| **Scriptlets** (`##+js`) | uBO scriptlets + Brave resources; trust gated per list | uBO scriptlet library (vendored), Brave resources where compatible; `trusted-*` only from uBO, Brave and Bastion sources (trust per source, so Fanboy parts of mixed lists are untrusted); the hostname lookup runs inside the injected script, as in uBO Lite | **Parity**. User and admin custom filters cannot add scriptlets (MV3 forbids runtime code without the user-scripts toggle). |
| **Redirect resources** (`$redirect`) | uBO resources; a redirect applies whichever engine blocked the request | uBO and Brave resources as web-accessible files. Redirects of first-party-protected lists get a third-party copy above the always-apply blocks, so the stub wins as in uBO and Brave | **Parity**, except that a `$important` block still beats a non-important redirect (as in uBO Lite). `$redirect-rule` is unsupported in DNR (**Gap**, as in uBO Lite). Pages that fetch a replaced script with `fetch`/`XMLHttpRequest` can read the stub's `chrome-extension://` address ([PRIVACY.md](PRIVACY.md#what-websites-can-see)). |
| **Domain block page** (navigation to a blocked domain) | Interstitial; in Standard with first-party ephemeral storage | Warning page with "proceed anyway" for lists with strict block | **Partial**: no ephemeral storage. |
| **HTTPS upgrade** | Standard: upgrade with HTTP fallback, exception list | Not done by the extension: DNR `upgradeScheme` has no fallback and would break HTTP-only sites | **Policy**: `HttpsUpgradesEnabled`, `HttpsOnlyMode` |
| **Block scripts** (per site) | Toggle, with per-script allow list in the panel | Per-site toggle through `chrome.contentSettings.javascript` | **Partial**: no per-script allow list. |
| **Fingerprinting protection** | "Farbling": canvas, WebGL/WebGL2, WebGPU, Web Audio, hardware concurrency, device memory, plugins, media devices, speech voices, languages, screen coordinates, fonts, user agent, keyboard, USB serials; per-site, per-session seed | MAIN-world script: canvas 2D (`getImageData`, `toDataURL`, `toBlob`, `OffscreenCanvas.convertToBlob`), WebGL `readPixels`, Web Audio, `hardwareConcurrency`, `deviceMemory` (Standard); plus WebGL vendor/renderer, `navigator.languages`, speech voices, `enumerateDevices` (Strict); per-site, per-session seed | **Partial**: no coverage inside Web Workers/Service Workers, no font limiting, no screen or plugin farbling, and patched functions are detectable by determined scripts. |
| **Third-party cookies** | Blocked by default | Optional setting through `chrome.privacy` (default: leave the browser's setting) | **Policy**: `BlockThirdPartyCookies` |
| **"Forget me when I close this site"** | Clears first-party storage when the last tab of a site closes | Not implemented | **Planned** (approximation with `browsingData`; partitioned third-party storage cannot be wiped selectively) |
| **Ephemeral third-party storage** | Native | – | **Gap** |
| **Debounce** (bounce tracking) | `debounce.json`, all rule types, eTLD+1 checks, main-frame navigations | Same list, converted to DNR redirects to a local bounce page: query-parameter targets, base64 targets, `prepend_scheme` and the `regex-path` rule types. The page decodes the target, requires http(s), and refuses targets on the tracker's own site (`?from=<host>`) | **Partial**: rules with exclusion lists are skipped (RE2 has no lookahead); for rules without a fixed host the different-site check is not possible. |
| **Query-parameter stripping** | `query-filter.json`; GET, cross-site requests and redirects only | Same list, `removeParams` on cross-site main and sub frames | **Parity** (same parameters). Brave's conditional parameters (kept on unsubscribe pages) and same-site-redirect exemption are approximated. `url-tracking` adds 2,000+ parameters as an option. |
| **Global Privacy Control** | Always on: `Sec-GPC: 1` and `navigator.globalPrivacyControl` | Same, on by default, can be switched off | **Parity** |
| **De-AMP** | Sniffs the first 192 KB of an HTML response and redirects before render; debounce rules for AMP caches | Content script detects `<html amp>` / `<html ⚡>` at document start and redirects to the canonical URL; debounce rules | **Partial**: the AMP page starts loading before the redirect. |
| **CNAME uncloaking** | Resolves hostnames and re-checks the canonical name (third-party requests in Standard) | Not possible: extensions get no CNAME data before a request; known disguised trackers are blocked through EasyPrivacy's CNAME sections | **Gap** (small against Standard, which does not uncloak first-party requests) |
| **Element picker** ("block elements") | Yes | Not yet; custom cosmetic filters can be typed in the dashboard | **Planned** |
| **Referrer capping** | Cross-origin referrers capped to origin | Not done (Chromium's default policy is `strict-origin-when-cross-origin` already) | **Partial** |
| **Hyperlink auditing** (`<a ping>`) | – | Disabled through `chrome.privacy` | **Extra** |
| **Privacy Sandbox ad APIs** | Not in Brave | Topics, Protected Audience and Attribution Reporting turned off through `chrome.privacy` | **Extra** |
| **Filter list updates** | Component updater, about every 100 minutes | Weekly extension releases (plus on demand); store review adds delay, Edge up to 7 business days | **Gap** in freshness ([FILTER-LISTS.md §8](FILTER-LISTS.md#8-update-cadence)) |
| **Custom filters, custom lists** | Custom filters, list subscriptions by URL | Custom filters (network and cosmetic) for users and admins; no subscriptions by URL | **Partial** |
| **Live log / statistics** | Per-page blocked resources in the panel, global counters | Live per-tab activity with the list that blocked each request, local history with daily statistics, toolbar badge | **Extra** (history) |
| **Central management** | Brave enterprise policies | `chrome.storage.managed` policy for every setting, Intune kit, fleet-wide emergency switch (`protectionEnabled`) | **Parity** |
| **Brave as host browser** | – | Shields blocks first; Bastion Shield sees and counts only what Shields lets through | see [Edge and Brave](#edge-and-brave) and the [DEPLOYMENT-INTUNE.md FAQ](DEPLOYMENT-INTUNE.md#should-we-deploy-bastion-shield-to-brave) |

## Why network blocking is not slower

Network blocking happens inside the browser's network stack in both cases: Brave runs its Rust engine, Chromium runs its C++ declarativeNetRequest matcher. No extension JavaScript runs per request. The costs specific to an extension are elsewhere (content scripts on each page, service-worker wake-ups for the activity log) and are measured below.


## Measured results

<!-- Filled in from the benchmark harness (npm run bench -- --rea; full output in test/bench/results/summary.md). Keep the method stable so numbers stay comparable between releases. -->

**Method.** `npm run bench -- --rea` (`test/bench/`) starts three browsers side by side, each with a fresh profile: Playwright's Chromium without a blocker, the same Chromium with Bastion Shield (default settings, Standard mode), and Brave with Shields at its defaults. Each home page of 25 sites (Swiss news and e-commerce, international news and top sites) is loaded once per browser, in an order that rotates per site, and observed for 15 s after the load event; consent banners are not clicked, so this is the first-visit state. Every request is recorded over the Chrome DevTools Protocol, including cross-site iframes and workers. A request counts as an ad/tracker request when it is third-party and its host is in a reference set of 56,377 hosts (the `||host^` entries of EasyList's adservers and EasyPrivacy's trackingservers sections, versions 202610181630); it counts as blocked when it fails with `ERR_BLOCKED_BY_CLIENT` or is replaced by a stub. REA 6.7.0 (`rea inspect-web-page`) inspected every visit independently and agreed with this capture on all 75 visits (0 disagreements, 63 stubs confirmed by content size).

Because both blockers ship EasyList and EasyPrivacy, "got through" measures coverage of those lists' known hosts, not of unknown trackers.

**Blocking** (2026-10-18 16:59 UTC, Bastion Shield 0.1.0.2900 dev build with the review fixes, Chromium 156.0.8078.4, Brave 155.1.97.59 on Chromium 155.0.8059.85, all headless, Windows 11, AMD Ryzen 7 9800X3D):

| Result | Chromium | Bastion Shield | Brave |
|---|---:|---:|---:|
| Ad/tracker requests that got through (25 sites) | 336 | 8 | 8 |
| Reduction against plain Chromium | – | 97.6 % | 97.6 % |
| Requests blocked or stubbed | 0 | 413 | 395 |
| Hosts that got through in one blocker but not the other | – | none | none |

The 8 requests that got through are the same in both blockers: 20min.ch (1, `20minuten-cdn.relevant-digital.com`), watson.ch (1, `www.googletagmanager.com`) and weather.com (6: `securepubads.g.doubleclick.net` 4, `micro.rubiconproject.com` 2).

**Performance** (medians over the 25 sites; in brackets the run before the review fixes, same machine and day, 13:24 UTC):

| Metric (median) | Chromium | Bastion Shield | Brave |
|---|---:|---:|---:|
| DOMContentLoaded, ms | 292 (295) | 305 (333) | 305 (297) |
| Load event, ms | 633 (619) | 462 (554) | 520 (516) |
| Page JS heap, MB | 24.9 (25.0) | 18.6 (18.6) | 19.6 (18.7) |
| Bastion Shield service worker JS heap, MB | – | 1.9, max 3.1 (7.8, max 8.9) | – |

Per-site differences (median of the 25 paired visits): Bastion's DOMContentLoaded is 11 ms later than plain Chromium's (before: 41 ms) and 23 ms later than Brave's (before: 29 ms); its load event is 101 ms earlier than plain Chromium's (Brave: 113 ms earlier). The review traced the DOMContentLoaded gap to content-script URL matching: the old build registered about 49,000 match patterns that Chromium checked in every frame. The current build registers 5 scripts with 1,662 patterns ([ARCHITECTURE.md §6](ARCHITECTURE.md#6-scriptlets)), which closed most of it. The service-worker heap dropped most likely because the generic cosmetic index is no longer parsed as one JSON object on every worker start. Single visits vary by several hundred milliseconds (ad auctions, consent scripts, CDN state), so only the medians are meaningful.

**Breakage and caveats.**

- Not measured systematically by the benchmark. Real-world reports come in through "Report a broken site" ([FILTER-LISTS.md §7](FILTER-LISTS.md#7-community-and-reporting)).
- stackoverflow.com: in this run the Bastion visit made 1,677 requests (Chromium 113, Brave 74). 985 of them were repeated `GET /Content/Img/SE-logo75.png` that the site answered with HTTP 429, and the site's main bundle (`full-anon.en.js`) did not load. Bastion was the third visit within 30 s, and the site was rate-limiting at that moment; a re-check minutes later only got the Cloudflare challenge page. The previous run (73 requests) showed no loop. **Re-checked (2026-10-18 17:33 UTC) with Bastion as the first visit:** 72 requests, page and main bundle loaded normally, 0 ad/tracker requests through (plain Chromium right after: 114 requests, 25 ad/tracker requests). The loop was the site's rate limiting of a third visit within 30 s, not Bastion behaviour.
- Brave answers most blocked third-party scripts with a stub (a 200 response with a tiny body), so the page sees a successful load. Bastion hard-blocks them (`ERR_BLOCKED_BY_CLIENT`) unless a list names a surrogate. Examples in this run: spiegel.de (Brave 7 stubs, Bastion 1 stub and 7 blocks) and corriere.it (Brave 16 stubs, Bastion 4). No visible breakage resulted on these home pages, but scripts that watch for load errors can react differently.
- The totals in `summary.md` include the stackoverflow.com outlier (Bastion 5,910 requests in total; 4,233 without stackoverflow.com, Brave 4,248). The medians above are not affected by it.

Last measured: 2026-10-18 16:59 UTC, Bastion Shield 0.1.0.2900. Per-site numbers and the REA cross-check: [`test/bench/results/summary.md`](../test/bench/results/summary.md); raw data `test/bench/results/2026-10-18T16-59-36.json` (previous run: `2026-10-18T13-24-08.json`).

## Edge and Brave

The numbers above come from Playwright's Chromium. On 2026-10-18 the same build (0.1.0.2900, loaded unpacked into a fresh profile, Swiss German UI) was checked in the installed **Microsoft Edge 155.0.4283.62** and **Brave 1.97.59** (Chromium 155.0.8059.85) on Windows 11, with visible windows. Edge runs the same extension code as Chrome; nothing Edge- or Brave-specific had to be changed. Screenshots: `docs/screenshots/edge-*.png` and `brave-*.png`.

| Check (home pages of 20min.ch, nzz.ch, cnn.com, blick.ch) | Edge | Brave, Shields at defaults | Brave, Shields down for the site |
|---|---|---|---|
| Loads without manifest or runtime errors (extensions page in developer mode, service-worker console) | yes ([screenshot](screenshots/edge-extensions.png)) | yes ([screenshot](screenshots/brave-extensions.png)) | yes |
| Rulesets enabled on install (28 declared, 22 on by default) | all 22 defaults | all 22 defaults | all 22 defaults |
| Blocked + replaced by stubs, as counted by Bastion's popup | 14+4, 19+1, 11+4, 6+2 ([screenshot](screenshots/edge-popup-20minch.png)) | 0 on all four ([screenshot](screenshots/brave-popup-20minch.png)) | 14+4, 20+1, 11+2, 6+2 ([screenshot](screenshots/brave-shieldsdown-popup-20minch.png)) |
| Requests failing with `ERR_BLOCKED_BY_CLIENT` on the page, any blocker | 14, 18, 11, 6 | 14, 17–19, 11, 6 | 14, 17–19, 11, 6 |
| Bastion switched off for 20min.ch in the popup, page reloaded | 0 blocked, the ads load (378 requests instead of 217); switched on again: blocking resumes ([screenshot](screenshots/edge-popup-20minch-off.png)) | still 14 blocked, by Shields; Bastion counts 0 | 0 blocked, 331 requests ([screenshot](screenshots/brave-shieldsdown-popup-20minch-off.png)) |
| Popup and dashboard | render, no console errors; list names in the live feed ([popup](screenshots/edge-popup-attributed.png), [dashboard](screenshots/edge-dashboard.png), [activity](screenshots/edge-dashboard-activity.png)) | render ([dashboard](screenshots/brave-dashboard.png)) | render |
| **Works** | **yes** | **yes**, with Bastion's counters at about zero (by design) | **yes** |

- **Edge.** Blocking is the same as Bastion Shield in Chromium, request for request (benchmark below). Edge's own tracking prevention (default "Balanced") blocked no network request on 20min.ch with Bastion switched off for the site, so it does not lower Bastion's counters there; in Balanced it mainly restricts storage access ([DEPLOYMENT-INTUNE.md FAQ](DEPLOYMENT-INTUNE.md#we-already-use-edge-tracking-prevention-do-we-still-need-bastion-shield)). Edge also runs the extension headless.
- **Brave, Shields up.** Shields blocked the same requests on these pages before Bastion's rules saw them, so Bastion counted 0 on all four sites. Bastion does not count Shields' blocks as its own: with Bastion off for 20min.ch the page still had 14 blocked requests and the popup showed 0. Switching Bastion off for a site therefore unblocks nothing on Brave; lower Shields as well or use `BraveShieldsDisabledForUrls` ([DEPLOYMENT-INTUNE.md FAQ](DEPLOYMENT-INTUNE.md#should-we-deploy-bastion-shield-to-brave)). With both active, all four pages loaded normally (same titles, request counts within a few of Edge's), and the extension logged no errors.
- **Brave, Shields down.** Bastion blocks exactly as in Chromium and Edge; with Bastion also switched off nothing is blocked, which confirms Shields was really down.
- **List names in the popup** can lag in every browser: the service worker asks `getMatchedRules` at most every 35 s and pauses for 60 s whenever the popup opens, to stay inside Chrome's quota. Opening popups every few seconds (as the check script did) leaves rows without a list name for a minute; after a quiet minute all 14 events on spiegel.de in Edge carried their list.
- **Not covered yet:** installation from Edge Add-ons and the Chrome Web Store, force-install through `ExtensionSettings` and the managed configuration from the registry (`3rdparty` policy). These need a managed test device and are the open item for the pilot. Also not checked: InPrivate and private windows, Edge and Brave on macOS.

**Benchmark with Edge** (`npm run bench -- --browsers chromium,bastion,edge --limit 5`, same method as above, all headless, 2026-10-18 18:34 UTC; Edge keeps its tracking prevention and component updates on):

| Result (20min.ch, blick.ch, watson.ch, nzz.ch, tagesanzeiger.ch) | Chromium | Bastion Shield in Chromium 156 | Bastion Shield in Edge 155 |
|---|---:|---:|---:|
| Ad/tracker requests that got through | 91 | 2 | 2 |
| Requests blocked or stubbed | 0 | 69 | 69 |
| Hosts that got through in one but not the other | – | none | none |

Per site the blocked counts are identical (18, 8, 11, 21, 11); the two requests that got through are the same in both (20min.ch and watson.ch, as in the 25-site run). Timings were in the same range (median load event 443 ms in Chromium with Bastion, 377 ms in Edge). Per-site numbers: [`test/bench/results/summary-edge.md`](../test/bench/results/summary-edge.md); raw data `test/bench/results/2026-10-18T18-34-42.json`.
