# Filter lists

Which filter lists Bastion Shield ships, why, under which licences, how they fit into the browser's rule limits, how fixes reach users, and how to add a list. The list catalog itself is [`filters/catalog.json`](../filters/catalog.json); this document explains it.

Facts about third-party lists were checked on 2026-10-18 by downloading every list and reading its header and licence. Rule counts are given both as the early *estimate* (uBlock Origin Lite's converter) and as measured in Bastion Shield's first build on that date; each release's notes and `build-report.json` carry the current numbers.

## Contents

1. [What ships](#1-what-ships)
2. [Parity with Brave Shields](#2-parity-with-brave-shields)
3. [Swiss regional strategy](#3-swiss-regional-strategy)
4. [Rule budget](#4-rule-budget)
5. [Licences and attribution](#5-licences-and-attribution)
6. ["Known advertising companies" data](#6-known-advertising-companies-data)
7. [Community and reporting](#7-community-and-reporting)
8. [Update cadence](#8-update-cadence)
9. [Adding a list](#9-adding-a-list)
10. [Lists users import («My lists»)](#10-lists-users-import-my-lists)

---

## 1. What ships

Each list becomes its own static ruleset (the list id is the ruleset id), so it can be switched on and off without a rebuild, and every blocked request can be traced back to its list and filter text.

| Id | List | Category | Default | Standard-mode 1p protection¹ | Strict block² | Trusted³ | Sources |
|---|---|---|---|---|---|---|---|
| `bastion` | Bastion filters | ads | on | no | yes | yes | [`filters/bastion.txt`](../filters/bastion.txt) |
| `ublock` | uBlock filters | ads | on | yes | yes | yes | uAssets `filters.txt` (with its `!#include`s: filters-general, filters-2020…2026, link shorteners), `quick-fixes.txt`, `unbreak.txt` |
| `easylist` | EasyList | ads | on | yes | yes | no | `easylist.to/easylist/easylist.txt` |
| `brave` | Brave filters | ads | on | yes | yes | yes | brave/adblock-lists `brave-unbreak.txt`, `brave-specific.txt`, `brave-social.txt`, `brave-sugarcoat.txt` |
| `brave-firstparty` | Brave first-party filters | ads | on | **no** | no | yes | `brave-firstparty.txt`, `brave-firstparty-regional.txt` |
| `easyprivacy` | EasyPrivacy | privacy | on | yes | yes | no | `easylist.to/easylist/easyprivacy.txt` |
| `ublock-privacy` | uBlock filters – Privacy | privacy | on | yes | yes | yes | uAssets `privacy.txt` (includes `resource-abuse.txt`) |
| `peter-lowe` | Peter Lowe's ad and tracking server list | privacy | on | yes | yes | no | `pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts…` |
| `ublock-badware` | Badware risks | security | on | no | yes | yes | uAssets `badware.txt` |
| `urlhaus` | Malicious URL blocklist (URLhaus) | security | on⁴ | no | yes | no | malware-filter `urlhaus-filter-agh-online.txt` (domain level) |
| `cookies` | Cookie notices | annoyances | on | no | no | partly (uAssets and Brave sources only) | Fanboy `fanboy-cookiemonster_ubo.txt`, uAssets `annoyances-cookies.txt`, Brave `brave-cookie-specific.txt` |
| `app-promos` | Mobile app promotions | annoyances | on | no | no | no | Fanboy `fanboy-mobile-notifications.txt` |
| `annoyances` | Annoyances | annoyances | off | no | no | partly (uAssets source only) | Fanboy `fanboy-annoyance_ubo.txt`, uAssets `annoyances-others.txt` |
| `social` | Social media widgets | annoyances | off | no | no | no | `easylist.to/easylist/fanboy-social.txt` |
| `url-tracking` | Tracking parameters (extended) | privacy | off | no | no | yes | uAssets `privacy-removeparam.txt` |
| `regional-de` | German websites (EasyList Germany) | regional | **on** | yes | yes | no | `easylist.to/easylistgermany/easylistgermany.txt` |
| `regional-fr` | French websites (AdGuard French) | regional | **on** | yes | yes | no | `filters.adtidy.org/extension/ublock/filters/16.txt` |
| `regional-it` | Italian websites (EasyList Italy) | regional | **on** | yes | yes | no | `easylist-downloads.adblockplus.org/easylistitaly.txt` |
| `block-lan` | Block outsider intrusion into LAN | security | off | no | no | yes | uAssets `lan-block.txt` |
| `hagezi-tif` | Threat Intelligence Feeds (HaGeZi, mini) | security | off | no | yes | no | hagezi/dns-blocklists `adblock/tif.mini.txt` (domain level) |
| `hagezi-pro` | Multi PRO (HaGeZi) | privacy | off | yes | yes | no | hagezi/dns-blocklists `adblock/pro.txt` (domain level) |
| `anti-facebook` | Anti-Facebook | privacy | off | no | no | no | Fanboy `fanboy-antifacebook.txt` |
| `easylist-chat` | Chat widgets | annoyances | off | no | no | no | uAssets mirror of EasyList `easylist-chat.txt` |
| `easylist-ai` | AI suggestions | annoyances | off | no | no | no | uAssets mirror of EasyList `easylist-ai.txt` |
| `adguard-popups` | Pop-ups (AdGuard) | annoyances | off | no | no | no | `filters.adtidy.org/extension/ublock/filters/19.txt` |

Built in, not a catalog list: `bastion-params`, Brave's tracking-parameter list (`query-filter.json`, MPL-2.0) compiled to parameter-stripping rules, and Brave's bounce-tracking list (`debounce.json`), applied as dynamic rules. Both can be switched off in the dashboard (`stripParams`, `debounce`).

Notes:

1. **First-party protection** reproduces Brave's "Standard" mode: in Standard, block rules of these lists do not apply to requests that go to the same site as the page. Lists without it (Brave's first-party list, cookie notices, app promotions, Bastion's list, security lists, custom filters) always apply, as in Brave. See [ARCHITECTURE.md §4.3](ARCHITECTURE.md#43-standard-vs-aggressive-brave-semantics).
2. **Strict block**: navigating to a domain blocked by a plain hostname filter of this list opens Bastion Shield's warning page ("proceed anyway" possible) instead of a browser error.
3. **Trusted** sources may use uBlock Origin's `trusted-*` scriptlets and redirect resources that need trust (for example to click "reject all" in cookie banners). Those can run arbitrary code on pages, so trust is granted **per source**: only sources maintained by uBlock Origin, Brave and Bastion are trusted, the same principle as uBO Lite (which trusts only uAssets) and uBlock Origin (which does not trust Fanboy's lists). A list that mixes sources, such as `cookies` and `annoyances`, is trusted only for its uAssets and Brave parts: the build wraps the Fanboy part in `!#trusted off/on` markers with a secret that is random per build, and the compiler rejects trusted scriptlets and redirects inside it. `!#trusted` lines in upstream text are removed, so a list can never switch trust on by itself.
4. See the licence note on URLhaus in [section 5](#5-licences-and-attribution).

**More lists.** The dashboard shows the off-by-default lists (except the regional ones, which follow the user's languages) in a separate «More lists» group, with the rules each would take from the budget. They were picked from uBlock Origin's own catalog of optional lists (`assets.json`) plus HaGeZi's, and checked on 2026-10-19:

- Left out because they overlap: the EasyList newsletter and notification lists (both are part of Fanboy's Annoyance list in `annoyances`), AdGuard Widgets (overlaps `easylist-chat`), AdGuard Base (overlaps EasyList, 53,000 lines), AdGuard Mobile Ads (mobile only).
- Left out for the licence: Dan Pollock's hosts file («free … for non-commercial uses»).
- HaGeZi's lists are GPL-3.0 as published; HaGeZi notes that the upstream feeds keep their own terms, which only matters to someone building on that raw data. Both HaGeZi lists change several times a day; Bastion ships them weekly like every other list. Together they add about 17 MB to the unpacked package (about 6 MB compressed) but only 2 rules each, because host filters merge into `requestDomains`.

Always use the uBlock Origin flavour of third-party lists (`filters.adtidy.org/extension/ublock/…`, Fanboy's `_ubo` files): the native AdGuard and Adblock Plus flavours contain syntax a uBO-style compiler cannot translate. We never ship lists that uBlock Origin flags as harmful in its `badlists.txt` (for example the Adblock Plus "acceptable ads" exception list).

---

## 2. Parity with Brave Shields

Brave's default protection is not a separate data set: it is the uBlock Origin / EasyList stack plus a few Brave lists. Source: Brave's catalog (`brave/adblock-resources`, `filter_lists/list_catalog.json`, commit 6da9b247).

| Brave component (desktop) | Brave default | Contents | Bastion Shield | Difference |
|---|---|---|---|---|
| Brave Default Adblock Filters | on, hidden | uAssets filters + yearly files + filters-general + link shorteners, badware, resource-abuse, unbreak, quick-fixes; EasyList; URLhaus (`agh-online`); Brave Unbreak, Specific, Social, Android-specific, SugarCoat | `ublock`, `easylist`, `ublock-badware`, `urlhaus`, `brave` (resource-abuse comes with `ublock-privacy`) | Brave's Android-specific list is left out (desktop browsers only). |
| Brave Default Privacy Filters | on, hidden | EasyPrivacy, uAssets `privacy.txt` | `easyprivacy`, `ublock-privacy` | same |
| Brave First Party Adblock Filters | on, hidden | `brave-firstparty.txt`, `brave-firstparty-regional.txt` | `brave-firstparty` | same; always applies, as in Brave |
| Cookie notice blocker | on | Fanboy Cookiemonster (`_ubo`), uAssets annoyances-cookies, Brave cookie additions | `cookies` | same |
| Mobile app promo blocker | on | Fanboy Mobile Notifications | `app-promos` | same |
| Regional lists | by browser UI language | de: EasyList Germany; fr: AdGuard French (includes Liste FR); it: EasyList Italy | `regional-de`, `regional-fr`, `regional-it` | German always on; French and Italian on when the browser UI language **or any preferred language** matches (section 3). Brave fetches EasyList Germany from the Adblock Plus mirror; we use the `easylist.to` original. |
| Query-parameter stripping | on | `query-filter.json` | `bastion-params` | same list; see [PARITY.md](PARITY.md) for when it applies |
| Debouncing | on | `debounce.json` | built in | almost every rule converts, including base64 targets and path rules; rules with exclusion lists are skipped (PARITY.md) |
| Facebook / X embed exceptions | on (settings) | hidden exception lists that keep embedded posts and logins working | not shipped | To check in the parity tests whether `brave-social` blocks embeds that Brave allows by default. |
| Annoying distractions, Social media blocker, Tracking URL blocker (AdGuard 17) | off | | `annoyances`, `social`, `url-tracking` (uAssets' parameter list, which builds on AdGuard's) | off in both |
| — | — | Peter Lowe's list | `peter-lowe` | Bastion extra (on in uBlock Origin and uBO Lite too): one rule, little risk |
| — | — | Bastion filters | `bastion` | Bastion extra: Swiss fixes and customer unbreaks |

Brave refreshes its lists about every 100 minutes through its component updater. An extension can only change its bundled rules with an extension update, so Bastion Shield is at most one weekly release behind (section 8).

---

## 3. Swiss regional strategy

Switzerland has four national languages and people routinely read German-, French- and Italian-language sites regardless of their browser language. Brave enables a regional list only when it matches the browser's UI language (and only once); a `de-CH` user on Romandie news sites gets no French list. Bastion Shield therefore:

- enables **EasyList Germany for everyone** (`default: true`; it also covers Romansh, Swiss German and Luxembourgish content, `langs: de, gsw, rm, lb`);
- enables **French** and **Italian** automatically when the browser UI language *or any of the user's preferred content languages* (`navigator.languages`) is `fr` or `it`. This is evaluated by the service worker on every start, so adding French to the browser's language list switches the French list on. An explicit choice in the dashboard always wins;
- lets administrators force any combination with the `lists` policy, for example `{"regional-fr": true, "regional-it": true}` for an organisation that works in all three languages.

This keeps the default set comfortably below the 30,000 guaranteed rules (section 4) while matching Brave for single-language users and doing better for multilingual ones.

- **German**: EasyList Germany covers Germany, Austria and Switzerland and contains a few hundred rules for `.ch` domains (20min.ch, blick.ch, finanzen.ch …).
- **French**: AdGuard French, the list Brave and uBlock Origin use, which already contains Liste FR.
- **Italian**: EasyList Italy, also used for Ticino sites.
- **Romansh** content is covered by the German list.

No maintained Swiss-specific ad list exists (the last one stopped in 2020). Gaps on Swiss sites are filled in the Bastion list and reported upstream.

Cost: EasyList Germany adds about 1,800 rules, AdGuard French about 4,100 and EasyList Italy about 1,100. With all three forced on, the default set is about 29,800 rules, right at the guaranteed budget; that is why French and Italian follow the user's languages instead of being on for everyone.

---

## 4. Rule budget

Chromium limits for extensions (see [ARCHITECTURE.md §3](ARCHITECTURE.md#3-platform-limits-we-design-against-chromeedge-155)):

- **30,000 static rules guaranteed** per extension. Beyond that, rules come from a pool of 300,000 shared by all extensions in the profile: not guaranteed.
- At most **50 enabled** and 100 declared rulesets.
- At most **1,000 regex rules** across all enabled static rulesets; a ruleset that would exceed it is skipped silently. Bastion Shield puts each list's regex rules into a separate companion ruleset (`<id>.regex`) so only that companion can be skipped, never the main list.

Plain hostname filters are merged into one rule per list (a rule can carry thousands of domains), so domain lists cost almost nothing. Cosmetic filters and scriptlets do not count against these limits at all.

Static rules per list (plain + regex). The first column is the *estimate* made with uBO Lite's converter before our compiler existed; the second is the first development build of Bastion Shield (0.1.0.2900, 2026-10-18). Release numbers are in every release's notes and `build-report.json`.

| List | Estimate (uBO Lite) | First build |
|---|---:|---:|
| `bastion` | – | 3 |
| `ublock` | 5,798 (with `ublock-privacy`) | 4,746 |
| `ublock-privacy` | (in `ublock`) | 1,268 |
| `easylist` | 3,728 | 3,740 |
| `easyprivacy` | 9,066 | 9,080 |
| `ublock-badware` | 462 | 1,517 |
| `peter-lowe` | 1 | 2 |
| `urlhaus` | 1 | 2 |
| `brave` | 273 | 271 |
| `brave-firstparty` | 425 | 426 |
| `cookies` | 1,842 | 1,840 |
| `app-promos` | 22 | 22 |
| `bastion-params` | – | 85 |
| **Default set without regional lists** | **≈ 21,600** | **23,002** |
| `regional-de` | 1,838 | 1,841 |
| `regional-fr` | 4,054 | 4,069 |
| `regional-it` | 1,057 | 1,057 |
| **Swiss default (all of the above)** | **≈ 28,600** | **29,969** |
| of which regex rules (limit 1,000) | ≈ 280 | 277 |
| Optional: `annoyances` | ≈ 3,500 | 3,376 |
| Optional: `social` | 596 | 596 |
| Optional: `url-tracking` | 2,165 | 4,169 |
| Optional: `block-lan` | – | 20 |
| Optional: `hagezi-tif`, `hagezi-pro` | – | 2 each |
| Optional: `anti-facebook` | – | 64 |
| Optional: `easylist-chat` | – | 71 |
| Optional: `easylist-ai` | – | 10 |
| Optional: `adguard-popups` | – | 1,687 |

The largest differences to the estimate: `ublock-badware`, whose strict-block navigation rules are static rules in Bastion Shield (uBO Lite keeps them as session rules), and the optional `url-tracking`, where parameter-removal rules are compiled differently (to be investigated).

Consequences:

- **Budget headroom**: with all three regional lists on, the default set would be about 29,800 of the 30,000 guaranteed rules. French and Italian therefore follow the user's languages (section 3); the manifest default (German only) leaves about 5,000 rules of headroom for list growth. `.github/scripts/check-budget.ts` fails CI above 30,000 and warns below 500 rules of headroom.
- Enabling optional lists can go beyond 30,000. Chromium then takes rules from the shared pool. If another extension has used it up, enabling the list fails; the dashboard shows the error and the list stays off. Nothing else is affected.
- `annoyances` uses Fanboy's `_ubo` Annoyances list, which includes the Social and Cookie lists; enabling it on top of `cookies` duplicates those rules.
- URL-level malware and phishing lists (URLhaus URL-level: 22,169 rules; the phishing list: 26,523) would not fit the budget and are not shipped. Domain-level security lists cost one rule each.

---

## 5. Licences and attribution

Compiling a filter list into Chromium's rule format creates an adapted version of the list. Each compiled ruleset therefore stays under its list's licence, and we attribute and mark the change: **"converted to Chromium DNR format by Bastion Shield"**, which CC BY-SA requires. The full notice is in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md); the dashboard's About page shows each list's licence and attribution from the catalog.

| List(s) | Licence | Attribution | Notes |
|---|---|---|---|
| `bastion` | GPL-3.0-or-later | Bastion GmbH i. Gr. and contributors | |
| `ublock`, `ublock-privacy`, `ublock-badware`, `url-tracking`, uAssets parts of `cookies` and `annoyances` | GPL-3.0 | uBlock Origin / uAssets contributors | `privacy-removeparam.txt` builds on AdGuard's URL tracking list (GPL-3.0). |
| `easylist`, `easyprivacy`, `regional-de`, `regional-it`, `social` | GPL-3.0-or-later **or** CC BY-SA 3.0 (dual) | The EasyList authors (https://easylist.to/) | We use them under the GPL option. The dual licence explicitly covers EasyList, EasyPrivacy, EasyList Germany, EasyList Italy and the contents of the EasyList repository ([easylist.to/pages/licence.html](https://easylist.to/pages/licence.html)). |
| Fanboy `_ubo` files (`cookies`, `app-promos`, `annoyances`) | CC BY 3.0 (per the file headers on secure.fanboy.co.nz) | The EasyList authors (Fanboy) | Attribution and change marking. |
| `regional-fr` | GPL-3.0 | AdGuard and the Liste FR authors | Contains Liste FR, which is published under CC BY-SA 3.0. Whether AdGuard's GPL release relicenses that part is not settled; we attribute Liste FR separately and treat that content as CC BY-SA 3.0 (adaptations may use BY-SA 4.0, which is one-way compatible with GPLv3). |
| `brave`, `brave-firstparty`, Brave part of `cookies`, `query-filter.json`, `debounce.json` | MPL-2.0 | Brave Software, Inc. and contributors | File-level copyleft: the compiled files stay MPL-2.0 and their source form is published (below). MPL-2.0 is compatible with distribution inside a GPL program. |
| `peter-lowe` | no formal licence; the author's site says "Feel free to combine this list with yours or lists from other sites and put it up on the web" | Peter Lowe (https://pgl.yoyo.org/) | uBlock Origin and uBO Lite ship it. **Open item:** written confirmation from the author for distribution by a commercial MSP. |
| `urlhaus` | malware-filter's list: CC0 / MIT; data: abuse.ch URLhaus | curbengh (malware-filter), data by abuse.ch | **Open item:** abuse.ch's terms of use (November 2025) say commercial or for-profit use may require a paid subscription managed by Spamhaus, and its pages no longer state CC0. abuse.ch is based in Zurich; Bastion clarifies this with abuse.ch before the first store release. If they do not agree, the list leaves the default set. |

### Corresponding source (GPL)

The GPL requires that whoever receives the compiled rules can get the source they were built from. For every release:

- the **extension source** is the tagged commit (`v<version>`) in this repository, including the compiler (`src/compiler/`) and build tools (`tools/`);
- **`filters/lock.json`** records URL, SHA-256, size and the `Version`/`Last-Modified` of every fetched list;
- **`bastion-shield-<version>-filter-sources.tar.gz`** contains the raw list snapshots the build consumed;
- all are attached to the GitHub release, with `SHA256SUMS.txt`.

With these files anyone can rebuild the same rulesets: check out the tag, `npm ci`, unpack the snapshot archive in the repository root (it restores `.cache/lists/` and the `filters/` files), then `npm run build:offline`.

---

## 6. "Known advertising companies" data

Customers ask whether Bastion Shield blocks "all known advertising companies". The honest answer: it blocks what the lists above contain, and the lists are the industry-standard ones. Ready-made "company" databases exist, but most cannot be shipped in a product an MSP gives to customers:

| Source | Licence | Usable? |
|---|---|---|
| Peter Lowe's list (hand-checked ad and tracking servers, validated weekly) | informal permission (above) | yes, shipped |
| EasyList's ad-server section (`easylist_adservers`, ~50,000 rules) and EasyPrivacy's tracking-server and per-vendor CNAME sections (Adobe, Oracle, Criteo, Branch, …) | GPL / CC BY-SA | yes, shipped; the best "known companies" source we can use |
| Disconnect tracking-protection lists | CC BY-NC-SA 4.0 | **no**: non-commercial; commercial licence on request |
| DuckDuckGo Tracker Radar and Tracker Blocklists | CC BY-NC-SA 4.0 | **no** without a licence |
| Ghostery TrackerDB | CC BY-NC-SA 4.0 | **no** without a licence |
| WhoTracks.me / AdGuard companiesdb | CC BY 4.0 / CC BY-SA 4.0 | unclear: their tracker data now derives from Ghostery's NC-licensed database |
| Phishing URL blocklist (malware-filter) | CC BY-SA 4.0, but built from OpenPhish, whose terms forbid commercial use including "customer protection" | **no** |

The activity view therefore shows the blocked hostname and the list that blocked it, not a company name. Vendor names may be added later from EasyPrivacy's section names or a Bastion-maintained CC BY-SA mapping, never from NC-licensed data.

---

## 7. Community and reporting

### The Bastion list

[`filters/bastion.txt`](../filters/bastion.txt) is small and Swiss-focused: Swiss publishers and consent tools, and unbreak rules for customer environments (it keeps Microsoft Entra sign-in working, for example). It is licensed GPL-3.0-or-later, uses uBlock Origin syntax, and every filter is preceded by a comment linking the GitHub issue that motivated it. It is on by default. Users can switch it off like any other list (Microsoft sign-in may then break if another list blocks it); administrators can force it on and lock it with the `lists` policy, for example `{"bastion": true}` (section 10.3 of [ARCHITECTURE.md](ARCHITECTURE.md#103-locks)).

### Upstream first

Fixes belong where the most people benefit:

| Problem | Where it goes |
|---|---|
| Ad or tracker missed on many sites, generic ABP-syntax fix | [EasyList](https://github.com/easylist/easylist) / EasyPrivacy (issues preferred over pull requests) |
| German-language site | [EasyList Germany](https://github.com/easylist/easylistgermany) |
| French-language site | AdGuard ([reporting tool](https://agrd.io/report)), which also carries Liste FR |
| Italian-language site | [EasyList Italy](https://github.com/easylist/easylistitaly) |
| Needs uBO extended syntax or a scriptlet, anti-adblock, site breakage caused by uAssets | [uBlockOrigin/uAssets](https://github.com/uBlockOrigin/uAssets) (every filter there carries its issue link; new filters are appended) |
| Brave list problem | [brave/adblock-lists](https://github.com/brave/adblock-lists) |
| Swiss-only, customer-specific, or urgent until upstream ships | Bastion list (and still reported upstream) |

Bastion staff contribute upstream from Bastion's GitHub organisation.

### How users report, without giving up privacy

The popup's "Report a broken site" button, configurable by administrators (`reportBrokenSite`):

- **`github`** (default): opens a prefilled issue form in a new tab with the **hostname only** (no path, query or fragment), browser and extension version, blocking mode and enabled list ids. The user sees everything, can edit it and submits it from their own GitHub account. Bastion Shield itself sends nothing.
- **`email`**: opens the user's mail program with the same information addressed to the organisation's `supportEmail`.
- **`none`**: hides the button (managed environments with their own process).

Bastion triages reports, fixes urgent cases in the Bastion list for the next weekly release, and forwards generic cases upstream.

---

## 8. Update cadence

Static rules ship inside the extension, so filter updates arrive as extension updates. The goal is "fire and forget": nobody has to do anything.

- **Weekly automated release**, every Monday 03:00 UTC, plus on-demand releases for urgent fixes. The release workflow fetches all lists, builds, tests, publishes a GitHub release and submits to both stores; it skips the week when nothing changed ([RELEASING.md](RELEASING.md)).
- **Chrome Web Store**: normal review usually takes a few days and can take longer. Updates that only change *safe* static network rules (block/allow) qualify for **skip review** and go live within minutes. A typical weekly release also changes cosmetic data and therefore goes through normal review; the workflow detects eligibility automatically.
- **Microsoft Edge Add-ons**: certification takes up to 7 business days for every update, so Edge users typically run one release behind Chrome users.
- **Browsers** check for extension updates shortly after start and then about every 5 hours.

List authors publish more often (uBlock's quick fixes every 8 hours, EasyList every few days). A weekly cadence is a deliberate trade-off between freshness, store review load and stability. A hot-fix channel that ships a small set of safe rules as data between releases is under consideration; it would need care with the Edge Add-ons policy, which says rules "should not be imported remotely unless necessary for functionality".

---

## 9. Adding a list

1. **Licence check.** The licence must allow redistribution, including by a for-profit company giving the product to its customers. No NC (non-commercial) licences, no terms that forbid "commercial use" or "customer protection". Record the licence URL.
2. **Syntax.** Prefer a uBlock Origin flavour. Check for `!#include` targets (only same-origin includes are expanded) and for options our compiler rejects (see the build report's "unsupported" reasons).
3. **Value.** Does it add something the default stack lacks? Overlapping lists cost rule budget and package size without blocking more.
4. **Catalog entry** in [`filters/catalog.json`](../filters/catalog.json): stable id (`[a-z0-9-]+`, becomes the ruleset id; never rename it later, because administrators reference it), names and descriptions in `en`, `de` (Swiss orthography), `fr`, `it`, category, `default`, `firstPartyProtected` (true only for lists Brave also runs in its first-party-protected engine), `trusted` (only for lists from uBlock Origin, Brave or Bastion; a trusted list that includes a third-party source marks that source `"trusted": false`), `strictBlock`, sources, homepage, licence, licence URL and attribution.
5. **Build** (`npm run build`) and read the report: rule count, regex count, unsupported filters, total budget. The default set must stay under 30,000 rules.
6. **Test** with `npm run test:e2e` and on a few real sites in Standard and Aggressive mode.
7. **Document**: add the list to the tables in this file and to [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
8. Open a pull request.

---

## 10. Lists users import («My lists»)

Beyond the catalog, users can import any list under **Filter lists › My lists**: upload a `.txt` file (uBlock Origin, Adblock Plus or hosts format) or enter an `https://` address. Up to 20 lists of 10 MB each.

- **Files** stay exactly as uploaded. «Replace…» swaps in a new file and keeps the list's name and switch. Uploading a file whose `! Title:` matches an existing list asks whether to replace that list or add a new one.
- **Web addresses** are downloaded when added and, with «Update daily» on (the default), about once a day; «Update now» fetches at once. A failed download keeps the last good copy and shows the error on the list. This is the only time Bastion Shield itself downloads anything ([PRIVACY.md](PRIVACY.md)).
- Imported lists are compiled in the browser like the user's own filters: network filters become dynamic rules (30,000 shared with «My filters», of which 5,000 redirect/header rules and 1,000 regex rules), cosmetic filters apply, **scriptlets are skipped** (Manifest V3 forbids code that is not in the package), and nothing in them is trusted: `@@…$important` exceptions are refused, so an imported list cannot lift the `$important` blocks of the built-in lists. The user's own filters always get the budget first; rules that do not fit are reported on the list.
- Licences are the user's business for lists they import; Bastion does not redistribute them.
- Administrators: `allowCustomLists: false` (or `lockSettings` without `allowCustomLists: true`) forbids imports **and switches off lists imported earlier** ([DEPLOYMENT-INTUNE.md](DEPLOYMENT-INTUNE.md)). To give a whole fleet an extra list, use the `lists` policy for catalog lists or `customFilters` for your own filters.
