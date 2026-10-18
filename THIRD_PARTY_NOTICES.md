# Third-party notices

Bastion Shield is Copyright (C) 2026 Bastion GmbH i. Gr. and contributors, licensed under the GNU General Public License, version 3 or (at your option) any later version ([LICENSE](LICENSE)).

The extension package contains code, data and fonts from the projects below. Each keeps its own licence and copyright. Licence texts are in this repository at the paths given, and in the extension package in the `licenses/` folder (together with this file and `VENDOR.json`).

## 1. Vendored code and data

Pinned in [`vendor/VENDOR.json`](vendor/VENDOR.json); the files in `vendor/` are copies of the upstream files at those commits.

### uBlock Origin

- Project: https://github.com/gorhill/uBlock, commit `2818335553a853edb12c02acd8ad98548e232202`
- Copyright (C) 2014-present Raymond Hill and the uBlock Origin contributors
- Licence: GNU General Public License v3.0 or later. Text: [`vendor/ublock/LICENSE.txt`](vendor/ublock/LICENSE.txt)
- Files: the scriptlet library (`src/js/resources/*.js`), redirect resources (`src/web_accessible_resources/*`, `src/js/redirect-resources.js`), `src/js/urlskip.js`, `src/js/arglist-parser.js`, `src/js/jsonpath.js`
- Use: the build serialises the scriptlets that the shipped lists use into the scriptlet files of the package, and copies the redirect resources that the lists reference into the package.
- **Ported code** (same repository and commit, Copyright (C) Raymond Hill, GPL-3.0-or-later, modified by Bastion):
  - `src/content/procedural-engine.ts`, shipped in `content/procedural.js`, is a TypeScript port of uBlock Origin Lite's procedural filtering engine, `platform/mv3/extension/js/scripting/css-procedural-api.js`.
  - `src/content/procedural-args.ts`, also shipped in `content/procedural.js`, follows the procedural-argument parsing of `src/js/static-filtering-parser.js`.

  Both files carry a `/*! … */` legal comment that the bundler keeps in `content/procedural.js`.
- **Exception:** `web_accessible_resources/google-ima.js` is based on Mozilla source code (Firefox's web-compatibility shim for Google IMA, https://searchfox.org/mozilla-central/rev/d317e93d9a59c9e4c06ada85fbff9f6a1ceaaad1/browser/extensions/webcompat/shims/google-ima.js) and is licensed under the **Mozilla Public License 2.0**, with uBlock Origin's modifications listed in its header. The MPL-2.0 notice is kept in the file; its source form is the file itself.

### Brave ad-block resources

- Project: https://github.com/brave/adblock-resources, commit `6da9b247c3368baa8b4f24cd02046e18702a6527`
- Copyright Brave Software, Inc. and contributors
- Licence: Mozilla Public License 2.0. Text: [`vendor/brave-resources/LICENSE`](vendor/brave-resources/LICENSE)
- Files: `resources/*.js` (Brave-specific scriptlets such as `brave-fix.js` and `de-amp.js`), `metadata.json`
- Use: scriptlets that Brave's filter lists reference, where their format is compatible.
- Note: `vaft-ublock-origin.js` and `video-swap-new-ublock-origin.js` are derived from third-party work (Twitch ad-workaround scripts). Their upstream provenance and licence are under review; they are only shipped if a shipped list references them.

### Brave ad-block lists data

- Project: https://github.com/brave/adblock-lists, commit `8846788d578bf89696ad4ec5cdff845dfb170f1a`
- Copyright Brave Software, Inc. and contributors
- Licence: Mozilla Public License 2.0. Text: [`vendor/brave-lists/LICENSE`](vendor/brave-lists/LICENSE)
- Files: `brave-lists/debounce.json` (bounce-tracking rules), `brave-lists/query-filter.json` (tracking parameters)
- Use: compiled into the `bastion-params` ruleset and the debounce rules.

MPL-2.0 is a file-level licence. The MPL-covered files above are available in Source Code Form in this repository (`vendor/`) and in the source of every release; the generated rules derived from them are distributed under the MPL-2.0 as well.

## 2. Fonts

The fonts are distributed as WOFF2 files from the [Fontsource](https://fontsource.org/) packages (`@fontsource-variable/inter`, `@fontsource-variable/inter-tight`, `@fontsource/ibm-plex-mono`, version 5.3.0), unmodified by Bastion. All are licensed under the **SIL Open Font License 1.1**; the licence texts are in [`src/ui/shared/fonts/`](src/ui/shared/fonts/).

| Font | Copyright | Licence file |
|---|---|---|
| Inter | Copyright 2016 The Inter Project Authors (https://github.com/rsms/inter) | `LICENSE-Inter.txt` |
| Inter Tight | Copyright 2022 The Inter Project Authors (https://github.com/rsms/inter-tight) | `LICENSE-InterTight.txt` |
| IBM Plex Mono | Copyright 2017 IBM Corp. | `LICENSE-IBMPlexMono.txt` |

## 3. Filter lists

The extension contains rulesets compiled from the filter lists below. The lists are the work of their authors. **Each list was converted to Chromium declarativeNetRequest format (and to cosmetic and scriptlet data files) by Bastion Shield**; filters that cannot be expressed in that format were left out, and the build report lists them. Each converted list remains under its original licence. The exact source files of every release (URL, SHA-256, version) are recorded in `filters/lock.json` and attached, as raw snapshots, to the release on GitHub. Details and open licence questions: [docs/FILTER-LISTS.md §5](docs/FILTER-LISTS.md#5-licences-and-attribution).

| List (catalog id) | Source | Licence | Attribution |
|---|---|---|---|
| Bastion filters (`bastion`) | this repository, `filters/bastion.txt` | GPL-3.0-or-later | Bastion GmbH i. Gr. and contributors |
| uBlock filters (`ublock`), uBlock filters – Privacy (`ublock-privacy`), Badware risks (`ublock-badware`), Tracking parameters (`url-tracking`) | https://github.com/uBlockOrigin/uAssets | GPL-3.0 | uBlock Origin / uAssets contributors; `privacy-removeparam.txt` builds on the AdGuard URL Tracking filter (AdGuard, GPL-3.0) |
| EasyList (`easylist`), EasyPrivacy (`easyprivacy`), EasyList Germany (`regional-de`), EasyList Italy (`regional-it`), Fanboy's Social (`social`) | https://easylist.to/ | GPL-3.0-or-later or CC BY-SA 3.0 (dual; used under the GPL) | The EasyList authors (https://easylist.to/) |
| Fanboy's Cookiemonster, Mobile Notifications and Annoyance lists, uBlock Origin flavour (parts of `cookies`, `app-promos`, `annoyances`) | https://secure.fanboy.co.nz/ | CC BY 3.0 (per file headers) | The EasyList authors (Fanboy). Converted to Chromium DNR format by Bastion Shield. |
| uBlock annoyance lists (parts of `cookies`, `annoyances`) | https://github.com/uBlockOrigin/uAssets | GPL-3.0 | uBlock Origin / uAssets contributors |
| Brave lists (`brave`, `brave-firstparty`, part of `cookies`) | https://github.com/brave/adblock-lists | MPL-2.0 | Brave Software, Inc. and contributors |
| AdGuard French (`regional-fr`) | https://github.com/AdguardTeam/AdguardFilters (uBlock flavour from filters.adtidy.org) | GPL-3.0 | AdGuard. Contains Liste FR (https://github.com/easylist/listefr), CC BY-SA 3.0, by the Liste FR authors; converted to Chromium DNR format by Bastion Shield. |
| Peter Lowe's ad and tracking server list (`peter-lowe`) | https://pgl.yoyo.org/adservers/ | distributed with the author's permission as stated on his site | Peter Lowe |
| Online Malicious URL Blocklist (`urlhaus`) | https://gitlab.com/malware-filter/urlhaus-filter | CC0 / MIT (list); data from abuse.ch URLhaus under abuse.ch's terms of use | curbengh (malware-filter); data by abuse.ch (https://urlhaus.abuse.ch/) |

## 4. Tools used to build (not distributed)

These are development dependencies; no part of them is included in the extension package: TypeScript (Apache-2.0), esbuild (MIT), Playwright and Playwright's Chromium (Apache-2.0; Chromium under its own BSD-style licences), DefinitelyTyped type packages (MIT).

Brave's adblock-rust (MPL-2.0) was used as a reference for behaviour. uBlock Origin Lite was used as a reference too, except for the procedural filtering engine, which is a port and is included (section 1).

## 5. Trademarks

Chrome is a trademark of Google LLC. Microsoft Edge is a trademark of the Microsoft group of companies. Brave is a trademark of Brave Software, Inc. uBlock Origin, EasyList and AdGuard are names of their respective projects. Bastion Shield is not affiliated with or endorsed by any of them.
