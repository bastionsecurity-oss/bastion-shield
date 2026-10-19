# Bastion Shield

[![CI](https://github.com/bastion-security/bastion-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/bastion-security/bastion-shield/actions/workflows/ci.yml)
[![Licence: GPL-3.0-or-later](https://img.shields.io/badge/licence-GPL--3.0--or--later-blue.svg)](LICENSE)

A lean, open-source ad and tracker blocker for Chromium browsers (Google Chrome, Microsoft Edge, Brave), built on Manifest V3. It blocks as well as Brave Shields in its default mode, shows exactly what it blocked and why, keeps everything on your device, and can be deployed and configured centrally with Microsoft Intune.

Made by [Bastion GmbH i. Gr.](https://bastionsecurity.ch), a cyber-security MSP in Zurich, for its customers and for everyone else.

## Kurz auf Deutsch

Bastion Shield ist ein schlanker, quelloffener Werbe- und Tracker-Blocker für Chrome, Edge und Brave. Er blockiert so gut wie Brave Shields im Standardmodus und verwendet dieselben bewährten Filterlisten (uBlock Origin, EasyList, EasyPrivacy, Brave) sowie die Regionallisten für Deutsch, Französisch und Italienisch, die in der Schweizer Ausgabe alle eingeschaltet sind.

- **Schnell:** Das Blockieren erledigt der Browser selbst (declarativeNetRequest); pro Anfrage läuft kein Erweiterungscode.
- **Transparent:** Für jede blockierte Anfrage zeigt Bastion Shield die Liste und die Filterregel. Der Quellcode ist offen (GPL-3.0).
- **Privat:** Nichts verlässt das Gerät. Keine Telemetrie, kein Konto, keine Fernkonfiguration. Der Verlauf bleibt lokal und lässt sich abschalten.
- **Für Unternehmen:** Installation und Konfiguration über Intune («Verwaltet von …»), siehe [docs/DEPLOYMENT-INTUNE.md](docs/DEPLOYMENT-INTUNE.md).
- **Aktuell ohne Aufwand:** Jede Woche erscheint automatisch eine neue Version mit frischen Filterlisten.

---

## Features

**Blocking**
- Network blocking with the same lists as Brave Shields: uBlock filters, EasyList, EasyPrivacy, Brave's lists, uBlock's badware list, URLhaus, cookie-notice and app-banner lists, plus Peter Lowe's list and Bastion's own Swiss list ([FILTER-LISTS.md](docs/FILTER-LISTS.md)).
- More vetted lists to switch on (HaGeZi, LAN protection, chat and AI widgets, …), and any other list imported from a file or a web address («My lists»; web lists can update themselves daily).
- Brave's two modes: **Standard** (does not block first-party requests on the lists Brave protects, for fewer broken sites) and **Aggressive**, globally or per site.
- Cosmetic filtering (site-specific, generic, procedural `:has-text()` and friends, `:style()`), uBlock Origin scriptlets against anti-adblock walls and cookie banners, harmless stand-ins for blocked ad scripts.
- Warning page for known malware and scam domains, with "proceed anyway".

**Live activity and history**
- Toolbar badge with the blocked count (counted by the extension while Global Privacy Control is on, otherwise by the browser).
- Live view per tab: every blocked, redirected or cleaned request, with the list and the original filter text that matched.
- Local history with daily statistics (most blocked hosts, sites, categories), 30 days by default, deletable, can be switched off.

**Per-site control**
- Protection on/off, Standard/Aggressive, block JavaScript, fingerprinting level, per site.
- Custom filters in uBlock Origin syntax.

**Privacy protections**
- Global Privacy Control (`Sec-GPC: 1`), tracking-parameter removal (Brave's list), bounce-tracking skip (Brave's debounce list), AMP-to-publisher redirect.
- Fingerprinting protection for canvas, WebGL, Web Audio and navigator properties, with a per-site, per-session seed.
- Hyperlink auditing (`<a ping>`) and the Privacy Sandbox ad APIs switched off; optional WebRTC and third-party cookie settings.

**For administrators**
- Every setting can be set and locked through `chrome.storage.managed`; Intune kit with Settings Catalog entries, an idempotent remediation script and macOS profiles ([DEPLOYMENT-INTUNE.md](docs/DEPLOYMENT-INTUNE.md), [policy/](policy/README.md)).
- Fleet-wide emergency switch (`protectionEnabled: false`) that turns protection off on every device without uninstalling ([DEPLOYMENT-INTUNE.md §9](docs/DEPLOYMENT-INTUNE.md#9-emergency-switch-protection-off-fleet-wide)).
- Weekly automated releases with fresh lists; nothing to maintain on the devices.
- UI in German (Swiss orthography), French, Italian and English.

## Compared with Brave Shields

Bastion Shield ships Brave's default list stack and copies Brave's Standard-mode semantics, so on network and cosmetic blocking it is on par with Brave Shields' default. As an extension, some things work differently or not at all. The full matrix and measured results are in [PARITY.md](docs/PARITY.md).

**What matches:** the filter lists (including Brave's own), Standard vs Aggressive, scriptlets, redirect resources, query-parameter stripping, Global Privacy Control, the main fingerprinting protections, the domain warning page, central management.

**What an MV3 extension cannot do:**
- **CNAME uncloaking.** Extensions get no DNS information before a request; trackers disguised as first-party subdomains are caught only when the lists name them (EasyPrivacy has large per-vendor sections for this). Brave's Standard mode does not uncloak first-party requests either, so the gap against Brave's default is small.
- **Fingerprinting protection inside workers**, font-list limiting and some of Brave's minor farbling (screen, plugins).
- **`$redirect-rule`**, `$popup` and a few other filter options that declarativeNetRequest has no equivalent for (rejected at build time, listed in the build report).
- **List updates between releases.** Brave refreshes its lists about every 100 minutes; Bastion Shield's rules change with each (weekly) release, and store review adds delay, up to 7 business days on Edge.
- HTTPS upgrading and third-party cookie blocking are browser features; we recommend the browser policies instead ([DEPLOYMENT-INTUNE.md §6](docs/DEPLOYMENT-INTUNE.md#6-complementary-browser-policies)).

**Not yet:** an element picker and Brave's "forget me when I close this site".

**Why network blocking is still native speed:** Bastion Shield compiles its lists at build time into Chromium's declarativeNetRequest format. The browser matches every request in its own network code, like Brave's built-in engine does; no extension JavaScript runs per request, and the service worker sleeps when nothing happens. Per-page work is limited to small content scripts that look the current site up in prebuilt tables.

**On Brave itself:** Shields blocks before any extension sees a request, so Bastion Shield's counts are lower there and its per-site "off" cannot unblock what Shields blocks.

## Quick start (development)

Requirements: Node.js 22.18 or newer (CI uses Node 24; TypeScript runs natively, no transpile step for tools), and Chrome, Edge or Brave 128+.

```sh
npm ci
npm run build          # fetches the filter lists (cached in .cache/lists), compiles, writes dist/
npm run validate       # loads a copy of dist/ in Playwright's Chromium; records regexes Chromium rejects
npm run build:offline  # same build, using only the cached lists (drops the regexes validate recorded)
npm run package        # store zips in dist-pkg/
npm test               # unit tests
npm run test:e2e       # loads a copy of dist/ into Playwright's Chromium and tests blocking on fixture pages
```

Load the build:

1. Open `chrome://extensions`, `edge://extensions` or `brave://extensions`.
2. Switch on **Developer mode**.
3. **Load unpacked** and choose the `dist/` folder.

After changing code, run `npm run build` again and click the reload button on the extension card. Loading the unpacked build also validates every network rule: Chromium refuses to load an unpacked extension with an invalid rule. Chromium writes a `_metadata/` folder into any folder it loads unpacked; `npm run package` leaves it out, and the tests load a copy of `dist/` instead.

The build report (`dist/build-report.json`, also printed) lists rule counts per list, the rule budget and every filter that could not be converted, with the reason.

Chromium's regex engine has a memory limit that can only be checked in a browser, so CI builds twice: `npm run build`, `npm run validate`, then `npm run build:offline` from the same cached lists ([RELEASING.md](docs/RELEASING.md#continuous-integration-githubworkflowsciyml)).

## Project layout

```
filters/          list catalog (catalog.json), Bastion's own list (bastion.txt), lock.json written by the build
src/shared/       constants and types shared by everything (the architecture contract)
src/compiler/     filter compiler: uBO/ABP syntax to declarativeNetRequest rules, cosmetic and scriptlet data
src/background/   service worker
src/content/      content scripts (cosmetic filtering, procedural filters)
src/main/         page-world privacy script (GPC, fingerprinting protection)
src/ui/           popup and dashboard
src/pages/        warning page for blocked domains, bounce-tracking page
src/_locales/     en, de, fr, it
tools/            build pipeline (fetch lists, compile, package)
vendor/           pinned third-party code: uBlock Origin scriptlets and resources, Brave resources and lists
policy/           managed-storage schema and Intune / registry / macOS examples
test/             unit and end-to-end tests
docs/             architecture and the documents below
.github/          CI, weekly release, issue templates
```

## Documentation

| Document | For |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How it works, and the contract between the components |
| [docs/FILTER-LISTS.md](docs/FILTER-LISTS.md) | Which lists ship and why, Swiss regional strategy, rule budget, licences, reporting, update cadence |
| [docs/PARITY.md](docs/PARITY.md) | Feature-by-feature comparison with Brave Shields, measured results |
| [docs/PRIVACY.md](docs/PRIVACY.md) | What is stored, what is never collected, why each permission is needed |
| [docs/DEPLOYMENT-INTUNE.md](docs/DEPLOYMENT-INTUNE.md) | Deploying and configuring with Microsoft Intune (Edge, Chrome, Brave; Windows, macOS) |
| [policy/README.md](policy/README.md) | The policy kit: schema, registry files, PowerShell script, macOS profiles |
| [docs/RELEASING.md](docs/RELEASING.md) | Versioning, CI, weekly releases, store publishing, signing key |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Filter contributions, code style, tests |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities |
| [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | Licences of included code, fonts and filter lists |

## Licence

Bastion Shield is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. See [LICENSE](LICENSE).

It includes code and data from other projects under their own licences (GPL-3.0, MPL-2.0, OFL-1.1, CC BY-SA, CC BY and others); see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The compiled rulesets are generated from the filter lists listed there; the exact inputs of every release are attached to its GitHub release.

## Credits

Bastion Shield stands on the work of the people who maintain the filter lists and the blocking tools the web relies on:

- [uBlock Origin](https://github.com/gorhill/uBlock) by Raymond Hill and contributors, and the [uAssets](https://github.com/uBlockOrigin/uAssets) filter maintainers: scriptlets, redirect resources, filter lists, uBlock Origin Lite's MV3 design, which showed the way, and its procedural filtering engine, which Bastion Shield ports.
- [EasyList](https://easylist.to/) authors: EasyList, EasyPrivacy, EasyList Germany, EasyList Italy, Fanboy's lists.
- [Brave](https://github.com/brave/adblock-lists): Brave's filter lists, resources, debounce and query-filter data, and Brave Shields as the benchmark.
- [AdGuard](https://github.com/AdguardTeam/AdguardFilters) and the Liste FR authors: French filters.
- [Peter Lowe](https://pgl.yoyo.org/adservers/): ad and tracking server list.
- [malware-filter](https://gitlab.com/malware-filter/urlhaus-filter) by curbengh, with data from [abuse.ch URLhaus](https://urlhaus.abuse.ch/).
- Fonts: Inter and Inter Tight (The Inter Project Authors), IBM Plex Mono (IBM).

Bastion Shield is not affiliated with or endorsed by Brave Software, Google, Microsoft, the uBlock Origin project, EasyList or AdGuard. Chrome, Edge and Brave are trademarks of their respective owners.
