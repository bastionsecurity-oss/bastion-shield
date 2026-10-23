# Privacy

**Bastion Shield does not send any data anywhere.** It has no telemetry, no analytics, no crash reporting, no remote configuration, no account and no server. Everything it records stays in your browser profile on your device, and you can switch recording off or delete it at any time.

This page describes exactly what is stored, for how long, what is never collected, and why the extension needs each browser permission. It applies to all builds published by Bastion Security GmbH in the Chrome Web Store, in Microsoft Edge Add-ons and on GitHub.

## Network traffic

- The extension makes **no network requests of its own**, with one exception that you start yourself: a filter list you add **by web address** (Filter lists › My lists) is downloaded from that address when you add it, when you click «Update now», and about once a day while «Update daily» is on. The request carries no cookies, credentials or referrer and uses conditional headers so an unchanged list is not downloaded again; the list's site sees your IP address, as with any download. Lists you upload as a file are never fetched. Administrators can forbid imported lists (`allowCustomLists: false`). Everything else (filter lists, cosmetic data, scriptlets, fonts and icons) is inside the installed package and read from the extension's own files.
- Filter lists are updated by **publishing a new extension version**. Your browser checks the store (Chrome Web Store or Edge Add-ons) for extension updates, as it does for every extension; that check is made by the browser, under the store's privacy policy, not by Bastion Shield.
- **"Report a broken site"** only acts when you click it. Depending on your organisation's setting it opens a GitHub issue form in a new tab with the hostname (no path, query or fragment), browser version, extension version, blocking mode and enabled list ids filled in, or your e-mail program with the same text. You see everything and decide whether to submit. Submitting a GitHub issue publishes it under your GitHub account.

## What is stored on your device

All data is stored in the browser profile, in storage areas that only the extension's own pages and service worker can read (content scripts and websites cannot).

| Data | Where | Content | Kept |
|---|---|---|---|
| Settings | `chrome.storage.local` (`settings`) | your choices: lists, blocking mode, privacy options, badge, history options | until changed or uninstalled |
| Per-site settings | `chrome.storage.local` (`sites`) | hostnames where you changed protection, mode, script blocking or fingerprinting level | until changed or uninstalled |
| Custom filters | `chrome.storage.local` (`customFilters`) | the filters you typed | until changed or uninstalled |
| Imported lists | `chrome.storage.local` (`myLists`, `myList:<id>`, `myListCompiled:<id>`) | the lists you imported, their file name or web address, when they were last downloaded, and their compiled form | until you remove them or uninstall |
| Totals | `chrome.storage.local` (`totals`) | counters (blocked, redirected, parameters removed, …) since a date | until reset or uninstalled |
| Install info, fingerprinting seed choice | `chrome.storage.local` (`install`, `seedPick`) | installation metadata (for example the installed version, used to migrate settings); which of the bundled random seed files are active this browser session | until uninstalled; the seed changes at every browser start |
| Live activity | memory; a shorter copy in `chrome.storage.session` (also memory only) so that a restart of the extension's service worker does not lose it | the last 300 blocking events per open tab: time, request URL, hostname, resource type, page site, list and rule that matched. The copy holds the counts, up to 500 third-party hostnames and the newest 50 events, without query strings | until the tab navigates or closes, and at the latest until the browser closes |
| Blocking history | IndexedDB `bastion-activity` (`events`) | the same events, but the URL **without query string and fragment** | 30 days by default (configurable, 0 = today's totals only), at most 50,000 events; pruned daily |
| Daily statistics | IndexedDB `bastion-activity` (`daily`) | per day: counts by kind, category and resource type; the 500 most blocked hostnames and the 500 sites with most blocking | same retention as the history |

With history switched off (dashboard, or `historyEnabled: false` by policy), nothing is persisted except the totals. What switching off the live activity log changes is described in [What the extension observes](#what-the-extension-observes).

You can delete the history from the dashboard at any time. Uninstalling the extension deletes all of the above.

The history stores the path of blocked requests (not their query strings). Paths can occasionally contain identifiers. If that matters in your environment, shorten the retention or switch history off.

**Private windows (Incognito, InPrivate).** The extension runs there only if you or your administrator allow it. It then runs as a separate instance ("split" mode). Nothing about private browsing is persisted: no history events, no daily statistics, and the totals are counted in memory only. The live activity of private tabs is kept in memory and is gone when the private session ends. Settings are shared with normal windows, so a setting you change in a private window is saved like any other setting.

**Backups.** The dashboard's backup export saves a file with your settings, per-site settings and custom filters (no history) to a location you choose.

## What the extension observes

To show what it blocked, the extension's service worker is notified by the browser (`webRequest`, read-only) when a request was **blocked or redirected** by Bastion Shield's rules. It is not notified of requests that load normally, and it never sees request or response contents.

- **Live activity log on** (default): each blocked or redirected request becomes an event in the live activity (table above) and, with history on, in the history.
- **Live activity log off** (`activityLog: false`): no request events are kept, shown or written to the history. While the toolbar badge and Global Privacy Control are both on (the defaults), the extension still observes blocked and redirected requests to count them for the badge and the totals; it keeps only per-tab counts (no addresses or hostnames), in memory and in `chrome.storage.session`, plus the totals. The browser cannot count the badge itself in this configuration, because it would count every request that carries the Global Privacy Control header.
- To stop this observation, switch the badge off (`showBadge: false`); with Global Privacy Control off, the browser counts the badge itself. One observation always stays: when a page is sent to the warning page for dangerous sites, the extension records that page's address in memory, so that the warning page can show it and offer to go back or proceed.

## What websites can see

Bastion Shield does not announce itself to websites, but it is not invisible:

- With Global Privacy Control on, every request carries the `Sec-GPC: 1` header and pages see `navigator.globalPrivacyControl = true`. That is the purpose of the signal; other browsers and extensions send it too.
- Blocked requests fail, and some blocked scripts are replaced by harmless stand-ins. Websites can notice that some content blocker is active, as with any blocker.
- The stand-ins and pages are web-accessible resources with dynamic URLs, which stops websites from probing for the extension directly. They do not hide it completely: when a page itself fetches a script (`fetch`, `XMLHttpRequest`) that Bastion Shield replaces with a stand-in, the browser exposes the stand-in's address, `chrome-extension://<extension id>/war/…`, in the response. A website can therefore detect Bastion Shield and read its extension id. For store installs the id is public anyway; for a self-hosted build it identifies the organisation's own signing key. This is a limitation of the browser platform (Manifest V3), not something the extension sends.

## What is never collected

- page content, form input, passwords, cookies or other website storage
- full URLs with query strings in the history
- IP addresses, device identifiers, advertising identifiers
- anything about sites where you have not interacted with Bastion Shield, beyond the blocking events above

## Settings the extension changes in your browser

Some protections are browser settings that the extension sets through the browser's own extension APIs. They are browser-wide while the extension is installed, and the browser restores its own value when the extension is removed:

| Setting | Default | API |
|---|---|---|
| Hyperlink auditing (`<a ping>`) off | on | `chrome.privacy.websites.hyperlinkAuditingEnabled` |
| Topics, Protected Audience, Attribution Reporting off | on | `chrome.privacy.websites.topicsEnabled` / `fledgeEnabled` / `adMeasurementEnabled` |
| WebRTC IP handling | browser default (not changed) | `chrome.privacy.network.webRTCIPHandlingPolicy` |
| Third-party cookies | browser default (not changed) | `chrome.privacy.websites.thirdPartyCookiesAllowed` |
| JavaScript blocked on sites you choose | off | `chrome.contentSettings.javascript` |

If your organisation sets the same setting by browser policy, the browser policy wins.

## Managed devices

If your organisation manages your browser, it can configure Bastion Shield through browser policy (for example sites where protection is off, switching history or the activity log off, or switching protection off entirely in an emergency). The extension reads that configuration locally (`chrome.storage.managed`) and shows "Managed by …" in the popup and dashboard. It does not report anything back to your organisation or to Bastion: the history stays on your device. Administrators can read the policy they set, not your activity.

## Permissions and why they are needed

The install prompt summarises these permissions in the browser's own words (the wording differs slightly between Chrome, Edge and Brave).

| Permission | Install warning (typical) | Why Bastion Shield needs it |
|---|---|---|
| `declarativeNetRequest` | "Block content on any page" | The core: the browser blocks, redirects and cleans requests from Bastion Shield's rule lists without running extension code per request. |
| `declarativeNetRequestFeedback` | "Read your browsing history" | Find out which rule (and therefore which list) blocked a request, to show it in the activity view. |
| `webRequest` | (covered by host access) | Observe, without changing anything, which requests the browser blocked or redirected, for the live activity view, the history and the badge count ([details](#what-the-extension-observes)). Not used to block. |
| `webNavigation` | "Read your browsing history" | Reset per-tab counters when a page loads, and attribute events to the right page. |
| `tabs` | "Read your browsing history" | Know the address of the current tab for the popup (site name, per-site switch), reload a tab after you change its settings, and set the grey "off" icon. |
| `scripting` | (covered by host access) | Insert the hiding styles and the scriptlets that remove ads and defuse anti-adblock code, only on the sites and frames that need them. |
| `storage` | none | Store settings and per-site choices (see above), read the administrator's configuration. |
| `unlimitedStorage` | none | Keep the local history and statistics without the 10 MB quota. |
| `alarms` | none | Prune old history once a day. |
| `privacy` | "Change your privacy-related settings" | Turn off hyperlink auditing and the Privacy Sandbox ad APIs; optionally WebRTC and third-party cookie settings. |
| `contentSettings` | "Change your settings that control websites' access to features such as cookies, JavaScript, …" | The per-site "Block scripts" switch. |
| `contextMenus` | none | Nerd mode only: right-click entries that open a link, image or selected filter in the Lab, and start the filter bisect. Nothing is read until you click an entry. |
| Host access `<all_urls>` | "Read and change all your data on all websites" | Needed for cosmetic filtering and scriptlets on every site, for redirect rules (replacing ad scripts with harmless stand-ins) and header rules (Global Privacy Control), and for observing blocked requests. The extension does not read page content beyond what filtering needs, and sends nothing anywhere. |
| `incognito: "split"` | none | Lets the extension's warning and bounce pages work in private windows when you allow the extension there. |
| `storage.managed_schema` | none | Declares the settings an administrator may set (`policy/managed_schema.json`). |
| Web-accessible resources (`pages/blocked.html`, `pages/bounce.html`, stand-in scripts) | none | The warning page for dangerous sites, the bounce-tracking skip page, and harmless replacements for blocked ad scripts. They are declared with dynamic URLs, which stops websites from probing for the extension directly, but a replaced `fetch`/`XMLHttpRequest` response still reveals the extension id ([details](#what-websites-can-see)). |

Bastion Shield does not request `cookies`, `history`, `downloads`, `bookmarks`, `identity`, `nativeMessaging`, `debugger` or `userScripts`.

## Contact

Responsible for Bastion Shield (controller under the Swiss Federal Act on Data Protection, FADP):

Bastion Security GmbH<br>
Am Wasser 55<br>
8049 Zürich<br>
Switzerland<br>
[info@bastionsecurity.ch](mailto:info@bastionsecurity.ch)

Questions about privacy: e-mail the address above or open an issue on GitHub. Security problems: see [SECURITY.md](../SECURITY.md).
