# Store privacy and review answers

Copy-paste answers for the **Privacy practices** tab of the Chrome Web Store and the **Properties** and **Submission** pages of Microsoft Edge Add-ons. They must stay consistent with [docs/PRIVACY.md](../docs/PRIVACY.md) and `src/manifest.base.json`; update all three together.

## Single purpose

> Bastion Shield blocks ads, trackers and known malicious websites, and shows the user what it blocked and why.

## Permission justifications

Chrome Web Store asks for one justification per permission. Each must fit in 1,000 characters.

**declarativeNetRequest**
> Core function. Bastion Shield ships its filter lists as static declarativeNetRequest rulesets, so the browser itself blocks ad, tracker and malware requests, replaces blocked ad scripts with harmless stand-ins, removes tracking parameters and sends the Global Privacy Control header, without running extension code for each request.

**declarativeNetRequestFeedback**
> Used only to look up which rule, and therefore which filter list, blocked a request, so the activity view can show the user the list and the exact filter. The result stays on the device.

**webRequest**
> Used read-only to learn that a request was blocked or redirected by Bastion Shield's own rules, for the live activity view, the local statistics and the toolbar count. It is not used to block or modify requests and never sees request or response contents.

**webNavigation**
> Resets the per-tab counters when a page loads and attributes blocked requests to the correct page and frame.

**tabs**
> Reads the address of the current tab so the popup can show the site and its per-site switch, reloads a tab after the user changes its settings, and sets the grey "off" icon on sites where protection is off.

**scripting**
> Inserts the element-hiding styles and the filter-list scriptlets that remove ads and defuse anti-adblock code, only on the sites and frames whose filters require them. All scripts are part of the extension package.

**storage**
> Stores the user's settings, per-site choices and custom filters locally, and reads the administrator's managed configuration (chrome.storage.managed).

**unlimitedStorage**
> Keeps the local blocking history and daily statistics (up to 30 days by default, deletable by the user) without the 10 MB storage quota.

**alarms**
> Prunes the local history once a day and refreshes filter lists that the user imported from a web address, if the user enabled daily updates for them.

**privacy**
> Turns off hyperlink auditing and the Privacy Sandbox advertising APIs, and applies the optional WebRTC and third-party cookie protections the user switches on.

**contentSettings**
> Implements the per-site "Block JavaScript" switch the user sets in the popup or dashboard.

**contextMenus**
> Optional power-user mode only (off by default): adds right-click entries to test a link, image or selected filter in the extension's filter tester. Nothing is read until the user clicks an entry.

**Host permissions (`<all_urls>`)**
> An ad and tracker blocker must work on every site the user visits. Host access is needed to apply element hiding and scriptlets on any site, for redirect rules that replace ad scripts with harmless stand-ins, for the header rule that sends Global Privacy Control, to observe which requests were blocked, and to warn about clipboard commands planted by ClickFix pages. Page content is processed locally only as far as filtering needs it; nothing is sent anywhere.

## Remote code

**No, I am not using remote code.**

> All JavaScript, WebAssembly and rules are included in the package. Filter lists are compiled at build time into static declarativeNetRequest rulesets and data files. Filter lists the user imports are data (filter rules), parsed locally; they cannot add code beyond the scriptlets already in the package.

## Data usage (Chrome Web Store)

Chrome Web Store counts data handled only on the device as well, so tick:

- [x] **Web history**: the local activity log and statistics record blocked requests with time, address and the site they occurred on.
- [x] **User activity**: blocked network requests are observed (read-only) to show and count them.
- [x] **Website content**: element hiding and the ClickFix protection process page content and text that pages try to place on the clipboard.

Leave all other categories (personally identifiable information, health, financial and payment, authentication, personal communications, location) unticked.

Certify all three statements:

- [x] I do not sell or transfer user data to third parties, outside of the approved use cases.
- [x] I do not use or transfer user data for purposes that are unrelated to my item's single purpose.
- [x] I do not use or transfer user data to determine creditworthiness or for lending purposes.

**Privacy policy URL:** `https://github.com/bastionsecurity-oss/bastion-shield/blob/main/docs/PRIVACY.md`
(Later, once the website has its own page: `https://bastionsecurity.ch/…`, and update this file.)

## Microsoft Edge Add-ons

**Does your extension access, collect or transmit personal information?** Yes (it processes browsing data locally, as above). Privacy policy URL as above.

**Notes for certification** (Submission page, field "Notes for certification"):

> Bastion Shield is an open-source ad and tracker blocker (GPL-3.0) by Bastion Security GmbH, Zurich. No account or test credentials are needed: install it and open any news website; the toolbar popup shows the blocked count, and the dashboard (popup › settings icon, or the extension's options page) shows the activity log with the matching filter list. All rules are static declarativeNetRequest rulesets bundled in the package; there is no remote code and no data is sent anywhere. Source code and the exact build inputs of every release: https://github.com/bastionsecurity-oss/bastion-shield/releases

## Support contact

- Website: `https://bastionsecurity.ch`
- Support URL: `https://github.com/bastionsecurity-oss/bastion-shield/issues`
- Support e-mail: `info@bastionsecurity.ch`
