# Nerd mode

Nerd mode is an opt-in set of power-user tools and experimental guards. It is
off by default (`settings.nerd.enabled`), and an admin can force it with the
`nerdMode` policy. With nerd mode off, Bastion Shield behaves and looks exactly
as before: no extra content scripts are registered, and the popup and dashboard
show nothing new. The one exception is not a nerd feature: the blocker notices
(see Blocker notices) also show uBlock filters' ClickFix blocks in Bastion
style instead of uBO's own alert bar.

Like everything else in Bastion, nothing leaves the device. The filter-history
links («GitHub ↗») are plain links the user chooses to open.

UI names (en / de): the dashboard section is "Developer tools" /
«Entwicklertools» (hash `#lab`, command `lab`; called the Lab in code and
below) with the tabs "Filter tester" / «Filter-Tester», "Checksums (SHA-256)"
/ «Prüfsummen (SHA-256)» and "Filter history" / «Filter-Historie». The
settings rows are "ClickFix protection (clipboard)", "Fingerprinting counter"
and "Lookalike domains (typosquatting)" with "Protected domains".

| Feature | Where | Setting / policy |
| --- | --- | --- |
| Find the breaking filter (bisect) | Popup (statusline), shortcut `Alt+Shift+X` | `nerd.enabled` |
| Command line (`Ctrl+K`) | Popup | `nerd.enabled` |
| Fingerprinting counter | Popup | `nerd.fingerprintMeter` |
| ClickFix protection (clipboard) | Page (notice), popup | `nerd.clipboardGuard` / `clipboardGuard` |
| Lookalike domains (typosquatting) | Page (notice), popup | `nerd.lookalike`, `nerd.protectedDomains` / `protectedDomains` |
| Filter history links («GitHub ↗») | Popup matched rules, dashboard Activity and Developer tools | `nerd.enabled` |
| Filter tester (dry run) | Dashboard › Developer tools | `nerd.enabled` |
| Check URL against installed rules | Dashboard › Developer tools | `nerd.enabled` |
| Checksums (SHA-256) self-check | Dashboard › Developer tools | `nerd.enabled` |
| Context menu | Right-click on pages, links, media, selections, toolbar icon | `nerd.enabled` |

## Context menu

While nerd mode is on, `background/nerd-menus.ts` adds a "Bastion Shield"
entry to the page context menu (permission `contextMenus`, no install
warning). The items are created and removed live when the setting flips
(`removeAll` + `create`, ids prefixed `nerd-`) and rebuilt on install, update
and browser start.

| Item | Context | Action |
| --- | --- | --- |
| Check URL: why blocked? | link, image, video, audio, frame | Opens `ui/dashboard.html#lab?url=…&site=<tab host>&type=…` next to the tab |
| Test selection in the filter tester | selection | `#lab?filter=…` |
| Filter history of the selection (GitHub) | selection | `#lab/blame?filter=…` |
| Find the breaking filter (bisect) | page | Starts the bisect for the tab (`NerdService.bisect`) and opens the popup |
| Open developer tools | toolbar icon | `#lab` |

## Developer tools (Lab)

The Lab follows deep links: `#lab?url=…` prefills the pasted-URL box
(`URL type site`) and runs the playground plus an explain run against the
installed rules; `#lab?filter=…` prefills the playground and runs it;
`#lab/blame?filter=…` looks the filter up. `/` focuses the main input,
`Ctrl+Enter` (`⌘ Enter`) runs, `Esc` leaves the field.

"Check URL against installed rules" (`ui/dashboard/lab-explain.ts`) answers
"why would this URL be blocked?". It reads the enabled static rulesets one at a
time from the package (`getEnabledRulesets`, manifest `rule_resources`),
scans them in chunks with a cheap pre-check (resource type, request domains,
the longest literal of the `urlFilter`), compiles the user's and the admin's
custom filters in the page so every rule keeps its filter text, and adds the
other dynamic and session rules. It lists every matching rule with priority,
source and filter text (transparency map) and names the rule that decides, in
Chromium's order. A page-level `allowAllRequests` (for example a site with
protection off) is evaluated against `https://<site>/`. At most 20 URLs and
50 rules per URL are shown.

Each result reads as follows:

- **Type.** "checked as" shows the resource type the URL was checked as
  (e.g. "Page navigation (main_frame)"); a small select changes it per URL and
  reruns the check (the URL line in the box is rewritten). A line without a
  type is guessed from the file extension (`guessType`, `other` when unknown)
  and marked as guessed; context-menu links pass `main_frame`.
- **Verdict.** One plain sentence: what happens, why, and the deciding rule,
  e.g. "Result: Allowed – protection is off for this website (rule #8000000,
  priority 1000)". Bastion's own allows (protection off, «proceed anyway»,
  bisect, Standard mode) are named; other rules name their list ("by
  EasyList"); custom and admin filters give the line instead of a rule id.
- **Counterfactual.** When an `allow` or `allowAllRequests` decides, a second
  line says what would happen without it: the deciding rule and every other
  allow of the same kind are dropped and the rest is decided again in
  Chromium's order (`counterfactual()`), e.g. "Without this exception: Block
  page (strict block) by EasyList, priority 29", or "would load normally" when
  nothing blocking remains.
- **Action labels.** Each matching rule shows a human label with the raw DNR
  action in small mono next to it: Blocked, Allowed (exception), Page allowed,
  Block page (strict block) (redirect to `pages/blocked.html` or priority 29),
  Surrogate script (redirect to a `war/` resource), Tracking parameters removed
  (`queryTransform` / empty query), Bounce tracking skipped (debounce), Headers
  modified (GPC header set for `Sec-GPC`), Upgraded to HTTPS (`actionKind()`).
- **Merged rules.** The build merges filters that differ only in their domain
  into one rule (one `requestDomains` list) and records at most 20 filter
  texts plus "+N more". The filter cell shows the text(s) naming the request
  host or a parent domain first, highlighted; when that text was not
  recorded, it is rebuilt from a recorded sibling with the matched
  `requestDomains` entry (e.g. `||000491b06a.com^` → `||googlesyndication.com^`,
  marked as derived in its tooltip). Then "+N more". When nothing can be tied
  to the request, the first recorded texts are shown. «GitHub ↗» opens the
  filter history of the highlighted text.

User and admin filters may use `@@…$important` (AdGuard syntax): it compiles to
an `allow` at priority 50 (`PRIORITY.IMPORTANT_ALLOW`), above every
`$important` block and redirect. Lists cannot use it.

## Popup statusline and command line

With nerd mode on, the popup gets one extra row at the bottom
(`ui/popup/nerd.ts`): a mono statusline with `fp N` (fingerprinting calls,
per-vector breakdown on hover or click), `clip N` (clipboard writes
replaced), `N hosts` (hosts blocked on this page load) and `≠ <domain>` (the
lookalike warning). Items show only when non-zero. With nerd mode off the
row is hidden and empty.

`Ctrl+K` (`⌘K`), `/` or `:` (outside text fields) open the command line:
fuzzy subsequence matching, at most six suggestions, `↑`/`↓` or
`Ctrl+N`/`Ctrl+P` to move, `Tab` to complete, `Enter` to run, `Esc` to close
(`ui/popup/commands.ts`).

| Command | Does |
| --- | --- |
| `bisect` / `bisect cancel` | Start the filter bisect on this tab, or end it |
| `why [url\|host]` | Check a URL against the installed rules: open `#lab?url=…&site=…` (the page itself without an argument) |
| `blame <filter>` | Filter history on GitHub: open `#lab/blame?filter=…` |
| `allow <host>` | Add `@@\|\|host^$domain=<site>` to the user's filters (completes from the blocked hosts) |
| `fp` | Fingerprinting calls per vector, inline |
| `copy report` | JSON to the clipboard: `site, url, at, counts, blockedHosts[{host, count, rules, filters, lists}], fp, clipboardBlocked, lookalike, version` |
| `lab` | Open developer tools |
| `nerd off` | Switch nerd mode off |

Keyboard shortcuts (`chrome://extensions/shortcuts`): `Alt+Shift+B` opens the
popup, `Alt+Shift+X` starts the bisect on the active tab or ends the one shown
there (`background/nerd-commands.ts`; nothing happens while nerd mode or the
activity log is off).

## Filter bisect

Bisect is `git bisect` for a broken page. Its candidates are the hosts that were
blocked or redirected on the tab's current page load. Each step installs
tab-scoped session `allow` rules (`requestDomains` + `tabIds`) for half of the
remaining candidates, reloads the tab and asks "does the page work now?". A
single culprit among n hosts takes at most 2 + ⌈log₂ n⌉ answers (one check
with everything let through, ⌈log₂ n⌉ halvings, and one check of the culprit
alone when a half had to be pinned); the popup shows this bound as
`bisect 2/≤5`, and the toolbar badge of the tab shows `2/5` while a test runs.
The activity badge leaves that tab alone until the test phase ends.

In the popup the bisect replaces the statusline and is answered with single
keys: `y` / `n` / `Esc` while testing ("does the page work now?"); `k` (keep
the exception), `b` (filter history in the developer tools) / `Esc` once found
("Found: <host>"). The result shows the culprit host,
the filter text from the transparency map and the list it came from. "Keep"
appends a narrow exception (`@@||host^$domain=site`) to the user's own
filters; when the blocking filter is `$important`, the exception is
`@@||host^$domain=site,important`. Switching nerd mode off ends every bisect
and removes its rules at once (the pages are not reloaded).

If the page is still broken with every candidate allowed, the cause is not a
network block (it may be a cosmetic filter, a scriptlet or the site itself).
The bisect then says so and stops. `allow` rules do not lift cosmetic
filtering.

## Fingerprinting counter

`main/fpmeter.js` runs in the MAIN world and counts calls to fingerprinting
APIs per vector (`FpVector`: canvas, webgl, audio, fonts, navigator, screen,
media, timing). It sends the counts in batches to the ISOLATED relay
(`content/nerd-relay.js`), which forwards them to the service worker as
`nerd:signal`. Counts reset on every top-level navigation and live in memory
only.

## ClickFix protection (clipboard)

`main/clipguard.js` checks text that a page writes to the clipboard
(`navigator.clipboard.writeText`/`write`, `setData` in copy events,
`execCommand('copy')`). It replaces text that looks like a shell command
pasted from a fake CAPTCHA ("ClickFix": PowerShell with encoded commands,
`mshta`, `curl … | sh`, …) with a harmless note, and the page shows the
Bastion notice «ClickFix blocked» (see Blocker notices). A user copying text
they selected on the page is not blocked.

The detector (`main/clip-detect.ts`) is at least as strong as uBlock filters'
generic ClickFix filter: every alternative of that filter's regex is ported as
a named rule (`UBO_PORTED_RULES`; a unit test fails when the cached uBlock
list gains an alternative that is not ported). Most rules are 'high'. Hidden
or minimised PowerShell windows (`-w hidden`, `-w minimized`) are 'high' even
without a download: no web page has a legitimate reason to put one on the
clipboard. PowerShell launched as a program (at a line start or after a path
separator, as uBO anchors it) with `-NoP`, `-ExecutionPolicy Bypass` /
`Unrestricted`, `iex(`, `Invoke-Expression`, `Invoke-WebRequest` or
`-UseBasicParsing` is 'high' too. 'medium' stays for the download-and-run
lines that install docs print (`curl -s … | bash`, `bash -c "$(curl …)"`,
`irm … | iex`, `iex(irm …)`, `wget -q …/install.sh`, `msiexec` of a local
package, a bash line with an aligned `#` comment); they are allowed when the
same text is visible on the page. uBO's `excludeMatches`
(`Maintainer|Contributor|^{|^http|^(git|import|require|use) `) is mirrored as
an allow-list for 'medium' verdicts only.

Where both run, uBO's scriptlet sits in front of the guard: it wraps
`writeText` and `execCommand` on the first `mousemove`, after the guard's
document_start hooks, so a write it blocks never reaches the guard and only
uBO's path reports it. The guard still sees `clipboard.write`, `setData`, and
everything on uBO's ~95 excluded developer sites.

## Blocker notices

Every in-page notice of the blocker is one component (`content/notice.ts`,
bundled into `content/cosmetic.js`, which runs in every frame where
protection is on, with nerd mode on or off):

- **ClickFix blocked** («Bastion Shield hat einen möglichen ClickFix-Angriff
  blockiert»): from uBlock filters' ClickFix filter (source line «Erkannt
  durch: uBlock-Filter», nerd mode on or off) or from the nerd mode clipboard
  guard («Erkannt durch: Bastion ClickFix-Schutz»). It shows the blocked
  command in a selectable, scrollable mono box (at most six lines visible).
- **Lookalike domain** (nerd mode): «Achtung: möglicherweise Phishing», the
  imitated and the visited domain, the reason, «Seite verlassen» (back, or
  `about:blank` when there is no history or «back» stays in the document) and
  «Trotzdem fortfahren» (closes the notice).

Cards stack top-right (12 px inset, `min(360px, 100vw − 24px)` wide), newest
on top, at most three; security notices never dismiss themselves. × and Esc
(on the focused notice) close a card. They render in the top frame only: a
subframe's cosmetic.js sends `notice:clip` to the service worker, which
forwards it to frame 0 as `notice:show`. The host element is in the top layer
(`popover="manual"`, z-index max), its inline styles are `!important` after
`all: initial`, and the content lives in a closed shadow root, so page CSS
cannot restyle it and ours does not leak. Light and dark follow
`prefers-color-scheme`; the enter animation (fade and 8 px slide) is off
with `prefers-reduced-motion`. Identical text from either source within 2 s
gives one notice.

**No «copy anyway».** The notice never offers to copy the blocked command.
ClickFix pages tell visitors what to click («press the button, then Win+R,
Ctrl+V, Enter»), so any override button would become one more step of the
lure. The command stays visible and selectable in the card, with the line
«Falls Sie diesen Befehl wirklich brauchen, markieren und kopieren Sie ihn
selbst – nachdem Sie geprüft haben, was er tut.» Copying by hand is a
deliberate act that a page cannot script.

**uBO's alert, routed.** The vendored `prevent-clipboard-write.js` stays
unchanged (`npm run vendor:check`). `tools/lib/notice-transform.ts` rewrites
the serialized function when the scriptlet core is emitted: the beige DOM
alert (`htmlTemplate` … `let currentAlert = null;`) becomes `bastionNotice`,
which dispatches a synchronous `CustomEvent` with the detail
`ubo|<blocked text>` on the frame's window, and `domAlert(text)` becomes
`bastionNotice(text)`. Matching, `excludeMatches`, the traps and their return
values are uBO's, so the write is still prevented exactly as before. Filters
without `domAlert` stay silent, as in uBO. cosmetic.js listens for the event,
stops it (page listeners never see the text), sends `nerd:signal` kind `clip`
(the nerd `clip` counter; the service worker ignores it while nerd mode is
off; at most 50 per page load) and shows the notice. Without the listener
nothing is shown: the beige bar cannot come back. When an anchor no longer
matches (a uBO update), the transform throws and the build fails;
`test/tools/notice-transform.test.ts` runs it on the vendored file, and
`emitScriptlets` refuses a core that still holds the alert.

**Event name.** A random token per build (`bsn` + 96 random bits,
`noticeEventName()`), compiled into the MAIN scriptlet core and, through the
esbuild define `__BASTION_NOTICE_EVENT__`, into cosmetic.js. Forgery: a page
needs the name to send or receive these events. It is not in anything the
page can read (content-script files are not web-accessible; the scriptlet
keeps it in a closure; the dispatch uses `EventTarget#dispatchEvent`,
`CustomEvent`, `Reflect.apply` and `Object.create` captured at
document_start, before page code can wrap them), event names cannot be
enumerated, and the listener stops the event before page listeners. A page
that learnt the token (or forged the nerd channel, whose name derives from
the extension id) could show a notice with text of its choice. The notice
has no copy button, so the worst outcome is a card telling the visitor that a
command was blocked.

## Lookalike domains (typosquatting)

`shared/lookalike.ts` compares the top-frame host with the protected domains.
These are the built-in list, the user's domains and the policy's
`protectedDomains`. It flags three cases: homoglyphs (punycode and look-alike
characters such as `rn`→`m`), typosquatting (small edit distance) and
combosquatting (`paypal-login-secure.com`). The result is sent with the `cosmetic:frame`
reply, and the content script shows the lookalike notice (see Blocker
notices). The protected domain itself and its subdomains are never flagged.

## Trust model

Page scripts can forge the MAIN→ISOLATED events. The worst a forged event can
do is inflate the meter or show a notice (see Blocker notices for the notice
channel). The service worker accepts only known
vectors and bounded counts (`background/nerd.ts`). The checksum check in the
developer tools («Prüfsummen (SHA-256)») hashes the packaged ruleset files with SHA-256 and compares them with
`rulesets/integrity.json` from the same build. It is a self-check, not a
signature.
